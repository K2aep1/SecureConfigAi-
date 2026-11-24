"""Configuration snapshot validation and normalisation.

Three input shapes are accepted, and the difference between them is reported rather
than hidden:

1. **Integrity-verified snapshot** (schema 1.0-1.2) — the SHA-256 in the ``integrity``
   block matches the document. Verified.
2. **Unverified snapshot** — has the format header and a ``checks`` map but no usable
   integrity block. Accepted with ``integrity_verified = False`` so the UI can say so.
3. **Legacy flat document** — the old scanner output with top-level ``firewall``,
   ``bitlocker``, ``rdp`` keys. Mapped into the ``checks`` structure so historical
   files stay analysable.

Two different guarantees, deliberately never conflated
------------------------------------------------------
* **Integrity (always available).** The SHA-256 is a *checksum over the payload*,
  computed by the same process that produced it. It detects corruption in transit and at
  rest. It does **not** prove who produced the evidence, because anyone holding the file
  can recompute it.
* **Authenticity (opt-in).** When the deployment configures ``EVIDENCE_SIGNING_KEY`` on
  both the scanner and the backend, the snapshot may carry a ``provenance`` block: an
  HMAC-SHA-256 over ``evidence_digest | scan_id | timestamp | scanner_version | nonce``.
  The backend recomputes the digest from the received bytes and verifies the MAC with the
  shared key, so a payload edited in flight fails verification even though its checksum
  would still "match".

Residual limitation, stated rather than hidden: a shared key gives *origin assurance
between two parties that share it* — it is not non-repudiation, and without a
server-issued nonce and a trusted timestamp it does not prevent replay. A full
asymmetric signature with RFC 3161 timestamps is the next step and is not implemented.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings

SUPPORTED_FORMAT = "SecureConfigAI Configuration Snapshot"
SUPPORTED_SCHEMA_VERSIONS = {"1.0", "1.1", "1.2"}

#: Legacy top-level collector keys that map straight into ``checks``.
LEGACY_DIRECT = (
    "firewall",
    "system_hardening",
    "updates",
    "account_security",
    "authentication",
    "network_security",
    "services",
    "access_control",
    "tpm",
    "registry",
    "device",
    "installed_software",
    "network_inventory",
)

PROVENANCE_ALGORITHM = "HMAC-SHA-256"
PROVENANCE_SCOPE = "evidence_digest|scan_id|timestamp|scanner_version|nonce"


class SnapshotValidationError(ValueError):
    """The upload is not a SecureConfigAI evidence document."""


@dataclass
class SnapshotLoad:
    document: dict[str, Any]
    integrity_verified: bool
    schema_version: str | None
    snapshot_id: str | None
    scanner_version: str | None
    warnings: list[str] = field(default_factory=list)
    #: True only when a configured key verified the submitted HMAC envelope.
    authenticity_verified: bool = False
    provenance: dict[str, Any] | None = None


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode(
        "utf-8"
    )


def calculate_snapshot_hash(payload: Mapping[str, Any]) -> str:
    data = dict(payload)
    data.pop("integrity", None)
    data.pop("provenance", None)
    return hashlib.sha256(_canonical_bytes(data)).hexdigest()


def verify_integrity(payload: Mapping[str, Any]) -> bool:
    integrity = payload.get("integrity")
    if not isinstance(integrity, Mapping):
        return False
    if str(integrity.get("algorithm", "")).upper() not in {"SHA-256", "SHA256"}:
        return False
    supplied = str(integrity.get("sha256", "")).strip().lower()
    if len(supplied) != 64:
        return False
    return supplied == calculate_snapshot_hash(payload)


# --------------------------------------------------------------------------- provenance
def provenance_message(
    *, evidence_digest: str, scan_id: str, timestamp: str, scanner_version: str, nonce: str
) -> bytes:
    """The exact byte string that is MAC'd. Order and separators are part of the contract."""
    return ("|".join((evidence_digest, scan_id, timestamp, scanner_version, nonce))).encode("utf-8")


def compute_provenance_hmac(
    *, evidence_digest: str, scan_id: str, timestamp: str, scanner_version: str, nonce: str, key: str
) -> str:
    return hmac.new(
        key.encode("utf-8"),
        provenance_message(
            evidence_digest=evidence_digest,
            scan_id=scan_id,
            timestamp=timestamp,
            scanner_version=scanner_version,
            nonce=nonce,
        ),
        hashlib.sha256,
    ).hexdigest()


def verify_provenance(payload: Mapping[str, Any]) -> tuple[bool, str, dict[str, Any] | None]:
    """Verify an optional provenance envelope. Returns ``(verified, reason, block)``.

    The evidence digest is always recomputed here from the received bytes; a digest
    supplied by the client is never trusted as the reference value.
    """
    block = payload.get("provenance")
    if not isinstance(block, Mapping):
        return False, "no provenance envelope was supplied", None
    if not settings.evidence_signing_configured:
        return False, ("provenance was supplied but no signing key is configured on the server"), dict(block)
    if str(block.get("algorithm", "")).upper() not in {"HMAC-SHA-256", "HMACSHA256"}:
        return False, f"unsupported provenance algorithm {block.get('algorithm')!r}", dict(block)

    fields = {}
    for name in ("scan_id", "timestamp", "scanner_version", "nonce", "hmac"):
        value = block.get(name)
        if not isinstance(value, str) or not value.strip():
            return False, f"provenance.{name} is missing", dict(block)
        fields[name] = value.strip()

    supplied = fields.pop("hmac").lower()
    if len(supplied) != 64:
        return False, "provenance.hmac is not a SHA-256 MAC", dict(block)

    digest = calculate_snapshot_hash(payload)
    expected = compute_provenance_hmac(
        evidence_digest=digest,
        scan_id=fields["scan_id"],
        timestamp=fields["timestamp"],
        scanner_version=fields["scanner_version"],
        nonce=fields["nonce"],
        key=(settings.EVIDENCE_SIGNING_KEY or "").strip(),
    )
    if not hmac.compare_digest(expected, supplied):
        return (
            False,
            (
                "provenance MAC does not match the received payload; the evidence "
                "was modified or signed with a different key"
            ),
            dict(block),
        )
    return True, "provenance verified", dict(block)


def _looks_like_checks(document: Mapping[str, Any]) -> bool:
    checks = document.get("checks")
    return isinstance(checks, Mapping) and len(checks) > 0


def _legacy_to_checks(document: Mapping[str, Any]) -> dict[str, Any]:
    """Translate a legacy flat scanner document into the ``checks`` structure."""
    checks: dict[str, Any] = {}
    for key in LEGACY_DIRECT:
        if key in document and key != "device":
            checks[key] = document[key]
    hardening: dict[str, Any] = dict(checks.get("system_hardening") or {})
    if "bitlocker" in document:
        hardening["bitlocker"] = document["bitlocker"]
    if "defender" in document:
        hardening["defender"] = document["defender"]
    for key in ("uac_enabled", "secure_boot", "secure_boot_supported"):
        if key in document:
            hardening[key] = document[key]
    if hardening:
        checks["system_hardening"] = hardening

    network: dict[str, Any] = dict(checks.get("network_security") or {})
    if "rdp" in document:
        network["rdp"] = document["rdp"]
    if "smb" in document:
        network["smb1"] = document["smb"]
    if network:
        checks["network_security"] = network
    return checks


def load_snapshot(payload: Any, *, raw_size: int | None = None) -> SnapshotLoad:
    """Validate and normalise an uploaded evidence document."""
    if raw_size is not None and raw_size > settings.MAX_UPLOAD_BYTES:
        raise SnapshotValidationError(
            f"Upload exceeds the {settings.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."
        )
    if not isinstance(payload, Mapping):
        raise SnapshotValidationError("The uploaded document must be a JSON object.")

    document = dict(payload)
    warnings: list[str] = []
    schema_version = document.get("schema_version")
    snapshot_id = document.get("snapshot_id")
    scanner_version = None
    scanner = document.get("scanner")
    if isinstance(scanner, Mapping):
        scanner_version = scanner.get("version")

    is_snapshot_format = str(document.get("format", "")) == SUPPORTED_FORMAT
    if is_snapshot_format:
        if schema_version and str(schema_version) not in SUPPORTED_SCHEMA_VERSIONS:
            raise SnapshotValidationError(f"Unsupported snapshot schema version {schema_version!r}.")
        if not _looks_like_checks(document):
            raise SnapshotValidationError("The snapshot contains no collected checks.")
        device = document.get("device")
        if not isinstance(device, Mapping) or not device.get("hostname"):
            raise SnapshotValidationError("The snapshot does not identify a device.")
        if not verify_integrity(document):
            if isinstance(document.get("integrity"), Mapping):
                # An integrity block exists but does not match: the payload was altered
                # after the hash was computed. That is tampering, not a legacy file.
                raise SnapshotValidationError(
                    "Snapshot integrity check failed: the SHA-256 in the document does "
                    "not match its contents."
                )
            warnings.append(
                "The snapshot carries no integrity block; the evidence is accepted as unverified."
            )
            integrity_verified = False
        else:
            integrity_verified = True

        authentic, reason, block = verify_provenance(document)
        if authentic:
            warnings.append("Evidence provenance verified with the configured signing key.")
        elif block is not None and settings.evidence_signing_configured:
            # A key is configured and the MAC does not match: that is tampering.
            raise SnapshotValidationError(f"Snapshot provenance check failed: {reason}.")
        elif block is not None:
            warnings.append(
                "The snapshot carries a provenance envelope but this server "
                "has no signing key configured, so it was accepted as "
                "integrity-checked only."
            )
        else:
            warnings.append(
                "No provenance envelope: this evidence is integrity-checked only, not authenticated."
            )
        return SnapshotLoad(
            document,
            integrity_verified,
            str(schema_version) if schema_version else None,
            str(snapshot_id) if snapshot_id else None,
            str(scanner_version) if scanner_version else None,
            warnings,
            authenticity_verified=authentic,
            provenance=block,
        )

    if _looks_like_checks(document):
        device = document.get("device")
        if not isinstance(device, Mapping) or not device.get("hostname"):
            raise SnapshotValidationError("The document does not identify a device.")
        warnings.append(
            "No snapshot format header or integrity block was found; "
            "the document is accepted as unverified evidence."
        )
        return SnapshotLoad(
            document,
            False,
            str(schema_version) if schema_version else None,
            None,
            str(scanner_version) if scanner_version else None,
            warnings,
        )

    checks = _legacy_to_checks(document)
    if checks:
        warnings.append(
            "Legacy document format converted to the current evidence "
            "structure; controls without evidence will be reported as unknown."
        )
        return SnapshotLoad({**document, "checks": checks}, False, None, None, None, warnings)

    raise SnapshotValidationError("The uploaded document contains no recognisable collected evidence.")
