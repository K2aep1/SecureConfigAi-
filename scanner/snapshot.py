"""Integrity-wrapped configuration snapshot builder.

The snapshot is the artifact that is stored and later re-verified.  Its
integrity semantics are **unchanged from schema 1.0/1.1** so previously issued
snapshots still validate:

* the hash is SHA-256 over the document with the ``integrity`` key removed;
* serialisation is canonical — ``sort_keys=True``, ``separators=(",", ":")``,
  ``ensure_ascii=False``, encoded UTF-8;
* ``integrity.hash_scope`` is always ``"snapshot_without_integrity"``.

``build_configuration_snapshot`` returns the *result document* (schema 1.2)
plus that ``integrity`` block.  It never re-shapes or nests collector evidence,
so the snapshot and ``scan_result.json`` carry identical payloads.
"""

from __future__ import annotations

import hashlib
import json
import platform
import uuid
from datetime import UTC, datetime
from typing import Any

from scanner.report import FORMAT, SCHEMA_VERSION

__all__ = [
    "FORMAT",
    "SCHEMA_VERSION",
    "build_configuration_snapshot",
    "build_provenance",
    "calculate_snapshot_hash",
    "canonical_bytes",
    "verify_snapshot_integrity",
]

SCANNER_NAME = "SecureConfigAI Scanner"

METADATA: dict[str, Any] = {
    "generator": "SecureConfigAI",
    "purpose": "Windows security configuration assessment",
    "contains_findings": False,
    "score_source": "backend_analysis",
}


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical UTF-8 encoding of a snapshot for hashing."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def calculate_snapshot_hash(payload: dict[str, Any]) -> str:
    """SHA-256 of ``payload`` with the ``integrity`` and ``provenance`` keys removed.

    ``provenance`` covers the digest of this same scope, so it cannot be inside it.
    Documents without a provenance block hash exactly as they did before.
    """
    data = dict(payload)
    data.pop("integrity", None)
    data.pop("provenance", None)
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


def build_provenance(
    *, snapshot: dict[str, Any], signing_key: str, nonce: str | None = None, timestamp: str | None = None
) -> dict[str, Any]:
    """Build the optional HMAC provenance envelope for a snapshot.

    The MAC covers ``evidence_digest | scan_id | timestamp | scanner_version | nonce``.
    The backend recomputes the digest itself and verifies the MAC with the same key, so
    an edited payload fails even though its checksum would still match.
    """
    import hmac

    digest = calculate_snapshot_hash(snapshot)
    scanner = snapshot.get("scanner") if isinstance(snapshot.get("scanner"), dict) else {}
    block = {
        "algorithm": "HMAC-SHA-256",
        "scope": "evidence_digest|scan_id|timestamp|scanner_version|nonce",
        "evidence_digest": digest,
        "scan_id": str(snapshot.get("snapshot_id") or ""),
        "timestamp": str(timestamp or snapshot.get("created_at") or ""),
        "scanner_version": str(scanner.get("version") or SCHEMA_VERSION),
        "nonce": str(nonce or uuid.uuid4().hex),
    }
    message = "|".join(
        (
            block["evidence_digest"],
            block["scan_id"],
            block["timestamp"],
            block["scanner_version"],
            block["nonce"],
        )
    ).encode("utf-8")
    block["hmac"] = hmac.new(signing_key.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return block


def verify_snapshot_integrity(snapshot: dict[str, Any]) -> bool:
    """``True`` when the published hash matches the recomputed one."""
    integrity = snapshot.get("integrity")
    if not isinstance(integrity, dict):
        return False
    supplied = str(integrity.get("sha256") or "").lower()
    return bool(supplied) and supplied == calculate_snapshot_hash(snapshot)


def build_configuration_snapshot(
    normalized: dict[str, Any] | None,
    *,
    scanner_version: str = SCHEMA_VERSION,
    scan_started_at: str | None = None,
    snapshot_id: str | None = None,
    created_at: str | None = None,
    signing_key: str | None = None,
) -> dict[str, Any]:
    """Return the result document plus its ``integrity`` block.

    Args:
        normalized: Output of :func:`scanner.normalizer.normalize_scan_output`.
        scanner_version: Version string recorded under ``scanner.version``.
        scan_started_at: Overrides ``scanner.started_at`` when supplied.
        snapshot_id: Overrides the generated snapshot identifier.
        created_at: Overrides the generated creation timestamp.
        signing_key: Optional shared secret. When supplied, an HMAC provenance
            envelope is added so the backend can verify origin, not just integrity.
    """
    source = normalized if isinstance(normalized, dict) else {}
    device = source.get("device") if isinstance(source.get("device"), dict) else {}
    scanner = source.get("scanner") if isinstance(source.get("scanner"), dict) else {}
    checks = source.get("checks") if isinstance(source.get("checks"), dict) else {}
    collector_status = (
        source.get("collector_status") if isinstance(source.get("collector_status"), dict) else {}
    )
    execution = source.get("execution") if isinstance(source.get("execution"), dict) else {}

    completed_at = created_at or datetime.now(UTC).isoformat()
    identifier = snapshot_id or f"SCFG-{datetime.now(UTC):%Y%m%d}-{uuid.uuid4().hex[:12].upper()}"

    counts = _status_counts(collector_status)

    snapshot: dict[str, Any] = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": identifier,
        "created_at": completed_at,
        "scanner": {
            "name": SCANNER_NAME,
            "version": scanner_version,
            "platform": platform.system().lower(),
            "status": scanner.get("status", "completed"),
            "collector_count": scanner.get("collector_count", len(checks)),
            "completed": scanner.get("completed", counts["completed"]),
            "errors": scanner.get("errors", counts["errors"]),
            "timeouts": scanner.get("timeouts", counts["timeouts"]),
            "skipped": scanner.get("skipped", counts["skipped"]),
            "unavailable": scanner.get("unavailable", counts["unavailable"]),
            "duration_seconds": scanner.get("duration_seconds"),
            "budget_seconds": scanner.get("budget_seconds"),
            "inventory": scanner.get("inventory", False),
            "started_at": scan_started_at or scanner.get("started_at"),
            "completed_at": scanner.get("completed_at", completed_at),
        },
        "execution": execution,
        "device": {
            "hostname": device.get("hostname", "unknown-host"),
            "os": device.get("os", "windows"),
            "version": device.get("version"),
            "build": device.get("build"),
            "name": device.get("name"),
            "architecture": device.get("architecture"),
            "install_date": device.get("install_date"),
            "last_boot": device.get("last_boot"),
            "serial_number": device.get("serial_number"),
            "windows_directory": device.get("windows_directory"),
            "computer_name": device.get("computer_name"),
        },
        "checks": checks,
        "collector_status": collector_status,
        "metadata": dict(METADATA),
    }
    snapshot["integrity"] = {
        "algorithm": "SHA-256",
        "hash_scope": "snapshot_without_integrity",
        "sha256": calculate_snapshot_hash(snapshot),
    }
    key = (signing_key or "").strip()
    if len(key) >= 32:
        snapshot["provenance"] = build_provenance(snapshot=snapshot, signing_key=key, timestamp=completed_at)
    return snapshot


def _status_counts(collector_status: dict[str, Any]) -> dict[str, int]:
    counts = {"completed": 0, "errors": 0, "timeouts": 0, "skipped": 0, "unavailable": 0}
    for entry in collector_status.values():
        status = str(entry.get("status", "")).lower() if isinstance(entry, dict) else ""
        if status == "error":
            counts["errors"] += 1
        elif status == "timeout":
            counts["timeouts"] += 1
        elif status in counts:
            counts[status] += 1
    return counts
