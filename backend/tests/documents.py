"""Evidence document fixtures.

Kept in a module of its own (rather than in ``conftest.py``) because the PostgreSQL
integration test builds documents inside a subprocess, and importing ``conftest`` there
would rewrite the database environment variables.
"""

from __future__ import annotations

import uuid
from typing import Any


def empty_document() -> dict:
    return {
        "schema_version": "1.2",
        "device": {"hostname": "EMPTY-PC", "os": "windows", "version": "10.0.26200", "build": "26200"},
        "checks": {},
    }


def perfect_document(hostname: str = "PERFECT-PC") -> dict:
    return {
        "schema_version": "1.2",
        "device": {"hostname": hostname, "os": "windows", "version": "10.0.26200", "build": "26200"},
        "scanner": {"name": "SecureConfigAI Scanner", "version": "2.0.0", "status": "completed"},
        "checks": {
            "firewall": {
                "status": "completed",
                "profiles": [
                    {"name": "Domain", "enabled": True, "inbound": "Block", "outbound": "Allow"},
                    {"name": "Private", "enabled": True, "inbound": "Block", "outbound": "Allow"},
                    {"name": "Public", "enabled": True, "inbound": "Block", "outbound": "Allow"},
                ],
                "logging": {
                    "Domain": {"LogBlocked": True, "LogAllowed": True},
                    "Private": {"LogBlocked": True, "LogAllowed": True},
                    "Public": {"LogBlocked": True, "LogAllowed": True},
                },
            },
            "system_hardening": {
                "status": "completed",
                "bitlocker": {"status": "completed", "enabled": True},
                "defender": {
                    "status": "completed",
                    "enabled": True,
                    "real_time_protection": True,
                    "tamper_protection": True,
                    "signature_age": 1,
                },
                "uac": {
                    "status": "completed",
                    "EnableLUA": 1,
                    "ConsentPromptBehaviorAdmin": 2,
                    "PromptOnSecureDesktop": 1,
                },
                "uac_enabled": True,
                "secure_boot": True,
                "secure_boot_supported": True,
            },
            "tpm": {"status": "completed", "present": True, "ready": True},
            "authentication": {
                "status": "completed",
                "source": "secedit",
                "minimum_length": 14,
                "lockout_threshold": 10,
                "minimum_password_age": 1,
                "complexity": True,
            },
            "network_security": {
                "status": "completed",
                "rdp": {"enabled": False},
                "smb1": {"enabled": False},
                "smb_server": {"require_security_signature": True, "smb1_protocol_enabled": False},
            },
            "updates": {"status": "completed", "days_since_patch": 5, "source": "get_hotfix"},
            "account_security": {"status": "completed", "admin_count": 1},
            "services": {"status": "completed", "suspicious": []},
            "access_control": {"status": "completed", "system_config_acl_protected": True},
            "registry": {
                "status": "completed",
                "wdigest": {"configured": True, "value": 0},
                "llmnr": {"configured": True, "value": 0},
                "autorun": {"configured": True, "value": 255},
                "netlogon": {
                    "require_sign_or_seal": {"configured": True, "value": 1},
                    "seal_secure_channel": {"configured": True, "value": 1},
                    "sign_secure_channel": {"configured": True, "value": 1},
                },
                "lm_compatibility_level": {"configured": True, "value": 5},
                "powershell_script_block_logging": {"configured": True, "value": 1},
                "wdigest_credential_caching_disabled": True,
                "llmnr_disabled": True,
                "autorun_disabled": True,
                "powershell_script_block_logging_enabled": True,
            },
        },
    }


def failing_document(hostname: str = "FAILING-PC") -> dict:
    document = perfect_document(hostname)
    checks = document["checks"]
    checks["firewall"] = {
        "status": "completed",
        "profiles": [{"name": "Domain", "enabled": False, "inbound": "Allow", "outbound": "Allow"}],
        "logging": {"Domain": {"LogBlocked": False, "LogAllowed": False}},
    }
    checks["system_hardening"] = {
        "status": "completed",
        "bitlocker": {"status": "completed", "enabled": False},
        "defender": {
            "status": "completed",
            "enabled": False,
            "real_time_protection": False,
            "tamper_protection": False,
            "signature_age": 45,
        },
        "uac": {"status": "completed", "EnableLUA": 0, "ConsentPromptBehaviorAdmin": 0},
        "uac_enabled": False,
        "secure_boot": False,
        "secure_boot_supported": True,
    }
    checks["tpm"] = {"status": "completed", "present": True, "ready": False}
    checks["authentication"] = {
        "status": "completed",
        "source": "secedit",
        "minimum_length": 4,
        "lockout_threshold": 0,
        "minimum_password_age": 0,
        "complexity": False,
    }
    checks["network_security"] = {
        "status": "completed",
        "rdp": {"enabled": True},
        "smb1": {"enabled": True},
        "smb_server": {"require_security_signature": False, "smb1_protocol_enabled": True},
    }
    checks["updates"] = {"status": "completed", "days_since_patch": 400}
    checks["account_security"] = {"status": "completed", "admin_count": 9}
    checks["services"] = {
        "status": "completed",
        "suspicious": [{"name": "RemoteRegistry", "state": "Running"}],
    }
    checks["access_control"] = {"status": "completed", "system_config_acl_protected": False}
    checks["registry"] = {
        "status": "completed",
        "wdigest": {"configured": True, "value": 1},
        "llmnr": {"configured": True, "value": 1},
        "autorun": {"configured": True, "value": 0},
        "netlogon": {
            "require_sign_or_seal": {"configured": True, "value": 0},
            "seal_secure_channel": {"configured": True, "value": 0},
            "sign_secure_channel": {"configured": True, "value": 0},
        },
        "lm_compatibility_level": {"configured": True, "value": 2},
        "powershell_script_block_logging": {"configured": True, "value": 0},
        "wdigest_credential_caching_disabled": False,
        "llmnr_disabled": False,
        "autorun_disabled": False,
        "powershell_script_block_logging_enabled": False,
    }
    return document


def legacy_document(hostname: str = "LEGACY-PC") -> dict:
    """The old flat format the project shipped as an example."""
    return {
        "device": {"hostname": hostname, "os": "windows", "version": "Windows 11", "build": "26100"},
        "firewall": {"enabled": False},
        "bitlocker": {"enabled": False},
        "updates": {"days_since_patch": 15},
        "rdp": {"enabled": True},
        "smb": {"enabled": True},
    }


def snapshot_from(document: dict, *, signing_key: str | None = None) -> dict[str, Any]:
    """Wrap a document in a snapshot envelope with a valid integrity block."""
    from app.services.configuration_snapshot import calculate_snapshot_hash

    payload: dict[str, Any] = {
        "format": "SecureConfigAI Configuration Snapshot",
        "schema_version": document.get("schema_version", "1.2"),
        "snapshot_id": f"SCFG-TEST-{uuid.uuid4().hex[:12].upper()}",
        "created_at": "2026-10-06T12:00:00+00:00",
        "scanner": document.get("scanner", {"name": "SecureConfigAI Scanner", "version": "2.0.0"}),
        "device": document["device"],
        "checks": document["checks"],
        "collector_status": {
            k: {"status": v.get("status", "completed")}
            for k, v in document["checks"].items()
            if isinstance(v, dict)
        },
    }
    payload["integrity"] = {
        "algorithm": "SHA-256",
        "hash_scope": "snapshot_without_integrity",
        "sha256": calculate_snapshot_hash(payload),
    }
    if signing_key:
        from app.services.configuration_snapshot import compute_provenance_hmac

        snapshot_id = payload["snapshot_id"]
        timestamp = payload["created_at"]
        version = payload["scanner"]["version"]
        nonce = uuid.uuid4().hex
        digest = calculate_snapshot_hash(payload)
        payload["provenance"] = {
            "algorithm": "HMAC-SHA-256",
            "scan_id": snapshot_id,
            "timestamp": timestamp,
            "scanner_version": version,
            "nonce": nonce,
            "evidence_digest": digest,
            "hmac": compute_provenance_hmac(
                evidence_digest=digest,
                scan_id=snapshot_id,
                timestamp=timestamp,
                scanner_version=version,
                nonce=nonce,
                key=signing_key,
            ),
        }
    return payload
