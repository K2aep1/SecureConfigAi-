"""Collector implementations — one PowerShell invocation each.

Every concrete collector delegates its evidence gathering to a single program
in :mod:`scanner.scripts` and then *shapes* the raw result into the typed
payload the backend control engine reads (spec section 3).

Shaping rules applied consistently here:

* real booleans stay booleans, counts stay ints, nothing is stringified;
* an unreadable sub-block keeps its own ``status`` and reports ``None`` for
  every value rather than ``False``/``0``;
* derived booleans are computed with :func:`scanner.values.coerce_bool` and are
  ``None`` whenever the underlying evidence was absent;
* a missing top-level or sub-block status defaults to ``completed``; explicit
  non-completed top-level status is retained as an ``error`` in every payload;
* collector timeouts are per-collector slices and are scaled by the scan
  orchestrator when it allocates the overall scan budget.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, ClassVar

from scanner.base.collector import BaseCollector, CollectorUnavailable
from scanner.psrun import run_script
from scanner.scripts import script_for
from scanner.values import (
    as_int,
    as_str,
    carry_status,
    coerce_bool,
    one_or_many,
    reg_state,
)

__all__ = [
    "AccessControlCollector",
    "AccountSecurityCollector",
    "AuthenticationCollector",
    "DeviceCollector",
    "FirewallCollector",
    "InstalledSoftwareCollector",
    "NetworkInventoryCollector",
    "NetworkSecurityCollector",
    "PowerShellCollector",
    "RegistryCollector",
    "ServicesCollector",
    "SystemHardeningCollector",
    "TPMCollector",
    "UpdatesCollector",
    "build_collectors",
]


class PowerShellCollector(BaseCollector):
    """Base class for collectors backed by exactly one PowerShell program."""

    #: Per-collector slice of the wall-clock budget, before budget scaling.
    timeout_seconds: ClassVar[float] = 45.0

    def collect(self) -> dict[str, Any]:
        """Run the collector's PowerShell program once and shape the result."""
        raw = run_script(script_for(self.category), timeout=self.timeout_seconds)
        if not isinstance(raw, dict):
            raise CollectorUnavailable(
                f"{self.category}: PowerShell returned {type(raw).__name__}, not an object"
            )

        # Status handling belongs here, not in shape(): concrete collectors
        # override shape() and must not be able to discard a failed run.
        status = str(raw.get("status") or "completed").strip().lower()
        payload = self.shape(raw)
        # _collect_one() in ScannerOrchestrator owns final status normalisation.
        # Preserve the status here; popping it silently converted failed evidence
        # into a successful collector result.
        if status != "completed":
            if status not in {"unavailable", "skipped", "timeout", "error"}:
                status = "error"
            payload["status"] = status
            payload.setdefault("error", as_str(raw.get("error")) or status)
        return payload

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Convert the raw PowerShell document into the evidence payload."""
        return {key: value for key, value in raw.items() if key not in {"status", "error"}}


class DeviceCollector(PowerShellCollector):
    category = "device"
    stage = "Detecting device"
    requires_admin = False
    evidence_keys = ("hostname", "os", "version", "build")

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "hostname": as_str(raw.get("hostname")),
            "os": as_str(raw.get("os")),
            "name": as_str(raw.get("name")),
            "version": as_str(raw.get("version")),
            "build": as_str(raw.get("build")),
            "architecture": as_str(raw.get("architecture")),
            "install_date": as_str(raw.get("install_date")),
            "last_boot": as_str(raw.get("last_boot")),
            "serial_number": as_str(raw.get("serial_number")),
            "windows_directory": as_str(raw.get("windows_directory")),
            "computer_name": as_str(raw.get("computer_name")),
            "collection_error": as_str(raw.get("collection_error")),
            "serial_number_error": as_str(raw.get("serial_number_error")),
        }


class FirewallCollector(PowerShellCollector):
    """Firewall policy plus an aggregate rule summary computed inside PowerShell.

    One ``Get-NetFirewallRule`` pass, grouped in PowerShell.  No per-rule
    ``Get-NetFirewallPortFilter``/``AddressFilter``/``SecurityFilter`` calls and
    no filter payloads at all, because no control reads them.
    """

    category = "firewall"
    stage = "Collecting Windows Firewall policy"
    requires_admin = False
    evidence_keys = (
        "profiles",
        "logging",
        "enabled",
        "rule_summary",
    )
    timeout_seconds = 30.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        profiles: list[dict[str, Any]] = []
        for row in one_or_many(raw.get("profiles")):
            if not isinstance(row, dict):
                continue
            profiles.append(
                {
                    "name": as_str(row.get("name")),
                    "enabled": coerce_bool(row.get("enabled")),
                    "inbound": as_str(row.get("inbound")),
                    "outbound": as_str(row.get("outbound")),
                }
            )

        logging: dict[str, Any] = {}
        raw_logging = raw.get("logging")
        if isinstance(raw_logging, dict):
            for name, entry in raw_logging.items():
                if not isinstance(entry, dict):
                    continue
                logging[str(name)] = {
                    "LogBlocked": coerce_bool(entry.get("LogBlocked")),
                    "LogAllowed": coerce_bool(entry.get("LogAllowed")),
                    "LogFileName": as_str(entry.get("LogFileName")),
                    "LogMaxSizeKilobytes": as_int(entry.get("LogMaxSizeKilobytes")),
                }

        enabled_values = [profile["enabled"] for profile in profiles]
        enabled: bool | None
        if not profiles or any(value is None for value in enabled_values):
            enabled = None
        else:
            enabled = all(value is True for value in enabled_values)

        summary = raw.get("rule_summary")
        def shape_summary(value: Any) -> Any:
            if isinstance(value, dict):
                return {as_str(key) or str(key): shape_summary(item) for key, item in value.items()}
            if isinstance(value, list):
                return [shape_summary(item) for item in value[:200]]
            if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
                return value
            return as_str(value)

        rule_summary = shape_summary(summary) if isinstance(summary, dict) else None

        global_raw = raw.get("global_settings")
        global_settings = (
            {
                as_str(key) or str(key): coerce_bool(value)
                for key, value in global_raw.items()
            }
            if isinstance(global_raw, dict)
            else None
        )
        collection_raw = raw.get("collection")
        collection = (
            {as_str(key) or str(key): as_str(value) for key, value in collection_raw.items()}
            if isinstance(collection_raw, dict)
            else None
        )

        payload: dict[str, Any] = {
            "enabled": enabled,
            "profiles": profiles,
            "logging": logging,
            "rule_summary": rule_summary,
            "global_settings": global_settings,
            "collection": collection,
        }
        for key in ("profile_error", "rule_error", "settings_error"):
            value = as_str(raw.get(key))
            if value:
                payload[key] = value
        return payload


class SystemHardeningCollector(PowerShellCollector):
    """BitLocker, Defender, UAC and Secure Boot state in one invocation."""

    category = "system_hardening"
    stage = "Collecting Defender, BitLocker, UAC and Secure Boot state"
    requires_admin = False
    evidence_keys = (
        "bitlocker.enabled",
        "bitlocker.status",
        "bitlocker.volume_status",
        "bitlocker.protection_status",
        "defender.enabled",
        "defender.real_time_protection",
        "defender.tamper_protection",
        "defender.signature_age",
        "defender.status",
        "uac.status",
        "uac.EnableLUA",
        "uac.ConsentPromptBehaviorAdmin",
        "uac.PromptOnSecureDesktop",
        "uac_enabled",
        "secure_boot",
        "secure_boot_supported",
    )
    timeout_seconds = 40.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "bitlocker": self._bitlocker(raw.get("bitlocker")),
            "defender": self._defender(raw.get("defender")),
            "uac": self._uac(raw.get("uac")),
            "uac_enabled": coerce_bool(raw.get("uac_enabled")),
            "secure_boot": coerce_bool(raw.get("secure_boot")),
            "secure_boot_supported": coerce_bool(raw.get("secure_boot_supported")),
            "secure_boot_error": as_str(raw.get("secure_boot_error")),
        }

    @staticmethod
    def _bitlocker(raw: Any) -> dict[str, Any]:
        data = raw if isinstance(raw, dict) else {}
        status = str(data.get("status") or "completed").lower()
        volume = data.get("volume")
        return {
            "status": status,
            "error": as_str(data.get("error")),
            "enabled": coerce_bool(data.get("enabled")),
            "volume": volume if isinstance(volume, dict) else {},
            "volume_status": as_str(data.get("volume_status")),
            "protection_status": as_str(data.get("protection_status")),
            "volumes": one_or_many(data.get("volumes")),
        }

    @staticmethod
    def _defender(raw: Any) -> dict[str, Any]:
        data = raw if isinstance(raw, dict) else {}
        status = str(data.get("status") or "completed").lower()
        preferences_raw = data.get("preferences")
        preferences = (
            {
                as_str(key) or str(key): coerce_bool(value)
                for key, value in preferences_raw.items()
            }
            if isinstance(preferences_raw, dict)
            else None
        )
        return {
            "status": status,
            "error": as_str(data.get("error")),
            "enabled": coerce_bool(data.get("enabled")),
            "real_time_protection": coerce_bool(data.get("real_time_protection")),
            "antispyware_enabled": coerce_bool(data.get("antispyware_enabled")),
            "behavior_monitoring": coerce_bool(data.get("behavior_monitoring")),
            "ioav_protection": coerce_bool(data.get("ioav_protection")),
            "network_inspection": coerce_bool(data.get("network_inspection")),
            "tamper_protection": coerce_bool(data.get("tamper_protection")),
            "signature_version": as_str(data.get("signature_version")),
            "signature_age": as_int(data.get("signature_age")),
            "engine_version": as_str(data.get("engine_version")),
            "platform_version": as_str(data.get("platform_version")),
            "last_quick_scan": as_str(data.get("last_quick_scan")),
            "preferences": preferences,
        }

    @staticmethod
    def _uac(raw: Any) -> dict[str, Any]:
        data = raw if isinstance(raw, dict) else {}
        status = str(data.get("status") or "completed").lower()
        return {
            "status": status,
            "error": as_str(data.get("error")),
            "EnableLUA": as_int(data.get("EnableLUA")),
            "ConsentPromptBehaviorAdmin": as_int(data.get("ConsentPromptBehaviorAdmin")),
            "PromptOnSecureDesktop": as_int(data.get("PromptOnSecureDesktop")),
            "EnableInstallerDetection": as_int(data.get("EnableInstallerDetection")),
            "ValidateAdminCodeSignatures": as_int(data.get("ValidateAdminCodeSignatures")),
            "FilterAdministratorToken": as_int(data.get("FilterAdministratorToken")),
        }


class TPMCollector(PowerShellCollector):
    category = "tpm"
    stage = "Collecting TPM state"
    requires_admin = True
    evidence_keys = ("present", "ready", "enabled", "activated", "specification_version")
    timeout_seconds = 25.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "present": coerce_bool(raw.get("present")),
            "ready": coerce_bool(raw.get("ready")),
            "enabled": coerce_bool(raw.get("enabled")),
            "activated": coerce_bool(raw.get("activated")),
            "specification_version": as_str(raw.get("specification_version")),
            "manufacturer_version": as_str(raw.get("manufacturer_version")),
        }
        return carry_status(
            payload,
            raw,
            default_reason="TPM state is not readable in this context",
        )


class AuthenticationCollector(PowerShellCollector):
    """Password and lockout policy from ``secedit /export``, then ``net accounts``.

    The exported INF is parsed by non-localised key names.  If neither source
    works, ``source`` is ``None`` and every value is ``None`` — never ``0``.
    """

    category = "authentication"
    stage = "Collecting password and lockout policy"
    requires_admin = True
    evidence_keys = (
        "source",
        "minimum_length",
        "lockout_threshold",
        "lockout_duration",
        "maximum_password_age",
        "minimum_password_age",
        "complexity",
    )
    timeout_seconds = 25.0

    def collect(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="scai_secedit_") as workdir:
            inf_path = str(__import__("pathlib").Path(workdir) / "secpol.inf")
            raw = run_script(
                script_for(self.category),
                timeout=self.timeout_seconds,
                env={"SCAI_SECEDIT_PATH": inf_path},
            )
            if not isinstance(raw, dict):
                raise CollectorUnavailable(
                    f"{self.category}: PowerShell returned {type(raw).__name__}, not an object"
                )
            status = str(raw.get("status") or "completed").strip().lower()
            payload = self.shape(raw)
            if status != "completed":
                if status not in {"unavailable", "skipped", "timeout", "error"}:
                    status = "error"
                payload["status"] = status
                payload.setdefault("error", as_str(raw.get("error")) or status)
            return payload

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        source = as_str(raw.get("source"))
        if source not in {"secedit", "net_accounts"}:
            source = None
        errors = raw.get("probe_errors")
        payload: dict[str, Any] = {
            "source": source,
            "minimum_length": as_int(raw.get("minimum_length")),
            "lockout_threshold": as_int(raw.get("lockout_threshold")),
            "lockout_duration": as_int(raw.get("lockout_duration")),
            "maximum_password_age": as_int(raw.get("maximum_password_age")),
            "minimum_password_age": as_int(raw.get("minimum_password_age")),
            "complexity": coerce_bool(raw.get("complexity")),
        }
        if isinstance(errors, dict):
            payload["probe_errors"] = {key: as_str(value) for key, value in errors.items() if as_str(value)}
        return carry_status(
            payload,
            raw,
            default_reason="no password or lockout policy source was readable",
        )


class UpdatesCollector(PowerShellCollector):
    """Patch state via the Windows Update Agent, falling back to QFE.

    ``windows_update_com`` when the WUA search produced a usable install
    history, ``get_hotfix`` when only ``Win32_QuickFixEngineering`` answered.
    If both fail the collector reports ``unavailable`` with
    ``days_since_patch: null`` — that is deliberately **not** an error.
    """

    category = "updates"
    stage = "Collecting patch state"
    requires_admin = False
    evidence_keys = (
        "days_since_patch",
        "latest_hotfix.id",
        "latest_hotfix.installed_on",
        "source",
    )
    timeout_seconds = 45.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        source = as_str(raw.get("source"))
        if source not in {"windows_update_com", "get_hotfix"}:
            source = None
        latest = raw.get("latest_hotfix")
        latest_hotfix: dict[str, Any] | None = None
        if isinstance(latest, dict):
            latest_hotfix = {
                "id": as_str(latest.get("id")),
                "installed_on": as_str(latest.get("installed_on")),
            }
        payload: dict[str, Any] = {
            "source": source,
            "days_since_patch": as_int(raw.get("days_since_patch")) if source else None,
            "latest_hotfix": latest_hotfix,
            "pending_update_count": as_int(raw.get("pending_update_count")),
            "history": one_or_many(raw.get("history"))[:25],
        }
        diagnostics = raw.get("diagnostics")
        if isinstance(diagnostics, dict):
            payload["diagnostics"] = {
                key: as_str(value) for key, value in diagnostics.items() if as_str(value)
            }
        return carry_status(
            payload,
            raw,
            default_reason="neither the Windows Update Agent nor Win32_QuickFixEngineering answered",
        )


class AccountSecurityCollector(PowerShellCollector):
    category = "account_security"
    stage = "Checking account security"
    requires_admin = False
    evidence_keys = ("admin_count", "admins", "enabled_user_count")
    timeout_seconds = 30.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        admins: list[dict[str, Any]] = []
        for row in one_or_many(raw.get("admins")):
            if not isinstance(row, dict):
                continue
            admins.append(
                {
                    "name": as_str(row.get("Name")),
                    "object_class": as_str(row.get("ObjectClass")),
                    "principal_source": as_str(row.get("PrincipalSource")),
                }
            )
        nested_groups = [
            {"name": as_str(row.get("Name")),
             "object_class": as_str(row.get("ObjectClass")),
             "principal_source": as_str(row.get("PrincipalSource"))}
            for row in one_or_many(raw.get("nested_groups")) if isinstance(row, dict)
        ]
        diagnostics = raw.get("diagnostics")
        payload: dict[str, Any] = {
            "admin_count": as_int(raw.get("admin_count")),
            "admins": admins,
            "nested_groups": nested_groups,
            "excluded_group_members": as_int(raw.get("excluded_group_members")),
            "admins_complete": coerce_bool(raw.get("admins_complete")),
            "enabled_user_count": as_int(raw.get("enabled_user_count")),
        }
        if isinstance(diagnostics, dict):
            payload["diagnostics"] = {
                key: as_str(value) for key, value in diagnostics.items() if as_str(value)
            }
        return carry_status(
            payload,
            raw,
            default_reason="local administrator and local user membership were not readable",
        )


class ServicesCollector(PowerShellCollector):
    category = "services"
    stage = "Collecting security-relevant services"
    requires_admin = False
    evidence_keys = ("suspicious", "checked_services", "running_count")
    timeout_seconds = 30.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        suspicious: list[dict[str, Any]] = []
        for row in one_or_many(raw.get("suspicious")):
            if not isinstance(row, dict):
                continue
            suspicious.append({"name": as_str(row.get("name")), "state": as_str(row.get("state"))})
        services: list[dict[str, Any]] = []
        for row in one_or_many(raw.get("services")):
            if not isinstance(row, dict):
                continue
            services.append(
                {
                    "name": as_str(row.get("Name")),
                    "state": as_str(row.get("State")),
                    "start_mode": as_str(row.get("StartMode")),
                    "display_name": as_str(row.get("DisplayName")),
                }
            )
        return carry_status(
            {
                "checked_services": [name for item in one_or_many(raw.get("checked_services")) if (name := as_str(item)) is not None],
                "services": services,
                "suspicious": suspicious,
                "running_count": as_int(raw.get("running_count")),
            },
            raw,
            default_reason="service state was not readable",
        )


class AccessControlCollector(PowerShellCollector):
    category = "access_control"
    stage = "Checking access control"
    requires_admin = True
    evidence_keys = ("system_config_acl_protected",)
    timeout_seconds = 20.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        return carry_status(
            {
                "system_config_acl_protected": coerce_bool(raw.get("system_config_acl_protected")),
                "path": as_str(raw.get("path")),
            },
            raw,
            default_reason="the System32\\config ACL was not readable without elevation",
        )


class RegistryCollector(PowerShellCollector):
    """Registry hardening evidence plus its derived booleans.

    Absent values are ``{"configured": false, "value": null}`` and every derived
    boolean is ``None`` rather than ``False``.
    """

    category = "registry"
    stage = "Checking registry hardening"
    requires_admin = False
    evidence_keys = (
        "wdigest",
        "llmnr",
        "autorun",
        "netlogon.require_sign_or_seal",
        "netlogon.seal_secure_channel",
        "netlogon.sign_secure_channel",
        "netlogon.refuse_password_change",
        "lm_compatibility_level",
        "powershell_execution_policy",
        "powershell_script_block_logging",
        "wdigest_credential_caching_disabled",
        "llmnr_disabled",
        "autorun_disabled",
        "smb_signing_required",
        "lm_compatibility_ok",
        "powershell_script_block_logging_enabled",
    )
    timeout_seconds = 25.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        readings = raw.get("readings")
        readings = readings if isinstance(readings, dict) else {}

        def state(key: str) -> dict[str, Any]:
            return reg_state(readings.get(key), key)

        wdigest = state("wdigest")
        llmnr = state("llmnr")
        autorun = state("autorun")
        lm_level = state("lm_compatibility_level")
        script_block = state("powershell_script_block_logging")
        smb_signing = state("smb_server_require_security_signature")
        execution_policy = state("powershell_execution_policy")

        lm_value = as_int(lm_level["value"]) if lm_level["configured"] else None
        lm_ok: bool | None = None
        if lm_value is not None:
            lm_ok = lm_value >= 3

        payload: dict[str, Any] = {
            "wdigest": wdigest,
            "llmnr": llmnr,
            "autorun": autorun,
            "netlogon": {
                "require_sign_or_seal": state("netlogon_require_sign_or_seal"),
                "seal_secure_channel": state("netlogon_seal_secure_channel"),
                "sign_secure_channel": state("netlogon_sign_secure_channel"),
                "refuse_password_change": state("netlogon_refuse_password_change"),
            },
            "lm_compatibility_level": lm_level,
            "powershell_execution_policy": execution_policy,
            "powershell_script_block_logging": script_block,
            "wdigest_credential_caching_disabled": self._flag(wdigest, lambda v: as_int(v) == 0),
            "llmnr_disabled": self._flag(llmnr, lambda v: as_int(v) == 0),
            "autorun_disabled": self._flag(autorun, lambda v: as_int(v) == 255),
            "smb_signing_required": self._flag(smb_signing, lambda v: coerce_bool(v) is True),
            "lm_compatibility_ok": lm_ok,
            "powershell_script_block_logging_enabled": self._flag(
                script_block, lambda v: coerce_bool(v) is True
            ),
        }
        errors = as_str(raw.get("execution_policy_error"))
        if errors:
            payload["execution_policy_error"] = errors
        read_errors = {
            key: as_str(value.get("error"))
            for key, value in readings.items()
            if isinstance(value, dict) and as_str(value.get("error"))
        }
        if read_errors:
            payload["reading_errors"] = read_errors
        return carry_status(
            payload, raw,
            default_reason="registry evidence could not be read",
        )

    @staticmethod
    def _flag(state: dict[str, Any], predicate: Any) -> bool | None:
        """Derive a boolean, or ``None`` when the value was never configured."""
        if not state.get("configured") or state.get("value") is None:
            return None
        return bool(predicate(state.get("value")))


class NetworkSecurityCollector(PowerShellCollector):
    category = "network_security"
    stage = "Checking network security"
    requires_admin = False
    evidence_keys = (
        "rdp.enabled",
        "smb1.enabled",
        "smb_server.require_security_signature",
        "smb_server.smb1_protocol_enabled",
    )
    timeout_seconds = 30.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        rdp = raw.get("rdp") if isinstance(raw.get("rdp"), dict) else {}
        smb1 = raw.get("smb1") if isinstance(raw.get("smb1"), dict) else {}
        server = raw.get("smb_server") if isinstance(raw.get("smb_server"), dict) else {}
        return carry_status(
            {
                "rdp": {
                    "enabled": coerce_bool(rdp.get("enabled")),
                    "status": as_str(rdp.get("status")),
                    "error": as_str(rdp.get("error")),
                },
                "smb1": {
                    "enabled": coerce_bool(smb1.get("enabled")),
                    "status": as_str(smb1.get("status")),
                    "error": as_str(smb1.get("error")),
                },
                "smb_server": {
                    "require_security_signature": coerce_bool(server.get("require_security_signature")),
                    "smb1_protocol_enabled": coerce_bool(server.get("smb1_protocol_enabled")),
                    "status": as_str(server.get("status")),
                    "error": as_str(server.get("error")),
                },
            },
            raw,
            default_reason="RDP and SMB server configuration were not readable",
        )


class NetworkInventoryCollector(PowerShellCollector):
    """Inventory only: adapters, IPv4 addresses and connection profiles."""

    category = "network_inventory"
    stage = "Collecting network inventory"
    requires_admin = False
    inventory_only = True
    evidence_keys = ("adapters", "ipv4", "profiles", "counts")
    timeout_seconds = 35.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        def preserve_row(row: dict[str, Any]) -> dict[str, Any]:
            # Keep JSON-native bool/int/float values; stringify only date/time and
            # other provider objects that cannot safely cross the JSON boundary.
            shaped: dict[str, Any] = {}
            for key, value in row.items():
                name = as_str(key) or str(key)
                if value is None or isinstance(value, (bool, int, float, str)):
                    shaped[name] = value
                else:
                    shaped[name] = as_str(value)
            return shaped

        payload = {
            "adapters": [preserve_row(row) for row in one_or_many(raw.get("adapters")) if isinstance(row, dict)],
            "ipv4": [preserve_row(row) for row in one_or_many(raw.get("ipv4")) if isinstance(row, dict)],
            "profiles": [preserve_row(row) for row in one_or_many(raw.get("profiles")) if isinstance(row, dict)],
            "counts": ({as_str(key) or str(key): as_int(value) for key, value in raw["counts"].items()}
                       if isinstance(raw.get("counts"), dict) else {}),
            "errors": [as_str(item) for item in one_or_many(raw.get("errors")) if as_str(item)],
            "collection_status": as_str(raw.get("collection_status")) or "complete",
        }
        return carry_status(payload, raw, default_reason="all network inventory queries failed")


class InstalledSoftwareCollector(PowerShellCollector):
    """Inventory only: uninstall-registry applications, capped at 2000.

    ``Win32_Product`` is forbidden and never used — it reconfigures MSI packages.
    """

    category = "installed_software"
    stage = "Collecting installed software"
    requires_admin = False
    inventory_only = True
    evidence_keys = ("count", "applications")
    timeout_seconds = 40.0

    def shape(self, raw: dict[str, Any]) -> dict[str, Any]:
        applications: list[dict[str, Any]] = []
        for row in one_or_many(raw.get("applications")):
            if not isinstance(row, dict):
                continue
            applications.append(
                {
                    "name": as_str(row.get("name")),
                    "version": as_str(row.get("version")),
                    "publisher": as_str(row.get("publisher")),
                    "install_date": as_str(row.get("install_date")),
                }
            )
        count = as_int(raw.get("count"))
        payload = {
            "count": count,
            "truncated": coerce_bool(raw.get("truncated")) is True,
            "applications": applications[:2000],
            "source": as_str(raw.get("source")),
            "collection_status": as_str(raw.get("collection_status")) or "complete",
            "successful_sources": [as_str(x) for x in one_or_many(raw.get("successful_sources")) if as_str(x)],
            "errors": [as_str(x) for x in one_or_many(raw.get("errors")) if as_str(x)],
        }
        return carry_status(payload, raw, default_reason="installed software registry could not be read")


def build_collectors() -> list[BaseCollector]:
    """Return the full collector set in the frozen, deterministic order."""
    return [
        DeviceCollector(),
        FirewallCollector(),
        SystemHardeningCollector(),
        TPMCollector(),
        AuthenticationCollector(),
        UpdatesCollector(),
        AccountSecurityCollector(),
        ServicesCollector(),
        AccessControlCollector(),
        RegistryCollector(),
        NetworkSecurityCollector(),
        NetworkInventoryCollector(),
        InstalledSoftwareCollector(),
    ]
