# Scanner Output Specification v1.2

**Status: FROZEN.** Contract between `scanner/` (producer) and `backend/` (consumer).
The backend's control engine reads **only** the keys listed under *Evidence contract*
below. Anything else is optional inventory and must be off by default.

## 1. Command line

```
python -m scanner.cli --output <dir> [--inventory] [--progress-json]
                      [--budget-seconds 120] [--collectors a,b,c]
                      [--elevate | --no-elevate] [--parallel 4]
```

* `--inventory` — include the three inventory collectors (network_inventory,
  installed_software, and listening-port evidence). Default **off**.
* `--progress-json` — write one JSON object per line to **stdout** as work
  progresses (see §4). Everything else goes to stderr.
* `--budget-seconds` — wall-clock budget for the whole run, default 120. When it
  expires, running collectors are aborted and the remaining collectors are
  recorded with `status: "skipped"`.
* `--elevate` — request UAC. The backend passes this **only** when
  `SCANNER_ELEVATE=true`; the default service path is `--no-elevate`.
* Exit code 0 = scan produced; 1 = the scan could not produce a result at all.

Writes `<output>/scan_result.json` (compact) and, when not disabled,
`<output>/configuration_snapshot.json` (compact, with integrity block).

## 2. Result document

```json
{
  "schema_version": "1.2",
  "format": "SecureConfigAI Configuration Snapshot",
  "snapshot_id": "SCFG-20261006-1A2B3C4D5E6F",
  "created_at": "2026-10-06T13:22:31.123456+00:00",
  "scanner": {
    "name": "SecureConfigAI Scanner", "version": "2.0.0", "platform": "windows",
    "status": "completed",            // completed | completed_with_errors | failed
    "collector_count": 13, "completed": 12, "errors": 0, "timeouts": 0, "skipped": 1,
    "duration_seconds": 21.437, "budget_seconds": 120, "inventory": false,
    "started_at": "...", "completed_at": "..."
  },
  "execution": {
    "user": "walid", "is_admin": true, "integrity_level": "high",
    "elevation_requested": false, "platform": "Windows-11-10.0.26200-SP0",
    "started_at": "...", "completed_at": "..."
  },
  "device": {
    "hostname": "HOST", "os": "windows", "version": "10.0.26200", "build": "26200",
    "name": "Windows 11 Pro", "architecture": "64-bit", "install_date": null,
    "last_boot": null, "serial_number": null, "windows_directory": null,
    "computer_name": null
  },
  "checks": { "<collector>": { "status": "...", "...": "..." } },
  "collector_status": {
    "<collector>": { "status": "completed", "duration_ms": 412.7, "error": null,
                     "required_privilege": "administrator", "evidence_status": "collected" }
  },
  "integrity": { "algorithm": "SHA-256", "hash_scope": "snapshot_without_integrity",
                 "sha256": "…" }
}
```

Rules:

1. **No duplication.** A collector payload appears exactly once, under
   `checks.<collector>`. There is no top-level copy and no
   `check_results.<collector>.raw/.normalized` copy. `collector_status` is a
   compact status map that must never embed payloads.
2. **Compact JSON.** `json.dumps(..., separators=(",", ":"), ensure_ascii=False)`,
   UTF-8, **no BOM**, `newline="\n"`.
3. **Honest absence.** A value that could not be read is `null` or the key is
   omitted. Never substitute `false` for "unknown", and never invent a default.
4. Every collector dict carries `status` ∈
   `completed | unavailable | skipped | timeout | error`.
   `completed` with a `null` value means "read succeeded, value unknown" and the
   engine will treat that control as `unknown`, which is correct.
5. Evidence values must be raw and typed (bool stays bool, int stays int, no
   stringified numbers) — string coercion is the engine's job, using a strict
   coercion that yields `null` for anything ambiguous.
6. When `status != "completed"`, include `"error": "<short reason>"`.

## 3. Evidence contract

The engine reads only these keys. Extra keys are allowed but must be small and
bounded; the payload target is **under 500 KB** for a default (non-inventory) scan.

| collector | keys read by the engine |
|---|---|
| `device` | `hostname`, `os`, `version`, `build` |
| `firewall` | `profiles[]` with `name`, `enabled` (bool), `inbound`, `outbound`; `logging{<profile>:{LogBlocked(bool),LogAllowed(bool)}}`; `enabled` (bool, derived); `rule_summary` (optional aggregate) |
| `system_hardening` | `bitlocker.enabled` (bool\|null), `bitlocker.status`, `bitlocker.volume.VolumeStatus`, `bitlocker.volume.ProtectionStatus`; `defender.enabled`, `defender.real_time_protection`, `defender.tamper_protection`, `defender.signature_age`, `defender.status`; `uac.status`, `uac.EnableLUA`, `uac.ConsentPromptBehaviorAdmin`, `uac.PromptOnSecureDesktop`; `uac_enabled` (bool\|null); `secure_boot` (bool\|null); `secure_boot_supported` (bool) |
| `tpm` | `present` (bool\|null), `ready` (bool\|null), `enabled`, `activated`, `specification_version` |
| `authentication` | `source` (`secedit`\|`net_accounts`\|null), `minimum_length` (int\|null), `lockout_threshold` (int\|null), `lockout_duration` (int\|null), `maximum_password_age` (int\|null), `minimum_password_age` (int\|null), `complexity` (bool\|null) |
| `network_security` | `rdp.enabled` (bool\|null), `smb1.enabled` (bool\|null), `smb_server.require_security_signature` (bool\|null), `smb_server.smb1_protocol_enabled` (bool\|null) |
| `updates` | `days_since_patch` (int\|null), `latest_hotfix.id`, `latest_hotfix.installed_on`, `source` (`windows_update_com`\|`get_hotfix`\|null) |
| `account_security` | `admin_count` (int\|null), `admins[]` (`name`, `object_class`, `principal_source`), `enabled_user_count` (int\|null) |
| `services` | `suspicious[]` (`name`, `state`), `checked_services[]`, `running_count` (int\|null) |
| `access_control` | `system_config_acl_protected` (bool\|null) |
| `registry` | `wdigest`, `llmnr`, `autorun`, `netlogon.{require_sign_or_seal,seal_secure_channel,sign_secure_channel,refuse_password_change}`, `lm_compatibility_level`, `powershell_execution_policy`, `powershell_script_block_logging` — each either `null`/absent, or `{"configured": bool, "value": <typed>}`; plus the derived booleans `wdigest_credential_caching_disabled`, `llmnr_disabled`, `autorun_disabled`, `smb_signing_required`, `lm_compatibility_ok`, `powershell_script_block_logging_enabled`, each `bool|null` |
| `network_inventory` *(inventory)* | `adapters[]`, `ipv4[]`, `profiles[]`, `counts` — aggregates, never full cmdlet objects |
| `installed_software` *(inventory)* | `count` (int), `applications[]` capped at 2000: `name`, `version`, `publisher`, `install_date` |

## 4. Progress protocol (`--progress-json`)

One JSON object per line on **stdout**, nothing else on stdout:

```json
{"event":"start","stage":"Detecting device","percent":0,"collector":null,"status":null,"duration_ms":null}
{"event":"collector","stage":"Collecting Windows Firewall policy","percent":38,"collector":"firewall","status":"completed","duration_ms":412.7}
{"event":"done","stage":"Analyzing configuration","percent":100,"collector":null,"status":"completed","duration_ms":21437.0}
```

`percent` is monotonically non-decreasing, 0..100. `event` ∈ `start|stage|collector|done|error`.

## 5. Performance requirements

| Requirement | Target |
|---|---|
| Default scan wall clock on a typical Windows 11 endpoint | ≤ 45 s (budget 120 s) |
| Default scan payload (non-inventory) | ≤ 500 KB |
| PowerShell process launches per default scan | ≤ 14 (one per collector, plus elevation) |
| Firewall collector | ≤ 15 s, aggregate rule summary computed inside one PowerShell call |
| Collectors may run in a bounded pool | default `--parallel 4`, results merged deterministically |
| Encoding | explicit UTF-8 both ways; never rely on the console code page |
| `ConvertTo-Json` | always explicit `-Depth` **and** `-Compress` |

## 6. Forbidden

* `Win32_Product` (it reconfigures MSI packages).
* Piping every firewall rule into per-rule filter cmdlets
  (`Get-NetFirewallRule | Get-NetFirewallPortFilter`-style N+1).
* `required=True` on evidence no control needs.
* Writing anything outside `--output` (except the progress lines on stdout).
* Silently converting an unreadable value into `false`/`0`.
* `indent=` in the written JSON.
