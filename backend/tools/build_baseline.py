"""Generate the shipped Global Security Baseline pack.

Run from the project root:

    backend\\.venv\\Scripts\\python.exe backend\\tools\\build_baseline.py

Writes ``backend/app/data/baseline/global_baseline_v1.json``.

The baseline is deliberately data, not code: every control's identity, weight,
severity, category exposure, evaluation predicate, applicability rule, evidence
paths, rationale, remediation text and standard references live here. The
decision engine loads it, validates it, and can then be re-tuned by updating a
policy override row rather than by editing Python.

Reference policy
----------------
Standard references name the *benchmark and the exact Windows setting*, and the
organisational control from CIS Controls v8.1 / NIST SP 800-53 Rev. 5. Benchmark
recommendation numbering is intentionally NOT asserted because it changes between
benchmark revisions; the setting name is the stable, checkable identifier.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "app" / "data" / "baseline" / "global_baseline_v1.json"

# --------------------------------------------------------------------------- refs
URLS = {
    "cis-controls": "https://www.cisecurity.org/controls",
    "cis-benchmarks": "https://www.cisecurity.org/cis-benchmarks",
    "ms-baselines": (
        "https://learn.microsoft.com/en-us/windows/security/"
        "operating-system-security/device-management/"
        "windows-security-configuration-framework/windows-security-baselines"
    ),
    "ms-sct": (
        "https://learn.microsoft.com/en-us/windows/security/"
        "operating-system-security/device-management/"
        "windows-security-configuration-framework/security-compliance-toolkit-10"
    ),
    "nist-53": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    "nist-40": "https://csrc.nist.gov/pubs/sp/800/40/r4/final",
    "cisa-cm0087": "https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0087",
    "smbv1": (
        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/"
        "troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
    ),
    "bitlocker": "https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume",
    "defender": "https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus",
    "defender-csp": "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender",
    "uac": (
        "https://learn.microsoft.com/en-us/windows/security/application-security/"
        "application-control/user-account-control/settings-and-configuration"
    ),
    "firewall": "https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile",
    "smb-sign": "https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration",
    "password": (
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/"
        "security-policy-settings/password-policy"
    ),
    "lockout": (
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/"
        "security-policy-settings/account-lockout-policy"
    ),
    "wdigest": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/",
    "dnsclient": "https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientglobalsetting",
    "pslogging": (
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/"
        "about/about_logging_windows"
    ),
    "lmcompat": (
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/"
        "security-policy-settings/network-security-lan-manager-authentication-level"
    ),
    "netlogon": (
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/"
        "security-policy-settings/domain-member-digitally-encrypt-or-sign-secure-channel-data-always"
    ),
    "autorun": (
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/"
    ),
    "secedit": "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit",
    "secureboot": "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot",
    "tpm": "https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview",
    "services": (
        "https://learn.microsoft.com/en-us/windows-server/security/windows-services-security-and-permissions"
    ),
    "acl": "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls",
}

STD_TITLES = {
    "cis-controls-v8.1": "CIS Critical Security Controls v8.1",
    "cis-win11-benchmark": "CIS Microsoft Windows 11 Enterprise Benchmark",
    "ms-security-baseline": "Microsoft Security Baseline for Windows 11",
    "nist-sp-800-53r5": "NIST SP 800-53 Rev. 5",
    "nist-sp-800-40r4": "NIST SP 800-40 Rev. 4 (Patch Management)",
    "cisa-countermeasures": "CISA Eviction Strategies — Countermeasures",
    "microsoft-learn": "Microsoft Learn product documentation",
}


def ref(standard: str, control: str, url_key: str) -> dict:
    return {"standard": standard, "control": control, "url": URLS[url_key]}


def cis(control: str, url_key: str = "cis-controls") -> dict:
    return ref("cis-controls-v8.1", control, url_key)


CIS_WIN = lambda setting: ref("cis-win11-benchmark", setting, "cis-benchmarks")  # noqa: E731
MSB = lambda setting: ref("ms-security-baseline", setting, "ms-baselines")  # noqa: E731
NIST = lambda control: ref("nist-sp-800-53r5", control, "nist-53")  # noqa: E731
LEARN = lambda title, key: ref("microsoft-learn", title, key)  # noqa: E731

C = "checks."

# --------------------------------------------------------------------------- controls
CONTROLS: list[dict] = [
    {
        "control_id": "FW-001",
        "title": "Windows Firewall is enabled for every network profile",
        "category": "Firewall",
        "weight": 12,
        "severity": "high",
        "collector": "firewall",
        "expected_state": "Every profile (Domain, Private, Public) reports Enabled = True",
        "applicability": {"type": "always"},
        "evaluation": {"op": "all_bool_true", "paths": [C + "firewall.profiles[*].enabled"]},
        "evidence_paths": [C + "firewall.profiles"],
        "rationale": (
            "Host-based filtering is the last control between an endpoint and lateral "
            "movement. A disabled profile removes filtering entirely for that network "
            "type, including for inbound traffic the operator believes is blocked."
        ),
        "remediation": {
            "what_is_wrong": "One or more Windows Firewall profiles are disabled.",
            "why_it_matters": (
                "With a profile disabled, inbound connections are no longer filtered for "
                "that network type, so exposed services become reachable from the "
                "surrounding network."
            ),
            "what_should_be_done": (
                "Enable all profiles: Set-NetFirewallProfile -Profile Domain,Private,Public "
                "-Enabled True. Enforce it centrally with the Microsoft Security Baseline "
                "setting 'Windows Defender Firewall: Protect all network connections'."
            ),
            "verify": "Get-NetFirewallProfile | Select-Object Name, Enabled",
        },
        "references": [
            MSB("Windows Defender Firewall: Domain/Private/Public Profile: Firewall state = On"),
            CIS_WIN("Windows Defender Firewall: Domain/Private/Public Profile: Firewall state"),
            cis("CIS Control 4 — Secure Configuration of Enterprise Assets and Software"),
            NIST("SC-7 Boundary Protection"),
            NIST("CM-6 Configuration Settings"),
        ],
    },
    {
        "control_id": "FW-002",
        "title": "Firewall default inbound action is Block",
        "category": "Firewall",
        "weight": 10,
        "severity": "high",
        "collector": "firewall",
        "expected_state": "DefaultInboundAction = Block on every profile",
        "applicability": {"type": "always"},
        "evaluation": {"op": "enum_in", "paths": [C + "firewall.profiles[*].inbound"], "values": ["block"]},
        "evidence_paths": [C + "firewall.profiles[*].inbound"],
        "rationale": (
            "A permissive default inbound policy means every rule that is not explicitly "
            "denying traffic becomes reachable. Default-deny keeps the exposed surface equal "
            "to the explicit allow list."
        ),
        "remediation": {
            "what_is_wrong": "A firewall profile allows inbound connections by default.",
            "why_it_matters": (
                "Traffic that matches no explicit rule is accepted, so services added by "
                "later software are reachable without any firewall decision."
            ),
            "what_should_be_done": (
                "Set-NetFirewallProfile -Profile Domain,Private,Public "
                "-DefaultInboundAction Block, then review the allow rules that are still "
                "required."
            ),
            "verify": "Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction",
        },
        "references": [
            MSB("Windows Defender Firewall: Domain Profile: Inbound connections = Block"),
            CIS_WIN("Windows Defender Firewall: Domain/Private/Public Profile: Inbound connections"),
            NIST("SC-7 Boundary Protection"),
            NIST("AC-4 Information Flow Enforcement"),
        ],
    },
    {
        "control_id": "FW-003",
        "title": "Firewall logging is enabled for dropped and allowed traffic",
        "category": "Firewall",
        "weight": 6,
        "severity": "medium",
        "collector": "firewall",
        "expected_state": "LogBlocked = True and LogAllowed = True on every profile",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "all_bool_true",
            "paths": [C + "firewall.logging[*].LogBlocked", C + "firewall.logging[*].LogAllowed"],
        },
        "evidence_paths": [C + "firewall.logging"],
        "rationale": (
            "Firewall logs are the only local record of what the host rejected. Without them "
            "an investigation cannot distinguish 'nothing happened' from 'nothing was "
            "recorded'."
        ),
        "remediation": {
            "what_is_wrong": "Firewall logging is disabled for at least one profile.",
            "why_it_matters": (
                "Blocked connection attempts leave no local evidence, which removes the "
                "endpoint's contribution to detection and incident reconstruction."
            ),
            "what_should_be_done": (
                "Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True "
                "-LogAllowed True -LogMaxSizeKilobytes 16384, and forward the logs."
            ),
            "verify": (
                "Get-NetFirewallProfile | Select-Object Name, LogBlocked, LogAllowed, LogMaxSizeKilobytes"
            ),
        },
        "references": [
            MSB("Windows Defender Firewall: Domain Profile: Logging: Log dropped packets = Yes"),
            CIS_WIN("Windows Defender Firewall: Domain/Private/Public Profile: Logging"),
            cis("CIS Control 8 — Audit Log Management"),
            NIST("AU-2 Event Logging"),
            NIST("AU-12 Audit Record Generation"),
        ],
    },
    {
        "control_id": "BL-001",
        "title": "Operating-system volume is encrypted with protection active",
        "category": "System Hardening",
        "weight": 14,
        "severity": "critical",
        "collector": "system_hardening",
        "expected_state": "VolumeStatus = FullyEncrypted and ProtectionStatus = On for the OS volume",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "system_hardening.bitlocker.enabled"], "value": True},
        "evidence_paths": [C + "system_hardening.bitlocker"],
        "rationale": (
            "Full-volume encryption with protection on is what protects data at rest when a "
            "device is lost, stolen or booted from other media. Encryption that is suspended "
            "or still encrypting does not provide that protection yet."
        ),
        "remediation": {
            "what_is_wrong": "BitLocker is not fully applied and protected on the OS volume.",
            "why_it_matters": (
                "Anyone with physical access can read the volume offline, so credential "
                "material and business data are exposed without ever logging in."
            ),
            "what_should_be_done": (
                "Enable BitLocker with a TPM protector and escrow the recovery key: "
                "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 "
                "-TpmProtector, then confirm Protect-BitLocker -MountPoint C:."
            ),
            "verify": "Get-BitLockerVolume -MountPoint C: | Select-Object VolumeStatus, ProtectionStatus",
        },
        "references": [
            MSB("BitLocker Drive Encryption: Operating System Drives"),
            cis("CIS Control 3.6 — Encrypt Data on End-User Devices"),
            LEARN("Get-BitLockerVolume", "bitlocker"),
            NIST("SC-28 Protection of Information at Rest"),
            NIST("SC-13 Cryptographic Protection"),
        ],
    },
    {
        "control_id": "DEF-001",
        "title": "Microsoft Defender antivirus and real-time protection are enabled",
        "category": "Endpoint Protection",
        "weight": 12,
        "severity": "high",
        "collector": "system_hardening",
        "expected_state": "AntivirusEnabled = True and RealTimeProtectionEnabled = True",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "all_bool_true",
            "paths": [
                C + "system_hardening.defender.enabled",
                C + "system_hardening.defender.real_time_protection",
            ],
        },
        "evidence_paths": [C + "system_hardening.defender"],
        "rationale": (
            "Real-time protection is the endpoint's execution-time detection. It is read from "
            "Get-MpComputerStatus, which reports the effective state — reading the policy "
            "registry key instead produces false 'not configured' results on healthy hosts."
        ),
        "remediation": {
            "what_is_wrong": "Defender is disabled or running without real-time protection.",
            "why_it_matters": (
                "Without real-time scanning, known malware executes unchallenged and the "
                "host cannot be considered defended by antivirus."
            ),
            "what_should_be_done": (
                "Re-enable Defender: Set-MpPreference -DisableRealtimeMonitoring $false, and "
                "confirm the Microsoft Defender Antivirus policy 'Turn off real-time "
                "protection' is set to Disabled. If a third-party antivirus is the primary "
                "product, Defender legitimately runs in passive mode — record that decision "
                "as a device exemption with a reason."
            ),
            "verify": "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMRunningMode",
        },
        "references": [
            MSB("Microsoft Defender Antivirus: Turn off real-time protection = Disabled"),
            cis("CIS Control 10.1 — Deploy and Maintain Anti-Malware Software"),
            LEARN("Get-MpComputerStatus", "defender"),
            NIST("SI-3 Malicious Code Protection"),
        ],
    },
    {
        "control_id": "DEF-002",
        "title": "Microsoft Defender tamper protection is enabled",
        "category": "Endpoint Protection",
        "weight": 8,
        "severity": "medium",
        "collector": "system_hardening",
        "expected_state": "IsTamperProtected = True",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "bool_is",
            "paths": [C + "system_hardening.defender.tamper_protection"],
            "value": True,
        },
        "evidence_paths": [C + "system_hardening.defender.tamper_protection"],
        "rationale": (
            "Tamper protection stops malware and unprivileged administrators from disabling "
            "Defender, its real-time protection or its cloud-delivered protection."
        ),
        "remediation": {
            "what_is_wrong": "Defender tamper protection is off.",
            "why_it_matters": (
                "Malicious code that reaches the endpoint can turn off the protection that "
                "would have detected it, and the change is not blocked."
            ),
            "what_should_be_done": (
                "Enable tamper protection in Microsoft Defender for Endpoint (or with "
                "Set-MpPreference -DisableTamperProtection $false where supported) and confirm "
                "the setting is not overridden by a third-party security product."
            ),
            "verify": "Get-MpComputerStatus | Select-Object IsTamperProtected",
        },
        "references": [
            MSB("Microsoft Defender Antivirus: Tamper protection"),
            ref(
                "microsoft-learn",
                "Prevent changes to security settings with tamper protection",
                "defender-csp",
            ),
            cis("CIS Control 10 — Malware Defenses"),
            NIST("SI-3 Malicious Code Protection"),
        ],
    },
    {
        "control_id": "DEF-003",
        "title": "Microsoft Defender signatures are current",
        "category": "Endpoint Protection",
        "weight": 6,
        "severity": "medium",
        "collector": "system_hardening",
        "expected_state": "AntivirusSignatureAge <= 3 days",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "int_at_most",
            "paths": [C + "system_hardening.defender.signature_age"],
            "max": 3,
        },
        "evidence_paths": [
            C + "system_hardening.defender.signature_age",
            C + "system_hardening.defender.status",
        ],
        "rationale": (
            "Signature-based detection only covers what the signature set knows. A stale set "
            "is a measurable gap that can be closed without user action."
        ),
        "remediation": {
            "what_is_wrong": "Defender signatures are more than three days old.",
            "why_it_matters": (
                "Recent malware families are not recognised regardless of whether real-time "
                "protection is running."
            ),
            "what_should_be_done": (
                "Update-MpSignature and confirm automatic signature updates are enabled: "
                "Set-MpPreference -SignatureUpdateInterval 4 (hours)."
            ),
            "verify": "Get-MpComputerStatus | Select-Object AntivirusSignatureAge, AntivirusSignatureVersion",
        },
        "references": [
            MSB("Microsoft Defender Antivirus: Signature updates"),
            cis("CIS Control 10.2 — Configure Automatic Anti-Malware Signature Updates"),
            NIST("SI-3 Malicious Code Protection"),
        ],
    },
    {
        "control_id": "SYS-UAC-001",
        "title": "User Account Control is enabled for all administrators",
        "category": "System Hardening",
        "weight": 8,
        "severity": "high",
        "collector": "system_hardening",
        "expected_state": "EnableLUA = 1 (Run all administrators in Admin Approval Mode)",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "system_hardening.uac_enabled"], "value": True},
        "evidence_paths": [C + "system_hardening.uac"],
        "rationale": (
            "UAC keeps administrator tokens split so routine work runs unelevated. Disabling "
            "it makes every process the administrator starts fully privileged, which removes "
            "the main barrier to silent privilege abuse. Note that the built-in Administrator "
            "account (RID 500) bypasses UAC by design."
        ),
        "remediation": {
            "what_is_wrong": "User Account Control is disabled or not enforcing approval mode.",
            "why_it_matters": (
                "Every process started by an administrator runs with full privileges, so any "
                "compromised application inherits administrative control of the endpoint."
            ),
            "what_should_be_done": (
                "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
                "EnableLUA = 1 and reboot, and apply the Microsoft Security Baseline "
                "'User Account Control: Run all administrators in Admin Approval Mode' = "
                "Enabled."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA",
        },
        "references": [
            MSB("User Account Control: Run all administrators in Admin Approval Mode = Enabled"),
            CIS_WIN("User Account Control: Run all administrators in Admin Approval Mode"),
            LEARN("User Account Control settings and registry keys", "uac"),
            NIST("AC-6 Least Privilege"),
        ],
    },
    {
        "control_id": "SYS-UAC-002",
        "title": "Administrator elevation prompts for consent on the secure desktop",
        "category": "System Hardening",
        "weight": 6,
        "severity": "medium",
        "collector": "system_hardening",
        "expected_state": "ConsentPromptBehaviorAdmin = 2",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "int_is",
            "paths": [C + "system_hardening.uac.ConsentPromptBehaviorAdmin"],
            "value": 2,
        },
        "evidence_paths": [C + "system_hardening.uac"],
        "rationale": (
            "Prompting on the secure desktop prevents other processes from drawing over or "
            "driving the consent dialog, which is what makes UAC a security boundary rather "
            "than a notification."
        ),
        "remediation": {
            "what_is_wrong": "Administrator elevation does not require consent on the secure desktop.",
            "why_it_matters": (
                "A same-session process can spoof or auto-accept the elevation dialog, so a "
                "user may approve something other than what they believe they approved."
            ),
            "what_should_be_done": (
                "Set 'User Account Control: Behavior of the elevation prompt for "
                "administrators in Admin Approval Mode' to 'Prompt for consent on the secure "
                "desktop' (ConsentPromptBehaviorAdmin = 2)."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object ConsentPromptBehaviorAdmin, PromptOnSecureDesktop",
        },
        "references": [
            MSB(
                "User Account Control: Behavior of the elevation prompt for administrators in "
                "Admin Approval Mode = Prompt for consent on the secure desktop"
            ),
            CIS_WIN("User Account Control: Behavior of the elevation prompt for administrators"),
            LEARN("User Account Control settings and registry keys", "uac"),
            NIST("AC-6 Least Privilege"),
        ],
    },
    {
        "control_id": "DEV-SB-001",
        "title": "Secure Boot is enabled",
        "category": "Device Security",
        "weight": 8,
        "severity": "high",
        "collector": "system_hardening",
        "expected_state": "Secure Boot is enabled on UEFI firmware",
        "applicability": {"type": "when_supported", "paths": [C + "system_hardening.secure_boot_supported"]},
        "evaluation": {"op": "bool_is", "paths": [C + "system_hardening.secure_boot"], "value": True},
        "evidence_paths": [C + "system_hardening.secure_boot", C + "system_hardening.secure_boot_error"],
        "rationale": (
            "Secure Boot verifies the boot chain, which is what stops bootkits and "
            "unauthenticated kernel drivers from loading before the operating system's own "
            "controls start."
        ),
        "remediation": {
            "what_is_wrong": "Secure Boot is not enabled.",
            "why_it_matters": (
                "Unsigned or tampered boot components can load before Windows defences, "
                "surviving reinstallation of the operating system."
            ),
            "what_should_be_done": (
                "Enable Secure Boot in UEFI firmware settings (and disable legacy/CSM "
                "booting); confirm with Confirm-SecureBootUEFI after a reboot."
            ),
            "verify": "Confirm-SecureBootUEFI",
        },
        "references": [
            MSB("Secure Boot"),
            CIS_WIN("Ensure Secure Boot is enabled"),
            LEARN("Secure Boot overview", "secureboot"),
            NIST("SI-7 Software, Firmware, and Information Integrity"),
        ],
    },
    {
        "control_id": "TPM-001",
        "title": "TPM is present and ready",
        "category": "Device Security",
        "weight": 8,
        "severity": "high",
        "collector": "tpm",
        "expected_state": "TpmPresent = True and TpmReady = True",
        "applicability": {"type": "when_present", "paths": [C + "tpm.present"]},
        "evaluation": {"op": "bool_is", "paths": [C + "tpm.ready"], "value": True},
        "evidence_paths": [C + "tpm"],
        "rationale": (
            "The TPM is the hardware root of trust used for BitLocker key protection, "
            "credential Guard and measured boot. When it is present but not ready, those "
            "protections silently degrade."
        ),
        "remediation": {
            "what_is_wrong": "The TPM is not ready, or no TPM is present on a device that should have one.",
            "why_it_matters": (
                "Disk-encryption keys and platform measurements cannot be sealed to hardware, "
                "weakening the protections that depend on the TPM."
            ),
            "what_should_be_done": (
                "Enable the TPM in firmware, clear and re-initialise it if it is in an error "
                "state (Clear-Tpm / Initialize-Tpm), and confirm ownership is taken."
            ),
            "verify": "Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated",
        },
        "references": [
            MSB("Trusted Platform Module (TPM) requirements for BitLocker and Credential Guard"),
            CIS_WIN("Ensure TPM is enabled"),
            LEARN("Trusted Platform Module overview", "tpm"),
            NIST("SI-7 Software, Firmware, and Information Integrity"),
        ],
    },
    {
        "control_id": "AUTH-001",
        "title": "Minimum password length is at least 14 characters",
        "category": "Authentication",
        "weight": 10,
        "severity": "high",
        "collector": "authentication",
        "expected_state": "MinimumPasswordLength >= 14",
        "applicability": {"type": "always"},
        "evaluation": {"op": "int_at_least", "paths": [C + "authentication.minimum_length"], "min": 14},
        "evidence_paths": [C + "authentication.minimum_length", C + "authentication.source"],
        "rationale": (
            "Length is the dominant factor in offline guessing resistance for local "
            "accounts. The value is read from the exported security policy rather than parsed "
            "from localised console output, so it is correct on non-English builds and on "
            "domain-joined hosts (where the effective value may come from a domain policy — "
            "the recorded source is shown with the finding)."
        ),
        "remediation": {
            "what_is_wrong": "The effective minimum password length is below 14 characters.",
            "why_it_matters": (
                "Short passwords fall to offline cracking and spraying attacks, which is how "
                "local accounts are most often taken over."
            ),
            "what_should_be_done": (
                "Set 'Minimum password length' to 14 or more (secpol.msc, or secedit with "
                "MinimumPasswordLength = 14). On domain-joined devices change the domain "
                "policy instead, otherwise the local setting has no effect."
            ),
            "verify": (
                "secedit /export /cfg %TEMP%\\secpol.cfg & findstr MinimumPasswordLength %TEMP%\\secpol.cfg"
            ),
        },
        "references": [
            MSB("Account Policies: Password Policy: Minimum password length = 14 characters"),
            CIS_WIN("Account Policies: Password Policy: Minimum password length"),
            cis("CIS Control 5 — Account Management"),
            LEARN("Password policy", "password"),
            NIST("IA-5 Authenticator Management"),
        ],
    },
    {
        "control_id": "AUTH-002",
        "title": "Account lockout threshold is configured (1 to 10 attempts)",
        "category": "Authentication",
        "weight": 6,
        "severity": "medium",
        "collector": "authentication",
        "expected_state": "LockoutBadCount between 1 and 10",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "int_between",
            "paths": [C + "authentication.lockout_threshold"],
            "min": 1,
            "max": 10,
        },
        "evidence_paths": [C + "authentication.lockout_threshold", C + "authentication.source"],
        "rationale": (
            "A lockout threshold converts unlimited online guessing into a bounded, "
            "detectable event. Zero means no lockout at all, which is the failure this control "
            "exists to catch."
        ),
        "remediation": {
            "what_is_wrong": "Account lockout is disabled or the threshold is outside the 1-10 range.",
            "why_it_matters": (
                "Without lockout, an attacker can guess passwords indefinitely, and repeated "
                "failures raise no signal an operator can act on."
            ),
            "what_should_be_done": (
                "Set 'Account lockout threshold' to 10 or fewer invalid attempts, with "
                "'Account lockout duration' of 15 minutes or more, or 'until an administrator "
                "unlocks the account'."
            ),
            "verify": (
                "secedit /export /cfg %TEMP%\\secpol.cfg & findstr LockoutBadCount %TEMP%\\secpol.cfg"
            ),
        },
        "references": [
            MSB("Account Policies: Account Lockout Policy: Account lockout threshold"),
            CIS_WIN("Account Policies: Account Lockout Policy: Account lockout threshold"),
            LEARN("Account lockout policy", "lockout"),
            NIST("AC-7 Unsuccessful Logon Attempts"),
        ],
    },
    {
        "control_id": "AUTH-003",
        "title": "Password complexity requirements are enabled",
        "category": "Authentication",
        "weight": 6,
        "severity": "medium",
        "collector": "authentication",
        "expected_state": "PasswordComplexity = 1",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "authentication.complexity"], "value": True},
        "evidence_paths": [C + "authentication.complexity"],
        "rationale": (
            "Complexity rules prevent the weakest single-class passwords, which are the first "
            "entries in any guessing list. They are a floor, not a substitute for length."
        ),
        "remediation": {
            "what_is_wrong": "Password complexity is not required.",
            "why_it_matters": (
                "Single-character-class passwords are trivially enumerated, and the same "
                "password is frequently reused on other systems."
            ),
            "what_should_be_done": (
                "Enable 'Password must meet complexity requirements' "
                "(PasswordComplexity = 1 in the exported security policy)."
            ),
            "verify": "secedit /export /cfg %TEMP%\\secpol.cfg & findstr PasswordComplexity %TEMP%\\secpol.cfg",
        },
        "references": [
            MSB("Account Policies: Password Policy: Password must meet complexity requirements = Enabled"),
            CIS_WIN("Account Policies: Password Policy: Password must meet complexity requirements"),
            LEARN("Password policy", "password"),
            NIST("IA-5 Authenticator Management"),
        ],
    },
    {
        "control_id": "AUTH-004",
        "title": "Minimum password age is at least 1 day",
        "category": "Authentication",
        "weight": 4,
        "severity": "low",
        "collector": "authentication",
        "expected_state": "MinimumPasswordAge >= 1",
        "applicability": {"type": "always"},
        "evaluation": {"op": "int_at_least", "paths": [C + "authentication.minimum_password_age"], "min": 1},
        "evidence_paths": [C + "authentication.minimum_password_age"],
        "rationale": (
            "A minimum age prevents a user from cycling through the password history in one "
            "sitting to return to a previous password, which would defeat the history rule."
        ),
        "remediation": {
            "what_is_wrong": "Users can change their password again immediately.",
            "why_it_matters": (
                "Password history can be bypassed in minutes by changing the password "
                "repeatedly, so the old password can be restored."
            ),
            "what_should_be_done": "Set 'Minimum password age' to 1 day.",
            "verify": "secedit /export /cfg %TEMP%\\secpol.cfg & findstr MinimumPasswordAge %TEMP%\\secpol.cfg",
        },
        "references": [
            MSB("Account Policies: Password Policy: Minimum password age = 1 day"),
            CIS_WIN("Account Policies: Password Policy: Minimum password age"),
            LEARN("Password policy", "password"),
            NIST("IA-5 Authenticator Management"),
        ],
    },
    {
        "control_id": "NET-RDP-001",
        "title": "Remote Desktop is disabled unless it is required",
        "category": "Network Security",
        "weight": 9,
        "severity": "medium",
        "collector": "network_security",
        "expected_state": "fDenyTSConnections = 1 (Remote Desktop disabled)",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "network_security.rdp.enabled"], "value": False},
        "evidence_paths": [C + "network_security.rdp"],
        "rationale": (
            "Remote Desktop is the most exploited remote-access service on Windows and is "
            "repeatedly targeted by credential attacks. If it is not needed, the exposed "
            "service and its attack surface should not exist."
        ),
        "remediation": {
            "what_is_wrong": "Remote Desktop is enabled.",
            "why_it_matters": (
                "An internet- or network-reachable RDP endpoint invites password spraying "
                "and exploitation of pre-authentication vulnerabilities."
            ),
            "what_should_be_done": (
                "If RDP is not required, disable it: Set-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name fDenyTSConnections -Value 1. If it is required, require Network Level "
                "Authentication, restrict source addresses at the firewall, and record a "
                "device exemption with the justification."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' | Select-Object fDenyTSConnections",
        },
        "references": [
            CIS_WIN(
                "Remote Desktop Services: Allow users to connect remotely by using Remote Desktop Services"
            ),
            cis("CIS Control 4.8 — Uninstall or Disable Unnecessary Services"),
            NIST("CM-7 Least Functionality"),
            NIST("AC-17 Remote Access"),
        ],
    },
    {
        "control_id": "NET-SMB1-001",
        "title": "SMBv1 is disabled on the server",
        "category": "Network Security",
        "weight": 10,
        "severity": "high",
        "collector": "network_security",
        "expected_state": "EnableSMB1Protocol = False",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "network_security.smb1.enabled"], "value": False},
        "evidence_paths": [C + "network_security.smb1", C + "network_security.smb_server"],
        "rationale": (
            "SMBv1 is a 1980s protocol with no integrity protection and a history of remote "
            "code execution vulnerabilities. It is also the transport used by WannaCry-class "
            "worms for lateral movement."
        ),
        "remediation": {
            "what_is_wrong": "SMBv1 is enabled on the SMB server.",
            "why_it_matters": (
                "A single SMBv1 host can be used to relay or execute across the network, so "
                "one legacy system weakens the whole segment."
            ),
            "what_should_be_done": (
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force and remove the "
                "SMB1Protocol optional feature: Disable-WindowsOptionalFeature -Online "
                "-FeatureName SMB1Protocol -NoRestart. Verify no dependency (older scanners, "
                "print devices or NAS) requires it before removing the feature."
            ),
            "verify": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
        },
        "references": [
            MSB("Configure SMBv1 client and server"),
            cis("CIS Control 4 — Secure Configuration of Enterprise Assets and Software"),
            LEARN("Detect, enable, and disable SMBv1, SMBv2, and SMBv3", "smbv1"),
            NIST("CM-7 Least Functionality"),
        ],
    },
    {
        "control_id": "NET-SMB-SIGN-001",
        "title": "SMB server signing is required",
        "category": "Network Security",
        "weight": 8,
        "severity": "high",
        "collector": "network_security",
        "expected_state": "RequireSecuritySignature = True",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "bool_is",
            "paths": [C + "network_security.smb_server.require_security_signature"],
            "value": True,
        },
        "evidence_paths": [C + "network_security.smb_server"],
        "rationale": (
            "Requiring SMB signing blocks NTLM relay and man-in-the-middle tampering with "
            "SMB traffic, which is the mechanism behind many lateral-movement toolkits."
        ),
        "remediation": {
            "what_is_wrong": "The SMB server does not require packet signing.",
            "why_it_matters": (
                "Unsigned SMB traffic can be relayed and modified, letting an attacker reuse "
                "captured authentication without cracking it."
            ),
            "what_should_be_done": (
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force, or apply "
                "'Microsoft network server: Digitally sign communications (always)' = Enabled "
                "through Group Policy."
            ),
            "verify": "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature",
        },
        "references": [
            MSB("Microsoft network server: Digitally sign communications (always) = Enabled"),
            CIS_WIN("Microsoft network server: Digitally sign communications (always)"),
            LEARN("Get-SmbServerConfiguration", "smb-sign"),
            NIST("SC-8 Transmission Confidentiality and Integrity"),
        ],
    },
    {
        "control_id": "PATCH-001",
        "title": "Latest installed operating-system update is within 30 days",
        "category": "Updates",
        "weight": 10,
        "severity": "medium",
        "collector": "updates",
        "expected_state": "days_since_patch <= 30",
        "applicability": {"type": "always"},
        "evaluation": {"op": "int_at_most", "paths": [C + "updates.days_since_patch"], "max": 30},
        "evidence_paths": [C + "updates.days_since_patch", C + "updates.latest_hotfix", C + "updates.source"],
        "rationale": (
            "Patch age is a proxy for exposure to publicly known vulnerabilities. The newest "
            "installed update is read from the Windows Update Agent where possible, because "
            "Get-HotFix only reports Component Based Servicing packages and misses MSI and "
            "catalogue-delivered updates."
        ),
        "remediation": {
            "what_is_wrong": "No operating-system update has been installed in the last 30 days.",
            "why_it_matters": (
                "Publicly documented vulnerabilities with available fixes remain exploitable, "
                "and they are the most common initial access vector for commodity malware."
            ),
            "what_should_be_done": (
                "Install outstanding updates (Get-WindowsUpdate / Install-WindowsUpdate or "
                "Windows Update), confirm the update service is running and not blocked by "
                "policy, then re-scan."
            ),
            "verify": "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\").Updates.Count",
        },
        "references": [
            cis("CIS Control 7.3 — Perform Automated Operating System Patch Management"),
            LEARN("Get-HotFix and Windows Update Agent", "secedit"),
            ref("nist-sp-800-40r4", "Enterprise Patch Management Planning", "nist-40"),
            NIST("SI-2 Flaw Remediation"),
            NIST("RA-5 Vulnerability Monitoring and Scanning"),
        ],
    },
    {
        "control_id": "ACCT-001",
        "title": "Local administrator membership is minimized",
        "category": "Account Security",
        "weight": 7,
        "severity": "medium",
        "collector": "account_security",
        "expected_state": "admin_count <= 2",
        "applicability": {"type": "always"},
        "evaluation": {"op": "int_at_most", "paths": [C + "account_security.admin_count"], "max": 2},
        "evidence_paths": [C + "account_security.admins", C + "account_security.admin_count"],
        "rationale": (
            "Every additional local administrator is another credential set that yields full "
            "control of the endpoint and can disable its protections."
        ),
        "remediation": {
            "what_is_wrong": "More than two accounts are members of the local Administrators group.",
            "why_it_matters": (
                "Each administrator account is a complete compromise of the endpoint if its "
                "credentials leak, and unnecessary membership hides who can do what."
            ),
            "what_should_be_done": (
                "Remove unnecessary members (Remove-LocalGroupMember -Group Administrators "
                "-Member <account>), keep at most one dedicated local administrator plus the "
                "domain-managed group, and use just-in-time elevation for the rest."
            ),
            "verify": "Get-LocalGroupMember -Group Administrators",
        },
        "references": [
            cis("CIS Control 5.4 — Restrict Administrator Privileges to Dedicated Administrator Accounts"),
            CIS_WIN("Ensure 'Administrators' group membership is limited"),
            NIST("AC-6 Least Privilege"),
            NIST("AC-2 Account Management"),
        ],
    },
    {
        "control_id": "SVC-001",
        "title": "Selected legacy or network-facing services are not running",
        "category": "Services",
        "weight": 6,
        "severity": "medium",
        "collector": "services",
        "expected_state": "None of RemoteRegistry, TlntSvr, SSDPSRV or upnphost is running",
        "applicability": {"type": "always"},
        "evaluation": {"op": "list_empty", "paths": [C + "services.suspicious"]},
        "evidence_paths": [C + "services.suspicious", C + "services.checked_services"],
        "rationale": (
            "These services expose remote registry access, a telnet server and device "
            "discovery protocols that are regular lateral-movement and reconnaissance "
            "targets. None is required on a hardened workstation."
        ),
        "remediation": {
            "what_is_wrong": "A legacy or discovery service is running.",
            "why_it_matters": (
                "Remote Registry allows remote modification of the endpoint's configuration "
                "and is used by several credential-theft tools; SSDP/UPnP expose the host to "
                "the local network."
            ),
            "what_should_be_done": (
                "Stop and disable the service (Stop-Service -Name <name>; Set-Service -Name "
                "<name> -StartupType Disabled) after confirming no business dependency, then "
                "re-scan."
            ),
            "verify": (
                "Get-Service RemoteRegistry, TlntSvr, SSDPSRV, upnphost | "
                "Select-Object Name, Status, StartType"
            ),
        },
        "references": [
            cis("CIS Control 4.8 — Uninstall or Disable Unnecessary Services"),
            LEARN("Windows services security and permissions", "services"),
            NIST("CM-7 Least Functionality"),
        ],
    },
    {
        "control_id": "ACL-001",
        "title": "System configuration directory ACLs are protected",
        "category": "Access Control",
        "weight": 5,
        "severity": "medium",
        "collector": "access_control",
        "expected_state": "AreAccessRulesProtected = True on C:\\Windows\\System32\\config",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "bool_is",
            "paths": [C + "access_control.system_config_acl_protected"],
            "value": True,
        },
        "evidence_paths": [C + "access_control"],
        "rationale": (
            "The configuration directory holds the SAM, SECURITY and SYSTEM hives. If "
            "inheritance from a permissive parent is re-enabled, the local account database "
            "becomes readable to non-administrators."
        ),
        "remediation": {
            "what_is_wrong": "Access rules on the system configuration directory are not protected.",
            "why_it_matters": (
                "Credential material and local policy can be read or altered by accounts that "
                "should have no access to them."
            ),
            "what_should_be_done": (
                "Re-enable protection of the ACL: icacls C:\\Windows\\System32\\config /inheritance:r "
                "with SYSTEM and Administrators full control, matching the default Windows ACL."
            ),
            "verify": "(Get-Acl C:\\Windows\\System32\\config).AreAccessRulesProtected",
        },
        "references": [
            CIS_WIN("Ensure permissions on the system configuration directory are restricted"),
            LEARN("icacls", "acl"),
            NIST("AC-3 Access Enforcement"),
            NIST("AC-6 Least Privilege"),
        ],
    },
    {
        "control_id": "REG-WDIGEST-001",
        "title": "WDigest credential caching is disabled",
        "category": "Registry Hardening",
        "weight": 8,
        "severity": "high",
        "collector": "registry",
        "expected_state": "UseLogonCredential is absent or 0",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "bool_is",
            "paths": [C + "registry.wdigest_credential_caching_disabled"],
            "value": True,
        },
        "evidence_paths": [C + "registry.wdigest"],
        "rationale": (
            "With WDigest credential caching enabled, the plaintext password is retained in "
            "LSASS memory, where credential-dumping tools recover it directly. CISA documents "
            "this as a specific eviction countermeasure."
        ),
        "remediation": {
            "what_is_wrong": "WDigest is configured to cache plaintext credentials (or the value is unknown).",
            "why_it_matters": (
                "Any credential dump of LSASS yields reusable plaintext passwords instead of "
                "hashes, removing the need for cracking and enabling immediate lateral movement."
            ),
            "what_should_be_done": (
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\"
                "UseLogonCredential to 0 (or delete the value), reboot, and confirm it persists "
                "after Group Policy refresh. On systems older than Windows 8.1/2012 R2, "
                "KB2871997 is required."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential",
        },
        "references": [
            ref("cisa-countermeasures", "CM0087 — Disable Credential Caching in WDigest", "cisa-cm0087"),
            CIS_WIN("Ensure 'WDigest Authentication' is disabled"),
            NIST("IA-5 Authenticator Management"),
            NIST("SC-28 Protection of Information at Rest"),
        ],
    },
    {
        "control_id": "REG-LLMNR-001",
        "title": "Link-Local Multicast Name Resolution (LLMNR) is disabled",
        "category": "Registry Hardening",
        "weight": 6,
        "severity": "medium",
        "collector": "registry",
        "expected_state": "EnableMulticast = 0",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "registry.llmnr_disabled"], "value": True},
        "evidence_paths": [C + "registry.llmnr"],
        "rationale": (
            "LLMNR answers are unauthenticated, so any host on the segment can answer a "
            "resolution request and harvest NetNTLM hashes for offline cracking or relay."
        ),
        "remediation": {
            "what_is_wrong": "LLMNR name resolution is enabled.",
            "why_it_matters": (
                "An attacker on the same network can impersonate any unresolved name and "
                "collect authentication material without user interaction."
            ),
            "what_should_be_done": (
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast "
                "to 0 via Group Policy ('Turn off multicast name resolution'), and disable "
                "NetBIOS over TCP/IP on the same adapters."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast",
        },
        "references": [
            CIS_WIN("Ensure 'Turn off multicast name resolution' is set to 'Enabled'"),
            LEARN("Get-DnsClientGlobalSetting", "dnsclient"),
            cis("CIS Control 9 — Email and Web Browser Protections"),
            NIST("SC-20 Secure Name/Address Resolution Service"),
        ],
    },
    {
        "control_id": "REG-AUTORUN-001",
        "title": "AutoRun and AutoPlay are disabled on all drives",
        "category": "Registry Hardening",
        "weight": 5,
        "severity": "medium",
        "collector": "registry",
        "expected_state": "NoDriveTypeAutoRun = 255",
        "applicability": {"type": "always"},
        "evaluation": {"op": "bool_is", "paths": [C + "registry.autorun_disabled"], "value": True},
        "evidence_paths": [C + "registry.autorun"],
        "rationale": (
            "AutoRun executes content from removable media the moment it is attached. "
            "Disabling it across all drive types removes a delivery path that requires no "
            "user decision."
        ),
        "remediation": {
            "what_is_wrong": "AutoRun is enabled for at least one drive type.",
            "why_it_matters": (
                "Malicious content on removable media can execute automatically, which is how "
                "air-gapped environments are commonly bridged."
            ),
            "what_should_be_done": (
                "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"
                "NoDriveTypeAutoRun to 255 (0xFF) and apply 'Turn off Autoplay' = "
                "'Enabled: All drives'."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun",
        },
        "references": [
            CIS_WIN("Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"),
            CIS_WIN("Ensure 'Do not execute any autorun commands' is set to 'Enabled'"),
            cis("CIS Control 4 — Secure Configuration of Enterprise Assets and Software"),
            NIST("CM-6 Configuration Settings"),
        ],
    },
    {
        "control_id": "REG-NETLOGON-001",
        "title": "Netlogon secure-channel signing and sealing are required",
        "category": "Registry Hardening",
        "weight": 6,
        "severity": "medium",
        "collector": "registry",
        "expected_state": "RequireSignOrSeal = 1, SignSecureChannel = 1, SealSecureChannel = 1",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "all_int_at_least",
            "paths": [
                C + "registry.netlogon.require_sign_or_seal.value",
                C + "registry.netlogon.sign_secure_channel.value",
                C + "registry.netlogon.seal_secure_channel.value",
            ],
            "min": 1,
        },
        "evidence_paths": [C + "registry.netlogon"],
        "rationale": (
            "Signing and sealing the computer-account secure channel protects the domain "
            "authentication traffic from tampering and disclosure — the basis of "
            "zero-login attacks such as Zerologon-class exploitation."
        ),
        "remediation": {
            "what_is_wrong": "Netlogon secure-channel signing or sealing is not required.",
            "why_it_matters": (
                "Unsigned or unsealed domain authentication traffic can be intercepted or "
                "modified, allowing credential abuse and machine-account takeover."
            ),
            "what_should_be_done": (
                "Apply the Microsoft Security Baseline settings 'Domain member: Digitally "
                "encrypt or sign secure channel data (always)' = Enabled, 'Domain member: "
                "Digitally sign secure channel data (when possible)' = Enabled, and 'Domain "
                "member: Require strong (Windows 2000 or later) session key' = Enabled."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' | Select-Object RequireSignOrSeal, SignSecureChannel, SealSecureChannel",
        },
        "references": [
            MSB("Domain member: Digitally encrypt or sign secure channel data (always) = Enabled"),
            CIS_WIN("Domain member: Digitally encrypt or sign secure channel data (always)"),
            LEARN("Domain member: Digitally encrypt or sign secure channel data", "netlogon"),
            NIST("SC-8 Transmission Confidentiality and Integrity"),
        ],
    },
    {
        "control_id": "REG-LMCOMPAT-001",
        "title": "LAN Manager authentication level refuses LM and NTLM",
        "category": "Registry Hardening",
        "weight": 8,
        "severity": "high",
        "collector": "registry",
        "expected_state": "LmCompatibilityLevel >= 5 (send NTLMv2 only, refuse LM and NTLM)",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "int_at_least",
            "paths": [C + "registry.lm_compatibility_level.value"],
            "min": 5,
        },
        "evidence_paths": [C + "registry.lm_compatibility_level"],
        "rationale": (
            "Weak LM and NTLM responses can be captured and cracked in seconds, or relayed. "
            "Level 5 forces NTLMv2 and refuses the legacy protocols outright."
        ),
        "remediation": {
            "what_is_wrong": "The LAN Manager authentication level still permits LM or NTLM responses.",
            "why_it_matters": (
                "Captured LM/NTLM challenge responses are trivially cracked, giving an "
                "attacker reusable credentials from passive network access."
            ),
            "what_should_be_done": (
                "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 "
                "response only. Refuse LM and NTLM' (LmCompatibilityLevel = 5), and audit for "
                "legacy applications that still require NTLM before enforcing it."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel",
        },
        "references": [
            MSB(
                "Network security: LAN Manager authentication level = Send NTLMv2 response only. "
                "Refuse LM and NTLM"
            ),
            CIS_WIN("Network security: LAN Manager authentication level"),
            LEARN("Network security: LAN Manager authentication level", "lmcompat"),
            NIST("IA-5 Authenticator Management"),
            NIST("SC-8 Transmission Confidentiality and Integrity"),
        ],
    },
    {
        "control_id": "REG-PSLOGGING-001",
        "title": "PowerShell script block logging is enabled",
        "category": "Registry Hardening",
        "weight": 5,
        "severity": "medium",
        "collector": "registry",
        "expected_state": "ScriptBlockLogging Enabled = 1",
        "applicability": {"type": "always"},
        "evaluation": {
            "op": "bool_is",
            "paths": [C + "registry.powershell_script_block_logging_enabled"],
            "value": True,
        },
        "evidence_paths": [C + "registry.powershell_script_block_logging"],
        "rationale": (
            "PowerShell is the most common post-exploitation and lateral-movement toolchain "
            "on Windows. Script block logging records the actual code that ran, including "
            "obfuscated and dynamically constructed commands."
        ),
        "remediation": {
            "what_is_wrong": "PowerShell script block logging is not enabled.",
            "why_it_matters": (
                "Malicious PowerShell activity leaves little evidence, so intrusions are "
                "detected late or not at all, and forensic reconstruction is impossible."
            ),
            "what_should_be_done": (
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\"
                "EnableScriptBlockLogging = 1, forward the PowerShell operational log to the "
                "SIEM, and ensure the log size is sufficient."
            ),
            "verify": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging",
        },
        "references": [
            MSB("Turn on PowerShell Script Block Logging = Enabled"),
            CIS_WIN("Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'"),
            LEARN("about_Logging_Windows", "pslogging"),
            cis("CIS Control 8 — Audit Log Management"),
            NIST("AU-2 Event Logging"),
            NIST("AU-12 Audit Record Generation"),
        ],
    },
]

# --------------------------------------------------------------------------- pack
CATEGORY_EXPOSURE = {
    "Firewall": 4,
    "Network Security": 5,
    "Authentication": 4,
    "Account Security": 4,
    "Endpoint Protection": 4,
    "Updates": 4,
    "System Hardening": 3,
    "Registry Hardening": 3,
    "Access Control": 3,
    "Device Security": 3,
    "Services": 3,
}

SEVERITY_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

PACK = {
    "baseline_id": "secureconfigai-windows-endpoint",
    "version": "1.0.0",
    "schema_version": "1.0",
    "title": "SecureConfigAI Windows Endpoint Security Baseline",
    "description": (
        "A 28-control endpoint hardening baseline for Windows 10/11 workstations and "
        "member servers, mapped to the CIS Critical Security Controls v8.1, the CIS "
        "Microsoft Windows 11 Enterprise Benchmark, the Microsoft Security Baseline for "
        "Windows 11 and NIST SP 800-53 Rev. 5. Control weights express relative security "
        "impact and are used as the denominator weighting for the posture and coverage "
        "metrics."
    ),
    "published_at": datetime(2026, 10, 6, tzinfo=UTC).isoformat(),
    "reference_policy": (
        "References name the benchmark and the exact Windows setting, plus organisational "
        "controls from CIS Controls v8.1 and NIST SP 800-53 Rev. 5. Benchmark recommendation "
        "numbering is intentionally omitted because it changes between benchmark revisions; "
        "the setting name is the stable identifier. Adjust the standard titles to the exact "
        "benchmark revision your organisation has adopted."
    ),
    "references": [
        {
            "id": k,
            "title": v,
            "url": {
                "cis-controls-v8.1": URLS["cis-controls"],
                "cis-win11-benchmark": URLS["cis-benchmarks"],
                "ms-security-baseline": URLS["ms-baselines"],
                "nist-sp-800-53r5": URLS["nist-53"],
                "nist-sp-800-40r4": URLS["nist-40"],
                "cisa-countermeasures": URLS["cisa-cm0087"],
                "microsoft-learn": URLS["ms-baselines"],
            }[k],
        }
        for k, v in STD_TITLES.items()
    ],
    "thresholds": {
        "risk": {"low_max": 15, "moderate_max": 39, "high_max": 69},
        "risk_model": {
            "single_control_likelihood": 0.5,
            "aggregation": "noisy_or",
            "formula": (
                "impact_i = severity_impact_i * category_exposure_i * "
                "asset_criticality / 125; "
                "risk = 100 * (1 - product(1 - L * impact_i)); L = "
                "single_control_likelihood"
            ),
        },
        "evidence_quality": {"high_coverage": 100, "medium_coverage": 75},
        "posture_bands": {"strong": 90, "adequate": 75, "weak": 50},
    },
    "categories": {
        name: {
            "exposure": exposure,
            "description": f"Security impact weighting for the {name} control family",
        }
        for name, exposure in CATEGORY_EXPOSURE.items()
    },
    "severity_impact": SEVERITY_IMPACT,
    "controls": CONTROLS,
}

if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    ids = [c["control_id"] for c in CONTROLS]
    assert len(ids) == len(set(ids)), "duplicate control_id"
    for c in CONTROLS:
        assert c["category"] in CATEGORY_EXPOSURE, c["control_id"]
        assert c["severity"] in SEVERITY_IMPACT, c["control_id"]
        assert c["references"], c["control_id"]
        assert c["remediation"]["verify"], c["control_id"]
    OUT.write_text(json.dumps(PACK, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    total = sum(c["weight"] for c in CONTROLS)
    print(f"wrote {OUT}")
    print(f"controls={len(CONTROLS)} total_weight={total}")
    by_cat: dict[str, int] = {}
    for c in CONTROLS:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    print("by category:", dict(sorted(by_cat.items())))
    print("by severity:", {s: sum(1 for c in CONTROLS if c["severity"] == s) for s in SEVERITY_IMPACT})
