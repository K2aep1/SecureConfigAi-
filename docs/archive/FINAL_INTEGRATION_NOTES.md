# SecureConfigAI v1-3 Final Integration Notes

This build is based on `SecureConfigAi v1-2(1)` plus the useful v1-3 Tier-1 changes and the requested scanner expansion.

## Added / expanded

1. **Network Configuration / Inventory**
   - Native PowerShell `Get-NetIPConfiguration`.
   - Captures interface alias/index, IPv4/IPv6, default gateway, DNS servers and network profile data.
   - Stored as `network_inventory` in raw checks and normalized output.

2. **Installed Software Inventory**
   - Uses Windows Registry Uninstall keys only.
   - Covers HKLM 64-bit, HKLM 32-bit/WOW6432Node and HKCU uninstall locations.
   - Does **not** use `Win32_Product`.
   - Captures name, version, publisher, install date/location, uninstall command and registry path.

3. **Registry Security / Hardening**
   - Expanded the real Registry Hardening Collector.
   - AutoRun, WDigest, LLMNR, Netlogon secure-channel settings and LocalMachine PowerShell execution policy.
   - Missing registry values are represented as `configured=false` / unknown rather than being treated as secure.
   - Adds deterministic findings for explicitly configured insecure WDigest, LLMNR and AutoRun values.

4. **OS Information**
   - Expanded the existing device collector using `Win32_OperatingSystem`.
   - Includes OS name, version/build, architecture, install date, last boot, serial number, Windows directory and computer name.
   - No duplicate OS collector was introduced.

5. **Update diagnostics**
   - `Get-HotFix` remains the existing update source.
   - No replacement was made.
   - Additional Windows Update diagnostics remain future work.

6. **Existing Tier-1 changes retained**
   - TPM collector.
   - Device/policy/admin management and AI chat sessions from the previous integration.

## Integrity / safety decisions

- No mock findings or fake Windows configuration were added.
- Scanner data comes from native Windows mechanisms when executed on Windows.
- Collector failures remain distinguishable from successful secure results.
- AI is not the source of truth for findings.
- No automatic remediation was added.

## Verification

- Python source compilation: passed for scanner and backend/app.
- Backend pytest was attempted but could not collect because the current environment is missing the `python-jose` dependency. This is an environment/dependency issue, not a claimed passing test run.
- A real scanner execution must be performed on the target Windows machine to validate native PowerShell output and permissions.
