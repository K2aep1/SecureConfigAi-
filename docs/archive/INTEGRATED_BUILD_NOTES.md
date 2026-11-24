# SecureConfigAI — Integrated Build

## Baseline
This build is based on `SecureConfigAi v1-2` as the project baseline.

## Integrated changes
Selected, reviewed changes from the experimental `v1-3_Tier1Complete` build were integrated without replacing the original project architecture:

- TPM collection using the native Windows `Get-Tpm` PowerShell cmdlet.
- Standalone Registry hardening collector for selected security-related registry settings.
- Policy update, enable/disable, and delete API operations.
- Device update and delete API operations while preserving historical scan records.
- Admin user enable/disable API with self-disable protection.
- Persistent AI chat session listing and conversation continuation.
- Frontend access to Devices, Policies, Admin, and AI Chat functionality.
- Additional automated API tests for the integrated features.
- Normalized TPM and Registry data in the scan output.

## Intentionally not copied
- No replacement of the v1-2 architecture with a new architecture.
- No Tier 2 fleet/team features.
- No Tier 3 stretch features.
- No changes to the core scoring philosophy.
- No fake/demo findings or synthetic Windows configuration data were introduced.

## Verification performed
- Python source compilation completed successfully.
- `__pycache__` artifacts were removed from the packaged build.

## Important
The frontend was not browser-built in this environment because its npm dependencies are not installed here. Run `npm install` and `npm run build` in `frontend/` on the development machine before treating the build as fully integration-tested.
