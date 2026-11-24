# SecureConfigAI V4 — Project Structure

## Root
- `backend/` — FastAPI application, database models, API routes, schemas, services, Alembic migrations and backend tests.
- `frontend/` — React + TypeScript + Vite application.
- `scanner/` — scanning integrations and scanner-side utilities.
- `scripts/` — development, maintenance and validation scripts.
- `docs/` — architecture, API contract, security model, scoring, troubleshooting and project notes.
- `.github/workflows/` — CI workflow definitions.
- `START_BACKEND.bat`, `START_FRONTEND.bat` — Windows development launchers.
- `README.md`, `README_AR.md` — project setup and usage guides.

## Deliberately excluded from the source package
- Local `.env` files and secrets. Copy `backend/.env.example` to `backend/.env` and fill in local values.
- Python caches, pytest/Ruff caches, local databases, compiled frontend `dist/`, and dependency folders.
- These are generated or machine-specific; recreate them locally when needed.

## Administration and User Management
The Administration page contains Users, Audit Log, and Storage sections. User management includes role updates, account enable/disable, lockout reset, refresh-session revocation, search, role/status filters, and confirmation for sensitive actions. All privileged operations are enforced by the backend and recorded in the audit log where supported.

## Development checks
- Backend: activate the virtual environment, install `backend/requirements.txt`, configure `backend/.env`, run Alembic migrations, then start FastAPI.
- Frontend: run `npm ci` and `npm run build` inside `frontend/`.
- Never commit real credentials, API keys, tokens, or local database files.
