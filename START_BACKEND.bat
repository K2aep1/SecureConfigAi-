@echo off
setlocal
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Backend virtual environment not found.
  echo Create it with: python -m venv .venv
  pause
  exit /b 1
)
if not exist ".env" (
  copy /y ".env.example" ".env" >nul
  echo [INFO] Created backend\.env from .env.example.
  echo [ACTION REQUIRED] Set the PostgreSQL password in DATABASE_URL and a strong JWT_SECRET_KEY.
  echo [INFO] AI is optional and does not require an API key for deterministic scans.
  echo Edit backend\.env, save it, then press any key to continue.
  pause >nul
)
echo Applying database migrations...
".venv\Scripts\python.exe" -m alembic upgrade head
if errorlevel 1 (
  echo [ERROR] Database migration failed.
  pause
  exit /b 1
)
echo.
echo Starting SecureConfigAI Backend on http://127.0.0.1:8001
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
pause
