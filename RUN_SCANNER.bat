@echo off
setlocal
cd /d "%~dp0"
if not exist "backend\.venv\Scripts\python.exe" (
  echo [ERROR] Backend virtual environment not found.
  pause
  exit /b 1
)
if not exist "scanner\manual_scan_output" mkdir "scanner\manual_scan_output"
echo Running Windows security scanner...
"backend\.venv\Scripts\python.exe" -m scanner.cli --output "%~dp0scanner\manual_scan_output" --elevate
if errorlevel 1 echo [ERROR] Scanner failed. Read the error above.
if exist "scanner\manual_scan_output\scan_result.json" (
  echo.
  echo Scan result created at:
  echo %~dp0scanner\manual_scan_output\scan_result.json
)
pause
