@echo off
setlocal EnableExtensions

for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
set "PY=%PROJECT_ROOT%\.venv\Scripts\python.exe"

if not exist "%PY%" (
  if exist "%PROJECT_ROOT%\..\.venv\Scripts\python.exe" (
    set "PY=%PROJECT_ROOT%\..\.venv\Scripts\python.exe"
  ) else (
    echo [ERROR] Python venv not found.
    exit /b 1
  )
)

cd /d "%PROJECT_ROOT%"
"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8088 --reload
