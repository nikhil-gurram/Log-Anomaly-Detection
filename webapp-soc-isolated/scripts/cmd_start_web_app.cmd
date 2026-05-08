@echo off
setlocal
for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
cd /d "%PROJECT_ROOT%"

set "PY=%PROJECT_ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" (
	if exist "%PROJECT_ROOT%\..\.venv\Scripts\python.exe" (
		set "PY=%PROJECT_ROOT%\..\.venv\Scripts\python.exe"
	) else (
		set "PY=python"
	)
)

"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
endlocal
