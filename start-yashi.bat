@echo off
chcp 65001 >nul
title Yashi Launcher
color 0B

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

echo ============================================================
echo                 YASHI ALL-IN-ONE LAUNCHER
echo ============================================================
echo.

echo [1/5] Cleaning up any old instances...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":3000" ^| findstr "LISTENING"') do (
    echo     Killing stale process on port 3000 ^(PID %%a^)
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8765" ^| findstr "LISTENING"') do (
    echo     Killing stale process on port 8765 ^(PID %%a^)
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 1 /nobreak >nul
echo     Done.
echo.

echo [2/5] Checking Node.js dependencies...
where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found on PATH. Please install Node.js 20+ from https://nodejs.org
    pause
    exit /b 1
)

if not exist "node_modules\" (
    echo     Installing Node dependencies ^(npm install^)...
    call npm install
    echo     Node dependencies installed.
) else (
    echo     Node dependencies OK.
)
echo.

echo [3/5] Setting up Python environment...
set "PYTHON_EXE=python"
where py >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_EXE=py -3"
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python was not found on PATH. Please install Python 3.10+ from python.org.
        pause
        exit /b 1
    )
)

if not exist ".venv\" (
    echo     Creating isolated Python virtual environment ^(.venv^)...
    %PYTHON_EXE% -m venv .venv
)

set "AGENT_PYTHON=%PROJECT_DIR%.venv\Scripts\python.exe"
set "AGENT_PIP=%PROJECT_DIR%.venv\Scripts\pip.exe"
if not exist "%AGENT_PYTHON%" (
    set "AGENT_PYTHON=%PYTHON_EXE%"
    set "AGENT_PIP=%PYTHON_EXE% -m pip"
)

"%AGENT_PYTHON%" -c "import fastapi" >nul 2>nul
if errorlevel 1 (
    echo     Installing desktop agent dependencies...
    "%AGENT_PIP%" install -r desktop_agent\requirements.txt --quiet
    echo     Python dependencies installed.
) else (
    echo     Python dependencies OK.
)
echo.

echo [4/5] Starting Desktop Control Agent ^(Python, port 8765^)...
start "Yashi Desktop Agent" /MIN cmd /k "cd /d "%PROJECT_DIR%" && "%AGENT_PYTHON%" -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765"
echo     Launching in background window...
echo.

echo [5/5] Waiting for Desktop Agent to be ready...
set "READY=0"
for /l %%i in (1,1,15) do (
    timeout /t 1 /nobreak >nul
    powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8765/health' -UseBasicParsing -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
    if not errorlevel 1 (
        set "READY=1"
        echo     Desktop Agent is ONLINE - 240 tools ready!
        goto :agent_ready
    )
    echo     ...waiting %%i/15
)
:agent_ready
if "%READY%"=="0" (
    echo     [WARNING] Desktop Agent did not respond in time.
    echo     Yashi will still run, but desktop control may be unavailable.
)
echo.

echo Starting Yashi UI ^(port 3000^)...
echo ============================================================
echo   Desktop Agent : http://127.0.0.1:8765
echo   Yashi UI       : http://localhost:3000
echo ============================================================
echo.
echo   Close this window to stop Yashi.
echo.

call npm run dev

echo.
echo Yashi has stopped. Cleaning up Desktop Agent...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8765" ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)
pause
