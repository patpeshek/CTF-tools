@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem Port and address. Can be overridden by environment variables:
rem   set PORT=9000
rem   start_site.bat
if not defined PORT set "PORT=8771"
if not defined BIND set "BIND=127.0.0.1"

set "CURL=%SystemRoot%\System32\curl.exe"
if not exist "%CURL%" set "CURL=curl"

rem --- find Python ---
set "PY="
python -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY=python"
if not defined PY (
    py -3 -c "import sys" >nul 2>&1
    if not errorlevel 1 set "PY=py -3"
)
if not defined PY (
    echo [x] Python not found.
    echo     Install Python 3 and add it to PATH: https://www.python.org/downloads/
    pause
    exit /b 1
)

rem --- is the site already running? health answers {"ok": true, ...} ---
set "PROBE=%TEMP%\toolbox_site_health.txt"
del "%PROBE%" >nul 2>&1
"%CURL%" -s -f -m 2 "http://127.0.0.1:%PORT%/health" >"%PROBE%" 2>nul

set "RUNNING="
if exist "%PROBE%" (
    findstr /c:"ok" "%PROBE%" >nul && set "RUNNING=1"
)
del "%PROBE%" >nul 2>&1

if defined RUNNING (
    echo [+] Site is already running: http://127.0.0.1:%PORT%/
    start "" "http://127.0.0.1:%PORT%/"
    exit /b 0
)

echo [+] Starting site: http://127.0.0.1:%PORT%/
echo     This window IS the server. Close it to stop.

rem Open the browser in 2 seconds; the server keeps running in THIS window.
start "" /min cmd /c "timeout /t 2 >nul & start http://127.0.0.1:%PORT%/"

if /i "%PY%"=="python" ( python -u site\app.py ) else ( py -3 -u site\app.py )
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
    echo.
    echo [x] Server exited with code %RC%. Error text is above.
    pause
)
exit /b %RC%
