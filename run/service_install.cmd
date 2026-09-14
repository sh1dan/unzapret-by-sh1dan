@echo off
setlocal
cd /d "%~dp0"

:: Check for administrative rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges to install service...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title unzapret-by-sh1dan (Install Service)
echo ============================================================
echo   Installing LocalDpiBypass Windows Service (Auto-Start)
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo ============================================================
echo.

dpi-bypass.exe service install
echo.
echo Starting service...
dpi-bypass.exe service start
echo.
dpi-bypass.exe service status

echo.
echo Operation complete. The service will automatically run on Windows boot.
pause
