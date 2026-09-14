@echo off
setlocal
cd /d "%~dp0"

:: Check for administrative rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title unzapret-by-sh1dan (Active Mode)
echo ============================================================
echo   Starting unzapret-by-sh1dan (Active Capture and Bypass)
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo   Press Ctrl+C to safely stop.
echo ============================================================
echo.

dpi-bypass.exe start

echo.
echo Engine stopped.
pause
