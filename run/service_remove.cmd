@echo off
setlocal
cd /d "%~dp0"

:: Check for administrative rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges to remove service...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title unzapret-by-sh1dan (Remove Service)
echo ============================================================
echo   Stopping and Removing LocalDpiBypass Windows Service
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo ============================================================
echo.

dpi-bypass.exe service remove
echo.
dpi-bypass.exe service status

echo.
echo Operation complete.
pause
