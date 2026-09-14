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

title dpi-bypass (Dry-Run Mode - Passive Sniff)
echo ============================================================
echo   Starting dpi-bypass in DRY-RUN mode (sniff only, no modify)
echo   Target IPs and ports configured in config\phase2.toml
echo   Press Ctrl+C in this console to safely stop the engine.
echo ============================================================
echo.

dpi-bypass.exe start --dry-run

echo.
echo Engine stopped.
pause
