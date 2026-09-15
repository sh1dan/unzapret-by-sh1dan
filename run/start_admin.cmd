@echo off
setlocal
cd /d "%~dp0"

:: Check for administrative rights
powershell.exe -NoProfile -Command "$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges...
    set "LOCAL_DPI_LAUNCHER=%~f0"
    powershell.exe -NoProfile -Command "Start-Process -FilePath $env:LOCAL_DPI_LAUNCHER -Verb RunAs -ErrorAction Stop"
    exit /b
)

title dpi-bypass (Active Mode - Capture and Reinject)
echo ============================================================
echo   Starting dpi-bypass (Run as Administrator)
echo   TCP profile configured in config\default.toml
echo   Press Ctrl+C in this console to safely stop the engine.
echo ============================================================
echo.

echo TCP-only candidate. Voice and QUIC bypass are unavailable.
echo Stop the old console and service before testing this build.
dpi-bypass.exe --version
dpi-bypass.exe start

echo.
echo Engine stopped.
pause
