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

title unzapret-by-sh1dan (Active Mode)
echo ============================================================
echo   Starting unzapret-by-sh1dan (Active Capture and Bypass)
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo   Press Ctrl+C to safely stop.
echo ============================================================
echo.

echo TCP-only candidate. Voice and QUIC bypass are unavailable.
echo Stop the old console and service before testing this build.
dpi-bypass.exe --version
dpi-bypass.exe start

echo.
echo Engine stopped.
pause
