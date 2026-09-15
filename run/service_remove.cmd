@echo off
setlocal
cd /d "%~dp0"

:: Check for administrative rights
powershell.exe -NoProfile -Command "$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges to remove service...
    set "LOCAL_DPI_LAUNCHER=%~f0"
    powershell.exe -NoProfile -Command "Start-Process -FilePath $env:LOCAL_DPI_LAUNCHER -Verb RunAs -ErrorAction Stop"
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
