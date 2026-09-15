@echo off
setlocal
cd /d "%~dp0"

:: Check for administrative rights
powershell.exe -NoProfile -Command "$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges to install service...
    set "LOCAL_DPI_LAUNCHER=%~f0"
    powershell.exe -NoProfile -Command "Start-Process -FilePath $env:LOCAL_DPI_LAUNCHER -Verb RunAs -ErrorAction Stop"
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
