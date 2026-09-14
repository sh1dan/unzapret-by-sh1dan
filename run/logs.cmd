@echo off
setlocal
cd /d "%~dp0"

title unzapret-by-sh1dan (Application Logs)
echo ============================================================
echo   Recent Privacy-Sanitized Event Logs
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo ============================================================
echo.

dpi-bypass.exe logs

echo.
pause
