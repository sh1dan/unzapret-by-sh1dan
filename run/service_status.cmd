@echo off
setlocal
cd /d "%~dp0"

title unzapret-by-sh1dan (Service Status)
echo ============================================================
echo   Querying LocalDpiBypass Service Status
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo ============================================================
echo.

dpi-bypass.exe service status

echo.
pause
