@echo off
setlocal
cd /d "%~dp0"

title unzapret-by-sh1dan (System Diagnostics)
echo ============================================================
echo   Running Read-Only System Diagnostics
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo ============================================================
echo.

dpi-bypass.exe diagnose

echo.
pause
