@echo off
setlocal
cd /d "%~dp0"

title unzapret-by-sh1dan (Connectivity Probe Only)
echo ============================================================
echo   Partial TLS probes only - NOT a strategy or voice test
echo   Repository: https://github.com/sh1dan/unzapret-by-sh1dan
echo ============================================================
echo.

dpi-bypass.exe test

echo.
pause
