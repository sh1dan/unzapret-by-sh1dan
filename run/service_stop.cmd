@echo off
setlocal
cd /d "%~dp0"
echo Run this helper as Administrator to stop the existing LocalDpiBypass service.
dpi-bypass.exe service stop
dpi-bypass.exe service status
pause
