@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-test.ps1"
set "result=%errorlevel%"
pause
exit /b %result%
