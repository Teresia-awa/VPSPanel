@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\publish-desktop.ps1"
if errorlevel 1 exit /b 1
start "" "publish\desktop\VPSPanel.Desktop.exe" --demo
