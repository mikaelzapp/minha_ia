@echo off
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0parar.ps1"
if errorlevel 1 pause
