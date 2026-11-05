@echo off
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0iniciar.ps1" -Abrir
if errorlevel 1 pause
