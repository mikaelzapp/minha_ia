@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "NEXUS_EXIT_CODE=1"
pushd "%~dp0" >nul 2>&1
if errorlevel 1 goto directory_error

where powershell.exe >nul 2>&1
if errorlevel 1 goto powershell_error

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\manutencao.ps1" -Acao Instalar %*
set "NEXUS_EXIT_CODE=%ERRORLEVEL%"
if "%NEXUS_EXIT_CODE%"=="0" (
    echo.
    echo Instalacao do NEXUS concluida.
) else (
    echo.
    echo A instalacao terminou com erro. Confira a mensagem acima.
)
goto finish

:powershell_error
echo ERRO: Windows PowerShell nao foi encontrado neste computador.
echo Restaure o Windows PowerShell e execute este arquivo novamente.
goto finish

:finish
popd
if not "%NEXUS_SEM_PAUSA%"=="1" pause
exit /b %NEXUS_EXIT_CODE%

:directory_error
echo ERRO: nao foi possivel acessar a pasta deste arquivo.
if not "%NEXUS_SEM_PAUSA%"=="1" pause
exit /b 1
