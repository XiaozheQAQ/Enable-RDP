@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title RDP Quick Access - Disable

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%RDP-QuickAccess.ps1"

if not exist "%PS_SCRIPT%" (
    echo [ERROR] RDP-QuickAccess.ps1 was not found next to this file.
    echo Expected path: "%PS_SCRIPT%"
    echo.
    pause
    exit /b 1
)

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 (
    if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" (
        set "PS_EXE=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    )
)

set "TARGET_ARG=-DisableRdp"
set "RDPQA_SELF=%~f0"
set "RDPQA_ARGS=%TARGET_ARG%"

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
if errorlevel 1 goto :elevate
goto :run

:elevate
echo Requesting administrator privileges...
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "$q=[char]34; $cmdArgs=@('/c', ($q + $env:RDPQA_SELF + $q)); if ($env:RDPQA_ARGS) { $cmdArgs += $env:RDPQA_ARGS }; try { $p=@{FilePath=$env:ComSpec; ArgumentList=$cmdArgs; WorkingDirectory=$env:SystemRoot; Verb='RunAs'; PassThru=$true; ErrorAction='Stop'}; Start-Process @p | Out-Null } catch { Write-Host ('[ERROR] Elevation failed: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or failed. Administrator rights are required.
    echo.
    pause
)
exit /b

:run
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %TARGET_ARG%
set "RC=%ERRORLEVEL%"
echo.
if not "%RDPQA_NOPAUSE%"=="1" pause >nul
exit /b %RC%
