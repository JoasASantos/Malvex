@echo off
REM Malvex - Windows launcher.
REM Elevates and runs setup.ps1 with bypass execution policy.
setlocal
set "HERE=%~dp0"
net session >nul 2>&1
if %errorLevel% == 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%setup.ps1" %*
) else (
  echo [malvex] requesting elevation...
  powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%HERE%setup.ps1\"'"
)
endlocal
