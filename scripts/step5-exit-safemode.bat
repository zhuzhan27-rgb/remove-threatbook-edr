@echo off
REM ===============================================================
REM  step5-exit-safemode.bat
REM  Leave Safe Mode and restore normal networking.
REM
REM  How to run (no desktop in Safe Mode):
REM     In the cmd window, type the full path to this file, e.g.
REM       D:\path\to\remove-threatbook-edr\scripts\step5-exit-safemode.bat
REM
REM  If you get "parameter error", you typed the command by hand
REM  without the braces. Use THIS file instead.
REM ===============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ================================================================
echo   Leaving Safe Mode
echo ================================================================
echo.

echo [1/3] Removing the safeboot flag...
bcdedit /deletevalue "{default}" safeboot
echo       done.
echo.

echo [2/3] Restoring full networking...
bcdedit /set "{default}" safeboot network
echo       done.
echo.

echo [3/3] Current boot configuration:
bcdedit /enum "{current}"
echo.
echo ================================================================
echo   Done. Rebooting into Normal Mode...
echo.
echo   After reboot, in NORMAL mode, run:
echo       step5a-rename-injection.ps1   (Administrator)
echo       step5b-queue-reboot-delete.ps1 (Administrator)
echo       verify.ps1                    (Administrator)
echo ================================================================
echo.
pause
shutdown /r /t 0