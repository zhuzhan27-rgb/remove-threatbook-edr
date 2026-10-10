@echo off
REM ===============================================================
REM  step3-enter-safemode.bat
REM  Enter Safe Mode via bcdedit, bypassing WinRE entirely.
REM
REM  WHY: WinRE is often blocked by an OEM pre-boot encryption lock
REM  (you get a BitLocker key prompt instead of the menu). The lock
REM  guards WinRE, NOT the normal boot path, so writing the BCD flag
REM  directly avoids it.
REM
REM  Run diagnose.ps1 first: if PEFirmwareType = 2 (UEFI) then F8
REM  does nothing, and this is the only reliable route.
REM
REM  EXPECT: after reboot you land in BARE cmd.exe.
REM  There is NO desktop and NO Explorer, so you cannot double-click
REM  anything. Type the full path of step4-safemode-remove.bat instead.
REM
REM  RUN AS ADMINISTRATOR.
REM ===============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ================================================================
echo   Enter Safe Mode via bcdedit
echo ================================================================
echo.

echo [1/4] Current boot configuration:
bcdedit /enum "{current}"
echo.

echo [2/4] Disabling fast-startup interference and WinRE...
bcdedit /set "{default}" bootstatuspolicy ignoreallfailures
bcdedit /set "{default}" recoveryenabled no
bcdedit /set "{current}" bootstatuspolicy ignoreallfailures
echo       done.
echo.

echo [3/4] Setting safeboot=minimal...
bcdedit /set "{default}" safeboot minimal
if %errorlevel% neq 0 (
    echo   [!!]  Failed to set safeboot. Are you really admin?
    pause
    exit /b 1
)
echo       done.
echo.

echo [4/4] Verifying the flag was written...
bcdedit /enum "{current}" | findstr /i "safeboot"
if %errorlevel% neq 0 (
    echo   [!!]  safeboot flag NOT found - aborting. Reboot is safe.
    pause
    exit /b 1
)
echo   [ OK ] safeboot flag is set.
echo.
echo ================================================================
echo   READY TO REBOOT.
echo.
echo   NEXT STEPS AFTER REBOOT:
echo.
echo   You will land in a bare cmd.exe (no desktop - this is normal).
echo   In that window, type the full path to:
echo.
echo       step4-safemode-remove.bat
echo.
echo   It will be next to this file, e.g.:
echo       %~dp0step4-safemode-remove.bat
echo.
echo   Do NOT close that cmd window.
echo ================================================================
echo.
set /p ANS=Reboot now? (Y/N):
if /i "%ANS%"=="Y" (
    shutdown /r /t 0
) else (
    echo.
    echo Cancelled, but the boot config WAS modified.
    echo To undo Safe Mode later:
    echo    "%~dp0step5-exit-safemode.bat"
    echo.
    pause
)