@echo off
REM ===============================================================
REM  step4-safemode-remove.bat
REM  Delete kernel drivers + install directory from Safe Mode.
REM
REM  MUST run inside Safe Mode. This is the ONLY place a running
REM  kernel driver's .sys file can be deleted (Windows locks the file
REM  with a handle that has no FILE_SHARE_DELETE).
REM
REM  HOW TO RUN (there is no desktop in bcdedit Safe Mode):
REM     In the cmd window, type the full path to this file, e.g.
REM       D:\path\to\remove-threatbook-edr\scripts\step4-safemode-remove.bat
REM
REM  All output is ASCII because Safe Mode has no CJK fonts.
REM ===============================================================

echo.
echo ================================================================
echo   Step 4 - Safe Mode removal (drivers + directory)
echo ================================================================
echo.

REM ---- 0. Self-check: are we actually in Safe Mode? --------------------
echo [0/5] Verifying Safe Mode...
if not exist "C:\Windows\System32\config\system" (
    echo.
    echo   [!!]  ABORT: this is NOT Safe Mode.
    echo.
    echo   A loaded kernel driver cannot be deleted in Normal Mode.
    echo   Doing it anyway would leave a half-removed state.
    echo.
    echo   Enter Safe Mode first:
    echo     Run step3-enter-safemode.bat as Administrator, reboot,
    echo     then in the bare cmd window type the full path to THIS file.
    echo.
    pause
    exit /b 1
)
echo       [ OK ] Safe Mode confirmed.
echo.

REM ---- 1. Kill processes (self-guard revives siblings) ------------------
echo [1/5] Killing EDR processes, 3 rounds...
for %%L in (1 2 3) do (
    taskkill /F /IM tbAgent.exe /T >nul 2>&1
    taskkill /F /IM tbGuard.exe /T >nul 2>&1
    taskkill /F /IM tbAgentSrv.exe /T >nul 2>&1
    taskkill /F /IM tbGuardSrv.exe /T >nul 2>&1
    taskkill /F /IM CtrlSC.exe /T >nul 2>&1
    taskkill /F /IM safeSrv.exe /T >nul 2>&1
    ping -n 2 127.0.0.1 >nul 2>&1
)
echo       done.
echo.

REM ---- 2. Stop services ------------------------------------------------
echo [2/5] Stopping services...
sc.exe stop tbAgentSrv >nul 2>&1
sc.exe stop tbGuardSrv >nul 2>&1
sc.exe stop webthreatdefsvc >nul 2>&1
echo       done.
echo.

REM ---- 3. Delete driver SERVICES --------------------------------------
echo [3/5] Deleting driver services...
echo   --- TbBoot (StartMode=Boot) ---
sc.exe delete TbBoot
echo   --- TbCardinal (StartMode=System) ---
sc.exe delete TbCardinal
echo.

REM ---- 4. Delete driver FILES -----------------------------------------
echo [4/5] Deleting driver files...
del /f "C:\WINDOWS\system32\drivers\TbBoot.sys" 2>nul
if exist "C:\WINDOWS\system32\drivers\TbBoot.sys" (
    echo   [!!]  TbBoot.sys STILL EXISTS
) else (
    echo   [ OK ] TbBoot.sys gone
)
del /f "C:\WINDOWS\system32\Drivers\TbCardinal.sys" 2>nul
if exist "C:\WINDOWS\system32\Drivers\TbCardinal.sys" (
    echo   [!!]  TbCardinal.sys STILL EXISTS
) else (
    echo   [ OK ] TbCardinal.sys gone
)
echo.

REM ---- 5. Remove directories ------------------------------------------
echo [5/5] Removing install directories...
if exist "C:\Program Files (x86)\Threatbook" (
    rd /s /q "C:\Program Files (x86)\Threatbook" 2>nul
)
if exist "C:\ProgramData\Threatbook" (
    rd /s /q "C:\ProgramData\Threatbook" 2>nul
)
if exist "C:\Program Files (x86)\Threatbook" (
    echo   [ i ] folder still present - remaining files are mapped DLLs.
    echo       Handle that with step5a + step5b after leaving Safe Mode.
    dir /a /s "C:\Program Files (x86)\Threatbook"
) else (
    echo   [ OK ] folder removed
)
echo.

echo ================================================================
echo   RESULT
echo ------------------------------------------------------------
sc.exe query TbBoot
sc.exe query TbCardinal
echo.
if exist "C:\WINDOWS\system32\drivers\TbBoot.sys" (echo   [!!]  TbBoot.sys EXISTS) else (echo   [ OK ] TbBoot.sys gone)
if exist "C:\WINDOWS\system32\Drivers\TbCardinal.sys" (echo   [!!]  TbCardinal.sys EXISTS) else (echo   [ OK ] TbCardinal.sys gone)
echo.
echo   NOTE: "FAILED 1060" means "service not installed" = SUCCESS.
echo   NOTE: "marked for deletion" is normal; it disappears on reboot.
echo ================================================================
echo.
echo   NEXT: type the full path to
echo       step5-exit-safemode.bat
echo.
pause