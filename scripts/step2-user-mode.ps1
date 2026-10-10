<#
    step2-user-mode.ps1 - Clear what CAN be cleared in Normal Mode.

    RUN AS ADMINISTRATOR.

    EXPECT MANY FAILURES. That is by design:
      * Layer 1 (kernel driver) blocks most file operations
      * Layer 2 (self-guard) reverts your ACL changes within seconds

    Do NOT retry repeatedly. This step exists to clear items that are
    NOT kernel-protected, and to lay groundwork. Real removal happens
    in Safe Mode (step4) and via rename (step5a).

    ASCII-only by design.
#>

$ErrorActionPreference = 'Continue'

# ---- CONFIG ---------------------------------------------------------
$EDR_SVC = @('tbAgentSrv', 'tbGuardSrv', 'webthreatdefsvc',
             'webthreatdefusersvc_c9da5')
$EDR_PROC = @('tbAgent', 'tbAgentSrv', 'tbGuard', 'tbGuardSrv',
              'CtrlSC', 'safeSrv')
$EDR_DIRS = @('C:\Program Files (x86)\Threatbook',
              'C:\ProgramData\Threatbook')
$REG_KEYS = @('HKLM:\SOFTWARE\Threatbook',
              'HKLM:\SOFTWARE\WOW6432Node\Threatbook',
              'HKCU:\SOFTWARE\Threatbook')
# -------------------------------------------------------------------

function Hdr  ($m) { Write-Host ''; Write-Host "=== $m ===" }
function Ok   ($m) { Write-Host "  [ OK ]  $m" }
function Bad  ($m) { Write-Host "  [!!  ]  $m" }
function Exp  ($m) { Write-Host "  [EXP ]  $m" -ForegroundColor Yellow }
function Info ($m) { Write-Host "  [ i  ]  $m" }

function Get-Err($e) { ($e.Exception.Message -split "`n")[0] }

$adm = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $adm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Bad 'NOT running as Administrator.'
    Bad 'Right-click PowerShell -> Run as administrator'
    exit 1
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  Step 2 - Normal-mode partial cleanup'
Write-Host '============================================================'
Info 'Many operations are EXPECTED to fail. That is normal.'
Info 'This step does NOT complete the removal.'

# ---------------------------------------------------------------- 1
Hdr '1/6 Killing processes (self-guard will revive them)'
foreach ($round in 1..3) {
    Info "round $round"
    foreach ($n in $EDR_PROC) {
        $ps = Get-Process -Name $n -ErrorAction SilentlyContinue
        foreach ($p in $ps) {
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                Ok "killed $n (PID $($p.Id))"
            } catch {
                Exp "cannot kill $n (PID $($p.Id))"
            }
        }
    }
    Start-Sleep -Seconds 1
}

# ---------------------------------------------------------------- 2
Hdr '2/6 Stopping and disabling services'
foreach ($s in $EDR_SVC) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if (-not $svc) { Ok "already gone: $s"; continue }
    try { Stop-Service -Name $s -Force -ErrorAction Stop; Ok "stopped $s" }
    catch { Exp "cannot stop ${s}: $(Get-Err $_)" }
    try { Set-Service -Name $s -StartupType Disabled -ErrorAction Stop; Ok "disabled $s" }
    catch { Exp "cannot disable ${s}: $(Get-Err $_)" }
}

# ---------------------------------------------------------------- 3
Hdr '3/6 Scheduled tasks and startup items'
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
$taskHit = 0
foreach ($t in $tasks) {
    if ($t.TaskName -match 'threat|tbAgent|erisk' -or $t.TaskPath -match 'Threatbook') {
        try {
            Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath `
                -Confirm:$false -ErrorAction Stop
            Ok "removed task $($t.TaskName)"
        } catch { Exp "cannot remove task $($t.TaskName)" }
        $taskHit++
    }
}
if ($taskHit -eq 0) { Ok 'no matching scheduled tasks' }

# ---------------------------------------------------------------- 4
Hdr '4/6 Registry keys'
foreach ($k in $REG_KEYS) {
    if (-not (Test-Path $k)) { Ok "absent: $k"; continue }
    try { Remove-Item -Path $k -Recurse -Force -ErrorAction Stop; Ok "deleted ${k}" }
    catch { Exp "cannot delete ${k}: $(Get-Err $_)" }
}

# Uninstall entries
$uninstRoots = @(
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($r in $uninstRoots) {
    $items = Get-ChildItem $r -ErrorAction SilentlyContinue
    foreach ($i in $items) {
        $p = Get-ItemProperty $i.PSPath -ErrorAction SilentlyContinue
        if ($p -and $p.DisplayName -like '*ThreatBook*') {
            try { Remove-Item $i.PSPath -Recurse -Force -ErrorAction Stop
                  Ok "deleted uninstall entry $($i.PSChildName)" }
            catch { Exp "cannot delete uninstall entry: $(Get-Err $_)" }
        }
    }
}

# ---------------------------------------------------------------- 5
Hdr '5/6 Seizing ownership of install directories'
foreach ($d in $EDR_DIRS) {
    if (-not (Test-Path $d)) { Ok "absent: $d"; continue }
    & takeown.exe /F $d /A /R /D Y 2>&1 | Out-Null
    & icacls.exe $d /grant '*S-1-5-32-544:F' /T /C /Q 2>&1 | Out-Null
    & attrib.exe -R -S -H "$d\*" /S /D 2>&1 | Out-Null
    $own = try { (Get-Acl $d).Owner } catch { 'unknown' }
    Ok "ownership seized: $d  (Owner = $own)"
}
Info 'WARNING: self-guard may revert this within seconds. That is normal.'

# ---------------------------------------------------------------- 6
Hdr '6/6 Summary'
Write-Host ''
foreach ($s in $EDR_SVC) {
    if (Get-Service -Name $s -ErrorAction SilentlyContinue) { Bad "STILL PRESENT: $s" }
    else { Ok "removed: $s" }
}
foreach ($d in $EDR_DIRS) {
    if (Test-Path $d) {
        $n = (Get-ChildItem $d -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
        Bad "STILL EXISTS: $d  ($n items)"
    } else { Ok "deleted: $d" }
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  DONE. Now continue:'
Write-Host ''
Write-Host '    3) step3-enter-safemode.bat'
Write-Host '       (bcdedit safe mode - bypasses WinRE pre-boot lock)'
Write-Host ''
Write-Host '  If DLL injection was detected by diagnose.ps1, you will'
Write-Host '  also need step5a + step5b afterwards.'
Write-Host '============================================================'