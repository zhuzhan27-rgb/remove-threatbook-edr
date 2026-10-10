<#
    verify.ps1 - 10-point verification after removal.

    RUN AS ADMINISTRATOR (items 7-10 need elevation).

    SUCCESS CRITERIA
    ----------------
    Items 1-6, 8, 10 must pass.
    Items 7 and 9 (Defender) MAY legitimately fail: Windows allows
    only one AV product to hold the real-time protection slot, and a
    different vendor usually occupies it. That is healthy, not a fault.

    ASCII-only by design.
#>

$ErrorActionPreference = 'Continue'

# ---- CONFIG ---------------------------------------------------------
$EDR_SVC  = @('tbAgentSrv', 'tbGuardSrv', 'webthreatdefsvc',
              'webthreatdefusersvc_c9da5')
$EDR_DRV  = @('TbBoot', 'TbCardinal')
$DRV_FILES = @('C:\WINDOWS\system32\drivers\TbBoot.sys',
               'C:\WINDOWS\system32\Drivers\TbCardinal.sys')
$EDR_DIRS = @('C:\Program Files (x86)\Threatbook',
              'C:\ProgramData\Threatbook',
              'C:\Program Files\ThreatBook')
$REG_KEYS = @('HKLM:\SOFTWARE\Threatbook',
              'HKLM:\SOFTWARE\WOW6432Node\Threatbook',
              'HKCU:\SOFTWARE\Threatbook')
# -------------------------------------------------------------------

function Hdr ($m) { Write-Host ''; Write-Host "=== $m ===" }
function Ok  ($m) { Write-Host "  [ OK ]  $m" }
function Bad ($m) { Write-Host "  [FAIL]  $m" -ForegroundColor Red }
function Warn($m) { Write-Host "  [ !! ]  $m" -ForegroundColor Yellow }
function Info($m) { Write-Host "  [ i  ]  $m" }

$pass = 0
$fail = 0
$warn = 0

Write-Host ''
Write-Host '============================================================'
Write-Host '  ThreatBook / Windows EDR - Residual Verification'
Write-Host '============================================================'

# ---------------------------------------------------------------- 1
Hdr '1. Services'
foreach ($s in $EDR_SVC) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) { Bad "STILL PRESENT: $s (State=$($svc.Status))"; $fail++ }
    else { Ok "removed: $s"; $pass++ }
}

# ---------------------------------------------------------------- 2
Hdr '2. Kernel drivers'
foreach ($d in $EDR_DRV) {
    $drv = Get-WmiObject Win32_SystemDriver -Filter "Name='$d'" -ErrorAction SilentlyContinue
    if ($drv) { Bad "STILL LOADED: $d (State=$($drv.State))"; $fail++ }
    else { Ok "removed: $d"; $pass++ }
}

# ---------------------------------------------------------------- 3
Hdr '3. Driver files'
foreach ($f in $DRV_FILES) {
    if (Test-Path $f) { Bad "STILL EXISTS: $f"; $fail++ }
    else { Ok "deleted: $(Split-Path $f -Leaf)"; $pass++ }
}

# ---------------------------------------------------------------- 4
Hdr '4. Directories'
foreach ($d in $EDR_DIRS) {
    if (Test-Path $d) {
        $n = (Get-ChildItem $d -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
        Bad "STILL EXISTS: $d ($n items)"; $fail++
    } else { Ok "deleted: $d"; $pass++ }
}

# ---------------------------------------------------------------- 5
Hdr '5. Registry keys'
foreach ($k in $REG_KEYS) {
    if (Test-Path $k) { Bad "STILL PRESENT: $k"; $fail++ }
    else { Ok "cleaned: $k"; $pass++ }
}

# ---------------------------------------------------------------- 6
Hdr '6. Uninstall entry'
$foundU = $false
foreach ($r in @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
    foreach ($i in (Get-ChildItem $r -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty $i.PSPath -ErrorAction SilentlyContinue
        if ($p -and $p.DisplayName -like '*ThreatBook*') {
            Bad "Control Panel still lists: $($p.DisplayName)"
            $foundU = $true; $fail++
        }
    }
}
if (-not $foundU) { Ok 'no ThreatBook entry in Control Panel'; $pass++ }

# ---------------------------------------------------------------- 7
Hdr '7. Processes'
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^tb|CtrlSC|webthreat' }
if ($procs) {
    foreach ($p in $procs) { Bad "STILL RUNNING: $($p.ProcessName) (PID $($p.Id))" }
    $fail++
} else { Ok 'no EDR processes'; $pass++ }

# ---------------------------------------------------------------- 8
Hdr '8. AV products in Windows Security Center'
$tbInWsc = $false
try {
    $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($a in $av) {
        if ($a.displayName -like '*ThreatBook*') {
            Bad "still registered: $($a.displayName)"
            Info "  path: $($a.pathToSignedProductExe)"
            $tbInWsc = $true
        } else { Ok "registered: $($a.displayName)" }
    }
    if (@($av).Count -gt 1) {
        Warn 'Multiple AV registered. Only ONE holds real-time protection.'
        Warn 'If Defender is disabled, another AV owns the slot (normal).'
    }
} catch { Warn 'cannot query SecurityCenter2 (needs admin)' }

if ($tbInWsc) {
    Write-Host ''
    Info 'This is an in-memory cache. Run step6-refresh-wsc.ps1'
    $warn++
} else { $pass++ }

# ---------------------------------------------------------------- 9
Hdr '9. Defender status (informational, not a pass/fail criterion)'
try {
    $d = Get-MpComputerStatus -ErrorAction Stop
    if ($d.AMServiceEnabled) { Ok 'Defender enabled' }
    else { Warn 'Defender disabled (AMServiceEnabled=False)' }
    if ($d.RealTimeProtectionEnabled) { Ok 'Real-time protection on' }
    else { Warn 'Real-time protection OFF' }
} catch { Warn 'cannot query Defender (needs admin)' }

foreach ($s in @('WinDefend', 'WdNisSvc')) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') { Ok "$s running" }
        else { Warn "$s is $($svc.Status)" }
    } else { Warn "$s not found" }
}

# ---------------------------------------------------------------- 10
Hdr '10. AMSI providers'
$amsiKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\AmsiProviders'
$tbAmsi = $false
try {
    if (Test-Path $amsiKey) {
        $props = Get-ItemProperty -Path $amsiKey -ErrorAction SilentlyContinue
        $hits = $props.PSObject.Properties | Where-Object { $_.Name -like 'Tb*' }
        if ($hits) {
            foreach ($h in $hits) { Bad "ThreatBook AMSI provider registered: $($h.Name)" }
            $tbAmsi = $true; $fail++
        } else { Ok 'no ThreatBook AMSI provider' }
    } else {
        Ok 'AmsiProviders key absent (no providers registered)'
    }
} catch { Warn 'cannot read AmsiProviders (needs admin)' }

# ---------------------------------------------------------------- verdict
Write-Host ''
Write-Host '============================================================'
Write-Host ("  RESULT:  {0} passed, {1} failed, {2} warnings" -f $pass, $fail, $warn)
Write-Host '============================================================'

if ($fail -eq 0) {
    Write-Host ''
    Write-Host '  REMOVAL COMPLETE.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Follow-up: if the EDR was quarantining another'
    Write-Host "  application's files, reinstall that application now."
} else {
    Write-Host ''
    Write-Host '  INCOMPLETE - review the failures above.' -ForegroundColor Yellow
    Write-Host '  Re-read the README section on the four layers of'
    Write-Host '  resistance to identify which layer still blocks you.'
}