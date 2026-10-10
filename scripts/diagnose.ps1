<#
    diagnose.ps1 - Read-only reconnaissance for Windows EDR removal.

    NEVER modifies anything. Safe to run without admin, though some
    checks will report "access denied" which is itself informative.

    ASCII-only by design (see SKILL.md "Gotchas").
#>

$ErrorActionPreference = 'Continue'

# ---- CONFIG: adjust for your EDR product -------------------------------
$EDR_PROC   = @('tbAgent', 'tbAgentSrv', 'tbGuard', 'tbGuardSrv',
                'CtrlSC', 'safeSrv', 'webthreatdefsvc')
$EDR_SVC    = @('tbAgentSrv', 'tbGuardSrv', 'webthreatdefsvc',
                'webthreatdefusersvc_c9da5')
$EDR_DRV    = @('TbBoot', 'TbCardinal')
$EDR_DIRS   = @('C:\Program Files (x86)\Threatbook',
                'C:\ProgramData\Threatbook')
$AMSI_DLL   = 'C:\Program Files (x86)\Threatbook\Agent\cardinal\TbAmsiProv64.dll'
# ----------------------------------------------------------------------

function Hdr  ($m) { Write-Host ''; Write-Host "=== $m ===" }
function Ok   ($m) { Write-Host "  [ OK ]  $m" }
function Bad  ($m) { Write-Host "  [!!  ]  $m" -ForegroundColor Red }
function Warn ($m) { Write-Host "  [ !! ]  $m" -ForegroundColor Yellow }
function Info ($m) { Write-Host "  [ i  ]  $m" }

Write-Host ''
Write-Host '============================================================'
Write-Host '  Windows EDR Removal - Diagnostic Recon'
Write-Host '  (read-only, no changes are made)'
Write-Host '============================================================'

# ---------------------------------------------------------------- 1
Hdr '1. Environment (determines the safe-mode path)'

$pe = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PE' -ErrorAction SilentlyContinue
if ($pe) {
    if ($pe.PEFirmwareType -eq 2) {
        Warn 'Firmware = UEFI'
        Info 'F8 will NOT work. Use bcdedit (step3).'
    } elseif ($pe.PEFirmwareType -eq 1) {
        Ok 'Firmware = legacy BIOS (F8 may work)'
    } else {
        Info "PEFirmwareType = $($pe.PEFirmwareType)"
    }
} else {
    Info 'Could not read PEFirmwareType'
}

$sb = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
if ($sb) { Info "SecureBoot = $($sb.UEFISecureBootEnabled)" }

$hs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue
if ($hs) {
    if ($hs.HiberbootEnabled -eq 1) {
        Warn 'HiberbootEnabled = 1 (fast startup on)'
        Info 'Run: powercfg -h off   before rebooting into safe mode'
    } else {
        Ok 'Fast startup disabled'
    }
}

# Pre-boot lock detection
$fve = Get-Service FVE -ErrorAction SilentlyContinue
$blKey = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
$blSet = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker\Settings'
if (-not $fve -and $blKey -and -not $blSet) {
    Warn 'PRE-BOOT LOCK LIKELY (no FVE service, BitLocker key without Settings)'
    Info 'WinRE will demand a recovery key. Use bcdedit (step3).'
} elseif ($fve) {
    Ok 'Standard BitLocker present (FVE service exists)'
} else {
    Ok 'No pre-boot encryption lock detected'
}

$adm = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $adm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Ok 'Running as Administrator' }
else { Warn 'Not elevated - steps 2/5/6 will need UAC approval' }

# ---------------------------------------------------------------- 2
Hdr '2. Kernel drivers (Layer 1 - forces safe mode)'
$drvFound = $false
foreach ($d in $EDR_DRV) {
    $drv = Get-WmiObject Win32_SystemDriver -Filter "Name='$d'" -ErrorAction SilentlyContinue
    if ($drv) {
        $drvFound = $true
        $color = if ($drv.State -eq 'Running') { 'Running' } else { $drv.State }
        Write-Host ("  [!!  ]  {0,-14} State={1,-9} StartMode={2,-8}" -f $d, $color, $drv.StartMode) -ForegroundColor Red
        Write-Host ("          Path = " + $drv.PathName)
    }
}
if (-not $drvFound) { Ok 'No EDR drivers found (maybe already removed)' }

# ---------------------------------------------------------------- 3
Hdr '3. Services (Layer 1)'
foreach ($s in $EDR_SVC) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) { Bad ("{0,-28} {1}" -f $svc.DisplayName, $svc.Status) }
}

# ---------------------------------------------------------------- 4
Hdr '4. Self-guard activity (Layer 2)'
foreach ($d in $EDR_DIRS) {
    $gol = Join-Path $d 'Agent\data\gol'
    if (Test-Path $gol) {
        Bad "self-guard log directory ACTIVE: $gol"
        $recent = Get-ChildItem $gol -Recurse -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 5
        foreach ($r in $recent) {
            Info ("   {0}  {1}" -f $r.LastWriteTime.ToString('MM-dd HH:mm:ss'), $r.Name)
        }
    }
}

# ---------------------------------------------------------------- 5
Hdr '5. OCCUPANCY PROBE (Layer 3 - THE DECISIVE TEST)'
Info 'Scanning every process module for EDR DLLs...'
Write-Host ''
$hit = $false
$skipped = 0
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    try {
        foreach ($m in $p.Modules) {
            if ($m.FileName -like '*Threatbook*' -or $m.FileName -like '*AmsiProv*') {
                Bad ("OCCUPIED BY: {0} (PID {1})" -f $p.ProcessName, $p.Id)
                Info ("            {0}" -f $m.FileName)
                $hit = $true
            }
        }
    } catch { $skipped++ }
}
Write-Host ''
if ($hit) {
    Warn 'RESULT: files ARE mapped into running processes.'
    Info '=> This is NOT a permission problem. ACL changes will NOT help.'
    Info '=> Go to step5a (RENAME) then step5b (queue delete at reboot).'
} else {
    Ok 'RESULT: no EDR DLL is mapped into any process.'
    Info 'Ordinary permission-based deletion should work.'
}
if ($skipped -gt 0) {
    Info "$skipped process(es) skipped (protected, need admin to inspect)"
}

# ---------------------------------------------------------------- 6
Hdr '6. Install directories'
foreach ($d in $EDR_DIRS) {
    if (Test-Path $d) {
        $n = (Get-ChildItem $d -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
        $own = try { (Get-Acl $d).Owner } catch { 'unknown' }
        Bad "$d  ($n items, Owner = $own)"
        $i = Get-Item $d -Force
        Info ("   Created={0}  Modified={1}" -f $i.CreationTime.ToString('yyyy-MM-dd HH:mm'),
                                                     $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
        if ($i.CreationTime -gt $i.LastWriteTime) {
            Info '   NOTE: CreationTime is NEWER than LastWriteTime.'
            Info '   => The directory shell was RE-CREATED after install.'
            Info '   => Strong indicator that files were deleted post-install.'
        }
    } else {
        Ok "$d  (absent)"
    }
}

# ---------------------------------------------------------------- 7
Hdr '7. Processes'
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in $EDR_PROC }
if ($procs) {
    foreach ($p in $procs) { Bad ("{0,-18} PID={1}" -f $p.ProcessName, $p.Id) }
} else {
    Ok 'No EDR processes running'
}

# ---------------------------------------------------------------- 8
Hdr '8. Windows Security Center registration (Layer 4)'
try {
    $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($a in $av) {
        $isEdr = if ($a.displayName -match 'ThreatBook') { ' [ EDR ]' } else { '' }
        Write-Host ("  [ i  ]  {0}{1}" -f $a.displayName, $isEdr)
        Info ("          state={0}  path={1}" -f $a.productState, $a.pathToSignedProductExe)
    }
    if (@($av).Count -gt 1) {
        Warn 'Multiple AV registered. Only ONE holds real-time protection.'
    }
} catch {
    Info 'Cannot query SecurityCenter2 (needs admin)'
}

# ---------------------------------------------------------------- 9
Hdr '9. Defender state'
try {
    $d = Get-MpComputerStatus -ErrorAction Stop
    Info "AMServiceEnabled   = $($d.AMServiceEnabled)"
    Info "RealTimeProtection = $($d.RealTimeProtectionEnabled)"
    if (-not $d.AMServiceEnabled) {
        Info 'Passive Defender is NORMAL when another AV holds the slot.'
    }
} catch {
    Info 'Cannot query Defender (needs admin)'
}

# ---------------------------------------------------------------- 10
Hdr 'VERDICT'

$needsSafeMode = $false
foreach ($d in $EDR_DRV) {
    if (Get-WmiObject Win32_SystemDriver -Filter "Name='$d'" -ErrorAction SilentlyContinue) { $needsSafeMode = $true }
}

$anySvc = $false
foreach ($s in $EDR_SVC) { if (Get-Service -Name $s -ErrorAction SilentlyContinue) { $anySvc = $true } }
$anyProc = $anySvc
$anyDir = $false
foreach ($d in $EDR_DIRS) { if (Test-Path $d) { $anyDir = $true } }

if (-not $needsSafeMode -and -not $anySvc -and -not $anyDir) {
    Write-Host '  >>> ALREADY CLEAN. Nothing to remove.' -ForegroundColor Green
} elseif ($needsSafeMode) {
    Write-Host '  >>> REQUIRES SAFE MODE (kernel driver present).' -ForegroundColor Yellow
    Write-Host '      Next: step2-user-mode.ps1  then  step3-enter-safemode.bat'
} else {
    Write-Host '  >>> NO KERNEL DRIVER. Normal-mode removal may suffice.' -ForegroundColor Yellow
    Write-Host '      Next: step2-user-mode.ps1'
    if ($hit) {
        Write-Host '      But DLL injection is active -> also run step5a/5b'
    }
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  Reminder: only do this on a PERSONAL machine.'
Write-Host '  Removing IT-deployed EDR may violate company policy.'
Write-Host '============================================================'