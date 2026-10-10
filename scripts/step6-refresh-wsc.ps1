<#
    step6-refresh-wsc.ps1
    Clear the stale "ThreatBook Agent" entry from Windows Security Center.

    RUN AS ADMINISTRATOR.

    WHY
    ---
    After full removal, root\SecurityCenter2 may still list the product.
    That entry is pure in-memory cache inside the WMI provider hosted by
    wscsvc / SecurityHealthService. Nothing on disk backs it any more.

    Restarting those services forces a re-enumeration.

    If it still persists, see docs/TROUBLESHOOTING.md for the last resort
    (restarting the wmiprvse host).

    ASCII-only by design.
#>

$ErrorActionPreference = 'Continue'

function Hdr  ($m) { Write-Host ''; Write-Host "=== $m ===" }
function Ok   ($m) { Write-Host "  [ OK ]  $m" }
function Bad  ($m) { Write-Host "  [!!  ]  $m" -ForegroundColor Red }
function Info ($m) { Write-Host "  [ i  ]  $m" }

function Get-Err($e) { ($e.Exception.Message -split "`n")[0] }

$adm = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $adm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Bad 'NOT running as Administrator.'
    exit 1
}

function Get-AvList {
    try { return @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop) }
    catch { return @() }
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  Step 6 - Refresh Windows Security Center'
Write-Host '============================================================'

# ---------------------------------------------------------------- 1
Hdr '1/3 AV products BEFORE'
$before = Get-AvList
foreach ($a in $before) { Info "$($a.displayName)  state=$($a.productState)" }
$beforeTb = @($before | Where-Object { $_.displayName -like '*ThreatBook*' }).Count
if ($beforeTb -eq 0) { Ok 'no ThreatBook entry present' }
else { Info "ThreatBook entry present ($beforeTb)" }
Write-Host ''

# ---------------------------------------------------------------- 2
Hdr '2/3 Restarting WSC host services'
foreach ($n in @('wscsvc', 'SecurityHealthService')) {
    $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
    if (-not $svc) { Info "${n} not found"; continue }
    try {
        if ($svc.Status -eq 'Running') {
            Stop-Service -Name $n -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Start-Service -Name $n -ErrorAction Stop
            Ok "${n} restarted"
        } else {
            Start-Service -Name $n -ErrorAction Stop
            Ok "${n} started"
        }
    } catch {
        Bad "${n}: $(Get-Err $_)"
    }
}
Start-Sleep -Seconds 3
Write-Host ''

# ---------------------------------------------------------------- 3
Hdr '3/3 AV products AFTER'
$after = Get-AvList
foreach ($a in $after) { Info "$($a.displayName)  state=$($a.productState)" }
$stillTb = @($after | Where-Object { $_.displayName -like '*ThreatBook*' })

Write-Host ''
if ($stillTb.Count -eq 0) {
    Ok 'ThreatBook is GONE from Windows Security Center.'
    Write-Host ''
    Write-Host '  Remediation complete. Run verify.ps1 for final confirmation.'
} else {
    Bad "ThreatBook still listed ($($stillTb.Count) entry)"
    foreach ($a in $stillTb) {
        Info "  name: $($a.displayName)"
        Info "  path: $($a.pathToSignedProductExe)"
        Info "  guid: $($a.productGuid)"
    }
    Write-Host ''
    Write-Host '  Next option: restart the WMI host process that serves'
    Write-Host '  root\SecurityCenter2. See docs/TROUBLESHOOTING.md.'
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  Reminder: Defender may stay passive because another AV'
Write-Host '  holds the single real-time protection slot. That is normal.'
Write-Host '============================================================'