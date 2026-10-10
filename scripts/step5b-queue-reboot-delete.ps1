<#
    step5b-queue-reboot-delete.ps1
    Queue the leftover files/directories for deletion during early boot.

    RUN AS ADMINISTRATOR, in Normal Mode, after step5a.

    HOW IT WORKS
    ------------
    Writes the target paths into:
      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
        \PendingFileRenameOperations
    Windows drains this queue during early boot, BEFORE any user
    process can map the files. That is the only moment a
    kernel-section-locked file can actually be removed.

    FORMAT REQUIREMENTS (learned the hard way)
    -----------------------------------------
      * Each entry must be "*2\??\<NT path>" followed by an EMPTY
        string. The empty target means "delete".
      * Total string count must be EVEN (source/destination pairs).
      * Order must be DEEPEST FIRST:
          file -> child dir -> parent dir -> root
        Deleting a parent first makes its children unreachable.

    MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) often returns error 3
    (ERROR_PATH_NOT_FOUND) because of these format rules. Writing
    the registry value directly is more reliable.

    ASCII-only by design.
#>

$ErrorActionPreference = 'Continue'

# ---- CONFIG ---------------------------------------------------------
$TBROOT = 'C:\Program Files (x86)\Threatbook'
# -------------------------------------------------------------------

function Hdr  ($m) { Write-Host ''; Write-Host "=== $m ===" }
function Ok   ($m) { Write-Host "  [ OK ]  $m" }
function Bad  ($m) { Write-Host "  [!!  ]  $m" }
function Info ($m) { Write-Host "  [ i  ]  $m" }

function Get-Err($e) { ($e.Exception.Message -split "`n")[0] }

$adm = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $adm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Bad 'NOT running as Administrator.'
    exit 1
}

$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$val = 'PendingFileRenameOperations'

Write-Host ''
Write-Host '============================================================'
Write-Host '  Step 5b - Queue delete-at-reboot'
Write-Host '============================================================'

# ---------------------------------------------------------------- 1
Hdr '1/4 Collecting targets (deepest first)'
$targets = @()
if (Test-Path $TBROOT) {
    $files = @(Get-ChildItem $TBROOT -Recurse -Force -File -ErrorAction SilentlyContinue |
               Sort-Object { $_.FullName.Length } -Descending)
    $dirs = @(Get-ChildItem $TBROOT -Recurse -Force -Directory -ErrorAction SilentlyContinue |
              Sort-Object { $_.FullName.Length } -Descending)
    foreach ($f in $files) { $targets += $f.FullName }
    foreach ($d in $dirs)  { $targets += $d.FullName }
    $targets += $TBROOT
}

if ($targets.Count -eq 0) {
    Ok 'Nothing to queue - folder already gone.'
    Info 'Skip to verify.ps1'
    exit 0
}

Info "$($targets.Count) target(s):"
foreach ($t in $targets) { Info "   $t" }
Write-Host ''

# ---------------------------------------------------------------- 2
Hdr '2/4 Reading and validating the existing queue'
$existing = @()
try {
    $props = Get-ItemProperty -Path $key -Name $val -ErrorAction Stop
    $existing = @($props.$val)
    Ok "existing entries: $($existing.Count)"
} catch {
    Info 'value does not exist yet - creating it'
    New-ItemProperty -Path $key -Name $val -Value @() `
        -PropertyType MultiString -Force -ErrorAction SilentlyContinue | Out-Null
}

# A malformed queue can make SMSS mis-parse unrelated entries.
$nonEmpty = @($existing | Where-Object { $_ -ne '' })
if ($existing.Count -ne $nonEmpty.Count * 2) {
    Warn "existing queue is malformed: $($existing.Count) total vs $($nonEmpty.Count) non-empty"
    Info 'repairing into strict source/destination pairs...'
    $repaired = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $nonEmpty.Count; $i += 2) {
        $src = $nonEmpty[$i]
        $dst = ''
        if (($i + 1) -lt $nonEmpty.Count -and $nonEmpty[$i + 1] -ne '') { $dst = $nonEmpty[$i + 1] }
        [void]$repaired.Add($src)
        [void]$repaired.Add($dst)
    }
    $existing = $repaired.ToArray()
    Ok "repaired to $($existing.Count) entries"
} else {
    Ok 'existing queue is well-formed'
}
Write-Host ''

# ---------------------------------------------------------------- 3
Hdr '3/4 Appending our targets'
function To-NtPath([string]$p) {
    $p = $p.TrimEnd('\')
    if ($p -like '*\??\*') { return $p }
    return '*2\??\' + $p
}

$new = New-Object System.Collections.ArrayList
foreach ($x in $existing) { [void]$new.Add($x) }
foreach ($t in $targets) {
    [void]$new.Add((To-NtPath $t))
    [void]$new.Add('')          # empty destination == delete
    Ok "queued: $t"
}
Write-Host ''

# ---------------------------------------------------------------- 4
Hdr '4/4 Writing and verifying'
try {
    Set-ItemProperty -Path $key -Name $val -Value $new.ToArray() `
        -Type MultiString -ErrorAction Stop
    Ok 'queue written'
} catch {
    Bad "write failed: $(Get-Err $_)"
    exit 1
}

Write-Host ''
Info 'Verifying...'
try {
    $check = @((Get-ItemProperty -Path $key -Name $val -ErrorAction Stop).$val)
    $found = @($check | Where-Object { $_ -like "*$($TBROOT.Split('\')[-1])*" })
    if ($found.Count -gt 0) {
        Ok "confirmed: $($found.Count) matching entries in queue"
        foreach ($f in $found) { Info "   [$f]" }
    } else {
        Bad 'no matching entries found - write may not have taken effect'
    }
    $ne = @($check | Where-Object { $_ -ne '' })
    Info "queue now: $($check.Count) total, $($ne.Count) non-empty (even = $(($ne.Count % 2) -eq 0))"
} catch {
    Bad "verify failed: $(Get-Err $_)"
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  NOW REBOOT:   shutdown /r /t 0 /f'
Write-Host ''
Write-Host '  Windows will delete these paths during early boot,'
Write-Host '  before any process can map them.'
Write-Host ''
Write-Host '  After reboot run:  verify.ps1'
Write-Host '============================================================'