<#
    step5a-rename-injection.ps1
    Break the AMSI provider injection chain by RENAMING the DLL.

    RUN AS ADMINISTRATOR, in Normal Mode, AFTER leaving Safe Mode.

    WHY RENAME, NOT DELETE
    ----------------------
    An AMSI Provider DLL gets mapped into running processes. A mapped
    file has a kernel section handle WITHOUT FILE_SHARE_DELETE, so:

        delete  -> requires exclusive file access -> always fails
        rename  -> requires parent-directory write permission -> succeeds

    Changing ACLs (takeown / icacls) has NO effect here. This is not
    a permission problem.

    Once renamed, the EDR can no longer load the DLL by name, so the
    injection chain is broken. That is the real win. Deleting the
    renamed file afterwards is cleanup, handled by step5b.

    ASCII-only by design.
#>

$ErrorActionPreference = 'Continue'

# ---- CONFIG ---------------------------------------------------------
$TBROOT = 'C:\Program Files (x86)\Threatbook'
$AMSI_REL = 'Agent\cardinal\TbAmsiProv64.dll'
# If your EDR differs, list every DLL that diagnose.ps1 found mapped.
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
    exit 1
}

$AMSI = Join-Path $TBROOT $AMSI_REL

Write-Host ''
Write-Host '============================================================'
Write-Host '  Step 5a - Break AMSI injection by renaming'
Write-Host '============================================================'
Info 'Delete will fail here. Rename usually succeeds.'

if (-not (Test-Path $TBROOT)) {
    Ok "EDR folder already gone: $TBROOT"
    Info 'Nothing to do. Skip to verify.ps1'
    exit 0
}

# ---------------------------------------------------------------- 1
Hdr '1/4 Current occupancy status'
$occupied = @()
$skipped = 0
$leaf = Split-Path $AMSI -Leaf
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    try {
        foreach ($m in $p.Modules) {
            if ($m.FileName -like ('*' + $leaf + '*')) {
                $occupied += "$($p.ProcessName) (PID $($p.Id))"
            }
        }
    } catch { $skipped++ }
}
if ($occupied.Count -gt 0) {
    Warn "Mapped into $($occupied.Count) process(es):"
    foreach ($o in $occupied) { Info "   $o" }
} else {
    Ok 'Not currently mapped into any process.'
}
if ($skipped -gt 0) { Info "$skipped protected process(es) not inspected" }
Write-Host ''

# ---------------------------------------------------------------- 2
Hdr '2/4 Relaxing permissions on the tree'
& takeown.exe /F $TBROOT /A /R /D Y 2>&1 | Out-Null
& icacls.exe $TBROOT /grant '*S-1-5-32-544:F' /T /C /Q 2>&1 | Out-Null
& attrib.exe -R -S -H "$TBROOT\*" /S /D 2>&1 | Out-Null
Ok 'takeown + icacls + attrib applied'
Write-Host ''

# ---------------------------------------------------------------- 3
Hdr '3/4 Renaming the DLL'
$STAMP = 'gone-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.tmp'
$renamed = $false

if (Test-Path $AMSI) {
    $parent = Split-Path $AMSI -Parent
    for ($i = 1; $i -le 5; $i++) {
        try {
            Rename-Item -LiteralPath $AMSI -NewName $STAMP -Force -ErrorAction Stop
            $renamed = $true
            Ok "renamed to $STAMP (attempt ${i})"
            Info 'Injection chain is now BROKEN.'
            break
        } catch {
            Exp "attempt ${i}: $(Get-Err $_)"
            Start-Sleep -Seconds 2
        }
    }
    if (-not $renamed) { Bad 'rename failed after 5 attempts' }
} else {
    Info 'AMSI DLL not present'
}

Write-Host ''

# ---------------------------------------------------------------- 4
Hdr '4/4 Trying a direct delete (may fail; that is expected)'
if ($renamed) {
    $target = Join-Path (Split-Path $AMSI -Parent) $STAMP
    $deleted = $false
    for ($i = 1; $i -le 3; $i++) {
        try {
            Remove-Item -LiteralPath $target -Force -ErrorAction Stop
            $deleted = $true
            Ok "deleted (attempt ${i})"
            break
        } catch {
            Exp "attempt ${i}: $(Get-Err $_)"
        }
    }
    if (-not $deleted) {
        Exp 'File still locked (kernel section handle). This is EXPECTED.'
        Info 'step5b will queue it for deletion during early boot.'
    }
}

Write-Host ''
Hdr 'Result'
if (Test-Path $TBROOT) {
    $items = Get-ChildItem $TBROOT -Recurse -Force -ErrorAction SilentlyContinue
    Warn "$TBROOT still present ($($items.Count) items):"
    foreach ($i in $items) {
        $sz = if ($i.PSIsContainer) { '<DIR>' } else { "$($i.Length)" }
        Info "   $($i.FullName.Replace($TBROOT,''))  ($sz)"
    }
} else {
    Ok 'Folder is completely gone'
}

Write-Host ''
Write-Host '============================================================'
Write-Host '  NEXT: step5b-queue-reboot-delete.ps1'
Write-Host '        then reboot, then verify.ps1'
Write-Host '============================================================'