---
name: remove-windows-edr
description: >-
  Remove or troubleshoot Windows EDR / endpoint security software that is
  silently deleting application files and causing apps to report "installation
  is corrupt or missing" on every launch. Use when diagnosing missing .exe files
  that coexist with intact .dll/.json files in the same folder, when an app's
  install manifest shows exe-only gaps, or when a user asks to uninstall
  enterprise EDR agents (ThreatBook/微步, Crowdstrike, SentinelOne, Carbon Black,
  360, Huorong) from a personal machine. Covers safe mode entry via bcdedit
  (bypasses WinRE OEM pre-boot locks), kernel driver removal, AMSI provider DLL
  rename to break injection, and PendingFileRenameOperations delete queuing.
---

# Remove Windows EDR from a Personal Machine

## When to Use This Skill

Trigger on any of these:

- App shows "installation is corrupt or missing, reinstall" on every launch
- Missing files are **exclusively `.exe`** while `.dll`/`.json`/`.zip` in the same
  folder are intact
- Install manifest (`install-manifest.json`, `manifest.json`, `*.filelist`)
  shows exe-only gaps
- User asks to remove an enterprise EDR agent from their own machine
- A process has been "quietly quarantined" and no backup exists on disk

**Do NOT use on corporate-managed devices.** Removing an IT-deployed EDR may
violate company policy. Verify the machine is personal first.

## Critical: Four Layers of Resistance

Understand these before acting. They determine which steps are futile.

| Layer | What it is | Symptom | Cure |
|---|---|---|---|
| **1. Kernel driver** | minifilter driver intercepts all file ops | Even admin gets "access denied" | Safe Mode (bcdedit) |
| **2. Self-guard** | Watcher processes restore ACLs, revive killed siblings | `takeown` succeeds, Owner reverts seconds later | Kill driver first |
| **3. DLL injection** | AMSI Provider mapped into every process | `delete` always fails; **changing ACL never helps** | **Rename**, then queue delete for reboot |
| **4. WSC cache** | In-memory display entry | App gone but Security Center still lists it | Restart `wscsvc` |

**The most expensive mistake is trying to fix Layer 3 with permissions.** Before
any attempt to modify ACLs, run the module-scan probe (below) to determine
whether a file is *occupied* or *permission-denied*. This one command collapses
what could otherwise be many wasted rounds.

## Mandatory First Step: Probe for Occupancy

```powershell
# THE decisive probe. Run this BEFORE touching ACLs.
Get-Process | ForEach-Object {
    $p = $_
    try { $p.Modules | Where-Object { $_.FileName -like '*TargetFileName*' } |
            ForEach-Object { "OCCUPIED BY: $($p.ProcessName) (PID $($p.Id)) -> $($_.FileName)" } }
    catch {}
}
```

- **Any output** → the file is **mapped**. No ACL change will ever work.
  Go to rename + reboot-delete.
- **No output** → it may genuinely be a permission issue.

## Scripts

Run in order from this skill directory. All `.ps1` are pure ASCII by design
(see Gotchas).

| Script | Mode | Purpose |
|---|---|---|
| `scripts/diagnose.ps1` | normal | Probe occupancy, list drivers/services, confirm EDR |
| `scripts/step2-user-mode.ps1` | **admin** | Clear services/registry/tasks; seize ownership |
| `scripts/step3-enter-safemode.bat` | **admin** | `bcdedit` safeboot, bypasses WinRE lock |
| `scripts/step4-safemode-remove.bat` | safe mode | Delete drivers + install dir |
| `scripts/step5-exit-safemode.bat` | safe mode | Restore normal boot |
| `scripts/step5a-rename-injection.ps1` | **admin** | Rename AMSI DLL → breaks injection |
| `scripts/step5b-queue-reboot-delete.ps1` | **admin** | Write `PendingFileRenameOperations` |
| `scripts/verify.ps1` | **admin** | 10-point verification |
| `scripts/step6-refresh-wsc.ps1` | **admin** | Clear WSC cache entry |

## Workflow

1. **Probe** — occupancy scan + driver/service inventory. Confirm personal device.
2. **Step 2** — admin normal mode. Expect most deletions to FAIL; that is normal
   and not worth retrying. Its value is clearing non-kernel-protected items.
3. **Step 3** — `bcdedit` safe mode. You land in **bare cmd.exe, no desktop**.
4. **Step 4** — in that cmd window, type the full path to the bat. Driver files
   must not be in use, so normal mode cannot delete them.
5. **Step 5** — `exit-safemode.bat`, then normal mode again.
6. **Step 5a** — rename the AMSI DLL. **Rename beats delete when a file is mapped**
   because rename needs only directory write permission, not exclusive file access.
7. **Step 5b** — append paths to `PendingFileRenameOperations`.
8. **Reboot** — Windows drains the queue during early boot, before any process can
   map the file.
9. **Verify** — 10-point check. Items 7 and 9 (Defender) may legitimately fail.
10. **Step 6** — only if WSC still lists the product.

## Gotchas That Cost Real Time

### "Access denied" that is NOT a permission problem

An AMSI Provider DLL mapped into a live process has a kernel section handle
**without `FILE_SHARE_DELETE`**. No amount of `takeown` / `icacls` will help.

```
delete  → needs exclusive file access → always fails while mapped
rename  → needs parent directory write permission → often succeeds
```

### Never escape `$_` in a `.bat`

```cmd
powershell -Command "... \$_.Foo ..."    # WRONG: \$ is bash escaping
powershell -Command "... $_.Foo ..."     # RIGHT
```

Put all PowerShell logic in a separate `.ps1` and have the `.bat` only elevate
and call `-File`. This eliminates the entire class of quoting bugs.

### `"$var:"` breaks the parser

```powershell
Bad   "$n: $($_.Exception.Message)"    # parser error: invalid variable reference
Good  "${n}: $($_.Exception.Message)"   # OK
```

Scan for it after writing any script:

```powershell
Select-String -Path *.ps1,*.bat -Pattern '"\$[A-Za-z_][A-Za-z0-9_]*:'
```

### PowerShell scripts must be pure ASCII

On a CJK-locale Windows, saving a `.ps1` with Chinese comments/strings in ANSI/GBK
crashes the PS 5.1 parser with a misleading "unexpected token" message that looks
like a logic bug. **Keep script text ASCII-only.** Chinese belongs in `Write-Host`
arguments or, better, in the Markdown docs.

### F8 does not work on UEFI

Check `HKLM:\SYSTEM\CurrentControlSet\Control\PE` → `PEFirmwareType`
(`2` = UEFI). On UEFI, "restart and mash F8" is a BIOS-era instruction and does
nothing.

### WinRE may be blocked by an OEM pre-boot lock

If WinRE demands a BitLocker recovery key, the traditional Shift+Restart route is
dead. Diagnose:

```
FVE service ABSENT  +  Control\BitLocker key PRESENT
+  no Settings subkey  →  OEM device encryption / firmware lock
```

`bcdedit` sidesteps it because the pre-boot lock guards WinRE, **not** the normal
boot path:

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} safeboot minimal
```

Trade-off: this boots to **bare cmd.exe**. No Explorer, so `.bat` files must be
invoked by typing their full path.

### bcdedit safe mode leaves `PendingFileRenameOperations` fragile

The queue must be **even-length pairs** of `*2\??\<path>` followed by an **empty
string** (empty target = delete), ordered **deepest first**. Verify existing
entries and repair malformed pairs before appending, or SMSS may skip your
entries or mis-parse unrelated ones.

`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` often returns **error 3**
(`ERROR_PATH_NOT_FOUND`) due to these format requirements. Writing the registry
value directly is more reliable.

### Defender staying disabled is expected

Windows allows only **one** AV product to hold the real-time protection slot.
After removing one EDR, a different vendor usually occupies it, keeping Defender
passive:

```powershell
Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct |
    Select-Object displayName, productState
```

Do **not** advise the user to uninstall a working third-party AV merely to
activate Defender. A passive Defender with an active third-party AV is healthy,
not a fault.

## Communicating Progress

State which layer is being handled at each step and **predict the expected
failure**. Saying "Layer 1 driver will block this and the ACL change will be
reverted" prevents the user from concluding the approach is broken.

## Success Criteria

Fully remediated when: drivers, services, processes, registry keys, install
directory, and AMSI providers are all absent; WSC no longer lists the product.
Defender may remain passive — that is not a failure.