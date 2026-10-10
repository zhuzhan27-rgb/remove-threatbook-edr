# Scripts

All scripts are **ASCII-only** by design (see [Troubleshooting](docs/TROUBLESHOOTING.md)
for why). PowerShell 5.1 on CJK-locale Windows crashes on ANSI/GBK-encoded
`.ps1` files with misleading parser errors.

> **Validation status**
>
> All `.ps1` files pass static analysis:
> `[System.Management.Automation.Language.Parser]::ParseFile()` → **0 errors**,
> 0 non-ASCII bytes, no `\$` bash-escaping, no `"$var:"` hazards.
>
> The scripts were **derived from a successful manual run** on the target
> machine. However, `diagnose.ps1` was **not executed end-to-end** in this
> sandbox (process-module introspection is blocked there). Run `diagnose.ps1`
> first on any new machine — it is read-only and safe.

---

## Execution Order

| # | Script | Mode | Admin? | Purpose |
|---|---|---|---|---|
| 1 | `diagnose.ps1` | normal | no | Read-only recon. **Always start here.** |
| 2 | `step2-user-mode.ps1` | normal | **yes** | Clear services/registry/tasks. Many failures expected. |
| 3 | `step3-enter-safemode.bat` | normal | **yes** | `bcdedit` safeboot, bypasses WinRE lock |
| 4 | `step4-safemode-remove.bat` | **safe mode** | yes | Delete drivers + install dir |
| 5 | `step5-exit-safemode.bat` | **safe mode** | yes | Restore normal boot |
| 6 | `step5a-rename-injection.ps1` | normal | **yes** | Rename AMSI DLL → breaks injection |
| 7 | `step5b-queue-reboot-delete.ps1` | normal | **yes** | Queue delete for early boot |
| — | **reboot** | | | `shutdown /r /t 0 /f` |
| 8 | `verify.ps1` | normal | **yes** | 10-point check |
| 9 | `step6-refresh-wsc.ps1` | normal | **yes** | Only if WSC still lists the product |

---

## Notes per Script

### `diagnose.ps1`
Read-only. The **occupancy probe** (section 5) is the single most valuable
command in this repo:

```powershell
Get-Process | ForEach-Object {
    $p = $_
    try { $p.Modules | Where-Object { $_.FileName -like '*TargetDll*' } |
            ForEach-Object { "OCCUPIED: $($p.ProcessName) -> $($_.FileName)" } } catch {}
}
```

Run this **before** touching any ACL. If it lists a process, the file is
*mapped* and no permission change will ever work.

### `step2-user-mode.ps1`
Most operations here fail by design (kernel driver + self-guard).
**Do not retry in a loop.** Its value is clearing unprotected items only.

### `step4-safemode-remove.bat`
Self-checks it is genuinely in Safe Mode via
`Test-Path 'C:\Windows\System32\config\system'` and **aborts if not**,
to avoid leaving a half-removed state.

Invoke by **typing its full path** in the bare cmd window — there is no
desktop in bcdedit Safe Mode.

### `step5a-rename-injection.ps1`
Renames rather than deletes. Rename requires only parent-directory write
permission, while delete requires exclusive file access — which a mapped
file never grants.

### `step5b-queue-reboot-delete.ps1`
Writes `PendingFileRenameOperations` directly.

Format is strict:
```
*2\??\C:\path\to\file
(empty string)          <- empty target means delete
```
- even number of strings
- **deepest first**

Validates and repairs the existing queue before appending, so a malformed
queue cannot cause SMSS to mis-parse unrelated entries.

### `verify.ps1`
Items **7 and 9** (Defender) may legitimately fail — another AV vendor
holds the single real-time protection slot. That is healthy, not a fault.
Success = items 1–6, 8, 10 pass.

---

## Adapting to Other EDR Products

Each script has a `CONFIG` block at the top. Replace the names for your product:

| Variable | Meaning |
|---|---|
| `$EDR_PROC` | process names |
| `$EDR_SVC` | service names |
| `$EDR_DRV` | driver names |
| `$EDR_DIRS` | install directories |
| `$TBROOT` | install root (used by step5a / step5b) |
| `$AMSI_REL` | AMSI provider DLL relative path |

Run `diagnose.ps1` on the target machine first — it prints the actual
processes/services/drivers it finds.

---

## PowerShell Invocation Notes

Some execution environments silently block scripts containing privileged
operations (`takeown`, `icacls`, `sc delete`, or process-module
introspection) **even on read-only code paths**, with no error message —
the run simply produces zero output.

If that happens to you, run the script yourself in a terminal you control:

```powershell
# Right-click PowerShell -> Run as administrator
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\diagnose.ps1
```