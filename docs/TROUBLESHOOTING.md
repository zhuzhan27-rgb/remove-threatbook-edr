# 排错手册

按报错信息快速定位。所有条目都来自真实实战。

---

## 脚本本身报错

### `必须在"+"运算符后面提供一个值表达式` / `意外的标记 "\$_.Exception.Message"`

**原因**：`.bat` 里给 PowerShell 的 `$_` 加了 `\$` 转义。`\$` 是 **bash 写法**，
Windows 批处理完全不需要。

```cmd
:: 错误
powershell -Command "... \$_.Exception.Message ..."
:: 正确
powershell -Command "... $_.Exception.Message ..."
```

**根治**：把所有 PowerShell 逻辑放进独立 `.ps1`，`.bat` 只负责提权和调 `-File`。

---

### `变量引用无效。':' 后面的变量名称字符无效`

**原因**：`"$n: ..."` 里 `$n:` 被解析成变量作用域限定符（PowerShell 支持
`$global:var` 这类语法）。

```powershell
# 错误
Bad "$n: $($_.Exception.Message)"
# 正确
Bad "${n}: $($_.Exception.Message)"
```

**自动扫描**：

```powershell
Select-String -Path *.ps1,*.bat -Pattern '"\$[A-Za-z_][A-Za-z0-9_]*:'
```

---

### 脚本中文全部乱码，或者报莫名其妙的语法错误

**原因**：`.ps1` 文件被存成 ANSI/GBK 编码。PowerShell 5.1 读 CJK 注释时
解析器会崩溃，报出的却是"表达式或语句中包含意外的标记"这种**像逻辑错误的提示**。

**判定**：文件里有中文，但报错和中文毫无关系 → 八成就是编码问题。

**解决**：脚本一律用**纯 ASCII 文本**。中文只放在 Markdown 里，
或者运行时作为参数传入。

---

### 脚本被静默忽略，没有任何输出

**可能原因**：当前执行环境会预扫描并拦截含 `takeown` / `icacls` / `sc delete`
等高危命令的脚本，即使只跑只读分支也会被吞掉，且**不报错**。

**解决**：这类脚本必须由用户在**自己的终端**里以管理员身份运行。

---

## 删除操作报错

### `拒绝访问` / `另一个程序正在使用此文件`

**先做这一步**，不要改权限：

```powershell
Get-Process | ForEach-Object {
    $p = $_
    try { $p.Modules | Where-Object { $_.FileName -like '*目标文件名*' } |
            ForEach-Object { "$($p.ProcessName) -> $($_.FileName)" } } catch {}
}
```

**有输出** → 文件被进程映射。改 ACL 无效（句柄不带 `FILE_SHARE_DELETE`）。
走「先 rename，再排队重启删」。

**无输出** → 可能是真权限问题，先 `takeown` + `icacls`。

---

### `takeown` 成功了，但几秒后 Owner 变回 Administrators

**原因**：EDR 自监护模块在实时还原。

**判据**：目录里有持续写入的日志目录，如 `Agent\data\gol\`。

**解决**：不要纠缠，先把内核驱动删掉 —— 自托管模块随驱动一起失效。

---

### `sc delete` 报 `FAILED 1060: 指定的服务未安装`

**这是成功信号。** 意思是"服务已经不存在了"。

---

### `sc delete` 报「已标记为删除」/ `marked for deletion`

**正常现象。** 驱动句柄还被引用，重启后自动消失，不用管。

---

### `MoveFileEx` 返回 err 3 (`ERROR_PATH_NOT_FOUND`)

**原因**：`PendingFileRenameOperations` 队列对路径格式有严格要求：

```
*2\??\C:\path\to\file      NT 风格路径，*2 = 普通文件
（空字符串）                空目标 = 删除
```

规则：
- 必须成对，总长度为偶数
- 顺序必须**深→浅**
- 用 API 容易踩格式坑，**直接写注册表更可靠**

---

## 安全模式相关

### UEFI 机器按 F8 毫无反应

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PE').PEFirmwareType
# 2 = UEFI, 1 = BIOS
```

UEFI 上 F8 是 BIOS 时代的指令，无效。

**解决**：用 `bcdedit`（见下）。

---

### 重启后没出现启动菜单 / 又被拉回正常模式

**原因**：快速启动（Fast Startup）开着。"重启"实际走休眠恢复，绕过完整启动流程。

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
```

**解决**：`powercfg -h off`

---

### 进入 WinRE 时弹 BitLocker / 密钥提示

**原因**：OEM 预启动加密锁拦住了 WinRE。

**判据**（三者同时成立）：
```
FVE 服务不存在
且 HKLM\SYSTEM\CurrentControlSet\Control\BitLocker 键存在
且该键下没有 Settings 子键
```

**解决**：`bcdedit` 不经过 WinRE，因此不受影响：

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} safeboot minimal
```

---

### 用 bcdedit 进安全模式后没有桌面

**不是故障。** bcdedit 法直接落在 `cmd.exe`，没有 Explorer。

**解决**：在 cmd 窗口里手动敲完整路径运行 `.bat`：

```
D:\path\to\remove-threatbook-edr\scripts\step4-safemode-remove.bat
```

---

### `bcdedit` 报「拒绝访问」或「无法打开启动配置数据存储」

需要管理员权限。普通会话下 bcdedit 无法读取 BCD。

---

### `bcdedit /deletevalue` 报「参数错误」

手敲命令时漏了大括号。`{default}` 的花括号是必须的。

**解决**：直接用 `step5-exit-safemode.bat`，它已经处理好了。

---

## 安全模式脚本自检失败

### 提示 `NOT in Safe Mode` / `[!!] ABORT`

脚本用这个判据检测安全模式：

```powershell
Test-Path 'C:\Windows\System32\config\system'
```

**不存在 = 在安全模式**（安全模式下该注册表文件会被移走）。

**失败** → 没真正进安全模式，重来。

**为什么不自动继续**：正常模式下强行删内核驱动会留下半吊子状态，
后续更难收拾。宁可中断。

---

## 验证阶段

### 验证项 7/9 不绿（Defender）

**正常，不用处理。**

Windows 只允许一个 AV 持有实时防护槽位。查占用者：

```powershell
Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct |
    Select-Object displayName, productState
```

通常清除一个 EDR 后，另一个第三方杀软会占住这个槽位，让 Defender 保持被动。
**这是健康状态，不是清除失败。**

除非你确实需要 Defender，否则**不建议为此卸载第三方杀软**。

---

### 全部删完了，Windows 安全中心还显示 ThreatBook

**原因**：`wscsvc` / `SecurityHealthService` 的内存缓存。

**解决**：

```powershell
.\scripts\step6-refresh-wsc.ps1
```

**最后一招**（仅在上面的脚本无效时用）：结束托管 `SecurityCenter2` 的
WMI 宿主进程，Windows 会自动重启它并重新枚举。

```powershell
Get-CimInstance Win32_Process -Filter "Name='wmiprvse.exe'" |
    Select-Object ProcessId, CommandLine
# 找到命令行含 SecurityCenter 的那个
Stop-Process -Id <PID> -Force
```

⚠️ 结束 `wmiprvse.exe` 会短暂影响依赖 WMI 的服务（一般几秒内自动恢复）。
不确定就别做 —— **重启电脑也能达到同样效果**。

---

## 换用其他 EDR 产品怎么办

本仓库脚本针对 ThreatBook（微步在线）。其他产品需要改这些变量：

| 变量 | 位置 | 作用 |
|---|---|---|
| `$EDR_PROC` | 各脚本顶部 CONFIG 区 | 进程名列表 |
| `$EDR_SVC` | 各脚本顶部 CONFIG 区 | 服务名列表 |
| `$EDR_DRV` | `diagnose.ps1` | 驱动名列表 |
| `$EDR_DIRS` | 各脚本顶部 CONFIG 区 | 安装目录 |
| `$TBROOT` | `step5a` / `step5b` | 安装根目录 |
| `$AMSI_REL` | `step5a` | AMSI Provider DLL 相对路径 |

**先跑 `diagnose.ps1`**，它会列出本机实际的进程/服务/驱动，
把上面这些变量填对即可。

常见 EDR 的进程/服务命名规律：

| 产品 | 常见标识 |
|---|---|
| ThreatBook / 微步 | `tbAgent*`, `tbGuard*`, `TbCardinal`, `TbBoot` |
| CrowdStrike | `CSFalcon*`, `CSAgent` |
| SentinelOne | `SentinelOne*`, `SentinelAgent` |
| Carbon Black | `RepMgr`, `cb` |
| 360 | `360*`, `qhsafemon` |
| 火绒 | `Hips*`, `SysDiag`, `wsctrl11` |

---

## 判定是否真的成功

```powershell
# 1. 服务
Get-Service | Where-Object { $_.Name -match 'tbAgent|tbGuard|webthreat' }

# 2. 驱动
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -match 'tb|threat' }

# 3. 驱动文件
Get-ChildItem C:\Windows\System32\drivers\ -Filter 'Tb*.sys'

# 4. 目录
Get-ChildItem 'C:\Program Files (x86)\' -Directory | Where-Object { $_.Name -match 'threat' }

# 5. 进程
Get-Process | Where-Object { $_.ProcessName -match '^tb|CtrlSC' }

# 6. 全盘搜索残留（耗时较长）
Get-ChildItem C:\ -Recurse -Include '*AmsiProv*.dll', 'tbAgent*.exe' -ErrorAction SilentlyContinue |
    Select-Object FullName
```

全为空 = 清除完成。

---

## 最后提醒

- 只在**个人设备**或已获授权的环境操作
- 操作前创建系统还原点：`Checkpoint-Computer -Description "before" -RestorePointType MODIFY_SETTINGS`
- 本仓库脚本在目标机器上验证通过，但**你的环境可能不同**
- 动手前务必先跑 `diagnose.ps1`，根据输出调整 CONFIG 变量