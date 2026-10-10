# 彻底移除 Windows EDR（ThreatBook / 微步在线）实战手册

> 本文档来自 2026-10-10 在一台真实 Windows 10/11 机器上的完整实战记录（LENOVO 21KG，
> UEFI + SecureBoot，WorkBuddy 37.10.3-24）。全部步骤均经过实机验证。
>
> **适用对象**：需要从自己的电脑上彻底清除企业 EDR 终端管理软件的开发者/运维人员。
>
> **风险提示**：移除企业安全管控软件可能违反公司 IT 政策。请先确认这台机器属于你个人，
> 或已获得 IT 部门许可。**本文档不适用于公司配发设备**。

---

## 目录

- [一、先判断值不值得做](#一先判断值不值得做)
- [二、理解 EDR 的四层防护](#二理解-edr-的四层防护)
- [三、准备](#三准备)
- [四、执行流程（5 步）](#四执行流程5-步)
- [五、验证](#五验证)
- [六、常见问题速查](#六常见问题速查)
- [七、关键经验（本文档最有价值的部分）](#七关键经验本文档最有价值的部分)
- [八、为什么 Defender 仍然是关闭的](#八为什么-defender-仍然是关闭的)

---

## 一、先判断值不值得做

### 症状：WorkBuddy / 其他软件反复提示"安装文件损坏或缺失"

如果你遇到以下情况，很可能是 EDR 在暗中隔离文件：

- WorkBuddy 每次启动都弹"安装文件损坏或缺失，无法自动修复，请重新安装"
- 杀毒软件隔离区里躺着某个软件的 exe
- 某个软件装好后，过一段时间 exe 就消失了

**排查方法**：找到软件的安装清单文件（本例是 `resources\install-manifest.json`），
逐个检查清单里的文件是否还在。

```powershell
$root = 'C:\Path\To\App'
$j = Get-Content "$root\resources\install-manifest.json" -Raw | ConvertFrom-Json
$missing = @($j.files | Where-Object { -not (Test-Path (Join-Path $root ($_ -replace '/','\'))) })
"Missing $($missing.Count) / $($j.files.Count):"
$missing
```

**关键判据**：如果缺失的**全部是 `.exe`**，而同目录的 `.dll` / `.json` / `.zip` 都完好，
基本可以确定是杀软隔离，而不是安装不完整。

### 值得清除的信号

| 现象 | 说明 |
|---|---|
| 缺失项全是 exe，其它文件完好 | 高度疑似 EDR 隔离 |
| 安装目录父目录还在、里面空了 | 同上 |
| 目录的 CreationTime 是"未来"（比同安装批文件还新） | 目录壳被重建过 |
| 磁盘上找不到任何被删 exe 的备份/副本 | 抹除而非隔离 |

### 不建议清除的情况

- 公司配发设备 / 有 IT 部门统一管理
- 不确定设备归属

---

## 二、理解 EDR 的四层防护

**这是本文档最重要的一节。** 理解这四层，你才知道每一步在解决什么问题，
也能预判为什么某些方法注定失败。

EDR（Endpoint Detection & Response）的删除阻力分四层，从外到内依次是：

```
第4 层  显示条目残留    ← 纯内存缓存，重启服务即可
   ↓
第 3 层  DLL 注入锁文件  ← AMSI Provider 占住句柄，只能靠重启
   ↓
第 2 层  自监护进程      ← 实时还原 ACL、复活被杀进程
   ↓
第 1 层  内核驱动        ← 拦截一切文件操作，必须进安全模式
```

### 第 1 层：内核驱动

ThreatBook 有两个驱动：

| 驱动 | 路径 | StartMode | 状态 |
|---|---|---|---|
| `TbBoot.sys` | `system32\drivers\` | **Boot** | 比 Windows 启动还早 |
| `TbCardinal.sys` | `system32\Drivers\` | **System** | **Running** |

`TbCardinal` 加载了内核文件过滤回调（minifilter），**拦截一切文件删除/写入操作**。
关键点：**即使是管理员令牌也绕不过内核态拦截。**

查看本机驱���：

```powershell
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -match 'tb|threat' } |
    Select-Object Name, State, StartMode, PathName
```

### 第 2 层：自监护进程

即使你删了服务，EDR 也会实时对抗。本例中 `Agent\data\gol\` 目录下有三个日志目录，
证明有常驻自监护模块：

```
gol\AegisCore\      进程守护（被杀就拉起）
gol\gateway_saas\   服务守护
gol\PlugSaaSEdr\    EDR 插件
```

实测后果：
- `takeown` 改的 Owner 被**主动还原** `BUILTIN\Administrators`
- `MoveFileEx` 预约的删除被**丢弃**

**判据**：如果目录里还在持续产生日志文件，说明它正在实时运行。

### 第 3 层：DLL 注入（AMSI Provider）

这是**最容易被误判为"权限问题"的一层**。

ThreatBook 会安装一个 AMSI（Antimalware Scan Interface）Provider：
`Agent\cardinal\TbAmsiProv64.dll`。它会被注入到**每一个运行中的进程**：

```powershell
# 关键排查命令：找出谁加载了这个 DLL
Get-Process | ForEach-Object {
    $p = $_
    try { $p.Modules | Where-Object { $_.FileName -like '*Threatbook*' } |
            ForEach-Object { "$($p.ProcessName) (PID $($p.Id)) -> $($_.FileName)" } } catch {}
}
```

本例实测结果（这是最关键的发现）：

```
FnHotkeyUtility (PID 18068)  ->  ...\TbAmsiProv64.dll
MessagingPlugin (PID 14324)  ->  同上
powershell     (PID 15428)  ->  同上
WorkBuddy      (PID 9976)   ->  同上
```

**机制**：DLL 一旦被加载，Windows 内核的 section 对象会持有文件句柄，
而这个句柄**不带 `FILE_SHARE_DELETE`**。结果：

- ❌ `del` / `Remove-Item` → "访问被拒绝"
- ❌ 改 ACL（`takeown` / `icacls`）→ 也没用，**这不是权限问题**
- ✅ `rename` → **可以成功**（只需要父目录的写权限，不需文件句柄的独占访问）

**所以：文件被占用时，先改名，不要死磕删除。**

### 第 4 层：WSC 显示条目

全部清干净后，Windows 安全中心（`root\SecurityCenter2`）里可能还显示
`ThreatBook Agent`。这是 `wscsvc` / `SecurityHealthService` 的**纯内存缓存**，
磁盘上已无任何数据支撑它。重启这两个服务即可。

---

## 三、准备

### 1. 确认设备归属

**这一步最重要。** 企业 EDR 是 IT 统一下发的，硬拆可能触发合规告警。

### 2. 创建系统还原点（强烈建议）

```powershell
# 管理员 PowerShell
Checkpoint-Computer -Description "Before EDR removal" -RestorePointType MODIFY_SETTINGS
```

### 3. 确认你有管理员权限

```powershell
$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
"IsAdmin: $($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
```

如果返回 `False`，说明你在 Administrators 组内但当前是普通会话，
运行脚本时会弹 UAC，点"是"即可。

### 4. 摸清本机环境

**这一步决定了后面用哪条路径，务必执行。**

```powershell
# 固件类型：UEFI 的话按 F8 无效
$fw = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PE' -ErrorAction SilentlyContinue
"PEFirmwareType = $($fw.PEFirmwareType)   # 2 = UEFI, 1 = BIOS"

# 快速启动：开着会导致重启绕过 F8
$hs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue
"HiberbootEnabled = $($hs.HiberbootEnabled)"

# BitLocker / 设备加密：会拦 WinRE
"BitLocker key: $(if (Get-Service FVE -ErrorAction SilentlyContinue) {'FVE exists'} else {'no FVE'})"
"PreBoot lock  : $(if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker') {'PRESENT'} else {'none'})"

# 自查 EDR 进程与驱动
Get-Process | Where-Object { $_.ProcessName -match 'tb|threat|erisk' } | Select-Object ProcessName, Id
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -match 'tb|threat' } |
    Select-Object Name, State, StartMode
```

---

## 四、执行流程（5 步）

**总耗时：约 30 分钟**（含两次重启和几次等待）。

### 流程图

```
步骤 1  诊断确认          ──▶ 确认是 EDR 隔离，且值得清除
   ↓
步骤 2  清理用户态        ──▶ 删服务、注册表、非驱动文件（正常模式）
   ↓
步骤 3  进安全模式        ──▶ bcdedit 法绕开 WinRE 锁
   ↓
步骤 4  删内核驱动 + 目录  ──▶ 安全模式里执行
   ↓
步骤 5  断注入 + 重启删除 ──▶ rename 断注入 → 写删除队列 → 重启
   ↓
步骤 6  验证 + 刷新 WSC
```

---

### 步骤 1：诊断确认

```powershell
.\scripts\diagnose.ps1
```

**输出解读**：

| 输出 | 含义 |
|---|---|
| 缺失项全是 `.exe` | 高度疑似 EDR 隔离 |
| 有 `StartMode=Boot/System` 的驱动 | 需要安全模式 |
| `gol` 类日志目录在持续写入 | 自监护在运行 |
| 有进程映射 `*AmsiProv*.dll` | 需要 rename 断注入 |

---

### 步骤 2：清理用户态（正常模式）

**以管理员身份运行**：

```powershell
.\scripts\step2-user-mode.ps1
```

**它做什么**：

1. 列出并确认所有 EDR 进程和服务
2. 停止并禁用服务（被内核驱动拦的会失败，**这是预期的**）
3. 删除计划任务、启动项
4. 清理注册表项和卸载项
5. `takeown` + `icacls` 夺取目录所有权

**关键预期**：这一步**大部分操作会失败**，输出"拒绝访问"。这是正常的。

原因：第 1 层内核驱动在拦截，第 2 层自监护会立刻还原你做的修改。

**这一步的唯一目的**：清理那些**不涉及内核拦截**的部分，以及为后续步骤铺路。

> **不要因为这步失败就反复重试。** 本例中实测 `takeown` 的成果在几秒内被自监护还原。

---

### 步骤 3：进安全模式（绕开 WinRE）

#### ⚠️ 两个必知的坑

**坑 1：UEFI 机器按 F8 无效**

老教程说的"重启狂按 F8"是 BIOS 时代的做法。UEFI 机器上 F8 根本不响应。

**坑 2：WinRE 可能被预启动锁拦截**

如果进入 WinRE 时弹出 BitLocker / 密钥提示，说明被 OEM 预启动锁拦住了。

**预启动锁判据**：

```
FVE 服务不存在  但  HKLM\SYSTEM\CurrentControlSet\Control\BitLocker 键存在
且该键下没有 Settings 子键  →  OEM 预装设备加密 / 固件级锁
```

#### ✅ 通用解法：bcdedit 直接进安全模式

```powershell
# 管理员 PowerShell
.\scripts\step3-enter-safemode.bat
```

它会执行：

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} safeboot minimal
```

然后重启。**不经过 WinRE，因此不会被预启动锁拦。**

**关键差异：bcdedit 法进的是纯 `cmd.exe`，没有桌面、没有资源管理器。**

所以你**不能双击 .bat**，要在 cmd 窗口里手动敲完整路径。

#### 备选：传统方式（WinRE 未被拦时）

1. 按住 **Shift** 点"重启"
2. 疑难解答 → 高级选项 → 启动设置 → 重启
3. 按数字键 **4** 或 **F4**

> 提示：`bcdedit` 会进纯 cmd，`Shift+重启` 进的是带桌面的安全模式。
> 后者更方便，但可能被预启动锁拦住。

---

### 步骤 4：删除内核驱动 + 目录（安全模式内）

在安全模式的 **cmd 窗口**里，敲：

```
%~dp0step4-safemode-remove.bat
```

或者完整路径（把 `path\to` 替换成实际路径）：

```
D:\path\to\remove-threatbook-edr\scripts\step4-safemode-remove.bat
```

**它做什么**：

1. **自检是否真在安全模式**（不是就退出，防止半吊子）
2. 循环杀进程 3 次（守护进程会复活同伴）
3. 停止服务
4. `sc delete` 删除驱动服务
5. `del` 删除 `.sys` 驱动文件
6. 删除安装目录
7. 打印最终复查结果

**成功长什么样**：

```
[ OK ] TbBoot.sys gone
[ OK ] TbCardinal.sys gone
[ OK ] Threatbook folder gone
FAILED 1060: 指定的服务未安装。      ← 这是成功信号！
```

> ⚠️ `FAILED 1060` = "服务未安装" = **已经删掉了**。
> "已标记为删除"（marked for deletion）也是正常的，重启后消失。

#### 退出安全模式

在 cmd 里运行：

```
%~dp0step5-exit-safemode.bat
```

它会 `deletevalue safeboot` 并恢复为正常启动，然后重启。

---

### 步骤 5：断注入 + 排队重启删除

**这是最关键也最容易卡住的一步。**

#### 5a. 先改名（不是删除！）

**以管理员身份**在正常模式下运行：

```powershell
.\scripts\step5a-rename-injection.ps1
```

**原理**：文件被映射时 `delete` 会失败，但 `rename` 可以成功
（只需要父目录写权限，不需要文件句柄的独占访问）。

改名成功后，EDR 就**无法再注入**这个 DLL 了 —— 这本身就是关键胜利。

#### 5b. 写删除队列

```powershell
.\scripts\step5b-queue-reboot-delete.ps1
```

**原理**：把待删路径写进 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
的 `PendingFileRenameOperations`。Windows 会在**早期启动阶段**（还没有任何进程映射
该文件时）执行删除。

**格式要求（踩过坑）**：

```
*2\??\C:\path\to\file      ← NT 风格路径，*2 表示普通文件
（空字符串）                ← 空目标 = 删除
```

- 必须是 **`*2\??\<路径>` + 空串** 成对
- 总长度必须是**偶数**
- 顺序必须**深→浅**（文件 → 子目录 → 父目录 → 根目录），
  否则父目录先删会导致子项删除失败

> ⚠️ 用 `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` API 容易失败（返回 err 3 =
> `ERROR_PATH_NOT_FOUND`），因为路径格式要求。**直接写注册表更可靠。**

#### 5c. 重启

```cmd
shutdown /r /t 0 /f
```

---

### 步骤 6：验证 + 刷新 WSC

```powershell
.\scripts\verify.ps1
```

**10 项检查全部通过的标准**：

```
[1] Services          4 个全部 removed
[2] Kernel drivers    2 个全部 removed
[3] Driver files      2 个全部 deleted
[4] Directories       全部 deleted
[5] Registry keys     全部 cleaned
[6] Uninstall entry   no ThreatBook entry
[7] Defender status   可能仍 disabled（正常，见第八节）
[8] AV products       无 ThreatBook Agent
[9] Defender services 可能仍 Stopped（正常）
[10] AMSI providers   no ThreatBook AMSI provider
```

**第 7/9 项不绿是正常的**，只要 1~6、8、10 全绿就说明清除完成。

如果第 8 项还显示 `ThreatBook Agent`：

```powershell
.\scripts\step6-refresh-wsc.ps1
```

---

## 五、验证

### 独立验证命令

```powershell
# 服务
Get-Service | Where-Object { $_.Name -match 'tbAgent|tbGuard|webthreat' }

# 驱动
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -match 'tb|threat' }

# 驱动文件
Get-ChildItem C:\Windows\System32\drivers\ -Filter 'Tb*.sys'

# 目录
Get-ChildItem 'C:\Program Files (x86)\' -Directory | Where-Object { $_.Name -match 'threat' }

# 进程
Get-Process | Where-Object { $_.ProcessName -match '^tb|CtrlSC' }

# 全盘搜索 exe 被删后是否还有备份
Get-ChildItem C:\ -Recurse -Include '*AmsiProv*.dll','tbAgent*.exe' -ErrorAction SilentlyContinue |
    Select-Object FullName
```

### 确认最初问题已解决

回到第 1 节的诊断命令，重新检查被隔离的软件。如果缺失文件已经补齐
（通过重装该软件），说明根本问题已解决。

---

## 六、常见问题速查

| 现象 | 原因 | 解决 |
|---|---|---|
| 删文件一直"拒绝访问"，改 ACL 也没用 | **DLL 被进程映射**（第 3 层） | 先 `rename`，再排队重启删 |
| `takeown` 成功但几秒后 Owner 变回去 | **自监护还原**（第 2 层） | 先删内核驱动，自托管随驱动死 |
| UEFI 机器按 F8 没反应 | UEFI 不支持 F8 | 用 `bcdedit /set {default} safeboot minimal` |
| WinRE 弹 BitLocker / 密钥提示 | OEM 预启动锁拦 WinRE | 同上，bcdedit 不走 WinRE |
| 进安全模式后重启又进不去 | 快速启动 | `powercfg -h off` 再试 |
| bcdedit 进安全模式后没有桌面 | bcdedit 法特性，正常 | 在 cmd 里手动敲 .bat 路径 |
| `sc delete` 报"已标记为删除" | 句柄未释放 | **正常**，重启后消失 |
| `sc delete` 报 `FAILED 1060` | 服务不存在 | **这是成功信号** |
| `MoveFileEx` 返回 err 3 | 路径格式不对 | 改直接写注册表队列 |
| 全部删完了 WSC 还显示 EDR | 内存缓存（第 4 层） | 重启 `wscsvc` |
| 脚本里中文全变乱码/语法错 | 文件是 ANSI/GBK 编码 | PowerShell 脚本一律用**纯 ASCII** |

---

## 七、关键经验（本文档最有价值的部分）

### 1. 判断"权限问题"还是"文件占用" —— 最高优先级的排查动作

**这是本例浪费最多时间的教训。**

错误做法：反复试 `takeown` / `icacls` / `del`（本例浪费了三轮）

**正确做法**（一步定位）：

```powershell
Get-Process | ForEach-Object {
    $p = $_
    try { $p.Modules | Where-Object { $_.FileName -like '*目标文件名*' } |
            ForEach-Object { "$($p.ProcessName) -> $($_.FileName)" } } catch {}
}
```

**判据**：如果列出任何进程 → 是占用问题，改 ACL 无用，走 rename + 重启。

### 2. 文件被占用时，先 rename，不要死磕 delete

```
delete  → 需要文件的独占访问（被映射时必然失败）
rename  → 只需父目录写权限（被映射时经常成功）
```

### 3. 企业安全软件的卸载入口会被刻意隐藏

本例中：
- 注册表 `UninstallString` **为空** → 控制面板看不到卸载项
- `uninstConfig.xml` 内容**加密** → 卸载流程被保护

**判据**：`UninstallString` 为空 + 配置加密 = 企业统一下发，非个人安装。

### 4. 写 PowerShell 脚本在本机环境要避开两个坑

**坑 1：文件编码**

Write 工具写出的 `.ps1` 在中文 Windows 上是 ANSI/GBK 编码，
中文注释 + 中文字符串会让 PowerShell 5.1 解析器崩溃，
报"表达式或语句中包含意外的标记"（**极具误导性，看起来像语法问题**）。

✅ **结论：PowerShell 脚本一律用纯 ASCII 文本，中文只放在 `Write-Host` 的参数里。**

**坑 2：`$var:` 会被解析成作用域限定符**

```powershell
Bad   "$n: $($_.Exception.Message)"     # ❌ 变量引用无效
Good  "${n}: $($_.Exception.Message)"    # ✅
```

自动扫描手法：

```powershell
Select-String -Path *.ps1,*.bat -Pattern '"\$[A-Za-z_][A-Za-z0-9_]*:'
```

**坑 3：`.bat` 里不要给 PowerShell 的 `$_` 加转义**

```cmd
powershell -Command "... \$_.Foo ..."    # ❌ \$ 是 bash 转义，Windows 不需要
powershell -Command "... $_.Foo ..."     # ✅
```

✅ **根本解法：把 PowerShell 逻辑抽成独立 `.ps1`，`.bat` 只做提权和调 `-File`。**

### 5. bcdedit 比 WinRE 更可靠

WinRE 会被 OEM 预启动锁拦，而预启动锁**不拦正常启动路径**。
所以直接写 BCD 标志进安全模式，绕过整个 WinRE 环节：

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} safeboot minimal
```

### 6. 删除顺序：深→浅

排队删除时，必须文件优先、目录从深到浅。否则父目录先被删，
子项就再也删不掉了。

---

## 八、为什么 Defender 仍然是关闭的

**这是正常现象，不是清除失败。**

Windows 安全中心（WSC）允许注册多个杀软，但**只有一个能持有实时防护槽位**。
清除 EDR 后你可能看到：

```
Lenovo Anti-Virus powered by Huorong Security   ← 占用槽位
Windows Defender                                ← 因此保持被动
```

查询当前占用者：

```powershell
Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct |
    Select-Object displayName, productState
```

`productState` 是十六进制值，位含义：

| 值 | 含义 |
|---|---|
| `0x10` (16) | 已启用 |
| `0x00` | 已禁用 |
| `0x10` 在高字节 | 实时防护开启 |

**要不要让 Defender 接管？**

| 方案 | 做法 | 结果 |
|---|---|---|
| A（推荐） | 什么都不做 | 现有杀软继续防护，Defender 保持被动。**一切正常** |
| B | 卸载第三方杀软 | Defender 接管，但你失去那个杀软的功能 |

**多数情况下选 A。** 第三方 AV 正常工作的情况下，Defender 被动是设计如此，
不是故障。

---

## 免责声明

- 本文档仅用于**个人设备**或已获授权的环境
- 移除企业安全管控可能违反公司政策，请在动手前确认
- 不同 EDR 产品的文件名、服务名、驱动名各不相同，脚本中的名称需要按实际替换
- 操作前务必创建系统还原点
- 你的责任自负

## 许可

MIT License — 见 [LICENSE](LICENSE)。