# Windows NTFS 取证 Artifact 详解

> NTFS 文件系统在多个层面记录文件操作痕迹，蓝队据此重建攻击时间线，红队需逐一清除

---

## 一、$MFT (Master File Table)

NTFS 的核心元数据结构，每个文件/目录对应一条 MFT 记录（通常 1024 字节）。

### 1.1 MACE 时间戳

每条 MFT 记录包含 **两组** 时间戳，每组 4 个时间（共 8 个）：

| 缩写 | 含义 | 说明 |
|------|------|------|
| M | Modified | 文件内容最后修改时间 |
| A | Accessed | 文件最后访问时间 |
| C | Changed ($MFT Modified) | MFT 记录本身的修改时间 |
| E | Entry Created (Birth) | 文件创建时间 |

两组时间戳存在于不同属性中：

| 属性 | API 可修改 | 说明 |
|------|-----------|------|
| **$STANDARD_INFORMATION ($SI)** | 是（SetFileTime API / PowerShell / touch） | 用户和大多数工具看到的时间 |
| **$FILE_NAME ($FN)** | 否（只能通过内核级操作修改） | 由 NTFS 驱动维护，仅在文件创建/重命名/移动时更新 |

### 1.2 Timestomping 检测（蓝队核心技术）

```
检测逻辑：对比 $SI 和 $FN 的时间戳
├─ 正常文件: $SI.Created ≈ $FN.Created（差异在秒级内）
├─ Timestomped: $SI.Created 远早于 $FN.Created
│   例: $SI.Created = 2020-01-01, $FN.Created = 2025-03-15
│   → 文件实际在 2025-03-15 创建，$SI 被篡改为 2020 年
├─ 另一个指标: $SI.Modified 早于 $FN.Created
│   → 逻辑上不可能（文件修改时间不能早于文件创建时间）
└─ 纳秒精度异常: $SI 时间的纳秒部分全为 0
    → 部分 timestomp 工具不设置纳秒位
```

### 1.3 MFT 分析工具

```bash
# MFTECmd（Eric Zimmerman 工具集） — 推荐
MFTECmd.exe -f C:\$MFT --csv output/ --csvf mft_parsed.csv

# analyzeMFT（Python）
python3 analyzeMFT.py -f \$MFT -o mft_output.csv -e

# 用 Sleuth Kit 提取 $MFT
icat /path/to/image 0 > extracted_mft

# Timeline Explorer 打开 CSV → 排序/过滤时间异常
# 重点关注: $SI Created vs $FN Created 差异 > 1小时的记录
```

### 1.4 红队: MFT 痕迹处理

```
限制：MFT 条目无法通过常规 API 删除记录，文件删除后 MFT 记录仍存在
├─ 策略 1: 不落盘 → 彻底避免 MFT 记录
├─ 策略 2: Timestomp $SI（简单但 $FN 不一致会暴露）
├─ 策略 3: 使用 SetMACE 等工具同时修改 $SI 和 $FN
│   需要内核级权限或直接操作 NTFS 扇区
├─ 策略 4: 将文件写入已有文件的 ADS（不产生新 MFT 条目）
└─ 策略 5: 操作后用 SDelete 覆写，MFT 条目标记为未使用
    但取证仍可恢复未使用条目！
```

---

## 二、$UsnJrnl (Update Sequence Number Journal)

NTFS 变更日志，记录文件系统上 **所有文件/目录变更操作**。位于 `$Extend\$UsnJrnl` 的 `$J` 数据流。

### 2.1 记录的操作类型

| Reason Flag | 含义 | 红队动作 |
|------------|------|---------|
| USN_REASON_FILE_CREATE | 文件创建 | 工具落盘 |
| USN_REASON_FILE_DELETE | 文件删除 | 工具清理 |
| USN_REASON_DATA_OVERWRITE | 数据覆写 | 文件修改 |
| USN_REASON_RENAME_NEW_NAME | 重命名（新名） | 文件伪装 |
| USN_REASON_RENAME_OLD_NAME | 重命名（原名） | 暴露原始名 |
| USN_REASON_SECURITY_CHANGE | 权限变更 | 提权操作 |
| USN_REASON_CLOSE | 文件关闭 | 操作完成 |

### 2.2 USN Journal 分析

```bash
# 提取 $UsnJrnl:$J（离线镜像）
# 使用 FTK Imager / icat 从镜像提取

# MFTECmd 解析（推荐）
MFTECmd.exe -f C:\$Extend\$UsnJrnl:$J --csv output/ --csvf usnjrnl.csv

# usn.py（Python）
python3 usn.py -f usnjrnl_extracted -o usn_output.csv

# fsutil（活系统查询，需管理员）
fsutil usn readjournal C: > usn_raw.txt
fsutil usn queryjournal C:    # 查看 Journal 状态

# ⛔ 取证关键：即使文件已被删除，USN Journal 仍然记录了
#   文件名、操作时间、父目录 MFT 引用
#   可以重建 "某个工具在某时被创建 → 执行 → 删除" 的完整链条
```

### 2.3 红队: USN Journal 清除

```cmd
:: 删除整个 USN Journal（需管理员）
fsutil usn deletejournal /d C:

:: ⛔ 注意：删除 Journal 本身会被记录为异常事件
:: 且 SIEM 可能监控 fsutil 执行（EventID 4688）
:: 更隐蔽的方式：让 Journal 自然滚动覆盖（默认大小 32MB-64MB）
:: 大量写入无关文件 → 填满 Journal → 旧记录被覆盖

:: 查看 Journal 大小
fsutil usn queryjournal C:
```

---

## 三、Prefetch

Windows 预读取文件，记录程序执行信息。位于 `C:\Windows\Prefetch\`，格式为 `<APPNAME>-<HASH>.pf`。

### 3.1 Prefetch 包含的信息

| 数据 | 取证价值 |
|------|---------|
| 可执行文件名 | 什么工具被执行 |
| 执行次数 | 执行了几次 |
| 最后执行时间 | 最后 8 次执行的时间戳（Win10+） |
| 加载的 DLL/文件列表 | 关联文件分析 |
| 所在卷信息 | 从哪个盘符执行 |

### 3.2 Prefetch 分析工具

```bash
# PECmd（Eric Zimmerman） — 推荐
PECmd.exe -d C:\Windows\Prefetch\ --csv output/ --csvf prefetch.csv

# 分析单个 Prefetch 文件
PECmd.exe -f C:\Windows\Prefetch\MIMIKATZ.EXE-12345678.pf

# WinPrefetchView（NirSoft，GUI）
WinPrefetchView.exe

# Python: libscca
python3 -c "import pyccsa; # ..."

# ⛔ 取证关键：
# 即使攻击者删除了工具文件，Prefetch 仍记录执行事实
# 文件名哈希基于文件路径 → 不同路径的同名工具产生不同 .pf
# Win10 最多保存 1024 个 Prefetch 文件
# Win7 最多保存 128 个
```

### 3.3 红队: Prefetch 清除

```cmd
:: 删除特定工具的 Prefetch
del C:\Windows\Prefetch\TOOLNAME*.pf

:: 删除所有 Prefetch（更可疑）
del C:\Windows\Prefetch\*.pf

:: 禁用 Prefetch（需重启生效，非常可疑）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f

:: ⛔ 最佳策略：不使用独立 EXE → 反射加载/LOLBins → 不产生新 Prefetch
:: 注意：通过 rundll32.exe 执行 DLL 会产生 RUNDLL32.EXE 的 Prefetch
::       但 Prefetch 中的加载文件列表会包含你的 DLL 路径
```

---

## 四、Amcache

应用程序兼容性缓存，位于 `C:\Windows\AppCompat\Programs\Amcache.hve`（注册表 hive 文件）。

### 4.1 Amcache 记录的信息

| 数据 | 说明 |
|------|------|
| 完整文件路径 | 精确的可执行文件位置 |
| SHA1 哈希 | 可送 VT 查询 |
| 文件大小 | 辅助确认 |
| 编译时间 | PE TimeDateStamp |
| 发布者 | 签名信息 |
| 首次执行时间 | 程序首次运行时间（Key LastWrite） |

### 4.2 分析工具

```bash
# AmcacheParser（Eric Zimmerman）
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv output/ --csvf amcache.csv

# 也可直接在 Registry Explorer 中打开 Amcache.hve 浏览

# ⛔ 取证关键：
# Amcache 记录了 SHA1 → 即使删了文件也能确认恶意工具
# 时间精确到首次出现 → 锁定攻击时间窗口
# 配合 Prefetch → 首次执行(Amcache) + 最后8次执行(Prefetch)
```

### 4.3 红队: Amcache 清除

```cmd
:: Amcache.hve 是活跃注册表，直接删除会失败
:: 方式 1: 通过注册表操作删除条目
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appcompat\Programs" /f

:: 方式 2: 离线修改（需停止相关服务或从 WinPE 操作）
:: 方式 3: 使用工具精确删除
:: GitHub: amcache_cleaner.py — 删除指定 SHA1 的记录
```

---

## 五、Shimcache (AppCompatCache)

应用程序兼容性缓存，存储在注册表 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` 中。

### 5.1 Shimcache 特点

```
关键区别：
├─ Shimcache 在内存中维护，关机/重启时才写入注册表
├─ 记录文件路径 + 最后修改时间 + （Win7）执行标志
├─ Win10: 不再记录执行标志，只记录文件"被操作系统注意到"
├─ 条目数量：Win10 最多 1024 条
└─ 新条目插入到列表头部 → 越靠前越新
```

### 5.2 分析

```bash
# AppCompatCacheParser（Eric Zimmerman）
AppCompatCacheParser.exe --csv output/ --csvf shimcache.csv

# ShimCacheParser（Mandiant）
python3 ShimCacheParser.py -i SYSTEM -o shimcache_output.csv

# ⛔ 取证要点：
# Shimcache 包含文件存在的证据，但不一定代表执行
# 配合 Prefetch/Amcache 交叉验证执行事实
# 关机前内存中的 Shimcache 数据最新 → 分析内存 dump 可获取未落盘的记录
```

### 5.3 红队: Shimcache 清除

```cmd
:: Shimcache 在内存中，关机时写入注册表
:: 策略 1: 操作完成后不正常关机（直接断电/蓝屏）→ 内存中的新条目不写入注册表
:: 策略 2: 正常关机前修改注册表中的 AppCompatCache 值
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f

:: ⛔ 但这会删除所有 Shimcache → 非常可疑
:: 策略 3: 使用工具精确删除内存中 Shimcache 的特定条目（需内核操作）
```

---

## 六、LNK 文件与 Jump Lists

### 6.1 LNK 快捷方式文件

文件访问时自动生成，位于 `%APPDATA%\Microsoft\Windows\Recent\`。

```
LNK 文件记录：
├─ 目标文件的完整路径
├─ 目标文件的 MACE 时间戳
├─ 目标文件大小
├─ 所在卷的序列号和类型（本地/网络/可移动）
├─ 网络共享路径（如果从网络访问）
├─ 机器的 NetBIOS 名称（可用于确认来源主机）
└─ MAC 地址（嵌入在 Machine ID 的 Object ID 中）
```

### 6.2 Jump Lists

任务栏应用的最近文件记录，位于：
- 自动生成：`%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\`
- 手动固定：`%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\`

文件名格式：`<AppID>.automaticDestinations-ms`（实质是 OLE/CF 文件）

### 6.3 分析工具

```bash
# LECmd（LNK Explorer，Eric Zimmerman）
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent" --csv output/ --csvf lnk.csv

# JLECmd（Jump List Explorer）
JLECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" --csv output/ --csvf jumplist.csv

# ⛔ 取证关键：
# LNK 记录了被访问文件的历史状态（时间戳、大小）
# 即使原始文件被删除，LNK 中仍保存了这些信息
# 网络共享 LNK → 横向移动证据（记录了目标主机名/IP）
# Jump List → 应用使用历史（哪个程序打开了哪些文件）
```

### 6.4 红队: LNK/JumpList 清除

```cmd
:: 删除 Recent 文件夹
del /f /q "%APPDATA%\Microsoft\Windows\Recent\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"

:: ⛔ 注意：资源管理器可能锁定这些文件
:: 使用 PowerShell 强制清理
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse
```

---

## 七、$Recycle.Bin

回收站结构，每个用户 SID 对应一个子目录。

### 7.1 文件结构

```
C:\$Recycle.Bin\<USER_SID>\
├─ $IXXXXXX.ext    → 元数据文件（原始路径、删除时间、文件大小）
└─ $RXXXXXX.ext    → 实际文件内容（原始数据完整保留）

命名规则：$I 和 $R 后的随机字符相同，配对使用
例：$I2A3B4C.exe 对应 $R2A3B4C.exe
```

### 7.2 $I 文件结构（Win10+）

| 偏移 | 大小 | 内容 |
|------|------|------|
| 0x00 | 8 bytes | Header (版本号: 01/02) |
| 0x08 | 8 bytes | 原始文件大小 |
| 0x10 | 8 bytes | 删除时间（FILETIME 格式） |
| 0x18 | 4 bytes | 文件名长度（Win10 v2） |
| 0x1C | Variable | 原始完整路径（Unicode） |

### 7.3 分析

```bash
# RBCmd（Eric Zimmerman）
RBCmd.exe -d "C:\$Recycle.Bin" --csv output/ --csvf recyclebin.csv

# 手动解析 $I 文件
python3 -c "
import struct, datetime
with open('\$I2A3B4C.exe', 'rb') as f:
    data = f.read()
    size = struct.unpack('<Q', data[8:16])[0]
    ts = struct.unpack('<Q', data[16:24])[0]
    # FILETIME to datetime
    dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ts//10)
    print(f'Size: {size}, Deleted: {dt}')
    # Win10 v2: filename at offset 0x1C
    name_len = struct.unpack('<I', data[24:28])[0]
    name = data[28:28+name_len*2].decode('utf-16-le')
    print(f'Original: {name}')
"

# ⛔ 取证关键：
# 攻击者 "del file.exe" 后文件进入回收站 → 完整内容可恢复
# $I 文件暴露原始路径和删除时间 → 精确时间线
```

### 7.4 红队: 回收站处理

```cmd
:: Shift+Del 或 cmd 的 del 不经过回收站
:: 但通过资源管理器删除的默认进回收站

:: 清空回收站
rd /s /q C:\$Recycle.Bin

:: PowerShell 清空当前用户回收站
Clear-RecycleBin -Force

:: ⛔ 最佳实践：始终使用 cmd 的 del 或 Shift+Del
:: 或使用 SDelete 安全删除 → 不进回收站且覆写数据
```

---

## 八、VSS (Volume Shadow Copy)

卷影副本，Windows 自动创建的文件系统快照。

### 8.1 VSS 的取证价值

```
VSS 快照保存了创建时刻的完整文件系统状态：
├─ 已被攻击者删除的文件 → 在旧快照中可能仍然存在
├─ 被修改的注册表 → 对比快照前后差异
├─ 被清除的日志 → 旧快照中可能还有完整日志
├─ 时间线重建 → 多个快照 = 多个时间点的状态
└─ Ransomware → 加密前的快照 = 数据恢复
```

### 8.2 VSS 分析

```cmd
:: 列出所有卷影副本
vssadmin list shadows

:: 创建符号链接访问卷影副本
mklink /d C:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

:: 使用 vshadowinfo（libvshadow）
vshadowinfo /path/to/image

:: 使用 ShadowExplorer（GUI 工具）浏览/提取快照文件
```

```bash
# 取证工作站上挂载 VSS（Linux）
vshadowmount /path/to/image /mnt/vss/
ls /mnt/vss/   # 每个快照一个目录: vss1, vss2, ...
mount -o ro,loop /mnt/vss/vss1 /mnt/snapshot1/

# 对比不同快照
diff <(find /mnt/snapshot1/ -type f | sort) <(find /mnt/snapshot2/ -type f | sort)

# 从 VSS 恢复被删除的文件
cp /mnt/snapshot1/path/to/deleted_file /evidence/
```

### 8.3 红队: VSS 清除

```cmd
:: 删除所有卷影副本（Ransomware 常用手法，非常可疑）
vssadmin delete shadows /all /quiet

:: 使用 WMI 删除
wmic shadowcopy delete

:: 使用 PowerShell
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }

:: 禁用 VSS 服务
sc stop VSS
sc config VSS start= disabled

:: ⛔ 注意：删除 VSS 会触发：
:: - EventID 7036（VSS 服务状态变更）
:: - Sysmon 进程创建事件（vssadmin.exe / wmic.exe）
:: - SIEM 可能有专门规则检测 "vssadmin delete shadows"
```

---

## 九、其他重要 Artifact

### 9.1 $LogFile

NTFS 事务日志，记录文件系统元数据变更。

```bash
# 提取 $LogFile
icat /path/to/image 2 > logfile_extracted

# LogFileParser 分析
python3 LogFileParser.py -f logfile_extracted -o logfile_output.csv

# 取证价值：可恢复最近的文件操作（即使 MFT 已被修改）
# 红队对策：无法直接清除活跃的 $LogFile
```

### 9.2 Thumbcache

缩略图缓存，位于 `%LocalAppData%\Microsoft\Windows\Explorer\`。

```bash
# thumbcache_*.db 文件（按分辨率分）
# Thumbcache Viewer 工具分析
# 取证价值：即使图片已删除，缩略图仍在缓存中

# 红队清除
del /f /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db"
```

### 9.3 Windows Search Index

`C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`

```bash
# 使用 ESEDatabaseView（NirSoft）或 esedbexport 提取
esedbexport Windows.edb

# 搜索索引包含文件名/部分内容/属性 → 即使文件已删除也有记录
```

### 9.4 SRUM (System Resource Usage Monitor)

`C:\Windows\System32\sru\SRUDB.dat`

```bash
# SrumECmd（Eric Zimmerman）
SrumECmd.exe -f SRUDB.dat --csv output/

# 记录每个应用的网络使用量、CPU 时间、电量消耗
# 取证价值：C2 通信的网络流量统计（即使没有网络日志）
```

---

## 十、综合取证工作流

### 完整 Windows NTFS 取证时间线重建

```bash
# Step 1: 提取并解析所有 artifact
MFTECmd.exe -f \$MFT --csv output/
MFTECmd.exe -f \$UsnJrnl:\$J --csv output/
PECmd.exe -d C:\Windows\Prefetch\ --csv output/
AmcacheParser.exe -f Amcache.hve --csv output/
AppCompatCacheParser.exe --csv output/
LECmd.exe -d Recent\ --csv output/
RBCmd.exe -d \$Recycle.Bin --csv output/

# Step 2: 合并时间线
# 使用 Timeline Explorer 或 Plaso 合并所有 CSV

# Step 3: 交叉验证
# MFT → 文件存在证据 + 时间
# USN Journal → 文件操作序列
# Prefetch → 程序执行证据
# Amcache → SHA1 哈希 + 首次出现
# Shimcache → 文件被系统注意到
# LNK/JumpList → 用户交互证据
# Recycle Bin → 删除操作证据
# VSS → 历史状态快照
```

### 红队完整反取证清单

```
操作后清除优先级（从高到低）：
├─ [P0] Prefetch: del C:\Windows\Prefetch\TOOLNAME*.pf
├─ [P0] Recent/LNK: del %APPDATA%\...\Recent\*
├─ [P1] USN Journal: fsutil usn deletejournal /d C:
├─ [P1] Amcache: 注册表删除对应条目
├─ [P1] Event Log: wevtutil cl Security（或精准删除）
├─ [P2] Shimcache: 内存中清除（复杂）
├─ [P2] VSS: vssadmin delete shadows /all /quiet
├─ [P2] Recycle Bin: rd /s /q C:\$Recycle.Bin
├─ [P3] Thumbcache: 删除 thumbcache_*.db
├─ [P3] SRUM: 难以清除（ESE 数据库锁定）
├─ [P3] $LogFile: 无法直接操作
└─ [P3] $MFT: 已删除文件的 MFT 条目仍可恢复

⛔ 终极策略：从一开始就不落盘
├─ 反射加载（不产生 MFT/Prefetch/Amcache/Shimcache）
├─ LOLBins 执行（使用已有系统文件，不引入新 artifact）
├─ 内存操作（/dev/shm 或 Named Pipe）
└─ 工具通过管道传输（curl | powershell -）
```

---

## 十一、Eric Zimmerman 工具集速查

所有工具下载: https://ericzimmerman.github.io/#!index.md

| 工具 | 分析目标 | 命令示例 |
|------|---------|---------|
| MFTECmd | $MFT, $UsnJrnl, $Boot, $SDS | `MFTECmd.exe -f $MFT --csv out/` |
| PECmd | Prefetch (.pf) | `PECmd.exe -d Prefetch/ --csv out/` |
| AmcacheParser | Amcache.hve | `AmcacheParser.exe -f Amcache.hve --csv out/` |
| AppCompatCacheParser | Shimcache | `AppCompatCacheParser.exe --csv out/` |
| LECmd | LNK 文件 | `LECmd.exe -d Recent/ --csv out/` |
| JLECmd | Jump Lists | `JLECmd.exe -d AutomaticDestinations/ --csv out/` |
| RBCmd | $Recycle.Bin | `RBCmd.exe -d $Recycle.Bin --csv out/` |
| RECmd | 注册表 hive | `RECmd.exe -f NTUSER.DAT --csv out/` |
| SrumECmd | SRUM DB | `SrumECmd.exe -f SRUDB.dat --csv out/` |
| EvtxECmd | Windows Event Log | `EvtxECmd.exe -d Logs/ --csv out/` |
| Timeline Explorer | CSV 时间线浏览 | GUI 工具，打开上述输出的 CSV |
