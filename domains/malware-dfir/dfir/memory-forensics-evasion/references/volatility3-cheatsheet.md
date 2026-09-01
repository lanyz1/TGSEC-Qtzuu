# Volatility3 完整插件速查手册

> 适用版本: Volatility 3.x | 基本语法: `vol -f <memory_dump> <plugin>`

---

## 一、系统信息

```bash
# 操作系统识别（自动判断 profile，Vol3 无需手动指定）
vol -f mem.raw windows.info
vol -f mem.raw linux.info
vol -f mem.raw mac.info

# banners.Banners — 扫描内存中的 OS banner 字符串
vol -f mem.raw banners.Banners
```

---

## 二、进程分析

### 2.1 进程列出

```bash
# pslist — 遍历 EPROCESS 双向链表（Rootkit 可通过 DKOM unlink 隐藏）
vol -f mem.raw windows.pslist
vol -f mem.raw windows.pslist --pid 1234
vol -f mem.raw windows.pslist --dump  # 导出进程可执行文件

# psscan — 池标签扫描（能找到已终止/隐藏的进程）
vol -f mem.raw windows.psscan

# pstree — 进程树（父子关系可视化）
vol -f mem.raw windows.pstree

# ⛔ 关键技巧：pslist vs psscan 对比
# pslist 有但 psscan 无 → EPROCESS 结构已损坏
# psscan 有但 pslist 无 → 被 DKOM 隐藏或已退出的进程
```

### 2.2 进程详情

```bash
# 命令行参数 — 发现异常启动参数
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.cmdline --pid 1234

# 环境变量
vol -f mem.raw windows.envars
vol -f mem.raw windows.envars --pid 1234

# DLL 列表 — 检查异常加载的 DLL
vol -f mem.raw windows.dlllist
vol -f mem.raw windows.dlllist --pid 1234

# 句柄 — 进程持有的内核对象（文件/注册表/互斥体）
vol -f mem.raw windows.handles
vol -f mem.raw windows.handles --pid 1234

# SID — 进程运行的安全上下文
vol -f mem.raw windows.getsids
vol -f mem.raw windows.getsids --pid 1234

# 权限 — 进程持有的特权令牌
vol -f mem.raw windows.privileges
vol -f mem.raw windows.privileges --pid 1234
```

### 2.3 Linux 进程

```bash
vol -f mem.raw linux.pslist
vol -f mem.raw linux.pstree
vol -f mem.raw linux.psaux         # 含命令行参数（类似 ps aux）
vol -f mem.raw linux.elfs          # 列出 ELF 映射
vol -f mem.raw linux.proc.Maps --pid 1234  # 进程内存映射
```

---

## 三、内存注入与恶意代码检测

```bash
# malfind — 扫描 PAGE_EXECUTE_READWRITE 的 VAD 节点
# 最重要的恶意代码发现插件
vol -f mem.raw windows.malfind
vol -f mem.raw windows.malfind --pid 1234
vol -f mem.raw windows.malfind --dump  # 导出可疑内存区域

# ⛔ malfind 输出解读：
# Protection: PAGE_EXECUTE_READWRITE → 高度可疑（正常代码不应 RWX）
# 开头有 MZ / 4D 5A → 反射加载的 PE
# 开头有 FC E8 → 常见 shellcode 特征（CLD + CALL）
# 无 PE 头但有可执行代码 → 注入的 shellcode

# hollowprocesses — 检测进程镂空（Process Hollowing）
vol -f mem.raw windows.hollowprocesses

# VAD 信息 — 虚拟地址描述符（进程内存布局）
vol -f mem.raw windows.vadinfo --pid 1234
vol -f mem.raw windows.vadwalk --pid 1234

# YARA 扫描 — 自定义规则匹配内存
vol -f mem.raw yarascan.YaraScan --yara-file rules.yar
vol -f mem.raw yarascan.YaraScan --yara-rules "rule test { strings: $a = \"password\" condition: $a }"
vol -f mem.raw windows.vadyarascan --yara-file rules.yar --pid 1234

# 线程检测
vol -f mem.raw windows.threads --pid 1234
# 关注 StartAddress 不在已知模块范围内的线程 → 注入代码
```

---

## 四、网络分析

```bash
# netscan — 扫描网络连接和监听端口（TCP/UDP）
vol -f mem.raw windows.netscan

# netstat — 通过内核结构枚举活动连接
vol -f mem.raw windows.netstat

# ⛔ netscan 输出解读：
# 关注 ESTABLISHED 状态的外部 IP → 可能是 C2
# 关注 LISTENING 的高位端口 → 可能是后门
# 关注 svchost.exe 的异常出站连接
# 对比 PID 与 pslist 中的进程名

# Linux 网络
vol -f mem.raw linux.sockstat       # socket 统计
```

---

## 五、注册表分析

```bash
# 列出注册表 hive
vol -f mem.raw windows.registry.hivelist

# 打印指定键值
vol -f mem.raw windows.registry.printkey
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.registry.printkey --key "ControlSet001\Services"

# 导出 hive 文件
vol -f mem.raw windows.registry.hivescan
vol -f mem.raw windows.registry.hivelist --dump

# ⛔ 注册表关键取证位置：
# Run/RunOnce → 自启动项（持久化）
# Services → 恶意服务（持久化）
# UserAssist → 程序执行记录（ROT13 编码）
# ShimCache / AppCompatCache → 程序执行痕迹
# MRU → 最近使用的文件/命令
# TypedURLs → IE/Edge 输入的 URL

# 密码/凭据提取
vol -f mem.raw windows.hashdump     # SAM 中的 NTLM 哈希
vol -f mem.raw windows.lsadump      # LSA secrets
vol -f mem.raw windows.cachedump    # 缓存的域凭据
```

---

## 六、文件系统

```bash
# filescan — 扫描内存中的 FILE_OBJECT
vol -f mem.raw windows.filescan
# 配合 grep 筛选
vol -f mem.raw windows.filescan | grep -i "\.exe$"
vol -f mem.raw windows.filescan | grep -i "\.ps1$"
vol -f mem.raw windows.filescan | grep -i "desktop"
vol -f mem.raw windows.filescan | grep -i "downloads"

# dumpfiles — 从内存提取文件（需要 filescan 的地址）
vol -f mem.raw windows.dumpfiles --virtaddr 0xXXXX
vol -f mem.raw windows.dumpfiles --physaddr 0xXXXX
vol -f mem.raw windows.dumpfiles --pid 1234

# MFT 扫描
vol -f mem.raw windows.mftscan.MFTScan

# Linux 文件
vol -f mem.raw linux.bash           # bash 历史记录
vol -f mem.raw linux.check_afinfo   # 网络协议处理函数 hook 检测
```

---

## 七、内核与 Rootkit 检测

```bash
# SSDT — 系统服务描述表 hook 检测
vol -f mem.raw windows.ssdt

# 驱动模块
vol -f mem.raw windows.modules       # 已加载内核模块
vol -f mem.raw windows.modscan       # 池标签扫描（含隐藏模块）
vol -f mem.raw windows.driverscan    # 驱动对象扫描
vol -f mem.raw windows.driverirp     # IRP hook 检测

# 回调函数 — Rootkit 常注册的内核回调
vol -f mem.raw windows.callbacks

# ⛔ modules vs modscan 对比 → 发现隐藏内核模块
# 类似 pslist vs psscan 的思路

# Linux Rootkit 检测
vol -f mem.raw linux.check_syscall   # syscall table 修改检测
vol -f mem.raw linux.check_modules   # 隐藏内核模块
vol -f mem.raw linux.hidden_modules  # 通过多种方式枚举隐藏模块
vol -f mem.raw linux.check_idt       # 中断描述表 hook
vol -f mem.raw linux.tty_check       # TTY hook 检测
vol -f mem.raw linux.lsmod           # 已加载模块列表
```

---

## 八、服务与自启动

```bash
# 服务列表
vol -f mem.raw windows.svcscan

# ⛔ 服务关注点：
# 异常 BinaryPathName → 指向非系统目录
# ServiceType = Own Process + 非 svchost → 可疑
# Start = Auto + 描述为空 → 可疑持久化
```

---

## 九、杂项与辅助

```bash
# 剪贴板内容
vol -f mem.raw windows.clipboard

# 桌面截图/窗口信息
vol -f mem.raw windows.sessions
vol -f mem.raw windows.deskscan

# 计时器 / DPC
vol -f mem.raw windows.bigpools
vol -f mem.raw windows.poolscanner

# 符号表信息
vol -f mem.raw windows.verinfo       # PE 版本信息
vol -f mem.raw windows.symlinkscan   # 符号链接

# 字符串提取（配合外部工具）
strings -a -e l mem.raw > strings_unicode.txt
strings -a mem.raw > strings_ascii.txt
# 然后用 vol 的 strings 插件映射到进程
```

---

## 十、常见调查工作流

### 工作流 A: 检测进程注入

```bash
# Step 1: 列出进程，发现异常
vol -f mem.raw windows.pslist
vol -f mem.raw windows.pstree       # 检查父子关系是否合理

# Step 2: 扫描 RWX 内存
vol -f mem.raw windows.malfind      # 寻找注入代码

# Step 3: 确认可疑进程的 DLL 和线程
vol -f mem.raw windows.dlllist --pid <SUSPECT_PID>
vol -f mem.raw windows.threads --pid <SUSPECT_PID>

# Step 4: 导出可疑内存区域分析
vol -f mem.raw windows.malfind --pid <SUSPECT_PID> --dump
# 送 VirusTotal / YARA 扫描

# Step 5: 检查进程镂空
vol -f mem.raw windows.hollowprocesses
```

### 工作流 B: 发现 C2 通信

```bash
# Step 1: 列出所有网络连接
vol -f mem.raw windows.netscan

# Step 2: 关注 ESTABLISHED 到外部 IP 的连接，记录 PID
# 将外部 IP 送威胁情报平台查询

# Step 3: 分析连接对应的进程
vol -f mem.raw windows.pslist --pid <C2_PID>
vol -f mem.raw windows.cmdline --pid <C2_PID>
vol -f mem.raw windows.dlllist --pid <C2_PID>

# Step 4: YARA 扫描已知 C2 框架特征
vol -f mem.raw yarascan.YaraScan --yara-rules "rule CobaltStrike { strings: \$a = { 2E 2F 2E 2F 2E 2C } condition: \$a }"

# Step 5: 提取可疑进程的可执行文件
vol -f mem.raw windows.pslist --pid <C2_PID> --dump
vol -f mem.raw windows.dumpfiles --pid <C2_PID>
```

### 工作流 C: 提取凭据

```bash
# Step 1: 导出密码哈希
vol -f mem.raw windows.hashdump

# Step 2: 导出 LSA secrets
vol -f mem.raw windows.lsadump

# Step 3: 导出缓存的域凭据
vol -f mem.raw windows.cachedump

# Step 4: 搜索内存中的明文密码字符串
vol -f mem.raw yarascan.YaraScan --yara-rules "rule creds { strings: \$a = \"password\" nocase \$b = \"Password=\" condition: any of them }"

# Step 5: 查找 LSASS 进程并导出
vol -f mem.raw windows.pslist | grep lsass
vol -f mem.raw windows.dumpfiles --pid <LSASS_PID>
# 离线用 Mimikatz: sekurlsa::minidump lsass.dmp
```

### 工作流 D: Rootkit 分析

```bash
# Step 1: 对比进程列表
vol -f mem.raw windows.pslist > pslist.txt
vol -f mem.raw windows.psscan > psscan.txt
# diff 两个列表，psscan 多出的 = 被隐藏的进程

# Step 2: 对比内核模块
vol -f mem.raw windows.modules > modules.txt
vol -f mem.raw windows.modscan > modscan.txt

# Step 3: 检查内核 hook
vol -f mem.raw windows.ssdt          # 系统调用表
vol -f mem.raw windows.callbacks     # 内核回调
vol -f mem.raw windows.driverirp     # IRP hook

# Step 4: 检查可疑驱动
vol -f mem.raw windows.driverscan
# 关注 DriverName 不在常见列表中的驱动
# 关注 DriverStart 地址不在 ntoskrnl 范围内的驱动
```

### 工作流 E: 持久化发现

```bash
# Step 1: 注册表自启动
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Step 2: 服务
vol -f mem.raw windows.svcscan | grep -i "auto"

# Step 3: 计划任务（从内存文件中查找）
vol -f mem.raw windows.filescan | grep -i "tasks"

# Step 4: WMI 事件订阅（搜索相关对象）
vol -f mem.raw windows.filescan | grep -i "wmi"
vol -f mem.raw windows.registry.printkey --key "SOFTWARE\Microsoft\Wbem"
```

---

## 十一、输出处理技巧

```bash
# 输出为 JSON 格式（便于后续处理）
vol -f mem.raw -r json windows.pslist > pslist.json

# 输出为 CSV
vol -f mem.raw -r csv windows.netscan > netscan.csv

# 管道过滤
vol -f mem.raw windows.netscan | grep ESTABLISHED
vol -f mem.raw windows.filescan | grep -iE "\.(exe|dll|ps1|bat|vbs)$"
vol -f mem.raw windows.pslist | awk '{print $1, $2, $3}'

# 指定输出目录
vol -f mem.raw -o /output/ windows.malfind --dump
vol -f mem.raw -o /output/ windows.dumpfiles --pid 1234
```

---

## 十二、常见问题与排错

| 问题 | 解决 |
|------|------|
| 无法识别内存格式 | 确认是 raw/lime 格式，尝试 `banners.Banners` |
| 插件报 Unsatisfied | 缺少符号表，下载对应 OS 的 ISF（`volatility3/symbols/`） |
| Linux 分析失败 | 需要对应内核版本的符号表（`dwarf2json` 生成） |
| 输出为空 | 确认 dump 完整性，尝试其他同类插件（如 pslist 无输出用 psscan） |
| 速度极慢 | 用 SSD 存放 dump 文件，增加 `--max-size` 参数 |

### 符号表配置

```bash
# Windows 符号表 — Vol3 自动从 Microsoft Symbol Server 下载
# 离线环境手动放置:
ls ~/.local/lib/python3.*/site-packages/volatility3/symbols/windows/

# Linux 符号表生成
# 需要目标系统内核的 vmlinux (带 debug info)
dwarf2json linux --elf vmlinux > linux_symbol.json
# 放入 volatility3/symbols/linux/

# macOS 符号表
dwarf2json mac --macho kernel.dSYM > mac_symbol.json
```

---

## 十三、快速参考表

### Windows 插件按用途分类

| 用途 | 插件 | 说明 |
|------|------|------|
| 系统信息 | `windows.info` | OS 版本/架构 |
| 进程列表 | `windows.pslist` | 链表遍历 |
| 隐藏进程 | `windows.psscan` | 池标签扫描 |
| 进程树 | `windows.pstree` | 父子关系 |
| 命令行 | `windows.cmdline` | 启动参数 |
| DLL | `windows.dlllist` | 加载的 DLL |
| 句柄 | `windows.handles` | 内核对象 |
| 注入检测 | `windows.malfind` | RWX 内存 |
| 进程镂空 | `windows.hollowprocesses` | Hollowing |
| 网络 | `windows.netscan` | 连接/端口 |
| 网络 | `windows.netstat` | 活动连接 |
| 注册表 | `windows.registry.printkey` | 键值读取 |
| 注册表 | `windows.registry.hivelist` | Hive 列表 |
| 服务 | `windows.svcscan` | 服务列表 |
| 文件 | `windows.filescan` | 文件对象 |
| 文件提取 | `windows.dumpfiles` | 提取文件 |
| 密码 | `windows.hashdump` | SAM 哈希 |
| 密码 | `windows.lsadump` | LSA 密钥 |
| 密码 | `windows.cachedump` | 域缓存 |
| 内核模块 | `windows.modules` | 驱动列表 |
| 隐藏模块 | `windows.modscan` | 池标签扫描 |
| 内核 hook | `windows.ssdt` | 系统调用表 |
| 回调 | `windows.callbacks` | 内核回调 |
| 驱动 | `windows.driverscan` | 驱动对象 |
| IRP hook | `windows.driverirp` | IRP 派遣 |
| YARA | `yarascan.YaraScan` | 规则匹配 |
| MFT | `windows.mftscan.MFTScan` | MFT 记录 |

### Linux 插件按用途分类

| 用途 | 插件 | 说明 |
|------|------|------|
| 系统信息 | `linux.info` | 内核版本 |
| 进程列表 | `linux.pslist` | task_struct 遍历 |
| 进程树 | `linux.pstree` | 父子关系 |
| 进程详情 | `linux.psaux` | 含参数 |
| Bash 历史 | `linux.bash` | 命令记录 |
| ELF 映射 | `linux.elfs` | 已加载 ELF |
| 进程映射 | `linux.proc.Maps` | 内存布局 |
| 内核模块 | `linux.lsmod` | 已加载模块 |
| 隐藏模块 | `linux.hidden_modules` | 隐藏检测 |
| Syscall hook | `linux.check_syscall` | 系统调用表 |
| IDT hook | `linux.check_idt` | 中断表 |
| 模块完整性 | `linux.check_modules` | 模块验证 |
| TTY hook | `linux.tty_check` | 终端 hook |
| Socket | `linux.sockstat` | 网络连接 |
| 网络 hook | `linux.check_afinfo` | 协议 hook |
