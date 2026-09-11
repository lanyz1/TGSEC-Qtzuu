---
name: pentest-ad
description: "AD/内网渗透：信息收集→OPSEC横向→提权维持——假设驱动三阶段速查表"
allowed-tools: Read,Grep,Glob,Bash,WebFetch
---

# AD / Internal Network

> 仅在根路由选择本目录后读取，且仅限明确授权的内网/AD 任务——不做宽泛自动触发。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 已获授权立足点，或范围含 AD/Windows/Linux 内网/消息队列/CI/CD。

## 领域决策直觉

1. 内网第一原则：零命令行。所有信息收集用 BOF/原生 API/LDAP 直连，不产生 cmd.exe 或 powershell.exe 进程
2. 收集 > 移动 > 提权 —— 先看清全局（BloodHound），不要拿到 shell 就立刻提权
3. OPSEC 不是"小声点"，是"看起来正常"——内存操作、原生 API 调用、LDAP 流量才是正常运维行为
4. 参考：https://lolol.farm/ — LOLBins/LOLDrivers/LOLRMM/LOT Tunnels/LOLEXFIL 综合索引。BOF 集合：TrustedSec CS-Situational-Awareness-BOF、ajpc500/BOFs、outflanknl/C2-Tool-Collection

---

## Phase 1：内网信息收集

> 目标：在不被发现的前提下，收集足够信息建立内网拓扑、身份关系和攻击路径。

### BloodHound CE 全量采集
- **信号**: Windows 域内主机
- **假设**: 域中存在可滥用的 ACL、证书模板、委派关系或跨域信任
- **验证**: SharpHound v4.3+ 采集（新边：`DCSync`/`SyncLAPSPassword`/`DumpSMSAPassword`/`AddKeyCredentialLink`/`WriteSPN`）→ AzureHound 采集 Entra ID → BloodHound 分析最短路径到 DA/域控/CA
- **OPSEC**: SharpHound 本身会产生大量 LDAP 查询。优先用 BOF 版本的 LDAP 查询替代完整 SharpHound 采集（如 TrustedSec 的 SA-LDAPCheck BOF 系列），或限制采集范围到特定 OU
- **证实**: 发现到高价值目标的可滥用路径
- **升级**: 选中路径 → Active 假设队列

### 本地信息枚举（BOF/原生 API，零命令行）

> 核心 OPSEC 原则：不产生 cmd.exe / powershell.exe 进程。所有信息收集通过 BOF 或直接调用 Windows API 完成。

- **信号**: 获得 Windows shell（C2 agent / BOF loader）
- **假设**: 本地配置包含凭据、连接串、信任关系和网络拓扑线索
- **验证**: 全部操作通过 BOF 或直接 syscall，不触发 create process 事件：
  - **当前用户/权限**: `GetUserNameExW` + `OpenProcessToken` + `GetTokenInformation(TokenGroups/TokenPrivileges)` — 不用 `whoami`
  - **网络连接**: `GetExtendedTcpTable` / `GetExtendedUdpTable` (IPHLPAPI.dll) — 不用 `netstat`
  - **网卡/DNS/网段**: `GetAdaptersAddresses` → 提取 IP、前缀长度、DNS 服务器、DHCP 服务器 — 不用 `ipconfig`
  - **入站会话**: `NetSessionEnum` (netapi32.dll) — 不用 `net session`
  - **保存的凭据**: DPAPI 直接解密 Credential Manager blob (CryptUnprotectData) — 不用 `cmdkey`
  - **路由表**: `GetIpForwardTable2` — 不用 `route print`
  - **ARP 表**: `GetIpNetTable2` — 不用 `arp -a`
  - **注册表读取**: `RegOpenKeyEx` + `RegQueryValueEx` (advapi32.dll) — 不用 `reg query`
  - **已安装软件**: 枚举 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` 子键，用原生 registry API — 不用 `wmic product`
  - **C2 BOF 参考**: TrustedSec CS-Situational-Awareness-BOF 集合、ajpc500 BOFs 集合 — 覆盖大部分信息收集需求
- **证实**: 获取完整的本地信息（用户/网络/凭据/软件），EDR 侧零进程创建事件
- **升级**: 凭据 → 横向移动；新网段 → 新 RECON

### AD 环境深度探测（LDAP 原生查询/BOF）

> 核心 OPSEC 原则：使用 LDAP 协议直接查询 AD，不走 net.exe / PowerShell AD cmdlet。

- **信号**: 域环境，需收集 AD 对象信息
- **假设**: LDAP 查询和 ADSI 接口可替代所有命令行 AD 工具，且 LDAP 流量本身就是域内正常行为
- **验证**: 所有操作使用 C2 BOF 或 .NET 通过 `System.DirectoryServices` / `DirectoryEntry` 反射加载：
  - **域控制器列表**: `DsGetDcName` (netapi32) — 不用 `nltest`
  - **域管组成员**: LDAP 查询 `(&(objectClass=user)(memberOf=CN=Domain Admins,...))` — 不用 `net group`
  - **所有用户/计算机**: LDAP 分页查询遍历 `(objectClass=user)` / `(objectClass=computer)` — 不用 `Get-ADUser`
  - **SPN 账户**: LDAP 查询 `(servicePrincipalName=*)` — 找 Kerberoast 目标
  - **高价值组**: 递归 LDAP 查询 Domain Admins / Enterprise Admins / Schema Admins / Account Operators / Backup Operators / DnsAdmins
  - **非默认 OU**: LDAP 查询 `(objectClass=organizationalUnit)` 发现非默认 OU 结构
  - **GPO**: LDAP 查询 `(objectClass=groupPolicyContainer)` — 发现可能弱配置的 GPO
  - **跨域信任**: `DsEnumerateDomainTrusts` (netapi32) — 不用 `nltest /domain_trusts`
  - **BOF 参考**: TrustedSec SA-LDAPCheck / SA-DCLocator BOF，Outflank NLTest BOF — 覆盖大部分 AD 探测
- **证实**: 获得域内对象全貌（DA/DC/SPN/OU/GPO/信任），EDR 零 process create 事件
- **升级**: 目标定向 → 进入横向阶段

### 网络拓扑推断（原生 API，无进程创建）
- **信号**: 只知道自己这一台机器，需要推断内网结构
- **假设**: ARP/路由/DNS/DHCP 信息均可通过原生 API 获取，无需启动独立进程
- **验证**: 全部通过 BOF 或直接 API 调用：
  - 同级网段活跃主机：`GetIpNetTable2`（ARP 表，IPHLPAPI）— 不用 `arp -a`
  - 路由表推断网段：`GetIpForwardTable2`（IPHLPAPI）— 不用 `route print`
  - DNS 服务器定位：`GetNetworkParams` 返回 DNS 服务器列表 — 不用 `nslookup`
  - DNS 正向/反向查询：`DnsQuery_W` / `DnsQueryEx`（dnsapi.dll）— 解析内部主机名推导拓扑
  - DHCP 租约：`DhcpEnumSubnetClients`（dhcpsapi.dll，需 DHCP 服务器权限）— 不用 `Get-DhcpServerv4Lease`
  - 域内共享：`NetShareEnum`（netapi32.dll）— 不用 `net view`
  - 碎片拼接：从 ARP（同级）、路由（跨网段）、DNS（命名规律）、共享（文件服务器）反推网络拓扑图
- **证实**: 推算出内网网段划分 + 域控/DNS/文件服务器 IP，零命令行
- **升级**: 绘制拓扑 → 确定横向下一跳

### 消息队列 / CI/CD / K8s 非传统通道发现
- **信号**: 传统 SMB/WinRM 被严密监控，需要非标准横向通道
- **假设**: 内网存在可作为代码执行跳板的消息队列/CI/CD/K8s/数据库
- **验证**: 端口检测通过 `ConnectEx` / raw socket SYN 探测（BOF），不启动外部端口扫描器 → MSSQL 通过 SQL BOF 直接执行 `SELECT * FROM sys.servers` → K8s 通过 KubeHound BOF 或 `ReadFile` BOF 读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`
- **证实**: 发现未监控的管理接口或可滥用的服务账户
- **升级**: 选定最隐蔽通道 → OPSEC 横向阶段

---

## Phase 2：OPSEC 横向移动

> 目标：在看起来像正常运维流量的前提下，到达下一台目标主机。优先使用目标自带工具（LOL）。

### 凭据提取（不留磁盘文件）
- **信号**: 有本地管理员或 SYSTEM 权限
- **假设**: 内存中存有可用的明文密码/hash/ticket
- **验证**: 全部通过内存操作 —— `CreateToolhelp32Snapshot` + `Process32First/Next` 枚举进程找 LSASS PID → nanodump 多种绕过模式（handle duplication / seclogon leak / process fork / PPL bypass / SSP loading）→ `--spoof-callstack` 欺骗 EDR 栈回溯 → Seatbelt `SecPackageCreds` BOF 不碰 LSASS 直接提取安全包凭据。备选离线提取——用原生 registry API (`RegSaveKeyEx`) dump SAM/SECURITY → secretsdump 离线
- **证实**: 获取可用 NTLM hash 或 Kerberos ticket，无文件落地
- **升级**: PTH/PTT → 横向移动

### PTH / PTT 横向（LOL 方式）
- **信号**: 有目标的 NTLM hash 或 Kerberos ticket
- **假设**: 可用目标凭据通过合法 Windows 协议横向
- **验证**: WMI 通过 COM 接口直接调用（`IWbemServices::ExecMethod`），不启动 wmic.exe → WinRM 通过 WinRS BOF 或直接 SOAP 调用，不启动 winrs.exe → 计划任务通过 `ITaskScheduler` COM 接口，不启动 schtasks.exe → 服务通过 `OpenSCManager` + `CreateService` 原生 API，不启动 sc.exe → RDP Restricted Admin BOF。PTT——Rubeus BOF 版 `asktgt` + Kerberos ticket 注入 → Kerberos 认证后的所有操作使用原生 API
- **证实**: 在目标主机上执行命令，返回结果
- **升级**: 新主机上线 → Phase 1 重启（在新主机上收集信息）

### MSSQL Linked Server 链式横向（LOL 方式）
- **信号**: MSSQL 实例存在 Linked Server（sysservers 非空）
- **假设**: 可通过 OPENQUERY 级联，用数据库原生功能逐跳横向
- **验证**: `SELECT * FROM sys.servers` 发现链接 → `EXECUTE ('SELECT * FROM sys.servers') AT [LinkedServer1]` 级联发现 → `EXECUTE ('EXEC xp_cmdshell ''whoami''') AT [LinkedServerN]` 多跳执行 → 每跳使用 MSSQL 服务账户，不引入外部工具
- **证实**: 链式 N 跳后成功执行命令
- **升级**: 逐跳渗透 → 跨域/跨森林 → 新 RECON

### RMM 工具滥用横向
- **信号**: 目标安装远程监控管理工具（TeamViewer/AnyDesk/ScreenConnect/MeshCentral 等）
- **假设**: RMM 工具本身是合法远程管理通道，其流量和进程不受 EDR 审查
- **验证**: 参考 LOLRMM 项目 (https://lolol.farm/) → 枚举已安装 RMM → 提取 RMM 配置中的预共享密钥/agent 密钥 → 用 RMM 自带功能在目标间移动（它本来就是干这个的）
- **证实**: 通过 RMM 通道在目标间移动，EDR 零告警
- **升级**: 多主机控制 → 持续横向

### VxLAN/GRE 无状态隧道伪造
- **信号**: 内网使用 VxLAN/GRE 隧道，RouterOS 默认启用 VxLAN
- **假设**: 无状态隧道不需要握手，可伪造源地址注入内网流量
- **验证**: 确认 VxLAN/GRE 存在 → 伪造源地址 → 在 RouterOS 默认启用 VxLAN 时劫持整个隧道 → 注入恶意内网流量到达原本不可达网段
- **证实**: 流量成功到达目标网段
- **升级**: 内网流量劫持 → 中间人 → 凭据窃取

### Dev Tunnels / LOT Tunnels 隐蔽通道
- **信号**: 需要出网 C2，但出站规则严格
- **假设**: 可通过合法隧道服务建立 C2，流量看起来像 Microsoft/Cloudflare/Ngrok
- **验证**: 参考 LOT Tunnels + LOLC2 项目 (https://lolol.farm/) → Dev Tunnels：`code --tunnel` 微软签名二进制 → WebSocket over SSH → 流量经 *.devtunnels.ms → Cloudflare Tunnel / Ngrok / Tailscale Funnel 作为备选
- **证实**: C2 通信正常，IDS 标记为合法云服务流量
- **升级**: 长期 C2 通道 → 多主机控制

### Kerberos 强制认证反射横向
- **信号**: 域内可注册 DNS 记录（默认允许），或可触发 DCOM OXID 解析
- **假设**: 可强制目标机器向我们认证，再反射 Kerberos ticket 到目标自身服务
- **验证**: Ghost SPNs——找到计算机对象上的幽灵 SPN（不可解析）→ 注册对应 DNS 指向攻击者 → PrinterBug/PetitPotam 强制认证 → 捕获 Kerberos AP-REQ → 反射到目标自身 SMB（CVE-2025-58726，Server 2025 已修复）。DCOM OXID 解析——构造含 CMTI blob 的特殊主机名 → 注册 DNS → 触发 OXID 解析 → 中继 Kerberos 到 ADCS Web Enrollment
- **证实**: 以目标机器账户身份访问其 SMB 或获取 ADCS 证书
- **升级**: 机器账户 → SYSTEM → DC 上的机器账户 → DCSync

### Windows Admin Center 反射 RPE（CVE-2026-26119）
- **信号**: 目标运行 Windows Admin Center（端口 443/6516）
- **假设**: WAC 用 Kestrel（非 IIS），EPA 未实现 → 可反射机器认证到 WAC REST API → PowerShell 执行
- **验证**: 低权限域用户 → 强制目标机器认证到 WAC → 反射认证到 WAC REST API → PowerShell 执行端点 → 如在 AD CS 服务器上 → Golden Certificate → 域控完全控制
- **证实**: WAC 上执行任意 PowerShell 命令
- **升级**: PowerShell → 凭据提取 → 域控

---

## Phase 3：权限提升与维持

> 目标：从当前权限级别提升到 SYSTEM/DA，并建立隐蔽持久的控制。

### ADCS ESC14-17（超越 ESC13 的证书攻击）
- **信号**: ADCS 存在且常规 ESC1-13 不可用
- **假设**: 2025 年新发现的 ESC14-17 变种可绕过之前的修复
- **验证**: Certify `find /vulnerable` → ESC14——弱显式映射（altSecurityIdentities 可写，四种子变体：直接覆盖/邮件属性操控/DNSHostName操控/X509SubjectOnly）→ ESC15（CVE-2024-49019）——v1 模板 Application Policy 覆盖 EKU → ESC16——CA 全局省略安全扩展 + StrongCertificateBindingEnforcement 设为 0/1 → Certighost（2026 新 ADCS 漏洞 PoC 已发布）
- **证实**: 通过 ESC14-17 获取目标账户证书，PKINIT 认证成功
- **升级**: 域管 TGT → DCSync → 域完全控制

### BadSuccessor dMSA → 域管
- **信号**: Windows Server 2025 域环境，dMSA 已配置或权限可写
- **假设**: dMSA 的委派权限可被滥用来强制 DC 签发票据
- **验证**: 审计 dMSA 权限分配 → 找到可利用的委派链 → 强制 DC 为 DA/域控账户签发 Kerberos ticket → 甚至可提取所有用户 NTLM hash 而不碰 DC
- **证实**: 获取 DA 的 Kerberos TGT 或任意用户 NTLM hash
- **升级**: 域完全控制

### DCSync + Golden Ticket + 跨森林
- **信号**: 已获域管理员权限或 Replication-Get-Changes-All 权限
- **假设**: 可提取 krbtgt hash，伪造任意票据，扩展到跨森林
- **验证**: Get-DomainController → Execute-DCSync 提取 krbtgt hash → Golden Ticket 伪造 → 如有跨森林信任，注入 Enterprise Admins SID → 跨森林访问
- **证实**: 以 Enterprise Admin 身份访问跨森林资源
- **升级**: 多域/多森林控制

### AD 持久化 9 种手法
- **信号**: 已获域管权限，需保持长期访问
- **假设**: 多种机制可独立恢复域管——蓝队清除一种，其他的存活
- **验证**: (1) DSRM 密码同步 (2) DCShadow 模拟 DC 复制注入 (3) SSP 自定义 DLL 拦截认证凭据 (4) SID History 注入 Enterprise Admins SID (5) AdminSDHolder 恶意 ACL——SDProp 每 60 分钟同步到所有特权组 (6) 黄金证书——导出 CA 私钥+导入 CA 证书 (7) 委派后门——非约束委派 + 打印机 Bug (8) Custom SSP (9) BadSuccessor dMSA 回退路径
- **证实**: 蓝队清理恶意账户后，仍能恢复域管
- **升级**: 长期隐蔽访问 → 持续数据收集

### WMI 事件订阅无文件持久化
- **信号**: Windows 环境需隐蔽持久化
- **假设**: WMI 事件订阅可在无文件落地情况下触发 Payload
- **验证**: __EventFilter + __FilterToConsumerBinding + __CommandLineEventConsumer → 订阅系统事件（进程启动/服务创建/用户登录）→ 触发 PowerShell payload → GadgetToJScript → WMI 事件链跨机传播
- **证实**: 重启/登录后 Payload 自动执行
- **升级**: 多层组合——WMI + 注册表 Run + 计划任务 + COM 劫持 + DLL 劫持

### ADFS 设备注册持久化 + Golden JWT
- **信号**: ADFS 2016+ 且 DRS 未禁用
- **假设**: ADFS DRS 可通过 OAuth2 Device Code Phishing 注册攻击者设备获取 PRT
- **验证**: OAuth2 Device Code Phishing → 注册攻击者设备的 msDS-Device → 生成 PRT → 长期持久化 → ADFS 签名密钥同时签发 SAML 和 JWT → Golden JWT 扩展 Golden SAML
- **证实**: 蓝队轮换 AD 密码后仍能通过 PRT 认证
- **升级**: 跨 OAuth2 应用冒充 → 云资源访问

### AAD Connect 密码提取 → 云持久化
- **信号**: 目标使用 Azure AD Connect 同步本地 AD 到 Azure
- **假设**: AAD Connect 服务器存储同步凭据，可提取后用于云访问
- **验证**: 从 AAD Connect 服务器提取同步凭据 → Kerberos 票据转向云 → Azure 资源访问 → Entra ID 后门（见下方）
- **证实**: 成功用同步凭据访问 Azure 订阅
- **升级**: Azure 订阅控制 → 云侧持久化

### Entra ID 混合持久化
- **信号**: 目标使用 Entra ID（Azure AD）+ 本地 AD 混合
- **假设**: 云侧后门可绕过本地 AD 的安全加固
- **验证**: 参考 EntraGoat 六大场景 (https://github.com/Semperis/EntraGoat) → Service Principal 所有权滥用/App-Only Graph 权限提权/Group Membership 滥用/PIM 激活逃逸/Administrative Units 边界突破/CBA 证书认证滥用 → Conditional Access 绕过（资源排除缺口 + sccauth 替代 Token Broker + Azure AD Graph API 隐蔽侦察）
- **证实**: 从 Entra ID 侧获取 Global Admin 或同步回本地 AD
- **升级**: 混合持久化 → 两侧都有后门 → 单侧清除无效

### LSA 保护绕过 + 凭据 dump（nanodump 方法论）
- **信号**: 需要从 LSASS 提取凭据但 PPL/EDR 保护中
- **假设**: 多层绕过方法，选择目标环境对应的那层即可
- **验证**: handle duplication（复用已有 LSASS 句柄）→ handle elevation（PROCESS_QUERY_LIMITED_INFORMATION → 完全访问）→ seclogon leak（三种变体）→ process fork（dump 克隆进程）→ PssNtCaptureSnapshot（避免直接读 LSASS）→ Silent Process Exit/WerFault → PPL bypass（按 Windows build 选择 exploit）→ SSP loading（通过命名管道直接注入 LSASS）→ 全程 `--spoof-callstack` 伪装
- **证实**: 成功 dump LSASS 且 EDR 无告警
- **升级**: 凭据提取 → 横向 → 域控

### 参考项目速查

| 需求 | 参考项目 | 网址 |
|------|---------|------|
| WIndows 原生工具 | LOLBAS | https://lolbas-project.github.io/ |
| AD 原生命令 | LOLAD | https://lolol.farm/ → LOLAD |
| 漏洞驱动 | LOLDrivers | https://www.loldrivers.io/ |
| RMM 工具 | LOLRMM | https://lolol.farm/ → LOLRMM |
| 隧道/C2 | LOT Tunnels + LOLC2 | https://lolol.farm/ → LOT Tunnels |
| 数据外带方法 | LOLEXFIL | https://lolol.farm/ → LOLEXFIL |
| Windows/AD 命令速查 | WADComs | https://wadcoms.github.io/ |
| 持久化机制 | Persistence Info | https://lolol.farm/ → Persistence Info |
| ESXi 原生工具 | LOLESXi | https://lolol.farm/ → LOLESXi |
| Entra ID 攻击实验 | EntraGoat | https://github.com/Semperis/EntraGoat |
