---
name: mythic-c2
description: "Mythic C2 操作方法论。当需要部署 Mythic、选择 Mythic Agent、安装 C2 Profile、配置 HTTP/DNS/WebSocket/SMB/TCP 通信、生成 payload、管理回连任务，或把 Mythic 作为跨平台 C2 框架用于授权红队演练时使用。覆盖 mythic-cli 安装、Agent/Profile 选择、SSL 证书配置、payload 构建和基础 OPSEC 判断"
metadata:
  tags: "mythic,c2,command and control,agent,profile,http,dns,websocket,smb,tcp,red team,红队,c2框架"
  category: "tool"
---

# Mythic C2 操作方法论

Mythic 是模块化 C2 框架，核心由 Mythic 服务端、Agent 和 C2 Profile 组成。使用时先确定目标平台和通信路径，再安装对应 Agent/Profile；不要先安装一堆组件再临场选择。

---

## Phase 1: 部署与启动

Mythic 通常部署在 Linux 服务器上，并依赖 Docker 运行各组件。基础安装流程如下：

```bash
sudo apt-get install build-essential
git clone https://github.com/its-a-feature/Mythic --depth 1
cd Mythic
sudo make
sudo ./mythic-cli start
```

如果在 Ubuntu/Debian 上首次安装 Docker 依赖，可使用项目提供的安装脚本；脚本会改动系统 Docker 环境，执行前应确认这是专用 C2 服务器。

```bash
./install_docker_ubuntu.sh
./install_docker_debian.sh
```

启动后先确认 Web UI、容器状态和日志，再进入 Agent/Profile 安装阶段。

---

## Phase 2: Agent 选择

Agent 决策取决于目标 OS、运行时限制和需要的后渗透能力。

| Agent | 语言/平台侧重 | 适用判断 |
|---|---|---|
| Apollo | C# / .NET Framework | Windows 域环境、.NET 可用、需要成熟 Windows 后渗透能力 |
| Athena | .NET | Windows/.NET 场景，优先确认当前维护状态和支持命令 |
| Poseidon | Go / Linux / macOS | Linux/macOS 目标，或需要较好的跨平台能力 |
| Medusa | Python | Python 环境可用、需要脚本化扩展时 |
| Hannibal | PIC C | 对原生载荷和内存加载有要求时 |
| Thanatos | Rust / Linux / Windows | 需要 Rust Agent 或跨平台实验能力时 |
| Xenon | C / httpx | 需要 C Agent 并配合 httpx profile 时 |

安装 Agent：

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo
./mythic-cli install github https://github.com/MythicAgents/poseidon
./mythic-cli install github https://github.com/MythicAgents/Athena
```

选择前优先查看 Mythic Community Agent Feature Matrix，确认目标命令是否由该 Agent 支持；不同 Agent 的命令、注入、凭据和横向能力并不一致。

---

## Phase 3: C2 Profile 选择

C2 Profile 决定 Agent 如何回连。它应匹配目标网络出口，而不是只按“隐蔽性”排序。

| Profile | 适用场景 | 注意点 |
|---|---|---|
| `http` / `httpx` | 常规 Web 出网 | 需要域名、证书和流量特征设计 |
| `websocket` | 长连接允许、需要低延迟交互 | 长连接在部分网络中更显眼 |
| `dns` | HTTP 出网受限但 DNS 可用 | 速度慢，适合作为备用或低频通道 |
| `dynamichttp` | 需要动态调整 HTTP 行为 | 先验证 Agent 支持情况 |
| `smb` | 内网横向、不出网主机 | 依赖已控主机与目标之间 SMB 可达 |
| `tcp` | 简单直连或内网绑定 | 易被网络边界阻断，适合受控实验或内网 |

安装 Profile：

```bash
./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicC2Profiles/httpx
./mythic-cli install github https://github.com/MythicC2Profiles/dns
./mythic-cli install github https://github.com/MythicC2Profiles/smb
```

---

## Phase 4: SSL 与域名

HTTP/HTTPS Profile 上线前先处理证书。生产演练中优先使用真实域名和有效证书；自签证书适合实验环境，但容易暴露异常特征。

使用 certbot 获取证书：

```bash
sudo apt install certbot
certbot certonly --standalone -d "example.com" --register-unsafely-without-email --non-interactive --agree-tos
```

把证书复制到对应 Profile 容器路径，并在 Profile 配置中设置 `key_path` 和 `cert_path` 对应文件名：

```bash
docker cp /etc/letsencrypt/archive/example.com/fullchain1.pem http:/Mythic/http/c2_code/fullchain.pem
docker cp /etc/letsencrypt/archive/example.com/privkey1.pem http:/Mythic/http/c2_code/privkey.pem
```

如果 Profile 开启 `use_ssl` 且磁盘上没有证书，部分 Profile 会自动生成自签证书；这种方式只适合测试，不建议用于真实授权演练。

---

## Phase 5: Payload 构建与任务操作

基本流程：

```text
安装 Agent → 安装 Profile → 创建 payload → 配置 callback 参数 → 生成并投递 → 等待 callback → 下发 task
```

构建 payload 时重点确认：

- Agent 与目标 OS/架构匹配。
- Profile 与目标出口网络匹配。
- callback host 指向 redirector 或 C2 域名，而不是暴露管理端。
- sleep/jitter 与演练噪声要求一致。
- payload 格式与投递方式匹配。

任务下发后先做低噪声验证，例如身份、主机名、当前目录和网络连通性；确认稳定后再进行文件、凭据或横向相关操作。

---

## OPSEC 与排障

| 问题 | 判断方向 |
|---|---|
| Agent 不回连 | callback host/port、Profile 容器状态、证书、目标出口策略 |
| 回连后命令无输出 | Agent 是否支持该命令、任务是否完成、sleep 是否过长 |
| HTTPS 异常 | 证书路径、域名 SNI、Profile `use_ssl` 配置 |
| DNS Profile 慢 | 这是通道特性；只适合低频任务或备用通道 |
| SMB/TCP 不通 | 先验证目标到 pivot 的网络可达性和端口监听 |

Mythic 的模块化意味着“安装成功”不等于“能力可用”。每次演练前都应以当前 Agent/Profile 的官方文档和 feature matrix 为准，确认命令支持、平台限制和日志特征。

## References

- Mythic Documentation: https://docs.mythic-c2.net
- Mythic Agents: https://github.com/MythicAgents
- Mythic C2 Profiles: https://github.com/MythicC2Profiles
