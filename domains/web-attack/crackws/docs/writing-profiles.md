# 写一个 crackws profile

面向两类人：**第一次接触 WebSocket 的新手**，和**已经会看报文、只想把 profile 写对的人**。
全文的字段名、取值、flag 都以源码为准（`internal/profile/profile.go`、`internal/cli/`）。

---

## 0. 一句话理解 profile

> profile 是**一份写给 crackws 的说明书**：告诉它「这个 WebSocket 服务长什么样、哪几个字是变量、回执怎么看」。

它不是配置框架，就是一段 YAML。`crackws profile export examples/vuln-sqli.yaml` 可以直接导出看全文。

**不写 profile 也能打**（`--target` 会自动套用内置的 `generic`），但那时注入点的粒度是「整条消息」。写了 profile，注入点才能细化到「消息里的某一个字段」。

---

## 1. 概念映射：profile 字段 ↔ WebSocket 概念

这张表是全文的核心。左边是你在报文里能看到的东西，右边是它在 profile 里的落点。

| WebSocket 里的东西 | profile 字段 | 备注 |
|---|---|---|
| 端点地址 `ws://host:port/path` | `target.url` | `wss://` 也支持 |
| 握手时的自定义头（`Origin`、`Cookie`、`Authorization`） | `target.headers` | 服务端校验 Origin 非常常见 |
| 子协议 `Sec-WebSocket-Protocol` | `target.subprotocols` | 有些服务不协商就拒绝 |
| 握手走的代理 / 自签证书 | `target.proxy` / `target.insecure_tls` | |
| **连接建立后服务端主动推的第一条消息** | `target.settle_ms` | 不排空就会污染第一个响应 |
| 一条消息的正文 | `requests[].template` | 原样抄，变量换成 `{{名字}}` |
| 消息里的可变部分（= 注入点） | `{{占位符}}` + `params` | 见 §4.3 |
| 发出去用文本帧还是二进制帧 | `requests[].opcode` | `text`（默认）/ `binary` |
| **一次请求回了多条消息** | `requests[].response.idle_ms` | 静默窗口，见 §2.3 |
| 回执里「哪一条」算答案 | `response.select` / `response.accept_types` | |
| 回执里「哪个字段」算答案 | `response.match_path` / `extract[].path` | |
| 必须先登录才能干活 | `setup[]` | 每条新连接先跑一遍 |
| 登录回执里的 token 给后续消息用 | `extract[].name` → 后续模板写 `{{token}}` | |
| 「一条连接只允许登录一次」 | CLI `--fresh-session` | 不是 profile 字段 |
| 给桥接的默认行为 | `bridge` / `detect` / `fuzz` | 见 §4.6 |

---

## 2. 新手先学会读 WebSocket

### 2.1 握手阶段：决定 `target` 怎么写

一个升级请求长这样：

```http
GET /ws HTTP/1.1
Host: 10.0.0.5:9000
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: http://10.0.0.5
Cookie: session=abc123
```

成功的响应：

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

要读出来的三件事：

1. **状态码不是 101**（403 / 401 / 426）→ 大概率卡在 `Origin` 校验或 Cookie 上。把浏览器里那条成功请求的头抄进 `target.headers`。
2. **有没有 `Sec-WebSocket-Protocol`** → 有就抄进 `target.subprotocols`。
3. **`Server` 头** → 能看出技术栈（`Python/3.x websockets/x.y` 之类），对后面判断行为有帮助。

> crackws 会自动校验 `Sec-WebSocket-Accept`。如果它报「可能被中间人改写」，说明链路里有个代理在动握手。

### 2.2 消息阶段：决定 `template` 怎么写

WebSocket 一次 `send` 就是一条**消息**。消息可能是：

| 形态 | 例子 | profile 写法 |
|---|---|---|
| JSON 信封 | `{"type":"login","username":"a"}` | 直接抄，见例 1 |
| 纯文本命令 | `LOGIN root secret` | 直接抄，见例 2 |
| 位置参数 | `5:3:hello` | 直接抄 |
| 二进制 | 任意字节 | `opcode: binary`，模板里放可打印部分或用 `repl` 的 `hex` 命令 |

**最容易忽略的一点**：消息在网线上会被拆成**帧**（frame）。一条大消息可能被切成多个 `continuation` 帧；另外还有 `ping`/`pong`/`close` 这些控制帧。crackws 会自动把分片拼回整条消息、自动回 `pong`，你只需要关心「消息」这一层。

### 2.3 最重要的一课：WebSocket 没有「请求-响应」

HTTP 是一问一答，WebSocket 是**双向流**。常见三种模式：

| 模式 | 表现 | 怎么处理 |
|---|---|---|
| 一问一答 | 发 1 条，回 1 条 | `idle_ms` 给个小值（100–200ms）即可 |
| **一问多答** | 发 1 条，回 3 条：`welcome` + `token` + `user_list` | 必须让 `idle_ms` 足够大，否则只读到第一条 |
| 主动推送 | 连上先推一条 banner，或订阅后持续推 | `settle_ms` 排空初期的推送 |

crackws 用**静默窗口**来切分回复：

```
发送 ──► 读到第一帧 ──► 继续读 ──► 连接安静 idle_ms ──► 认为「这次回复结束了」
```

所以 `idle_ms` 是新手第一个要调对的参数：

- **太小** → 多帧回复被截断，只拿到第一帧
- **太大** → 每次请求都要多等这么久，扫描变慢

先用浏览器 DevTools 观察「一次操作回了几条、间隔多久」，然后给一个略大于最大间隔的值。

### 2.4 手边的工具

```bash
# 浏览器：F12 → Network → 筛选 WS → 点连接 → Messages 面板，看真实收发的每一帧
# 命令行：
websocat -v ws://10.0.0.5:9000/          # 有装 websocat 的话，-v 会打印帧

# crackws 自带（不需要 profile）：
crackws probe  --target ws://10.0.0.5:9000/
crackws recon  --target ws://10.0.0.5:9000/
crackws send   --target ws://10.0.0.5:9000/ --message '{"type":"ping"}'
crackws repl   --target ws://10.0.0.5:9000/     # 交互式，命令见 repl 的 help
```

`repl` 里最常用的几条：

```
raw {"type":"ping"}      发一条原文
show                     打印上一条回复（JSON 会美化）
frames                   看这次回复由几帧组成、每帧的结构签名
login                    跑 profile 里的 setup 序列
use login / send         切换模板并发送
```

---

## 3. 四步法：从零写出一个 profile

### 第 1 步：先别写，先探

```bash
crackws probe --target ws://10.0.0.5:9000/
crackws recon --target ws://10.0.0.5:9000/ --max-fields 20
```

`recon` 会告诉你：

- 协议是 `json` 还是 `text`
- 哪些 `type` 被服务端识别（差分法：先发一个必然被拒的值当基线）
- 每个 type 大概读哪些字段
- 服务端错误文案里泄露的字段名（「用户名不能为空」→ 有个 `用户名` 字段）

### 第 2 步：手工确认报文形态

```bash
crackws repl --target ws://10.0.0.5:9000/
crackws[raw]> raw {"type":"login","username":"admin","password":"x"}
crackws[raw]> show
```

把**成功的**那条报文原样记下来。同时记下：

- 回了几条消息（用 `frames` 看）
- 回执里哪个字段代表「成功」/「失败」
- 有没有需要带去后续请求的值（token、session id）

### 第 3 步：抄成模板，把变量挖成占位符

```
观察到的报文：  {"type":"login","username":"admin","password":"x"}
                              ~~~~~~~~~~~~~ 变量      ~~~~ 变量
写成模板：      {"type":"login","username":"{{username}}","password":"{{password}}"}
```

**关键规则**：占位符替换**不做 JSON 转义**。这是故意的——否则 `'` 会被转义成 `\'`，注入 payload 在离开客户端之前就被中和了。

由此产生「两种上下文」，你必须知道自己在哪一种：

| 你写的模板 | 上下文 | payload 落地后的样子 |
|---|---|---|
| `"username":"{{username}}"` | **字符串内**（占位符被引号包着） | `"username":"1' OR '1'='1"` |
| `"username":{{username}}` | **裸值**（没有引号） | `"username":1' OR '1'='1` ← 会破坏 JSON |

绝大多数情况你应该用**第一种**（带引号）。第二种只在你要注入 JSON 结构（比如塞一个 `{"$ne":null}` 对象）时才用。

`crackws` 会自己判断上下文（`string` / `raw`），NoSQL 之类的检测器会据此挑 payload。

### 第 4 步：调 response 策略

把 §2.3 观察到的结果填进去：

```yaml
response:
  idle_ms: 500                 # 比「多帧最大间隔」略大
  select: first                # 取第一帧作为 body（也可 last / all / largest）
  accept_types: [system, error, login_success]   # 只认这几类帧，其余当噪声
  timeout_ms: 15000            # 等第一帧的上限
```

---

## 4. 字段参考

### 4.1 `target`（连接）

```yaml
target:
  url: ws://10.0.0.5:9000/ws       # 必填
  headers:                          # 握手头，键大小写照写
    Origin: "http://10.0.0.5"
    Cookie: "session=abc123"
  subprotocols: [graphql-ws]        # 会被拼成 Sec-WebSocket-Protocol
  proxy: socks5://127.0.0.1:1080    # 也可 http://127.0.0.1:8080
  insecure_tls: false               # wss:// 自签证书时设 true
  server_name: example.com          # 覆盖 TLS SNI / 证书校验名
  timeout_ms: 10000                 # 拨号+握手上限
  settle_ms: 200                    # 连接后先排空这么多毫秒的主动推送
  mask_frames: true                 # 默认 true（RFC 要求客户端必须掩码）
  no_mask: false                    # 设 true 会发不掩码的帧（协议违规，仅用于测服务端）
  auto_pong: true                   # 收到 ping 自动回 pong
  max_payload_bytes: 10485760       # 单帧上限，超过就断开
```

> `settle_ms` 是新手最容易漏的一个。服务端「连上就推一条 banner」时，那条 banner 会被算进**第一个请求**的回复里，导致第一个响应和其他响应长得不一样——差分比较全部失真。症状是「recon 把每个候选 type 都判成有效」。

### 4.2 `setup[]`（会话建立）

```yaml
setup:
  - name: login
    template: '{"type":"login","username":"admin","password":"admin123"}'
    response:
      idle_ms: 500
      accept_types: [system, login_success]
    extract:
      - { name: token, path: token }      # 提取出来，后续模板写 {{token}} 即可引用
```

每条**新连接**都会按顺序跑一遍 `setup`。提取出的变量存在会话里，之后所有请求的模板都能引用。

如果目标「一条连接只允许登录一次」，跑完 setup 后再发 login 会被拒绝 → 用 CLI 的 `--fresh-session --no-setup` 让每个 HTTP 请求用全新连接、且不预先登录。

### 4.3 `requests[]`（消息模板）

```yaml
requests:
  - name: login                        # 桥接时映射成 /msg/login
    description: 攻击者可控凭据登录
    template: '{"type":"login","username":"{{username}}","password":"{{password}}"}'
    template_file: ""                  # 或者从文件读模板（模板很长时用）
    opcode: text                       # text（默认）| binary
    params:
      username:
        default: admin                 # 不传时的默认值
        required: false
        inject: true                   # 是否算「注入点」（默认 true）
        escape_json: false             # true 则对值做 JSON 字符串转义
        description: 用户名
    response: { ... }                   # 见 4.4
    extract: [ ... ]                    # 见 4.5
```

`inject: false` 的用处：某些字段是你不想被扫描器乱动的固定值（比如版本号），标掉它，桥接和 `detect` 就不会把它列成注入点。

### 4.4 `response`（怎么读回复）

```yaml
response:
  idle_ms: 300        # 静默窗口：连接安静这么久就认为回复结束
  max_frames: 32      # 最多收集多少帧
  select: first       # first | last | all | largest
  accept_types: []    # 只接受 JSON 里 "type" 等于这些值的帧
  match_path: ""      # 只接受这个 JSON 路径能解析出值的帧
  timeout_ms: 15000   # 等第一帧的上限
```

`select` 的四种取值对应的场景：

| 取值 | 用途 |
|---|---|
| `first` | 最常见，直接答复通常在第一帧 |
| `last` | 终态在最后一帧（比如先 `progress` 后 `done`） |
| `all` | 把所有帧拼起来当 body，信息最全但会让差分变钝 |
| `largest` | 推送流里挑最长的那帧（通常才是数据帧） |

### 4.5 `extract`（从回复里取值）

```yaml
extract:
  - name: token            # 变量名，后续模板写 {{token}}
    path: data.token       # JSON 路径：a.b.c / a[0].b / /a/b/0 都行
    # regex: '"token":"([^"]+)"'   # 或者用正则（此时忽略 path）
    # group: 1                     # 正则捕获组，默认 1
    optional: false          # true 则取不到也不报错
```

### 4.6 `detect` / `fuzz` / `bridge` / `wordlists`

这三个是「默认计划」，让 `crackws detect` / `fuzz` / `bridge` 不带参数也知道该打哪里。

```yaml
detect:
  request: login                  # 打哪个 request
  params: [username, password]    # 打哪些注入点（省略则用该 request 全部 inject 参数）
  detectors: []                   # 只跑指定检测器，可选

fuzz:
  request: chat
  param: content                  # 留空 = fuzz 整条消息
  wordlist: custom
  concurrency: 1                  # 单会话后端必须用 1，否则自己把自己踢掉
  max_payloads: 200

bridge:
  default_request: login          # 请求 "/" 时用哪个模板
  raw_param: data                 # /raw?data=... 的参数名
  idle_ms: 400                    # 覆盖 response 的 idle
  extract: ""                     # 对所有响应统一提取某个字段作为 body
  error_match: []                 # 命中则返回非 200（给 Burp 看；**驱动 sqlmap 时不要开**）
  error_status: 500
  aliases: {p: password}          # 把 HTTP 参数名映射到占位符名
  content_type: ""                # 覆盖响应 Content-Type

wordlists:
  custom: ["'", '"', "../", "$(id)"]
  types:  [login, chat, admin]    # recon 的 --profile 会优先用这个
```

---

## 5. 三个可直接抄的完整示例

### 例 1：JSON 信封 + 会话 + 可注入（`examples/vuln-sqli.yaml` 的精简版）

```yaml
name: json-login
description: JSON 登录接口，字符串拼接 SQL，可注入

target:
  url: ws://127.0.0.1:9100/
  timeout_ms: 10000

requests:
  - name: login
    template: '{"type":"login","username":"{{username}}","password":"{{password}}"}'
    params:
      username: { default: admin, inject: true }
      password: { default: x, inject: true }
    response:
      idle_ms: 200
      select: first
      accept_types: [system, error]

  - name: chat
    template: '{"type":"chat","content":"{{content}}"}'
    params:
      content: { default: hello, inject: true }
    response: { idle_ms: 200, select: first }

detect: { request: login, params: [username, password] }
fuzz:   { request: chat, param: content, concurrency: 1, max_payloads: 120 }
bridge: { default_request: login, raw_param: data, idle_ms: 200 }
```

```bash
crackws bridge --profile json-login.yaml --listen 127.0.0.1:8899
sqlmap -u 'http://127.0.0.1:8899/msg/login?username=admin&password=1' -p password --batch
```

### 例 2：纯文本位置参数（`examples/alt-protocol.yaml` 的精简版）

报文是 `LOGIN <user> <pass>`，**没有 JSON、没有 type 字段**。注意模板直接就是一行文本：

```yaml
name: text-login
description: 空格分隔的纯文本命令协议

target:
  url: ws://127.0.0.1:9200/
  settle_ms: 200          # 该服务连上就推一行 banner

requests:
  - name: login
    template: 'LOGIN {{user}} {{pass}}'     # 注意：这里 {{pass}} 后面没有内容
    params:
      user: { default: root, inject: true }
      pass: { default: x, inject: true }
    response: { idle_ms: 150, select: all }

  - name: echo
    template: 'ECHO {{text}}'
    params:
      text: { default: hello, inject: true }
    response: { idle_ms: 150, select: all }

bridge: { default_request: login, raw_param: data, idle_ms: 150 }
```

`{{pass}}` 落在口令位置，payload 里的空格会被服务器当作口令的一部分（因为它是最后一个位置参数），所以 `x' UNION SELECT 1--` 能完整送达。

### 例 3：需要先登录、回执多帧、token 要复用

```yaml
name: authed-json
description: 先登录拿 token，之后的业务消息要带 token

target:
  url: wss://10.0.0.5:9443/ws
  headers:
    Origin: "https://10.0.0.5"
  insecure_tls: true
  settle_ms: 150

setup:                        # 每条新连接先执行
  - name: login
    template: '{"op":"auth","user":"{{AUTH_USER}}","pass":"{{AUTH_PASS}}"}'
    params:
      AUTH_USER: { default: admin, inject: false }   # 固定值，不是注入点
      AUTH_PASS: { default: hunter2, inject: false }
    response:
      idle_ms: 600
      select: first
      accept_types: [auth_ok, welcome, error]
    extract:
      - { name: token, path: data.token }
      - { name: uid,   path: data.user.id, optional: true }

requests:
  - name: search
    template: '{"op":"search","token":"{{token}}","q":"{{q}}"}'
    params:
      q: { default: test, inject: true }
    response:
      idle_ms: 400
      select: last                    # 先回 progress 再回 result

detect: { request: search, params: [q] }
fuzz:   { request: search, param: q, concurrency: 1 }
bridge: { default_request: search, raw_param: data, idle_ms: 400 }
```

注意 `{{token}}` 在 `requests` 里被引用——它来自 `setup` 的 `extract`，是**会话变量**，不是这个 request 的参数。两者可以同名共存，请求级参数优先。

---

## 6. 常见坑与对策

| 症状 | 原因 | 对策 |
|---|---|---|
| recon 把每个候选 type 都判成「有效」 | 服务端回显了请求内容，或连上先推 banner | 检查 `settle_ms`；crackws 已内置回显消除，但 banner 属于另一类 |
| 只拿到回复的第一帧 | `idle_ms` 太小 | 调大；用 `repl` 的 `frames` 确认实际帧数 |
| 每个请求都慢得离谱 | `idle_ms` 太大 | 调到「比多帧最大间隔略大」即可 |
| 非 login 请求都返回「请先登录」 | 没有 `setup` | 加 `setup` 序列 |
| 第二次登录被拒 | 服务端一条连接只允许登录一次 | 用 CLI `--fresh-session --no-setup` |
| payload 里的 `'` 没生效 | 你用了 `escape_json: true` | 关掉它（默认就是关的） |
| payload 导致 JSON 非法、服务端报「无效的 JSON」 | 占位符在字符串内，payload 里的 `"` 破坏了字符串 | 这是**正常现象**；sqlmap 的 payload 多为 `'`，一般不触发。要注入结构时改用裸值上下文 |
| 服务端额外字段就报错 | 模板里少写了必填字段 | 对照真实报文补齐 |
| 桥接的 `/` 返回 400 | 没配 `bridge.default_request` | 配上，或用 `/msg/<name>` |
| sqlmap 说 not injectable | 见下 | |

关于 sqlmap：零 profile 时 URL 的参数值就是**整条消息**，而 sqlmap 对参数值是**在其后追加** payload。所以要把「注入点之前的固定内容」直接写进参数值：

```bash
# 消息形态是 LOGIN root <payload>
sqlmap -u 'http://127.0.0.1:8891/raw?data=LOGIN+root+1' -p data --batch
```

用 `--prefix` 是错的——它会被拼在**原参数值之后**，而不是替换原值。

---

## 7. 验证你写的 profile

```bash
# 1. 语法与结构
crackws profile show my.yaml            # 打印解析后的结果，能看出哪个 request 有什么注入点
crackws profile export my.yaml > out.yaml

# 2. 单条消息能不能发通
crackws send   --profile my.yaml --request login
crackws send   --profile my.yaml --message '{"type":"ping"}'

# 3. 提取规则对不对（会话变量有没有拿到）—— 在 repl 里跑 setup，再看变量
crackws repl --profile my.yaml
crackws[login]> login                   # 执行 profile 里的 setup 序列
crackws[login]> vars                    # 打印提取到的会话变量

# 4. 桥接是否映射正确
crackws bridge --profile my.yaml --listen 127.0.0.1:8899
curl -s http://127.0.0.1:8899/__crackws/info     # 打印每个模板的注入点
curl -s 'http://127.0.0.1:8899/msg/login?username=admin&password=x'

# 5. 全流程
crackws recon  --profile my.yaml
crackws detect --profile my.yaml
crackws fuzz   --profile my.yaml
```

任何时候不确定，加 `--verbose` 看协议层细节；`--idle` / `--timeout` / `--settle` / `--fresh-session` / `--no-setup` 都是 CLI flag，可以在不改 profile 的情况下临时调整。

---

## 附：一张速查表

```yaml
name: <名字>
description: <一句话>

target:
  url: ws://host:port/path       # 必填
  headers: {Origin: "..."}       # Origin 校验
  subprotocols: []
  proxy: ""                      # http:// 或 socks5://
  insecure_tls: false
  timeout_ms: 10000
  settle_ms: 0                   # 连上先排空主动推送

setup:                           # 可选：每条新连接先跑
  - name: login
    template: '...'
    response: {idle_ms: 500, accept_types: [ok]}
    extract: [{name: token, path: data.token}]

requests:
  - name: <桥接路径 /msg/<name>>
    template: '... {{占位符}} ...'
    opcode: text                 # text | binary
    params:
      <占位符>: {default: x, inject: true, escape_json: false}
    response:
      idle_ms: 300               # 静默窗口
      select: first              # first|last|all|largest
      accept_types: []
      match_path: ""
      timeout_ms: 15000
    extract: []

detect: {request: <name>, params: [<占位符>]}
fuzz:   {request: <name>, param: <占位符>, concurrency: 1, max_payloads: 200}
bridge: {default_request: <name>, raw_param: data, idle_ms: 300, error_match: []}
wordlists: {}
```
