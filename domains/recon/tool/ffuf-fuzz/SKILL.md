---
name: ffuf-fuzz
description: "ffuf 模糊测试工具完整参考。用于目录/文件发现、参数 Fuzz、虚拟主机枚举、POST 数据 Fuzz、多位置 Fuzz。当需要对 Web 应用进行路径爆破、参数发现、子域名枚举时使用。比 gobuster/dirsearch 更灵活——支持多 FUZZ 位置和自定义过滤。任何需要 Web 路径或参数暴力枚举的场景都应使用此 skill"
metadata:
  tags: "ffuf,fuzz,directory,brute force,parameter,vhost,wordlist,web,目录扫描,参数发现,模糊测试"
  category: "tool"
---

# ffuf 模糊测试工具完整参考

ffuf (Fuzz Faster U Fool) 是最灵活的 Web 模糊测试工具。核心概念：用 `FUZZ` 关键字标记需要替换的位置。

## Phase 1: 目录/文件发现（最常用）

```bash
# 基础目录扫描
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# 指定扩展名
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -e .php,.html,.txt,.bak,.zip

# 递归扫描（发现目录后继续深入）
ffuf -u http://target/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# 大字典深度扫描
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -e .php,.asp,.jsp -t 50
```

### 字典选择

| 场景 | 推荐字典 |
|------|----------|
| 快速扫描 | `Discovery/Web-Content/common.txt` (4660) |
| 中等扫描 | `Discovery/Web-Content/directory-list-2.3-small.txt` (87k) |
| 深度扫描 | `Discovery/Web-Content/directory-list-2.3-medium.txt` (220k) |
| 备份文件 | `Discovery/Web-Content/common-and-backup.txt` |
| API 路径 | `Discovery/Web-Content/api/api-endpoints.txt` |
| CTF 常见 | `/pentest/AboutSecurity/Dic/Web/CTF/` |

---

## Phase 2: 参数 Fuzz（发现隐藏参数）

```bash
# GET 参数发现
ffuf -u 'http://target/page.php?FUZZ=test' \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242  # 过滤默认响应大小

# GET 参数值 Fuzz
ffuf -u 'http://target/page.php?id=FUZZ' \
    -w /usr/share/seclists/Fuzzing/integers-1-1000.txt

# POST 参数发现
ffuf -u 'http://target/api' -X POST \
    -d 'FUZZ=test' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242

# JSON 参数 Fuzz
ffuf -u 'http://target/api' -X POST \
    -d '{"FUZZ":"test"}' \
    -H 'Content-Type: application/json' \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242
```

**CTF 专用参数字典**：`/pentest/AboutSecurity/Dic/Web/CTF/Fuzz_param.txt`

---

## Phase 3: 虚拟主机 / 子域名枚举

```bash
# 虚拟主机枚举（通过 Host 头）
ffuf -u http://target/ -H 'Host: FUZZ.target.com' \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -fs 4242  # 过滤默认页面大小
```

---

## Phase 4: 多位置 Fuzz

ffuf 支持多个 FUZZ 关键字（用不同名称区分）：

```bash
# 用户名+密码爆破
ffuf -u http://target/login -X POST \
    -d 'username=HFUZZ&password=WFUZZ' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -w users.txt:HFUZZ -w passwords.txt:WFUZZ \
    -fc 401  # 过滤 401 响应

# 目录+扩展名组合
ffuf -u http://target/W1FUZZ.W2FUZZ \
    -w dirs.txt:W1FUZZ -w extensions.txt:W2FUZZ \
    -mode clusterbomb  # 所有组合（笛卡尔积）
```

### Fuzz 模式

| 模式 | 说明 | 场景 |
|------|------|------|
| `clusterbomb` | 所有组合（默认） | 用户名×密码 |
| `pitchfork` | 一一对应 | 已知配对的凭据 |
| `sniper` | 单字典逐位置 | 单参数多位置 |

---

## Phase 5: 过滤与匹配（关键！）

ffuf 默认显示所有响应，需要过滤噪音：

### 过滤（排除不想要的）

| 参数 | 作用 | 示例 |
|------|------|------|
| `-fc` | 过滤状态码 | `-fc 404,403,500` |
| `-fs` | 过滤响应大小 | `-fs 4242` |
| `-fw` | 过滤响应词数 | `-fw 12` |
| `-fl` | 过滤响应行数 | `-fl 5` |
| `-fr` | 过滤正则匹配 | `-fr 'not found'` |
| `-ft` | 过滤响应时间 | `-ft '>3000'`（>3秒） |

### 匹配（只显示想要的）

| 参数 | 作用 | 示例 |
|------|------|------|
| `-mc` | 匹配状态码 | `-mc 200,301,302` |
| `-ms` | 匹配响应大小 | `-ms 1234` |
| `-mw` | 匹配响应词数 | `-mw 100-500` |
| `-mr` | 匹配正则 | `-mr 'flag\{.*\}'` |

**技巧**：先不加过滤跑一次，观察默认响应大小，然后用 `-fs` 过滤掉。

---

## Phase 6: 常用选项

```bash
# 线程数（默认 40，可调高）
-t 100

# 延迟（避免被封，单位秒；0.1 = 100ms）
-p 0.1

# 请求速率限制（每秒请求数）
-rate 50

# 自定义 Cookie
-b 'session=abc123; token=xyz'

# 自定义 Header
-H 'Authorization: Bearer TOKEN'
-H 'X-Forwarded-For: 127.0.0.1'

# 代理
-x http://127.0.0.1:8080
-x socks5://127.0.0.1:1080

# 输出到文件
-o results.json -of json
-o results.csv -of csv
-o results.html -of html

# 自动校准（自动检测过滤基线）
-ac

# 跟随重定向
-r

# 超时（秒）
-timeout 10

# 静默模式（只输出结果）
-s
```

---

## 实战场景速查

| 场景 | 命令 |
|------|------|
| 快速目录扫描 | `ffuf -u URL/FUZZ -w common.txt -mc 200,301,302` |
| 扫 PHP 文件 | `ffuf -u URL/FUZZ -w common.txt -e .php -mc 200` |
| 找隐藏参数 | `ffuf -u 'URL?FUZZ=1' -w burp-parameter-names.txt -fs SIZE` |
| LFI 参数 Fuzz | `ffuf -u 'URL?FUZZ=../../../etc/passwd' -w Fuzz_param.txt -mr 'root:'` |
| 子域名枚举 | `ffuf -u URL -H 'Host: FUZZ.target' -w subdomains.txt -fs SIZE` |
| 暴力登录 | `ffuf -u URL -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt -fc 401` |
| API 端点发现 | `ffuf -u URL/api/FUZZ -w api-endpoints.txt -mc 200,401,403` |
| 备份文件搜索 | `ffuf -u URL/FUZZ -w common.txt -e .bak,.zip,.tar.gz,.sql -mc 200` |

## 注意事项

- **`-ac` 自动校准**非常实用——自动检测默认响应并过滤，减少手动设置 `-fs` 的麻烦
- ffuf 默认 40 线程，对弱目标可能过快导致 429/封 IP，降到 `-t 10 -p 0.1`
- 字典路径：SecLists 通常在 `/usr/share/seclists/`，AboutSecurity 字典在 `/pentest/AboutSecurity/Dic/`
- POST Fuzz 必须指定 Content-Type 头，否则服务端可能不解析
- 多位置 Fuzz 默认是 clusterbomb（笛卡尔积），大字典时组合数爆炸，注意字典大小
