# WAF Auto Fuzzer

自动化 WAF 绕过探测与指纹识别工具。

## 功能

- **17 类攻击 payload** — SQLi, XSS, 命令注入, 路径穿越, SSRF, RCE, XXE, SSTI, LDAP, Open Redirect 等
- **49 种编码/变形** — URL 系列(8种), HTML实体(3种), Unicode(4种), Base64(2种), 大小写混淆(5种), 注释注入(8种), 空白变形(7种), 空字节(2种), 字符串连接(3种), Hex(2种), Shell通配符(2种), 其他(3种)
- **TLS 指纹伪装** — `--impersonate chrome120` 模拟浏览器 JA3/JA4 指纹，绕过 Cloudflare/Akamai/DataDome 的 TLS 层拦截（需 curl_cffi）
- **Session 连接池** — 共享 HTTP Session，连接复用 + Cookie 持久化（cf_clearance 等 challenge cookie 跨请求保持）
- **多 HTTP 方法** — GET, POST, PUT, Cookie 注入, Header 注入
- **并发 FUZZ** — 多线程快速扫描
- **WAF 指纹识别** — 自动识别 **35 种** WAF（Cloudflare, Akamai, AWS, Azure, F5, Imperva, Sucuri, 腾讯云, 华为云, 奇安信, 绿盟, 山石, 安恒, 启明星辰, 天融信, 火山引擎, 加速乐, 云盾, 百度云, SafeDog, DataDome, PerimeterX, Kasada, Reblaze, Wallarm, Zscaler 等）
- **结果输出** — JSON / CSV / HTML 报告
- **绕过脚本生成** — 自动生成可复用的 Python 绕过脚本
- **代理支持** — 支持 Burp Suite 等中间人代理
- **断点信号处理** — Ctrl+C 安全中断

## 安装

```bash
pip install -r requirements.txt

# 可选：TLS 指纹伪装支持
pip install curl_cffi
```

## 快速开始

```bash
# 基本用法：GET 参数 fuzz
python waf_fuzz.py -t "http://target.com/search?q=" -p q

# TLS 指纹伪装绕过 Cloudflare
python waf_fuzz.py -t "https://target.com/search?q=" -p q --impersonate chrome120

# POST 表单 fuzz
python waf_fuzz.py -t "http://target.com/login" -m POST -p username

# 仅测试 SQLi 和 XSS
python waf_fuzz.py -t "http://target.com/search?q=" -p q -c sqli xss

# 仅用 URL 编码
python waf_fuzz.py -t "http://target.com/search?q=" -p q -e urlencode base64

# 通过 Burp 代理
python waf_fuzz.py -t "http://target.com" -p q --proxy http://127.0.0.1:8080

# 保存结果并生成绕过脚本
python waf_fuzz.py -t "http://target.com" -p q -o result.json --generate-script

# Cookie 注入测试
python waf_fuzz.py -t "http://target.com" -m COOKIE -p session_id

# Header 注入测试
python waf_fuzz.py -t "http://target.com" -m HEADER -p X-Forwarded-For

# 完整 HTML 报告
python waf_fuzz.py -t "http://target.com" -p q -o result.json --html-report report.html --bypass-report bypass.txt
```

## 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-t, --target` | 必填 | 目标 URL |
| `-p, --param` | q | 参数名 |
| `-m, --method` | GET | HTTP 方法 (GET/POST/PUT/COOKIE/HEADER) |
| `-d, --data-param` | 同 -p | POST 参数名 |
| `-c, --categories` | 全部 | 测试分类 (sqli xss cmdi traversal ssrf rce xxe ssti ldap redirect) |
| `-e, --encodings` | 全部 | 编码方式 |
| `--threads` | 10 | 并发线程数 |
| `--delay` | 0 | 请求间延迟(秒) |
| `--timeout` | 10 | 超时(秒) |
| `--proxy` | — | 代理地址 |
| `--header` | — | 自定义请求头 |
| `--user-agent-rotate` | — | 轮换 UA |
| `--no-verify` | — | 跳过 SSL 验证 |
| `--follow-redirects` | — | 跟随重定向 |
| `--impersonate` | — | TLS 指纹伪装目标（chrome120/safari17_0/firefox135 等，需 curl_cffi） |
| `-o, --output` | — | 输出文件 (.json/.csv) |
| `--html-report` | — | HTML 报告路径 |
| `--bypass-report` | — | 绕过摘要报告路径 |
| `--generate-script` | — | 生成绕过脚本 waf_bypass.py |
| `--dry-run` | — | 仅显示测试计划 |

## 项目结构

```
waf_fuzz.py           # CLI 入口
waf_fuzz/
├── __init__.py       # 版本信息
├── payloads.py       # 所有攻击 payload 定义
├── encoders.py       # 编码/变形引擎
├── detector.py       # WAF 检测与指纹识别
├── fuzzer.py         # 多线程 FUZZ 引擎
├── bypass.py         # 绕过脚本生成器
└── output.py         # JSON/CSV/HTML 输出
```

## 编码方式（49 种）

| 名称 | 说明 |
|------|------|
| raw | 原始 payload |
| urlencode | URL 编码 |
| double_urlencode | 双重 URL 编码 |
| triple_urlencode | 三重 URL 编码 |
| percent_double | %% 双重编码绕过 |
| unicode_url | Unicode + URL 编码 |
| urlencode_twice_mixed | 选择性双重编码（仅特定字符）|
| leading_zero_url | 前导零 URL 编码 (%00XX) |
| html_escape | HTML 命名实体编码 |
| decimal_html | HTML 十进制实体 &#xx; |
| hex_html | HTML 十六进制实体 &#xxx; |
| unicode | Unicode 转义 |
| unicode_percent | %uXXXX 格式（IIS/ASP）|
| utf16_le | UTF-16-LE 编码 |
| full_width | 全角 ASCII 字母/数字 |
| base64 | Base64 编码 |
| base64_urlsafe | URL 安全 Base64 |
| swapcase | 大小写反转 |
| mixed_case | 交替大小写 |
| case_by_word | 按词切换大小写 |
| upper | 全大写 |
| lower | 全小写 |
| inline_comment | /**/ 替换空格 |
| sql_comment | 每字符间插 /**/ |
| sql_nested_comment | /*! 包裹注释 |
| sql_mysql_comment | MySQL /*!50000*/ 版本注释 |
| sql_hash_comment | 追加 # 注释 |
| sql_dash_comment | 追加 -- 注释 |
| mid_comment_char | 关键字中间插入注释 |
| comment_wrap | /* 包裹 payload */ |
| tab_replace | Tab 替换空格 |
| newline_replace | 换行替换空格 |
| space_to_plus | 加号替换空格 |
| space_to_dash | 横线替换空格 |
| collapse_spaces | 合并连续空格 |
| newline_delimited | %0a 分隔每个字符 |
| tab_delimited | %09 分隔每个字符 |
| null_byte_suffix | 末尾加 %00 空字节 |
| null_byte_mid | 关键字中间插 %00 |
| concat_dots | SQL \|\| 字符串连接 |
| plus_concat | 加号字符串连接 |
| bracket_wrap | 括号包裹 |
| hex_escape | 纯十六进制拼接 |
| javascript_escape | JavaScript \x 十六进制转义 |
| wildcard_shell | Shell 通配符 `?` 替换 |
| tilde_expand | 路径前加 ~ |
| reverse | 字符串反转 |
| trailing_spaces | 尾部追加空格 |
| overlong_utf8 | 过长 UTF-8 编码 |

## WAF 指纹识别库

支持 15+ 种 WAF 识别：Cloudflare, ModSecurity, AWS WAF, F5 BIG-IP, Akamai, Imperva, Sucuri, Barracuda, Fortinet, Azure WAF, Cisco ACE, Alibaba Cloud, SafeDog, DDoS-Guard, Wordfence。

## 免责声明

本工具仅供授权的安全评估使用。在未获得系统所有者书面授权的情况下使用本工具是非法的。作者对任何滥用行为不承担责任。
