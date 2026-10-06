# WAF 检测与绕过双工具（hnytgl）

本卡收录同作者（GitHub `hnytgl`）的两个 WAF 检测 / 绕过工具，均用于**已授权**的安全测试。
两份工具的源 README 原文分别保存在各自子目录，本文件做合并导航与速查。

|  | **WafBypass**（`WafBypass/`） | **Waf-Auto-Fuzzer**（`Waf-Auto-Fuzzer/`） |
|---|---|---|
| 定位 | 高级 WAF 检测与自动绕过（原 WhatWaf 全面升级版）：回答「目标真的有 WAF 防护吗」 | 自动化 WAF 绕过探测与指纹识别：payload × 编码矩阵 FUZZ，找出能过的变形 |
| 版本 / 语言 | v4.0.0；Python 3.9+（GPLv3） | Python 3（requests；TLS 伪装需 curl_cffi） |
| 检测面 | **112+ 种** WAF/防护系统；v4.0.0 为声明式签名引擎（111 个纯数据 YAML 签名 + Python 插件 fallback） | 自动识别 **35 种** WAF（Cloudflare/Akamai/AWS/Azure/F5/Imperva/Sucuri/DataDome/PerimeterX/Kasada/腾讯云/华为云/奇安信/绿盟/山石/安恒/启明星辰/天融信/火山引擎/加速乐/云盾/百度云/SafeDog/Reblaze/Wallarm/Zscaler 等） |
| 绕过面 | **81 个** tamper 脚本，支持 2–3 层自动组合链（档案：balanced/sqli/xss/encoding/cmdi/lfi/ssti）；自适应绕过引擎（自学习阻断签名、Tamper 动态重排序、按 WAF 产品优先、家族多样性早停） | **17 类攻击 payload × 49 种编码/变形**（SQLi/XSS/命令注入/路径穿越/SSRF/RCE/XXE/SSTI/LDAP/Open Redirect 等） |
| 共同能力 | TLS 指纹伪装 `--impersonate`（绕 Cloudflare/Akamai/DataDome 的 JA3/JA4 层拦截）、代理/报告（JSON/HTML） | 同左；另可 `--generate-script` 自动生成可复用绕过脚本 |

## 文件清单

```
waf-tools/
├── README.md                            ← 本文件（合并说明）
├── summary.md
├── WafBypass/
│   ├── README.md                        ← 源仓库 README 原文（v2.4~v4.0 更新史 / 参数表 / 示例 / Docker / FAQ）
│   ├── signatures/all-signatures.yaml   ← 111 个 WAF 检测签名 + _schema.json 合并档（见下方说明）
│   └── tools/migrate_plugins.py         ← AST 迁移工具：Python 检测插件 → 等效 YAML 签名
└── Waf-Auto-Fuzzer/
    ├── README.md                        ← 源仓库 README 原文（用法 / 参数表 / 编码清单）
    ├── waf_fuzz.py                      ← CLI 入口
    ├── requirements.txt                 ← colorama / requests / urllib3（curl_cffi 可选）
    └── waf_fuzz/                        ← detector(WAF指纹) / fuzzer / payloads / bypass / encoders / output
```

> **signatures 合并档说明**：源 `hnytgl/WafBypass/signatures/` 目录共 112 个文件
> （111 个 WAF 产品签名 YAML + `_schema.json`）。因知识卡单卡文件数限制，已按
> `# ===== signatures/<文件名> =====` 分隔线**合并为一个文件**保存；实际使用时按分隔线
> 拆回独立文件，或用 `--update-signatures` 直接拉取官方签名包（SHA256 校验）。

## 快速上手

WafBypass（`python wafbypass ...`，源目录内直接运行）：

```bash
pip install -r requirements.txt          # 或 pip install wafbypass[impersonate]

# 检测单个 URL 的 WAF 并自动尝试绕过
python wafbypass -u https://example.com/?id=1

# 批量 + JSON 输出 + 多线程
python wafbypass -l targets.txt -F -J -t 5

# 查可用签名 / tamper / 组合档案
python wafbypass --wafs
python wafbypass --tampers
python wafbypass --tamper-profiles

# SQLi 档案、最多两层、最多 16 条组合链（授权测试环境）
python wafbypass -u "https://lab.example/?id=1" --payload-type sqli \
  --tamper-profile sqli --tamper-chain-depth 2 --tamper-chain-budget 16

# TLS 指纹伪装绕 Cloudflare / 自检 JA3-JA4 指纹
python wafbypass -u https://target.com/?id=1 --impersonate chrome120
python wafbypass --tls-fingerprint

# 生成 HTML 报告 / 机器可读输出
python wafbypass -u https://example.com/?id=1 --html-report -F -J
python wafbypass -u https://example.com/?id=1 --json-stdout | jq .
```

Waf-Auto-Fuzzer（`python waf_fuzz.py ...`）：

```bash
pip install -r requirements.txt

# 基本用法：GET 参数 fuzz
python waf_fuzz.py -t "http://target.com/search?q=" -p q

# 仅测 SQLi 和 XSS / 仅用 URL 编码
python waf_fuzz.py -t "http://target.com/search?q=" -p q -c sqli xss
python waf_fuzz.py -t "http://target.com/search?q=" -p q -e urlencode base64

# TLS 指纹伪装绕过 Cloudflare
python waf_fuzz.py -t "https://target.com/search?q=" -p q --impersonate chrome120

# POST / Cookie / Header 注入；经 Burp 代理
python waf_fuzz.py -t "http://target.com/login" -m POST -p username
python waf_fuzz.py -t "http://target.com" -m COOKIE -p session_id
python waf_fuzz.py -t "http://target.com" -m HEADER -p X-Forwarded-For
python waf_fuzz.py -t "http://target.com" -p q --proxy http://127.0.0.1:8080

# 完整报告 + 自动生成绕过脚本
python waf_fuzz.py -t "http://target.com" -p q -o result.json \
  --generate-script --html-report report.html --bypass-report bypass.txt
```

## 来源与版本

- Source: `hnytgl/WafBypass`（v4.0.0；声明式 YAML 签名引擎、81 tamper、自适应绕过引擎）
- Source: `hnytgl/Waf-Auto-Fuzzer`（17 类 payload × 49 编码、35 种 WAF 指纹）
- 收录于 TGSEC 知识库批次 `2026-10-06b`（@cvebird 吸收）。

## 授权声明

两工具均要求仅对自有资产或已获书面授权的目标使用：
`WafBypass` 标注「请仅对自己拥有或已获得明确授权的目标进行测试」；
`Waf-Auto-Fuzzer` 标注「本工具仅供授权的安全评估使用」。

@TGSEC社区 · @TGSEC-Qtzuu 整理
