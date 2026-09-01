---
name: local-resources
description: "本地资源库导航——字典库(Dic)、Payload库、POC库的结构和使用方法。当需要使用 ffuf/spray 目录爆破、密码爆破、或构造 Fuzz payload 时必读。覆盖字典选择策略、payload 模板调用、POC 库搜索方法。字典库统一安装在 /pentest 目录下"
metadata:
  category: "general"
  tags: "dictionary,wordlist,payload,poc,ffuf,spray,resource,字典,工具"
---

# 本地资源库导航

⚠️ **核心规则：字典统一在 /pentest 目录** — aboutsecurity 字典库和 nuclei 模板库均安装在 `/pentest/` 下。

## 📁 字典库 (Dic/) — 目录爆破 / 密码爆破 / 参数 Fuzz

### 工具链
```bash
# 查看字典库分类
ls /pentest/AboutSecurity/Dic/
# 查看 Web 字典子分类
ls /pentest/AboutSecurity/Dic/Web/
# 使用字典（示例）
spray -u http://target -d /pentest/AboutSecurity/Dic/Web/Directory/Fuzz_common.txt
ffuf -u http://target/FUZZ -w /pentest/AboutSecurity/Dic/Web/Directory/Fuzz_common.txt
```

### 常用字典速查表

| 场景 | 路径 | 行数 |
|------|-------------------|------|
| 通用目录爆破 | `Web/Directory/Fuzz_common.txt` | ~5k |
| PHP 文件发现 | `Web/Directory/php/Fuzz_php.txt` | ~48k |
| PHP Top100 | `Web/Directory/php/Top100_php.txt` | ~100 |
| CTF URI Fuzz | `Web/CTF/Fuzz_uri.txt` | ~220 |
| CTF 参数 Fuzz | `Web/CTF/Fuzz_param.txt` | ~44 |
| CTF SQL Fuzz | `Web/CTF/Fuzz_sql.txt` | ~94 |
| 后台路径 | `Web/Directory/Fuzz_admin_dir.txt` | — |
| API 路径 | `Web/Directory/Fuzz_api.txt` | — |
| 备份文件 | `Web/File_Backup/` | — |
| 密码 Top100 | `Auth/password/top100.txt` | — |
| DNS 子域名 | `Web/dns/` | — |

### 决策树：该用哪个字典？

```
目标是 Web 应用？
├── CTF/靶场 → Web/CTF/Fuzz_uri.txt（小而精）
├── PHP 站 → Web/Directory/php/Fuzz_php.txt（全面）
├── 通用站 → Web/Directory/Fuzz_common.txt
├── 找后台 → Web/Directory/Fuzz_admin_dir.txt
├── 找 API → Web/Directory/Fuzz_api.txt
└── 找备份 → Web/File_Backup/

目标是认证服务？
├── 密码爆破 → Auth/password/top100.txt
├── 用户名枚举 → Auth/username/
└── 特定服务 → Port/{mysql,ssh,rdp,...}/
```

## 📁 Payload 库 — 漏洞验证 payload

### 工具链
```bash
# 查看 aboutsecurity 字典库分类
ls /pentest/AboutSecurity/Dic/
# 查看 nuclei 模板库
ls ~/nuclei-templates/
# 读取具体 payload 文件
cat /pentest/AboutSecurity/Dic/SQL-Inj/bypass-waf.txt
```

### 可用分类
SQL-Inj | XSS | LFI | SSRF | XXE | RCE | 403 绕过 | upload | CORS | HPP | SSI

## ⚠️ 使用外部工具的正确流程

```
❌ 错误：ffuf -u http://target/FUZZ -w /usr/share/wordlists/common.txt
                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                        猜测路径，大概率不存在

✅ 正确：
1. ls /pentest/AboutSecurity/Dic/Web/Directory/  → 确认字典存在
2. ffuf -u http://target/FUZZ -w /pentest/AboutSecurity/Dic/Web/Directory/Fuzz_common.txt
```

## 💡 高效使用提示

1. **spray / ffuf 已封装字典** — 如果只是简单目录爆破，直接用 `spray -u target -d wordlist.txt` 或 `ffuf -u target/FUZZ -w wordlist.txt`
2. **自定义参数用 ffuf** — 需要自定义参数（如 -e .bak -mc 200）时用 `ffuf -u target/FUZZ -w /pentest/AboutSecurity/Dic/...`
3. **CTF 场景优先用小字典** — Web/CTF/ 下的字典精简且针对性强，避免大字典浪费时间
