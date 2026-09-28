# vuln-search-skill — 漏洞搜索与利用研究工具箱

- **来源:** https://github.com/ming-14/vuln-search-skill
- **性质:** AI 漏洞搜索 skill（NVD CLI + Exploit-DB + CISA-KEV + Vulners + GitHub 五源联合）

## 内容

| 组件 | 说明 | 数量 |
|------|------|------|
| **SKILL.md** | 方法论（多轮搜索策略、关键词清单、经验教训、代码审查门控） | 1 |
| **NVD-CLI** | Python CLI（NVD API 客户端，支持关键词/CWE/日期/KEV/severity 交叉搜索） | 4477 行 |
| **CISA-KEV** | 已知被利用漏洞离线索引 | 1631 条 |
| **Exploit-DB** | exploit 索引 + shellcode 索引（CSV） | 47090 + 1067 |
| **Vulners API Docs** | 中英文 API 文档 | 12 篇 |

## 用法

```bash
# NVD 搜索
python3 vuln-search/NVD-CLI/main.py cve search -k "linux" -k "kernel" --severity-v3 HIGH
python3 vuln-search/NVD-CLI/main.py cve get CVE-2026-31431 -o json

# Exploit-DB 离线搜索（rg）
rg -i "dirty.*pipe|nf_tables" vuln-search-skill/files_exploits.csv

# CISA-KEV 搜索
rg -i "CVE-2026-31431" vuln-search-skill/known_exploited_vulnerabilities.json
```

SKIP: `rg.exe`（Windows 二进制）、`.bat` 更新脚本

@TGSEC社区 · @TGSEC-Qtzuu 整理
