# vuln-search

SKILL 技能 —— 漏洞搜索与利用研究。

## 这是什么

漏洞搜索技能包。加载后，AI 可以自动搜索 CVE 漏洞、查找 exploit、研究提权路径。

集成了四个数据源：

| 数据源 | 本地索引 | 搜索方式 |
|--------|----------|----------|
| NVD | 无（API 实时查询） | `NVD-CLI/main.py` |
| Exploit-DB | `files_exploits.csv` | `rg` 全文搜索 |
| CISA-KEV | `known_exploited_vulnerabilities.json` | `rg` 全文搜索 |
| Vulners | API 文档 | REST API |

## 安装

让 AI 帮你装

## 人类看这里：API Key 配置

三个数据源需要 API Key：

- **NVD**: `NVD-CLI/config.toml`中的`api_key`（可选，提升限流额度）
- **Vulners**: `Vulners API Docs/apikey.toml`中的`api_key`
- **Github**：`Github API\config.toml`中的`token`（可选，提升限流额度）

## 数据更新

索引需要定期更新以保持数据新鲜：

```bash
cd CISA-KEV && update.bat
cd Exploit-DB && update_files_exploits.csv.bat
```

## 许可

MIT
