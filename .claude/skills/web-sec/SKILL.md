---
name: web-sec
description: "Use for web EXP/VUL SQLi XSS SSRF playbooks."
version: 1.0.0
---

> **路径说明（全 AI）：** 知识正文在包根 `domains/`；配合 `ROUTING.md` / `MASTER.md` / `START.md`。Windows 请优先用 `domains/`，勿依赖 Linux 专用绝对路径。


# WEB安全手册 (local) — /root/web-sec

WEB安全手册 (ReAbout/web-sec). 2.9MB, 81 files. Three-layer structure: exp(vuln exploitation) + vul(principles) + penetration(流程).

## Content

| Layer | Path | Files | Description |
|---|---|---|---|
| **Exploitation** | `exp/` | 38 | XSS, CSRF, SSRF, SQLi, SSTI, XXE, 文件上传, 反序列化(Java/PHP/Python), 命令注入, JWT, IDOR, NoSQL, CRLF, CORS, OGNL, SPEL, EL, 原型链, DNS Rebinding, XPath, 请求走私, 信息泄露, 文件读取, 逻辑漏洞, Java绕过, MSSQL, Redis, nodejs-proto... |
| **Principles** | `vul/` | 5 | Auth-Session, Backend, CrossDomain(CSP/SOP), Crypto, Logic |
| **Penetration** | `penetration/` | 21 | GetHash(Linux/Windows), BloodHound, Kerberos, Linux-LPE, ReShell, MSF, Cloud, SSH, Webshell, WiFi, Openwrt, 痕迹清理(Win/Linux), 提权, 扫描器... |
| **AI-WIKI** | `AI-WIKI.md` | 1 | 主题映射+别名+检索关键词+推荐输出结构, 专为AI检索设计 |

## AI-WIKI主题映射(38个主题)

XSS → EXP-XSS · CSRF → EXP-CSRF · SSRF → EXP-SSRF · SQLi → EXP-SQLi-MySQL · SSTI → EXP-SSTI-ALL · 命令执行 → EXP-CI-* · XXE → EXP-XXE · 文件上传 → EXP-Upload · 反序列化 → EXP-Java/PHP/Python-Unserialize · JWT → EXP-JWT · IDOR → EXP-IDOR · 原型链 → EXP-nodejs-proto · NoSQL → EXP-NoSQL · CRLF → EXP-CRLF · CORS → EXP-CORS · OGNL → EXP-OGNL-Injection · SPEL → EXP-SPEL-Injection · EL → EXP-Expression-Injection · DNS Rebinding → EXP-DNS-Rebinding · XPath → EXP-XPath · 请求走私 → EXP-Request-Smuggling · 文件读取 → EXP-FileRead · 信息泄露 → EXP-InfoLeak · 逻辑漏洞 → EXP-Logic · 表达式注入 → EXP-Expression-Injection · 更多...

## Usage

```
# AI-WIKI entry (recommended first)
read_file(/root/web-sec/AI-WIKI.md)

# Load exploitation doc
read_file(/root/web-sec/exp/EXP-<topic>.md)

# Load penetration doc
read_file(/root/web-sec/penetration/PEN-<topic>.md)
```

## Notes

- Three-layer: principles(vul/) → exploitation(exp/) → penetration流程(penetration/)
- AI-WIKI.md has topic mapping, aliases, search keywords, recommended output structure
- Covers PHP/Java/Python/Node.js/Go stacks
- Good for quick reference during engagements
