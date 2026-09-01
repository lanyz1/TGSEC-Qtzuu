---
name: xray-scan
description: "使用 xray 进行 Web 漏洞自动化扫描。当需要对 Web 应用进行全面漏洞扫描（XSS/SQLi/命令注入/SSRF/XXE/路径穿越/文件上传/弱口令等）时使用。xray 是长亭科技出品的综合性 Web 安全评估工具，支持主动扫描、被动代理扫描、基础爬虫扫描三种模式，内置丰富的检测插件和社区 POC。任何涉及 xray 漏洞扫描、Web 安全评估、被动代理扫描的场景都应使用此技能"
metadata:
  tags: "xray,scan,web,vuln,漏洞扫描,安全评估,被动扫描,代理扫描,长亭,chaitin,poc"
  category: "tool"
---

# xray Web 漏洞扫描方法论

xray 是长亭科技出品的综合性 Web 安全评估工具，核心优势：**检测精度高**（语义分析引擎）+ **误报率低** + **社区 POC 丰富**。支持主动扫描、被动代理扫描、爬虫扫描三种模式。

项目地址：https://github.com/chaitin/xray

## Phase 1: 单 URL 扫描（最常用）

```bash
# 扫描单个 URL（全插件）
xray webscan --url http://target/?id=1 --html-output result.html

# 指定检测插件（节省时间）
xray webscan --url http://target/?id=1 --plugins sqldet,cmd-injection --html-output result.html

# JSON 输出（便于解析）
xray webscan --url http://target/?id=1 --json-output result.json
```

## Phase 2: 爬虫扫描（自动发现页面）

```bash
# 基础爬虫 + 漏洞扫描
xray webscan --basic-crawler http://target --html-output crawl-result.html

# 指定爬虫深度和插件
xray webscan --basic-crawler http://target --plugins xss,sqldet,cmd-injection --html-output result.html
```

## Phase 3: 被动代理扫描

适合配合浏览器手动测试，xray 自动分析经过代理的流量：

```bash
# 启动代理监听
xray webscan --listen 127.0.0.1:7777 --html-output proxy-result.html

# 然后设置浏览器/工具代理为 127.0.0.1:7777
# 所有经过代理的请求都会被自动扫描
```

## Phase 4: 检测插件速查

| 插件 Key | 检测内容 | 说明 |
|----------|---------|------|
| `xss` | XSS 漏洞 | 语义分析引擎 |
| `sqldet` | SQL 注入 | 报错/布尔/时间盲注 |
| `cmd-injection` | 命令注入/代码执行/SSTI | 多种 payload |
| `dirscan` | 目录枚举 | 备份文件、配置文件、debug 页面 |
| `path-traversal` | 路径穿越 | 多平台多编码 |
| `xxe` | XML 实体注入 | 有回显 + 反连检测 |
| `upload` | 文件上传 | 常见后端语言 |
| `brute-force` | 弱口令 | HTTP 基础认证 + 表单 |
| `jsonp` | JSONP 劫持 | 敏感信息跨域读取 |
| `ssrf` | SSRF | 常见绕过 + 反连检测 |
| `baseline` | 基线检查 | SSL 版本、HTTP 头检测 |
| `redirect` | 任意跳转 | meta/30x 跳转 |
| `crlf-injection` | CRLF 注入 | HTTP 头注入 |
| `struts` | Struts2 漏洞 | s2-016/032/045/059/061（高级版）|
| `shiro` | Shiro 反序列化 | 密钥检测（高级版）|
| `fastjson` | Fastjson 漏洞 | 系列检测（高级版）|
| `thinkphp` | ThinkPHP 漏洞 | 系列检测（高级版）|

### 按场景选择插件组合

```bash
# 快速扫描（高危优先，1-2 分钟）
xray webscan --url URL --plugins sqldet,cmd-injection,xxe,ssrf

# 全面扫描（所有插件，默认行为）
xray webscan --url URL

# Web 应用测试（聚焦 Web 漏洞）
xray webscan --url URL --plugins xss,sqldet,cmd-injection,upload,path-traversal

# Java 应用（针对性）
xray webscan --url URL --plugins struts,shiro,fastjson,sqldet
```

## Phase 5: POC 扫描

xray 内置 POC 引擎 (phantasm)，支持社区贡献的 POC：

```bash
# 使用内置 POC 扫描
xray webscan --plugins phantasm --url http://target

# 指定自定义 POC 目录
xray webscan --plugins phantasm --poc /path/to/pocs/ --url http://target
```

社区 POC 仓库：https://github.com/chaitin/xray-plugins

## 配置优化

```bash
# 生成默认配置文件
xray genca    # 生成 CA 证书（HTTPS 代理需要）

# 配置文件位置：~/.xray/config.yaml
# 常用配置项：
# - http.proxy: 设置上游代理
# - http.headers: 自定义请求头
# - plugins.xxx.enabled: 启用/禁用插件
```

## 与 nuclei 对比决策

| 场景 | 推荐工具 | 原因 |
|------|---------|------|
| 已知 CVE 验证 | **nuclei** | 模板库更全 (9000+) |
| 通用 Web 漏洞扫描 | **xray** | 语义分析，误报率更低 |
| 被动代理扫描 | **xray** | 原生支持代理模式 |
| 批量目标 PoC 检测 | **nuclei** | 批量性能更好 |
| SQL 注入深度检测 | **xray** | sqldet 引擎更精准 |
