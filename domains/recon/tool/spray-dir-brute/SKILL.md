---
name: spray-dir-brute
description: "使用 spray 进行高性能目录爆破和指纹识别。当需要对 Web 目标进行目录/文件枚举、备份文件发现、指纹识别时使用。spray 是 chainreactors 出品的下一代目录爆破工具，性能超过 ffuf 50%+，支持智能过滤、掩码字典、断点续传、批量目标。任何涉及目录爆破、路径枚举、备份文件扫描、Web 指纹识别的场景都应考虑此技能"
metadata:
  tags: "spray,directory,brute,fuzz,目录爆破,路径枚举,备份文件,指纹识别,chainreactors,web扫描"
  category: "tool"
---

# spray 目录爆破方法论

spray 是 chainreactors 开发的高性能目录爆破工具，核心优势：**智能过滤**（自动识别无效响应）+ **极致性能**（多目标场景下远超 ffuf）+ **指纹识别**（集成 gogo/fingerprinthub/wappalyzer 指纹库）。

项目地址：https://github.com/chainreactors/spray

## Phase 1: 基本目录爆破

```bash
# 从字典爆破（最常用）
spray -u http://target -d wordlist.txt

# 多字典组合
spray -u http://target -d wordlist1.txt -d wordlist2.txt

# 指定后缀
spray -u http://target -d wordlist.txt --suffix .php,.jsp,.asp

# 批量目标
spray -l urls.txt -d wordlist.txt
```

### 常用字典路径（/pentest 目录）

```bash
# aboutsecurity 字典库
/pentest/AboutSecurity/Dic/Web/Directory/Fuzz_common.txt
/pentest/AboutSecurity/Dic/Web/Directory/Fuzz_php.txt
/pentest/AboutSecurity/Dic/Web/CTF/Fuzz_param.txt

# spray 自带字典会自动加载
```

## Phase 2: 掩码字典生成

spray 支持类似 hashcat 的掩码语法，无需预生成字典：

```bash
# 掩码: ?l=小写 ?u=大写 ?d=数字 ?s=特殊字符
# 爆破 /backup_XXXX.zip（4 位数字）
spray -u http://target -w "/backup_{?d#4}.zip"

# 爆破 /api/v1 到 /api/v9
spray -u http://target -w "/api/v{?d#1}"

# 组合路径
spray -u http://target -w "/{?l#3}/{?l#4}.php"
```

## Phase 3: 智能过滤

spray 的核心优势——自动过滤无效响应，减少人工筛选：

```bash
# 智能过滤（自动检测 404 页面特征并过滤）
spray -u http://target -d wordlist.txt --smart

# 按状态码过滤
spray -u http://target -d wordlist.txt --match-status 200,301,302,403

# 按响应长度过滤（排除统一错误页面）
spray -u http://target -d wordlist.txt --filter-length 1234

# 按关键词过滤
spray -u http://target -d wordlist.txt --match-string "admin"
```

## Phase 4: 指纹识别模式

spray 集成了 gogo、fingerprinthub、wappalyzer 三大指纹库：

```bash
# check-only 模式：只做指纹识别（类似 httpx）
spray -l urls.txt --check-only

# 启用拓展指纹（主动探测 + 第三方指纹库）
spray -u http://target --finger

# 爆破 + 指纹识别
spray -u http://target -d wordlist.txt --finger
```

## Phase 5: 备份文件和常见文件

```bash
# 扫描备份文件（.bak, .zip, .tar.gz, .sql 等）
spray -u http://target --bak

# 扫描常见通用文件（robots.txt, .git, .env 等）
spray -u http://target --common

# 全功能扫描（爆破 + 备份 + 常见文件 + 爬虫 + 指纹）
spray -u http://target -a
```

## Phase 6: 高级用法

```bash
# 启用爬虫（从页面中提取更多路径）
spray -u http://target --crawl

# 断点续传（中断后继续）
spray --resume stat.json

# 自定义 Header
spray -u http://target -d wordlist.txt -H "Cookie: session=xxx"

# 使用代理
spray -u http://target -d wordlist.txt --proxy http://127.0.0.1:8080

# 控制并发
spray -u http://target -d wordlist.txt -t 50
```

## 与 ffuf 对比决策

| 场景 | 推荐工具 | 原因 |
|------|---------|------|
| 单目标目录爆破 | spray 或 ffuf 均可 | 性能差异不大 |
| 批量多目标 | **spray** | 批量性能远超 ffuf |
| 参数 Fuzz | **ffuf** | FUZZ 占位符更灵活 |
| 备份文件扫描 | **spray** | `--bak` 一键扫描 |
| 指纹识别 | **spray** | 内置三大指纹库 |
| 需要掩码字典 | **spray** | 内置掩码生成 |
