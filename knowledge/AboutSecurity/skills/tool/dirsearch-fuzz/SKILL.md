---
name: dirsearch-fuzz
description: "使用 dirsearch 进行 Web 目录和文件暴力枚举。当需要发现隐藏的目录、文件、后台路径、备份文件时使用。dirsearch 内置高质量字典，支持多扩展名、递归扫描、状态码过滤。任何涉及目录枚举、路径发现、后台查找、敏感文件发现的场景都应使用此技能"
metadata:
  tags: "dirsearch,directory,fuzz,目录扫描,路径枚举,后台发现,文件发现,备份文件,web"
  category: "tool"
---

# dirsearch Web 目录枚举方法论

dirsearch 是功能丰富的 Web 目录暴力枚举工具。核心优势：**内置高质量字典** + **多扩展名支持** + **递归扫描** + **智能过滤**。

项目地址：https://github.com/maurosoria/dirsearch

## Phase 1: 基本扫描

```bash
# 使用内置字典扫描
dirsearch -u http://target.com

# 指定扩展名
dirsearch -u http://target.com -e php,asp,aspx,jsp

# 指定字典
dirsearch -u http://target.com -w /path/to/wordlist.txt

# 静默输出
dirsearch -u http://target.com --quiet
```

## Phase 2: 过滤和匹配

```bash
# 排除状态码
dirsearch -u http://target.com -x 404,403,500

# 只显示特定状态码
dirsearch -u http://target.com -i 200,301,302

# 按响应大小过滤
dirsearch -u http://target.com --exclude-sizes 0B,4KB

# 按响应内容过滤
dirsearch -u http://target.com --exclude-texts "Not Found"

# 递归扫描（发现目录后继续扫描子目录）
dirsearch -u http://target.com -r --recursion-depth 3
```

## Phase 3: 高级选项

```bash
# 自定义请求头
dirsearch -u http://target.com -H "Cookie: session=abc"

# 带认证
dirsearch -u http://target.com --auth admin:password --auth-type basic

# 使用代理
dirsearch -u http://target.com --proxy http://127.0.0.1:8080

# 控制线程
dirsearch -u http://target.com -t 50

# 批量目标
dirsearch -l urls.txt -e php,asp

# 随机 User-Agent
dirsearch -u http://target.com --random-agent

# 强制扩展名（不使用 %EXT% 占位符）
dirsearch -u http://target.com -f -e php,asp
```

## Phase 4: 输出

```bash
# 简单文本
dirsearch -u http://target.com -o results.txt --format plain

# JSON 输出
dirsearch -u http://target.com -o results.json --format json

# CSV 输出
dirsearch -u http://target.com -o results.csv --format csv
```

## 常用场景速查

| 场景 | 命令 |
|------|------|
| PHP 站点 | `dirsearch -u http://target -e php -x 404` |
| Java 站点 | `dirsearch -u http://target -e jsp,do,action -x 404` |
| 后台查找 | `dirsearch -u http://target -w admin-wordlist.txt` |
| 备份文件 | `dirsearch -u http://target -e bak,old,zip,tar.gz,sql` |
| 递归深扫 | `dirsearch -u http://target -r --recursion-depth 3 -e php` |
