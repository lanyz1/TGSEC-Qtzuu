---
source: test008008008008-glitch/web-security-skills
skill: 11-jwt-attacks
fused: 2026-09-17
method: 五步猎洞法
---

---
name: jwt-attacks
description: JWT 攻击实战手册。当目标使用 JWT 做认证（Bearer 头/Authorization）时使用，覆盖结构解析、算法混淆、密钥注入、伪造与 jwk/jku 注入。
---

# 第十一技 · JWT —— 三段点号里的信任游戏

> 猎手视角：JWT 的设计哲学是"签名即法律"。但签名的"算法"和"密钥"这两样东西，恰恰是最容易出错的配置——你要找的，就是那个签名者自己都没想到的漏洞。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：了解 JWT 结构（header.payload.signature）、base64url、常见签名算法差异

---

## 何时启用本技

- 请求头 `Authorization: Bearer eyJ...`
- 会话/Cookie 里存 JWT
- 单点登录（OIDC）、API 网关鉴权
- 看到报错泄露算法信息（`alg` 相关错误）

---

## 一、原理拆解

```
eyJhbGciOiJIUzI1NiJ9 . eyJ1c2VyIjoiYWRtaW4ifQ . SflKxwRJSMeKKF2QT4f...
└── header(算法声明)     └── payload(身份声明)      └── 签名(合法性证明)
```

它信任的三个声明，也是攻击的三个抓手：

1. **alg**：算法由 token 自己声明——"你说是啥算法我就用啥验"
2. **签名密钥**：弱密钥可爆破
3. **验证逻辑**：`verify()` 的参数默认行为（实现漏洞重灾区）

---

## 二、五步猎洞法

### 第一步：识面 —— 解开 token 看结构

用脚本解开三段（base64url 解码 header 与 payload）：

```text
header:  {"alg":"HS256","typ":"JWT"}            ← 算法是什么
payload: {"sub":"1001","role":"user","exp":...}  ← 有哪些可伪造声明
```

记录：算法类型、有无 `kid`（密钥 ID）、有无 `jku`/`jwk`（远程密钥声明——高危特征）。

### 第二步：定点 —— 改动重放试探验证强度

无签名改动（只改 payload，原签名保留）：`role` 改 `admin`——若直接通过，验证逻辑根本没生效（最低级但常见）。再做**过期测试**：过期 token 重放，看 `exp` 是否校验。

### 第三步：验证 —— 按算法类型选攻击

**攻击 A：alg = none**

```text
header 改为 {"alg":"none"} + 签名段清空（保留尾部点号）
```

老版本库（jwt-simple 旧版、部分 Java 库）接受 none 算法直接放行。

**攻击 B：RS256 → HS256 算法混淆（经典）**

服务端用非对称（私钥签发、公钥验签）时，把 header 改成 HS256，用**服务端公钥**（可从 JWKS 端点拿到）当 HMAC 密钥签名——服务端拿公钥做 HMAC 验证，你用同一把公钥签的名自然匹配。

**攻击 C：弱 HMAC 密钥爆破**

HS256 场景 hashcat / jwt-tools 跑字典：

```text
hashcat -m 16500 jwt.txt rockyou.txt
```

爆破成功 = 任意伪造。常见命中：`secret`、`key`、项目名、公司名。

**攻击 D：kid 注入**

header 里的 `kid`（密钥选择器）被拼进 SQL 或文件路径：

```text
{"alg":"HS256","kid":"x' UNION SELECT 'aaa' -- "}     → SQL注入控制密钥
{"alg":"HS256","kid":"../../dev/null"}                → 文件路径, 用 /dev/null 的空内容当密钥
```

**攻击 E：jwk / jku 注入**（JWT 头里声明自己的公钥）

```text
{"alg":"RS256","jwk":{"kty":"RSA", ...攻击者的公钥...}}   → 部分库直接采信token内嵌公钥
{"alg":"RS256","jku":"https://<你的域>/keys.jwks"}          → 部分库拉取攻击者指定的密钥集
```

### 第四步：利用 —— 构造越权 token

验证通过后，伪造目标明确的最小化改动：`role: admin`、`sub: 1`（管理员用户）、`exp` 延长。访问一个高权限接口证明影响，**不要**漫游全站。

### 第五步：收官 —— 证据与修复

报告附：原始 token 与伪造 token 的三段对比、成功访问的高权限响应截图。修复建议按对应攻击给（见防御节）。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构后台 `admin.demo-example.com`，登录后返回 JWT

1. **识面**：解码：`{"alg":"RS256"}` + payload 含 `role: "viewer"`；有 `/.well-known/jwks.json` 公钥端点
2. **定点**：改 `role: "admin"` 保留原签名重放——401（签名校验正常）；过期 token 重放——401（exp 校验正常）
3. **验证**：测算法混淆：header 改 `HS256`，用 JWKS 端点里的公钥（PEM）做 HMAC 密钥签名——**200 通过**，验证逻辑未锁死算法
4. **利用**：用公钥签发 `role: "admin"` token，请求 `/api/user/list` 成功返回全量用户列表
5. **收官**：报告高危（认证绕过 → 管理员权限），修复：服务端固定算法 + `verify(token, pubkey, {algorithms:['RS256']})`

---

## 四、对抗与绕过

| 防线 | 破解思路 |
|------|----------|
| 锁死 RS256 | 试攻击 C（弱密钥只对 HS 有效）、D（kid 注入）、E（jwk/jku） |
| 锁死 HS256 + 强密钥 | 看密钥轮换实现、`kid` 处理逻辑 |
| 混淆后验证算法白名单 | 检查 `verify` 是否仍接受 jwk/jku 自声明密钥 |
| payload 加密（JWE） | 攻击面转向加密库实现与密钥管理 |

---

## 五、防御视角

1. **算法白名单**：验证时显式声明 `algorithms: ['RS256']`，绝不信任 token 自声明的 alg
2. HMAC 密钥强度：≥ 32 字节随机，禁止入字典的弱密钥
3. `kid` 只做索引：白名单字符集，禁止进 SQL/文件路径
4. 禁用 jwk/jku 自声明密钥，公钥只信服务端配置的 JWKS
5. 声明服务端核实：role/权限以服务端存储为准，JWT 只做身份不做授权（越权防御的另一道保险）

---

## 六、踩坑记录

- 算法混淆签名时"公钥"要用**原始 PEM 字节**（含换行）做 HMAC，不是 base64 解码后的裸模数——签不上先检查密钥格式
- `alg: none` 的 payload 结尾**点号必须保留**（空签名），少个点直接格式错
- 爆破 HS256 前**先测弱密钥 top100**：`secret`、`123456`、`jwt_secret` 命中率惊人，完整字典跑一半往往就已出结果
- 部分网关会改写 JWT（重新签名），你改的 payload 过了网关就变样——抓包确认**到达后端的原始报文**
- `exp` 校验缺失是低危，但配合**登出无效化缺失**（token 无法吊销）一起报，就是完整的会话管理缺陷

---

## 七、速查卡

```text
解码:   base64url 解 header/payload
none:   {"alg":"none"} + 空签名
混淆:   RS→HS + 公钥当HMAC密钥签名
爆破:   hashcat -m 16500 token.txt dict
kid:    SQL注入/路径穿越控制密钥
jwk/jku: token内嵌/远程密钥集声明
防御:   算法白名单 + 强密钥 + 服务端角色
```
