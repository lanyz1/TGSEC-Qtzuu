# 漏洞报告模板

> 漏洞挖掘阶段（含威胁收敛阶段的补测/绕过突破）确认存在漏洞时，按本模板撰写报告，文件名 = 报告号
> （`reports/{vuln_id}.md`），并用 `register_report.py` 登记到漏洞报告清单。
>
> **铁律**：「已验证危害」**必须附真实的原始请求/响应片段或工具调用证据**并标来源 op；
> **严禁幻觉式验证**（不得编造未真实发生的请求、响应或结论）。报告须含复现步骤 + 完整可执行 payload。
> 缺真实证据的报告，质量门禁一律拒绝。

---

# 漏洞报告 VULN-VD-URL00021-0001

## 报告元信息

- 报告ID：VULN-VD-URL00021-0001
- 标题：订单创建接口价格篡改导致 1 元购买任意商品
- 漏洞类型：业务逻辑 / 越权
- 危害等级：严重（critical）
- 关联 URLID：URL00021
- 关联威胁：THREAT0012（消账到本报告的威胁，无则可省略）

## 漏洞摘要

一句话概述：攻击者创建订单时可篡改 couponId 引用他人高额优惠券，使 payAmount 降至 1 元。

## 漏洞描述

详细说明漏洞原理、触发条件与受影响范围：服务端创建订单时未校验 couponId 与当前用户的归属关系，
且最终金额由客户端传入的 couponId 决定……

## 复现步骤

### 环境要求

- 账号：user01（买家）；目标接口：POST /api/order/create
- 安全等级 / 前置数据：……

### 完整步骤（填写要求：应尽可能按照人工操作的步骤进行，说明通过浏览器操作路径如何访问到目标接口，拦截篡改什么操作的请求等）

1. 登录 user01，抓取创建订单请求。
2. 将 couponId 改为枚举得到的他人大额券 ID 88231。
3. 发送请求，payAmount 由 299 变为 1。
4. 完成支付，订单成立。

### 完整 Payload

```http
POST /api/order/create HTTP/1.1
Host: host
Cookie: SESSION=...
Content-Type: application/json

{"skuId":1001,"count":1,"addressId":55,"couponId":88231}
```

## 危害说明（填写要求：必须是基于实际观察发现的危害，不能是纯假设或推理）

- 可 1 元购买任意标价商品，直接经济损失。
- 优惠券 ID 可枚举，影响面覆盖全部在售商品。

## 验证证据（填写要求：必须是真实的原始请求/响应片段或工具调用证据，必须可以直接观察到具体危害表现）

- **请求**：见上「完整 Payload」。
- **响应（关键片段）**：如`HTTP/1.1 200 OK` … `{"orderId":10293,"payAmount":1}`（payAmount 由 299 → 1）。
- **证据来源**：标明该请求/响应的来源，如代理日志 `proxy-logs/requests/URL00021.log` 第 N 条、
  或 playwright/ python 工具调用记录。审核据此核验证据真实性；缺原始请求/响应或工具调用证据则审核不通过。



## 修复建议

- 校验 couponId 归属当前用户且未使用。
- 金额与优惠在服务端二次核验，不接受客户端传入的最终金额。

## 参考资料

- OWASP API1:2023 Broken Object Level Authorization
- CWE-639 Authorization Bypass Through User-Controlled Key
