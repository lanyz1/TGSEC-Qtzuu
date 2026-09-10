# ControlIntent 防御闭环（验证→控制意图→审批→灰度→复测）

> 定位：不替换 SIEM/EDR/NDR/WAF/FW/IAM/SOAR，而是作为验证与控制意图层。  
> **禁止**把本文写成生产 WAF/EDR 绕过手册；对抗验证见控制有效性，不提供可复用规避步骤。

## 七步

1. **攻击验证** → confirmed/tentative/deprecated 事实 + 路径 + 证据  
2. **控制对齐** → covered / partial / missing / conflict / unknown  
3. **生成 ControlIntent**（厂商无关）  
4. **冲突检查与模拟**  
5. **Workflow / HITL 审批**（生产变更绝不由通用 Agent 直执）  
6. **灰度观察** shadow → canary，限定资产/用户/应用/网段  
7. **复测闭环** → 原路径复测；有效转长期或 TTL 结束；无效回滚；结果写回战役状态

## ControlIntent 建议字段

`match_logic, scope, false_positive_risk, deployment_mode, ttl, rollback_condition, retest_plan, approval_required`

## 职责隔离

| 角色 | 允许 | 禁止 |
|---|---|---|
| 攻击验证 | 低风险验证、证据、缺口描述 | 生产策略下发、批量高危变更 |
| 防御建议 | 查控制、生成 Intent、冲突检查、复测计划 | 直接调设备写接口 |
| 变更执行 | 审批后的灰度/回滚/提升 | 脱离审批、扩范围 |

与 AI安全工程「响应强度 / 自动动作门禁」一致：模型可建议，策略与人审决定能否自动执行。


@TGSEC社区 · @TGSEC-Qtzuu 整理 · 2026-09-10
