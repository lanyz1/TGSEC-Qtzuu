# 支付/收款配置面（Crown Surface）

业务里「改收款地址 / 支付方式 / 结算 QR」= **真实资金影响面**，常比拿 shell 更贴近交付目标。

文档中地址一律用占位符 **`CROWN_TRC20` / `CROWN_ABA`**；实战只用授权书指定值。

## 与 Anti-Logic

- **A1**：不夺权，先测支付写接口、settings  
- **QR upload**：改图有时比改字符串字段松（用户扫码不读 TRC20 文本）  
- **ABA/多通道**：一条通道严、一条松  
- 正逻辑拿 token 后：在 scope 内验证 Crown 变更是否生效  

```bash
# 示意：汇合后的高权验证（地址来自 scope）
# ./run.sh admin-takeover --token '<JWT>' --crown-trc20 'CROWN_TRC20_FROM_SCOPE'
```

## 检查清单（授权范围内）

- [ ] `PUT/PATCH` payment-methods、settings、settle-address 是否鉴权  
- [ ] user 角色能否写 admin 支付配置（BFLA）  
- [ ] QR 图片上传与地址字符串校验是否不一致  
- [ ] 回调/通知是否在改密后告警  
- [ ] 无 auth 或 setup 阶段是否可写支付配置  
- [ ] 前端展示地址与服务端结算地址是否双源  

## 修复

写支付配置 = 高敏：强鉴权 + MFA + 审计日志 + 双人复核（视业务）；QR 与字符串同一数据源；禁止安装向导残留无 auth。

相关：`redteam-framework/anti-logic-layout.md` · `auth-security/session-crypto-identity-layer.md`



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
