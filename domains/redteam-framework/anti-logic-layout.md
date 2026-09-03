# Anti-Logic — 逆向思维 / 反逻辑布局

原则：对手按「你会怎么走」布防；你专走「他不会想你会走」的缝。

前置：`recon/true-false-separation-recon.md`（真假分离）。  
并列：`auth-security/session-crypto-identity-layer.md`（身份层 ROI）。  
资金面：`business-logic/payment-config-crown-surface.md`。

> 授权评估/红队演练决策框架。改收款地址等动作仅在**书面授权范围**内验证；下文 `CROWN_TRC20` 为占位符。

---

## 对手心理模型 vs 反逻辑

| 他认为你会… | 实际你不走 | 反逻辑刀 |
|-------------|------------|----------|
| 死磕 admin/auth/login 爆破 | 已停或降权 | 打 **user/login 同口令** · **setup/install 无 auth** 建站窗口 |
| 先拿 admin 再改 TRC20 | 不串行死等 | **无 auth** 直接测 `PUT payment-methods` / `settings` |
| 必须伪造合法 init_data HMAC | 不硬刚 Bot Token | `telegram/register` **无 init** · **phone-only** 状态机 |
| 正面 Crown PUT | 不硬刚唯一写口 | 先 **QR upload 换图**（用户扫码不读字符串）· **ABA/其它通道** 旁路 |
| 外部黑客 JSON + Bearer 画像 | 不按 scanner 画像 | **内网 persona** · **cron UA** · **form/500** 错误面 |
| 只从 `/admin` 进 | 不单点 | `/admin/reports/*` **export** · `/chat/*` · **Socket.io** |
| 继续大规模喷洒 | 停扫射 | **慢速 support/kefu** 单发 + **decoy**（不像攻击） |

---

## 六轴反逻辑（A1–A6）

| 轴 | 名称 | 做法 |
|----|------|------|
| **A1 反目标** | 不夺权，先碰钱/配置 | 无 token 或低权测 TRC20/ABA/settings/支付方式；能写配置常比拿 shell 更近业务 |
| **A2 反路径** | 不打正门 | `register` / `setup` / `install` / `admin-users` / `reports` / `export` |
| **A3 反协议** | 非标准 init_data | 空 init · phone-only · internal `X-Forwarded-For` / 内网 persona |
| **A4 反顺序** | 先 user 链 | register → recharge/merchant → 再测 admin 越权（自批充值等） |
| **A5 反身份** | 扮客服/运维/cron | `device_id`、UA、频次像 support，不像 hacker 扫段 |
| **A6 反入口** | 非主 API 前缀 | `chat` · `socket.io` · `telegram-test` 类回调/SSRF 面 |

### 工程化（概念）

```text
# 并行跑六轴 work items（名称示意，按目标改脚本）
./run.sh anti-logic
# 或手工：每轴记录 入口 / auth 状态 / 是否可写 / 证据
```

---

## 与正逻辑 Kill Chain 的关系

```text
正逻辑 (REDTEAM_LAYOUT):  R0→Rn   身份 → 权限 → Crown
反逻辑 (ANTI-LOGIC):      A1→A6   旁门 → 业务链 → QR/SSRF/export → 仍可回 Crown
```

- **不是二选一，是并行**  
  - 正逻辑：等人/口令/token  
  - 反逻辑：扫旁门与业务缝  
- **汇合点**：任一轴拿到 **token** 或 **有效写权限**  
  → 再在授权范围内做高权验证（示意）：

```bash
# 占位：勿把真实地址写进知识库；用客户授权书指定地址
./run.sh admin-takeover --token '<JWT>' \
  --crown-trc20 'CROWN_TRC20_FROM_SCOPE' \
  --skip-reset
```

反逻辑是为了**开缝**；Crown 目标地址以 **scope/授权书** 为准，文档只用占位符。

---

## 反逻辑优先序（实战常用）

1. **A4** user 链 + 真实/异常 init_data — 商户/充值自批若存在即越权  
2. **A1** QR upload / 支付展示 — 有时改图比改字符串校验更松  
3. **A6** telegram-test / 回调 SSRF — 常需已有 token，作二次武器化  
4. **A5** decoy + support persona — 降噪声  
5. **A2** setup/install — 新部署/重装窗口期偶发无 auth  

---

## 运行检查表

- [ ] 已做真假分离，诱饵面不耗主时间  
- [ ] A1–A6 至少各探一轮并记结果  
- [ ] 正逻辑登录/爆破与反逻辑并行，不互等  
- [ ] 汇合后 Crown 验证仅用授权地址  
- [ ] 证据按轴归档，写入报告 Path  



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
