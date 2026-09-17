# snddapp/sundapp 钱包管理端审计

- Source report: `AUDIT_REPORT_admin_snddapp_2026-09-11.md`
- Full report: `domains/business-logic/case-reports/snddapp-admin-audit/AUDIT_REPORT_admin_snddapp_2026-09-11.md`
- Techniques: wallet, payment, auth
- Fused: 2026-09-17

## Key findings (distilled)

- 鉴权: Admin JWT HS256 `type=user`；Customer JWT HS512 `type=customer`
- `admin` / `bin@qq.com` 不是弱口令字典里的常见值
- 成功拿 `jwt`（HS512, type=customer）
- 本地已存: `CUST_JWT_0x7EB9a9.txt`, `CUST_JWT_COLL_FULL.txt`, 以及多个 whale JWT
- 代理弱口令 + 2FA secret 持久化**（IR 重置后仍可登录一批）
- MinIO / 对象存储写探针**（本地大量 webshell 探针残留，未形成稳定主机 RCE）
- 超管密码 / JWT HS secret 轮换** → 旧 token `invalid signature`
- Food: `foodadmin`/`foodapi` @ `169.58.78.26`；`test:test`、`food:123456`；独立 JWT

## Repro snippets

```
POST /api/customer-auth/login
{"address":"0x…|T…","network":"ETH|BSC|TRX"}
/root/sundapp/
├── STATUS.md / STATS_NOW.json          # 作战态
├── CRITICAL_KEYS.json                  # 全局 ETH auth + MZR888
├── PLAIN_PRIVKEYS_ALL.json             # 1491 plains
├── KP_350_ETH.json / KP_A3B8_BSC.json  # auth KP（含 plain）
├── CREATE_EMP.json / CREATE_SUPERISH.json  # AES dual-KP 材料
├── PROXY.txt                           # bitip + ipyser
├── *_2FA_SECRET.txt                    # 24 个
├── LOGIN_HIT_*.json / CUST_JWT_*.txt
├── CUSTOMERS_ALL.json / GGA775_CUSTOMERS.json
├── admin_chu
```

## When to reuse

- 同类标签命中：wallet, payment, auth
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
