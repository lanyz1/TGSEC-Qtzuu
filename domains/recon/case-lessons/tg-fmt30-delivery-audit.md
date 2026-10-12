# TG 会话资产 FMT30 交割审计课

- Source report: 报告包 20261012（`REPORT_TG_FMT30_AUDIT.md` + summary.csv/json；原文留本机案卷）
- Techniques: tg-session, delivery-audit, sampling-extrapolation
- Fused: 2026-10-12

## 交割格式规范（FMT30）

- 目录结构：`<phone>/<phone>.json + <phone>.session` **成对**
- **登录坑（重要）**：`session_str` 字段非法 → 必须用同目录 `.session` 文件 + `jdata['app_id']/['app_hash']` 构造 TelegramClient
- 文件层校验：auth_key ≥32B、无缺文件、有 user_id/name

## 审计口径

- 文件层全量 1300/1300 通过；twoFA 字段 72、premium 29
- **活体抽检外推法**：n=55 → OK 率 60% → 外推 ~780（95% 粗区间 612–948）；最终在用库存须全量活检
- **存活率与 app_id 相关**：app_id=2040 样本几乎全活；app_id=8 失效率高（过期/踢下线，非文件坏）→ 选号/验活策略素材
- **禁混算口径表**：MQTT 池（仅 ID，不可登）/ clonebots 用户画像（无 session）/ 社媒库 —— 不得计入交割数
- 交割前全量活检 → `alive_phones.txt`；**活体 ≠ 未被挤号**；自动化先读 twoFA 字段

## 诚实卡点

- 未做全量活检/挤号/2FA 挑战/挂机稳定性；780 为抽检外推

## When to reuse

- 会话资产收管/验活 → `tg-account-library`；成功口径 = 可登录 session 而非手机号 → `tg-cloud-panel`；session_string 解密 → `fernet-session-decrypt`

@TGSEC社区 · @TGSEC-Qtzuu 整理
