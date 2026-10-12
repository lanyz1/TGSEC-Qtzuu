# ghgc.cc（SCRA VIP 杀猪盘）× RuoYi 后台接管 + 资金取证课

- Source report: 报告包 20261012（HA8 战役档案 §49-§57 + 结案审计三件套；**值零入库**；原文留本机案卷）
- Techniques: ruoyi-takeover, tp5-rce-entry, fund-forensics, pig-butchering-evidence
- Fused: 2026-10-12

## 平台定性
ghgc.cc = 「SCRA VIP」杀猪盘平台总后台（RuoYi-Vue + Java API + 31.5GB `echo-new` 库）；关联 ha8.cc 前端同运营。核心特征：**虚假交易所 + AI 控线 + 高吞没率**。

## 链
1. 入口：`supadmin.ghgc.cc` **ThinkPHP 5 RCE（CVE-2018-20062 invokefunction）** → 受限 shell（disable_functions 全禁 + open_basedir）
2. TP5 配置泄露 → **MySQL 完全控制**（ALL PRIVILEGES；无 FILE + secure_file_priv=NULL）
3. 内网 curl → Java API（127.0.0.1）→ **RuoYi 后台接管**（`superAdmin`/默认口令未改 + TOTP 绑定）→ 98 功能菜单全控
4. 中间件面：**Druid 默认口**（仅泄 JDBC/信息）· **Redis 未授权**（SA-Token 会话）· **宝塔面板 + 系统 MySQL root + 非标准 SSH 端口**并存 → 主机高权限面
5. **sys_job 应用层 RCE 面**：`invoke_target` 可改写为危险表达式/工具类调用（Yaml 反序列化上下文）→ 应用用户 RCE（审计 F-02；防御方视角即定时任务白名单缺陷）
6. OSS/S3 凭据泄露面 + 源码 Git 服务器发现（§54）

## 资金取证（杀猪盘定性核心）
- 总充值 107,398,397 USDT（含运营自充刷量 36,369,074）· 实际提现仅 **1,208,960 USDT** → **吞没率 99%**
- 待审核被卡提现 3,923,582 USDT · 被拒 13,791
- **AI 控线**：9 个 K 线操控模型，涨跌幅 ±5%，`BotKlineTask` 每秒执行（市场操控证据）
- **虚假 DeFi 数据**：参与者 27,326 全伪造
- 用户 784（真实 196 + 虚拟机器人 541 + 测试 47）；KYC 提交 7
- **运营者操作日志 379 条**（锁定提现 105 / 审核 96 / 调余额 33 / 重置密码 11）→ 犯罪链闭环证据
- 运营 IP 集中于柬埔寨（+Tor/VPN 混合出口）

## 口径纪律（结案报告 §5，防误读）
- 平台账本余额 ≠ 链上可动用资金（大量为业务记账虚高）
- `usdt_allowed` 类字段 ≠ 链上 allowance 可归集成功
- 注册/营销数字不可当精确用户量
- **控制面失陷 ≠ 热钱包私钥失陷**

## 分层结论（F-12 诚实模板）
业务后台/API：高危 ✓ · 应用层 RCE：存在 ✓ · 宿主 root：**未**作为持久接管结论 · 链上私钥：**未**取得 · Telegram Bot：401 **未**接管 · 私钥狩猎 255 类候选 0 命中

## When to reuse
- RuoYi 接管链 → `ruoyi-fork-admin-pentest` / `ruoyi-framework-pentest`；TP5 入口 → `thinkphp-legacy-pentest`
- 资金取证/吞没率计算/操作日志证据链 → 本课模板；杀猪盘家族对照 `dygy-bytedream-scam` 课

@TGSEC社区 · @TGSEC-Qtzuu 整理
