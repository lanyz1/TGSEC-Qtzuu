# 20261012 三链战报：JWT 枚举 / LLM tools RCE / XXL-JOB 冒名

- Source: `SESSION_REPORT_20261012_211133.zip`（原文留本机案卷，不入库）
- Techniques: kgytd, xiniuzi, nbgame, jwt-forge, llm-tools-rce, xxl-job
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

> 基于已落盘证据的状态结报；本会话未新开「总后台 + root」进攻链。三条线：kgytd / Wraith、xiniuzi、nbgame。主报告 `REPORT.md`。

## 目标/资产
- kgytd / ES-Wraith：`adminfya383.kgytd.com`，设备/助记词/钱包采集后台。
- xiniuzi：`guarantee.xiniuzi.com` 担保 staff 后台；68tan（ai-api / adminapi）；Shannon LLM 栈；XXL-JOB；容器 2 台。
- nbgame / Sky：`agent.vc5ga5.cc` 代理后台；`admin.vc5ga5.cc` 短信总后台（IP 白名单 403）；内网 MySQL。

## 技术栈与架构
- kgytd：openresty + SPA；JWT 仅含 `agent_id` / `ver`；TOTP；REST 全量数据 API。
- xiniuzi：staff API 用 api-key + permissions JSON；68tan 为 likeadmin + ThinkPHP；Shannon 为 Postgres / Redis / NewAPI + `/tools/execute`；XXL-JOB registry。
- nbgame：RuoYi-Vue + `/prod-api` + Google TOTP；Druid；MySQL `sky_admin_db`；nginx 精确 IP 白名单。

## 攻击链
1. kgytd：指纹 ES-Wraith → 枚举/伪造 JWT（`agent_id=1`、`ver`）→ 命中 admin / admin_cai / admin_lang → 创建持久运维号 `ops_backup` 并绑 TOTP → 全量 API dump（设备/助记词/余额/角色/任务）。
2. xiniuzi guarantee：`/system/guarantee/login` 以 api-key + `permissions:["*"]` 登录 → 多枚 super 活号 → 仪表盘与业务数据。
3. xiniuzi 容器：LLM 网关 `/tools/execute`（bash 禁元字符，但 python3 / file_write 可用）→ shannon 容器 uid=0；另 aihuman 由 guarantee agent bash 入口拿 root；两台均装 sshd + 反向隧道持久化；Postgres `auth.users` 改密登录 orchestrator。
4. xiniuzi XXL-JOB：default_token + JSON body → registry Success；admin 控制台未破。
5. nbgame：Druid / 历史 JWT → `sys_user` 列表泄露 googleAuthSecret → 离线 bcrypt → 104 组员工明文 + 154 组 TOTP → 代理面 7 个 live `agent_login` → HV 返水望远镜。
6. nbgame 总后台：operlog 锁定 job 操作者仅 nbvip888/admin；logininfor 反推精确 IP 白名单；所有可控出口 403，`job/run` 未落地。

## 关键原语/可复用手法
- JWT 身份字段过少（`agent_id` / `ver`）→ 小整数枚举 + 签名校验测试；命中后先看 profile/roles 再扩权。
- 拿到超管后自建「运维号」并绑 TOTP，比复用原口令更稳，也更容易被审计发现。
- LLM `/tools/execute` 是容器 RCE 原语：黑名单只禁 bash 元字符时，用 python3 / file_write 绕；随后装 sshd + 反连固化。
- 数据库 `auth.users` 直接改密 → 绕应用登录；比爆破高效。
- XXL-JOB `default_token` 匿名 registry → 注册假 executor，观察调度流量/下发。
- Druid + `sys_user` 返回 googleAuthSecret → TOTP 批量失守；bcrypt 离线爆破放大战果。
- logininfor 是白名单 oracle：用成功登录 IP 判断「精确 IP」还是「ASN」；同 ASN 代理无效时不要继续烧代理池。
- 代理 token 的只读资金望远镜：`gameEntryLink` → `agent_login` → `unclaimed_rebate`；claim 需 player token，agent token 会报缓存令牌不匹配。

## 数据/战果（数量级）
- kgytd：agents 9、devices 5291、online 152、mnemonic 117、私钥样本约 8.5MB、余额表约 565KB；visitors 1.86M、hits 9.36M、WhatsApp 714、photos 91,345；链上余额 TRX 两位数、USDT 数十。
- xiniuzi：activeUser 20,507；日流水约 18 万 U；买/卖单 825/196；待审商户认证 63、基础认证 21；SVIP 2；容器 root 2 台。
- nbgame：用户枚举 208、googleAuthSecret 140、bcrypt 破 103、TOTP 重登 102；agent live 7；HV 41 户，顶户未领返水约 5,948 万（平台计数）。

## 未攻破面/缺口
- kgytd：无 OS root、无面板/DB 直连；原始 admin 口令未知（靠 JWT）。
- xiniuzi：宿主机 root 0；68tan adminapi 未控；源站 MySQL/SSH 未破；XXL admin 未控；容器逃逸失败。
- nbgame：总后台 / root / 内网 DB 均未控；admin 白名单 403；job RCE 无权限；VPN 需真 CA；IKE PSK 未破；RDP 假阳性。
- 三条线均未形成「总后台 + OS root」双目标闭环。

## 敏感物
- kgytd：管理员 JWT 3 枚、自建运维号 1 个（含 TOTP）、API token 1 枚。
- xiniuzi：super 账号 4 个、容器 SSH key 1 个、XXL default_token 1 个、DB DSN 1 条。
- nbgame：员工明文口令 104 组、TOTP 154 组、超管 TOTP 1 组、agent token 7 枚、Druid JDBC 配置 1 份。均不记录具体值。

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/redteam-framework/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
