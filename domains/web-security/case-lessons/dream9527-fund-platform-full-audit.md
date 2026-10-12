# dream9527「算力中国」资金盘家族 · 全量审计闭环课

- Source report: 报告包 20261012（`AUDIT_REPORT.md` RA-2026-1007；原文留本机案卷）
- Techniques: fastadmin, totp-oracle, openim-unauth, mass-export, fund-scam
- Fused: 2026-10-12

## 链

11 品牌共库 → CDN（网宿）识别 → 后台定位（`/assets/js/backend.js` 泄露接口表）→ ddddocr 破验证码（≈100%）→ F-01 TOTP 预言机 → admin 接管 → 只读取证（10 表 **2,142,836** 条）

## 关键缺陷

- **F-01 未授权 TOTP 校验预言机**：`POST /admins.php/index/bind_google_auth` 无会话可达；响应差分（`用户不存在` vs `谷歌验证码错误`）= user_id 存在性 + TOTP 校验器；无锁定无限速
- **枚举基线（本课新增数字）**：32 线程 keep-alive **330 req/s** → 第 **337,631** 次命中（≈50 分钟窗口，63–95% 概率口径）
- **F-02 静态码重放**：命中码跨分钟窗仍通过（未按 RFC 6238 步进）→ 一次命中 = 永久免密凭据
- **F-03 密钥明文回显**：未绑定态 `code=-10001` 回显 secret+二维码 → 7 名管理员 TOTP 密钥全泄
- **F-04 OpenIM 万能码**：`:10008/account/login` 手机号+固定码免密登录 → 群/私聊全读

## 规模基线

- 会员 40,974 行（去重手机号 40,901）· 流水 846,253 笔 · 提现 4,530 笔 · 红包 828,533
- 传销层级四层还原：349 队 / 40,536 人 / 34 团队长（IM 名册 + 昵称邀请码替代 `p_tree`）

## 判穷负证据（该层穷尽即停）

上传双校验 / SQLi 全阻断 / IDOR 六参数名全忽略 / TP RCE 全 404 / lang 读取已补丁 / SSH 仅公钥 / DB 仅本机+需认证 / 70 敏感路径全 404 → **未得 root 与 DB 主机，停手正确**（同族勿恋战）

## When to reuse

- FastAdmin 家族同形态直走 `pentest-execution/references/fastadmin-2fa-oracle.md` + `openim-mass-enum.md`（方法层已在库，不重复建卡）
- 团队层级还原：`fake-mining-ledger-pentest/references/im-team-hierarchy.md`

@TGSEC社区 · @TGSEC-Qtzuu 整理
