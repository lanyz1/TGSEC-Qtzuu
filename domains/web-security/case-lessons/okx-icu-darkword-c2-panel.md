# OKX ICU 挂马站群 C2 面板接管（注册角色注入 + Web 根可写）

- Source: `OKX_ICU_REPORT_PACK.zip`（原文留本机案卷，不入库）
- Techniques: spa, api, auth-logic, c2, site-group, hot-update
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

> 报告自述授权红队；目标为挂马入口 + iOS 木马收割面板 + 同机站群。主报告 `reports/OKX_ICU_PENTEST_REPORT.md`。

## 目标/资产
- 入口站 `www.okx.icu` / `okx.icu`；同机 `156.239.229.74`（HK）。
- 木马/C2：`ty.55555.skin`、Coruna 投递路径、`:8883` DarkSword「iOS 管理系统」。
- 同机站群：宝塔 39 站、nginx 90+ 域名（jjw00、mc163、adsbom、`*.333.autos` 等）。
- 管理面：宝塔 `:26754`、x-ui `:8000`、SSH `:22`。

## 技术栈与架构
- nginx + 宝塔面板；PHP 站群 + 文件管理；Python 业务服务由 systemd 托管。
- Docker Swarm、MySQL、Redis（本机）、x-ui 代理面板。
- DarkSword 自研面板：HTTP API + 注册/登录 + 设备/会话/钱包数据。
- 单机多站、多 vhost 共用 www 用户，站群与木马基础设施混布。

## 攻击链
1. 信息收集：DNS / 端口 / vhost / FOFA 同 IP / JS 与隐藏 iframe。
2. 入口站发现 1×1 隐藏 iframe → `ty.55555.skin/coruna/group.html`；二级 payload 长期 502，iOS 26 未打穿。
3. 同 IP 扫到 `:8883`；弱口令 viewer + `POST /api/auth/register` 传 `role=admin` → 超管。
4. 拖 users/sessions；确认是 DarkSword 收割面板，非页面内嵌 CVE。
5. 同机 mc163 后台默认口令 → 文件管理上传 PHP → uid=1000 www 任意读写（`shell_exec` 禁用，`open_basedir` 为空）。
6. 读 `/www/wwwroot`、面板密钥、DB、sshd 配置；发现 `/www/wwwroot` 对 www 可写，且多个 systemd 服务 `User=root`、ExecStart 指向站点目录。
7. rename `ty.55555.skin` → 植入 `server.py` → 重启服务 → root payload → 改 root 口令 + SUID bash → SSH root。
8. root 后：宝塔 / x-ui / 站群后台改密、批量 webshell、业务库与 exfil 库收割。

## 关键原语/可复用手法
- 注册接口角色注入：自助注册时提交 `role` / `is_admin` / `tenant` 等字段，直接造超管（先测小写、嵌套、数组形式）。
- Web 根可写 + root systemd 路径替换：`systemctl cat` 找 `User=root` 且 WorkingDirectory / ExecStart 在 `/www/wwwroot` 的服务；目录 rename + 同名 payload + restart = root RCE。
- 文件管理上传 + disable_functions 不全：即使命令执行被禁，任意文件读写仍可读配置/密钥/DB；`open_basedir` 为空时全盘可读。
- 默认口令 lateral：niche CMS / 备份站 / 旧站常保留厂商默认口令（默认后台路径 + 默认账号）；先试默认，再试弱口令。
- Redis 无密码 ≠ 可写 cron：先确认 protected-mode 下 `dir` / `dbfilename` 是否可改；不可改就换面。
- 证据分级：面板已控 / OS root / 可花费钱包三件事分开证明；链上大额地址无会话归属不得计入战果。
- 归属分析：以 exfil 会话为锚反查钱包地址与余额；只有能绑定会话的余额才算“可归属”。

## 数据/战果（数量级）
- 主机：root 实控 1 台；宝塔 39 站、nginx 90+ 域名；批量 webshell 40+ 路径。
- 面板：DarkSword 超管；宝塔 / x-ui 已改密；多站后台已控。
- 设备：现行 sessions 289（model/ios/files 多为 0，探针为主）、历史 330、phones 15；可信真机 ≈ 0。
- 钱包：现行 wallets 0；历史 crypto 48 行；可归属地址 3 个，链上余额 ≈ 0；另有链上大额地址但无会话/无私钥。
- 客户：zgl 用户 4–5 行、宿主 3 行；外部付费客户约 1–3 量级。

## 未攻破面/缺口
- iOS 26 真机利用链未证实：Coruna 二级 C2 全程 502。
- 无可花费私钥/助记词；链上大额地址无法归属。
- 宝塔 BT-0x 库密码未全解；部分 vhost webshell HTTP 未打通（301/502）。
- Redis 无法写 cron；MySQL 维护账号无 FILE，未读 shadow。

## 敏感物
- SSH root 口令 1 套；宝塔 / x-ui / 多站后台口令各 1 套；DarkSword 超管会话/API token 若干；webshell key 1 套；业务库账号若干；Fernet 密钥仅测试向量。均不记录具体值。

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/web-security/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
