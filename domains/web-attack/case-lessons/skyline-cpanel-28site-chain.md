# skyline × HunterJungle · cPanel 共享主机 28 站链课

- Source report: 报告包 20261012（`skyline-渗透测试交付报告`；原文留本机案卷）
- Techniques: cpanel-shared-host, upload-rce, env-harvest, hidden-ssh, socks-pivot
- Fused: 2026-10-12

## 链（八步）

1. 侦察：skyline 与顶级域同 IP → **cPanel/WHM 共享主机**（2082/2083/2086/2087 + Webmail 2095/2096）；入口站 = 开源 FoxQR/QR Maker v2.0.1（`/includes/QrController.php`）
2. `/uploads/` 开目录列举 → 85 条目，含**他人 30 个历史 webshell**（2021-08 → 2026-06，两批独立攻击者）→ 该点长期可打
3. `POST /includes/QrController.php`（logo 字段零校验）→ **响应 500 但文件先落盘** → `/uploads/<id>.php` 直执行（uid=1013，`disable_functions`/`open_basedir` 均空）
4. RCE 读 28 站源码 → 两处 `.env` 明文 DB 凭据 + APP_KEY + **明文管理员口令**
5. `127.0.0.1:3306` 该账号 **27 库全读**；`dna.member` 6,266 会员 PII + 泰籍身份证 6,269 + 179 明文口令/银行账号
6. 明文管理员口令**实测登录**业务系统（302→/home，/profile 200）
7. 持久化：冰蝎马（AES-128-CBC，密钥 = md5(密码)[:16]）同点投递，回显验通
8. **SSH 不在 22 而在 21098**（top2000 漏扫；内部 `ss` 发现）→ 写公钥 → `ssh -N -D 1081` SOCKS5（**jailshell 只禁交互 shell，端口转发不受影响**）→ 发现外网不可见服务（WHM 2086 / cPanel 2077/2079 / Go 11234 / Memcached 11211）

## 精妙点

- **签名服务 IP 白名单含本机自身 IP**：链上签名服务用占位密钥（产品默认常量从未更换）+ 无鉴权取钥接口（eth_call 只读）→ RCE 后即从「允许来源」调用
- **埋钩纪律**：`.user.ini` 有 5 分钟缓存 → 语法错误会整站 500（先 `php -l` 校验 + base64 传源码再启用）；`.htaccess auto_prepend` 不生效 → 直插目标文件 + 完整回滚核验
- **误判修正**：`10.99.170.0/24`「220 台存活」= 透明代理层（判据：**端口分布过于一致 = 代理层**）

## 诚实卡点

root 未拿（sudo 需口令 / SUID 标准集 / jailshell）；同机其他 ~20 cPanel 账号 700 隔离有效；链上私钥不落盘（全盘+全库扫描证实由调用方传入）；WHM/cPanel 未爆破（范围外）；`10.99.170.0/24` 属第三方资产**明确未探测**
清理记录：我方 32 文件全删 + 他人 30 webshell **原样保留** + 业务可用性回归通过

## When to reuse

- cPanel 多租户整链 → `cpanel-shared-host-takeover`
- 上传判据补丁 → `file-upload-webshell`（列举+解析组合；「500 但先落盘」）
- 同族归档：`web-attack/case-lessons/cyberpanel-source-ssh-chain.md`

@TGSEC社区 · @TGSEC-Qtzuu 整理
