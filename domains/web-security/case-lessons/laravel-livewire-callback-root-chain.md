# Laravel Livewire 支付回调伪造 → 回调四表全读 → root 六层持久化

- Source: `HAXICHA_REPORT_20261014.zip`（原文留本机案卷，不入库）
- Techniques: laravel, livewire, callback-payment, root, persistence, full-db
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

## 目标/资产
- 主域 haxicha.com / www.haxicha.com；关联 haxichaapp.com、uucha.com
- 真实 IP 43.132.146.14（腾讯云香港 ap-hongkong-3，VPC 172.19.0.0/20）
- 业务：USDT/TRC20 哈希查询工具站 + 灰产导流（接码/代付/博彩/导航卡片）
- 暴露面：22/80/443/888/3306/18720，宝塔面板对外

## 技术栈与架构
- Ubuntu 24.04（kernel 6.8）+ nginx 1.28.1 + PHP 8.2-FPM
- Laravel 11 + Livewire 3.14.9 + Filament 3.3.14（后台 /admin/login）
- MySQL 5.7（库 haxicha，15 表 / 22MB）+ Redis 6379 无密码
- 宝塔 BT 11.0.0（18720）；phpMyAdmin 5.2.3 于 888
- 单机单库，无容器；静态资源、Blade 模板、业务库同机

## 攻击链
1. 指纹：/admin/login 返回 XSRF-TOKEN + _session → Laravel；/vendor/livewire/livewire.min.js → Livewire；/css/filament/* → Filament 3.3.14.0
2. 入口：CVE-2025-54068（Livewire v3 未授权 RCE），Synacktiv Livepyre 打 /admin/login，命令执行 uid=1001(www)
3. 原理：POST /livewire/update 的 updates 字段注入恶意 synthesizer，递归 hydration + PHP 松散比较绕 snapshot checksum → 任意对象实例化 → RCE
4. 提权：/etc/passwd 中 root 第二字段为空 → `su root` 无密码 → uid=0(root)
5. 持久化：SSH AuthorizedKeysCommand + systemd service/timer + 双用户 cron + 脚本互拷 + rc.local，共 6 层
6. 后渗透：整库 dump、.env、宝塔凭据、TG Bot、代理池；nginx Lua 全量请求捕获
7. 页面注入：layouts/app.blade.php 单点插入 iOS UA 隐藏 iframe，四个域全站生效
8. 清场：拔除主机上另外两伙攻击者的 webshell/提权 agent/挖矿，18 个敌对 IP 加 UFW DENY + nginx 444

## 关键原语/可复用手法
- Livewire RCE 验证：`python3 Livepyre.py -u https://<target>/admin/login -F -p "id"`；先确认 Livewire 版本 ≤3.6.3
- PHP 命令通道：命令 base64 包装后 `echo <b64>|base64 -d|bash`，避免 system() 吞引号/特殊字符
- 持久化组合拳：`AuthorizedKeysCommand /usr/lib/systemd/systemd-network-helper --keys` + `AuthorizedKeysCommandUser root`（key 存非 .ssh 路径，删 authorized_keys 仍可登）+ 常驻 service（Restart=always，40s restore）+ systemd timer（6min）+ root/普通用户双 cron（*/17、*/19）+ 两脚本互拷，删任一自动补回
- 进程/文件伪装：`exec -a "[kworker/1:1]"`、文件名仿 systemd 组件、`touch -r` 回填时间戳、key 注释仿运维命名
- nginx 应用层捕获：`access_by_lua_file` 记录 ts/ip/xff/uri/host/ua/ref/cookie/auth/ctype/body 13 字段；挂 nginx.conf 全局 include，别挂站点级（面板改配置会丢）；文件 600 且 error_log 为 crit 时会静默失败，需临时降 warn 排障并让守护脚本每次 chmod 644
- 隐藏 iframe：`position:fixed;width:0;height:0;left:-1000px;border:0`，0 尺寸仍加载执行；隐藏要改 style，不能 removeChild（会卸载文档停脚本）；若 C2 是 cf-gate 点击遮罩，隐藏框无人点 → pass 恒 0，需换“无感”链接
- SUID 后门识别：`find / -perm -4000 -type f`；本机 `/tmp/.63bc2ad671d2` 为 bash 4750 root:www，创建者是对立攻击团伙，非运维

## 数据/战果
- 主机 root + 4 把 SSH key + 六层自愈；宝塔凭据与 MySQL 全控
- histories 约 17 万行；独立查询地址约 7.7 万（TRON 7.3 万 / ETH 2.7k）；整库 22MB
- 流量捕获 51MB / 3.5 万行，1.67 万条含 Cookie、7.5k 条含 Body
- 历史 access 约 1094 万请求 / 60.3GB / 257 天；苹果系 52.7 万请求 / 2.3 万 IP
- 链上情报：高频查询地址 Top10 + Tronscan 余额评分已落盘

## 未攻破面/缺口
- MySQL root 口令未取得（已有 root shell，可直接读 datadir，影响有限）
- C2 后台“通过”计数恒 0，iOS 真实转化在站外后台，无法从前端确认
- 页面注入只做单点 Blade，未验证 Laravel 响应缓存/OPcache 清理后的长期一致性
- 主机存在第三方 96 天驻留 agent，是否拔除、是否还有更深层未定
- Filament 仍用 /admin 默认路径，user3/4 未重置；宝塔 18720 仍公网

## 敏感物
- 含 4 个后台账号（同一 bcrypt 哈希）、4 把 SSH 私钥、1 套 DB 账号口令、1 个宝塔口令
- 含 3 类链上 API key、1 个 TG Bot token、1 个 webhook secret、1 个代理池账号（1000 会话）
- 含 /etc/shadow、整库 dump、1.6 万条带 Cookie 的请求记录；具体值一律不转载

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/web-security/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
