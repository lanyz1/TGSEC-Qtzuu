# BillionMail Docker API → 宿主机 ROOT (r4z.lol 犯罪帝国案, 2026-09-27/30)

**目标**: x99piz4c.clubhosty.com (犯罪帝国单主机: 7 USDT drainer + 6 支付平台 + 11 赌博站 + BillionMail + WHMCS)
**结果**: ROOT 完整接管

## 完整链 (可复用原语)
1. Vercel USDT 钓鱼站源码 → **JWT 硬编码密钥 (HESOYAM)** → 伪造管理员 token
2. 上传绕过: PNG 魔数 + 双扩展 `.png.php` → PHP 执行
3. **FCGI socket 未授权** (/tmp/php-cgi-84.sock) → 绕过 open_basedir 任意文件读写
4. **PostgreSQL trust 认证** (/tmp/.s.PGSQL.5432) → superuser → `COPY TO PROGRAM` RCE
5. BillionMail Docker API 未鉴权 (127.0.0.1:8080/api/docker_api/) → `outbound_ip` **SQL 注入 → $() → iptables shell 拼接** → 特权容器命令执行
6. **ExecHostCommand 逃逸**: privileged 容器 + host rootfs 挂载 → `chroot /host_root` → 写 SSH 公钥 → 宿主机 ROOT

## 关键检查面 (通用)
- 明文凭据陈列: 宝塔 default.db (SQLite) 存 MySQL root 明文; BillionMail 默认凭据; drainer .env **共享密钥** (supersecretdrainer)
- **disable_functions 绕过: putenv + LD_PRELOAD + mail()**
- 容器逃逸三件套: Docker API socket/HTTP 未鉴权 + privileged + /host_root 挂载

## 持久化矩阵 (跨层冗余)
- SSH 密钥×3 / 隐藏 uid0 用户 (sysdiag) / systemd timer 45min 自愈 / cron 30min 重植 / rc.local / 126 webshell (.health.php eval) / PG trust / 数据库后门账号

## 业务面教训
- 犯罪基础设施**单机聚合度极高**: 一台 = drainer + 支付 + 赌博 + 邮件 + 主机销售 → 拿下=全帝国
- drainer 源码 7 套 (321MB) + approve 授权模式 + BSC/TRON 双链
- 私钥 9 把余额≈0 (防守方转移快) → 链上变现窗口极短
