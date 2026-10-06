# FCGI socket 0666 + sendmail_path 覆写 → 绕 disable_functions

## 条件
- unix sock `/tmp/php-cgi-72.sock` 权限 **0666** (world-writable)

## 手法
- 直连 PHP-FPM socket (cgi-fcgi) → `PHP_VALUE/PHP_ADMIN_VALUE` 覆盖 `sendmail_path` 指向自定义脚本
- 触发 `mail()` → 脚本以 php-fpm 用户执行 → www 侧 RCE
- 同机后续: **PwnKit (CVE-2021-4034, polkit-0.112 "berdav 精确布局")** → root; 落 3 个 SUID bash 持久化

## 教训
- php-fpm sock 权限检查: 0666/0777 = 直接可用 (无需其它漏洞栈)
- disable_functions 黑名单永远漏: sendmail_path / mail() / putenv+LD_PRELOAD / FFI / imap_open — 常驻检查表
