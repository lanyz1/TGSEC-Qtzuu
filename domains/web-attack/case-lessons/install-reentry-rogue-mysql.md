# 装机接口重入 + Rogue MySQL 劫持写配置 (国强利民金盘案)

## 链
生产 `/install` 可重入 → 安装器连接被我方 **rogue MySQL (3307)** 接管 → 装机流程被劫持 → 注入写入 `config/database.php`

## 要点
- Payload 必须 **语法合法 + 强制求值** (否则破坏 PHP 数组 → 站点全挂)
- 后续: www 侧写马 (public/xchk.php 文件读写; upload/default/{dbq,get,sh}.php, key=z9)
- 数据: 全量用户 191,952 条 (手机/实名/余额哈希)
- 后台二级密码硬编码 (AdminAdmin.php); 宝塔安全入口/端口/口令文件全落盘

## 教训
- ThinkPHP/pear-admin 类"可重装"指纹 → 先探 /install 重入 (生产环境忘删是常见疏漏)
- Rogue MySQL 劫持装机 = 稳定的服务端配置写入通道; PHP 数组注入记"语法合法+强制求值"
