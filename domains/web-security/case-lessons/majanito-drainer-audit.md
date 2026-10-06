# Drainer 犯罪集群审计要点 (Majanito 案 — 只读反制审计)

**目标**: 犯罪集群 4 服务器 16 域名 (DEX 克隆钓鱼 + Privnote MITM + Minecraft 木马 + drainer 面板)

## 技术要点
- **Privnote 路径遍历**: `/api/note/....//....//etc/passwd` — `....//` 归一化绕过 (过滤单 `../` 却漏掉剥离一层后的残留)
- **Drainer 引擎架构** (427KB 源码, nginx 暴露 src/): check→approve→scanner→executor→sweep 五段式; 与合约伪函数映射
- `/config.php` 未授权泄 client_api_key → 越权读写 8/12 端点 (可向 Permit 执行队列注入)
- 前端 311KB bundle: Spender 合约 + WalletConnect ProjectID; 代理凭证/TG Bot Token 硬编码
- **SELFDESTRUCT 证据风险**: 合约含 10 个 SELFDESTRUCT → 审计第一步先固化字节码/storage (防链上证据销毁)
## 归因产出 (方法参考)
- 5 人身份 + 22 链上地址 + 15 条传票路径
- 记录"攻不动的面"同样有价值: SSH 仅公钥 / PHP 无注入 / 多向量全失败 = 无 RCE 路径结论
