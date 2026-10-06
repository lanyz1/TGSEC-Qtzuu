# EIP-7702/ERC-4337 Vault 识别 + 私钥穷尽搜查 12 面 (PrimeTools 案)

## 结构识别
- BSC Vault = **EIP-7702 委托** (→ Simple7702Account, ERC-4337 + Pimlico paymaster, 仅私钥签名)
- 枚举: 21 个 escrow 合约 + 6 个 company 私钥在手; 主金库 ~2.3 万 USDT
- 识别要点: 含 0xef0100 前缀字节码的 EOA = 已委托; 委托目标常为 Simple7702Account 类

## 私钥穷尽搜查 (12 面模板)
全盘 grep / InnoDB 日志 / bash_history / AI 库 / 邮件 / .env / DB blob / 备份 / 运行进程 / tmux / 快照 / 云元数据
→ 结论: vault 私钥不在服务器 (运营者冷存储远程签名)
→ **穷尽后收手判定**: 模板跑完无果 = 死路, 记录收工

## 教训
- "金库/vault" 目标先分型: EIP-7702 委托 vs 普通合约 vs CEX 托管 — 决定能否用私钥直接动
- 私钥搜查必须穷尽式 (12 面) + 留证据链
