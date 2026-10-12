# LuckyPool.IO 矿池团伙 · 侦察与打击课

- Source report: 报告包 20261012（`loot_inventory.md` 战报；原文留本机案卷）
- Techniques: mining-pool, nomp/unomp, unauth-api, infra-mapping, fofa-recon
- Fused: 2026-10-12

## Key findings (distilled)

- 入口 185.165.171.21:8888 定性 = 团伙手搓 OOB 回连接收器（`oob2 up` / `oob listener up`，Python BaseHTTP）；归属 FlokiNET（罗马尼亚，防弹主机）
- 真身 = 「AI 算力服务」伪装的跨国矿池运营团伙，19+ 池线（TensorCash/Nockchain/BTX/Zano/Tari/CoreCoin…），假 LLM 端点钓算力
- 软件栈 = NOMP/UNOMP（React CRA + Express + Redis + dot.template）
- ★ 未授权操作面 `GET /api/remove_worker?address=&workerName=`（无 captcha 无鉴权；参数错误漏 `EXECABORT` → Redis 事务指纹）
- 未授权数据面 `/api/stats` 全池运营数据（zano 池样本：1271 区块 / 617,584 付款 / 332 矿工）
- 前端 `main.js` 内嵌三组 coin 配置密钥（值脱敏，存本机案卷）
- 心跳网关 4505/4506：MAGIC `ff…01`+1 字节命令 → `01{status}`；逆向结论 = 哑网关（不构成 RCE 面）
- 基础设施测绘 30+ 节点（OVH FR/SG/US/CA；`eu.lproute.com` nginx+Stratum 网关）

## 诚实卡点（原文证据）

- SSH 全 publickey（无口令面）· `change_settings` 有 reCAPTCHA（未绕过）· 8811 仅 bind localhost · 无 SQLi（引号差异 = URL 编码）· 4505/4506 非可控 C2

## When to reuse

- 命中 NOMP/UNOMP 指纹或「AI 算力」伪装站 → 先 `skill_view(mining-pool-pentest)`（六章方法论 + 5 脚本 + 协议图谱在技能内）
- 同类团伙打击流程：测绘 → `/api/stats` 定性 → 未授权扫描 → 管理面定向 → Redis → Stratum 验证

@TGSEC社区 · @TGSEC-Qtzuu 整理
