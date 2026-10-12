# 盗U 黑产工业链 · 威胁情报课（含两条判别法）

- Source report: 报告包 20261012（`盗U黑产帝国_威胁情报报告.docx`，2026-10-03；原文留本机案卷）
- Techniques: drainer, ios-exploit-chain, telegram-saas, c2-forensics
- Fused: 2026-10-12

## 产业链全景（五层）

1. 刷粉/僵尸粉 SaaS → 2. 钓鱼落地页（0×0 隐藏 iframe 注入）→ 3. iOS RCE（**版本闸门只放行 18.4/18.5/18.6**；`runtime.js` vs `runtime-legacy.js` 双分支；GPU 路径 OffscreenCanvas+WebGL；`rce_offsets[device_model]` 偏移表；机型白名单 chipset A15/A16/A17 Pro）→ 4. DarkSword 木马 C2（`:7000` uvicorn/FastAPI+Vite）→ 5. 盗U 合约授权 + 博彩洗白；配套层（担保/支付/卡商）
- 定性：团伙同时自营盗U **并向同行出售 iOS 木马/博彩 bot/TG 号/刷粉** = 基础设施供应商，SaaS 化扩散

## 两条判别法（防污染，入库价值最高）

1. **「C2 是否处于实网验证期」五指标**：指令全 pending / 假设备命名 `dev-<md5>` / chipset=null / agents=0 / 项目龄<3 个月 → 流量数字**不得引用为受害规模**
2. **「返水≈投注」= 样板数据**：返水占投注额 99.98%（合理区间 0.5–2%）→ 流水为演示数据；只信余额类字段量级

## 打法要点

- 开群/托号 SaaS 拖穿通病：越权读不按 client 过滤（42+8 台口径）
- 同业供应商反推：从 bot 用户 `first_name`（=TG 名片）上游溯源
- exploit 链工艺细节（版本闸门/双分支/GPU 路径/偏移表）比既有卡更具体 → 作 `ios-harvest-chain-recon` 增补素材
- 链上判读交叉：`crypto-drainer-farm-pentest` + 本域既有 `*-drainer-*` 课

## 诚实卡点

- 该 C2 无大规模受害证据（本轮新增判定）；经营数据含演示样本；链上读数未二次复核

@TGSEC社区 · @TGSEC-Qtzuu 整理
