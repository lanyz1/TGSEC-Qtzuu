# CF绕过 → WP REST → CyberPanel → SSH (PrimeTools 案)

**链**: crt.sh 子域 → CF 绕过定位源站 (192.166.82.155) → **WP REST API 未授权读取** → **CyberPanel 8090** → 凭据链 → SSH 双通道持久化 → MySQL 全量 dump

## 要点
- CF 前置 → 先 crt.sh/证书找源站; 源站找到后 WP REST (/wp-json/wp/v2/*) 是零成本信息源
- **CyberPanel (8090)**: 凭据从 WP 配置/弱口令链达到 → 面板→SSH 常规跳板
- 提取: WP 库 10.9MB (48 客户/863 License/49 订单) + AI 代理库 3.3MB
- AI 运营面: 'openclaw' AI 网关 (:18789, DeepSeek-R1 via HF) — 犯罪方的 AI 化运营 (其 AI 自身被越狱滥用, 引述内容)
- 未陷落: 旧服务器 (IP 白名单) / kit 反代 SSH / vouchpay C2 / OLS WebAdmin (预留 CVE-2026-31386, 缺 creds)
