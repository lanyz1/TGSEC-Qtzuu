# Web 评估流水线（测绘→挖洞→收敛→门禁）

抽自端到端 WEB 评估工作流，重点保留：
- mitm 代理按 URL 落盘
- 权限矩阵 / 会话池
- 子代理挖洞与绕过门禁（blocking_count 真值）
- 四阶段：准备 → 广度建模 → 深度挖掘 → 威胁收敛

与 `pentest-execution` 配合：活靶执行纪律用 pentest-execution；需要结构化门禁与代理证据时读本目录。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
