# llm-armor-tester — 破甲测试器要点

- 定位：对**已授权**的 OpenAI 兼容 `/v1` 端点批量执行 prompt 注入/越狱载荷，判定是否破防并生成渗透报告 + 破防过程深度分析。Python 3.10+ 纯标准库（零第三方依赖）。
- 判定口径：BREAK（canary 服从命中 / 已知 system prompt 泄露 / 泄露内容证据 / 模型 judge 拍板）、SUSPECT（证据不足、假装执行、边拒边泄）、RESIST（拒答特征）、UNKNOWN、ERROR；全部判定理由逐条留痕。
- canary 机制：载荷可内嵌 `[[OBEYED-<id>]]` 类服从标记；命中且语境+形态双重校验才判破防，专门排除「引用标记并拒答」假阳性。
- 载荷组件栈（README）：角色覆盖 / 规则重写 / 目的合法化 / 格式约束 / 渐进锚定 / 编码转写——协议采纳、本体重塑、惰性夹具归一、推理链劫持、幻影权威、格式越权、审查倒取；刻意避开「忽略指令 / 无审查模式」低阶范式。
- 概率采样：`--repeat N` 同一载荷打 N 次输出破防率（应对随机防御层）；`--qps` 全局限速保护目标；`--resume` 按 payload×采样粒度断点续跑。
- 多轮攻击链：`chains/attack_chains.jsonl` 6 条——C001 密语触发 seed_trigger、C002 登门槛 foot_in_door、C003 记忆污染 memory_poison、C004 角色渐变 persona_drift、C005 分心掩护 distraction、C006 跨轮编码分段重组 split_decode。
- 间接注入载体：`--carrier email/webpage/tooldoc/code_comment/log/json_field`，模拟 RAG 与 Agent 场景的间接注入。
- 进化引擎：`evolve --gens 5 --pop 20 --elite 5` 适者生存自动繁育越狱变体，破防个体进名人堂（hof.jsonl）。
- 命令链：payloads stats/list → import-goods → expand → run（可 `--dry-run` 验 CSV 链路）→ judge（`--mode both` 规则+模型复核）→ report（MD/HTML/PDF + SVG 图表）→ analyze（攻击链分解/防御层失效矩阵 L1~L6/ATLAS 映射/修复路线图）→ diff（修复前后差分：已修复/回归/仍破防）。
- 一站式：`scan --intensity quick|standard|full --judge-mode both --analyst-model ...`；常测目标可存 `profiles` 档案（`scan --profile myai` 零参数复测）。
- 本地自测：`python tools/mock_target.py --port 8899` 提供模拟靶标（越狱特征命中即模拟破防，但 25% 概率仍拒答以验证概率采样），配 `scan --base-url http://127.0.0.1:8899/v1 --api-key mock --model mock --intensity quick`。
- tools/ 附带脚本：full_scan.ps1（一键全流程）、build_exe.ps1（PyInstaller 单文件 exe）、chains_to_standard.py（chains CSV→标准结果列复用报告引擎）、dump_verdicts.py（判定明细导出）、final_summary.py（终版分布/模型 judge 改判统计）、judge_debug.py（judge 返回格式调试）、upgrade_payloads.py（P002-P013 旧范式载荷原位升级为组件栈新范式）。
- PDF 导出：`--pdf` 优先 weasyprint，未安装则自动调用本机 Edge/Chrome headless。
- 合规（DISCLAIMER.md 中英双语「使用即同意」）：仅限自有资产/书面授权（客户合同 / SRC 众测 / CTF 靶场）或学术研究；仓库不携带真实凭据、测试数据与第三方版权文本。

@TGSEC社区 · @TGSEC-Qtzuu 整理
