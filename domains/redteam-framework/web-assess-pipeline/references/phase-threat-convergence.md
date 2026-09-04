# 威胁收敛阶段 SOP（主代理调度）

# 工作目标

在完整挖掘产出之上收口：把威胁清单逐条对账到挖掘产出（**威胁消账**），并对被防护（`filtered`）的漏洞信号做
**专项绕过**突破。本阶段单一并发池、最多 3 个后台子代理滚动补位，混排两类工作——威胁消账调度
`pentest-vuln-miner` 补测、专项绕过调度 `pentest-bypass-miner`。

- 输入：`threats.jsonl`、`vuln-matrix/{id}.json`、`vuln-reports.json`、`url-inventory.json`、`retest-list.json`、`sessions.json`。
- 输出：更新 `threats.jsonl`（每条威胁消账）、`bypass-list.json`、更新的 `vuln-matrix`、新增 `VULN-VD` 报告、更新 `vuln-reports.json`。

# 工作流程

## 1. 建立两类任务队列

### 队列 A · 威胁消账

遍历 `threats.jsonl` 中仍为 `pending` 的威胁（漏洞挖掘阶段验收时已回填 `confirmed`/`excluded` 的不再重复对账），映射到挖掘产出并更新 `verification_status`（收尾后不得遗留 `pending`）：

- **已确认（confirmed）**：该威胁攻击面已被某 `VULN-VD` 报告命中 → `verification_status=confirmed`、
  `verification_report_id` 填该报告号、`verification_detail` 简述确认结论。
- **已排除（excluded）**：相关 URL 参数漏洞矩阵结论为不可利用（`tested_not_found` 且证据充分）→
  `verification_status=excluded`、`verification_detail` **引用该矩阵结论作证据**。
- **存疑（doubtful）/ 被防护（filtered）**：客观或安全边界不可测记 `doubtful`；有防护绕不过记 `filtered`
  （filtered 项自然进入队列 B 专项绕过）——均在 `verification_detail` 详述。
- **缺账（挖掘产出中找不到对应结论）**：该威胁攻击面无任何矩阵/报告结论 → 相关 URL **入队列 A**，以补充测试
  形式调度 `pentest-vuln-miner` 补测；回收后按上述规则再消账。

### 队列 B · 专项绕过

先生成绕过台账：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_bypass_list.py --project {id}
```

汇集全部 `vuln-matrix` 中 `status=filtered` 的条目为 `bypass-list.json`（每条一个 `(url_id, 参数, 漏洞类型)`
绕过目标）。**按漏洞类型（`vuln_type`）分组**——同一类型的 filtered 条目所属 URL 归为一组，每组按 URL 切块
（**每任务 ≤5 个 URL**）成绕过任务入队列 B；**一个任务对应单一漏洞类型 + 一批（≤5）该类型 URL**。同一 URL 含多个类型
的 filtered 条目时，在各对应类型的任务中分别出现。**同类型 URL 的防护往往同源、绕过手法可互通**，故同类型 URL 归批下发。

## 2. 任务调度（单一并发池，滚动补位）

- 用**后台子代理**（`run_in_background: true`）执行任务，**同一并发池最多 3 个**在跑，队列 A
  （`pentest-vuln-miner`）与队列 B（`pentest-bypass-miner`）**混排下发**。注意不是3个一批并发下任务，而是第一批先下3个任务，之后每个子代理完成后就补1个任务（滚动补位），保持始终3个并发，避免一个批次最慢的任务拖慢整批任务时间。
- 某个子代理完成（收到完成通知）后，若两队列仍非空则**补发 1 个新任务**维持 3 并发，直到两队列全部完成；
  等待期间主代理处理和验收已返回结果。

### 下发给子代理的内容

- **威胁消账（`subagent_type: pentest-vuln-miner`）**：`project-id` + 待补测 `url-id` + 测试要求
  （指明待消账威胁的攻击点，例：`THREAT0007：order_no 参数疑似越权读取他人订单，请针对性验证并给出结论`）。
- **专项绕过（`subagent_type: pentest-bypass-miner`，定义见 `.codex/agents/pentest-bypass-miner.toml`）**：
  `project-id` + **目标漏洞类型** + 本批 `url-id`（≤5 个同类型 URL）+（前序批次已突破同类型防护时）**已知有效绕过手法提示**
  （例：`SQL注入：空格过滤已在 URL00064 用 /**/ 替代空格突破，请优先尝试同法`）。子代理对本批各 URL 该漏洞类型的 filtered
  条目做多族绕过，某 URL 突破后在本批其他 URL 复用该手法。

## 3. 结果验收

主代理按子代理完成顺序依次处理其返回：

### 1. 校验产物落盘

确认该任务的 `vuln-matrix/{URLID}.json` / 报告已落盘；缺失或明显不完整 → 重新调度该 url-id（子代理按
url-id 幂等重跑覆盖旧产物）。

### 2. 消账 / 绕过结果验收

- **威胁消账**：核对补测矩阵结论是否真能支撑该威胁的 `confirmed`/`excluded` 判定，回填该威胁
  `verification_status` / `verification_report_id` / `verification_detail`（消账映射须真实，杜绝无对应结论蒙混）。
- **专项绕过**：核对绕过尝试是否真实充分——
  - 突破成功：矩阵条目 `status` 已由 `filtered` 转 `found`+`report_id`、报告证据真实；回填 `bypass-list.json`
    该项 `bypass_status=retested` + `access_note`（引用报告号）。
  - 仍绕不过：矩阵条目保持 `filtered` 且 `filter_probe` 已扩充已试绕过族；回填该项 `bypass_status=retested`
    + `access_note`（记已试绕过族与判定依据）。
  - **绕过手法沉淀与跨批复用**：突破成功的绕过手法（针对某防护的有效 payload 结构 / 编码 / 等价构造）记录留存，
    下发后续**同类型**批次任务时作为提示携带（"尝试使用 X 绕过方式"），供其他 URL 优先复用。

### 3. 报告验收

逐份阅读本阶段新增报告（补测 / 绕过突破），检查证据是否真实、复现是否完整、危害是否合理；用
`register_report.py` 登记 `vuln-reports.json`（`pending_review`），复核为 `approved` / `rejected`
（拒绝须写明理由、修改标题加【已拒绝】但不删除报告）。**报告被拒后**，若关联威胁为 `confirmed`，须反向修正
该威胁状态（改 `excluded`/`doubtful`/`filtered` 并补 `verification_detail`、清空 `verification_report_id`）。

## 4. 收尾 → 威胁收敛质量门禁 → 报告汇总

`threats.jsonl` 无 `pending`（每条已消账）、`bypass-list.json` 每条 `bypass_status` 非 `pending`、
`vuln-reports.json` 无 `pending_review` 后，进入**威胁收敛质量门禁**（见 [quality-gates.md](quality-gates.md)）。
门禁通过后进入**报告汇总阶段**——运行 `build_report.py` 汇总四阶段数据与已批准报告，产出 HTML/DOCX 评估报告
（见 [phase-reporting.md](phase-reporting.md)）。
