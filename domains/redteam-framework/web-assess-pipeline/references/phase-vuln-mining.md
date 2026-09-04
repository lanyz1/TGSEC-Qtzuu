# 漏洞挖掘阶段 SOP（主代理调度）

# 工作目标

调度子代理 `pentest-vuln-miner` 对 `url-inventory.json` 中的 page/api URL和`retest-list.json`中的`disposition=retest` 的补测 URL **逐个 URL、逐个参数**挖掘漏洞，产出参数漏洞矩阵与漏洞报告。
**本阶段全程独立开展，不受前期安全结论影响**——严格按照要做独立的逐URL、逐参数挖掘，不受前期任何安全结论或假设影响。

# 工作流程

## 0.固化必挖清单

进入本阶段先把当前 `url-inventory.json` 中全部 page/api URL 的 `{id, url, param_names}` 固化为必挖清单基线 `mining-scope.json`，作漏洞挖掘覆盖度**唯一硬门禁**依据：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_mining_scope.py --project {id}
```

冻结后基线不随挖掘阶段代理新记录的 URL/参数变动（`build_mining_scope.py` 检测到已存在即不覆盖）。挖掘阶段 payload 产生的新 URL/参数（如自上传 shell 文件、注入调试参数）由质量门禁列为软复核项——确为正规业务接口用 `build_mining_scope.py --add URLID...` 追加进基线，payload 副产物忽略、不入必挖清单。

## 1.任务编排

**建立任务队列**：将 `url-inventory.json` 中的 page/api URL 和 `retest-list.json` 中 `disposition=retest` 的补测 URL（`disposition=blocked` 的**不挖掘**）合并后切块成**一条任务队列**，按以下优先级排序下发：

1. **有威胁关联的有参数 URL**（该 URL 出现在任一 `threats.jsonl.related_objects`，属威胁建模已标记的高关注攻击面）——每任务 ≤5 个；
2. **其余有参数 URL**——每任务 ≤5 个；
3. **无参数 URL**——每任务 ≤15 个。
4. **涉及删除功能的URL**——每任务 ≤5 个；放在最后测试，避免删除了必要的测试数据影响其他功能测试。
5. 

主代理按此队列顺序下发（高优先级批次先发、发完再发下一优先级）。**编排优先级只决定下发次序，不改变任何单个 URL 的独立逐参数挖掘方式与结论**——子代理只收 project-id + url-id、不读威胁清单（见「工作目标」的独立性要求），对每个 URL 一律做独立的逐参数挖掘。

> 断点续跑：扫描 `url-inventory.json` 各 URL 的 `*_mining_done` 与 `retest-list.json` 中 `disposition=retest` 项的 `mining_status`，跳过已 `completed`/`not_applicable` 的，继续 `pending` 的。

**关联上下文提取**：
下发任务前，对该任务每个 URL 先生成关联上下文：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\extract_url_context.py --project {id} --url-id URL00010 URL00011 ...
```

生成 `url-context/{URLID}.json`（聚合页面/JS/业务链关联记录），供子代理快速聚焦。

## 2.任务调度（并发调度后台代理，滚动补位）

根据任务队列，调度后台子代理并发执行任务，当子代理完成后主代理**先补位下发新任务（始终维持 3 个并发），等待期间再处理和验收结果****。**注意不是3个一批并发下任务，而是第一批先下3个任务，之后每个子代理完成后就补1个任务（滚动补位），保持始终3个并发，避免一个批次最慢的任务拖慢整批任务时间。

### 并发调度规则

- 用**后台子代理**（`run_in_background: true`）执行任务，**同时最多 3 个**在跑。
- 某个子代理完成（收到完成通知）后，若队列非空则**按队列顺序补发 1 个新任务**（有参数任务在前、无参数任务在后），直到队列全部完成。

### 下发给子代理的内容

使用专用子代理 **`pentest-vuln-miner`**（定义见 `.codex/agents/pentest-vuln-miner.toml`）执行漏洞挖掘任务，方法论、工作流程、产出格式、上下文信息等**全部固化在其系统提示词中**，无需主代理额外透传。

**默认任务内容**：
调度时（`subagent_type: pentest-vuln-miner`）任务内容默认只需两项：

- `project-id`；
- 本批 `url-id` 列表。

例：`project-id=TGSEC-shop，本批 url-id：URL00007 URL00012 URL00048`。

**补充测试任务内容**：
如果子代理的任务意外中断或任务结果验收不不合格，可以针对指定URL下发补充测试任务，在默认任务内容基础上添加具体测试要求）。

例：

```markdown
project-id=TGSEC-shop， url-id：URL00007 
测试要求：
1. name参数漏未做测试，请按流程进行测试。
2. age参数SQL注入漏洞测试方法不规范，构造playload时未考虑过滤空格、&等特殊字符带来的影响，测试结果不可信，请重新测试。
3. description参数未做XSS测试，请补充测试
4. 在开展重放测试时仅进行了串行重放，未进行并发重放测试，可能遗漏TOC/TOU漏洞，请补充测试
5. 已验证time参数可控，但危害性未充分验证，请进一步分析相关业务流程和约束条件，挖掘验证可能存在的危害
```

## 3. 结果验收

主代理按子代理任务完成的顺序（收到完成通知的顺序）依次处理其返回：

### 1.校验产物落盘

确认该任务每个 url-id 的 `vuln-matrix/{URLID}.json` 已生成（后台进程偶发中断/进程退出会导致 in-process 状态丢失、产物未落盘）。**若某 url-id 矩阵缺失或明显不完整 → 重新调度该 url-id**（子代理按 url-id 幂等重跑，覆盖旧产物），把缺失的任务重新入队。

### 2.漏洞矩阵验收

子代理提交前已用 `check_matrix.py` 自检矩阵结构合规（参数覆盖、filter_probe 结构、checkpoint_response 应答、状态分流等硬规则），验收聚焦**语义与测试充分性**：逐一阅读每个 url-id 的 `vuln-matrix/{URLID}.json` ，确保每个参数测试的漏洞类型选择合理无遗漏，测试过程符合漏洞技术原理和子代理的规范要求（**重点检查测试要点应答情况**），测试结果判定无明显偏差、错误，输出结果符合规范要求。验收通过后根据url-id的来源将结果回填至 `url-inventory.json` 或 `retest-list.json` 中。

- **典型错误示例**：

  - **遗漏应当测试的漏洞类型**：例如某个参数明显会拼接到数据库语句中（无论是增删改查）但未测试 SQL 注入漏洞，登录功能未测试用户枚举等。
  - **通用漏洞防护机制测试不到位或 `filter_probe` 格式不合规**：`filter_probe` 不是结构化对象、把整条 payload 当 key（应每个符号/关键字一个 key）、防护情况取值不实，或防护机制测试不全面、测试方法错误等。
    - 按照测试规范，通用漏洞挖掘时必须先测试防护机制，逐个针对该漏洞类型常用的特定字符/关键字（如 SQL 注入的 `空格`/`'`/`"`/`union`/`select`、XSS 的 `<`/`>`/`script`/`onerror`、路径穿越的 `../`/`..%2f`、SSRF 的内网地址/协议等）探测服务端是**过滤/拦截/替换/转义/放行**中的哪种，据实记入 `filter_probe`（`{符号/关键字:[防护情况,说明]}`，**key 是单个符号/关键字而非整条 payload**）；再据探测结果构造真正的利用 payload。
  - **测试要点未逐编号应答或应答不规范**：有编号要点的漏洞类型（见 [test-checkpoints.md](test-checkpoints.md)）在 `tested_not_found`/`doubtful`/`filtered` 时未填 `checkpoint_response`、KEY 越界或漏答关键要点（如 SQL 未答 SQL003 绕过、用户枚举未答 ENUM001 状态码一致性），没有提供应答明确要求的证据，或应答结果过于宽泛/不合逻辑。
  - **测试payload未考虑防护机制或未充分尝试绕过机制**：例如已知某个参数过滤了空格、&等特殊字符但测试payload中仍包含这些字符，XSS只尝试了个别标签被过滤就认为安全没有全面尝试可用于XSS注入的标签。
  - **业务逻辑漏洞测试不到位**：例如测试用户枚举漏洞时仅看响应体未看响应码，验证码参数未测试空值/不带参数等特殊情况，重放漏洞测试时直接重放已请求的数据包而没有新生成数据包进行竞态重放测试等。
  - **业务逻辑漏洞测试角度偏差**：例如未全面考虑业务约束条件的绕过，未从可实际可获利的角度考虑漏洞危害性。
    - 历史教训：某创建订单请求订单时间参数可控，测试时选取了一个在优惠窗口期内的商品创建订单，认为篡改优惠时间只能放弃优惠无危害，实际应选取一个不在优惠窗口期内的商品创建订单，验证能否利用该漏洞获取优惠。
- **验收不通过的处理**：验收不通过时应调度子代理进行补充测试（加入任务队列，等待下一个子代理任务完成时优先下发）。
- **回填规则**：回填该任务各 URL 的 `*_mining_done` 与 `*_mining_result`

  - 回填的文件：根据URL的来源将结果回填到不同的文件中。
    - 若 URL 为 page/api，则回填 `url-inventory.json` 中的 `*_mining_done` 与 `*_mining_result`。
    - 若 URL 为补测 URL，则回填 `retest-list.json` 中的 `*_mining_done` 与 `*_mining_result`。
  - 回填的内容：具体结构见 [data-schemas.md](data-schemas.md)
  - `generic_vuln_mining_done` / `business_logic_mining_done`：
    - 该类有任一参数测试过 → `completed`；
    - 该类所有参数与矩阵条目均不适用 → `not_applicable`。
  - `*_mining_result`：按参数记**已测试**的漏洞类型 → 报告号（found）/ `tested_not_found` / `doubtful` / `filtered`（不适用的不记）；URL 级测试记 `_url_level`。

### 3.漏洞报告验收

逐一阅读任务产生的漏洞报告，检查是否存在证据不足、危害性判断错误或逻辑错误等问题，将结果记录在 `vuln-reports.json`（用 `register_report.py`，`pending_review`），例如：
- **证据不足**：未提供真实请求/响应信息，或提供的信息不足以证明漏洞存在。
- **夸大危害性**：漏洞仅损害攻击者自身的利益（不应是漏洞），泄露的信息不是实际的业务数据而是菜单下拉选项信息等敏感度较低的信息（级别不高于低危）。
- **逻辑错误**：漏洞的描述或操作过程明显不合理，存在自相矛盾或与其他漏洞报告存在明显冲突。

主代理需要根据验收结果选择以下操作之一，可以根据需要对漏洞报告进行简单的验证或修正，必要时可以下发补充测试任务：
- **接受报告**：不做任何调整
- **调整漏洞等级**：提高或降低漏洞危害等级，直接修改报告并登记结果
- **拒绝报告**：拒绝该报告，需要修改报告标题增加【已拒绝】但不要删除报告


### 4.威胁消账前置回填

某 URL 的矩阵与报告验收通过后，顺带对账 `threats.jsonl` 中 `related_objects` 指向该 URL 的威胁并回填消账状态：

- 该 URL 挖掘已命中对应攻击面的报告 → `verification_status=confirmed`、`verification_report_id` 填该报告号、`verification_detail` 简述确认结论；
- 该 URL 相关矩阵结论为不可利用且证据充分 → `verification_status=excluded`、`verification_detail` 引用该矩阵结论作证据；
- 尚不能定论的保持 `pending`，交威胁收敛阶段队列 A 补测消账。

威胁消账由主代理在验收环节完成（主代理有全局视角，掌握威胁清单与全量产出）；`pentest-vuln-miner` 子代理仍不读威胁清单、保持独立逐参数挖掘。

## 4. 收尾 → 漏洞挖掘质量门禁

固化必挖清单 `mining-scope.json` 内全部 URL 两类 `*_mining_done` 均非 `pending`、其中有参数 URL 均有合规矩阵，
且 `retest-list.json` 中 `disposition=retest` 项均已挖掘（`mining_status` 非 `pending`）后，进入**漏洞挖掘质量门禁**
（见 [quality-gates.md](quality-gates.md)）。挖掘阶段新出现、经复核确认应挖掘的正规接口先 `build_mining_scope.py --add` 纳入必挖清单再收尾。
