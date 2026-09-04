# 质量门禁 SOP

三个阶段（广度建模、漏洞挖掘、威胁收敛）结束前都必须过门禁：**先用 Python 脚本做机器硬检查，再由 AI 做
语义复核**。有遗漏或不合规的记录必须处置完成、重新验证通过后方可流转。通过后输出对应「质量检查报告」。

> 分工原则：脚本负责**机器可判**的硬规则（格式 / 必填字段 / 枚举 / 交叉引用 / 一致性），输出
> 「必须修复」与「待复核清单」；AI 负责脚本列出的**需语义判断**的复核项。脚本 exit 0 仅代表硬检查过，
> **必须**完成 AI 复核才算门禁通过。

---

## 门禁退出态与放行判据（贯穿三门禁 · 不可空口"通过"）

> 背景：曾出现门禁实为 `exit 1`（页面未解析/接口未纳入清单），却被口头记成"硬检查通过"并流转，
> 导致高价值接口漏挖。为此**门禁退出态由脚本落盘、下一阶段强制校验**，杜绝"数据改了/门禁没重跑/空口通过"。

**1｜脚本落盘真实退出态（机器写，AI 不可伪造）**
每个 `check_*.py` 结束时把真实结果写入 `state.json.gates.<breadth|vuln_mining|threat_convergence>`：
`{exit, blocking_count, hard_errors[], acknowledged[], checked_at}`。**exit 语义 = blocking**（0 = 无硬错误，
或硬错误已全部**有效 acknowledged**）。

**2｜放行判据 = `blocking_count == 0`**

- 硬错误能修的**先修**（下载解析页面 / 走通接口并入清单 / 补矩阵），重跑门禁后自然消失；
- **确属客观走不通**的，在 `state.json.gates.<gate>.acknowledged` 逐条登记 `{match, reason_code, note}` 放行
  （`match`=能唯一命中该错误的子串，通常是 URL）——这是避免死锁的合法出口。未被**有效** acknowledged
  覆盖的硬错误即 `blocking`，必须清零才能流转。

**3｜acknowledged 的 `reason_code`（固定集合，AI 研判标尺——要点1）**
`out_of_scope`（确认不在范围）/ `system_bug`（靶标缺陷非本方问题）/ `captcha_unbypassable`（人机校验确实绕不过）/
`precondition_unmet`（前置条件客观无法满足）/ `not_exist`（探测项确不存在 404 等）/ `accepted_residual`（承认并显式接受残余风险）。
reason_code 非法或缺 `note` 的 acknowledged **不生效**（脚本标"无效 acknowledged"，对应错误仍 blocking）。
**卫生类错误（JSON/字段/枚举/矩阵缺失）不可 acknowledged，必须修**。

**4｜下一阶段强制校验前置门禁（脚本读，非靠自觉）**
`check_vuln_mining.py` 开头校验 `breadth`、`check_threat_convergence.py` 开头校验 `breadth`+`vuln_mining`：
上一门禁 `blocking_count>0` 或退出态缺失 → 本门禁直接报 `[前置门禁]` 硬错误、禁止流转。

**5｜质量报告须贴真实退出态、逐条列明（要点4）**
每份质量检查报告**必须粘贴门禁脚本真实的 `exit / blocking_count`**，并**逐条列出**：blocking 项如何修复、
acknowledged 项的 `reason_code + note`；`accepted_residual` 的还须进最终报告"残余缺口/未覆盖清单"。
**禁止在报告写"通过"而 `state.json` 里 `blocking_count>0`**。AI 复核须核验每条 acknowledged 理由是否成立、
reason_code 是否贴切（要点4 由 AI 按原则执行）。

---

## 广度建模质量门禁

### 第 1 步：生成 URL 清单（脚本）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_url_inventory.py --project {id}
```

从 `proxy-logs/url_index.jsonl` 提取 page/api 类入 `url-inventory.json`；other 类也纳入但标 `needs_review`
待 AI 判断是否实为页面/接口。幂等：只增新 URL/新参数，不改已有状态字段。

再生成补测清单（幂等研判台账）：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_retest_list.py --project {id}
```

**前向驱动**：从 `pages.jsonl` / `js.jsonl` **已登记**的 in-scope 接口/链接中，把落入 `failed_index` 且未纳入
`url-inventory` 的收进 `retest-list.json`（默认 `disposition=pending`）；**不反向扫描 failed_index**，避免 payload
探测/上传残留等未登记噪声。**失败默认视为没走通正规业务流程**——只 seed 候选、不代表已处置，须在下方 AI 复核
逐条研判（走通 / retest / blocked）。

### 第 1.5 步：页面候选 URL 抽取（脚本，软核验）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\extract_page_urls.py --project {id}
```

从每个页面的落盘 HTML 枚举各类标签属性与 JS 语法中可能含 URL 的位置，与该页已登记 URL 对比，列出
「疑似未登记」候选供 AI 复核。**不做硬校验、恒 exit 0**，结果并入第 3 步 AI 复核逐条判断。

### 第 1.6 步：静态请求参数提取（脚本，为参数覆盖门禁产出基准）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\extract_static_params.py --project {id}
```

从页面内联脚本与外链 JS 静态解析 `jsonPost/postJSON/axios.post` 等「请求体在第 2 实参」调用的**内联对象字面量
顶层键**，落盘 `url-static-params.json`（每接口「应有参数」基准，只信 high-confidence；变量/动态拼装 body 一律
跳过，宁漏不误）。供第 2 步 `check_breadth.py` 与代理实测 `param_names` 比对，抓出「静态可见却从未随真实流量
记录」的参数缺口（如商品详情页 `create-order` 的 `order_time`）。**恒 exit 0**；缺该文件时 `check_breadth`
参数覆盖检查降级为复核提示（不 blocking）。

### 第 2 步：硬检查（脚本）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\check_breadth.py --project {id}
```

检查：五清单 JSON/JSONL 可解析、必填字段齐全、枚举合法；
**每个页面已下载 HTML（`html_file` 文件存在）且 `fully_parsed=true`**；
**每个页面据代理请求日志 `User-Agent`/`Sec-Fetch` 头确认经浏览器(playwright)走查**（仅工具访问记录 → 必须修复）；
JS `is_opensource`/`download_status` 合法、非开源且已下载的 JS `fully_read=true`；
**代理 `js` 类请求全部登记在 `js.jsonl`**；页面 `discovered_js.js_id` 均已登记；
交叉引用双向（页面/JS 的 discovered_urls ↔ URL 清单；URL 清单 page/api ↔ 页面/JS/业务链承载）；
**参数覆盖**（`url-static-params.json` 的 high 参数须都在代理实测 `param_names` 中，缺失即 `[参数覆盖]` 硬错误——
该参数在页面/JS 内联请求体可见却从未真实发送、业务流程未走通、漏洞挖掘阶段不会挖掘；仅对已访问接口检查，容忍代理嵌套
展平 `k`↔`k.child`）；
**权限矩阵覆盖**（每个 page/api URL `permission_matrix_status=verified`、`permission-matrix/{id}.json` 非空、
`results.judgment` 合法且带 `session_valid`/`final_status`/`body_fingerprint` 证据字段，页面型另做纯长度反向抽查兜底
判定器漏判——此项须先完成第 2.5 步权限矩阵验证后才会清零）。
exit 1 表示有「必须修复」项，逐条处置后重跑至 exit 0。

### 第 2.5 步：权限矩阵验证（脚本）

攻击面/URL 覆盖检查清零（全部 page/api 已纳入 `url-inventory.json`）后，对**全部 page/api URL** 逐角色验证访问控制：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\permission_probe.py --project {id}
```

以未登录基线 + 各角色 cookie 逐 URL 产出 `permission-matrix/{id}.json`（判定三铁律见 [phase-breadth.md](phase-breadth.md) 「权限矩阵验证」）。
将 `judgment=abnormal`（越权/未授权）逐条**补入 `threats.jsonl`**（新 `THREAT` 记录、`related_objects` 指向该 URL、
`verification_status=pending`），再重跑第 2 步 `check_breadth.py` 使权限矩阵覆盖检查清零。

### 第 3 步：AI 语义复核（脚本列清单，AI 判断）

对应需求门禁项，逐项复核脚本「待复核清单」：

1. `needs_review`(other) 是否实为页面/接口——是则改 `category` 并去掉 `needs_review`。
2. `is_opensource=true` 的 JS 确为开源库（不下载不通读合理）；`failed` 的确为资源不存在，而非路径拼接错误。
3. 逐页复核 `extract_page_urls.py` 列出的「疑似未登记」候选 URL，判断是否遗漏页面/接口/JS，遗漏则补登记。
4. 无匹配代理访问记录的页面，逐一确认是否确经浏览器访问（SPA 哈希路由无独立请求属正常，URL 与代理记录不一致则修正）。
5. **补测清单研判**（`retest-list.json`）：访问失败的接口/URL——失败默认是没走通业务，**优先用 playwright 走通正规业务流程**使其进入 url-inventory；确属客观阻塞（系统 bug / 人机校验无法绕过 / 前置条件无法满足）→ 置 `disposition=retest` 交漏洞挖掘阶段补测；安全边界所限或无需/无法测 → `disposition=blocked` 留痕不补测；均须填 `access_note`。页面/JS 中 URL 访问失败、权限禁止的记录同时确认 URL 正确且带了必要参数。**`[参数覆盖]` 硬错误**逐条处置：优先用 playwright 走通该接口完整业务流程使缺失参数（如 `order_time`）进入代理记录并重跑 `build_url_inventory.py`；确属客观无法触发（仅特定分支/特权角色发送）→ `retest-list.json` 记 `disposition+access_note`，或 acknowledged 记 `reason_code=precondition_unmet`；静态误判（非真实入参）→ acknowledged `reason_code=not_exist`。
6. 业务链是否覆盖所有业务目标 / 生命周期 / 可交互元素 / 接口，有无遗漏。
7. 非 `completed` 的业务链确系客观条件或安全边界所限且理由合理，本条必须在广度建模质量检查报告中逐一说明为什么接受业务链没走通。
8. 抽查 `not_found` 记录确属未发现。
9. 威胁建模是否充分，是否全面考虑业务约束条件。
10. **权限矩阵**：逐一核对页面型 URL 越权判定基于**内容指纹/长度对比**而非 JSON `"success":true`（页面型越权返回 HTML 后台，用 JSON 标志判会漏）；各角色 `session_valid=true`（存在 `false` 者其判定不作数，须重登刷新 `sessions.json` 后重跑 `permission_probe.py`）；脚本列出的「疑似判定器漏判越权」抽查项逐条确认（低权角色响应贴近归属角色后台即越权）。
11. **权限矩阵异常入库**：`judgment=abnormal` 的越权/未授权是否均已补入 `threats.jsonl`（`related_objects` 指向该 URL、`verification_status=pending`）作为攻击面威胁，无遗漏。
12. 所有 `notes` 特殊情况说明是否符合实际、合理。

发现问题 → 补全/修正记录 → 重跑第 1~2.5 步 → 复核通过。

### 输出：广度建模质量检查报告

汇总：各清单条数；权限矩阵覆盖与越权分布；**门禁真实退出态**（粘贴 `state.json.gates.breadth` 的
`exit`/`blocking_count`，逐条列出 blocking 如何修复、每条 acknowledged 的 `reason_code+note`）；AI 复核结论（逐项）；
遗留特殊情况说明。**`blocking_count>0` 时不得写"通过"、不得流转。** 通过（`blocking_count==0`）后更新 `state.json`：
`phase=3`、`breadth=completed`、`vuln_mining=in_progress`。

---

## 漏洞挖掘质量门禁

### 第 0 步：固化必挖清单 + 并入本阶段新触达接口后重算清单（脚本）

进入漏洞挖掘阶段时已用 `build_mining_scope.py` 固化必挖清单基线 `mining-scope.json`（见
[phase-vuln-mining.md](phase-vuln-mining.md)「0.固化必挖清单」）——覆盖度硬门禁只认此基线，挖掘阶段 payload 产生的
新 URL/参数（如自上传 shell 文件）不入必挖。

本阶段挖掘/补测中常经 curl 或 playwright 打通新接口（如账号接管链里的 `reset-password`、二级页 `create-order`），
这些成功仅落 `url_index.jsonl`。收尾前先并入 URL 清单再校验建模质量：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_url_inventory.py --project {id}
python .agents\skills\pentest-web-assess-pipeline\scripts\build_retest_list.py --project {id}
```

并入后**重跑广度覆盖门禁** `check_breadth.py` 确认仍 exit 0——本阶段新触达的 page/api 若仍未下载解析/未研判会在此
暴露（如二级页 `product_detail.php` 被发现却未解析、`reset_password.php` 代理已记录却未登记 pages）；这些**建模硬错误由
「模型内声明」（discovered_urls / 静态参数 / 业务链 / 已解析页面 HTML）驱动，payload 上传的 shell 文件不会触发**。
exit 1 逐条处置（下载解析页面 / 走通接口并入清单 / 在 `retest-list.json` 研判为 retest|blocked）后再进入下方硬检查。

**新触达接口是否纳入必挖**：经 `check_breadth` 处置的正规业务新接口，用 `build_mining_scope.py --add URLID...` 追加进
必挖清单基线后一并挖掘；确为 payload 副产物（如自上传 webshell）在 `state.json.gates.breadth.acknowledged` 记
`reason_code`+`note` 放行、且**不** `--add` 进必挖清单。

### 第 1 步：硬检查（脚本）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\check_vuln_mining.py --project {id}
```

> **一致性硬错误即"打通未纳入"信号**：脚本报 `[一致性] 代理记录的 URL {id} 不在 URL 清单（请重跑 build_url_inventory.py）`
> 时，**不得跳过**——按第 0 步并入后确认该 URL 已进 `url-inventory` 并完成逐参数挖掘（本轮 `reset-password` URL00098
> 正是此错误被放行导致漏挖）。

检查：JSON 格式/字段无缺失；`url-inventory` 与代理 `url_index.jsonl` 一致；**必挖清单基线（`mining-scope.json`）内
每个 URL** 两类 `*_mining_done ∈ {completed, not_applicable}`（无 `pending`），其中每个【有参数】URL 有
`vuln-matrix/{id}.json` 且**基线 `param_names`** 每个参数都有条目、`status` 合法（`found`→有已登记的 `report_id`；
`tested_not_found`/`doubtful`/`filtered`→有 `tests`+`basis`）；无参数 URL 若已产出矩阵则同样校验其 `_url_level` 条目；**基线外挖掘阶段新出现的 URL/参数转软复核、不强制挖掘**
（AI 判断 payload 副产物忽略 / 正规接口 `build_mining_scope.py --add` 纳入）；**通用漏洞 `filter_probe` 为结构化对象**
（`generic` 且 `tested_not_found`/`doubtful`/`filtered`：`{符号/关键字:[防护情况∈{过滤,拦截,替换,转义,放行},说明]}`，
key 疑似完整 payload 软告警不 block）；**有编号要点的类型 `checkpoint_response` 逐要点应答**（KEY 命中该类型编号集、值非空，
要点见 `references/test-checkpoints.md`）；`*_mining_result` 形态合法；**补测清单 `retest-list.json` 每条已研判
（`disposition` 非 `pending`）、`disposition=retest` 的须已挖掘（`mining_status` 非 `pending`，有参数则有合规矩阵）、
非 pending 项须填 `access_note`**；**已生成报告文件（`reports/VULN-VD-*.md`）都已登记 `vuln-reports.json`**。exit 1 逐条处置后重跑至 exit 0。


1. `filter_probe` 结构与语义专项：key 是否为单个符号/关键字（非整条 payload，重点看脚本软告警项）、防护情况(过滤/拦截/替换/转义/放行)与说明是否真实、是否覆盖该类型常用字符/关键字。
2. `checkpoint_response` 要点应答专项：有编号要点的类型是否逐要点应答（对照 `references/test-checkpoints.md`）、有无漏答关键要点、应答是否属实且与 `tests`/报告证据一致（杜绝套话）。
3. 对 `tested_not_found` / `doubtful` / `filtered` **各自抽样**复核测试结果合理性（payload、现象、判定依据是否站得住）；
   重点核对状态分流：有漏洞信号但过滤/防护经真实尝试绕不过记 `filtered`（被防护），客观条件或安全边界不可测记 `doubtful`（存疑），确无信号记 `tested_not_found`。
   `generic` 探到防护(过滤/拦截/替换/转义)时由测试者判断是否存在漏洞信号与绕过必要——确无信号或无绕过价值记 `tested_not_found`（`basis` 说明依据），有信号且值得绕过记 `filtered` 交威胁收敛阶段专项绕过；脚本对该分流列软复核抽查项、不硬拦截。
4. **基线外新增项**逐条判断：门禁软复核列出的挖掘阶段新出现 URL/参数——正规业务接口/参数则 `build_mining_scope.py --add` 或补测重固化纳入必挖，payload 副产物（如自上传文件、注入调试参数）忽略。
5. **补测清单**（`retest-list.json`）逐条复核：`disposition` 理由（`access_note`）是否成立、`retest` 项挖掘结论是否合理、`blocked` 项确系安全边界所限或确无需测。
6. 所有 `notes` 特殊情况说明是否符合实际、合理。

### 输出：漏洞挖掘质量检查报告

汇总：必挖清单覆盖度、参数矩阵覆盖、报告登记数、基线外新增项处置；**门禁真实退出态**（粘贴 `state.json.gates.vuln_mining`
的 `exit`/`blocking_count` + 各 blocking 修复/各 acknowledged 的 `reason_code+note`；`accepted_residual` 项汇入
"残余缺口/未覆盖清单"）；AI 复核结论；遗留特殊情况说明。**`blocking_count>0` 时不得写"通过"。**
通过后更新 `state.json`：`phase=4`、`vuln_mining=completed`、`threat_convergence=in_progress`。

---

## 威胁收敛质量门禁

### 第 1 步：生成绕过台账（脚本）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_bypass_list.py --project {id}
```

汇集全部 `vuln-matrix` 中 `status=filtered` 的条目为 `bypass-list.json`（每条一个 `(url_id, 参数, 漏洞类型)` 绕过目标，
默认 `bypass_status=pending`），交威胁收敛阶段 `pentest-bypass-miner` **按漏洞类型分组、每任务 ≤5 个同类型 URL** 专项绕过。

### 第 2 步：硬检查（脚本）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\check_threat_convergence.py --project {id}
```

检查：前置门禁 `breadth`+`vuln_mining` 已清零；`threats.jsonl` 无 `pending`——`confirmed` 的 `verification_report_id`
非空且在报告清单（消账到某 `VULN-VD` 报告），`excluded`/`doubtful`/`filtered` 的 `verification_detail` 有详述
（引用矩阵结论作证据）；`bypass-list.json` 每条 `bypass_status` 非 `pending`、非 pending 项填 `access_note`；
`vuln-reports.json` 字段/枚举合法、`report_file` 存在、**无 `pending_review`**。exit 1 逐条处置后重跑至 exit 0。

### 第 3 步：AI 复核（脚本列清单，AI 判断）

1. **威胁消账映射专项**：每条 `confirmed`/`excluded` 是否真能在挖掘产出（`vuln-matrix`/报告）中找到对应结论，
   无缺账蒙混；缺账威胁须已调 `pentest-vuln-miner` 补测后再消账。
2. **专项绕过复核**：逐条复核绕过台账——突破项（`filtered`→`found`）报告证据真实；仍 `filtered` 项的 `filter_probe`
   是否已扩充已试绕过族、判定成立。
3. **逐份审核收敛阶段新增报告**（补测 / 绕过突破：描述 / 复现 / 证据 / 危害），不通过则打回或拒绝，直到全部
   `approved`/`rejected`；报告被拒后若关联威胁为 `confirmed`，须反向修正该威胁状态。
4. 所有 `notes` 特殊情况说明是否符合实际、合理。

### 输出：威胁收敛质量检查报告

汇总：威胁确认/排除/存疑/被防护分布、绕过突破/仍被防护数、报告通过/拒绝数；**门禁真实退出态**（粘贴
`state.json.gates.threat_convergence` 的 `exit`/`blocking_count` + 各 blocking 修复/各 acknowledged 的
`reason_code+note`；`accepted_residual` 项汇入"残余缺口/未覆盖清单"）；AI 复核结论；遗留特殊情况说明。
**`blocking_count>0` 时不得写"通过"。** 通过后更新 `state.json`：`threat_convergence=completed`，
并将 `index.json` 对应项 `status` 视情置 `completed`。
