---
name: pentest-web-assess-pipeline
description: |
  WEB 应用安全评估的端到端工作流：全面访问业务流程与接口、测绘攻击面、威胁建模并验证权限矩阵，
  再逐 URL 逐参数挖掘漏洞，最后收敛威胁、对被防护信号专项绕过，产出附真实请求/响应证据、
  经质量门禁审核的漏洞报告清单。
  触发场景：WEB 安全评估 / 渗透测试、威胁建模 / threat modeling、攻击面测绘 / attack surface mapping、
  权限矩阵验证、漏洞挖掘、威胁收敛、接口与参数清点、业务逻辑漏洞与通用漏洞测试、漏洞报告与审核。
  当用户给出一个目标站点并希望系统性梳理其页面、接口、业务链并挖掘、收敛其安全漏洞时使用。
license: GPL-3.0-only
metadata:
  version: "1.0.0"
  category: security
---
# WEB 应用安全评估（Web Application Security Assessment）

把"全面访问所有业务流程和接口、测绘攻击面并验证权限矩阵、逐参数挖掘漏洞、收敛威胁并突破被防护信号、
产出经审核的漏洞报告"固化为 **数据驱动、可断点续跑、有质量门禁**的标准流程。技能以
"测绘 → 挖掘 → 收敛"四阶段递进，最终交付附真实证据、经质量门禁审核的漏洞报告清单。

## 核心原则（核心价值导向）

以下原则是技能的核心价值导向，在进行任何决策时应严格遵循以下原则进行

1. **真实性原则**：所有记录的数据必须完全真实，严禁基于任何理由不记录或篡改已发现的真实数据，严禁录入不符合真实情况的数据。
2. **全面性原则**：全面性是本技能最核心的价值，漏掉任何一个业务链、页面、接口、参数、威胁和漏洞可能性等都会对技能的输出结果评价产生巨大负面影响，通过本技能下发的任务没有资源和时间限制，保证全面性是第一优先级。
3. **目标导向原则**：所有的工作要求和质量门禁都是为了帮助你产出符合技能目标的工作成果，这是你的下限而不是上限，你的行为和决策出发点应该是“更好的完成目标工作”而不能仅仅是“通过质量门禁”，你要借助工作要求找到完成目标的最佳方案而不是机械的“满足规范要求”。
4. **可行性原则**：在满足前面三个原则的情况下，如果你遇到了确实无法解决的客观问题，你可以在详细记录相关信息后跳过该操作。这是为了避免工作阻塞的兜底逃生规则，你必须极其谨慎的使用本规则，启用本规则时必须详细记录理由，包括客观的现象、已经进行的尝试和无法执行的原因，确保你没有滥用本规则。

# 工作规范

1. **数据驱动**：所有工作产物要及时落盘到文件，发现新实体即建记录（允许不全后补），数据结构以 [references/data-schemas.md](references/data-schemas.md) 为唯一权威来源。
2. **全程走代理**：代理服务器日志是重要的客观工作数据，playwright 浏览、curl/python 探测都必须经代理服务器，由代理统一记录请求与参数，不允许直连目标。
3. **Playwright强制执行**：技能要求使用playwright完成的操作**任何情况下绝不用curl、python或其他手段替代**，curl或python脚本可以在**playwright完成指定操作的后**用于补充或强化测试。
4. **脚本优先**：默认使用 `scripts/` 下脚本完成 URL 清单生成、上下文提取、质量校验等大规模/机械的数据处理操作。
5. **URL统一使用绝对路径**：为了确保全局数据的统一性，所有记录URL的位置统一使用绝对路径，避免质量门禁校验失败。
6. **人机校验处理**：遇到人机校验机制时应先尝试绕过，如参数篡改（参数值留空或不提交该参数）、暴力破解、检查是否泄露验证信息等，确实无法绕过才记录业务阻塞。
7. **门禁以脚本落盘退出态为准**：门禁是否通过，以门禁脚本写入 `state.json.gates.<gate>` 的 `blocking_count==0` 为**唯一判据**（脚本作者真值，不可人工改写伪造）。**严禁在 `blocking_count>0` 时于质量报告或对话中声称"门禁通过"并流转**——这是本技能曾经最严重的失效模式（门禁实为 exit 1 却被口头记通过，导致高价值接口漏挖）。确属客观走不通的，按可行性原则(核心原则4)在对应 gate 的 `acknowledged` 逐条登记 `{match, reason_code, note}` 放行（reason_code 须∈固定集合且有 note，否则不生效）；下一阶段门禁开头会**强制读取并校验**上一门禁退出态，未清零直接拦截。详见 [references/quality-gates.md](references/quality-gates.md) 「门禁退出态与放行判据」。
8. **临时文件集中存放**：除本技能明确规定落盘路径的产物（`pentest-data/{id}/` 下各清单、报告、代理日志等）外，过程中临时生成的脚本、payload、中间数据文件一律放在该项目目录下的 `pentest-data/{project-id}/tmp/`（`init_project.py` 建项目时已创建，对应 `common.project_paths()` 的 `tmp_dir`），按需建子目录、文件名带 url-id 以避免并发冲突。

## 安全边界

准备阶段从用户输入获取并写入 `config.json`，全程遵守；受边界所限无法完成的工作在对应记录 `notes` 说明。

- **测试范围**：只测目标范围内的页面和接口（注意区分允许访问和允许安全测试）；用户未明确则默认取目标路径下全部（写入 `config.scope`）。
- **默认禁止**：批量下载敏感数据（>50 条）；任何影响目标系统可用性的操作。
- **安全等级 `security_level`（high/medium/low，默认 high）**：
  - `high`：影响范围限于测试账号；不删除已有数据；禁止影响资金或其它不可回退操作。（真实生产环境）
  - `medium`：影响范围限于测试账号（含测试中注册的账号），可对其增删改/办理业务；其它账号仅读。（生产中的测试账号）
  - `low`：可对测试环境数据任意增删改查。（测试环境）

## 工作守则

用户以 `# 工作守则` 标记下发的补充规则，**最高优先级**，全程所有阶段与子代理严格遵守。

准备阶段及后续任意时刻，用户在下发任务或交流中输入 `# 工作守则` 标记时，主代理将该标记之后的全部内容**完整写入** `config.json` 的 `work_guidelines` 字段（多次下发则追加保全既有条目，不丢弃）。`config.json` 为单一事实源，各阶段与子代理受调度时自读 `work_guidelines` 并遵守；受守则所限无法完成的工作在对应记录 `notes` 说明。

## 工具使用

- **playwright**（`browser_*`）：默认的页面访问与交互（走查、表单、触发交互、`browser_snapshot` 枚举元素）。
- **curl**：接口探测、下载 JS/HTML、构造漏洞 payload——**必须走代理**（`-x http://127.0.0.1:<config.proxy_port>`，端口取自 config.json、默认 24304；证书见代理 README）。
- **python 脚本**：批量探测（如权限矩阵验证），耗时较长的脚本运行应该使用后台bash任务的方式调用，避免阻塞会话——**必须走代理**。
- **代理服务器**：全程开启，用法见 [scripts/proxy/README.md](scripts/proxy/README.md)。

## 工作流程（四阶段 + 报告汇总）

按需断点续跑；`state.json` 记录当前 `phase` 与各阶段状态。四阶段测试完成、威胁收敛门禁通过后进入报告汇总收尾。每阶段详情见对应 reference。

### 阶段一 · 准备 → [references/phase-preparation.md](references/phase-preparation.md)

理解需求、校验子代理注册、初始化项目、启动并验证代理、建立会话池。

1. 校验子代理注册：确认 `pentest-vuln-miner` 与 `pentest-bypass-miner` 均在可用子代理列表中；任一缺失即阻塞，通知用户修复（对应 `.codex/agents/<name>.toml` 存在并重启会话）后再继续。
2. 检查 mitmproxy 可用（否则 `pip install -r scripts/proxy/requirements.txt`）。
3. `python .agents\skills\pentest-web-assess-pipeline\scripts\init_project.py --target <url>` → 建目录/登记/配置；补全 `config.json`（含把 `# 工作守则` 标记之后内容写入 `work_guidelines`）。
4. 后台启动代理：`python .agents\skills\pentest-web-assess-pipeline\scripts\proxy\start.py --config pentest-data\{id}\config.json --log-dir pentest-data\{id}\proxy-logs`（端口取自 config.proxy_port，默认 24304，用户指定则以用户指定为准）。
5. 校验 playwright 已配 `--proxy-server`（未配则提示用户，访问一次确认流量被记录）。
6. 用测试账号登录建会话池写 `sessions.json`（含 unauthenticated 基线）。

### 阶段二 · 广度建模 → [references/phase-breadth.md](references/phase-breadth.md)

全面测绘攻击面。五类工作非线性循环：**页面走查 / 页面解析 / JS 深度阅读 / 业务链遍历 / 威胁建模**。
页面解析对每个页面落盘渲染后 HTML 并全文阅读解析；所有发现的 JS（含开源库）登记 `js.jsonl`。
输出 `pages.jsonl`、`js.jsonl`、`business-chains.jsonl`、`threats.jsonl`。
攻击面/URL 覆盖清零（确保全部 URL 已纳入清单）后，对**全部 page/api URL** 跑 `permission_probe.py` 做
**权限矩阵验证**（未登录基线 + 各角色逐 URL 访问控制），将 `judgment=abnormal`（越权/未授权）逐条
**补入 `threats.jsonl`** 作为攻击面威胁。结束过广度建模质量门禁（见下）。

### 阶段三 · 漏洞挖掘 → [references/phase-vuln-mining.md](references/phase-vuln-mining.md)

进入阶段先用 `build_mining_scope.py` 固化必挖清单基线 `mining-scope.json`（作覆盖度硬门禁；挖掘阶段 payload 产生的
新 URL/参数不入必挖），再从 `url-inventory.json` 逐 URL 逐参数挖掘漏洞：**所有 page/api URL 均调度固化子代理
`pentest-vuln-miner`** 挖掘（定义在 `.codex/agents/`，方法论/路径/cookie自取规则已固化，**调度只需传 project-id + url-id**；
滚动补位、≤3 并发）。**主代理负责任务编排、调度、验收、整合**——任务队列**优先编排有威胁关联的 URL**
（该 URL 出现在任一 `threats.jsonl.related_objects`），再排其余有参数 URL（每任务 ≤5），最后无参数 URL（每任务 ≤15）。
子代理逐参数比对漏洞清单并实测，产出 `vuln-matrix/{id}.json`，**提交前经 `check_matrix.py` 自检矩阵合规**；发现漏洞出报告
`VULN-VD-{URLID}-NNNN` 并登记。回填 `url-inventory.json` 挖掘进度。结束过漏洞挖掘质量门禁（见下）。

**执行铁则**：子代理**逐 URL 独立挖掘**——每个 URL 严格按设计流程做独立的逐参数挖掘，不读取威胁清单、不受既有威胁建模与安全测试结论影响，避免锚定偏置；多次实践表明这种独立性能有效弥补前期工作的不足。主代理依威胁关联对任务队列排序仅是**调度优先级**，不改变任何单个 URL 的独立挖掘方式与结论。

### 阶段四 · 威胁收敛 → [references/phase-threat-convergence.md](references/phase-threat-convergence.md)

在完整挖掘产出之上收口。单一并发池、最多 3 个后台子代理滚动补位，混排两类工作：
- **威胁消账**：遍历 `threats.jsonl`，每条威胁映射到挖掘产出——命中某 `VULN-VD` 报告则 `confirmed`+引用报告号，
  相关 URL 矩阵结论为不可利用则 `excluded`+引用矩阵证据；找不到对应结论（缺账）则以补充测试调度
  `pentest-vuln-miner` 补测相关 URL，回收后再消账。
- **专项绕过**：`build_bypass_list.py` 汇集全部 `filtered` 矩阵条目为 `bypass-list.json`，**按漏洞类型分组、每任务 ≤5 个同类型 URL**
  调度绕过子代理 `pentest-bypass-miner` 做多族绕过——某 URL 突破即在同批其他 URL 复用该手法，主代理向后续同类型批次下发时
  携带已成功手法作提示；突破则条目转 `found` 出 `VULN-VD-{URLID}-NNNN` 报告，仍绕不过则保持 `filtered` 并扩充证据。

**主代理负责调度、验收、整合**。结束过威胁收敛质量门禁（见下）。

### 阶段五 · 报告汇总 → [references/phase-reporting.md](references/phase-reporting.md)

威胁收敛质量门禁通过后，运行 `build_report.py` 把四阶段结构化数据与已批准的逐份漏洞报告
**自动汇总**为完整评估报告，并渲染 **HTML** 与 **DOCX** 两版（内容一致），落 `pentest-data/{id}/report/`。
报告含测试概述 / 测试账号 / 攻击面测绘 / 漏洞统计 / 漏洞详情（仅 `approved`，按危害降序嵌入正文）/
威胁收敛结论 / 被防护与残余缺口 / 修复建议 / 质量门禁退出态。主代理可润色生成的 md 后用 `render_report.py` 重渲染。
报告渲染完成后运行 `proxy/stop.py` 关闭准备阶段长驻的记录代理，释放端口、停止抓包，作为全流程收尾。

## 质量门禁 → [references/quality-gates.md](references/quality-gates.md)

每阶段结束前必过：先脚本硬检查、再 AI 语义复核，处置所有问题并重验通过后输出质量检查报告才可流转。

- 广度：`build_url_inventory.py`（生成 URL 清单）→ `build_retest_list.py`（生成补测清单）→ `extract_page_urls.py`（页面候选 URL 软核验）→ `extract_static_params.py`（静态请求参数基准）→ `check_breadth.py`（硬检查，攻击面/URL 覆盖清零）→ `permission_probe.py`（全 URL 权限矩阵、异常项补入威胁清单）→ 重跑 `check_breadth.py`（含权限矩阵覆盖）清零 → AI 复核。
- 挖掘：`build_mining_scope.py`（进入阶段前固化必挖清单基线）→ `check_vuln_mining.py`（硬检查：必挖清单覆盖 / 参数矩阵 / 报告登记）→ AI 复核（抽查未发现/存疑、基线外新增项处置）。
- 收敛：`build_bypass_list.py`（汇集 filtered 绕过台账）→ `check_threat_convergence.py`（硬检查：威胁消账 / 绕过台账 / 报告清单）→ AI 复核（消账映射、绕过与报告质量）。

## 脚本清单（`scripts/`，均接受 `--project <id>`，数据根默认 `pentest-data`）

| 脚本                           | 用途                                                                          | 阶段      |
| ------------------------------ | ----------------------------------------------------------------------------- | --------- |
| `init_project.py`            | 推导 project-id、建目录、登记 index.json、初始化 config/state（幂等/断点）    | 准备      |
| `proxy/start.py`             | 启动记录代理（mitmdump + recorder.py）                                        | 准备~全程 |
| `proxy/stop.py`              | 停止记录代理（按 config.proxy_port 结束监听进程，幂等收尾）                   | 报告/收尾 |
| `build_url_inventory.py`     | 从 `url_index.jsonl` 生成/更新 URL 清单（幂等，只增不改状态）               | 广度门禁  |
| `build_retest_list.py`       | 前向汇集 pages/js 已登记接口∩`failed_index` 成补测清单（研判台账，幂等）    | 广度门禁 |
| `extract_page_urls.py`       | 从页面落盘 HTML 枚举候选 URL 与登记清单对比（软核验，供 AI 复核）             | 广度门禁  |
| `extract_static_params.py`   | 从页面/JS 内联请求体静态提取每接口「应有参数」基准（`url-static-params.json`，供参数覆盖门禁） | 广度门禁  |
| `permission_probe.py`        | 多角色越权探测与判定（页面/接口分流、禁跟随重定向、会话校验），产出权限矩阵   | 广度门禁  |
| `check_breadth.py`           | 广度建模门禁——机器硬检查（含参数覆盖 + 权限矩阵覆盖 + 页面型越权反向抽查）   | 广度门禁  |
| `extract_url_context.py`     | 按 URL 提取 pages/js/业务链关联记录 →`url-context/{id}.json`               | 挖掘/收敛 |
| `register_report.py`         | 分配漏洞报告编号并登记 `vuln-reports.json`                                  | 挖掘/收敛 |
| `build_mining_scope.py`      | 固化漏洞挖掘必挖清单基线 `mining-scope.json`（进入阶段前冻结；`--add` 追加正规新接口） | 挖掘门禁  |
| `check_matrix.py`            | 参数漏洞矩阵自检（子代理提交前，规则与挖掘门禁同源，逐 url-id 校验矩阵合规）   | 挖掘      |
| `check_vuln_mining.py`       | 漏洞挖掘门禁——必挖清单覆盖 / 参数矩阵 / 报告登记 / 一致性硬检查              | 挖掘门禁  |
| `build_bypass_list.py`       | 汇集全部 `filtered` 矩阵条目成绕过台账 `bypass-list.json`（幂等）            | 收敛门禁 |
| `check_threat_convergence.py`| 威胁收敛门禁——威胁消账 / 绕过台账 / 报告清单硬检查                          | 收敛门禁 |
| `build_report.py`            | 汇总四阶段数据与已批准报告 → 完整评估报告 md，并渲染 HTML+DOCX（落 `report/`） | 报告      |
| `render_report.py`           | 报告渲染器 Markdown → HTML+DOCX（模块+CLI，供 build_report 调用或独立重渲染） | 报告      |
| `common.py`                  | 共享工具（读写/时间戳/ID/枚举常量），被上述脚本导入                           | —        |

## 数据目录（工作目录下 `pentest-data/`）

```
pentest-data/
├── index.json                                  项目清单（根级）
└── {project-id}/
    ├── config.json  state.json  sessions.json
    ├── pages.jsonl  js.jsonl  business-chains.jsonl  threats.jsonl
    ├── url-inventory.json  mining-scope.json  url-static-params.json  retest-list.json  bypass-list.json  vuln-reports.json
    ├── pages-html/{PAGExxxx}.html  js-files/  permission-matrix/{URLxxxxx}.json
    ├── reports/{vuln_id}.md  vuln-matrix/{URLxxxxx}.json  url-context/{URLxxxxx}.json
    ├── report/{id}-report-{YYYYMMDD}.{md,html,docx}   汇总评估报告（阶段五产出）
    ├── proxy-logs/  (url_index.jsonl / requests/ / params/ …)
    └── tmp/                                         过程临时脚本/payload/中间产物
```
