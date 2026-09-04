# 报告汇总阶段 SOP（主代理执行）

# 工作目标

威胁收敛质量门禁通过后，把四阶段结构化数据与已批准的逐份漏洞报告**自动汇总**为一份完整 WEB 应用安全评估报告，
并渲染 **HTML**（查看/存档）与 **DOCX**（交付）两个版本（内容一致），落 `pentest-data/{id}/report/`。

# 前置条件

- 威胁收敛门禁 `state.json.gates.threat_convergence.blocking_count==0`（门禁未过时仍可出报告，但概述会如实标注退出态、标为阶段性结果）。
- 漏洞报告已由主代理逐份验收并登记 `vuln-reports.json`（仅 `review_status=approved` 的报告进入漏洞详情；`pending_review`/`rejected` 仅计数不入详情）。
- `python-docx` 可用（缺失则 `pip install python-docx`）。

# 工作流程

## 1. 生成报告（脚本自动汇总 + 渲染）

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\build_report.py --project {id}
```

脚本读取 `config.json`、`state.json`（gates）、`vuln-reports.json` + `reports/{vuln_id}.md`、`threats.jsonl`、
`url-inventory.json`、`pages.jsonl`/`js.jsonl`/`business-chains.jsonl`、`permission-matrix/*.json`、
`bypass-list.json`、`retest-list.json`、`sessions.json`，拼出完整报告 Markdown 并渲染，产出：

```
pentest-data/{id}/report/{id}-report-{YYYYMMDD}.md    Markdown 源
pentest-data/{id}/report/{id}-report-{YYYYMMDD}.html  HTML 版
pentest-data/{id}/report/{id}-report-{YYYYMMDD}.docx  DOCX 版
```

系统名默认取 `config.target` 路径末段（可用 `--title 系统名` 覆盖）。

## 2. 报告结构

| 章节 | 内容 |
| --- | --- |
| 封面 | 系统名 + 目标/范围/安全等级/测试时间/测试方法/漏洞统计 |
| 1. 测试概述 | 目标·范围·方法·整体结论·三门禁退出态 |
| 2. 测试账号与角色 | `config.test_accounts` + `sessions` 角色/登录状态 |
| 3. 攻击面测绘概览 | 页面/JS/业务链/接口计数 + 权限矩阵越权异常 + 业务链走通分布 |
| 4. 漏洞统计概览 | 危害等级分布 + 漏洞类型分布 |
| 5. 漏洞详情 | 每个 `approved` 报告，按危害降序，嵌入 `reports/*.md` 正文 |
| 6. 威胁收敛结论 | `threats` 状态分布 + `confirmed`→报告映射 |
| 7. 被防护与残余缺口 | `bypass-list` 被防护项 + 门禁 `accepted_residual` + `blocked` 未补测项 |
| 8. 修复建议汇总 | 各漏洞修复要点（从报告「修复建议」提取聚合） |
| 附录 | 三阶段质量门禁 `exit`/`blocking_count` 退出态 |

## 3. 润色与重渲染（可选）

生成的 Markdown 可直接编辑（补充执行摘要叙述、调整措辞），再单独渲染两版：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\render_report.py pentest-data\{id}\report\{id}-report-{YYYYMMDD}.md
```

`render_report.py` 亦可对任意符合约定（首行 `# 标题` + `> 元信息` + `---` + 正文）的 Markdown 渲染。

## 4. 关闭代理服务器（收尾）

报告渲染完成、测试结束后，停止准备阶段长驻的记录代理，释放端口、停止抓包：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\proxy\stop.py `
  --config pentest-data\{id}\config.json
```

- 读 `config.proxy_port`，结束监听该端口的代理进程；与在代理终端按 `Ctrl+C` 等效，但可脚本化、跨会话可靠。
- **幂等**：端口无监听进程（已停止）则跳过并正常退出，不报错。
- 若后续用户提出补充测试，需重跑相关阶段前，再按准备阶段第 2 步重新启动代理。

# 交付提示

- 报告含**完整请求/响应片段（可能含 Cookie/Token 等凭据）**，交付前加密或内网传输。
- `pentest-data/` 建议纳入 `.gitignore`，避免凭据与报告随仓库外泄。
- 用户提出补充测试后，回填相关数据文件、重跑对应门禁，再重新运行 `build_report.py` 刷新报告。
