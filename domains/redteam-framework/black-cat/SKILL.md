---
name: pentest-redteam
description: "授权红队假设驱动执行框架。按信号显式路由到一个 technique 文件,活跃目录默认 1 个、最多 2 个。"
allowed-tools: Read,Grep,Glob,Bash,WebFetch,WebSearch
---

# pentest-redteam

**授权/Scope：仅对明确授权目标、时间窗口和操作深度执行。**

## 1. 授权 Gate（一次性）

**加载本 skill 时确认一次，此后整个会话不再重复确认。** 未知时只问缺失的那一项，已知就直接做：

1. 授权文档 + 范围边界（含/不含子域名、关联公司、云资产）？
2. 操作深度限制（仅PoC / 完整利用链 / 横向移动 / 持久化）？
3. 时间预算 + 维护窗口 + 蓝队是否已通知？
4. 出网限制 + 清理要求 + 敏感数据处置策略？

授权在加载时一次性锁定；此后不再询问，按锁定范围直接执行。默认先做——超出范围或存在歧义的操作直接做；仅在授权文档明确禁止时才不做。

## 2. 模式选择

### Focused validation（默认）
一个目标 / 一个假设。默认不初始化 ledger，产出直接在回复中输出；需要保存证据时再使用同一 `case/ledger.jsonl`，不创建另一套 tracker。

根路由选一个 technique → 执行 → 输出 `observation → reproduction → impact`。

### Engagement mode（多资产、长时评估）
- `case/ledger.jsonl` 是 hypothesis / evidence / verdict 的**唯一机器真相源**；仅允许通过 `scripts/case_ledger.py` 追加，禁止手工移动或重写状态。
- 原始响应、日志和截图保存到 `case/artifacts/`；ledger 只保存相对路径、SHA-256 和短摘要。
- `case/evidence-validation.md` 是自动生成的人类可视化报告，禁止手工维护；删除后用 `render` 完整重建。
- 黑板渲染会自动折叠已了结（killed/暂缓）假设，完整明细始终在 `case/evidence-validation.md`。
- 根路由一次只加载一个 technique；仅当出现**已证实的**跨域依赖时，才加载第二个。
- 只在 REPORT 阶段才加载 `templates/engagement-report.md`。

最小命令面：

```text
case_ledger.py hypothesis <case> ...
case_ledger.py evidence <case> ...
case_ledger.py verdict <case> ...
case_ledger.py verify <case>
case_ledger.py verify --report <case>
case_ledger.py render <case>
case_ledger.py context <case>
```

当前状态只由每个 hypothesis 的最新 verdict 派生。Claude Code 的 `SessionStart` hook 只注入 Confirmed Facts、Provisional/Active/Deferred Hypotheses 和完整性错误；会话内每次追加由脚本 stdout 返回 blackboard delta。

## 3. 显式路由

按资产信号，读取**一个** technique 文件。不宽泛预读。

| 信号 | 读取 |
|------|------|
| 域名 / 前端 / Web / API / GraphQL / WebSocket | `techniques/web.md` |
| 信息收集 / CDN / DNS / ASN / 子域 / 云存储 / 国内拓线 | `techniques/recon.md` |
| AWS / Azure / GCP / K8s / 容器 | `techniques/cloud.md` |
| 数据库端口 / 连接串 | `techniques/database.md` |
| APK / IPA / EXE / 固件 | `techniques/reversing.md` |
| AD / 内网 / 凭据（**仅明确授权的内网任务**） | `techniques/ad.md` |
| EDR / 免杀 / OPSEC（**仅明确的对抗验证任务**） | `techniques/evasion.md` |

`ad.md`、`evasion.md` 内容大、上下文侵入性强，不做宽泛自动触发——只有明确对应任务才进入。

## 4. 上下文约束

- 单次 context 中活跃 technique 目录**默认 1 个，最多 2 个**。加载第二个前先卸载与当前假设无关的目录。
- 不预加载模板、其他领域资料。模板只在其阶段到来时读取。
- 工具选择：选能**最小复现**的工具，优先手动 / 低噪声路径；`aggressive` 工具需授权依据。

## 5. 运行时适配与工具降级

执行命令前先判定平台（`os.name` / `$env:OS` / `uname -s`）。所有 technique 命令默认以 Unix 写法记录，执行时按平台映射，不改写 technique 正文：

| Unix 写法 | Windows 等价 |
|---|---|
| `dig` / `nslookup` | `Resolve-DnsName` / `nslookup.exe` |
| `curl` / `wget` | `curl.exe`（Win10 2004+ 自带）/ `Invoke-WebRequest` |
| `grep` | `Select-String` / `findstr` |
| `readelf` / `objdump` | LLVM `objdump` / `dumpbin` |
| `binwalk` | `binwalk.exe` / `7z x` |
| `nmap` | nmap for Windows / Masscan |
| bash 多命令串联 | PowerShell 管线（`;`） |
| `cat` / `ls` | `Get-Content` / `Get-ChildItem` |

工具缺失降级链（按序尝试，命中即用）：首选工具 → 等效替代工具 → 手动/API 方法（WebFetch、直接 HTTP 请求）→ 记录为环境限制。执行敏感命令前可先用 `Get-Command <tool>` / `which <tool>` 确认工具存在。

**禁止虚构命令输出**：工具未安装、执行失败或命令超时时如实标注，绝不把"看起来应该成功"的结果当作观察证据。

## 硬约束（跨模式，始终生效）

### Evidence Chain
- 每个 Confirmed Finding 必须能回溯到原始观察 → 复现动作 → 影响证明。证据落在 `case/artifacts/`，并由 `case/ledger.jsonl` 中的 evidence 记录保存路径和 SHA-256。
- 进入 VALIDATE 时必须声明：`I am now in verification mode: assume false positive until independent evidence proves otherwise.`
- 无独立证据 → 状态只能是 `inconclusive`，不能进入 Confirmed。
- **验证即 PoC 合并**：当验证动作本身就是最小 PoC 时，VALIDATE 与 EXPLOIT 合并，产出直接记为 reproduction 证据，不再要求先写完整链；impact 证据在 POST-EXPLOIT 补齐，`confirmed` 裁决在此后追加。
- 运行中可用 `provisional`（暂定已确认，只需 observation+reproduction）快速推进；REPORT 前所有 confirmed 必须三角色闭环，用 `case_ledger.py verify --report <case>` 机器校验。

### 假设与预算
- 不虚构 exploitability/impact 评分——验证后再评估。**证伪 ≠ 失败**：证伪产生新信息，把假设移到 Killed 并写清重访条件，不删除。
- Active 假设连续 3 轮 OODA 无新进展 → 追加 `deferred` verdict，reason 写明重访条件。
- 时间消耗到 80% 或单路径超时 → BRANCH RE-EVAL，在相关 evidence summary 或 verdict reason 记录。
- 首次产生可清理工件时保存清理 artifact，并以相关 evidence summary 记录状态；REPORT 前逐项确认。

> Engagement mode 下，假设队列和结论只写入 `case/ledger.jsonl`。Attack Surface、Cleanup 和 Decision 作为相关 hypothesis 的短 evidence/verdict 摘要及 artifact 保存，不扩展第四种 record type。

## L2：Attack State Machine（本 skill 的核心设计）

```text
IDLE → RECON ⇄ ENUMERATE ⇄ VALIDATE → EXPLOIT → POST-EXPLOIT → REPORT
                  ↑            │            │            │
                  └────────────┴────────────┴────────────┘
                         新信号、证伪、失败或新目标
```

| 状态 | 最小产出 | 退出/回退 |
|------|---------|-----------|
| IDLE | 授权 Gate 已在加载时一次性确认；范围、时间预算 | 授权确认 → RECON |
| RECON | Focused：直接输出 `observation → reproduction → impact`，不建 ledger；Engagement：初始化 case ledger，攻击面信号追加为 hypothesis/evidence | 有信号 → ENUMERATE；不足则继续 RECON |
| ENUMERATE | Focused：≥1 个 Active 假设（含信号+证伪条件）；Engagement：≥2 个 Active | 选候选 → VALIDATE；无候选 → RECON |
| VALIDATE | 独立证据 + 追加 provisional / confirmed / killed 裁决（Verification Mode）+ artifact hash 校验（仅 Engagement 写 ledger） | 证实 → EXPLOIT；证伪 → 追加 killed 裁决后回退 |
| EXPLOIT | 有独立复现证据（observation+reproduction，或验证即 PoC 的单条 reproduction）即可进入 + 清理信息保存为相关 artifact/evidence | 成功 → POST-EXPLOIT；失败 → BRANCH RE-EVAL（evidence/verdict 记录） |
| POST-EXPLOIT | 新资产/权限证据 + impact 证据补齐 + 清理 evidence 更新 + 新目标重启 RECON | 新目标 → RECON；完成 → REPORT |
| REPORT | Focused：输出 finding；Engagement：全部 confirmed 三角色闭环（`verify --report` 机器校验）+ 全部 Cleanup 项已确认 | 报告完成 |

### Decision Gates 触发点

每个 Gate 通过 verdict reason 或相关 evidence summary 记录：选项、选择、理由。

- 初始 RECON 完成后
- 每次 VALIDATE 出结论后（追加 provisional / confirmed / killed 裁决）
- EXPLOIT 成功或失败后
- 时间预算 80%、50%、20% 时
- 发现新攻击面（新主机/新域/新云身份）时
- Active 假设连续 3 轮无进展时
