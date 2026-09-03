---
name: vuln-sub
description: 漏洞挖掘项目完成后，手动触发提炼蒸馏流程——汇总本次会话所有挖洞成果，提取实战经验，蒸馏进长时图谱（永久跨目标可召回）。用法：直接输入 /sub，无需参数。
---

# /sub — 挖洞项目完结蒸馏

## 触发方式
```
/sub
```
无需参数。执行时自动从当前会话上下文中汇总所有漏洞挖掘成果并蒸馏。

## 执行流程

当用户调用 `/sub` 时，按以下步骤完整执行：

### Step 1：汇总本次项目成果
- 回顾当前会话中的所有漏洞发现、测试结论、技术细节
- 如果有对应的 session，先 `recall --session target_<目标> --query "全部"` 拉取历史记录
- 整理成结构化摘要：目标信息、技术栈、发现的漏洞、失败的尝试、关键经验

### Step 2：执行 distill 获取蒸馏 prompt
```bash
PYTHONIOENCODING=utf-8 python vulnmem.py distill
```
如果 distill 返回 `"empty": true`（短时层无素材），跳过 distill，直接用 Step 1 的汇总内容手动构造蒸馏三元组。

### Step 3：执行蒸馏（你作为大脑）
根据 distill 返回的 prompt（或 Step 1 的汇总），提取实体-关系三元组 JSON 数组。

重点提炼：
- **可复用的攻击模式**（Pattern）：payload模板、绕过技巧、上下文条件
- **目标特征与漏洞关联**（Target → Vuln）：什么技术栈/配置容易出什么漏洞
- **防御机制与绕过关系**（Filter ← bypasses ← Pattern）
- **利用条件与前置依赖**（Condition → enables → Vuln）
- **失败教训**（某种测试为什么不work，避免下次重复踩坑）

实体类型参考：Target, Asset, Service, Vuln, CVE, Payload, Pattern, Sink, Fix, Tool, Condition, Filter

### Step 4：commit-kg 写入图谱
```bash
PYTHONIOENCODING=utf-8 python vulnmem.py commit-kg --content - << 'KGJSON'
[蒸馏的JSON数组]
KGJSON
```

### Step 5：保存实战经验到短时层（补充语义细节）
用 `save-short` 存一条精炼的实战经验总结（自然语言，补充图谱三元组无法表达的上下文和判断逻辑）：
```bash
PYTHONIOENCODING=utf-8 python vulnmem.py save-short --content - << 'EOF'
[实战经验总结文本]
EOF
```

### Step 6：输出完成报告
向用户展示：
- 蒸馏了多少条三元组
- 当前图谱规模（节点/边数）
- 核心提炼的经验要点（3-5条）
- 下次遇到类似目标时如何 recall

## 输出格式示例
```
蒸馏完成：
- 写入图谱：15条三元组（当前 180 nodes / 120 edges）
- 核心经验：
  1. xxx技术栈 + yyy配置 = zzz漏洞高概率存在
  2. aaa绕过bbb的通用模式：payload模板
  3. ccc参数在ddd上下文不可利用的原因
- 召回方式：python vulnmem.py recall --query "关键词"
```

## 注意事项
- 蒸馏的重点是**可跨目标复用的经验**，不是具体目标的数据（IP、密码等不入图谱）
- 失败经验同样重要——"为什么某个思路不work"能避免下次浪费时间
- 如果本次项目产出了漏洞报告文件，在经验总结中注明文件路径方便日后参考

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
