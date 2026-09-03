---
name: vuln-memory
description: 仿生人类四层记忆模型漏洞挖掘记忆系统。在漏洞挖掘工作流中按四层（瞬时/工作/短时/长时）调用 vulnmem CLI 进行记忆的写入、分级、融合、召回与固化。所有需要"思考"的步骤（LOP 深浅分类、场景融合、实体关系蒸馏）由 Claude Code 自身作为大脑执行——记忆系统不配单独大模型。触发场景：挖洞的目标侦察、漏洞分析、利用验证、结论固化各阶段，以及跨目标/跨会话调用历史经验时。
---

# 四层记忆 × Claude Code 漏洞挖掘

## 它是什么
一套融入 Claude Code 挖洞工作流的记忆系统，对标《仿生人类四层记忆模型》：
- L1 瞬时记忆：缓冲本轮原始观察，LOP 深浅分级，浅层丢弃、深层保留
- L2 工作记忆：Baddeley 四组件，把深层信息融合成结构化场景摘要
- L3 短时向量记忆：7 天有效语义召回，带艾宾浩斯衰减
- L4 长时图谱记忆：海马蒸馏成【实体-关系-实体】固化进知识图谱

## 关键原则（务必遵守）
**记忆系统不配单独大模型**。所有认知步由你（Claude Code）同步执行：
- `classify` / `distill` / `fusion` 等 CLI 只**返回 prompt**
- 你按 prompt 自行分类/融合/蒸馏（你就是 LLM），再把结果回写对应 `commit-*` 命令
- 绝不要试图给记忆系统接入别的模型；它只是存取与编排

## 前置
项目根目录有 `vulnmem.py` 与 `vuln_memory/` 包。命令统一用：
```
python vulnmem.py <cmd> [opts]          # 或 python -m vuln_memory.cli <cmd>
```
所有命令输出 JSON。大段多行内容用 `--content -`（读 stdin）或 `--file PATH`。

CLI 命令速查：
| 命令 | 作用 | 谁思考 |
|---|---|---|
| `add` | 写原始观察到瞬时层 | 存储 |
| `classify` | 出 LOP 分级 prompt | **你执行** → `commit-classify` |
| `commit-classify` | 回写【LOW】【HIGH】标记文本 | 存储 |
| `fusion` | 出场景融合 prompt | **你执行** → `commit-fusion` |
| `commit-fusion` | 回写场景摘要入短时层 | 存储 |
| `save-short` | 直接存短时记忆 | 存储 |
| `recall-short` | 短时向量召回 | 存储 |
| `distill` | 出实体关系蒸馏 prompt | **你执行** → `commit-kg` |
| `commit-kg` | 把蒸馏 JSON 写回图谱 | 存储 |
| `recall-long` | 长时图谱召回 | 存储 |
| `recall` | 短时+长时综合召回=挖洞上下文 | 存储 |
| `reinforce` | 召回+强化摘要 prompt | **你执行**(可选回写) |
| `expire-clean` | 清理过期+衰减权重 | 存储 |
| `status` | 各层记忆状态 | 存储 |
| `save-state` | 保存挖洞项目工作流状态（断点续挖） | 存储 |
| `load-state` | 载入上次保存的项目状态 | 存储 |
| `sessions` | 列出所有保存过状态的会话 | 存储 |

## 会话 ID 约定
同一挖洞目标用一个 `--session`，如 `target_<域名或项目名>`。跨目标调用经验时用 `recall --session <目标> --query <...>`；想查全局图谱用 `recall-long`。

## 挖洞工作流中的集成节奏

### 阶段 0 · 开工先召回
开工前先按当前目标/技术栈召回历史经验，避免重复踩坑：
```
python vulnmem.py recall --session target_xxx --query "目标资产 指纹 攻击面"
```
把 `context_text` 读进上下文再开始侦察。

### 阶段 1 · 侦察（瞬时层活跃写入）
每收集到一条观察（指纹、端口、技术栈、路由、参数）就 `add`：
```
echo "Nginx 1.18.0 / 后端 Tomcat / /api/v2/upload 未鉴权" | \
  python vulnmem.py add --session target_xxx --role user
```
截图/拓扑/界面描述走 `--img`。观察攒到一定量（或换阶段前）做一次分级：
1. `python vulnmem.py classify --session target_xxx` → 拿到 prompt
2. **你**对 prompt 里的 raw 做深浅分类，输出带【HIGH】/【LOW】标记文本
3. 把标记文本回写：`echo '<带标记文本>' | python vulnmem.py commit-classify --session target_xxx`
   → HIGH 自动进工作记忆，LOW 丢弃

### 阶段 2 · 分析（工作→短时层）
线索聚拢后做场景融合：
1. `python vulnmem.py fusion --session target_xxx` → 拿到融合 prompt
2. **你**融合出"目标资产/攻击面/已确认线索/待验证假设"结构化摘要
3. 回写：`echo '<场景摘要>' | python vulnmem.py commit-fusion --session target_xxx`
   → 自动向量化入短时层

中途随时可 `recall-short --query "..."` 拉相似线索。

### 阶段 3 · 利用验证（召回驱动）
构造/验证 PoC 前先召回相关模式与历史坑：
```
python vulnmem.py recall --session target_xxx --query "上传绕过 路径穿越 SSRF"
```
新验证结论用 `save-short` 存阶段性结论，或 `add`+走一遍分级/融合。

### 阶段 4 · 固化（海马蒸馏 → 长时图谱）
挖到结论/漏洞确认后，固化成永久结构化记忆：
1. `python vulnmem.py distill` → 拿到蒸馏 prompt（素材来自全部短时记忆）
2. **你**按 prompt 抽取【实体-关系-实体】，输出标准 JSON 数组：
   `[{"type":"Vuln","entity1":"任意文件上传","attrs1":{"cwe":"CWE-434"},
      "relation":"存在","type2":"Target","entity2":"target_xxx"},
    {"type":"Payload","entity1":"../shell.php","relation":"绕过","type2":"Vuln","entity2":"任意文件上传"}]`
3. 回写：`echo '<JSON数组>' | python vulnmem.py commit-kg`
   → 写入知识图谱，跨目标永久可召回

### 阶段间 · 记忆强化（可选）
对关键召回结果做强化摘要、加固记忆：`python vulnmem.py reinforce --query "..."`，按返回 prompt 自行摘要后可 `save-short` 回写。

### 收尾 · 维护
长跑后清理：`python vulnmem.py expire-clean`；看状态：`python vulnmem.py status --session target_xxx`。

## 失败/降级
- 默认零依赖哈希向量化，离线即时可跑，无需安装任何包。
- 想用真语义向量：设环境变量 `VULNMEM_EMBED=sentence_transformers`（需已缓存 `all-MiniLM-L6-v2`，否则可能联网慢）。
- 切换到真实 Redis/Neo4j：实现 `vuln_memory/backends.py` 中对应接口即可，业务层不动。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
