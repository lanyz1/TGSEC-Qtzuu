"""
vuln_memory — 仿生人类四层记忆模型 × Claude Code 漏洞挖掘记忆系统
================================================================
对标《仿生人类四层记忆模型AI记忆系统设计方案》四层架构：
  L1 瞬时感官记忆  (instant)   —— Atkinson-Shiffrin + LOP 深浅编码
  L2 工作记忆      (working)   —— Baddeley 四组件
  L3 短时向量记忆  (shortterm) —— 7 天有效向量召回
  L4 长时图谱记忆  (longterm)  —— 海马蒸馏 + 知识图谱固化

关键改造（相对原方案）：
  原方案每层用 `llm = ChatOpenAI(...)` 自带大模型做认知操作。
  本系统**不单独配置大模型**——所有需要"思考"的步骤
  （LOP 深浅分类 / 场景融合 / 实体关系蒸馏 / 记忆强化摘要）
  一律改为「出 prompt → Claude Code 当大脑执行 → 回写结果」的契约。
  记忆系统只负责存取与编排，Claude Code 在挖洞工作流中同步充当大脑。
"""
from .config import Config
from .agent import HumanLikeMemoryAgent

__all__ = ["Config", "HumanLikeMemoryAgent"]
