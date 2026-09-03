"""L4 长时海马蒸馏 + 知识图谱记忆（对标 Neo4j + 海马巩固）。

职责：把短时向量记忆里的内容蒸馏成【实体-关系-实体】，固化进知识图谱，
模拟睡眠期记忆巩固，形成永久结构化记忆；并按 query 做图谱召回。

★改造点★：原方案用 threading 后台循环 + llm.invoke 做蒸馏。本系统
`distill_prompt()` 只产出蒸馏 prompt，Claude Code 执行后回写 `commit_kg()`。
蒸馏由 Claude Code 在挖洞固化阶段触发（同步大脑），而非独立后台 LLM。
"""
import json

from .backends import GraphStore
from .shortterm import ShortTermMem


class LongTermMem:
    def __init__(self, short_mem: ShortTermMem = None, graph: GraphStore = None):
        self.short_mem = short_mem or ShortTermMem()
        self.graph = graph or GraphStore()

    # ---- 海马蒸馏（认知步：出 prompt）----
    def distill_prompt(self):
        """收集全部短时记忆，产出实体关系蒸馏 prompt。"""
        all_short = self.short_mem.all_contents()
        if not all_short:
            return {"prompt": None, "empty": True,
                    "hint": "短时记忆为空，无需蒸馏"}
        prompt = f"""从下列漏洞挖掘素材中提取【实体，属性，关系】，输出标准 JSON 数组。
实体类型建议：Target(目标) Asset(资产) Service(服务) Vuln(漏洞) CVE Payload(利用)
CVE Pattern(漏洞模式) Sink(污点汇聚点) Fix(修复) Tool Condition(利用条件) 等。
每条结构: {{"type":"...","entity1":"...","attrs1":{{...}},
        "relation":"...","type2":"...","entity2":"...","attrs2":{{...}}}}
素材:
{json.dumps(all_short, ensure_ascii=False, indent=0)}

仅输出 JSON 数组，不要解释。"""
        return {"prompt": prompt, "count": len(all_short), "empty": False}

    def commit_kg(self, items_json):
        """对标原 graph.create：解析 Claude Code 产出的 JSON 数组，写入图谱。

        items_json 可为 JSON 字符串或已解析列表。每条含
        type/entity1/[attrs1]/relation/type2/entity2/[attrs2]。
        """
        if isinstance(items_json, str):
            try:
                data = json.loads(items_json)
            except Exception as e:
                return {"ok": False, "error": f"JSON 解析失败: {e}"}
        else:
            data = items_json
        if not isinstance(data, list):
            return {"ok": False, "error": "需为 JSON 数组"}

        created = 0
        for item in data:
            try:
                n1 = {"type": item.get("type", "Entity"),
                      "name": item.get("entity1", "")}
                n1.update(item.get("attrs1", {}))
                n2 = {"type": item.get("type2", item.get("type", "Entity")),
                      "name": item.get("entity2", "")}
                n2.update(item.get("attrs2", {}))
                rel = item.get("relation", "RELATED")
                if n1["name"] and n2["name"]:
                    self.graph.create(n1, rel, n2)
                    created += 1
            except Exception:
                continue
        return {"ok": True, "created": created, "stats": self.graph.stats()}

    def kg_recall(self, query):
        rows = self.graph.recall(query)
        return rows

    def reinforce(self, query):
        """回忆强化（拓展项）：调取长时记忆后可重新摘要入库加固。
        这里只返回召回结果与可强化提示，真正摘要仍由 Claude Code 执行。"""
        rows = self.kg_recall(query)
        if not rows:
            return {"rows": [], "hint": "无相关长时记忆"}
        prompt = ("对以下图谱三元组做精简摘要，可用于加固记忆（可选回写到短时层）：\n"
                  + json.dumps(rows, ensure_ascii=False))
        return {"rows": rows, "reinforce_prompt": prompt}
