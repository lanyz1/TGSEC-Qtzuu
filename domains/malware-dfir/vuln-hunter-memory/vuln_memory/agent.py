"""顶层调度 Agent —— 编排四层记忆流转。

对标原方案 HumanLikeMemoryAgent，但把所有 llm.invoke 改造为
「出 prompt / 收结果」契约，认知由 Claude Code 同步执行。

典型挖洞一轮（chat_step）改造后由 CLI 分步驱动：
  1) add            写入原始观察到瞬时层
  2) classify       瞬时层产出 LOP 分级 prompt → Claude Code 执行
  3) commit-classify 回写 HIGH → 工作记忆 add_text
  4) fusion         工作记忆产出融合 prompt → Claude Code 执行
  5) commit-fusion  回写场景摘要 → 短时层 save_memory
  6) recall         短时+长时召回，拼成挖洞上下文
  → Claude Code 据此上下文推进挖洞；结论稳定后 distill → commit-kg 固化

本类提供 Python 内的等价编排，CLI 是它的命令行映射。
"""
from .instant import InstantMemory
from .working import BaddeleyWorkingMem
from .shortterm import ShortTermMem
from .longterm import LongTermMem
from .backends import ProjectStore


class HumanLikeMemoryAgent:
    def __init__(self, session_id):
        self.sid = session_id
        self.instant = InstantMemory(session_id)
        self.working = BaddeleyWorkingMem(session_id)
        self.short = ShortTermMem()
        self.long = LongTermMem(self.short)
        self.project = ProjectStore()

    # ---- 1. 接收原始观察 ----
    def observe(self, role, content, img_info=None):
        self.instant.add_msg(role, content)
        if img_info:
            self.working.add_multimodal(img_info)
        return {"instant_len": self.instant.r.llen(self.instant.key)}

    # ---- 2. 出 LOP 分级 prompt ----
    def classify(self):
        return self.instant.classify_prompt()

    # ---- 3. 回写分级结果 ----
    def commit_classify(self, marked_text):
        res = self.instant.commit_classify(marked_text)
        if res["high"]:
            self.working.add_text(res["high"])
        return res

    # ---- 4. 出融合 prompt ----
    def fusion(self):
        return self.working.fusion_prompt()

    # ---- 5. 回写场景摘要入库 ----
    def commit_fusion(self, summary):
        self.working.commit_fusion(summary)
        return self.short.save_memory(summary, session=self.sid)

    # ---- 6. 召回上下文（短时+长时）----
    def recall(self, query, top_k=3):
        short_hits = self.short.recall_memory(query, top_k=top_k, session=self.sid)
        # 若本会话短时召回不足，跨会话全量补
        if len(short_hits) < top_k:
            extra = self.short.recall_memory(query, top_k=top_k)
            short_hits += [h for h in extra if h not in short_hits]
        long_rows = self.long.kg_recall(query)
        return {"short": short_hits, "long": long_rows,
                "context_text": self._build_context(short_hits, long_rows, query)}

    @staticmethod
    def _build_context(short_hits, long_rows, query):
        parts = []
        if short_hits:
            parts.append("【短时召回】")
            for h in short_hits:
                parts.append(f"- (s={h['score']}) {h['content']}")
        if long_rows:
            parts.append("【长时图谱】")
            for r in long_rows:
                parts.append(f"- {r['src']}({r['src_type']}) -[{r['rel']}]-> "
                             f"{r['dst']}({r['dst_type']})")
        if not parts:
            parts.append("（无相关记忆）")
        parts.append(f"【当前任务】{query}")
        return "\n".join(parts)

    # ---- 7. 蒸馏固化 ----
    def distill(self):
        return self.long.distill_prompt()

    def commit_kg(self, items_json):
        return self.long.commit_kg(items_json)

    # ---- 8. 记忆强化 ----
    def reinforce(self, query):
        return self.long.reinforce(query)

    def status(self):
        return {
            "session": self.sid,
            "instant_msgs": self.instant.r.llen(self.instant.key),
            "working_text": self.working.r.llen(self.working.text_loop_key),
            "working_img": self.working.r.llen(self.working.img_space_key),
            "working_buffer": "yes" if self.working.buffer() else "no",
            "short_docs": len(self.short.all_contents()),
            "long_graph": self.long.graph.stats(),
        }

    # ---- 9. 项目工作流状态（断点续挖）----
    def save_state(self, state):
        """state 为 dict：target/phase/completed/pending/hypotheses/next/context 等。"""
        if not isinstance(state, dict):
            return {"ok": False, "error": "state 需为 JSON 对象"}
        prev = self.project.load(self.sid) or {}
        prev.update(state)
        self.project.save(self.sid, prev)
        return {"ok": True, "saved_to": self.sid, "state": prev}

    def load_state(self):
        return self.project.load(self.sid)

    def list_sessions(self):
        return self.project.list_sessions()
