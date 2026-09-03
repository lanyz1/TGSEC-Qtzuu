"""L1 瞬时感官记忆（对标 Atkinson-Shiffrin 感觉记忆 + LOP 加工水平）。

职责：缓冲本轮挖洞的原始观察/对话；按 LOP 深浅分级——浅层（闲聊/无价值）
丢弃，深层（目标资产、漏洞特征、利用条件、关键数据）→ 写入工作记忆。

★改造点★：原方案在 clean_useless() 里调用 llm.invoke(prompt) 做深浅分类。
本系统不配大模型——`classify()` 只**产出分类 prompt**，由 Claude Code
作为大脑自行执行分类，再调用 `commit_classify()` 回写 HIGH 内容、丢弃 LOW。
"""
from .config import Config
from .backends import FileKVBackend


class InstantMemory:
    def __init__(self, session_id, kv: FileKVBackend = None):
        self.sid = session_id
        self.r = kv or FileKVBackend()
        self.key = f"instant:{session_id}"

    # ---- 写入 ----
    def add_msg(self, role, content):
        """对标原 add_msg：写入原始消息，溢出则按保留最近比例裁剪。"""
        msgs = self.r.lrange(self.key, 0, -1)
        msgs.append(f"{role}:{content}")
        if len("\n".join(msgs)) > Config.INSTANT_MAX_TOKEN * 0.9:
            keep = int(len(msgs) * Config.INSTANT_KEEP_RATIO)
            msgs = msgs[-keep:] if keep else msgs[-1:]
        self.r.delete(self.key)
        self.r.rpush(self.key, *msgs)
        return "\n".join(msgs)

    def raw(self):
        return "\n".join(self.r.lrange(self.key, 0, -1))

    # ---- LOP 深浅分级（认知步：出 prompt）----
    def classify_prompt(self):
        """产出 LOP 分级 prompt，供 Claude Code 执行。

        返回 dict：{prompt, raw, hint}。Claude Code 读 prompt、对 raw 做分类，
        输出带【LOW】/【HIGH】标记的分段，再调 commit_classify(标记文本)。
        """
        raw = self.raw()
        prompt = f"""区分下面对话/观察内容：
1.浅层信息(闲聊、无价值废话、泛泛描述):标记【LOW】
2.深层信息(目标资产指纹、漏洞特征、利用条件、关键数据、规则约束、PoC要点):标记【HIGH】
原文:{raw}
只输出标记+分段内容，格式如:
【HIGH】...
【LOW】...
【HIGH】..."""
        return {"prompt": prompt, "raw": raw, "hint": "执行后把带【LOW】【HIGH】标记的完整文本回传给 commit-classify"}

    def commit_classify(self, marked_text):
        """对标原 split_level + clean_useless：解析标记，保留 HIGH，丢弃 LOW。"""
        low, high = [], []
        for seg in marked_text.split("【"):
            if "LOW】" in seg:
                low.append(seg.split("】", 1)[1] if "】" in seg else "")
            elif "HIGH】" in seg:
                high.append(seg.split("】", 1)[1] if "】" in seg else "")
        high_text = "\n".join(high).strip()
        self.r.delete(self.key)  # 瞬时缓冲清空（已加工）
        return {"high": high_text, "low": "\n".join(low).strip(),
                "high_lines": high_text.count("\n") + 1 if high_text else 0}
