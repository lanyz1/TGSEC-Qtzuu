"""L2 Baddeley 工作记忆（中央执行器 + 文本环路 + 视空画板 + 情景缓冲器）。

职责：把瞬时层筛出的深层信息纳入工作记忆——文本环路存文字线索，
视空画板存图像/拓扑/截图描述，情景缓冲器融合成结构化场景摘要，
供短时向量层入库与即时回取。

★改造点★：原方案 scene_fusion() 调 llm.invoke 做融合。本系统
`fusion_prompt()` 只产出融合 prompt，Claude Code 执行后回写 `commit_fusion()`。
"""
from .backends import FileKVBackend


class BaddeleyWorkingMem:
    def __init__(self, session_id, kv: FileKVBackend = None):
        self.sid = session_id
        self.r = kv or FileKVBackend()
        # 文本环路（phonological loop）
        self.text_loop_key = f"work:text:{session_id}"
        # 视空画板（visuospatial sketchpad）
        self.img_space_key = f"work:img:{session_id}"
        # 情景缓冲器（episodic buffer）
        self.buffer_key = f"work:buffer:{session_id}"

    def add_text(self, text):
        self.r.rpush(self.text_loop_key, text)
        from .config import Config
        if self.r.llen(self.text_loop_key) > Config.WORKING_TEXT_MAXLEN:
            self.r.lpop(self.text_loop_key)

    def add_multimodal(self, img_desc):
        """视空画板：存截图/拓扑图/界面结构的文字描述。"""
        self.r.rpush(self.img_space_key, img_desc)

    def text_data(self):
        return "\n".join(self.r.lrange(self.text_loop_key, 0, -1))

    def img_data(self):
        return "\n".join(self.r.lrange(self.img_space_key, 0, -1))

    def buffer(self):
        return self.r.get(self.buffer_key)

    # ---- 场景融合（认知步：出 prompt）----
    def fusion_prompt(self):
        """产出融合 prompt，Claude Code 执行后回写 commit_fusion。"""
        txt = self.text_data()
        img = self.img_data()
        prompt = f"""整合对话与图像/拓扑信息，精简为结构化场景摘要（用于漏洞挖掘上下文）。
对话文本:{txt}
图像/拓扑信息:{img}
输出要点：目标资产、攻击面、已确认线索、待验证假设。"""
        return {"prompt": prompt, "text": txt, "img": img}

    def commit_fusion(self, scene_summary):
        """情景缓冲器写入融合后的场景摘要，并清空文本/视空临时区。"""
        self.r.set(self.buffer_key, scene_summary)
        self.r.delete(self.text_loop_key)
        self.r.delete(self.img_space_key)
        return scene_summary
