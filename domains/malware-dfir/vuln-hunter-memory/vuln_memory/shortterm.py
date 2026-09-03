"""L3 短时向量记忆（对标 FAISS，7 天有效期 + 艾宾浩斯衰减）。

职责：把工作记忆融合出的场景摘要、阶段性结论、已验证线索向量化入库，
供后续按语义相似度召回。7 天过期，长期未调用权重衰减。
"""
import time

from .backends import VectorIndex
from .embeddings import get_embedder


class ShortTermMem:
    def __init__(self, index: VectorIndex = None):
        self.vector_store = index or VectorIndex()
        self.embedder = get_embedder()

    def save_memory(self, content, session=None, ts=None):
        ts = ts if ts is not None else time.time()
        vec = self.embedder.embed(content)
        self.vector_store.add(content, vec, session, ts)
        return {"saved": True, "chars": len(content), "ts": ts}

    def recall_memory(self, query, top_k=3, session=None):
        qvec = self.embedder.embed(query)
        hits = self.vector_store.search(qvec, top_k=top_k, session=session)
        out = []
        for score, d in hits:
            out.append({
                "score": round(score, 4),
                "content": d["content"],
                "ts": d["ts"],
                "session": d.get("session"),
            })
        return out

    def auto_expire_clean(self, now_ts=None):
        now_ts = now_ts if now_ts is not None else time.time()
        self.vector_store.expire_clean(now_ts)

    def decay_weights(self, now_ts=None):
        now_ts = now_ts if now_ts is not None else time.time()
        self.vector_store.decay_weights(now_ts)

    def all_contents(self):
        return [d["content"] for d in self.vector_store.all_docs()]
