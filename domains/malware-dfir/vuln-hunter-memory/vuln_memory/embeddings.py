"""向量化组件。

记忆系统**不配置大模型**，但向量化是编码器（非生成式 LLM），属于存储侧
机制，可保留。为「可立即跑」：
  - 默认 HashingEmbedder：纯 Python 词哈希 TF 向量，零依赖，余弦相似召回；
  - 若环境已装 sentence-transformers，则自动升级为真语义向量。
"""
import hashlib
import os
import re
from functools import lru_cache

from .config import Config


def _tokenize(text: str):
    # 中英混合切词：英文按词、数字、非 ASCII 按字符 bigram 近似
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*|\d+|[^\s]", text)
    out = []
    non_ascii = [t for t in tokens if len(t) == 1 and not t.isascii()]
    word_tokens = [t.lower() for t in tokens if t not in non_ascii]
    out.extend(word_tokens)
    # CJK 字符做 2-gram
    cjk = "".join(non_ascii)
    for i in range(len(cjk) - 1):
        out.append(cjk[i:i + 2])
    if len(cjk) == 1:
        out.append(cjk)
    return out


class HashingEmbedder:
    """无依赖哈希 TF 向量化。可立即跑。"""

    dim = Config.EMBED_DIM

    def embed(self, text: str):
        toks = _tokenize(text)
        vec = [0.0] * self.dim
        for t in toks:
            h = int(hashlib.md5(t.encode("utf-8")).hexdigest(), 16) % self.dim
            vec[h] += 1.0
        # L2 归一
        norm = sum(v * v for v in vec) ** 0.5
        if norm:
            vec = [v / norm for v in vec]
        return vec

    def embed_batch(self, texts):
        return [self.embed(t) for t in texts]


class STEmbedder:
    """sentence-transformers 真语义向量（若已安装则自动启用）。"""

    def __init__(self):
        from sentence_transformers import SentenceTransformer
        self._m = SentenceTransformer(Config.ST_MODEL)
        self.dim = self._m.get_sentence_embedding_dimension()

    def embed(self, text: str):
        return self._m.encode(text, normalize_embeddings=True).tolist()

    def embed_batch(self, texts):
        return self._m.encode(texts, normalize_embeddings=True).tolist()


@lru_cache(maxsize=1)
def get_embedder():
    # 默认零依赖哈希向量化，离线、即时、可跑。
    # 设环境变量 VULNMEM_EMBED=sentence_transformers 启用真语义向量
    # （需联网/已缓存 all-MiniLM-L6-v2 模型）。
    if os.environ.get("VULNMEM_EMBED", "").lower() in ("st", "sentence_transformers", "1", "true"):
        try:
            return STEmbedder()
        except Exception:
            pass
    return HashingEmbedder()


def cosine(a, b):
    return sum(x * y for x, y in zip(a, b))
