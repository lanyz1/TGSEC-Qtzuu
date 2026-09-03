"""文件级存储后端 + 可插拔真实中间件接口。

为「可立即跑」，所有存储落到本地文件：
  - 瞬时/工作记忆 -> JSON 文件（对标 Redis list/set/string）
  - 短时向量记忆   -> numpy 数组 + meta.json（对标 FAISS）
  - 长时图谱记忆   -> networkx 图 + kg.json（对标 Neo4j）

`RedisLikeBackend` / `GraphBackend` 为抽象接口，可随时实现
RedisBackend / Neo4jBackend 替换，业务层（四层模块）不感知存储介质。
"""
import json
import os
import threading

from .config import Config

Config.ensure_dirs()


# ---------------------- JSON 文件底层工具 ----------------------
def _path(d, name):
    return os.path.join(d, name + ".json")


def json_load(d, name, default):
    p = _path(d, name)
    if not os.path.exists(p):
        return default
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def json_save(d, name, data):
    p = _path(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ---------------------- Redis-Like（list/string 语义）-----------------------
class FileKVBackend:
    """模拟 Redis 的 list (rpush/lrange/lpop/llen) 与 string (set/get)。"""

    def _key_dir(self, key):
        return Config.WORKING_DIR if key.startswith("work") else Config.INSTANT_DIR

    def _list_get(self, key, default=None):
        name = key.replace(":", "__")
        return json_load(self._key_dir(key), name, default if default is not None else [])

    def _list_set(self, key, val):
        name = key.replace(":", "__")
        json_save(self._key_dir(key), name, val)

    def rpush(self, key, *vals):
        lst = self._list_get(key, [])
        lst.extend(vals)
        self._list_set(key, lst)
        return len(lst)

    def lrange(self, key, start, end):
        lst = self._list_get(key, [])
        if end == -1:
            return lst[start:]
        return lst[start:end + 1]

    def llen(self, key):
        return len(self._list_get(key, []))

    def lpop(self, key):
        lst = self._list_get(key, [])
        if not lst:
            return None
        v = lst.pop(0)
        self._list_set(key, lst)
        return v

    def delete(self, key):
        name = key.replace(":", "__")
        d = Config.WORKING_DIR if key.startswith("work") else Config.INSTANT_DIR
        p = _path(d, name)
        if os.path.exists(p):
            os.remove(p)

    def set(self, key, val):
        d = Config.WORKING_DIR
        name = key.replace(":", "__")
        json_save(d, name, {"_str": val})

    def get(self, key):
        name = key.replace(":", "__")
        d = json_load(Config.WORKING_DIR, name, None)
        return d.get("_str") if d else None


class RedisLikeBackend(FileKVBackend):
    """抽象接口：可子类化为真实 Redis 后端。"""

    @classmethod
    def real_redis(cls, host, port, db):
        try:
            import redis  # noqa
        except Exception:
            return None
        # 真实实现略；如需可在此接入 redis.Redis(...) 并覆写各方法
        return None


# ---------------------- 向量索引（对标 FAISS）-----------------------
class VectorIndex:
    """numpy 余弦相似向量索引 + 7 天过期 + 艾宾浩斯衰减权重。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._meta = json_load(Config.SHORT_DIR, "meta", {"docs": []})
        # docs: [{id, content, vec:[...], ts, weight, session}]

    def _persist(self):
        json_save(Config.SHORT_DIR, "meta", self._meta)

    def add(self, content, vec, session, ts):
        with self._lock:
            self._meta["docs"].append({
                "id": len(self._meta["docs"]),
                "content": content,
                "vec": list(vec),
                "ts": ts,
                "weight": 1.0,
                "session": session,
            })
            self._persist()

    def search(self, qvec, top_k=3, session=None):
        from .embeddings import cosine
        with self._lock:
            scored = []
            for d in self._meta["docs"]:
                if session and d.get("session") != session:
                    continue
                s = cosine(qvec, d["vec"]) * d.get("weight", 1.0)
                scored.append((s, d))
            scored.sort(key=lambda x: x[0], reverse=True)
            return scored[:top_k]

    def all_docs(self):
        return list(self._meta.get("docs", []))

    def expire_clean(self, now_ts):
        from .config import Config as C
        sec = C.SHORT_MEM_EXPIRE.total_seconds()
        with self._lock:
            kept = []
            for d in self._meta["docs"]:
                if now_ts - d["ts"] < sec:
                    kept.append(d)
            self._meta["docs"] = kept
            self._persist()

    def decay_weights(self, now_ts):
        """艾宾浩斯遗忘曲线：长期未调用的向量权重衰减。"""
        with self._lock:
            for d in self._meta["docs"]:
                age_days = max(0.0, (now_ts - d["ts"]) / 86400)
                d["weight"] = round(max(0.05, 1.0 / (1.0 + 0.3 * age_days)), 4)
            self._persist()


# ---------------------- 知识图谱（对标 Neo4j）-----------------------
class GraphStore:
    """networkx 图持久化为 kg.json。对标 Neo4j 的 (Node)-[REL]->(Node)。"""

    def __init__(self):
        try:
            import networkx as nx
            self._nx = nx
        except Exception:
            self._nx = None
        self._load()

    def _path(self):
        return os.path.join(Config.LONG_DIR, "kg.json")

    def _load(self):
        data = json_load(Config.LONG_DIR, "kg", {"nodes": [], "edges": []})
        self._nodes = data.get("nodes", [])
        self._edges = data.get("edges", [])

    def _persist(self):
        json_save(Config.LONG_DIR, "kg", {"nodes": self._nodes, "edges": self._edges})

    @staticmethod
    def _node_key(ntype, name):
        return f"{ntype}::{name}"

    def create(self, n1, rel, n2):
        """n1/n2: dict {type,name, **attrs} ; rel: str or dict"""
        k1 = self._node_key(n1["type"], n1["name"])
        k2 = self._node_key(n2["type"], n2["name"])
        # upsert n1
        n1d = next((x for x in self._nodes if x["key"] == k1), None)
        if n1d is None:
            n1d = {"key": k1, "type": n1["type"], "name": n1["name"], "attrs": {}}
            self._nodes.append(n1d)
        n1d["attrs"].update({k: v for k, v in n1.items() if k not in ("type", "name")})
        # upsert n2
        n2d = next((x for x in self._nodes if x["key"] == k2), None)
        if n2d is None:
            n2d = {"key": k2, "type": n2["type"], "name": n2["name"], "attrs": {}}
            self._nodes.append(n2d)
        n2d["attrs"].update({k: v for k, v in n2.items() if k not in ("type", "name")})
        # edge
        rel_name = rel if isinstance(rel, str) else rel.get("name", "rel")
        edge = {"src": k1, "rel": rel_name, "dst": k2}
        if not any(e == edge for e in self._edges):
            self._edges.append(edge)
        self._persist()

    def recall(self, query, limit=20):
        """对标原 Cypher: MATCH (n)-[r]->(m) WHERE name CONTAINS query RETURN ..."""
        q = query.lower()
        rows = []
        for e in self._edges:
            src = next((x for x in self._nodes if x["key"] == e["src"]), None)
            dst = next((x for x in self._nodes if x["key"] == e["dst"]), None)
            if not src or not dst:
                continue
            if q in (src["name"] + dst["name"]).lower():
                rows.append({
                    "src": src["name"], "src_type": src["type"],
                    "rel": e["rel"],
                    "dst": dst["name"], "dst_type": dst["type"],
                })
            if len(rows) >= limit:
                break
        return rows

    def stats(self):
        return {"nodes": len(self._nodes), "edges": len(self._edges)}


# ---------------------- 项目工作流状态（断点续挖）-----------------------
class ProjectStore:
    """保存挖洞项目的工作流状态：目标/阶段/已完成/待办/假设/下一步。
    与四层"内容记忆"不同，这是"进行到哪了"的断点，供关机后续挖。"""

    def __init__(self):
        os.makedirs(Config.PROJECT_DIR, exist_ok=True)

    def _path(self, session):
        return os.path.join(Config.PROJECT_DIR, f"{session}.json")

    def save(self, session, state):
        json_save(Config.PROJECT_DIR, session, state)

    def load(self, session):
        return json_load(Config.PROJECT_DIR, session, None)

    def list_sessions(self):
        d = Config.PROJECT_DIR
        if not os.path.exists(d):
            return []
        return [f[:-5] for f in os.listdir(d) if f.endswith(".json")]
