"""rag：MITRE ATT&CK 知识库检索（AttackKB）。

两级策略：
  1. 若 LLM endpoint 支持 embeddings（DashScope 兼容模式 text-embedding-v3），
     则一次性嵌入全部文档、向量缓存到磁盘（npz），查询时余弦相似度检索
     （numpy 实现；numpy 不可用时退化为纯 Python 点积）；
  2. 否则回退到纯 Python 的 BM25 风格关键词评分（EN 词元 + 中文 bigram，
     idf 离线计算；对 T1110 这类技术编号做精确命中加权）。

两种模式都支持完全离线查询（embedding 模式仅在首次建索引与查询向量化时
需要网络；缓存命中后文档向量不再请求网络）。可用环境变量
``CYBERORION_KB_EMBEDDINGS=0`` 强制关闭 embedding（测试 / 离线场景）。

用法：
    from cyberorion.kb.rag import get_kb
    kb = get_kb()
    docs = kb.search("ssh brute force", k=5)
    doc = kb.lookup("T1110")
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent
DEFAULT_KB = _HERE / "data" / "attack_kb.jsonl"
VEC_CACHE = _HERE / "data" / "attack_kb_vecs.npz"

EMBEDDING_MODEL = os.getenv("CYBERORION_KB_EMBEDDING_MODEL",
                            "text-embedding-v3")
_EMBED_BATCH = 10  # DashScope 兼容端点单批上限 10 条

_WORD_RE = re.compile(r"[a-zA-Z0-9]+")
_CJK_RE = re.compile(r"[一-鿿]")
_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

# 技术编号精确命中的加权（远大于普通词项得分，保证排在最前）。
_TID_BOOST = 100.0


def _tokenize(text: str) -> list[str]:
    """EN 小写词元 + 中文单字与 bigram（混合查询场景）。"""
    text = str(text or "").lower()
    tokens = _WORD_RE.findall(text)
    cjk = _CJK_RE.findall(text)
    tokens.extend(cjk)
    tokens.extend(cjk[i] + cjk[i + 1] for i in range(len(cjk) - 1))
    return tokens


class AttackKB:
    """ATT&CK 知识库：lookup（按编号）+ search（语义/关键词检索）。"""

    def __init__(self, kb_path: "str | Path" = DEFAULT_KB,
                 use_embeddings: "bool | str" = "auto",
                 vec_cache: "str | Path | None" = None):
        self.kb_path = Path(kb_path)
        self.docs: list[dict] = []
        _skipped = 0
        with open(self.kb_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.docs.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    _skipped += 1
        if _skipped:
            import logging
            logging.getLogger("cyberorion.kb").warning(
                "KB load: skipped %d malformed lines", _skipped)
        self._by_id = {d["id"].upper(): d for d in self.docs}
        self._vec_cache = Path(vec_cache) if vec_cache else \
            self.kb_path.with_name("attack_kb_vecs.npz")
        self._embed_mode = self._resolve_mode(use_embeddings)
        self._bm25: dict | None = None       # 懒构建
        self._vectors = None                 # 懒构建 / 懒加载

    # ------------------------------------------------------------------ #
    # 公共 API
    # ------------------------------------------------------------------ #
    @property
    def uses_embeddings(self) -> bool:
        """当前是否处于 embedding 检索模式（False = BM25 回退）。"""
        return self._embed_mode

    def lookup(self, technique_id: str) -> "dict | None":
        """按 ATT&CK 编号精确查文档（大小写不敏感），未命中返回 None。"""
        return self._by_id.get(str(technique_id or "").strip().upper())

    def search(self, query: str, k: int = 5) -> list[dict]:
        """检索 top-k 文档，返回带 score 的浅拷贝列表（score 降序）。"""
        query = str(query or "").strip()
        if not query or not self.docs:
            return []
        k = max(1, int(k or 5))
        scores = self._score_embeddings(query) if self._embed_mode \
            else self._score_bm25(query)
        if scores is None:  # embedding 查询失败 -> 回退 BM25
            scores = self._score_bm25(query)
        # 技术编号精确命中加权（两种模式通用）。
        for tid in set(m.upper() for m in _TID_RE.findall(query)):
            idx = self._doc_index(tid)
            if idx is not None:
                scores[idx] = scores[idx] + _TID_BOOST
        ranked = sorted(range(len(scores)), key=lambda i: scores[i],
                        reverse=True)[:k]
        results = []
        for i in ranked:
            if scores[i] <= 0:
                continue
            doc = dict(self.docs[i])
            doc["score"] = round(float(scores[i]), 4)
            results.append(doc)
        return results

    # ------------------------------------------------------------------ #
    # embedding 模式
    # ------------------------------------------------------------------ #
    def _resolve_mode(self, use_embeddings: "bool | str") -> bool:
        """决定是否启用 embedding：显式布尔 > 环境变量 > 自动探测。"""
        if isinstance(use_embeddings, bool):
            return use_embeddings
        env = os.getenv("CYBERORION_KB_EMBEDDINGS")
        if env is not None:
            return env.strip().lower() not in ("0", "false", "no", "off")
        return self._probe_embeddings()

    def _embedding_client(self):
        from openai import OpenAI  # 延迟导入，离线环境不受影响
        kwargs = {"api_key": os.getenv("OPENAI_API_KEY", "missing-key"),
                  "timeout": 30.0, "max_retries": 0}
        base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url
        return OpenAI(**kwargs)

    def _probe_embeddings(self) -> bool:
        """向 endpoint 发一条最小 embedding 请求，失败则回退 BM25。"""
        if not os.getenv("OPENAI_API_KEY"):
            return False
        try:
            client = self._embedding_client()
            resp = client.embeddings.create(model=EMBEDDING_MODEL,
                                            input=["ping"])
            return bool(resp.data and resp.data[0].embedding)
        except Exception:
            return False

    def _embed_texts(self, texts: list[str]) -> "list[list[float]] | None":
        try:
            client = self._embedding_client()
            out: list[list[float]] = []
            for i in range(0, len(texts), _EMBED_BATCH):
                resp = client.embeddings.create(
                    model=EMBEDDING_MODEL, input=texts[i:i + _EMBED_BATCH])
                out.extend(d.embedding for d in resp.data)
            return out
        except Exception:
            return None

    def _doc_index(self, tid: str) -> "int | None":
        doc = self._by_id.get(tid.upper())
        if doc is None:
            return None
        # docs 与 _vectors 顺序一致（同源）。
        for i, d in enumerate(self.docs):
            if d is doc:
                return i
        return None

    def _load_or_build_vectors(self):
        """加载缓存向量；缓存失效则请求 endpoint 重建并落盘（npz）。"""
        if self._vectors is not None:
            return self._vectors
        ids = [d["id"] for d in self.docs]
        try:
            import numpy as np
            if self._vec_cache.is_file():
                cached = np.load(self._vec_cache, allow_pickle=False)
                if list(cached["ids"]) == ids:
                    self._vectors = cached["vecs"].astype("float32")
                    return self._vectors
            vectors = self._embed_texts([d["text"] for d in self.docs])
            if not vectors:
                return None
            mat = np.asarray(vectors, dtype="float32")
            norm = np.linalg.norm(mat, axis=1, keepdims=True)
            norm[norm == 0] = 1.0
            self._vectors = mat / norm
            try:
                np.savez(self._vec_cache, ids=np.asarray(ids),
                         vecs=self._vectors)
            except Exception:
                pass  # 缓存失败不影响使用
            return self._vectors
        except ImportError:
            vectors = self._embed_texts([d["text"] for d in self.docs])
            return vectors  # 未归一化，查询时按点积近似

    def _score_embeddings(self, query: str) -> "list[float] | None":
        mat = self._load_or_build_vectors()
        if mat is None:
            return None
        qv = self._embed_texts([query])
        if not qv:
            return None
        try:
            import numpy as np
            q = np.asarray(qv[0], dtype="float32")
            n = float(np.linalg.norm(q)) or 1.0
            return (mat @ (q / n)).tolist()
        except ImportError:
            q = qv[0]
            n = math.sqrt(sum(x * x for x in q)) or 1.0
            q = [x / n for x in q]
            out = []
            for row in mat:
                rn = math.sqrt(sum(x * x for x in row)) or 1.0
                out.append(sum(a * b for a, b in zip(row, q)) / rn)
            return out

    # ------------------------------------------------------------------ #
    # BM25 风格回退（纯 Python，完全离线）
    # ------------------------------------------------------------------ #
    def _build_bm25(self) -> dict:
        doc_tokens = [_tokenize(d.get("text", "")) for d in self.docs]
        df: dict[str, int] = {}
        for tokens in doc_tokens:
            for tok in set(tokens):
                df[tok] = df.get(tok, 0) + 1
        n = len(doc_tokens)
        idf = {tok: math.log((n - cnt + 0.5) / (cnt + 0.5) + 1.0)
               for tok, cnt in df.items()}
        tf_table = []
        for tokens in doc_tokens:
            tf: dict[str, int] = {}
            for tok in tokens:
                tf[tok] = tf.get(tok, 0) + 1
            tf_table.append(tf)
        return {"idf": idf, "tf": tf_table}

    def _score_bm25(self, query: str) -> list[float]:
        if self._bm25 is None:
            self._bm25 = self._build_bm25()
        idf, tf_table = self._bm25["idf"], self._bm25["tf"]
        k1, b = 1.5, 0.75
        avgdl = sum(sum(t.values()) for t in tf_table) / max(1, len(tf_table))
        scores = [0.0] * len(self.docs)
        q_tokens = set(_tokenize(query))
        # 复合词拆解：查询词不在词表时尝试拆成两个词表内词
        # （如 webshell -> web shell）。
        for tok in list(q_tokens):
            if len(tok) < 5:
                continue
            for cut in range(2, len(tok) - 1):
                left, right = tok[:cut], tok[cut:]
                if left in idf and right in idf:
                    q_tokens.add(left)
                    q_tokens.add(right)
                    break
        for tok in q_tokens:
            w = idf.get(tok)
            if not w:
                continue
            for i, tf in enumerate(tf_table):
                f = tf.get(tok, 0)
                if not f:
                    continue
                dl = sum(tf.values())
                scores[i] += w * (f * (k1 + 1)) / (
                    f + k1 * (1 - b + b * dl / max(1e-9, avgdl)))
        # 名称精确命中加权（如查询含 "brute force"）。
        q = query.lower()
        for i, d in enumerate(self.docs):
            name = (d.get("name") or "").lower()
            if name and name in q:
                scores[i] += 5.0
        # 类型先验：知识查询以技术（technique）为主，轻微压低
        # 软件/组织文档，避免同名软件淹没技术条目。
        for i, d in enumerate(self.docs):
            if d.get("type") in ("software", "group"):
                scores[i] *= 0.6
        return scores


# ----------------------------------------------------------------------- #
# 懒加载单例
# ----------------------------------------------------------------------- #
_lock = threading.Lock()
_KB: "AttackKB | None" = None


def get_kb(kb_path: "str | Path" = DEFAULT_KB,
           use_embeddings: "bool | str" = "auto") -> AttackKB:
    """返回进程级 AttackKB 单例（首次调用时构建）。"""
    global _KB
    with _lock:
        if _KB is None or Path(kb_path) != _KB.kb_path:
            _KB = AttackKB(kb_path, use_embeddings=use_embeddings)
        return _KB


def reset_kb() -> None:
    """清空单例（测试用）。"""
    global _KB
    with _lock:
        _KB = None
