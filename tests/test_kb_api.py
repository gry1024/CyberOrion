"""KB HTTP API 测试（/api/kb/*）+ service 纯函数层。

微型 KB fixture（8 篇文档），BM25 模式（无网络）；server 端点通过
monkeypatch get_kb 注入 fixture KB。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SERVER_DIR = Path(__file__).resolve().parents[1]
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

import server as server_mod  # noqa: E402
from server import app  # noqa: E402
from cyberorion.kb.rag import AttackKB  # noqa: E402
from cyberorion.kb import service as kb_service  # noqa: E402

_DET = ("Detects excessive failed authentication attempts from a single "
        "source against remote services such as SSH or RDP within a short "
        "time window and correlates them with subsequent successful logins.")


def _tech(tid: str, name: str, tactics: list[str],
          detection: str = _DET) -> dict:
    return {"id": tid, "name": name, "type": "technique",
            "tactics": tactics, "description": f"{name} description.",
            "detection": detection, "mitigations": ["M1036"],
            "platforms": ["Linux"], "data_sources": [],
            "is_subtechnique": False,
            "text": f"{tid} {name} tactics: {', '.join(tactics)}. "
                    f"{name} description. Detection: {detection}"}


DOCS = [
    _tech("T1110", "Brute Force", ["credential-access"]),
    _tech("T1110.001", "Password Guessing", ["credential-access"]),
    _tech("T1078", "Valid Accounts", ["defense-evasion", "persistence",
                                      "privilege-escalation", "initial-access"]),
    _tech("T1190", "Exploit Public-Facing Application", ["initial-access"]),
    _tech("T1059", "Command and Scripting Interpreter", ["execution"]),
    _tech("T1505.003", "Web Shell", ["persistence"]),
    {"id": "MALPEDIA:win.remcos", "name": "Remcos", "type": "malware",
     "tactics": [], "description": "Remcos RAT family.",
     "text": "MALPEDIA:win.remcos Remcos RAT family."},
    {"id": "SBX001", "name": "沙箱报告阅读指南", "type": "sandbox_report",
     "tactics": [], "description": "如何阅读沙箱报告。",
     "text": "SBX001 沙箱报告阅读指南 如何阅读沙箱报告"},
]


@pytest.fixture()
def kb(tmp_path) -> AttackKB:
    p = tmp_path / "kb.jsonl"
    p.write_text("\n".join(json.dumps(d, ensure_ascii=False) for d in DOCS),
                 encoding="utf-8")
    return AttackKB(p, use_embeddings=False)


class TestService:
    def test_stats(self, kb: AttackKB) -> None:
        s = kb_service.kb_stats(kb)
        assert s["total"] == 8
        assert s["by_type"]["technique"] == 6
        assert s["by_type"]["malware"] == 1
        assert s["embedding"] is False

    def test_tactics_tree(self, kb: AttackKB) -> None:
        tree = kb_service.kb_tactics(kb)
        # ATT&CK v18：defense-evasion 拆为 stealth + defense-impairment -> 13
        assert len(tree) == 13
        # canonical 顺序：initial-access 在前，impact 收尾
        assert tree[0]["tactic"] == "initial-access"
        assert tree[0]["name_cn"] == "初始访问"
        assert tree[-1]["tactic"] == "impact"
        names = [t["tactic"] for t in tree]
        assert "stealth" in names and "defense-impairment" in names
        ia = tree[0]
        # T1078 与 T1190 都属于 initial-access
        assert ia["count"] == 2
        assert [t["id"] for t in ia["techniques"]] == ["T1078", "T1190"]
        assert all("has_detection" in t for t in ia["techniques"])
        ca = next(t for t in tree if t["tactic"] == "credential-access")
        assert ca["count"] == 2
        # 无技术的战术也存在，count=0
        assert any(t["count"] == 0 for t in tree)

    def test_search(self, kb: AttackKB) -> None:
        hits = kb_service.kb_search(kb, "Brute Force", k=3)
        assert hits and hits[0]["id"] == "T1110"
        assert set(hits[0]) == {"id", "type", "name", "score", "excerpt"}
        assert len(hits[0]["excerpt"]) <= 300

    def test_doc(self, kb: AttackKB) -> None:
        doc = kb_service.kb_doc(kb, "T1110")
        assert doc["name"] == "Brute Force"
        assert doc["tactics"] == ["credential-access"]
        assert "text" in doc and "mitigations" in doc
        # 大小写不敏感 + 冒号 id
        assert kb_service.kb_doc(kb, "malpedia:win.remcos")["type"] == "malware"
        assert kb_service.kb_doc(kb, "NOPE") is None


# --------------------------------------------------------------------------- #
# HTTP 端点
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client(kb: AttackKB, monkeypatch) -> TestClient:
    monkeypatch.setattr(server_mod, "get_kb", lambda *a, **kw: kb)
    with TestClient(app) as c:
        yield c


def test_api_stats(client: TestClient) -> None:
    r = client.get("/api/kb/stats")
    assert r.status_code == 200
    s = r.json()
    assert s["total"] == 8 and s["embedding"] is False


def test_api_tactics(client: TestClient) -> None:
    r = client.get("/api/kb/tactics")
    assert r.status_code == 200
    tree = r.json()
    assert len(tree) == 13
    assert {"tactic", "name_cn", "count", "techniques"} <= set(tree[0])


def test_api_search(client: TestClient) -> None:
    r = client.get("/api/kb/search", params={"q": "Brute Force", "k": 5})
    assert r.status_code == 200
    hits = r.json()
    assert hits and hits[0]["id"] == "T1110"
    r = client.get("/api/kb/search", params={"q": ""})
    assert r.json() == []


def test_api_doc(client: TestClient) -> None:
    r = client.get("/api/kb/doc/T1110")
    assert r.status_code == 200
    assert r.json()["name"] == "Brute Force"
    # URL 编码的冒号 id
    r = client.get("/api/kb/doc/MALPEDIA%3Awin.remcos")
    assert r.status_code == 200
    assert r.json()["type"] == "malware"
    r = client.get("/api/kb/doc/NOPE")
    assert r.status_code == 404
