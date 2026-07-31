"""storyline 生成与 /api/sessions/{id}/storyline 端点测试。

LLM 全部 mock（llm_fn 注入 / server 端点 monkeypatch），无网络。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SERVER_DIR = Path(__file__).resolve().parents[1]
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

import server as server_mod  # noqa: E402
from server import app  # noqa: E402
from cyberorion import storyline as storyline_mod  # noqa: E402

SID = "session_20990101_000000"


@pytest.fixture()
def session_dir(tmp_path) -> Path:
    """最小可用会话目录（只有 telemetry.db 也能复盘）。"""
    import sqlite3
    d = tmp_path / "logs" / SID
    d.mkdir(parents=True)
    conn = sqlite3.connect(d / "telemetry.db")
    conn.executescript("""
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        session_id TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '', technique TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT 'info',
        summary TEXT NOT NULL DEFAULT '', raw TEXT NOT NULL DEFAULT '');
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        session_id TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
        technique TEXT NOT NULL DEFAULT '', verdict TEXT NOT NULL DEFAULT '',
        confidence REAL NOT NULL DEFAULT 0.0,
        evidence TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        source_tool TEXT NOT NULL DEFAULT '');
    CREATE TABLE attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        session_id TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
        technique TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
        success INTEGER NOT NULL DEFAULT 0,
        evidence TEXT NOT NULL DEFAULT '');
    CREATE TABLE snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        host TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL DEFAULT '');
    """)
    conn.execute(
        "INSERT INTO attacks (ts, target, technique, action, success,"
        " evidence) VALUES (?,?,?,?,?,?)",
        (1000.0, "weak_ssh", "T1110", "ssh_bruteforce", 1, "SUCCESS"))
    conn.execute(
        "INSERT INTO alerts (ts, host, technique, verdict, confidence,"
        " evidence, source_tool) VALUES (?,?,?,?,?,?,?)",
        (1010.0, "weak_ssh", "T1110", "malicious", 0.9, " brute", "report_finding"))
    conn.commit()
    conn.close()
    return d


class TestGenerate:
    def test_llm_path(self, session_dir: Path) -> None:
        md, llm_used = storyline_mod.generate_storyline(
            session_dir, llm_fn=lambda prompt: "# 故事线复盘\nLLM 写的复盘")
        assert llm_used is True
        assert "LLM 写的复盘" in md
        # 落盘 + meta
        assert (session_dir / "storyline.md").read_text(
            encoding="utf-8") == md
        cached = storyline_mod.read_cached(session_dir)
        assert cached == (md, True)

    def test_template_fallback_on_llm_failure(
            self, session_dir: Path) -> None:
        def boom(prompt: str) -> str:
            raise RuntimeError("endpoint down")

        md, llm_used = storyline_mod.generate_storyline(
            session_dir, llm_fn=boom)
        assert llm_used is False
        # 模板产物：必备章节 + 诚实标注
        for section in ("# 故事线复盘", "## 战役故事线", "## 关键转折",
                        "## 蓝队表现评判", "## 红队战术分析", "## 改进建议"):
            assert section in md
        assert "模板生成" in md
        # 内容来自事实：攻击与告警都在叙事里
        assert "ssh_bruteforce" in md and "malicious" in md
        cached = storyline_mod.read_cached(session_dir)
        assert cached is not None and cached[1] is False

    def test_read_cached_missing(self, tmp_path: Path) -> None:
        assert storyline_mod.read_cached(tmp_path) is None


# --------------------------------------------------------------------------- #
# HTTP 端点（generate_storyline monkeypatch 为即时 fake）
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client(session_dir: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(server_mod, "_HERE", session_dir.parent.parent)

    def fake_generate(path):
        path = Path(path)
        (path / "storyline.md").write_text(
            "# 故事线复盘\nfake 复盘", encoding="utf-8")
        (path / "storyline.meta.json").write_text(
            '{"llm": true, "generated_at": 1}', encoding="utf-8")
        return "# 故事线复盘\nfake 复盘", True

    monkeypatch.setattr(server_mod.storyline_mod, "generate_storyline",
                        fake_generate)
    with TestClient(app) as c:
        yield c
    server_mod._storyline_tasks.clear()


def test_storyline_generate_then_cached(client: TestClient) -> None:
    r = client.post(f"/api/sessions/{SID}/storyline", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["cached"] is False and body["llm"] is True
    assert "fake 复盘" in body["storyline_md"]

    # 第二次 POST -> 命中缓存
    r = client.post(f"/api/sessions/{SID}/storyline", json={})
    assert r.json()["cached"] is True

    # force -> 重新生成
    r = client.post(f"/api/sessions/{SID}/storyline",
                    json={"force": True})
    assert r.json()["cached"] is False

    # GET 读取
    r = client.get(f"/api/sessions/{SID}/storyline")
    assert r.status_code == 200
    assert r.json()["llm"] is True


def test_storyline_get_404_when_not_generated(client: TestClient,
                                              session_dir: Path) -> None:
    r = client.get(f"/api/sessions/{SID}/storyline")
    assert r.status_code == 404


def test_storyline_202_when_in_flight(client: TestClient) -> None:
    # 塞一个未完成的任务模拟“生成进行中”（端点只调用 .done()）。
    loop = asyncio.new_event_loop()
    server_mod._storyline_tasks[SID] = loop.create_future()
    r = client.post(f"/api/sessions/{SID}/storyline",
                    json={"force": True})
    assert r.status_code == 202
    assert r.json()["status"] == "generating"


def test_storyline_invalid_id_400(client: TestClient) -> None:
    assert client.post("/api/sessions/bad/storyline",
                       json={}).status_code == 400
    assert client.get("/api/sessions/bad/storyline").status_code == 400
