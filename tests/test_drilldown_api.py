"""drill-down 新端点测试：/api/scenario/info、/api/about、
/api/bench/run/{run_id}/task/{idx}。无 LLM、无网络、无 docker。
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
from cyberorion.bench import cybersoceval as bench_mod  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


# ----------------------------------------------------------------------- #
# /api/scenario/info
# ----------------------------------------------------------------------- #
def test_scenario_info_shape_and_no_ground_truth(client):
    r = client.get("/api/scenario/info")
    assert r.status_code == 200
    data = r.json()
    for k in ("name", "description", "mode", "briefing", "targets",
              "red_objectives", "blue_objectives"):
        assert k in data, f"缺少字段 {k}"
    assert data["targets"], "targets 不能为空"
    assert len(data["red_objectives"]) >= 3
    assert len(data["blue_objectives"]) >= 3
    t = data["targets"][0]
    assert set(t) >= {"name", "ip", "container", "services", "logs"}
    assert set(t["services"][0]) >= {
        "name", "container_port", "host_port", "proto"}
    # 绝不泄露 ground truth / grader
    blob = json.dumps(data, ensure_ascii=False)
    for secret in ("ground_truth", "grader", "flag.txt",
                   "admin123", "admin:password"):
        assert secret not in blob, f"泄露了 {secret}"


def test_scenario_info_arena_objectives(client):
    """默认场景（web_basic, 通用 arena 模式）→ 通用红蓝目标。"""
    data = client.get("/api/scenario/info").json()
    assert data["mode"] == "arena"
    assert any("flag" in o for o in data["red_objectives"])
    assert any("report_finding" in o for o in data["blue_objectives"])


def test_scenario_info_cve_objectives():
    """cve 模式场景 → 简报/grader 导向的目标。"""
    from cyberorion.scenarios import load_scenario
    sc = load_scenario("cve_cve-2024-4323")
    red, blue = server_mod._scenario_objectives(sc)
    assert any("裁判" in o or "grader" in o for o in red)
    assert any("report_finding" in o for o in blue)


# ----------------------------------------------------------------------- #
# /api/about
# ----------------------------------------------------------------------- #
def test_about_returns_framework_doc(client):
    r = client.get("/api/about")
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "CyberOrion" in md
    assert "watcher" in md and "dispatch_task" in md


# ----------------------------------------------------------------------- #
# /api/bench/run/{run_id}/task/{idx}
# ----------------------------------------------------------------------- #
@pytest.fixture()
def qa_run_file():
    rid = "drilldown_qa_n2"
    run = {
        "run_id": rid, "suite": "malware_analysis", "mode": "base",
        "n": 2, "seed": 42,
        "scores": {"n": 2, "correct_mc_pct": 0.5, "avg_score": 0.5,
                   "parse_fail": 0},
        "results": [
            {"idx": 0, "topic": "t", "difficulty": "easy", "attack": "",
             "question": "（截断的旧题干）…", "gold": ["A"],
             "pred": ["A", "B"], "raw": "推理… ANSWER: [\"A\",\"B\"]",
             "parse_ok": True, "exact": False, "jaccard": 0.5},
            {"idx": 999999, "topic": "t2", "difficulty": "hard",
             "attack": "", "question": "q2", "gold": ["C"], "pred": ["C"],
             "raw": "ANSWER: [\"C\"]", "parse_ok": True,
             "exact": True, "jaccard": 1.0},
        ],
    }
    p = bench_mod.DEFAULT_LOG_DIR / f"{rid}.json"
    p.write_text(json.dumps(run), encoding="utf-8")
    yield rid
    p.unlink(missing_ok=True)


def test_bench_task_qa_enriched(client, qa_run_file, monkeypatch):
    """QA 套件：题干/选项从 questions.json 按 idx 补全（此处 mock）。"""
    monkeypatch.setattr(server_mod, "_load_qa_questions", lambda: [
        {"idx": 0, "question": "完整题干全文",
         "options": ["A. x", "B. y", "C. z"],
         "correct_options": ["A"], "topic": "t",
         "difficulty": "easy", "attack": ""},
    ])
    r = client.get(f"/api/bench/run/{qa_run_file}/task/0")
    assert r.status_code == 200
    d = r.json()
    assert d["run_id"] == qa_run_file and d["idx"] == 0 and d["n"] == 2
    assert d["suite"] == "malware_analysis" and d["mode"] == "base"
    t = d["task"]
    assert t["question"] == "完整题干全文"
    assert t["options"] == ["A. x", "B. y", "C. z"]
    assert t["gold"] == ["A"] and t["pred"] == ["A", "B"]
    assert t["exact"] is False and t["jaccard"] == 0.5
    assert "ANSWER" in t["raw"]
    assert t["topic"] == "t" and t["difficulty"] == "easy"


def test_bench_task_qa_unknown_idx_fallback(client, qa_run_file,
                                            monkeypatch):
    """题库缺失/idx 对不上时降级返回运行文件里的原样，不报错。"""
    monkeypatch.setattr(server_mod, "_load_qa_questions", lambda: None)
    r = client.get(f"/api/bench/run/{qa_run_file}/task/1")
    assert r.status_code == 200
    t = r.json()["task"]
    assert t["question"] == "q2" and "options" not in t


def test_bench_task_errors(client, qa_run_file):
    assert client.get(f"/api/bench/run/{qa_run_file}/task/9").status_code == 404
    assert client.get(
        f"/api/bench/run/{qa_run_file}/task/-1").status_code == 404
    assert client.get(
        "/api/bench/run/no_such_run_xyz/task/0").status_code == 404
    assert client.get("/api/bench/run/bad%20id/task/0").status_code == 400
