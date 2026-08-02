"""server.py 基准 API 测试（B3）：POST/GET bench 端点。

run_bench 用 monkeypatch 替换为即时完成的 fake，无 LLM、无网络。
"""

from __future__ import annotations

import asyncio
import sys
import time
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


@pytest.fixture()
def fake_bench(monkeypatch, tmp_path):
    """把 run_bench 换成写临时结果文件的 fake。"""
    created: list[Path] = []

    async def fake_run(n=100, mode="base", seed=42, on_progress=None,
                       run_id=None, suite="malware_analysis", **kwargs):
        rid = run_id or f"fake_{mode}_n{n}"
        if on_progress:
            on_progress(n, n)
        run = {
            "run_id": rid, "suite": suite, "mode": mode, "n": n, "seed": seed,
            "model": "fake-model", "scores": {
                "n": n, "correct_mc_pct": 0.5, "avg_score": 0.6,
                "parse_fail": 1,
                "by_difficulty": {"easy": {"n": n, "correct_mc_pct": 0.5,
                                           "avg_score": 0.6}},
                "by_topic": {},
            },
            "results": [{"idx": 0, "exact": True, "jaccard": 1.0,
                         "parse_ok": True, "gold": ["A"], "pred": ["A"],
                         "raw": "ANSWER: [\"A\"]", "topic": "t",
                         "difficulty": "easy", "attack": "",
                         "question": "q"}],
        }
        path = bench_mod.DEFAULT_LOG_DIR / f"{rid}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        import json
        path.write_text(json.dumps(run), encoding="utf-8")
        run["path"] = str(path)
        created.append(path)
        return run

    monkeypatch.setattr(bench_mod, "run_bench", fake_run)
    yield
    # 清理 fake 运行产生的文件与内存状态（含时间戳命名的泄漏文件）
    for p in created:
        p.unlink(missing_ok=True)
    for rid in [r for r in server_mod._bench_runs if r.startswith("fake_")
                or "_base_n" in r or "_rag_n" in r]:
        server_mod._bench_runs.pop(rid, None)


def _wait_done(run_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = server_mod._bench_runs.get(run_id, {})
        if state.get("status") in ("done", "error"):
            return state
        time.sleep(0.05)
    raise AssertionError(f"bench run {run_id} 未在 {timeout}s 内完成")


class TestBenchAPI:
    def test_run_and_detail(self, client: TestClient, fake_bench) -> None:
        r = client.post("/api/bench/run", json={"n": 8, "mode": "rag"})
        assert r.status_code == 200
        run_id = r.json()["run_id"]
        assert "_rag_n8" in run_id
        state = _wait_done(run_id)
        assert state["status"] == "done"
        assert state["scores"]["correct_mc_pct"] == 0.5

        r = client.get(f"/api/bench/run/{run_id}")
        assert r.status_code == 200
        assert r.json()["scores"]["avg_score"] == 0.6

    def test_bad_mode_400(self, client: TestClient, fake_bench) -> None:
        r = client.post("/api/bench/run", json={"mode": "bogus"})
        assert r.status_code == 400

    def test_all_bench_modes_accepted(self, client: TestClient,
                                      fake_bench) -> None:
        # 端点白名单与 bench.MODES 保持同一事实源：sc/rag_g 等新模式不再 400
        for mode in bench_mod.MODES:
            r = client.post("/api/bench/run", json={"n": 2, "mode": mode})
            assert r.status_code == 200, mode
            state = _wait_done(r.json()["run_id"])
            assert state["status"] == "done", mode

    def test_runs_list(self, client: TestClient, fake_bench) -> None:
        r = client.post("/api/bench/run", json={"n": 4, "mode": "base"})
        run_id = r.json()["run_id"]
        _wait_done(run_id)
        r = client.get("/api/bench/runs")
        assert r.status_code == 200
        runs = r.json()
        assert isinstance(runs, list)
        assert any(run["run_id"] == run_id for run in runs)

    def test_unknown_run_404(self, client: TestClient) -> None:
        r = client.get("/api/bench/run/20990101_000000_base_n1")
        assert r.status_code == 404

    def test_bad_run_id_400(self, client: TestClient) -> None:
        r = client.get("/api/bench/run/..%2F..%2Fetc")
        assert r.status_code in (400, 404, 422)

    def test_bad_suite_400(self, client: TestClient, fake_bench) -> None:
        r = client.post("/api/bench/run", json={"suite": "nope"})
        assert r.status_code == 400

    def test_attack_kb_suite_accepted(self, client: TestClient,
                                      fake_bench) -> None:
        # attack_kb 仅支持 base/rag（单一事实源：attack_kb.MODES）
        r = client.post("/api/bench/run", json={
            "suite": "attack_kb", "mode": "rag", "n": 2})
        assert r.status_code == 200
        run_id = r.json()["run_id"]
        assert "_attack_kb_rag_n2" in run_id
        state = _wait_done(run_id)
        assert state["status"] == "done"
        assert state["suite"] == "attack_kb"
        # GET /api/bench/runs 返回 suite 字段
        runs = client.get("/api/bench/runs").json()
        assert any(run.get("suite") == "attack_kb" for run in runs)

    def test_attack_kb_rejects_sc_mode(self, client: TestClient,
                                       fake_bench) -> None:
        r = client.post("/api/bench/run", json={
            "suite": "attack_kb", "mode": "sc", "n": 2})
        assert r.status_code == 400

    def test_bench_questions_preview(self, client: TestClient) -> None:
        from cyberorion.bench import cybersoceval as bench_mod
        if not Path(bench_mod.DEFAULT_QUESTIONS).is_file():
            pytest.skip("questions.json 不可用")
        r = client.get(
            "/api/bench/questions?suite=malware_analysis&n=3&seed=42")
        assert r.status_code == 200
        data = r.json()
        assert data["n"] == 3 and len(data["questions"]) == 3
        for q in data["questions"]:
            assert q["question"] and q["options"] and q["correct_options"]
        # 同 seed 确定性：两次采样同一批题
        r2 = client.get(
            "/api/bench/questions?suite=malware_analysis&n=3&seed=42")
        assert [q["idx"] for q in r2.json()["questions"]] == \
               [q["idx"] for q in data["questions"]]

    def test_bench_questions_bad_suite(self, client: TestClient) -> None:
        r = client.get("/api/bench/questions?suite=nope")
        assert r.status_code == 400
