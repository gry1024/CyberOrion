"""cybergym_bench 套件管线单测（mock docker / LLM / 服务器，无外部依赖）。"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from cyberorion.bench import cybergym_bench as cg  # noqa: E402
from cyberorion.bench import cybersoceval  # noqa: E402


# ----------------------------------------------------------------------- #
# 纯函数：池 / 采样 / 评分
# ----------------------------------------------------------------------- #
def test_sample_tasks_deterministic_and_capped():
    pool = ["arvo:1", "arvo:2", "arvo:3", "arvo:4", "arvo:5", "arvo:6"]
    a = cg.sample_tasks(pool, 3, 42)
    b = cg.sample_tasks(pool, 3, 42)
    assert a == b and len(a) == 3 and a == sorted(a)
    assert cg.sample_tasks(pool, 99, 42) == sorted(pool)


def test_load_task_pool_fallback_and_file(tmp_path):
    assert cg.load_task_pool(tmp_path / "missing.json") == cg.DEFAULT_POOL
    f = tmp_path / "pool.json"
    f.write_text(json.dumps({"tasks": ["arvo:9", "oss-fuzz:7"]}))
    assert cg.load_task_pool(f) == ["arvo:9", "oss-fuzz:7"]


def test_compute_scores():
    results = [
        {"success": True, "success_any": True, "project": "file", "elapsed_sec": 10},
        {"success": False, "success_any": True, "project": "file", "elapsed_sec": 20},
        {"success": False, "success_any": False, "project": "jq", "elapsed_sec": 30},
    ]
    s = cg.compute_scores(results)
    assert s["n"] == 3 and s["successes"] == 1
    assert s["success_pct"] == pytest.approx(1 / 3, abs=1e-3)
    assert s["any_of_successes"] == 2
    assert s["by_project"]["file"] == {"n": 2, "success": 1}
    assert s["avg_elapsed_sec"] == 20.0


# ----------------------------------------------------------------------- #
# vanilla 臂：文本协议循环（真实 bash + 假 submit.sh，mock LLM）
# ----------------------------------------------------------------------- #
def _make_workspace(tmp_path: Path, crash_on: str = "crashme") -> Path:
    """造一个任务工作目录：submit.sh 按文件名返回伪造的 checker JSON。"""
    submit = tmp_path / "submit.sh"
    submit.write_text(
        "#!/bin/bash\n"
        f'if [ "$1" == "{crash_on}" ]; then\n'
        '  echo \'{"task_id":"arvo:1","exit_code":1,"output":"AddressSanitizer: heap-buffer-overflow","poc_id":"x"}\'\n'
        "else\n"
        '  echo \'{"task_id":"arvo:1","exit_code":0,"output":"Executed /tmp/poc in 3 ms","poc_id":"y"}\'\n'
        "fi\n")
    submit.chmod(0o755)
    (tmp_path / crash_on).write_text("BB")   # 崩溃 PoC 文件须存在（fix 复核要读）
    return tmp_path


def test_run_vanilla_task_stops_on_crash(tmp_path, monkeypatch):
    ws = _make_workspace(tmp_path)
    ctx = {"task_id": "arvo:1", "out_dir": ws, "agent_id": "a", "checksum": "c"}
    replies = iter([
        "先看看目录\n```bash\nls\n```",
        "试一个不崩的\n```bash\nprintf 'AA' > try1 && bash ./submit.sh try1\n```",
        "构造崩溃输入\n```bash\nprintf 'BB' > crashme && bash ./submit.sh crashme\n```",
        "这条不应被执行到\n```bash\necho extra\n```",
    ])

    async def llm(messages):
        return next(replies)

    # 崩溃后 harness 立即用修复版复核：修复版不崩（exit 0）→ VERIFIED → 停止
    def fake_fix_submit(poc_path, task_ctx, server_url=None, mode="vul", timeout=120):
        return {"exit_code": 0, "output": ""}

    monkeypatch.setattr(cg, "submit_poc", fake_fix_submit)
    out = asyncio.run(cg.run_vanilla_task(ctx, "briefing", llm))
    assert out["steps"] == 3          # 崩溃 + 修复版复核通过即停
    assert len(out["submissions"]) == 2
    assert out["submissions"][-1]["exit_code"] == 1
    assert out["submissions"][-1]["fix_exit_code"] == 0
    assert out["submissions"][0]["exit_code"] == 0


def test_run_vanilla_task_continues_when_fix_also_crashes(tmp_path, monkeypatch):
    """修复版也崩 → 不算目标漏洞：harness 告知 agent 并继续迭代。"""
    ws = _make_workspace(tmp_path)
    ctx = {"task_id": "arvo:1", "out_dir": ws, "agent_id": "a", "checksum": "c"}
    replies = iter([
        "泛型崩溃\n```bash\nprintf 'BB' > crashme && bash ./submit.sh crashme\n```",
        "再试\n```bash\necho retry\n```",
        "收官\n```bash\necho done\n```",
    ])

    async def llm(messages):
        seen.extend(m["content"] for m in messages)
        return next(replies)

    def fake_fix_submit(poc_path, task_ctx, server_url=None, mode="vul", timeout=120):
        return {"exit_code": 139, "output": ""}   # 修复版也崩 → REJECTED

    monkeypatch.setattr(cg, "submit_poc", fake_fix_submit)
    seen: list[str] = []
    out = asyncio.run(cg.run_vanilla_task(ctx, "briefing", llm, max_steps=3))
    assert out["steps"] == 3          # 未停在第一次崩溃，继续迭代到预算上限
    assert out["submissions"][-1]["exit_code"] == 1
    assert out["submissions"][-1]["fix_exit_code"] == 139
    assert any("ALSO crashes the FIXED build" in c for c in seen)


def test_run_vanilla_task_nudges_without_bash_block(tmp_path, monkeypatch):
    ws = _make_workspace(tmp_path)
    ctx = {"task_id": "arvo:1", "out_dir": ws, "agent_id": "a", "checksum": "c"}
    replies = iter([
        "我不知道该怎么做",                       # 无 bash 块 → nudge
        "```bash\nbash ./submit.sh crashme\n```",
    ])

    async def llm(messages):
        return next(replies)

    def fake_fix_submit(poc_path, task_ctx, server_url=None, mode="vul", timeout=120):
        return {"exit_code": 0, "output": ""}

    monkeypatch.setattr(cg, "submit_poc", fake_fix_submit)
    out = asyncio.run(cg.run_vanilla_task(ctx, "b", llm, max_steps=5))
    assert out["submissions"] and out["submissions"][-1]["exit_code"] == 1


# ----------------------------------------------------------------------- #
# 最终判定（mock submit_poc 的 fix 复核）
# ----------------------------------------------------------------------- #
def test_final_verdict_final_submission_and_any_of(tmp_path, monkeypatch):
    (tmp_path / "p1").write_text("x")
    (tmp_path / "p2").write_text("y")
    ctx = {"task_id": "arvo:1", "out_dir": tmp_path, "agent_id": "a", "checksum": "c"}
    fix_codes = {"p1": 1, "p2": 0}   # p1 修复版也崩 → 不算；p2 修复版干净

    def fake_submit(poc_path, task_ctx, server_url=None, mode="vul", timeout=120):
        return {"exit_code": fix_codes[Path(poc_path).name], "output": ""}

    monkeypatch.setattr(cg, "submit_poc", fake_submit)
    result = {"submissions": [
        {"poc": "p2", "exit_code": 1},   # 先成功的
        {"poc": "p1", "exit_code": 1},   # 最后提交却打到修复版也崩 → final 失败
    ]}
    v = cg._final_verdict(result, ctx, "http://x")
    assert v["success"] is False
    assert v["success_any"] is True


def test_final_verdict_no_submission(tmp_path):
    ctx = {"task_id": "arvo:1", "out_dir": tmp_path, "agent_id": "a", "checksum": "c"}
    v = cg._final_verdict({"submissions": []}, ctx, "http://x")
    assert v == {"success": False, "success_any": False,
                 "final_exit_code": None, "final_fix_exit_code": None}


# ----------------------------------------------------------------------- #
# run_bench 全流程（mock 数据/镜像/服务器/gen_task + mock LLM）
# ----------------------------------------------------------------------- #
def _patch_infra(monkeypatch, tmp_path):
    monkeypatch.setattr(cg, "ensure_task_data", lambda tid: tmp_path)
    monkeypatch.setattr(cg, "ensure_images", lambda tid: None)

    def fake_gen(task_id, out_dir, server_url=None):
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        _make_workspace(out)
        (out / "README.md").write_text("fake readme")
        return {"task_id": task_id, "out_dir": out, "repo_dir": out,
                "agent_id": "a", "checksum": "c"}

    monkeypatch.setattr(cg, "gen_task", fake_gen)

    class FakeServer:
        def __init__(self, url):
            self.url = url

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(cg, "CyberGymServer", FakeServer)
    monkeypatch.setattr(cg, "submit_poc",
                        lambda *a, **k: {"exit_code": 0, "output": ""})


def test_run_bench_vanilla_persists_and_scores(monkeypatch, tmp_path):
    _patch_infra(monkeypatch, tmp_path)

    async def llm(messages):
        return "```bash\nprintf 'BB' > crashme && bash ./submit.sh crashme\n```"

    run = asyncio.run(cg.run_bench(
        n=2, mode="vanilla", seed=42, log_dir=tmp_path / "logs",
        pool=["arvo:1", "arvo:2"], work_root=tmp_path / "work", llm=llm))
    assert run["suite"] == "cybergym" and run["mode"] == "vanilla"
    assert run["n"] == 2 and run["status"] == "done"
    assert run["scores"]["success_pct"] == 1.0
    path = Path(run["path"])
    assert path.is_file()
    saved = json.loads(path.read_text())
    assert saved["suite"] == "cybergym"
    # list_runs 兼容（cybersoceval.list_runs 通用扫描）
    runs = cybersoceval.list_runs(tmp_path / "logs")
    assert runs and runs[0]["suite"] == "cybergym"
    assert runs[0]["mode"] == "vanilla"


def test_run_bench_task_failure_isolated(monkeypatch, tmp_path):
    _patch_infra(monkeypatch, tmp_path)

    def boom(tid):
        raise RuntimeError("docker pull failed")

    monkeypatch.setattr(cg, "ensure_images", boom)

    async def llm(messages):
        return "```bash\nbash ./submit.sh crashme\n```"

    run = asyncio.run(cg.run_bench(
        n=2, mode="vanilla", seed=42, log_dir=tmp_path / "logs",
        pool=["arvo:1", "arvo:2"], work_root=tmp_path / "work", llm=llm))
    assert run["status"] == "error"      # 全部任务失败
    assert run["scores"]["success_pct"] == 0.0
    assert "docker pull failed" in run["error"]


def test_run_bench_rejects_bad_mode():
    with pytest.raises(ValueError):
        asyncio.run(cg.run_bench(n=1, mode="base", pool=["arvo:1"]))


def test_cybersoceval_dispatches_cybergym(monkeypatch, tmp_path):
    """cybersoceval.run_bench 把 suite=cybergym 委托给 cybergym_bench。"""
    called = {}

    async def fake_run(**kwargs):
        called.update(kwargs)
        return {"run_id": "x", "suite": "cybergym", "mode": kwargs["mode"],
                "scores": {}, "results": [], "n": 0, "path": "x"}

    monkeypatch.setattr(cg, "run_bench", fake_run)
    out = asyncio.run(cybersoceval.run_bench(n=5, mode="vanilla", seed=1,
                                             suite="cybergym"))
    assert out["suite"] == "cybergym" and called["mode"] == "vanilla"


# ----------------------------------------------------------------------- #
# server API：suite=cybergym 的 mode 白名单（single source of truth）
# ----------------------------------------------------------------------- #
def test_api_cybergym_mode_validation(monkeypatch):
    from fastapi.testclient import TestClient

    import server as server_mod

    async def fake_run(**kwargs):
        return {"run_id": kwargs.get("run_id", "r"), "suite": "cybergym",
                "mode": kwargs["mode"], "n": kwargs["n"], "scores": {},
                "results": [], "status": "done", "path": None,
                "model": "m", "elapsed_sec": 0}

    monkeypatch.setattr(cybersoceval, "run_bench", fake_run)
    with TestClient(server_mod.app) as client:
        ok = client.post("/api/bench/run",
                         json={"suite": "cybergym", "mode": "vanilla", "n": 5})
        assert ok.status_code == 200 and ok.json()["ok"]
        bad = client.post("/api/bench/run",
                          json={"suite": "cybergym", "mode": "base", "n": 5})
        assert bad.status_code == 400
        assert "vanilla" in bad.json()["error"]
    server_mod._bench_runs.clear()
