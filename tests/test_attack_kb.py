"""attack_kb 套件测试 — LLM 全部 mock，微型 KB fixture，无网络。

  - 题目池构建：合格性过滤（detection 长度 / 同战术干扰项数）、干扰项
    同战术、正确答案在选项中、确定性；
  - 采样确定性（同 seed 同卷）；
  - run_bench 评分路径（base / rag，mock LLM）与结果持久化；
  - cybersoceval.run_bench 的 suite 分发与旧文件兼容（list_runs）。
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from cyberorion.bench import attack_kb as akb
from cyberorion.bench import cybersoceval as bench
from cyberorion.kb.rag import AttackKB

_DET_TMPL = ("Detects {name} behavior by correlating authentication and "
             "process telemetry across hosts, flagging anomalous sequences "
             "that match this technique's known detection analytics number ")


def _tech(tid: str, name: str, tactic: str) -> dict:
    # tid 前置，保证各文档 detection 前缀唯一（同文碰撞组会被剔除）。
    det = f"{tid} analytics. " + _DET_TMPL.format(name=name)
    return {"id": tid, "name": name, "type": "technique",
            "tactics": [tactic], "description": f"{name} description.",
            "detection": det,
            "text": f"{tid} {name} tactics: {tactic}. Detection: {det}"}


DOCS = (
    # 6 个同战术技术 -> 合格池成员
    [_tech(f"T10{i:02d}", f"Tech{i}", "credential-access") for i in range(6)]
    # 孤战术技术（干扰项不足 4 个）-> 不合格
    + [_tech("T2000", "LonelyTech", "collection")]
    # detection 太短 -> 不合格
    + [{"id": "T2001", "name": "ShortDet", "type": "technique",
        "tactics": ["credential-access"], "description": "x",
        "detection": "short", "text": "T2001 ShortDet short"}]
)


@pytest.fixture()
def kb(tmp_path) -> AttackKB:
    p = tmp_path / "kb.jsonl"
    p.write_text("\n".join(json.dumps(d, ensure_ascii=False) for d in DOCS),
                 encoding="utf-8")
    return AttackKB(p, use_embeddings=False)


class TestQuestionPool:
    def test_eligibility(self, kb: AttackKB) -> None:
        pool = akb.build_question_pool(kb)
        ids = {q["attack"] for q in pool}
        assert ids == {f"T10{i:02d}" for i in range(6)}
        # 孤战术与短 detection 被排除
        assert "T2000" not in ids and "T2001" not in ids

    def test_distractors_prefer_siblings(self, tmp_path) -> None:
        """同父技术的兄弟子技术优先作为干扰项（最难凭记忆区分）。"""
        docs = []
        # T1055 家族：父 + 4 个子技术（同战术）
        fam = ["T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004"]
        for i, tid in enumerate(fam):
            docs.append(_tech(tid, f"ProcessInjection{i}", "defense-evasion"))
        # 凑足干扰项数的同战术其他技术
        for i in range(5):
            docs.append(_tech(f"T11{i:02d}", f"Other{i}", "defense-evasion"))
        p = tmp_path / "kb.jsonl"
        p.write_text("\n".join(json.dumps(d, ensure_ascii=False)
                               for d in docs), encoding="utf-8")
        kb2 = AttackKB(p, use_embeddings=False)
        pool = akb.build_question_pool(kb2)
        q = next(q for q in pool if q["attack"] == "T1055.001")
        option_ids = {o.split(". ")[1] for o in q["options"]}
        # 4 个干扰位应全部来自 T1055 家族
        assert option_ids == set(fam)

    def test_detection_collision_excluded(self, tmp_path) -> None:
        """共享同一段 detection 样板的技术整组剔除（摘录无法唯一辨识）。"""
        boiler = ("Shared generic detection boilerplate text used by many "
                  "PRE-ATT&CK techniques verbatim, making the excerpt "
                  "ambiguous and impossible to attribute uniquely.")
        docs = [_tech(f"T10{i:02d}", f"Tech{i}", "credential-access")
                for i in range(6)]
        for i, tid in enumerate(("T3000", "T3001")):
            docs.append({"id": tid, "name": f"Boiler{i}", "type": "technique",
                         "tactics": ["credential-access"],
                         "description": "x", "detection": boiler,
                         "text": f"{tid} Boiler{i} {boiler}"})
        p = tmp_path / "kb.jsonl"
        p.write_text("\n".join(json.dumps(d, ensure_ascii=False)
                               for d in docs), encoding="utf-8")
        kb2 = AttackKB(p, use_embeddings=False)
        pool = akb.build_question_pool(kb2)
        ids = {q["attack"] for q in pool}
        assert "T3000" not in ids and "T3001" not in ids
        # 碰撞文档也不得作为干扰项出现
        for q in pool:
            option_ids = {o.split(". ")[1] for o in q["options"]}
            assert "T3000" not in option_ids and "T3001" not in option_ids

    def test_options_shape(self, kb: AttackKB) -> None:
        pool = akb.build_question_pool(kb)
        # 干扰项可以是同战术的任意 technique（含 detection 过短的 T2001，
        # 它只是选项编号，不作题干）。
        tactic_members = {f"T10{i:02d}" for i in range(6)} | {"T2001"}
        for q in pool:
            assert len(q["options"]) == 5
            assert len(q["correct_options"]) == 1
            letter = q["correct_options"][0]
            idx = ord(letter) - ord("A")
            chosen = q["options"][idx].split(". ")[1]
            # 正确答案在选项中且就是题干技术
            assert chosen == q["attack"]
            # 干扰项全部同战术
            option_ids = {o.split(". ")[1] for o in q["options"]}
            assert option_ids <= tactic_members
            # 题干是 detection 摘录
            assert "Detects" in q["question"]
            assert q["topic"] == "credential-access"

    def test_deterministic(self, kb: AttackKB) -> None:
        a = akb.build_question_pool(kb)
        b = akb.build_question_pool(kb)
        assert [q["options"] for q in a] == [q["options"] for q in b]
        assert [q["correct_options"] for q in a] == \
               [q["correct_options"] for q in b]

    def test_sampling_seeded(self, kb: AttackKB) -> None:
        pool = akb.build_question_pool(kb)
        s1 = bench.sample_questions(pool, 3, seed=42)
        s2 = bench.sample_questions(pool, 3, seed=42)
        assert [q["attack"] for q in s1] == [q["attack"] for q in s2]
        assert len(s1) == 3


# --------------------------------------------------------------------------- #
# run_bench 评分路径
# --------------------------------------------------------------------------- #
def _letter_of(q_attack: str, prompt: str) -> str:
    """从提示的选项列表中找出正确技术编号对应的字母。"""
    for m in re.finditer(r"^([A-E])\. (T\d+)\s*$", prompt, re.MULTILINE):
        if m.group(2) == q_attack:
            return m.group(1)
    return "A"


class TestRunBench:
    def test_rag_perfect_when_answer_in_context(self, kb: AttackKB,
                                                tmp_path: Path) -> None:
        """rag 模式把正确文档注入提示 -> 能读提示的模型应得满分。"""
        async def llm(system: str, user: str) -> str:
            # 从检索结果区块取第一个条目编号（题干文档即 top-1），
            # 再在选项中定位其字母 —— 模拟“会用 KB 的模型”。
            m = re.search(r"### (T\d+) ", user)
            assert m, "rag 提示中应注入检索结果"
            letter = _letter_of(m.group(1), user)
            return f"对照检索结果，答案是 {letter}\nANSWER: [\"{letter}\"]"

        run = asyncio.run(akb.run_bench(
            n=4, mode="rag", seed=42, log_dir=tmp_path, llm=llm, kb=kb))
        assert run["scores"]["correct_mc_pct"] == 1.0
        assert run["suite"] == "attack_kb"
        assert run["rag_top_k"] == akb.RAG_TOP_K
        # 持久化 + suite 字段
        saved = json.loads((tmp_path / f"{run['run_id']}.json")
                           .read_text(encoding="utf-8"))
        assert saved["suite"] == "attack_kb"
        assert "_attack_kb_rag_n4" in run["run_id"]

    def test_base_has_no_retrieval(self, kb: AttackKB,
                                   tmp_path: Path) -> None:
        seen = []

        async def llm(system: str, user: str) -> str:
            seen.append(user)
            return "ANSWER: [\"A\"]"

        run = asyncio.run(akb.run_bench(
            n=3, mode="base", seed=1, log_dir=tmp_path, llm=llm, kb=kb))
        assert all("知识库检索结果" not in u for u in seen)
        assert run["rag_top_k"] == 0
        # 评分路径完整：每题都有 gold/pred/exact
        assert all(set(r) >= {"gold", "pred", "exact", "jaccard",
                              "parse_ok"} for r in run["results"])

    def test_bad_mode_rejected(self, kb: AttackKB, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            asyncio.run(akb.run_bench(n=1, mode="sc", log_dir=tmp_path,
                                      kb=kb, llm=None))


class TestSuiteDispatch:
    def test_cybersoceval_dispatch(self, kb: AttackKB,
                                   tmp_path: Path) -> None:
        async def llm(system: str, user: str) -> str:
            return "ANSWER: [\"B\"]"

        run = asyncio.run(bench.run_bench(
            n=2, mode="rag", seed=7, suite="attack_kb",
            log_dir=tmp_path, llm=llm, kb=kb))
        assert run["suite"] == "attack_kb"
        assert run["n"] == 2

    def test_unknown_suite_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            asyncio.run(bench.run_bench(n=1, suite="nope", log_dir=tmp_path,
                                        llm=None))

    def test_list_runs_suite_default_for_old_files(
            self, tmp_path: Path) -> None:
        # 旧版运行文件（无 suite 字段）-> 默认 malware_analysis
        old = {"run_id": "20260101_000000_base_n1", "mode": "base", "n": 1,
               "scores": {"n": 1}}
        (tmp_path / "20260101_000000_base_n1.json").write_text(
            json.dumps(old), encoding="utf-8")
        runs = bench.list_runs(tmp_path)
        assert runs[0]["suite"] == "malware_analysis"
