"""bench/cybersoceval 测试（B4）— LLM 全部 mock，无网络。

  - 题目加载与确定性采样；
  - 容错答案解析（markdown 围栏 / 中文“答案是” / 裸字母 / 垃圾输出）；
  - 评分（exact-match 与 Jaccard）；
  - run_bench 端到端（mock LLM + 注入 KB）与结果持久化。
"""

from __future__ import annotations

import asyncio
import json

import pytest

from cyberorion.bench import cybersoceval as bench


@pytest.fixture()
def questions_path(tmp_path):
    qs = [
        {"question": f"Q{i} what does the malware do?",
         "options": ["A. Steal data", "B. Execute commands",
                     "C. Mine coins", "D. Update itself"],
         "correct_options": ["A", "B"],
         "topic": "Risk Assessment" if i % 2 == 0 else "Evasion Techniques",
         "difficulty": ["easy", "medium", "hard"][i % 3],
         "attack": "infostealers", "sha256": f"{i:064x}"}
        for i in range(20)
    ]
    p = tmp_path / "questions.json"
    p.write_text(json.dumps(qs), encoding="utf-8")
    return p


class TestLoader:
    def test_load(self, questions_path):
        qs = bench.load_questions(questions_path)
        assert len(qs) == 20
        q = qs[0]
        assert q["correct_options"] == ["A", "B"]
        assert q["difficulty"] == "easy"
        assert q["topic"] == "Risk Assessment"

    def test_bad_schema(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps([{"question": "x"}]), encoding="utf-8")
        with pytest.raises(ValueError):
            bench.load_questions(p, strict=True)
        # 非 strict 模式跳过无效条目
        assert bench.load_questions(p) == []

    def test_deterministic_sample(self, questions_path):
        qs = bench.load_questions(questions_path)
        a = bench.sample_questions(qs, 5, seed=42)
        b = bench.sample_questions(qs, 5, seed=42)
        c = bench.sample_questions(qs, 5, seed=7)
        assert [q["idx"] for q in a] == [q["idx"] for q in b]
        assert [q["idx"] for q in a] != [q["idx"] for q in c]
        assert len(a) == 5


class TestParser:
    @pytest.mark.parametrize("text,expected", [
        ('推理过程……\nANSWER: ["A","C"]', ["A", "C"]),
        ("ANSWER: [A, C]", ["A", "C"]),
        ("```json\nANSWER: [\"B\"]\n```", ["B"]),
        ("ANSWER: A and C", ["A", "C"]),
        ("答案是 AC", ["A", "C"]),
        ("答案：A、C", ["A", "C"]),
        ("答案是：B", ["B"]),
        ("我认为应该选 [\"A\", \"D\"]", ["A", "D"]),
        ("推理一长串\nA, C", ["A", "C"]),
        ('选 ["A"]，不对，最终 ANSWER: ["B","C"]', ["B", "C"]),
    ])
    def test_messy_formats(self, text, expected):
        assert bench.parse_answers(text) == expected

    @pytest.mark.parametrize("text", [
        "",
        "我完全不知道",
        "ANSWER:",
        "没有字母只有汉字",
    ])
    def test_unparseable(self, text):
        assert bench.parse_answers(text) == []


class TestGrading:
    def test_exact(self):
        assert bench.grade(["A", "B"], ["A", "B"]) == (True, 1.0)
        assert bench.grade(["B", "A"], ["A", "B"]) == (True, 1.0)

    def test_partial(self):
        exact, jac = bench.grade(["A"], ["A", "B"])
        assert exact is False and abs(jac - 0.5) < 1e-9
        exact, jac = bench.grade(["A", "C"], ["A", "B"])
        assert exact is False and abs(jac - 1 / 3) < 1e-9

    def test_empty_pred(self):
        assert bench.grade([], ["A"]) == (False, 0.0)


# ----------------------------------------------------------------------- #
# run_bench 端到端（mock LLM）
# ----------------------------------------------------------------------- #
def _mock_llm(mapping):
    async def call(system, user):
        for key, ans in mapping.items():
            if key in user:
                return ans
        return "ANSWER: [\"A\",\"B\"]"
    return call


class TestRunBench:
    def test_base_run_and_persist(self, questions_path, tmp_path):
        llm = _mock_llm({"Q0": 'ANSWER: ["A","B"]',
                         "Q1": "ANSWER: [\"A\"]",      # 半对
                         "Q2": "不知道"})               # parse_fail
        run = asyncio.run(bench.run_bench(
            n=6, mode="base", seed=42,
            questions_path=questions_path, log_dir=tmp_path, llm=llm))
        s = run["scores"]
        assert s["n"] == 6
        assert 0.0 <= s["correct_mc_pct"] <= 1.0
        assert "by_difficulty" in s and "by_topic" in s
        # 持久化
        saved = json.loads((tmp_path / f"{run['run_id']}.json")
                           .read_text(encoding="utf-8"))
        assert saved["run_id"] == run["run_id"]
        assert saved["scores"] == run["scores"]
        assert len(saved["results"]) == 6

    def test_all_correct_scores_one(self, questions_path, tmp_path):
        run = asyncio.run(bench.run_bench(
            n=4, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({})))
        assert run["scores"]["correct_mc_pct"] == 1.0
        assert run["scores"]["avg_score"] == 1.0
        assert run["scores"]["parse_fail"] == 0

    def test_llm_error_counts_wrong(self, questions_path, tmp_path):
        async def boom(system, user):
            raise RuntimeError("endpoint down")
        run = asyncio.run(bench.run_bench(
            n=3, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=boom))
        assert run["scores"]["correct_mc_pct"] == 0.0
        assert run["scores"]["parse_fail"] == 3
        assert "__LLM_ERROR__" in run["results"][0]["raw"]

    def test_same_questions_across_modes(self, questions_path, tmp_path):
        kb_hits = []

        class FakeKB:
            def search(self, query, k):
                kb_hits.append(query)
                return []

        llm = _mock_llm({})
        base = asyncio.run(bench.run_bench(
            n=5, mode="base", seed=42, questions_path=questions_path,
            log_dir=tmp_path, llm=llm))
        rag = asyncio.run(bench.run_bench(
            n=5, mode="rag", seed=42, questions_path=questions_path,
            log_dir=tmp_path, llm=llm, kb=FakeKB()))
        assert [r["idx"] for r in base["results"]] == \
               [r["idx"] for r in rag["results"]]
        # rag v5 两段式检索：stage-1 无结果（得分 0 < 阈值）时每题再触发
        # stage-2，共 2 次/题
        assert len(kb_hits) == 10
        # stage-1 查询携带家族类别（attack 元数据）
        assert any(h.startswith("infostealers ") for h in kb_hits)

    def test_progress_callback(self, questions_path, tmp_path):
        seen = []
        asyncio.run(bench.run_bench(
            n=3, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}),
            on_progress=lambda d, t: seen.append((d, t))))
        assert seen[-1] == (3, 3)

    def test_list_runs(self, questions_path, tmp_path):
        asyncio.run(bench.run_bench(
            n=2, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({})))
        runs = bench.list_runs(tmp_path)
        assert len(runs) == 1
        assert runs[0]["mode"] == "base"
        assert runs[0]["scores"]["correct_mc_pct"] == 1.0


# ----------------------------------------------------------------------- #
# self-consistency：多数投票与 sc 模式
# ----------------------------------------------------------------------- #
class TestMajorityVote:
    def test_threshold_two_of_three(self):
        assert bench.majority_vote(
            [["A", "B"], ["A", "C"], ["A", "B"]], k=3) == ["A", "B"]

    def test_failed_samples_lose_vote(self):
        # 解析失败（空列表）只是不投票；2 个有效样本一致即可入选
        assert bench.majority_vote([["A", "B"], [], ["A", "B"]], k=3) \
            == ["A", "B"]

    def test_all_fail_returns_empty(self):
        assert bench.majority_vote([[], [], []], k=3) == []

    def test_no_consensus_returns_empty(self):
        assert bench.majority_vote([["A"], ["B"], ["C"]], k=3) == []

    def test_single_sample_cannot_reach_threshold(self):
        assert bench.majority_vote([["A"], [], []], k=3) == []

    def test_duplicate_letters_counted_once(self):
        # 同一次采样内重复出现的选项只算一票
        assert bench.majority_vote(
            [["A", "A"], ["B"], ["B"]], k=3) == ["B"]


def _scripted_llm(script):
    """mock LLM：同一题目按调用次序轮流返回 script[key] 中的应答。"""
    calls: dict[str, int] = {}

    async def call(system, user):
        for key, seq in script.items():
            if key in user:
                i = calls.get(key, 0)
                calls[key] = i + 1
                return seq[i % len(seq)]
        return "ANSWER: [\"A\",\"B\"]"
    return call


class TestSelfConsistency:
    def test_sc_vote_wins(self, questions_path, tmp_path):
        # Q0: 3 次采样 2 次 [A,B] 1 次 [A] -> 投票得 [A,B]（全对）
        llm = _scripted_llm({
            "Q0": ["ANSWER: [\"A\",\"B\"]", "ANSWER: [\"A\"]",
                   "ANSWER: [\"A\",\"B\"]"]})
        run = asyncio.run(bench.run_bench(
            n=4, mode="sc", seed=42, questions_path=questions_path,
            log_dir=tmp_path, llm=llm, kb=FakeKB(), sc_k=3))
        assert run["sc_k"] == 3 and run["sc_temperature"] == 0.7
        r0 = next(r for r in run["results"] if "Q0" in r["question"])
        assert r0["pred"] == ["A", "B"] and r0["exact"] is True

    def test_sc_all_samples_fail_is_parse_fail(self, questions_path,
                                               tmp_path):
        llm = _scripted_llm({"Q0": ["不知道", "完全没思路", "???"]})
        run = asyncio.run(bench.run_bench(
            n=4, mode="sc", seed=42, questions_path=questions_path,
            log_dir=tmp_path, llm=llm, kb=FakeKB(), sc_k=3))
        r0 = next(r for r in run["results"] if "Q0" in r["question"])
        assert r0["pred"] == [] and r0["parse_ok"] is False
        assert run["scores"]["parse_fail"] >= 1

    def test_sc_each_question_sampled_k_times(self, questions_path,
                                              tmp_path):
        counts = {"n": 0}

        async def counting(system, user):
            counts["n"] += 1
            return "ANSWER: [\"A\",\"B\"]"
        asyncio.run(bench.run_bench(
            n=3, mode="sc_base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=counting, sc_k=3))
        assert counts["n"] == 9  # 3 题 × 3 次采样

    def test_sc_base_does_not_touch_kb(self, questions_path, tmp_path):
        # sc_base 不注入 kb 也不应检索：传一个会爆炸的 kb 验证没人调它
        class ExplodingKB:
            def search(self, query, k):
                raise AssertionError("sc_base 不应调用 KB")
        run = asyncio.run(bench.run_bench(
            n=3, mode="sc_base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}), kb=ExplodingKB()))
        assert run["scores"]["correct_mc_pct"] == 1.0
        assert run["rag_top_k"] == 0

    def test_sc_uses_rag_prompt_and_kb(self, questions_path, tmp_path):
        hits = []

        class FakeKB2:
            def search(self, query, k):
                hits.append(query)
                return []
        asyncio.run(bench.run_bench(
            n=3, mode="sc", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}), kb=FakeKB2()))
        # 每题检索一次（而非每采样一次）；v5 两段式：stage-1 空结果触发
        # stage-2，共 2 次/题
        assert len(hits) == 6

    def test_unknown_mode_rejected(self, questions_path, tmp_path):
        with pytest.raises(ValueError):
            asyncio.run(bench.run_bench(
                n=2, mode="sc2", seed=1, questions_path=questions_path,
                log_dir=tmp_path, llm=_mock_llm({})))


class FakeKB:
    def search(self, query, k):
        return []


class TestFewShot:
    def test_rag_fs_prompt_contains_examples(self):
        q = {"question": "某样本做了什么？", "options": ["A. x", "B. y"]}
        system, user = bench.build_prompt(q, "rag_fs", [])
        assert "【示例 1】" in user and "【示例 2】" in user
        assert "【待答题目】" in user
        assert system == bench._SYSTEM_RAG

    def test_rag_fs_end_to_end(self, questions_path, tmp_path):
        run = asyncio.run(bench.run_bench(
            n=3, mode="rag_fs", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}), kb=FakeKB()))
        assert run["scores"]["correct_mc_pct"] == 1.0
        assert run["prompt_version"] == bench.PROMPT_VERSION_FS


class TestGuessForced:
    def test_rag_g_prompt_has_guess_rules(self):
        q = {"question": "某样本做了什么？", "options": ["A. x", "B. y"]}
        system, user = bench.build_prompt(q, "rag_g", [])
        assert system == bench._SYSTEM_RAG
        assert "禁止弃答" in user
        assert "ANSWER: []" in user          # 明确点名禁止空答案
        assert "最佳猜测" in user
        assert "宁缺毋滥" in user            # 保持 v2 精神
        assert "【待答题目】" in user

    def test_rag_g_legacy_has_no_knowledge_guidance(self):
        # rag_g 是冻结的 legacy v4 配方：旧知识头、无 v5 知识使用指引
        q = {"question": "某样本做了什么？", "options": ["A. x", "B. y"]}
        _, user = bench.build_prompt(q, "rag_g", [])
        assert "【检索到的 MITRE ATT&CK 知识】" in user
        assert "知识用法" not in user

    def test_rag_g_end_to_end(self, questions_path, tmp_path):
        run = asyncio.run(bench.run_bench(
            n=3, mode="rag_g", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}), kb=FakeKB()))
        assert run["scores"]["correct_mc_pct"] == 1.0
        assert run["prompt_version"] == bench.PROMPT_VERSION_G
        assert run["rag_top_k"] == bench.RAG_TOP_K

    def test_modes_single_source_of_truth(self):
        assert "rag_g" in bench.MODES and "sc" in bench.MODES


# ----------------------------------------------------------------------- #
# rag v5（默认）：禁止弃答 + 知识使用指引
# ----------------------------------------------------------------------- #
class TestRagV5:
    def test_rag_v5_prompt(self):
        q = {"question": "某样本做了什么？", "options": ["A. x", "B. y"]}
        system, user = bench.build_prompt(q, "rag", [])
        assert system == bench._SYSTEM_RAG
        assert "禁止弃答" in user             # 并入原 rag_g v4 规则
        assert "最佳猜测" in user
        assert "宁缺毋滥" in user
        assert "知识用法" in user             # v5 新增知识使用指引
        assert "逐项裁决" in user             # v6 新增逐项裁决
        assert "【检索到的恶意软件知识】" in user
        assert "【待答题目】" in user

    def test_rag_v5_end_to_end(self, questions_path, tmp_path):
        run = asyncio.run(bench.run_bench(
            n=3, mode="rag", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}), kb=FakeKB()))
        assert run["scores"]["correct_mc_pct"] == 1.0
        assert run["prompt_version"] == bench.PROMPT_VERSION
        assert bench.PROMPT_VERSION > bench.PROMPT_VERSION_G

    def test_sc_uses_v5_prompt_version(self, questions_path, tmp_path):
        run = asyncio.run(bench.run_bench(
            n=2, mode="sc", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}), kb=FakeKB(), sc_k=2))
        assert run["prompt_version"] == bench.PROMPT_VERSION


# ----------------------------------------------------------------------- #
# 两段式检索
# ----------------------------------------------------------------------- #
class _ScoredKB:
    """按预设得分返回假文档的 KB stub。"""

    def __init__(self, scores):
        self.scores = list(scores)     # 每次 search 依序弹出一个得分
        self.queries: list[str] = []

    def search(self, query, k):
        self.queries.append(query)
        score = self.scores.pop(0)
        if score <= 0:
            return []
        return [{"id": f"D{len(self.queries)}", "name": "d", "text": "t",
                 "score": score}]


_Q = {"question": "What does the sample do?", "attack": "remcos",
      "options": ["A. Keylogging", "B. Screen capture"]}


class TestTwoStageRetrieval:
    def test_stage1_sufficient_single_call(self):
        kb = _ScoredKB([0.9])
        docs = bench.retrieve_for_question(kb, _Q, k=3)
        assert len(kb.queries) == 1
        assert kb.queries[0].startswith("remcos ")
        assert docs[0]["score"] == 0.9

    def test_low_score_triggers_stage2(self):
        kb = _ScoredKB([0.1, 0.8])
        docs = bench.retrieve_for_question(kb, _Q, k=3)
        assert len(kb.queries) == 2
        # stage-2 查询 = stage-1 + 选项文本（去掉字母标号）
        assert "Keylogging" in kb.queries[1]
        assert "A." not in kb.queries[1]
        assert docs[0]["score"] == 0.8

    def test_stage2_worse_keeps_stage1(self):
        kb = _ScoredKB([0.3, 0.2])
        docs = bench.retrieve_for_question(kb, _Q, k=3)
        assert len(kb.queries) == 2
        assert docs[0]["score"] == 0.3

    def test_no_attack_metadata(self):
        kb = _ScoredKB([0.9])
        q = {"question": "Q?", "options": ["A. x"]}
        bench.retrieve_for_question(kb, q, k=3)
        assert kb.queries[0] == "Q?"

    def test_strip_option_prefix(self):
        assert bench._strip_option_prefix("A. Packing (UPX)") == \
            "Packing (UPX)"
        assert bench._strip_option_prefix("B、隐藏文件") == "隐藏文件"


class TestPlaybookInjection:
    class _KBWithLookup(_ScoredKB):
        def __init__(self, scores, playbook):
            super().__init__(scores)
            self._playbook = playbook

        def lookup(self, doc_id):
            return self._playbook if doc_id == "SBX011" else None

    _PLAYBOOK = {"id": "SBX011", "name": "Remcos playbook",
                 "type": "sandbox_report", "text": "remcos behavior"}

    def test_playbook_prepended_and_deduped(self):
        # stage-1 命中（0.9 单调用）；playbook 应置顶且不重复
        kb = self._KBWithLookup([0.9], dict(self._PLAYBOOK))
        docs = bench.retrieve_for_question(kb, _Q, k=3)
        assert docs[0]["id"] == "SBX011"
        assert [d["id"] for d in docs].count("SBX011") == 1

    def test_playbook_dedup_against_retrieved(self):
        # 检索结果本身含 playbook 时只保留置顶的一份
        kb = self._KBWithLookup([0.9], dict(self._PLAYBOOK))
        orig_search = kb.search

        def search(query, k):
            return [dict(self._PLAYBOOK, score=0.9)] + orig_search(query, k)
        kb.search = search
        docs = bench.retrieve_for_question(kb, _Q, k=3)
        assert [d["id"] for d in docs].count("SBX011") == 1

    def test_unknown_category_no_injection(self):
        kb = self._KBWithLookup([0.9], dict(self._PLAYBOOK))
        q = {"question": "Q?", "attack": "unknown_family",
             "options": ["A. x"]}
        docs = bench.retrieve_for_question(kb, q, k=3)
        assert all(d["id"] != "SBX011" for d in docs)

    def test_kb_without_lookup_still_works(self):
        # 旧式 KB stub（无 lookup 方法）不报错、不注入
        kb = _ScoredKB([0.9])
        docs = bench.retrieve_for_question(kb, _Q, k=3)
        assert docs and docs[0]["score"] == 0.9

    def test_playbook_map_covers_dataset_categories(self):
        for cat in ("infostealers", "ransomware", "killers", "remcos",
                    "um_unhooking"):
            assert cat in bench.ATTACK_PLAYBOOK


# ----------------------------------------------------------------------- #
# LLM endpoint 故障可见性（__LLM_ERROR__ -> run.llm_errors/error/status）
# ----------------------------------------------------------------------- #
class TestLlmErrorSurfacing:
    def test_total_failure_marks_run_error(self, questions_path, tmp_path):
        async def broken(system, user):
            raise RuntimeError("402 Payment Required: account arrears")

        run = asyncio.run(bench.run_bench(
            n=4, mode="base", seed=42, questions_path=questions_path,
            log_dir=tmp_path, llm=broken))
        assert run["status"] == "error"
        assert run["llm_errors"] == run["n"] == 4
        assert run["error"] and "402" in run["error"]
        assert run["scores"]["llm_errors"] == 4
        assert all(r["llm_error"] for r in run["results"])
        # 持久化文件同样带 status/error（GET /api/bench/run/{id} 直接透传）
        saved = json.loads(
            (tmp_path / f"{run['run_id']}.json").read_text(encoding="utf-8"))
        assert saved["status"] == "error" and "402" in saved["error"]

    def test_partial_failure_stays_done(self, questions_path, tmp_path):
        calls = {"n": 0}

        async def flaky(system, user):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("endpoint boom")
            return "ANSWER: [\"A\",\"B\"]"

        run = asyncio.run(bench.run_bench(
            n=4, mode="base", seed=42, questions_path=questions_path,
            log_dir=tmp_path, llm=flaky))
        assert run["status"] == "done"
        assert run["llm_errors"] == 1
        assert run["scores"]["llm_errors"] == 1
        assert run["error"] and "TimeoutError" in run["error"]
        assert run["scores"]["correct_mc_pct"] == 0.75

    def test_no_failure_has_clean_fields(self, questions_path, tmp_path):
        run = asyncio.run(bench.run_bench(
            n=3, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({})))
        assert run["status"] == "done"
        assert run["llm_errors"] == 0
        assert run["error"] is None
        assert run["scores"]["llm_errors"] == 0

    def test_on_progress_reports_llm_errors(self, questions_path, tmp_path):
        seen = []

        async def broken(system, user):
            raise RuntimeError("down")

        asyncio.run(bench.run_bench(
            n=3, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=broken,
            on_progress=lambda d, t, e: seen.append((d, t, e))))
        assert seen[-1] == (3, 3, 3)

    def test_two_arg_on_progress_still_works(self, questions_path, tmp_path):
        seen = []
        asyncio.run(bench.run_bench(
            n=2, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=_mock_llm({}),
            on_progress=lambda d, t: seen.append((d, t))))
        assert seen[-1] == (2, 2)

    def test_list_runs_surfaces_error_fields(self, questions_path, tmp_path):
        async def broken(system, user):
            raise RuntimeError("arrears")

        asyncio.run(bench.run_bench(
            n=2, mode="base", seed=1, questions_path=questions_path,
            log_dir=tmp_path, llm=broken))
        runs = bench.list_runs(tmp_path)
        assert runs and runs[0]["status"] == "error"
        assert runs[0]["llm_errors"] == 2
        assert "arrears" in (runs[0]["error"] or "")
