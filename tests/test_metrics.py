"""P4 评估引擎测试：metrics / judge 模板回退 / finalize_session / CybORG 适配器。

全部使用 tmp_path 下的真实 TelemetryStore 预填合成数据，不需要 docker、
不需要网络、不需要 LLM。
"""

from __future__ import annotations

import json

import pytest

from cyberorion.eval import judge as judge_mod
from cyberorion.eval.benchmarks import run_cage2
from cyberorion.eval.judge import generate_judge_report
from cyberorion.eval.metrics import compute_metrics
from cyberorion.eval.report import finalize_session
from cyberorion.telemetry.store import TelemetryStore

T0 = 1_700_000_000.0  # 固定基准时间，避免 time.time() 带来的不确定性


@pytest.fixture()
def store(tmp_path):
    s = TelemetryStore(tmp_path / "telemetry.db", session_id="session_eval")
    yield s
    s.close()


def _fill_main(store: TelemetryStore) -> None:
    """主场景：3 次已验证攻击，2 次被检测（+45s/+120s），1 次漏报；
    1 条不匹配的恶意告警 -> FP；1 次防御响应覆盖第 1 次检测。"""
    # 失败的攻击尝试（只计入 attacks_total / red_score 分母）。
    store.insert_attack(target="log4j", technique="T1210",
                        action="log4shell probe", success=False,
                        evidence="", ts=T0 - 100)
    # 3 次 VERIFIED 攻击。
    store.insert_attack(target="weak_ssh", technique="T1110",
                        action="ssh brute force", success=True,
                        evidence="uid=1000", ts=T0)
    store.insert_attack(target="dvwa", technique="T1190",
                        action="sqli dump", success=True,
                        evidence="admin:password", ts=T0 + 100)
    store.insert_attack(target="weak_ssh", technique="T1078",
                        action="ssh login", success=True,
                        evidence="flag{ssh}", ts=T0 + 200)
    # 告警 1：+45s 检测 attack1。
    store.insert_alert(host="weak_ssh", technique="T1110", verdict="malicious",
                       confidence=0.9, evidence="5 failed logins", ts=T0 + 45)
    # 告警 2：+120s 检测 attack2（host 用容器名，测试容器名等价匹配）。
    store.insert_alert(host="cyberorion_dvwa", technique="T1190",
                       verdict="malicious", confidence=0.85,
                       evidence="UNION SELECT in access.log", ts=T0 + 220)
    # 告警 3：不匹配任何已验证攻击 -> FP（技术前缀 T9 不命中 T1）。
    store.insert_alert(host="weak_ssh", technique="T9999", verdict="malicious",
                       confidence=0.4, evidence="noise", ts=T0 + 50)
    # 良性告警：不进入恶意统计。
    store.insert_alert(host="dvwa", technique="T1190", verdict="benign",
                       confidence=0.2, evidence="normal traffic", ts=T0 + 60)
    # 防御响应：attack1 之后 50s（在窗口内）-> 覆盖第 1 次检测。
    store.insert_event(host="cyberorion_weak_ssh", source="response",
                       severity="info", summary="block_ip: 封禁 1.2.3.4",
                       ts=T0 + 50)


# ---------------------------------------------------------------------------
# compute_metrics 主场景
# ---------------------------------------------------------------------------

class TestComputeMetrics:
    def test_main_scenario_exact_values(self, store):
        _fill_main(store)
        m = compute_metrics(store)

        assert m["totals"] == {
            "attacks_total": 4, "attacks_verified": 3,
            "attacks_recon": 0,
            "alerts": 4, "alerts_malicious": 3,
        }
        assert m["tp"] == 2 and m["fn"] == 1 and m["fp"] == 1
        assert m["detection_rate"] == pytest.approx(2 / 3, abs=1e-4)
        assert m["fp_rate"] == pytest.approx(1 / 3, abs=1e-4)
        assert m["mttd_sec"] == pytest.approx(82.5)

        # 检测明细：TTD 与弱标记。
        ttds = sorted(d["ttd_sec"] for d in m["detections"])
        assert ttds == [pytest.approx(45.0), pytest.approx(120.0)]
        assert all(not d["weak"] for d in m["detections"])
        assert len(m["missed"]) == 1
        assert m["missed"][0]["technique"] == "T1078"
        assert len(m["false_positives"]) == 1
        assert m["false_positives"][0]["technique"] == "T9999"

        # 响应统计：2 次检测中 1 次有窗口内响应。
        assert m["response"] == {
            "total": 1, "responded": 1, "response_rate": 0.5,
        }

        # 评分公式：50*det + 25*(1-fp_capped) + 25*response_rate。
        expected_blue = 50 * (2 / 3) + 25 * (1 - 1 / 3) + 25 * 0.5
        assert m["blue_score"] == pytest.approx(expected_blue, abs=0.05)
        # 红方：3 次已验证 / 4 次尝试。
        assert m["red_score"] == pytest.approx(75.0)

    def test_per_technique_and_per_target(self, store):
        _fill_main(store)
        m = compute_metrics(store)
        assert m["per_technique"]["T1110"] == {
            "attacks": 1, "detected": 1, "detection_rate": 1.0}
        assert m["per_technique"]["T1078"] == {
            "attacks": 1, "detected": 0, "detection_rate": 0.0}
        assert m["per_target"]["weak_ssh"] == {
            "attacks": 2, "detected": 1, "detection_rate": 0.5}
        assert m["per_target"]["dvwa"]["detected"] == 1

    def test_empty_store(self, store):
        m = compute_metrics(store)
        assert m["totals"]["attacks_total"] == 0
        assert m["detection_rate"] == 0.0
        assert m["mttd_sec"] is None
        assert m["blue_score"] == 25.0  # 0 检测 + 无误报 + 无响应
        assert m["red_score"] == 0.0


# ---------------------------------------------------------------------------
# 匹配规则
# ---------------------------------------------------------------------------

class TestMatchingRules:
    def test_technique_prefix_match(self, store):
        """子技术 T1110.001 对告警 T1110：同战术前缀 -> 命中。"""
        store.insert_attack(target="weak_ssh", technique="T1110.001",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 + 30)
        m = compute_metrics(store)
        assert m["tp"] == 1 and m["fp"] == 0

    def test_empty_technique_wildcard_half_credit(self, store):
        """任一侧技术为空 -> 通配匹配但 weak=True（半信用）。"""
        store.insert_attack(target="weak_ssh", technique="",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 + 30)
        m = compute_metrics(store)
        assert m["tp"] == 1
        assert m["detections"][0]["weak"] is True
        assert m["per_technique"]["(unknown)"]["detected"] == 1

    def test_web_target_matches_http_services(self, store):
        """attack.target='web' 匹配任何带 http 服务的目标（含容器名）。"""
        store.insert_attack(target="web", technique="T1190",
                            action="sqli", success=True, evidence="e", ts=T0)
        store.insert_alert(host="cyberorion_log4j", technique="T1190",
                           verdict="malicious", confidence=0.8,
                           evidence="jndi", ts=T0 + 20)
        m = compute_metrics(store)
        assert m["tp"] == 1

    def test_web_target_does_not_match_ssh_host(self, store):
        """'web' 不应匹配纯 ssh 目标。"""
        store.insert_attack(target="web", technique="T1190",
                            action="sqli", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1190",
                           verdict="malicious", confidence=0.8,
                           evidence="x", ts=T0 + 20)
        m = compute_metrics(store)
        assert m["tp"] == 0 and m["fp"] == 1

    def test_ip_target_matches_named_alert(self, store):
        """attack.target 为场景目标 IP（红方工具按 LLM 传入的标识记录）
        时，等价于该目标名/容器名 -> 命中。"""
        store.insert_attack(target="172.29.0.12", technique="T1110",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 + 30)
        m = compute_metrics(store)
        assert m["tp"] == 1 and m["fp"] == 0

    def test_window_boundary_miss(self, store):
        """告警晚于 window_sec（默认 600）到达 -> 漏报。"""
        store.insert_attack(target="weak_ssh", technique="T1110",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 + 601)
        m = compute_metrics(store)
        assert m["tp"] == 0 and m["fn"] == 1 and m["fp"] == 1
        # 窗口内（600s 整）则命中。
        m2 = compute_metrics(store, window_sec=601)
        assert m2["tp"] == 1

    def test_alert_before_attack_within_tolerance(self, store):
        """告警早于攻击 30s 内（采集时钟差）仍可命中。"""
        store.insert_attack(target="weak_ssh", technique="T1110",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 - 25)
        m = compute_metrics(store)
        assert m["tp"] == 1
        assert m["detections"][0]["ttd_sec"] == pytest.approx(-25.0)

    def test_first_alert_wins(self, store):
        """同一攻击有多条命中告警时取时间最早的一条。"""
        store.insert_attack(target="weak_ssh", technique="T1110",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="late", ts=T0 + 300)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="early", ts=T0 + 60)
        m = compute_metrics(store)
        assert m["mttd_sec"] == pytest.approx(60.0)


# ---------------------------------------------------------------------------
# 响应统计
# ---------------------------------------------------------------------------

class TestResponseStats:
    def test_response_before_attack_not_counted(self, store):
        """响应事件早于攻击发生 -> 不计入该攻击的响应。"""
        store.insert_attack(target="weak_ssh", technique="T1110",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 + 30)
        store.insert_event(host="h", source="response", severity="info",
                           summary="block_ip: old", ts=T0 - 10)
        m = compute_metrics(store)
        assert m["response"]["total"] == 1
        assert m["response"]["responded"] == 0
        assert m["response"]["response_rate"] == 0.0

    def test_non_response_events_ignored(self, store):
        store.insert_attack(target="weak_ssh", technique="T1110",
                            action="bf", success=True, evidence="e", ts=T0)
        store.insert_alert(host="weak_ssh", technique="T1110",
                           verdict="malicious", confidence=0.9,
                           evidence="x", ts=T0 + 30)
        store.insert_event(host="weak_ssh", source="auth", severity="high",
                           summary="ssh event", ts=T0 + 40)
        m = compute_metrics(store)
        assert m["response"]["total"] == 0


# ---------------------------------------------------------------------------
# judge 模板回退
# ---------------------------------------------------------------------------

class TestJudgeFallback:
    def test_llm_failure_falls_back_to_template(self, store, monkeypatch):
        """LLM 路径抛异常 -> 模板报告，且包含指标表与正确数字。"""
        _fill_main(store)
        m = compute_metrics(store)

        def _boom(facts, model=None):
            raise RuntimeError("no API key")

        monkeypatch.setattr(judge_mod, "_render_with_llm", _boom)
        report = generate_judge_report(store, m)

        assert "## 指标表" in report
        assert "## 战役概述" in report
        assert "## 判罚结论" in report
        assert "## 改进建议" in report
        # 数字正确：62.5 蓝方得分、检测率 66.7%、MTTD 82.5s。
        assert "62.5" in report
        assert "66.7%" in report
        assert "82.5s" in report
        # 红方时间线只含 verified 攻击（3 条），失败尝试不出现。
        assert "log4shell probe" not in report
        assert "ssh brute force" in report


# ---------------------------------------------------------------------------
# finalize_session
# ---------------------------------------------------------------------------

class TestFinalizeSession:
    def test_writes_report_and_metrics(self, store, tmp_path, monkeypatch):
        _fill_main(store)
        monkeypatch.setattr(
            judge_mod, "_render_with_llm",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")))

        session_dir = tmp_path / "session_x"
        m = finalize_session(store, session_dir)

        report_path = session_dir / "report.md"
        metrics_path = session_dir / "metrics.json"
        assert report_path.is_file() and metrics_path.is_file()
        assert "## 指标表" in report_path.read_text(encoding="utf-8")
        saved = json.loads(metrics_path.read_text(encoding="utf-8"))
        assert saved["tp"] == m["tp"] == 2
        assert saved["blue_score"] == m["blue_score"]


# ---------------------------------------------------------------------------
# CybORG 适配器（未安装时优雅降级）
# ---------------------------------------------------------------------------

class TestCyborgAdapter:
    def test_graceful_when_cyborg_absent(self):
        try:
            import CybORG  # noqa: F401
            pytest.skip("CybORG 已安装，跳过降级路径测试")
        except ImportError:
            pass
        result = run_cage2(episodes=1, steps=1)
        assert result["error"] == "CybORG not installed"
        assert "pip install" in result["install"]
