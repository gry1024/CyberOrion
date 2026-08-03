"""客观评估指标引擎：红方地面真值 × 蓝方告警对齐 -> 真实检测指标。

纯函数、仅依赖标准库 + 场景加载器（load_scenario 失败时降级为精确匹配），
完全可在无 docker / 无网络环境下单元测试。

匹配规则（对每条 VERIFIED 攻击寻找蓝方【第一条】命中告警）：
  - 主机匹配（容差）：
      ① alert.host == attack.target（精确）；
      ② alert.host == attack.target 对应场景目标的容器名（反之亦然，
         目标名/容器名互为等价；attack.target 为场景目标 IP 时同样
         等价于该目标名/容器名）；
      ③ attack.target == "web" 时，匹配场景中任何带 http 服务的目标
         （目标名或容器名均可）。
  - 技术匹配：
      ① ATT&CK 编号精确相等；
      ② 前 2 字符（战术前缀）相同（如 T1110.001 对 T1110）；
      ③ 任一侧 technique 为空串 -> 通配匹配，但记为半信用
         （match=True, weak=True）。
  - 时间窗口：attack.ts - 30 <= alert.ts <= attack.ts + window_sec。

指标定义：
  - TP / FN：被检测到 / 漏报的 VERIFIED 攻击数；
  - FP：verdict 为 malicious/suspicious 但不匹配任何 VERIFIED 攻击的告警数；
  - detection_rate = TP / attacks_verified（无已验证攻击时为 0）；
  - fp_rate = FP / alerts_malicious（alerts_malicious = verdict 为
    malicious/suspicious 的告警总数，为 0 时 fp_rate 为 0）；
  - MTTD：所有 TP 的 (alert.ts - attack.ts) 均值（秒，可低至 -30）；
  - response_rate：被检测到的攻击中，在 [attack.ts, attack.ts + window_sec]
    内存在 source='response' 防御事件（block_ip / harden_service 埋点）的比例。

评分公式（0-100，文档即实现）：
  blue_score = 50 * detection_rate
             + 25 * (1 - min(fp_rate, 1.0))
             + 25 * response_rate
  red_score  = 100 * attacks_verified / attacks_total（红方已验证成功率，
             无攻击尝试时为 0）
"""

from __future__ import annotations

from typing import Any

# 判定为"恶意倾向"的告警 verdict 集合（FP 统计与 alerts_malicious 的分母）。
_MALICIOUS_VERDICTS = ("malicious", "suspicious")

# 告警相对攻击时间的容差：允许告警比攻击早 30 秒（采集时钟差）。
_PRE_TOLERANCE_SEC = 30.0


def _load_scenario_safe() -> Any:
    """加载当前场景；任何失败都返回 None（降级为仅精确匹配）。"""
    try:
        from ..scenarios import load_scenario
        return load_scenario()
    except Exception:
        return None


def _host_equiv(attack_target: str, scenario: Any) -> set:
    """返回与攻击目标等价的主机名集合（含容器名 / IP / http 泛化）。"""
    names = {attack_target}
    if scenario is None or not attack_target:
        return names
    targets = getattr(scenario, "targets", {}) or {}
    for t in targets.values():
        # 红方工具按 LLM 传入的标识记录 target —— 可能是目标名、容器名
        # 或场景里的 IP；三者指向同一台目标，判定检测时互为等价。
        if attack_target in (t.name, t.container) or \
                attack_target == getattr(t, "ip", ""):
            names |= {t.name, t.container}
    # 红方有时用宿主映射 127.0.0.1/localhost 访问 SSH 目标：无法归属到
    # 具体容器时，展开为全部带 SSH 服务的目标（蓝方告警 host 匹配即可）。
    if attack_target in ("127.0.0.1", "localhost", "0.0.0.0"):
        for t in targets.values():
            svcs = (t.services or {}).values()
            if any(getattr(s, "proto", "") == "ssh" for s in svcs):
                names |= {t.name, t.container}
    # "web" 泛化：任何带 http 服务的目标都算命中。
    if attack_target == "web":
        for t in targets.values():
            if any(getattr(s, "proto", "") == "http"
                   for s in (t.services or {}).values()):
                names |= {t.name, t.container}
    return names


def _technique_match(a_tech: str, b_tech: str) -> "tuple[bool, bool]":
    """技术匹配判定，返回 (是否匹配, 是否半信用/weak)。"""
    if not a_tech or not b_tech:
        return True, True  # 任一侧为空 -> 通配半信用
    if a_tech == b_tech:
        return True, False
    if len(a_tech) >= 2 and len(b_tech) >= 2 and a_tech[:2] == b_tech[:2]:
        return True, False  # 同战术前缀（如 T1110.001 对 T1110）
    return False, False


def _matches(attack: dict, alert: dict, equiv: set, window_sec: float) -> "tuple[bool, bool]":
    """判断 alert 是否是 attack 的有效检测，返回 (是否命中, 是否 weak)。"""
    if (alert.get("host") or "") not in equiv:
        return False, False
    tech_ok, weak = _technique_match(
        attack.get("technique") or "", alert.get("technique") or "")
    if not tech_ok:
        return False, False
    a_ts = float(attack.get("ts") or 0)
    b_ts = float(alert.get("ts") or 0)
    if not (a_ts - _PRE_TOLERANCE_SEC <= b_ts <= a_ts + window_sec):
        return False, False
    return True, weak


def compute_metrics(store: Any, window_sec: int = 600) -> dict:
    """对 store 中的红方地面真值与蓝方告警计算检测指标。

    Args:
        store: TelemetryStore（或提供 query_attacks/query_alerts/query_events
            的等价对象）。
        window_sec: 检测 / 响应归因的时间窗（秒），默认 600。

    Returns:
        指标字典（schema 见模块 docstring 与 README 说明），可直接 JSON 序列化。
    """
    window = float(window_sec)
    scenario = _load_scenario_safe()

    attacks = sorted(store.query_attacks(limit=100000),
                     key=lambda r: float(r.get("ts") or 0))
    alerts = sorted(store.query_alerts(limit=100000),
                    key=lambda r: float(r.get("ts") or 0))
    # 侦察类动作（nmap_scan 等）不留日志痕迹、蓝方无从检测：
    # 从检测率分母排除，只影响攻击计数展示，不计入 TP/FN。
    verified = [a for a in attacks
                if a.get("success") and not a.get("recon")]

    detections: list[dict] = []
    missed: list[dict] = []
    matched_alert_ids: set = set()
    per_technique: dict[str, dict] = {}
    per_target: dict[str, dict] = {}

    for atk in verified:
        equiv = _host_equiv(atk.get("target") or "", scenario)
        hit = None
        hit_weak = False
        for alert in alerts:  # 时间升序，第一条命中即检测
            ok, weak = _matches(atk, alert, equiv, window)
            if ok:
                hit = alert
                hit_weak = weak
                break
        tech = (atk.get("technique") or "").strip() or "(unknown)"
        tgt = (atk.get("target") or "").strip() or "(unknown)"
        for bucket, key in ((per_technique, tech), (per_target, tgt)):
            b = bucket.setdefault(key, {"attacks": 0, "detected": 0})
            b["attacks"] += 1
        if hit is not None:
            matched_alert_ids.add(hit["id"])
            per_technique[tech]["detected"] += 1
            per_target[tgt]["detected"] += 1
            detections.append({
                "attack_id": atk["id"],
                "alert_id": hit["id"],
                "target": atk.get("target") or "",
                "technique": atk.get("technique") or "",
                "ttd_sec": round(float(hit.get("ts") or 0)
                                 - float(atk.get("ts") or 0), 3),
                "weak": hit_weak,
            })
        else:
            missed.append({
                "attack_id": atk["id"],
                "target": atk.get("target") or "",
                "technique": atk.get("technique") or "",
                "action": atk.get("action") or "",
                "ts": float(atk.get("ts") or 0),
            })

    # FP：恶意倾向告警但不匹配任何 VERIFIED 攻击。
    malicious_alerts = [a for a in alerts
                        if (a.get("verdict") or "") in _MALICIOUS_VERDICTS]
    false_positives: list[dict] = []
    for alert in malicious_alerts:
        if alert["id"] in matched_alert_ids:
            continue
        matched_any = False
        for atk in verified:
            equiv = _host_equiv(atk.get("target") or "", scenario)
            ok, _weak = _matches(atk, alert, equiv, window)
            if ok:
                matched_any = True
                break
        if not matched_any:
            false_positives.append({
                "alert_id": alert["id"],
                "host": alert.get("host") or "",
                "technique": alert.get("technique") or "",
                "verdict": alert.get("verdict") or "",
                "confidence": float(alert.get("confidence") or 0),
                "ts": float(alert.get("ts") or 0),
            })

    tp = len(detections)
    fn = len(missed)
    fp = len(false_positives)
    n_verified = len(verified)
    n_malicious = len(malicious_alerts)
    # 侦察（recon）与可检测攻击分开统计：侦察不留日志、蓝方无从检测，
    # 只作展示（红方时间线标注），不进检测率分母。
    n_recon = sum(1 for a in attacks if a.get("recon"))

    detection_rate = tp / n_verified if n_verified else 0.0
    fp_rate = fp / n_malicious if n_malicious else 0.0
    mttd = (sum(d["ttd_sec"] for d in detections) / tp) if tp else None

    # 响应统计：source='response' 的防御事件（block_ip / harden_service 埋点）。
    responses = store.query_events(source="response", limit=100000)
    responded = 0
    for det in detections:
        atk = next(a for a in verified if a["id"] == det["attack_id"])
        a_ts = float(atk.get("ts") or 0)
        if any(a_ts <= float(ev.get("ts") or 0) <= a_ts + window
               for ev in responses):
            responded += 1
    response_rate = responded / tp if tp else 0.0

    for bucket in (per_technique, per_target):
        for b in bucket.values():
            b["detection_rate"] = (
                b["detected"] / b["attacks"] if b["attacks"] else 0.0)

    # 评分：公式见模块 docstring。
    blue_score = (50.0 * detection_rate
                  + 25.0 * (1.0 - min(fp_rate, 1.0))
                  + 25.0 * response_rate)
    red_score = (100.0 * n_verified / max(len(attacks) - n_recon, 1)) if attacks else 0.0

    return {
        "window_sec": int(window_sec),
        "scenario": (getattr(scenario, "name", "") or "") if scenario else "",
        "totals": {
            "attacks_total": len(attacks),
            "attacks_verified": n_verified,
            "attacks_recon": n_recon,
            "alerts": len(alerts),
            "alerts_malicious": n_malicious,
        },
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "detection_rate": round(detection_rate, 4),
        "fp_rate": round(fp_rate, 4),
        "mttd_sec": round(mttd, 3) if mttd is not None else None,
        "detections": detections,
        "missed": missed,
        "false_positives": false_positives,
        "per_technique": per_technique,
        "per_target": per_target,
        "response": {
            "total": len(responses),
            "responded": responded,
            "response_rate": round(response_rate, 4),
        },
        "blue_score": round(blue_score, 1),
        "red_score": round(red_score, 1),
    }
