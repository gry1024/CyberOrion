"""故事线复盘（storyline）：由会话详情生成中文叙事复盘报告。

与 :mod:`cyberorion.eval.judge` 同一模式：结构化事实先行，LLM 渲染为主、
模板渲染兜底（任何 LLM 失败都保证有产出，且明确标注「模板生成」）。

产物缓存到会话目录：
  - ``storyline.md``       复盘正文；
  - ``storyline.meta.json`` 生成元数据（llm 是否参与、生成时间），
    供 ``GET /api/sessions/{id}/storyline`` 返回 ``llm`` 标志。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from .session_detail import build_session_detail

STORYLINE_FILE = "storyline.md"
META_FILE = "storyline.meta.json"
# 模板兜底产物中的标识（旧会话无 meta 文件时据此推断 llm=False）。
_TEMPLATE_MARKER = "模板生成"

# 喂给 LLM 的单条证据最大长度。
_EVIDENCE_CLIP = 160


def _clip(text: Any, limit: int = _EVIDENCE_CLIP) -> str:
    text = str(text or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-"


# --------------------------------------------------------------------------- #
# 缓存
# --------------------------------------------------------------------------- #
def read_cached(session_dir: "str | Path") -> "tuple[str, bool] | None":
    """读取已缓存的 storyline；返回 (markdown, llm_used)，无缓存返回 None。"""
    session_dir = Path(session_dir)
    path = session_dir / STORYLINE_FILE
    if not path.is_file():
        return None
    try:
        md = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    llm_used = _TEMPLATE_MARKER not in md[:300]
    meta_path = session_dir / META_FILE
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            llm_used = bool(meta.get("llm", llm_used))
        except Exception:
            pass
    return md, llm_used


# --------------------------------------------------------------------------- #
# 事实抽取（LLM 路径与模板路径共用）
# --------------------------------------------------------------------------- #
def build_facts(detail: dict) -> dict:
    """从 session_detail 输出提炼复盘所需的结构化事实。"""
    attacks = sorted(detail.get("attacks") or [],
                     key=lambda r: float(r.get("ts") or 0))
    alerts = sorted(detail.get("alerts") or [],
                    key=lambda r: float(r.get("ts") or 0))
    counts = detail.get("counts") or {}
    metrics = detail.get("metrics") or {}
    return {
        "session_id": detail.get("id") or "",
        "counts": counts,
        "metrics_summary": {
            k: metrics.get(k) for k in
            ("blue_score", "red_score", "detection_rate", "fp_rate",
             "mttd_sec", "tp", "fn", "fp") if k in metrics
        },
        "attacks": [
            {
                "ts": float(a.get("ts") or 0),
                "time": _fmt_ts(float(a.get("ts") or 0)),
                "target": a.get("target") or "",
                "technique": a.get("technique") or "",
                "action": a.get("action") or "",
                "success": bool(a.get("success")),
                "evidence": _clip(a.get("evidence")),
            }
            for a in attacks
        ],
        "alerts": [
            {
                "ts": float(a.get("ts") or 0),
                "time": _fmt_ts(float(a.get("ts") or 0)),
                "host": a.get("host") or "",
                "technique": a.get("technique") or "",
                "verdict": a.get("verdict") or "",
                "confidence": float(a.get("confidence") or 0),
                "evidence": _clip(a.get("evidence")),
            }
            for a in alerts
        ],
        "responses": [
            {
                "ts": float(t.get("ts") or 0),
                "time": _fmt_ts(float(t.get("ts") or 0)),
                "summary": _clip(t.get("title") or t.get("detail")),
            }
            for t in (detail.get("timeline") or [])
            if t.get("kind") == "response"
        ],
    }


# --------------------------------------------------------------------------- #
# LLM 路径（与 eval/judge.py 相同的模型构造模式）
# --------------------------------------------------------------------------- #
_STORYLINE_INSTRUCTIONS = """你是一场红蓝对抗演练的战史记录官。给你一份结构化事实
JSON（红方攻击时间线、蓝方告警、防御处置、检测指标、统计计数），请输出一份
中文 Markdown 故事线复盘报告，严格使用以下章节标题：

# 故事线复盘
## 战役故事线
## 关键转折
## 蓝队表现评判
## 红队战术分析
## 改进建议

要求：
- 【战役故事线】按时间顺序叙述红蓝双方的交锋过程，引用具体时间（HH:MM:SS）、
  目标主机与 ATT&CK 技术编号；红方做了什么、蓝方何时发现、如何处置，写成
  连贯的叙事而不是流水账。
- 【关键转折】指出改变战局的 1-3 个关键节点（如首次成功突破、首次有效检测、
  关键处置）。
- 【蓝队表现评判】客观评价检测（检出/漏报）、处置（是否及时有效）与误报情况，
  明确指出不足之处，不粉饰。
- 【红队战术分析】分析红方的战术路径与技术选择（ATT&CK 视角）。
- 【改进建议】分别给蓝方与红方的可执行改进建议。
只依据给出的事实，不编造；数字必须与输入一致。直接输出报告正文。"""


def _render_with_llm(facts: dict, llm_fn: Callable | None = None) -> str:
    """LLM 渲染；任何失败抛异常由调用方兜底（模板路径）。"""
    prompt = (
        "以下是本场对抗演练的结构化事实（JSON），请据此撰写故事线复盘：\n"
        + json.dumps(facts, ensure_ascii=False, indent=2, default=str)
    )
    if llm_fn is not None:
        report = str(llm_fn(prompt) or "").strip()
    else:
        # 与 eval/judge.py 相同的模型构造模式（agents.blue._model +
        # cai.sdk.agents Runner，max_turns=1）。
        # Runner.run_sync 依赖当前线程的 event loop；本函数常经
        # asyncio.to_thread 在 worker 线程执行（无线程 loop），需先补建。
        import asyncio
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
        from cai.sdk.agents import Agent, Runner
        from .agents.blue import _model

        agent = Agent(
            name="StorylineWriter",
            instructions=_STORYLINE_INSTRUCTIONS,
            tools=[],
            model=_model(),
        )
        result = Runner.run_sync(agent, input=prompt, max_turns=1)
        report = str(getattr(result, "final_output", "") or "").strip()
    if not report:
        raise RuntimeError("storyline LLM 返回空报告")
    return report


# --------------------------------------------------------------------------- #
# 模板路径（LLM 失败兜底，永远有产出；明确标注模板生成）
# --------------------------------------------------------------------------- #
def _render_template(facts: dict) -> str:
    counts = facts.get("counts") or {}
    m = facts.get("metrics_summary") or {}
    attacks = facts.get("attacks") or []
    alerts = facts.get("alerts") or []
    responses = facts.get("responses") or []
    verified = [a for a in attacks if a.get("success")]

    lines: list[str] = []
    sid = facts.get("session_id") or "unknown"
    lines.append(f"# 故事线复盘 | {sid}")
    lines.append(f"\n> 本报告为**{_TEMPLATE_MARKER}**（LLM 不可用时的结构化数据"
                 "自动复盘），内容完全来自遥测记录，未做文学加工。\n")

    # ---- 战役故事线 ----
    lines.append("## 战役故事线\n")
    if not attacks and not alerts:
        lines.append("本场会话没有记录到任何攻击或告警事件。\n")
    else:
        # 按时间合并红蓝动作，叙述交锋过程。
        merged: list[tuple[float, str]] = []
        for a in attacks:
            mark = "✅ 成功" if a["success"] else "❌ 未成功"
            merged.append((a["ts"],
                           f"- {a['time']} **红方** `{a['action']}` → "
                           f"`{a['target']}`（{a['technique'] or '-'}，{mark}）"
                           + (f"：{a['evidence']}" if a["evidence"] else "")))
        for al in alerts:
            merged.append((al["ts"],
                           f"- {al['time']} **蓝方** 告警 `{al['host']}` "
                           f"判定 **{al['verdict'] or '?'}**"
                           f"（{al['technique'] or '-'}，"
                           f"置信度 {al['confidence']:.2f}）"))
        for r in responses:
            merged.append((r["ts"], f"- {r['time']} **蓝方** 处置：{r['summary']}"))
        lines += [text for _, text in sorted(merged, key=lambda x: x[0])]
        lines.append("")

    # ---- 关键转折 ----
    lines.append("## 关键转折\n")
    turning: list[str] = []
    if verified:
        first = verified[0]
        turning.append(f"- {first['time']} 红方首次验证成功："
                       f"`{first['target']}` {first['technique'] or '-'}"
                       "，防线被突破。")
    malicious = [a for a in alerts if a.get("verdict") == "malicious"]
    if malicious:
        first = malicious[0]
        turning.append(f"- {first['time']} 蓝方首次恶意定性："
                       f"`{first['host']}` {first['technique'] or '-'}，"
                       "由被动转为主动处置。")
    if responses:
        turning.append(f"- {responses[0]['time']} 蓝方首次处置动作："
                       f"{responses[0]['summary']}。")
    lines += turning or ["- 本场会话无明显转折点（无验证成功的攻击且无响应）。", ""]
    if turning:
        lines.append("")

    # ---- 蓝队表现评判 ----
    lines.append("## 蓝队表现评判\n")
    n_alerts = counts.get("alerts", len(alerts))
    n_verified = counts.get("verified", len(verified))
    det = m.get("detection_rate")
    lines.append(f"- 检测：共产生 {n_alerts} 条告警，其中恶意定性 "
                 f"{len(malicious)} 条；已验证攻击 {n_verified} 次，"
                 + (f"检测率 {det:.1%}。" if isinstance(det, (int, float))
                    else "无对齐指标。"))
    lines.append(f"- 处置：共 {len(responses)} 次响应动作"
                 + ("；检测到处置的链路完整。" if responses
                    else "；未记录到处置动作（只报不动或无需处置）。"))
    fp = m.get("fp")
    lines.append(f"- 误报：{fp} 条。" if isinstance(fp, int)
                 else "- 误报：无指标数据。")
    # 客观指出不足：未被恶意定性覆盖的已验证攻击。
    alerted_hosts = {(a["host"], a["technique"]) for a in malicious}
    missed = [a for a in verified
              if (a["target"], a["technique"]) not in alerted_hosts
              and not any(a["target"] in h for h, _ in alerted_hosts)]
    if missed:
        lines.append("- 不足：以下已验证攻击未见恶意定性告警——"
                     + "、".join(f"`{a['target']}`({a['technique'] or '-'})"
                                 for a in missed[:8]) + "。")
    if not responses and verified:
        lines.append("- 不足：攻击已被验证成功，但蓝方未执行任何处置动作。")
    lines.append("")

    # ---- 红队战术分析 ----
    lines.append("## 红队战术分析\n")
    if attacks:
        techs: dict[str, int] = {}
        for a in attacks:
            if a.get("technique"):
                techs[a["technique"]] = techs.get(a["technique"], 0) + 1
        tech_str = "、".join(f"{t}×{c}" for t, c in
                             sorted(techs.items(), key=lambda x: -x[1]))
        targets = sorted({a["target"] for a in attacks if a.get("target")})
        lines.append(f"- 攻击尝试 {counts.get('attacks', len(attacks))} 次，"
                     f"验证成功 {n_verified} 次。")
        lines.append(f"- 使用技术：{tech_str or '无技术标注'}。")
        lines.append(f"- 打击目标：{'、'.join(f'`{t}`' for t in targets)}。")
    else:
        lines.append("- 红方未发起任何攻击尝试。")
    lines.append("")

    # ---- 改进建议 ----
    lines.append("## 改进建议\n")
    if missed:
        techs = sorted({a["technique"] for a in missed if a["technique"]})
        lines.append(f"- 蓝方：补齐 {'、'.join(techs) or '相关技术'} 的"
                     "遥测覆盖与检测规则。")
    if not responses and verified:
        lines.append("- 蓝方：告警确认后应立即执行 block_ip / harden_service "
                     "/ remediate 处置，闭环检测-响应链路。")
    if verified and len(verified) < len(attacks):
        lines.append("- 红方：部分攻击未成功，建议加强侦察后再选择攻击面，"
                     "提高一次成功率。")
    if not attacks:
        lines.append("- 红方：本场无攻击记录，建议检查攻击代理执行链路。")
    if len(lines) > 0 and lines[-1] != "":
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 生成入口
# --------------------------------------------------------------------------- #
def generate_storyline(session_dir: "str | Path",
                       llm_fn: Callable | None = None) -> tuple[str, bool]:
    """生成故事线复盘并落盘；返回 (markdown, llm_used)。

    LLM 路径因任何原因失败时自动回退模板渲染（产物标注「模板生成」），
    保证永远有产出。``llm_fn`` 为测试注入点（sync callable(prompt)->str）。
    """
    session_dir = Path(session_dir)
    detail = build_session_detail(session_dir)
    facts = build_facts(detail)
    try:
        md = _render_with_llm(facts, llm_fn)
        llm_used = True
    except Exception:
        md = _render_template(facts)
        llm_used = False
    try:
        (session_dir / STORYLINE_FILE).write_text(md, encoding="utf-8")
        (session_dir / META_FILE).write_text(json.dumps({
            "llm": llm_used, "generated_at": time.time(),
        }, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return md, llm_used
