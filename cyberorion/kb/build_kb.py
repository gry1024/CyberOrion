"""build_kb：把 MITRE ATT&CK Enterprise STIX 2.1 bundle 解析为紧凑知识库 JSONL。

输入：``data/enterprise-attack.json``（来自 mitre/cti，attack-spec 3.x：
检测信息在 x-mitre-detection-strategy / x-mitre-analytic 对象中，通过
``detects`` 关系挂到 attack-pattern 上）。

输出：``data/attack_kb.jsonl``，每行一个文档：
  - technique   : 每个 attack-pattern 一条（含子技术），字段
                  id/name/tactics/description/detection/mitigations/
                  platforms/data_sources/text；
  - mitigation  : 每个 course-of-action 一条（id/name/description/
                  mitigates/text）；
  - group       : 每个 intrusion-set 一条（id/name/aliases/description/text）；
  - software    : 每个 malware/tool 一条（id/name/description/text）。

``text`` 字段是供检索（BM25 / embedding）用的拼接文本，裁剪到 ~1200 字符。

v2 新增两类文档：
  - malware       : Malpedia（CC0，https://malpedia.caad.fkie.fraunhofer.de/）
                    家族库，``--with-malpedia`` 开启；只收录 description 达到
                    ``MALPEDIA_MIN_DESC`` 字符的家族，字段 id(MALPEDIA:<fam>)/
                    name(common_name)/aliases/attribution/description/text；
  - sandbox_report: 手工编写的沙箱报告解读知识（如何读 process/file/
                    registry/network 段、常见规避/持久化/注入行为到可观测
                    痕迹的映射），默认从 ``data/sandbox_knowledge.json``
                    加载，``--no-sandbox-docs`` 关闭。

用法：
    python -m cyberorion.kb.build_kb                 # 用默认路径
    python -m cyberorion.kb.build_kb --stix X.json --out Y.jsonl
    python -m cyberorion.kb.build_kb --with-malpedia  # 附加 Malpedia 家族库
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent
DEFAULT_STIX = _HERE / "data" / "enterprise-attack.json"
DEFAULT_OUT = _HERE / "data" / "attack_kb.jsonl"
DEFAULT_MALPEDIA = _HERE / "data" / "malpedia_families.json"
DEFAULT_SANDBOX = _HERE / "data" / "sandbox_knowledge.json"
DEFAULT_REGULATIONS = _HERE / "data" / "regulations.json"
DEFAULT_CVE = _HERE / "data" / "cve_critical.json"

# 构建器版本：v1 = 仅 ATT&CK STIX；v2 = + Malpedia 家族库 + 沙箱解读知识。
KB_BUILDER_VERSION = 3

# Malpedia 家族入库的 description 最小长度（过滤掉只有一行占位描述的家族）。
MALPEDIA_MIN_DESC = 100

_DESC_CLIP = 700   # 单条 description 最大字符数
_DET_CLIP = 500    # 单条 detection 合并文本最大字符数
_TEXT_CLIP = 1200  # 检索用 text 字段最大字符数

_WS_RE = re.compile(r"\s+")


def _clean(text: str) -> str:
    return _WS_RE.sub(" ", str(text or "")).strip()


def _clip(text: str, limit: int) -> str:
    text = _clean(text)
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


def _active(obj: dict) -> bool:
    """过滤已废弃 / 已撤销的 STIX 对象。"""
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _ext_id(obj: dict) -> str:
    """取 mitre-attack 外部编号（T1110 / M1036 / G0016 / S0366 / DET0001）。"""
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def build_docs(stix_path: "str | Path" = DEFAULT_STIX) -> list[dict]:
    """解析 STIX bundle，返回 KB 文档列表（不落盘，便于测试复用）。"""
    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    objects = bundle.get("objects") or []
    by_id = {o["id"]: o for o in objects if o.get("id")}

    # --- 关系索引 ----------------------------------------------------------
    # mitigates: course-of-action -> attack-pattern
    tech_mitigations: dict[str, list[str]] = {}
    # detects: x-mitre-detection-strategy -> attack-pattern
    tech_strategies: dict[str, list[str]] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or not _active(rel):
            continue
        src, tgt = rel.get("source_ref"), rel.get("target_ref")
        if rel.get("relationship_type") == "mitigates" and tgt in by_id:
            name = _clean(by_id.get(src, {}).get("name", ""))
            if name:
                tech_mitigations.setdefault(tgt, []).append(name)
        elif rel.get("relationship_type") == "detects" and tgt in by_id:
            tech_strategies.setdefault(tgt, []).append(src)

    data_components = {
        oid: o.get("name", "") for oid, o in by_id.items()
        if o.get("type") == "x-mitre-data-component"
    }

    def _strategy_detail(strategy_id: str) -> tuple[str, set[str]]:
        """detection-strategy -> (analytic 描述拼接, data component 名集合)。"""
        strategy = by_id.get(strategy_id) or {}
        texts: list[str] = []
        sources: set[str] = set()
        for an_id in strategy.get("x_mitre_analytic_refs") or []:
            analytic = by_id.get(an_id) or {}
            desc = _clean(analytic.get("description", ""))
            if desc:
                texts.append(desc)
            for ref in analytic.get("x_mitre_log_source_references") or []:
                comp = data_components.get(
                    ref.get("x_mitre_data_component_ref", ""), "")
                if comp:
                    sources.add(comp)
        return "; ".join(texts), sources

    docs: list[dict] = []

    # --- 技术（attack-pattern）--------------------------------------------
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _active(obj):
            continue
        tid = _ext_id(obj)
        if not tid:
            continue
        tactics = [
            ph.get("phase_name", "")
            for ph in obj.get("kill_chain_phases") or []
            if ph.get("kill_chain_name") == "mitre-attack"
        ]
        detection_parts: list[str] = []
        data_sources: set[str] = set()
        for sid in tech_strategies.get(obj["id"], []):
            text, sources = _strategy_detail(sid)
            if text:
                detection_parts.append(text)
            data_sources |= sources
        description = _clip(obj.get("description", ""), _DESC_CLIP)
        detection = _clip(" ".join(detection_parts), _DET_CLIP)
        mitigations = sorted(set(tech_mitigations.get(obj["id"], [])))
        platforms = obj.get("x_mitre_platforms") or []
        text = _clip(
            f"{tid} {obj.get('name', '')} tactics: {', '.join(tactics)}. "
            f"{description} Detection: {detection} "
            f"Mitigations: {', '.join(mitigations)}",
            _TEXT_CLIP,
        )
        docs.append({
            "id": tid,
            "name": _clean(obj.get("name", "")),
            "type": "technique",
            "tactics": tactics,
            "description": description,
            "detection": detection,
            "mitigations": mitigations,
            "platforms": platforms,
            "data_sources": sorted(data_sources),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "text": text,
        })

    # --- 缓解措施（course-of-action）---------------------------------------
    for obj in objects:
        if obj.get("type") != "course-of-action" or not _active(obj):
            continue
        mid = _ext_id(obj)
        if not mid:
            continue
        mitigates = sorted({
            _ext_id(by_id[t]) for t, srcs in tech_mitigations.items()
            if t in by_id and _clean(obj.get("name", "")) in srcs
            and by_id[t].get("type") == "attack-pattern"
        } - {""})
        description = _clip(obj.get("description", ""), _DESC_CLIP)
        docs.append({
            "id": mid,
            "name": _clean(obj.get("name", "")),
            "type": "mitigation",
            "description": description,
            "mitigates": mitigates,
            "text": _clip(f"{mid} {obj.get('name', '')}. {description}",
                          _TEXT_CLIP),
        })

    # --- 组织（intrusion-set）与软件（malware/tool）------------------------
    for obj in objects:
        if obj.get("type") not in ("intrusion-set", "malware", "tool") \
                or not _active(obj):
            continue
        ext = _ext_id(obj)
        if not ext:
            continue
        kind = "group" if obj["type"] == "intrusion-set" else "software"
        aliases = [a for a in (obj.get("aliases") or [])
                   if a != obj.get("name")]
        description = _clip(obj.get("description", ""), _DESC_CLIP)
        doc = {
            "id": ext,
            "name": _clean(obj.get("name", "")),
            "type": kind,
            "description": description,
            "text": _clip(
                f"{ext} {obj.get('name', '')} "
                f"{'aka ' + ', '.join(aliases) if aliases else ''}. "
                f"{description}",
                _TEXT_CLIP,
            ),
        }
        if aliases:
            doc["aliases"] = aliases
        if kind == "software":
            doc["software_types"] = [obj["type"]]
        docs.append(doc)

    docs.sort(key=lambda d: (d["type"] != "technique", d["id"]))
    return docs


# ----------------------------------------------------------------------- #
# v2：Malpedia 家族库 + 沙箱报告解读知识
# ----------------------------------------------------------------------- #
def build_malpedia_docs(malpedia_path: "str | Path" = DEFAULT_MALPEDIA,
                        min_desc: int = MALPEDIA_MIN_DESC) -> list[dict]:
    """解析 Malpedia /api/get/families 全量 dump，返回 type="malware" 文档。

    只收录 description 达到 min_desc 字符的家族（短描述多为占位文本，
    检索价值低）。text 字段拼接 common_name + alt_names + attribution +
    description，供 BM25 / embedding 检索。
    """
    with open(malpedia_path, "r", encoding="utf-8") as f:
        families = json.load(f)
    if not isinstance(families, dict):
        raise ValueError("Malpedia dump 顶层必须是 {family_id: {...}} 字典")
    docs: list[dict] = []
    for fam_id, entry in sorted(families.items()):
        if not isinstance(entry, dict):
            continue
        description = _clip(entry.get("description", ""), _DESC_CLIP)
        if len(_clean(entry.get("description", ""))) < min_desc:
            continue
        name = _clean(entry.get("common_name", "")) or fam_id
        aliases = [_clean(a) for a in entry.get("alt_names") or []]
        aliases = [a for a in aliases if a and a.lower() != name.lower()]
        attribution = [_clean(a) for a in entry.get("attribution") or []]
        attribution = [a for a in attribution if a]
        doc = {
            "id": f"MALPEDIA:{fam_id}",
            "name": name,
            "type": "malware",
            "family": fam_id,
            "description": description,
            "text": _clip(
                f"{name} ({fam_id}) malware family"
                f"{' aka ' + ', '.join(aliases) if aliases else ''}"
                f"{'. Attributed to: ' + ', '.join(attribution) if attribution else ''}"
                f". {description}",
                _TEXT_CLIP,
            ),
        }
        if aliases:
            doc["aliases"] = aliases
        if attribution:
            doc["attribution"] = attribution
        docs.append(doc)
    return docs


def load_sandbox_docs(
        sandbox_path: "str | Path" = DEFAULT_SANDBOX) -> list[dict]:
    """加载手工编写的沙箱报告解读知识（type="sandbox_report"）。"""
    with open(sandbox_path, "r", encoding="utf-8") as f:
        docs = json.load(f)
    if not isinstance(docs, list):
        raise ValueError("sandbox_knowledge.json 顶层必须是数组")
    out = []
    for d in docs:
        doc = dict(d)
        doc.setdefault("type", "sandbox_report")
        for key in ("id", "name", "description", "text"):
            if not doc.get(key):
                raise ValueError(f"沙箱知识文档缺少字段 {key}: {doc.get('id')}")
        out.append(doc)
    return out


def load_regulations_docs(reg_path: "str | Path" = DEFAULT_REGULATIONS) -> list[dict]:
    """加载行业监管政策知识（type="regulation"）。"""
    with open(reg_path, "r", encoding="utf-8") as f:
        docs = json.load(f)
    if not isinstance(docs, list):
        raise ValueError("regulations.json 顶层必须是数组")
    out = []
    for d in docs:
        doc = dict(d)
        doc.setdefault("type", "regulation")
        for key in ("id", "name", "description", "text"):
            if not doc.get(key):
                raise ValueError(f"监管政策文档缺少字段 {key}: {doc.get('id')}")
        out.append(doc)
    return out


def load_cve_docs(cve_path: "str | Path" = DEFAULT_CVE) -> list[dict]:
    """加载高危CVE漏洞知识（type="cve"）。"""
    with open(cve_path, "r", encoding="utf-8") as f:
        docs = json.load(f)
    if not isinstance(docs, list):
        raise ValueError("cve_critical.json 顶层必须是数组")
    out = []
    for d in docs:
        doc = dict(d)
        doc.setdefault("type", "cve")
        for key in ("id", "name", "text"):
            if not doc.get(key):
                continue  # 跳过不完整记录
        if not doc.get("text"):
            continue
        if not doc.get("description"):
            doc["description"] = doc["text"][:300]
        out.append(doc)
    return out


def write_jsonl(docs: list[dict], out_path: "str | Path" = DEFAULT_OUT) -> int:
    """把文档列表写入 JSONL，返回条数。"""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for doc in docs:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
    return len(docs)


def main(argv: "list[str] | None" = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix", default=str(DEFAULT_STIX),
                        help="enterprise-attack.json 路径")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="输出 attack_kb.jsonl 路径")
    parser.add_argument("--with-malpedia", nargs="?", const=str(DEFAULT_MALPEDIA),
                        default=None, metavar="PATH",
                        help="附加 Malpedia 家族库（默认 data/malpedia_families.json，"
                             "来自 /api/get/families 全量 dump）")
    parser.add_argument("--sandbox-docs", default=str(DEFAULT_SANDBOX),
                        help="沙箱报告解读知识 JSON 路径")
    parser.add_argument("--no-sandbox-docs", action="store_true",
                        help="不附加沙箱报告解读知识")
    parser.add_argument("--regulations", default=str(DEFAULT_REGULATIONS),
                        help="行业监管政策知识 JSON 路径")
    parser.add_argument("--no-regulations", action="store_true",
                        help="不附加监管政策知识")
    parser.add_argument("--cve", default=str(DEFAULT_CVE),
                        help="高危CVE漏洞知识 JSON 路径")
    parser.add_argument("--no-cve", action="store_true",
                        help="不附加CVE漏洞知识")
    args = parser.parse_args(argv)
    docs = build_docs(args.stix)
    if args.with_malpedia:
        docs += build_malpedia_docs(args.with_malpedia)
    if not args.no_sandbox_docs:
        docs += load_sandbox_docs(args.sandbox_docs)
    if not args.no_regulations:
        docs += load_regulations_docs(args.regulations)
    if not args.no_cve:
        docs += load_cve_docs(args.cve)
    n = write_jsonl(docs, args.out)
    by_type: dict[str, int] = {}
    for d in docs:
        by_type[d["type"]] = by_type.get(d["type"], 0) + 1
    print(f"builder v{KB_BUILDER_VERSION}：已写入 {n} 条文档 -> {args.out}")
    for t, c in sorted(by_type.items()):
        print(f"  {t}: {c}")


if __name__ == "__main__":
    main()
