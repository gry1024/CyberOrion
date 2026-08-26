"""ATT&CK 知识库测试（A4）— 全部离线，用合成 STIX / 合成 KB fixture。

  - build_kb：微型合成 STIX bundle -> 文档解析正确；
  - build_kb v2：合成 Malpedia dump -> malware 文档解析与短描述过滤；
    沙箱解读知识加载与字段校验；
  - rag：合成 KB 上的检索相关性（T1110/T1059.001/T1505.003）与 lookup；
  - tools.blue.kb：工具输出格式（走 FunctionTool.on_invoke_tool）。
"""

from __future__ import annotations

import asyncio
import json

import pytest

from cyberorion.kb import build_kb
from cyberorion.kb.rag import AttackKB, get_kb, reset_kb
from cyberorion.tools.blue.kb import search_attack_kb, lookup_technique


def call(tool, **kwargs) -> str:
    return asyncio.run(tool.on_invoke_tool(None, json.dumps(kwargs)))


# ----------------------------------------------------------------------- #
# 合成 STIX fixture（attack-spec 3.x 结构：检测在 analytic 对象上）
# ----------------------------------------------------------------------- #
@pytest.fixture()
def stix_path(tmp_path):
    tech = {
        "type": "attack-pattern", "id": "attack-pattern--t1110",
        "name": "Brute Force", "revoked": False, "x_mitre_deprecated": False,
        "description": "Adversaries may guess passwords.",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                               "phase_name": "credential-access"}],
        "external_references": [{"source_name": "mitre-attack",
                                 "external_id": "T1110"}],
        "x_mitre_platforms": ["Linux", "Windows"],
        "x_mitre_is_subtechnique": False,
    }
    coa = {
        "type": "course-of-action", "id": "course-of-action--m1036",
        "name": "Account Use Policies",
        "description": "Configure lockout policies.",
        "external_references": [{"source_name": "mitre-attack",
                                 "external_id": "M1036"}],
    }
    analytic = {
        "type": "x-mitre-analytic", "id": "x-mitre-analytic--an1",
        "name": "Analytic 0001",
        "description": "High volume of failed logon attempts.",
        "x_mitre_log_source_references": [
            {"x_mitre_data_component_ref": "x-mitre-data-component--dc1",
             "name": "authlog"}],
    }
    component = {
        "type": "x-mitre-data-component", "id": "x-mitre-data-component--dc1",
        "name": "User Account Authentication",
    }
    strategy = {
        "type": "x-mitre-detection-strategy",
        "id": "x-mitre-detection-strategy--det1",
        "name": "Detection Strategy for Brute Force",
        "x_mitre_analytic_refs": ["x-mitre-analytic--an1"],
    }
    group = {
        "type": "intrusion-set", "id": "intrusion-set--g1",
        "name": "APT-Example", "aliases": ["APT-Example", "ExampleBear"],
        "description": "An example group.",
        "external_references": [{"source_name": "mitre-attack",
                                 "external_id": "G9999"}],
    }
    dead = {
        "type": "attack-pattern", "id": "attack-pattern--dead",
        "name": "Revoked Tech", "revoked": True,
        "description": "should be skipped",
        "external_references": [{"source_name": "mitre-attack",
                                 "external_id": "T9999"}],
    }
    rels = [
        {"type": "relationship", "id": "relationship--r1",
         "relationship_type": "mitigates",
         "source_ref": "course-of-action--m1036",
         "target_ref": "attack-pattern--t1110"},
        {"type": "relationship", "id": "relationship--r2",
         "relationship_type": "detects",
         "source_ref": "x-mitre-detection-strategy--det1",
         "target_ref": "attack-pattern--t1110"},
    ]
    bundle = {"type": "bundle",
              "objects": [tech, coa, analytic, component, strategy, group,
                          dead] + rels}
    p = tmp_path / "stix.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    return p


class TestBuildKB:
    def test_parse_technique(self, stix_path):
        docs = build_kb.build_docs(stix_path)
        tech = next(d for d in docs if d["id"] == "T1110")
        assert tech["type"] == "technique"
        assert tech["tactics"] == ["credential-access"]
        assert tech["platforms"] == ["Linux", "Windows"]
        assert "failed logon" in tech["detection"]
        assert tech["data_sources"] == ["User Account Authentication"]
        assert tech["mitigations"] == ["Account Use Policies"]
        assert "T1110 Brute Force" in tech["text"]

    def test_mitigation_group_and_revoked(self, stix_path):
        docs = build_kb.build_docs(stix_path)
        by_id = {d["id"]: d for d in docs}
        assert by_id["M1036"]["type"] == "mitigation"
        assert by_id["M1036"]["mitigates"] == ["T1110"]
        assert by_id["G9999"]["type"] == "group"
        assert by_id["G9999"]["aliases"] == ["ExampleBear"]
        assert "T9999" not in by_id  # revoked 被过滤

    def test_write_jsonl_roundtrip(self, stix_path, tmp_path):
        docs = build_kb.build_docs(stix_path)
        out = tmp_path / "kb.jsonl"
        n = build_kb.write_jsonl(docs, out)
        loaded = [json.loads(l) for l in
                  out.read_text(encoding="utf-8").splitlines()]
        assert n == len(docs) == len(loaded)


# ----------------------------------------------------------------------- #
# v2：Malpedia 家族库 + 沙箱解读知识（合成 fixture）
# ----------------------------------------------------------------------- #
@pytest.fixture()
def malpedia_path(tmp_path):
    dump = {
        "win.remcos": {
            "common_name": "Remcos",
            "alt_names": ["RemcosRAT", "Socmer"],
            "attribution": [],
            "description": "Remcos is a commercial Remote Access Tool "
                           "used to remotely control computers. It supports "
                           "keylogging, screen capture and file transfer "
                           "over a C2 channel. " * 2,
            "urls": ["https://example.invalid/remcos"],
        },
        "win.tinyd": {
            "common_name": "TinyD",
            "alt_names": [],
            "attribution": ["ExampleBear"],
            "description": "too short",   # 低于 min_desc，应被过滤
        },
        "win.badpayload": "not-a-dict",    # 畸形条目应被跳过
    }
    p = tmp_path / "malpedia.json"
    p.write_text(json.dumps(dump), encoding="utf-8")
    return p


class TestMalpediaDocs:
    def test_parse_and_filter(self, malpedia_path):
        docs = build_kb.build_malpedia_docs(malpedia_path, min_desc=100)
        assert [d["id"] for d in docs] == ["MALPEDIA:win.remcos"]
        doc = docs[0]
        assert doc["type"] == "malware"
        assert doc["name"] == "Remcos"
        assert doc["family"] == "win.remcos"
        assert doc["aliases"] == ["RemcosRAT", "Socmer"]
        assert "keylogging" in doc["text"]
        assert "aka RemcosRAT" in doc["text"]

    def test_min_desc_threshold(self, malpedia_path):
        # 阈值放低后短描述家族也入库
        docs = build_kb.build_malpedia_docs(malpedia_path, min_desc=5)
        ids = {d["id"] for d in docs}
        assert ids == {"MALPEDIA:win.remcos", "MALPEDIA:win.tinyd"}

    def test_bad_top_level(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(ValueError):
            build_kb.build_malpedia_docs(p)


class TestSandboxDocs:
    def test_load(self, tmp_path):
        p = tmp_path / "sbx.json"
        p.write_text(json.dumps([
            {"id": "SBX001", "name": "doc", "description": "d",
             "text": "t"},
        ]), encoding="utf-8")
        docs = build_kb.load_sandbox_docs(p)
        assert docs[0]["type"] == "sandbox_report"
        assert docs[0]["id"] == "SBX001"

    def test_missing_field_rejected(self, tmp_path):
        p = tmp_path / "sbx.json"
        p.write_text(json.dumps([{"id": "SBX001", "name": "doc"}]),
                     encoding="utf-8")
        with pytest.raises(ValueError):
            build_kb.load_sandbox_docs(p)

    def test_real_data_file_loads(self):
        # 仓库内置的沙箱知识库必须通过自身校验
        docs = build_kb.load_sandbox_docs(build_kb.DEFAULT_SANDBOX)
        assert len(docs) >= 15
        assert all(d["type"] == "sandbox_report" for d in docs)


# ----------------------------------------------------------------------- #
# 检索（BM25 强制，离线）
# ----------------------------------------------------------------------- #
_KB_DOCS = [
    {"id": "T1110", "name": "Brute Force", "type": "technique",
     "tactics": ["credential-access"],
     "description": "Adversaries may use brute force to gain access via "
                    "password guessing against services such as ssh.",
     "detection": "High volume of failed logon attempts.",
     "mitigations": ["Account Use Policies"], "platforms": ["Linux"],
     "data_sources": ["Auth Logs"],
     "text": "T1110 Brute Force tactics: credential-access. Adversaries "
             "may use brute force password guessing against ssh login "
             "services. Detection: failed logon volume."},
    {"id": "T1059.001", "name": "PowerShell", "type": "technique",
     "tactics": ["execution"],
     "description": "Adversaries may abuse PowerShell commands and scripts "
                    "for execution, often with encoded command payloads.",
     "detection": "PowerShell launched with encoded commands.",
     "mitigations": [], "platforms": ["Windows"], "data_sources": [],
     "text": "T1059.001 PowerShell tactics: execution. Abuse powershell "
             "commands scripts encoded command payload execution."},
    {"id": "T1027", "name": "Obfuscated Files or Information",
     "type": "technique", "tactics": ["defense-evasion"],
     "description": "Adversaries may obfuscate or encode payloads and "
                    "commands to evade detection.",
     "detection": "", "mitigations": [], "platforms": [], "data_sources": [],
     "text": "T1027 Obfuscated Files or Information tactics: "
             "defense-evasion. obfuscate encode payload command evasion."},
    {"id": "T1505.003", "name": "Web Shell", "type": "technique",
     "tactics": ["persistence"],
     "description": "Adversaries may install a web shell on a web server "
                    "for persistent remote access.",
     "detection": "Unexpected files in web root.", "mitigations": [],
     "platforms": ["Linux"], "data_sources": [],
     "text": "T1505.003 Web Shell tactics: persistence. web shell backdoor "
             "installed on web server remote access."},
    {"id": "T1190", "name": "Exploit Public-Facing Application",
     "type": "technique", "tactics": ["initial-access"],
     "description": "Adversaries may exploit vulnerabilities in "
                    "internet-facing applications.",
     "detection": "", "mitigations": [], "platforms": [], "data_sources": [],
     "text": "T1190 Exploit Public-Facing Application tactics: "
             "initial-access. exploit vulnerability public application."},
    {"id": "MALPEDIA:win.remcos", "name": "Remcos", "type": "malware",
     "family": "win.remcos", "aliases": ["RemcosRAT"],
     "description": "Remcos is a commercial Remote Access Tool with "
                    "keylogging, screen capture and file transfer.",
     "text": "Remcos (win.remcos) malware family aka RemcosRAT. Remcos is "
             "a commercial Remote Access Tool RAT with keylogging screen "
             "capture file transfer C2."},
]


@pytest.fixture()
def kb(tmp_path):
    p = tmp_path / "kb.jsonl"
    p.write_text("\n".join(json.dumps(d) for d in _KB_DOCS),
                 encoding="utf-8")
    return AttackKB(p, use_embeddings=False)


class TestRetrieval:
    def test_ssh_brute_force(self, kb):
        top = [d["id"] for d in kb.search("ssh brute force", k=3)]
        assert "T1110" in top

    def test_powershell_encoded(self, kb):
        top = [d["id"] for d in kb.search("powershell encoded command", k=3)]
        assert "T1059.001" in top

    def test_webshell_compound(self, kb):
        # webshell 作为复合词应能命中 Web Shell
        top = [d["id"] for d in kb.search("webshell", k=3)]
        assert "T1505.003" in top

    def test_technique_id_boost(self, kb):
        top = kb.search("T1027 detection guidance", k=1)
        assert top[0]["id"] == "T1027"

    def test_score_sorted_and_positive(self, kb):
        results = kb.search("brute force", k=5)
        scores = [d["score"] for d in results]
        assert scores == sorted(scores, reverse=True)
        assert all(s > 0 for s in scores)

    def test_empty_query(self, kb):
        assert kb.search("", k=3) == []

    def test_lookup(self, kb):
        doc = kb.lookup("t1059.001")
        assert doc is not None and doc["name"] == "PowerShell"
        assert kb.lookup("T0000") is None

    def test_malware_family_doc_retrieved(self, kb):
        # KB v2 的 malware 文档：家族行为查询应命中家族条目
        top = [d["id"] for d in kb.search("remcos keylogging rat", k=3)]
        assert "MALPEDIA:win.remcos" in top

    def test_lookup_malware_id(self, kb):
        doc = kb.lookup("malpedia:win.remcos")
        assert doc is not None and doc["type"] == "malware"


class TestSingleton:
    def test_get_kb_and_reset(self, tmp_path):
        p = tmp_path / "kb.jsonl"
        p.write_text("\n".join(json.dumps(d) for d in _KB_DOCS),
                     encoding="utf-8")
        reset_kb()
        kb1 = get_kb(p, use_embeddings=False)
        assert get_kb(p, use_embeddings=False) is kb1
        reset_kb()


# ----------------------------------------------------------------------- #
# 工具输出格式
# ----------------------------------------------------------------------- #
@pytest.fixture()
def kb_tools(tmp_path, monkeypatch):
    """把工具背后的 get_kb 指到合成 KB（BM25 离线）。"""
    p = tmp_path / "kb.jsonl"
    p.write_text("\n".join(json.dumps(d) for d in _KB_DOCS),
                 encoding="utf-8")
    instance = AttackKB(p, use_embeddings=False)
    monkeypatch.setattr("cyberorion.kb.rag._KB", None)
    monkeypatch.setattr("cyberorion.tools.blue.kb._kb", lambda: instance)
    return instance


class TestKBTools:
    def test_search_output_format(self, kb_tools):
        out = call(search_attack_kb, query="ssh brute force", k=2)
        assert "ATT&CK 知识库命中" in out
        assert "T1110 Brute Force" in out
        assert "credential-access" in out
        assert "检测要点" in out

    def test_search_no_hit(self, kb_tools):
        out = call(search_attack_kb, query="zzzqqq 完全无关词", k=3)
        assert "未命中" in out

    def test_lookup_output(self, kb_tools):
        out = call(lookup_technique, technique_id="T1505.003")
        assert "T1505.003 Web Shell" in out
        assert "检测要点" in out
        assert "persistence" in out

    def test_lookup_unknown(self, kb_tools):
        out = call(lookup_technique, technique_id="T0000")
        assert "未找到" in out
