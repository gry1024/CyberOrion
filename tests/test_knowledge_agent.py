from __future__ import annotations

from cyberorion.agents.knowledge import knowledge_context


class FakeKnowledgeBase:
    def __init__(self, results: list[dict]) -> None:
        self.results = results
        self.last_query = ""

    def search(self, query: str, k: int = 5) -> list[dict]:
        self.last_query = query
        return self.results[:k]


def test_knowledge_context_returns_structured_security_guidance() -> None:
    kb = FakeKnowledgeBase([
        {
            "id": "T1110",
            "type": "technique",
            "name": "Brute Force",
            "score": 12.5,
            "description": "Adversaries may use brute force to gain access.",
            "_source": "MITRE ATT&CK",
        },
    ])

    result = knowledge_context(
        background="SSH 登录失败次数突然升高，疑似口令爆破。",
        evidence="来自 10.0.0.8 的连续失败登录，随后出现一次成功登录。",
        expected_output="给出研判和处置建议",
        kb=kb,
    )

    assert kb.last_query
    assert result["matches"][0]["id"] == "T1110"
    assert result["attack_mapping"] == [{"id": "T1110", "reason": "Brute Force"}]
    assert result["sources"] == ["MITRE ATT&CK"]
    assert result["recommendations"]
    assert 0.0 < result["confidence"] <= 1.0


def test_knowledge_context_is_honest_when_the_kb_has_no_match() -> None:
    result = knowledge_context(
        background="一个没有对应条目的未知安全现象。",
        evidence="没有可验证的外部证据。",
        expected_output="说明是否能确认根因",
        kb=FakeKnowledgeBase([]),
    )

    assert result["matches"] == []
    assert result["attack_mapping"] == []
    assert result["sources"] == []
    assert result["confidence"] == 0.0
    assert any("未检索到" in note for note in result["risk_notes"])
