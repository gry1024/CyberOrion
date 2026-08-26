"""kb：蓝队的 MITRE ATT&CK 知识库工具。

不依赖遥测 store —— 知识库是静态资源（cyberorion/kb），任何会话
状态下都可用。检索失败 / 知识库缺失时返回解释性字符串，绝不抛进
agent loop。
"""

from __future__ import annotations

from cai.sdk.agents import function_tool

_DET_CLIP = 220   # search 结果里检测要点摘录长度


def _kb():
    from ...kb.rag import get_kb
    return get_kb()


@function_tool
def search_attack_kb(query: str, k: int = 5) -> str:
    """检索 MITRE ATT&CK 知识库（巡逻/研判时查不熟悉的攻击模式）。

    Args:
        query: 攻击模式描述或关键词（中英文均可），如
            "ssh brute force"、"webshell 上传"、"powershell encoded command"。
        k: 返回条数，默认 5。

    Returns:
        每条一行：技术编号 + 名称 + 战术 + 检测要点摘录；未命中时返回提示。
    """
    try:
        results = _kb().search(query, k=k)
    except FileNotFoundError:
        return "知识库未构建：请先运行 python -m cyberorion.kb.build_kb"
    except Exception as exc:  # noqa: BLE001 - 工具不得抛进 agent loop
        return f"知识库检索失败：{exc}"
    if not results:
        return f"知识库未命中：{query!r}（可换关键词或用 lookup_technique 按编号查询）"
    lines = [f"ATT&CK 知识库命中 {len(results)} 条（query={query!r}）："]
    for d in results:
        det = (d.get("detection") or d.get("description") or "")[:_DET_CLIP]
        tactics = ",".join(d.get("tactics") or []) or d.get("type", "")
        lines.append(
            f"- {d['id']} {d['name']} [{tactics}] score={d['score']}\n"
            f"  检测要点: {det}"
        )
    return "\n".join(lines)


@function_tool
def lookup_technique(technique_id: str) -> str:
    """按 ATT&CK 编号查询完整检测与缓解详情（如 T1110、T1505.003）。

    Args:
        technique_id: ATT&CK 技术/子技术编号（也支持缓解 Mxxxx /
            组织 Gxxxx / 软件 Sxxxx），大小写不敏感。

    Returns:
        该条目的描述、检测要点、缓解措施、平台与数据源；未命中返回提示。
    """
    try:
        doc = _kb().lookup(technique_id)
    except FileNotFoundError:
        return "知识库未构建：请先运行 python -m cyberorion.kb.build_kb"
    except Exception as exc:  # noqa: BLE001
        return f"知识库查询失败：{exc}"
    if doc is None:
        return f"未找到条目 {technique_id!r}（编号形如 T1110 / T1505.003 / M1036）"
    lines = [f"{doc['id']} {doc['name']}（{doc.get('type', 'technique')}）"]
    if doc.get("tactics"):
        lines.append(f"战术: {', '.join(doc['tactics'])}")
    if doc.get("platforms"):
        lines.append(f"平台: {', '.join(doc['platforms'])}")
    if doc.get("data_sources"):
        lines.append(f"数据源: {', '.join(doc['data_sources'])}")
    if doc.get("description"):
        lines.append(f"描述: {doc['description']}")
    if doc.get("detection"):
        lines.append(f"检测要点: {doc['detection']}")
    if doc.get("mitigations"):
        lines.append(f"缓解措施: {', '.join(doc['mitigations'])}")
    if doc.get("mitigates"):
        lines.append(f"可缓解技术: {', '.join(doc['mitigates'])}")
    return "\n".join(lines)
