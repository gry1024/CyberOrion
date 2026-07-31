"""CyberSOCEval malware_analysis 基准：对【我们自己的 pipeline】打分。

与官方 runner 的区别（也是之前 23/100 INVALID 的教训）：
  - 【不】使用 response_format=json_object —— 该 endpoint 的模型会把
    json schema 提示原样复读而不是作答；
  - 纯文本提示，要求最后一行输出 ``ANSWER: ["A","C"]``；
  - 容错解析器从自然语言回答中提取选项字母；解析失败记 wrong 并单独
    统计 parse_fail。

五种模式（rag_fs / sc / sc_base / rag_g 为 legacy，保留用于对比实验）：
  - base  ：单次 LLM 调用，裸提示；
  - rag   ：【默认】先用知识库（cyberorion.kb：ATT&CK + Malpedia 家族库 +
            沙箱报告解读知识）检索 top-k 相关文档注入提示；检索为两段式：
            先以「家族类别(attack 字段) + 题干」检索，若 top-1 相似度低于
            RETRIEVAL_MIN_SCORE 则以「题干 + 全部选项文本」重检并取更优；
            并将该家族类别的行为 playbook（SBX008-011）确定性置顶注入；
            作答规则含逐项裁决与“禁止弃答、最佳猜测”（原 rag_g v4 规则）；
  - rag_fs：【legacy】旧 v2 rag 提示前再加 2 条 few-shot 示例；
  - sc    ：【legacy】self-consistency —— rag 提示采样 k 次（温度>0）后
            逐选项多数投票（得票 >= k//2+1 才入选）；
  - sc_base：【legacy】同 sc，但用裸提示（分离投票与知识库的贡献）；
  - rag_g ：【legacy】旧 v4 提示 = v2 规则 + 禁止弃答（不含新的知识使用
            指引与两段式检索，用于新旧对比）。

采样用固定 seed（base 与 rag 回答【同一批】题目，保证可比）。
评分：exact-match（correct_mc_pct）+ Jaccard 部分分（avg_score），
并按 difficulty / topic 分组统计。每次运行持久化到 logs/bench/。
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent          # cyberorion/ 仓库根
DEFAULT_QUESTIONS = Path(
    "/home/groy/cai/benchmarks/cybersoceval/PurpleLlama/"
    "CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/"
    "questions.json")
DEFAULT_LOG_DIR = _REPO / "logs" / "bench"

RAG_TOP_K = 3
CONCURRENCY = 10
LLM_TIMEOUT = 120.0
_MAX_TOKENS = 1024

_SYSTEM_BASE = (
    "你是一名资深恶意软件分析专家，熟悉 MITRE ATT&CK 框架与沙箱"
    "（Hybrid Analysis）行为报告。请根据题目所描述的报告内容作答。"
)
_SYSTEM_RAG = _SYSTEM_BASE + (
    "题目下方附【检索到的恶意软件知识】（MITRE ATT&CK 技术、恶意软件家族"
    "资料、沙箱报告解读知识）仅供参考：仅当条目与题目明确相关时才可采信；"
    "与题目无关的条目必须完全忽略。"
)

# 两段式检索：stage-1 用「家族类别 + 题干」检索，top-1 得分低于该阈值时
# 用「题干 + 全部选项文本」重检（stage-2），取 top-1 得分更高的一组。
# 阈值按 embedding 余弦相似度标定；BM25 回退模式得分量级远大于它，
# 因此 BM25 下 stage-2 实际不会触发（保持旧行为）。
RETRIEVAL_MIN_SCORE = 0.45

_ANSWER_INSTRUCTION = (
    "这是多选题（可能有 1 个或多个正确选项）。请先简要推理，然后在"
    "【最后一行】严格输出：ANSWER: [\"A\",\"C\"]（只包含你最终选定的"
    "选项字母，JSON 数组格式）。"
)

# RAG 提示迭代版本号（记录进 run dict，便于对比不同提示的效果）。
# v5 = v2 规则 + 禁止弃答/最佳猜测（原 v4）+ 知识使用指引 + 两段式检索；
#      实测 0.190/0.453（n=100 seed=42），提升 < 3pt。
# v6 = v5 + 家族类别 playbook 确定性注入（attack 元数据 -> SBX008-011，
#      解决相似度检索带不出类别行为知识的问题）+ 逐项裁决规则；
#      在 KB v2（ATT&CK + Malpedia + 沙箱知识）上评测。
PROMPT_VERSION = 6
# v3 = 旧 v2 + 2 条 few-shot 示例（rag_fs 模式，legacy）。
PROMPT_VERSION_FS = 3
# v4 = 旧 v2 + 禁止弃答规则（rag_g 模式，legacy）：题目引用的沙箱报告
# 内容不在提示中，模型容易“理性弃答”输出 ANSWER: []（计 0 分），v4 起
# 强制猜测；v5 已并入默认 rag，rag_g 仅保留用于新旧对比。
PROMPT_VERSION_G = 4

# run_bench 支持的全部 mode（server.py 等调用方以此为准，单一事实源）。
MODES = ("base", "rag", "rag_fs", "sc", "sc_base", "rag_g")
# run_bench 支持的全部 suite（单一事实源）；attack_kb 套件的 mode 白名单
# 见 bench/attack_kb.py 的 MODES。
SUITES = ("malware_analysis", "attack_kb", "cybergym")

# rag_g 模式追加的作答规则（接在 rag v2 的 3 条要求之后）。
_GUESS_RULES = (
    "4. 【禁止弃答】不允许输出空答案 ANSWER: []；每题必须选出你认为"
    "最可能的选项。\n"
    "5. 当题目引用的沙箱报告内容未随题提供、无法获得时，基于恶意软件"
    "的典型行为、MITRE ATT&CK 知识和选项间的相对合理性给出最佳猜测，"
    "不得弃答。\n"
    "6. 仍保持“宁缺毋滥”的精神（不要把所有沾边选项都选上），但绝不"
    "弃答。\n\n"
)

# rag v6（默认）同款规则，编号接在知识使用指引/逐项裁决之后。
_GUESS_RULES_V5 = (
    "6. 【禁止弃答】不允许输出空答案 ANSWER: []；每题必须选出你认为"
    "最可能的选项。\n"
    "7. 当题目引用的沙箱报告内容未随题提供、无法获得时，基于恶意软件"
    "的典型行为、检索到的家族/类别行为资料和选项间的相对合理性给出"
    "最佳猜测，不得弃答。\n"
    "8. 仍保持“宁缺毋滥”的精神（不要把所有沾边选项都选上），但绝不"
    "弃答。\n\n"
)

# self-consistency（sc / sc_base 模式）默认参数：每题采样 k 次（温度>0），
# 然后逐选项多数投票（选项得票 >= k//2+1 才入选）。
SC_K = 3
SC_TEMPERATURE = 0.7

# rag_fs 模式的 2 条示例：基于公开恶意软件知识手工编写，
# 与 609 道基准题无关（避免泄题）。
_FEWSHOT_EXAMPLES = (
    "【示例 1】\n"
    "题目：某样本在 HKCU\\...\\Run 下写入自启动项，并创建名为 "
    "\"UpdateSvc\" 的计划任务在每次登录时运行。该样本使用了哪些持久化"
    "技术？\n"
    "选项：\n"
    "A. Registry Run Keys / Startup Folder\n"
    "B. Scheduled Task/Job\n"
    "C. DLL Search Order Hijacking\n"
    "D. Bootkit\n"
    "推理：写入 Run 注册表键对应 T1547.001（A）；创建计划任务对应 "
    "T1053（B）。报告中没有 DLL 加载顺序或引导扇区相关行为，"
    "C、D 无依据，不选。\n"
    "ANSWER: [\"A\",\"B\"]\n\n"
    "【示例 2】\n"
    "题目：样本先通过 DGA 算法生成大量域名进行解析，随后将窃取的凭证用 "
    "RC4 加密后嵌入 DNS TXT 查询发往攻击者控制的权威域名服务器。这"
    "描述了哪些行为？\n"
    "选项：\n"
    "A. 使用 DGA 生成 C2 域名\n"
    "B. 通过 DNS 协议外传数据\n"
    "C. 利用 SMB 进行横向移动\n"
    "D. 对磁盘文件进行勒索加密\n"
    "推理：DGA 生成域名对应 T1568.002（A）；把加密数据放进 DNS TXT "
    "查询发出属于经 DNS 的 C2/外传（B）。SMB 横向移动与勒索加密在"
    "描述中均未出现，C、D 不选。\n"
    "ANSWER: [\"A\",\"B\"]"
)

_LETTER = r"[A-H]"
_ANSWER_LINE_RE = re.compile(
    r"ANSWER\s*[:：=]?\s*(.+)", re.IGNORECASE)
_CN_ANSWER_RE = re.compile(
    r"答案\s*[是为:]?\s*[:：]?\s*((?:{0}|[,、，和\s])+)".format(_LETTER))
_BRACKET_RE = re.compile(r"\[([^\[\]]{0,40})\]")
_BARE_LINE_RE = re.compile(
    r"^\s*\[?\s*({0}(?:\s*[,，、]\s*{0})*)\s*\]?\s*$".format(_LETTER),
    re.MULTILINE)
_LETTERS_RE = re.compile(_LETTER)


# ----------------------------------------------------------------------- #
# 题目加载与采样
# ----------------------------------------------------------------------- #
def load_questions(path: "str | Path" = DEFAULT_QUESTIONS,
                   strict: bool = False) -> list[dict]:
    """加载 questions.json 并做 schema 校验，返回题目列表。

    默认跳过无效条目（如 correct_options 为空）；strict=True 时遇到
    无效条目直接抛 ValueError（测试用）。
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        raise ValueError("questions.json 顶层必须是数组")
    questions = []
    for i, q in enumerate(raw):
        try:
            if not isinstance(q.get("question"), str) \
                    or not q["question"].strip():
                raise ValueError(f"第 {i} 题缺少 question 字段")
            options = q.get("options")
            if not isinstance(options, list) or len(options) < 2:
                raise ValueError(f"第 {i} 题 options 必须是长度>=2 的数组")
            gold = q.get("correct_options")
            if not isinstance(gold, list) or not gold:
                raise ValueError(f"第 {i} 题 correct_options 必须是非空数组")
            gold_letters = sorted({str(a).strip().upper() for a in gold})
            valid = {chr(ord("A") + k) for k in range(len(options))}
            if any(a not in valid for a in gold_letters):
                raise ValueError(f"第 {i} 题 correct_options 超出选项范围")
        except ValueError:
            if strict:
                raise
            continue
        questions.append({
            "idx": i,
            "question": q["question"].strip(),
            "options": [str(o) for o in options],
            "correct_options": gold_letters,
            "topic": q.get("topic") or "unknown",
            "difficulty": q.get("difficulty") or "unknown",
            "attack": q.get("attack") or "",
        })
    return questions


def sample_questions(questions: list[dict], n: int, seed: int) -> list[dict]:
    """固定 seed 确定性采样（base / rag 回答同一批题目）。"""
    n = max(1, min(int(n), len(questions)))
    rng = random.Random(seed)
    idxs = sorted(rng.sample(range(len(questions)), n))
    return [questions[i] for i in idxs]


# ----------------------------------------------------------------------- #
# 答案解析（容错）
# ----------------------------------------------------------------------- #
def _letters_from(text: str) -> list[str]:
    seen: list[str] = []
    for m in _LETTERS_RE.findall(text):
        if m not in seen:
            seen.append(m)
    return sorted(seen)


def parse_answers(text: str) -> list[str]:
    """从模型输出中提取选项字母；解析失败返回 []（计 wrong + parse_fail）。

    依次尝试：
      1. 最后一个 ANSWER: ... 行（首选，兼容 markdown 围栏）；
      2. “答案是 AC”/“答案：A、C”中文表述；
      3. 最后一个只含字母的方括号列表（如 ["A","C"] / [A, C]）；
      4. 最后一个只含字母的裸行（如 ``A, C``）。
    """
    text = str(text or "")
    hits = _ANSWER_LINE_RE.findall(text)
    if hits:
        letters = _letters_from(hits[-1])
        if letters:
            return letters
    hits = _CN_ANSWER_RE.findall(text)
    if hits:
        letters = _letters_from(hits[-1])
        if letters:
            return letters
    for content in reversed(_BRACKET_RE.findall(text)):
        if re.fullmatch(rf"\s*[\"']?{_LETTER}[\"']?"
                        rf"(\s*[,，、]\s*[\"']?{_LETTER}[\"']?)*\s*",
                        content):
            return _letters_from(content)
    hits = _BARE_LINE_RE.findall(text)
    if hits:
        letters = _letters_from(hits[-1])
        if letters:
            return letters
    return []


# ----------------------------------------------------------------------- #
# self-consistency：逐选项多数投票
# ----------------------------------------------------------------------- #
def majority_vote(sample_preds: list[list[str]], k: int) -> list[str]:
    """对 k 次采样的解析结果逐选项投票：得票 >= k//2+1 的选项入选。

    解析失败的样本（空列表）只是不投票；全部失败或没有任何选项达到
    多数门槛时返回 []（记 wrong + parse_fail）。
    """
    threshold = k // 2 + 1
    counts: dict[str, int] = {}
    for pred in sample_preds:
        for letter in set(pred):       # 同一选项在一次采样内只算一票
            counts[letter] = counts.get(letter, 0) + 1
    return sorted(l for l, c in counts.items() if c >= threshold)


# ----------------------------------------------------------------------- #
# 评分
# ----------------------------------------------------------------------- #
def grade(pred: list[str], gold: list[str]) -> tuple[bool, float]:
    """返回 (exact_match, jaccard)。pred 为空时 (False, 0.0)。"""
    p, g = set(pred), set(gold)
    if not g:
        return False, 0.0
    if not p:
        return False, 0.0
    jaccard = len(p & g) / len(p | g)
    return p == g, jaccard


def _group_scores(rows: list[dict], key: str) -> dict:
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r.get(key) or "unknown", []).append(r)
    return {
        name: {
            "n": len(rs),
            "correct_mc_pct": round(
                sum(1 for r in rs if r["exact"]) / len(rs), 4),
            "avg_score": round(
                sum(r["jaccard"] for r in rs) / len(rs), 4),
        }
        for name, rs in sorted(groups.items())
    }


def compute_scores(rows: list[dict]) -> dict:
    """由逐题结果计算总分与分组统计。"""
    n = len(rows)
    if not n:
        return {"n": 0, "correct_mc_pct": 0.0, "avg_score": 0.0,
                "parse_fail": 0, "llm_errors": 0}
    return {
        "n": n,
        "correct_mc_pct": round(sum(r["exact"] for r in rows) / n, 4),
        "avg_score": round(sum(r["jaccard"] for r in rows) / n, 4),
        "parse_fail": sum(1 for r in rows if not r["parse_ok"]),
        # LLM 调用失败的题目数（endpoint 故障时不再静默成全 0 分）。
        "llm_errors": sum(1 for r in rows if r.get("llm_error")),
        "by_difficulty": _group_scores(rows, "difficulty"),
        "by_topic": _group_scores(rows, "topic"),
    }


# ----------------------------------------------------------------------- #
# 两段式检索 + 家族类别 playbook 注入
# ----------------------------------------------------------------------- #
_OPT_PREFIX_RE = re.compile(r"^\s*[A-Z]\s*[.、)]\s*")

# 题目的 attack 元数据（所引用报告所属家族/类别）-> kb/data/
# sandbox_knowledge.json 中对应的类别行为 playbook 文档。
# 实测纯相似度检索只能把 playbook 带进 top-3 约 4% 的题，而它正是
# “报告内容缺失”失败模式下最相关的知识，因此按类别确定性注入。
ATTACK_PLAYBOOK = {
    "infostealers": "SBX008",
    "ransomware": "SBX009",
    "killers": "SBX010",
    "um_unhooking": "SBX010",   # 用户态 unhooking 见 SBX010 EDR 对抗段
    "remcos": "SBX011",
}


def _strip_option_prefix(option: str) -> str:
    """去掉选项文本前的字母标号（"A. Packing (UPX)" -> "Packing (UPX)"）。"""
    return _OPT_PREFIX_RE.sub("", str(option or ""), count=1).strip()


def retrieve_for_question(kb, q: dict, k: int) -> list[dict]:
    """两段式检索 + 家族类别 playbook 注入（rag/sc 模式）。

    stage-1：查询 = 家族类别（题目的 attack 元数据，标识所引用报告属于
    哪个家族/类别，如 infostealers/remcos）+ 题干。
    若 stage-1 top-1 得分 < RETRIEVAL_MIN_SCORE（embedding 余弦相似度
    标定；BM25 回退模式得分量级远大于阈值，stage-2 不会触发），
    stage-2：查询 = stage-1 查询 + 全部选项文本（去掉字母标号），
    取 top-1 得分更高的一组结果。
    最后：若 attack 类别在 ATTACK_PLAYBOOK 中有对应 playbook 文档，
    将其确定性置顶（去重），保证类别行为知识一定出现在提示中。
    """
    attack = (q.get("attack") or "").strip()
    q1 = f"{attack} {q['question']}".strip()
    docs1 = kb.search(q1, k)
    top1 = docs1[0]["score"] if docs1 else 0.0
    if top1 >= RETRIEVAL_MIN_SCORE:
        docs = docs1
    else:
        options = " ".join(
            _strip_option_prefix(o) for o in q.get("options") or [])
        docs2 = kb.search(f"{q1} {options}".strip(), k)
        top2 = docs2[0]["score"] if docs2 else 0.0
        docs = docs2 if top2 > top1 else docs1
    playbook_id = ATTACK_PLAYBOOK.get(attack.lower())
    if playbook_id:
        playbook = None
        lookup = getattr(kb, "lookup", None)
        if callable(lookup):
            playbook = lookup(playbook_id)
        if playbook:
            playbook = dict(playbook)
            playbook["score"] = 1.0   # 确定性置顶（展示用）
            docs = [playbook] + [d for d in docs
                                 if d.get("id") != playbook_id]
    return docs


# ----------------------------------------------------------------------- #
# 提示构造
# ----------------------------------------------------------------------- #
def _format_question(q: dict) -> str:
    return q["question"] + "\n\n选项：\n" + "\n".join(q["options"])


def _format_kb_docs(docs: list[dict], clip: int = 600) -> str:
    blocks = []
    for d in docs:
        parts = [f"### {d['id']} {d['name']}"]
        if d.get("tactics"):
            parts.append(f"战术: {', '.join(d['tactics'])}")
        desc = (d.get("description") or "")[:clip]
        if desc:
            parts.append(f"描述: {desc}")
        det = (d.get("detection") or "")[:300]
        if det:
            parts.append(f"检测要点: {det}")
        blocks.append("\n".join(parts))
    return "\n\n".join(blocks)


# rag v5（默认）在禁止弃答规则之前追加的知识使用指引：检索条目可能正好
# 是题目所指样本的家族/类别行为资料，应主动用来推断报告内容。
# v6 追加第 5 条逐项裁决（针对细粒度多选总多选/漏选 1 项的问题）。
_KNOWLEDGE_GUIDANCE = (
    "4. 【知识用法】检索条目中若包含题目所指恶意软件的家族/类别行为"
    "资料（如 infostealer、ransomware、RAT、AV-killer 的典型行为）或"
    "沙箱报告解读知识，应将其视为对该报告最可能内容的描述：据此判断"
    "每个选项是否属于该样本的典型可观测行为。\n"
    "5. 【逐项裁决】先对每个选项单独给出“是/否”裁决（一句话理由），"
    "再汇总最终答案；不要凭整体印象一次性圈选。\n"
)


def build_prompt(q: dict, mode: str = "base",
                 kb_docs: "list[dict] | None" = None) -> tuple[str, str]:
    """构造 (system, user)。

    rag（默认 v5）：知识摘录 + 知识使用指引 + 禁止弃答规则；
    rag_fs（legacy v3）：旧 v2 提示前置 2 条示例；
    rag_g（legacy v4）：旧 v2 提示 + 禁止弃答规则（无知识使用指引）。"""
    user = f"题目：\n{_format_question(q)}\n\n{_ANSWER_INSTRUCTION}"
    if mode in ("rag", "rag_fs", "rag_g"):
        system = _SYSTEM_RAG
        excerpt = _format_kb_docs(kb_docs or [])
        rules = (
            "作答要求：\n"
            "1. 以题目描述的恶意软件行为本身为判断依据；知识条目只在"
            "与题目明确相关时作为佐证，绝不因为某个知识条目被检索到就"
            "把对应选项选上。\n"
            "2. 宁缺毋滥：只选有充分依据的选项，不要把所有沾边的选项"
            "都选上——多选错误选项与漏选同样扣分。\n"
            "3. 若知识条目与题目无关，完全忽略它们，依据你自身的恶意"
            "软件分析知识作答。\n"
        )
        header = ("【检索到的 MITRE ATT&CK 知识】（仅供参考，可能部分或"
                  "全部与本题无关）")
        if mode == "rag":
            rules += _KNOWLEDGE_GUIDANCE + _GUESS_RULES_V5
            header = ("【检索到的恶意软件知识】（ATT&CK 技术 / 恶意软件"
                      "家族资料 / 沙箱报告解读知识，仅供参考）")
        elif mode == "rag_g":
            rules += _GUESS_RULES
        user = (
            "【待答题目】\n"
            f"{_format_question(q)}\n\n"
            f"{header}\n"
            f"{excerpt or '（无相关条目）'}\n\n"
            f"{rules}"
            f"{_ANSWER_INSTRUCTION}"
        )
        if mode == "rag_fs":
            user = (
                "先阅读下面 2 个作答示例（学习“依据题目行为、宁缺毋滥”"
                "的答题方式），然后回答【待答题目】。\n\n"
                f"{_FEWSHOT_EXAMPLES}\n\n"
                "————————————————————\n\n"
                f"{user}"
            )
    else:
        system = _SYSTEM_BASE
    return system, user


# ----------------------------------------------------------------------- #
# LLM 客户端（与 agents 相同的环境变量驱动模式）
# ----------------------------------------------------------------------- #
def _model_name() -> str:
    """CAI_MODEL 去掉 provider/ 前缀（如 openai/qwen3.7-max -> qwen3.7-max）。"""
    name = os.getenv("CAI_MODEL", "qwen3.7-max")
    return name.split("/", 1)[1] if "/" in name else name


def make_llm(timeout: float = LLM_TIMEOUT,
             temperature: "float | None" = None):
    """返回 async callable(system, user) -> str（单次对话补全）。

    temperature 为 None 时不下发该参数（沿用 endpoint 默认，保持
    base/rag 的历史行为不变）；sc 模式传 0.7 以获得多样采样。
    """
    from openai import AsyncOpenAI

    kwargs = {"api_key": os.getenv("OPENAI_API_KEY", "missing-key"),
              "timeout": timeout, "max_retries": 1}
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url
    client = AsyncOpenAI(**kwargs)
    model = _model_name()

    async def call(system: str, user: str) -> str:
        extra = {"temperature": temperature} if temperature is not None else {}
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            max_tokens=_MAX_TOKENS,
            **extra)
        return (resp.choices[0].message.content or "").strip()

    return call


# ----------------------------------------------------------------------- #
# 运行
# ----------------------------------------------------------------------- #
async def run_bench(n: int = 100, mode: str = "base", seed: int = 42,
                    questions_path: "str | Path" = DEFAULT_QUESTIONS,
                    log_dir: "str | Path" = DEFAULT_LOG_DIR,
                    concurrency: int = CONCURRENCY,
                    llm=None, kb=None,
                    on_progress=None, run_id: "str | None" = None,
                    sc_k: int = SC_K,
                    sc_temperature: float = SC_TEMPERATURE,
                    suite: str = "malware_analysis") -> dict:
    """跑一次基准并持久化结果，返回 run dict。

    Args:
        suite: "malware_analysis"（默认，CyberSOCEval 恶意软件分析）/
               "attack_kb"（ATT&CK 知识库访问能力测试，委托
               bench.attack_kb 实现，仅支持 base/rag）/
               "cybergym"（CyberGym 真实漏洞 PoC 复现，委托
               bench.cybergym_bench 实现，mode 解释为臂：
               vanilla/framework）。
        mode: "base"（裸提示）/ "rag"（默认 v5：知识检索注入 + 禁止弃答，
              两段式检索）/ "rag_fs"（legacy：旧 v2 + 2 条 few-shot 示例）/
              "sc"（rag 提示采样 sc_k 次后逐选项多数投票）/
              "sc_base"（同 sc，但用裸提示，用于分离投票与 KB 的贡献）/
              "rag_g"（legacy：旧 v4 = v2 + 禁止弃答，用于新旧对比）。
        llm: 可注入的 async callable(system, user)->str（测试用 mock）。
        kb: 可注入的 AttackKB（rag/rag_fs/rag_g/sc 模式；None 时用
            get_kb()）。
        on_progress: 可选回调 fn(done, total, llm_errors)（服务端推送进度用；
            旧的两参数回调也兼容）。
        sc_k / sc_temperature: sc 模式的每题采样数与采样温度。
    """
    if suite == "attack_kb":
        from . import attack_kb
        return await attack_kb.run_bench(
            n=n, mode=mode, seed=seed, log_dir=log_dir,
            concurrency=concurrency, llm=llm, kb=kb,
            on_progress=on_progress, run_id=run_id)
    if suite == "cybergym":
        from . import cybergym_bench
        return await cybergym_bench.run_bench(
            n=n, mode=mode, seed=seed, log_dir=log_dir,
            on_progress=on_progress, run_id=run_id)
    if suite != "malware_analysis":
        raise ValueError(f"未知 suite: {suite!r}（支持 {SUITES}）")
    if mode not in MODES:
        raise ValueError(f"未知 mode: {mode!r}")
    is_sc = mode in ("sc", "sc_base")
    use_kb = mode in ("rag", "rag_fs", "rag_g", "sc")
    prompt_mode = {"sc": "rag", "sc_base": "base"}.get(mode, mode)
    sc_k = max(1, int(sc_k))
    questions = sample_questions(load_questions(questions_path), n, seed)
    if llm is None:
        llm = make_llm(temperature=sc_temperature if is_sc else None)
    if use_kb and kb is None:
        from ..kb.rag import get_kb
        kb = get_kb()

    sem = asyncio.Semaphore(max(1, concurrency))
    rows: list[dict | None] = [None] * len(questions)
    done = 0
    err_questions = 0           # LLM 调用失败的题目数（sc：k 次全败）
    first_llm_error: list[str] = []   # 只保留第一条，作为 run["error"]

    async def _call(system: str, user: str) -> str:
        async with sem:
            try:
                return await llm(system, user)
            except Exception as exc:  # 单次失败记 wrong，不中断整轮
                if not first_llm_error:
                    first_llm_error.append(
                        f"{type(exc).__name__}: {exc}"[:400])
                return f"__LLM_ERROR__: {type(exc).__name__}: {exc}"

    async def answer(i: int, q: dict) -> None:
        nonlocal done, err_questions
        kb_docs = None
        if use_kb:
            try:
                if mode in ("rag", "sc"):
                    # v5：两段式检索（家族类别 + 题干；低分时并入选项文本
                    # 重检）。
                    kb_docs = await asyncio.to_thread(
                        retrieve_for_question, kb, q, RAG_TOP_K)
                else:
                    # legacy（rag_fs / rag_g）：保持 v2 的题干单段检索，
                    # 用于新旧配方对比。
                    kb_docs = await asyncio.to_thread(kb.search,
                                                      q["question"],
                                                      RAG_TOP_K)
            except Exception:
                kb_docs = []
        system, user = build_prompt(q, prompt_mode, kb_docs)
        if is_sc:
            # k 次采样并发，但每次调用仍单独受 sem 约束（总并发不超上限）。
            raws = await asyncio.gather(*(_call(system, user)
                                          for _ in range(sc_k)))
            sample_preds = [parse_answers(r) for r in raws]
            pred = majority_vote(sample_preds, sc_k)
            raw = "\n--- sample ---\n".join(raws)
            # k 次采样全部失败才算本题 LLM 失败。
            row_err = all(r.startswith("__LLM_ERROR__") for r in raws)
        else:
            raw = await _call(system, user)
            pred = parse_answers(raw)
            row_err = raw.startswith("__LLM_ERROR__")
        if row_err:
            err_questions += 1
        exact, jaccard = grade(pred, q["correct_options"])
        rows[i] = {
            "idx": q["idx"],
            "topic": q["topic"],
            "difficulty": q["difficulty"],
            "attack": q["attack"],
            "question": q["question"][:200],
            "gold": q["correct_options"],
            "pred": pred,
            "raw": raw[:800],
            "parse_ok": bool(pred),
            "llm_error": row_err,
            "exact": exact,
            "jaccard": round(jaccard, 4),
        }
        done += 1
        if on_progress is not None:
            try:
                on_progress(done, len(questions), err_questions)
            except TypeError:
                # 兼容旧的两参数回调。
                try:
                    on_progress(done, len(questions))
                except Exception:
                    pass
            except Exception:
                pass

    started = time.time()
    await asyncio.gather(*(answer(i, q) for i, q in enumerate(questions)))
    finished = time.time()
    results = [r for r in rows if r is not None]

    ts = time.strftime("%Y%m%d_%H%M%S")
    run_id = run_id or f"{ts}_{suite}_{mode}_n{len(results)}"
    llm_errors = err_questions
    run = {
        "run_id": run_id,
        "suite": suite,
        "mode": mode,
        "n": len(results),
        "seed": seed,
        "model": _model_name(),
        "rag_top_k": RAG_TOP_K if use_kb else 0,
        "prompt_version": (PROMPT_VERSION_G if mode == "rag_g"
                           else PROMPT_VERSION_FS if mode == "rag_fs"
                           else PROMPT_VERSION if use_kb else 1),
        "started_at": started,
        "finished_at": finished,
        "elapsed_sec": round(finished - started, 1),
        "scores": compute_scores(results),
        "results": results,
        # LLM endpoint 故障可见性：失败题数 + 首条错误信息；全部失败时
        # status="error"（持久化 + 由 server 经 WS/REST 透出）。
        "llm_errors": llm_errors,
        "error": first_llm_error[0] if llm_errors else None,
        "status": ("error" if results and llm_errors == len(results)
                   else "done"),
    }
    if is_sc:
        run["sc_k"] = sc_k
        run["sc_temperature"] = sc_temperature

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    out = log_dir / f"{run_id}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(run, f, ensure_ascii=False, indent=1)
    run["path"] = str(out)
    return run


def list_runs(log_dir: "str | Path" = DEFAULT_LOG_DIR) -> list[dict]:
    """扫描 logs/bench 下历史运行的摘要（按时间倒序）。"""
    log_dir = Path(log_dir)
    runs = []
    for p in sorted(log_dir.glob("*.json"), reverse=True):
        try:
            with open(p, "r", encoding="utf-8") as f:
                run = json.load(f)
            runs.append({
                "run_id": run.get("run_id") or p.stem,
                # 旧版运行文件无 suite 字段 -> 默认 malware_analysis。
                "suite": run.get("suite") or "malware_analysis",
                "mode": run.get("mode"),
                "n": run.get("n"),
                "seed": run.get("seed"),
                "model": run.get("model"),
                "elapsed_sec": run.get("elapsed_sec"),
                "scores": run.get("scores"),
                # 旧版运行文件无以下字段 -> None/0，前端按缺失处理。
                "status": run.get("status"),
                "error": run.get("error"),
                "llm_errors": run.get("llm_errors", 0),
                "path": str(p),
            })
        except Exception:
            continue
    return runs
