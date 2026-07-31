"""红方工具共享辅助：_gt_record 地面真值记录装饰器与输出裁剪。

红方仅允许网络攻击面，禁止 docker exec 攻击（唯一例外见 claim_success 裁判）。

_gt_record 移植自已删除的 tools/red_attacks.py：工具运行后把结果记录到
会话地面真值（cyberorion.eval.ground_truth）。无活动会话（未绑定）时静默
跳过，绝不影响工具本身返回。
"""

from __future__ import annotations

import functools
from typing import Any, Callable

# 红方工具统一输出上限（紧凑结构化输出）。
MAX_OUTPUT = 1200


def _clip(text: str, limit: int = MAX_OUTPUT) -> str:
    """裁剪输出到 limit 字符，超长时追加省略标记。"""
    text = str(text or "")
    if len(text) <= limit:
        return text
    return text[:limit] + f"...<+{len(text) - limit} chars>"


def _kw(name: str, pos: int, default: Any) -> Callable:
    """构造一个按关键字或位置取工具参数的 callable（供 _gt_record 用）。"""
    def pick(*args: Any, **kwargs: Any) -> Any:
        if name in kwargs:
            return kwargs[name]
        return args[pos] if len(args) > pos else default
    return pick


def _gt_record(technique: Any, target: Any, judge: Callable[[str], bool]):
    """装饰器：红方工具运行后记录地面真值。

    Args:
        technique: MITRE ATT&CK 编号字符串，或 callable(*args, **kwargs)
            返回编号（当编号依赖工具参数时）。
        target: 目标名字符串，或同 technique 形式的 callable。
        judge: callable(result: str) -> bool，从工具自身输出判定成功与否。

    绑定缺失（无活动会话）绝不能破坏工具，所有异常一律吞掉。
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            try:
                from ...eval.ground_truth import get_ground_truth
                gt = get_ground_truth()
                if gt is not None:
                    tech = technique(*args, **kwargs) if callable(technique) else technique
                    tgt = target(*args, **kwargs) if callable(target) else target
                    gt.record(
                        target=str(tgt), technique=str(tech),
                        action=fn.__name__, success=bool(judge(result)),
                        evidence=str(result)[:300],
                    )
            except Exception:
                pass
            return result
        return wrapper
    return deco
