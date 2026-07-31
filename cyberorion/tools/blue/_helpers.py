"""蓝队工具共享辅助函数。

包含 store 获取、输出截断、场景目标解析（host 名 -> 容器名）与
IP 校验。本模块与 tools/blue 下所有工具一样，只接触遥测数据与
容器运行时，绝不读取红队 ground truth。
"""

from __future__ import annotations

import re
from typing import Any

from ...scenarios import load_scenario
from ...telemetry.binding import get_store
from ...telemetry.store import TelemetryStore

# 单次工具返回的最大字符数，超出则截断并注明。
MAX_OUT = 1200

# 场景缓存：进程内只加载一次（load_scenario 每次都会读 YAML）。
_SCENARIO_CACHE: Any = None


def _clip(text: str, limit: int = MAX_OUT) -> str:
    """把输出截断到 ``limit`` 字符，截断时附注说明。"""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...(已截断，共 {len(text)} 字符)"


def _require_store() -> "TelemetryStore | str":
    """返回绑定的 store；未绑定时返回解释性错误字符串。"""
    store = get_store()
    if store is None:
        return ("telemetry store 未绑定：当前没有活动会话"
                "（控制器在会话开始时才会绑定 store）")
    return store


def _scenario():
    """加载并缓存当前场景；失败时返回 None。"""
    global _SCENARIO_CACHE
    if _SCENARIO_CACHE is None:
        try:
            _SCENARIO_CACHE = load_scenario()
        except Exception:
            return None
    return _SCENARIO_CACHE


def _target_container(host: str) -> "str | None":
    """把场景目标名解析为容器名；查不到时返回 None。

    只读取 target.container（结构信息），绝不触碰 target.ground_truth。
    """
    sc = _scenario()
    if sc is not None and host in sc.targets:
        return sc.targets[host].container
    return None


def _all_containers() -> list[str]:
    """返回场景中所有目标的容器名列表。"""
    sc = _scenario()
    if sc is None:
        return []
    return [t.container for t in sc.targets.values()]


def _resolve_container(host_or_container: str) -> "str | None":
    """把工具入参（目标名或容器名）解析为容器名。

    优先按场景目标名解析；否则回退到 _common._resolve_container 的
    别名表；都失败时返回 None（调用方应返回错误字符串）。
    """
    name = (host_or_container or "").strip()
    if not name:
        return None
    c = _target_container(name)
    if c is not None:
        return c
    from .._common import _resolve_container as _legacy
    resolved = _legacy(name)
    return resolved or None


def _is_safe_ip(ip: str) -> bool:
    """校验 IPv4 字符串并拒绝 shell 元字符（沿用旧蓝队工具的校验）。"""
    if not ip or "/" in ip or any(c in ip for c in ";&|`$"):
        return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip.strip()))
