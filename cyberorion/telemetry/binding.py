"""会话级 TelemetryStore 绑定。

镜像 ``eval.ground_truth`` 的模式：控制器在会话开始时调用
:func:`set_store`，蓝队工具通过 :func:`get_store` 获取当前会话的
store，无需把 store 穿进工具签名。工具必须容忍 ``None``（无活动
会话 / store 未绑定）并返回解释性字符串，绝不能抛进 agent loop。
"""

from __future__ import annotations

import threading

from .store import TelemetryStore

_lock = threading.Lock()
_CURRENT: "TelemetryStore | None" = None


def set_store(store: "TelemetryStore | None") -> None:
    """绑定（或解绑）当前会话的 TelemetryStore。"""
    global _CURRENT
    with _lock:
        _CURRENT = store


def get_store() -> "TelemetryStore | None":
    """返回当前会话的 TelemetryStore，未绑定时返回 None。"""
    with _lock:
        return _CURRENT
