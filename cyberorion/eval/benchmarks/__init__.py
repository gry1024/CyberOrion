"""CybORG CAGE-2 benchmark 适配器（懒加载、可选依赖）。

导入本模块【不需要】安装 CybORG；只有真正调用 :func:`run_cage2` 且
CybORG 可用时才会进入基准流程。未安装时返回带安装提示的 error 字典，
绝不抛 ImportError。
"""

from .cyborg_adapter import run_cage2

__all__ = ["run_cage2"]
