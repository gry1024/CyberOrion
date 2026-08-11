"""流量分析模块 — 数据集回放 + 异常检测 + 统一事件格式。

低耦合设计：loaders（数据加载）→ feeder（回放引擎）→ detector（检测）三件独立，
互相只通过 UnifiedEvent 数据结构通信，不依赖项目其他模块。
"""
from .feeder import TrafficFeeder, UnifiedEvent
from .detector import TrafficDetector, TrafficAlert
from .loaders import load_cicids, load_ad_scenario
from .synthetic import load_synthetic, generate_ad_attack_scenario

__all__ = [
    "TrafficFeeder", "UnifiedEvent", "TrafficDetector", "TrafficAlert",
    "load_cicids", "load_synthetic", "load_ad_scenario", "generate_ad_attack_scenario",
]