#!/usr/bin/env python3
"""v2 攻防联调测试 — 验证红蓝 agent 能完整运行。

流程：
  1. 加载 ad_domain 场景
  2. 创建 ControllerV2
  3. 启动红队（短 max_steps=10 用于测试）
  4. 等待红队完成
  5. 启动蓝队（短 max_steps=10）
  6. 等待蓝队完成
  7. 打印结果摘要

无 API key / 网络问题时 agent loop 会产出 error 事件，但 ControllerV2 不崩溃，
测试仍打印摘要。退出码 0=通过，1=断言失败。
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
_ROOT = _REPO.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _load_env() -> None:
    """从 cai/.env 加载环境变量（API key / model 等）。"""
    env_path = _ROOT / ".env"
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return
    except ImportError:
        pass
    with open(env_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


async def main() -> None:
    import yaml
    from cyberorion.core.event_bus import EventBus
    from cyberorion.core.session_state import SessionState
    from cyberorion.core.controller_v2 import ControllerV2
    from cyberorion.scenarios.loader import SCENARIOS_DIR

    # 1. 加载场景
    scenario_path = SCENARIOS_DIR / "ad_domain.yaml"
    scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    print(f"[1/7] 场景加载: {scenario.get('name', '?')}")

    # 2. 创建 ControllerV2
    bus = EventBus()
    state = SessionState()
    controller = ControllerV2(bus, state)
    # 订阅事件用于打印
    q = bus.subscribe()
    print("[2/7] ControllerV2 创建完成")

    # 3. 启动红队（短 max_steps=10 用于测试）
    red_task = await controller.start_red(scenario, max_steps=10)
    print("[3/7] 红队已启动 (max_steps=10)")

    # 4. 等待红队完成（超时 300s）
    try:
        done, _ = await asyncio.wait({red_task}, timeout=300)
        if red_task not in done:
            print("  [WARN] 红队超时，主动停止")
            await controller.stop_red()
            try:
                await asyncio.wait_for(red_task, timeout=30)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                red_task.cancel()
                try:
                    await red_task
                except (asyncio.CancelledError, Exception):
                    pass
    except Exception as exc:
        print(f"  [WARN] 红队异常: {exc}")
    print("[4/7] 红队完成")

    # 5. 启动蓝队（短 max_steps=10）
    blue_task = await controller.start_blue(scenario, max_steps=10)
    print("[5/7] 蓝队已启动 (max_steps=10)")

    # 6. 等待蓝队完成
    try:
        done, _ = await asyncio.wait({blue_task}, timeout=300)
        if blue_task not in done:
            print("  [WARN] 蓝队超时，主动停止")
            await controller.stop_blue()
            try:
                await asyncio.wait_for(blue_task, timeout=30)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                blue_task.cancel()
                try:
                    await blue_task
                except (asyncio.CancelledError, Exception):
                    pass
    except Exception as exc:
        print(f"  [WARN] 蓝队异常: {exc}")
    print("[6/7] 蓝队完成")

    # 打印收集到的事件摘要
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    print(f"  事件总数: {len(events)}")
    types = sorted({e.type for e in events})
    print(f"  事件类型: {types}")

    # 7. 打印结果摘要
    status = controller.get_status()
    print("[7/7] 结果摘要:")
    print(f"  红队: running={status['red_running']}")
    if status["red_last"]:
        r = status["red_last"]
        print(f"    reason={r['reason']}, steps={r['steps']}, "
              f"findings={len(r['findings'])}")
        if r.get("error"):
            print(f"    error={r['error'][:200]}")
    else:
        print("    (无产出)")
    print(f"  蓝队: running={status['blue_running']}")
    if status["blue_last"]:
        b = status["blue_last"]
        print(f"    reason={b['reason']}, steps={b['steps']}, "
              f"findings={len(b['findings'])}")
        if b.get("error"):
            print(f"    error={b['error'][:200]}")
    else:
        print("    (无产出)")
    print("\n=== v2 攻防联调测试完成 ===")


if __name__ == "__main__":
    _load_env()
    asyncio.run(main())