#!/usr/bin/env python3
# Add transient API-failure retry to AgentRunner.run()
from __future__ import annotations
from pathlib import Path
HERE = Path(__file__).resolve().parent.parent
TARGET = HERE / "cyberorion" / "core" / "agent_runner.py"
src = TARGET.read_text(encoding="utf-8")
old_import = "from cai.sdk.agents import Agent, Runner, RunConfig"
new_import = (
    "from cai.sdk.agents import Agent, Runner, RunConfig\n"
    "from openai import APIConnectionError, APITimeoutError, RateLimitError\n"
)
assert old_import in src, "import anchor not found"
src = src.replace(old_import, new_import, 1)
old_try = """        try:
            result_obj, timed_out = await run_with_timeout(
                _stream, timeout, task_registry=task_registry)
            if timed_out:
                output = f"({self.side} timed out after {timeout}s)"
                await self.event_bus.publish(Event(
                    type="tool_output", side=self.side,
                    data=self._tag({"output": output, "error": "timeout"}),
                ))
                await self.event_bus.publish(Event(
                    type="error", side=self.side,
                    data=self._tag({
                        "message": f"{self.side} agent \u8fd0\u884c\u8d85\u65f6\uff08{timeout}s\uff09",
                        "source": "agent_run",
                    }),
                ))
            else:
                try:
                    output = (getattr(result_obj, "final_output", "") or "").strip()
                except Exception:
                    output = ""
        except Exception as exc:
            ename = type(exc).__name__
            tb = traceback.format_exc(limit=3)
            output = f"(agent error: {ename}: {exc})"
            await self.event_bus.publish(Event(
                type="tool_output", side=self.side,
                data=self._tag({"output": output, "error": ename,
                                "traceback": tb}),
            ))
            await self.event_bus.publish(Event(
                type="error", side=self.side,
                data=self._tag({
                    "message": f"{ename}: {exc}"[:400],
                    "source": "agent_run",
                }),
            ))
"""
new_try = """        # DeepSeek \u7f51\u7edc/API \u77ac\u65f6\u6545\u969c\u91cd\u8bd5\uff1a\u8fde\u63a5\u65ad\u5f00\u3001\u8d85\u65f6\u3001
        # \u9650\u6d41\u90fd\u4e0d\u5e94\u8be5\u8ba9\u6574\u8f6e\u653b\u9632\u4f5c\u5e9f\u3002\u53ef\u91cd\u8bd5\u5f02\u5e38\u505a
        # \u6700\u591a max_attempts \u6b21\u91cd\u8bd5\uff08\u6307\u6570\u9000\u907f\uff09\uff0c\u5176\u4f59\u5f02\u5e38\u7167\u65e7\u4e0a\u62a5\u3002
        retriable = (APIConnectionError, APITimeoutError, RateLimitError)
        max_attempts = 3
        for _attempt in range(1, max_attempts + 1):
            try:
                result_obj, timed_out = await run_with_timeout(
                    _stream, timeout, task_registry=task_registry)
                if timed_out:
                    output = f"({self.side} timed out after {timeout}s)"
                    await self.event_bus.publish(Event(
                        type="tool_output", side=self.side,
                        data=self._tag({"output": output, "error": "timeout"}),
                    ))
                    await self.event_bus.publish(Event(
                        type="error", side=self.side,
                        data=self._tag({
                            "message": f"{self.side} agent \u8fd0\u884c\u8d85\u65f6\uff08{timeout}s\uff09",
                            "source": "agent_run",
                        }),
                    ))
                else:
                    try:
                        output = (getattr(result_obj, "final_output", "") or "").strip()
                    except Exception:
                        output = ""
                break  # success
            except retriable as exc:
                if _attempt >= max_attempts:
                    ename = type(exc).__name__
                    tb = traceback.format_exc(limit=3)
                    output = f"(agent error: {ename}: {exc})"
                    await self.event_bus.publish(Event(
                        type="tool_output", side=self.side,
                        data=self._tag({"output": output, "error": ename,
                                        "traceback": tb}),
                    ))
                    await self.event_bus.publish(Event(
                        type="error", side=self.side,
                        data=self._tag({
                            "message": f"{ename}: {exc}"[:400],
                            "source": "agent_run",
                        }),
                    ))
                    break
                wait_s = min(30, 2 ** (_attempt + 1))
                msg = (f"({self.side} API \u77ac\u65f6\u6545\u969c "
                       f"{type(exc).__name__} \uff0c{wait_s}s \u540e\u91cd\u8bd5 "
                       f"{_attempt}/{max_attempts})")
                await self.event_bus.publish(Event(
                    type="tool_output", side=self.side,
                    data=self._tag({"output": msg, "retry": True}),
                ))
                await asyncio.sleep(wait_s)
            except Exception as exc:
                ename = type(exc).__name__
                tb = traceback.format_exc(limit=3)
                output = f"(agent error: {ename}: {exc})"
                await self.event_bus.publish(Event(
                    type="tool_output", side=self.side,
                    data=self._tag({"output": output, "error": ename,
                                    "traceback": tb}),
                ))
                await self.event_bus.publish(Event(
                    type="error", side=self.side,
                    data=self._tag({
                        "message": f"{ename}: {exc}"[:400],
                        "source": "agent_run",
                    }),
                ))
                break
"""
assert old_try in src, "run try-block anchor not found"
src = src.replace(old_try, new_try, 1)
TARGET.write_text(src, encoding="utf-8")
print("patched OK:", TARGET)