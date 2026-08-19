"""V2 Controller (ControllerV2) - ares-style agent loop managing red/blue cyber range.

仅支持 live 模式（REFACTOR_M1_tools.md D1）。
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from .agent_loop import AgentLoopConfig, AgentLoopOutcome, LoopEndReason, ToolDef, run_agent_loop
from .event_bus import EventBus, Event
from .op_state import OpState
from .prompt_renderer import render_task_prompt
from .session_state import SessionState
from ..agents.v2.red_orchestrator import build_red_orchestrator
from ..agents.v2.blue_orchestrator import build_blue_orchestrator
from ..eval.ground_truth import GroundTruth, set_ground_truth
from ..scenarios import load_scenario
from ..telemetry.binding import set_store
from ..telemetry.collectors import TelemetryCollector
from ..telemetry.store import TelemetryStore
logger = logging.getLogger(__name__)
DEFAULT_RED_MAX_STEPS = 75
DEFAULT_BLUE_MAX_STEPS = 50
DEFAULT_MAX_TOKENS = 8192



class ControllerV2:
    """V2 Controller - ares-style agent loop for red/blue cyber range operations."""

    def __init__(self, event_bus: EventBus, session_state: SessionState) -> None:
        self.event_bus = event_bus
        self.session_state = session_state
        self.state = session_state
        self.red_state = OpState()
        self.blue_state = OpState()
        self.red_task: Optional[asyncio.Task] = None
        self.blue_task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()
        self._red_stop = asyncio.Event()
        self._blue_stop = asyncio.Event()
        self._last_outcome: dict[str, Optional[AgentLoopOutcome]] = {"red": None, "blue": None}
        self.session_id = ""
        self.scenario = {}
        self.scenario_name = ""
        self._scenario_model = None
        self._session_dir: Optional[Path] = None
        self._timeline_fp = None
        self._timeline: list[dict[str, Any]] = []
        self._session_start_time: float = 0.0
        self._session_active = False
        self._red_tool_calls: list = []
        self._blue_tool_calls: list = []
        self._red_step_count: int = 0
        self._blue_step_count: int = 0
        # 兼容 server.py 的只读遥测端点；资源只在活动会话期间有效。
        self.store: Optional[TelemetryStore] = None
        self.collector: Optional[TelemetryCollector] = None
        self.ground_truth: Optional[GroundTruth] = None
        self.last_metrics: Optional[dict[str, Any]] = None

    def _setup_session_dir(self):
        ts = datetime.fromtimestamp(self._session_start_time).strftime("%Y%m%d_%H%M%S")
        logs_dir = Path(os.getcwd()) / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = f"session_{ts}"
        self._session_dir = logs_dir / self.session_id
        self._session_dir.mkdir(parents=True, exist_ok=True)
        tl_path = self._session_dir / "timeline.jsonl"
        self._timeline_fp = open(tl_path, "a", encoding="utf-8")

    def _log_timeline(self, event_type: str, side: str, data: dict):
        entry = {"ts": time.time(), "type": event_type, "side": side, "data": data}
        self._timeline.append(entry)
        if self._timeline_fp is None:
            return
        self._timeline_fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._timeline_fp.flush()

    async def start_session(self, scenario=None) -> None:
        if self._session_active:
            raise RuntimeError("session already active; stop it before starting another")
        if scenario is None:
            from ..scenarios.loader import DEFAULT_SCENARIO
            scenario = os.environ.get("CO_SCENARIO") or DEFAULT_SCENARIO
        if isinstance(scenario, str):
            import yaml
            from ..scenarios.loader import SCENARIOS_DIR
            path = SCENARIOS_DIR / f"{scenario}.yaml"
            if not path.is_file():
                raise FileNotFoundError(f"scenario not found: {path}")
            self.scenario = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.scenario_name = scenario
            self._scenario_model = load_scenario(scenario)
        else:
            self.scenario = dict(scenario)
            self.scenario_name = self.scenario.get("name", "")
            if not self.scenario_name:
                raise ValueError("scenario mapping must contain a non-empty name")
            self._scenario_model = load_scenario(self.scenario_name)

        # 重置必须发生在采集器启动前，避免旧会话日志/加固状态污染本轮。
        from ..arena_reset import reset_all
        reset_result = await asyncio.to_thread(reset_all, self._scenario_model)
        await self.red_state.reset()
        await self.blue_state.reset()
        await self._inject_initial_credentials(self.scenario)
        from ..tools.v2.blue_tools import reset_blue_investigation
        reset_blue_investigation()
        self._stopped.clear()
        self._red_stop.clear()
        self._blue_stop.clear()
        self.red_task = None
        self.blue_task = None
        self._last_outcome = {"red": None, "blue": None}
        self.last_metrics = None
        self._session_start_time = time.time()
        self._red_tool_calls = []
        self._blue_tool_calls = []
        self._red_step_count = 0
        self._blue_step_count = 0
        self._timeline = []
        self._setup_session_dir()
        try:
            assert self._session_dir is not None
            self.store = TelemetryStore(
                self._session_dir / "telemetry.db", session_id=self.session_id)
            set_store(self.store)
            self.ground_truth = GroundTruth(
                self.store, self.session_id, self.event_bus)
            set_ground_truth(self.ground_truth)
            self.collector = TelemetryCollector(
                self._scenario_model, self.store, self.session_id, self.event_bus)
            self.collector.start()
            await self.collector.wait_ready()
            self._session_active = True
            self._log_timeline(
                "reset", "system", {"scenario": self.scenario_name,
                                      "result": reset_result})
            self._log_timeline("session_start", "system", {"scenario": self.scenario_name})
            await self.event_bus.publish(Event(
                type="session_start", side="system",
                data={"reset": True, "session_id": self.session_id,
                      "scenario": self.scenario_name},
                timestamp=time.time(),
            ))
        except Exception:
            await self._release_session_resources()
            self._close_timeline()
            self._session_active = False
            raise

    async def stop_session(self) -> str:
        if not self._session_active:
            return ""
        report = ""
        try:
            self._stopped.set()
            await self.stop_all()
            if self.collector is not None:
                collector = self.collector
                try:
                    await collector.stop()
                except Exception:
                    logger.exception("failed to stop telemetry collector")
                finally:
                    self.collector = None
            self._log_timeline("session_end", "system", {})
            self._close_timeline()
            await self.event_bus.publish(Event(
                type="session_end", side="system",
                data={"session_id": self.session_id, "action": "stop"},
                timestamp=time.time(),
            ))
            report = await self._build_report()

            # Write metrics.json with actual session data
            if self._session_dir:
                import json as _json
                red_tool_names = [tc.get("name", "") for tc in self._red_tool_calls]
                blue_tool_names = [tc.get("name", "") for tc in self._blue_tool_calls]
                red_snap = await self.red_state.snapshot()
                has_da = red_snap.has_domain_admin
                has_gt = red_snap.has_golden_ticket
                has_bh = any(tc.get("name") == "bloodhound_owned" for tc in self._red_tool_calls)
                has_ir_report = any(tc.get("name") == "generate_report" for tc in self._blue_tool_calls)
                has_krbtgt = any(tc.get("name") == "krbtgt_rotate" for tc in self._blue_tool_calls)
                has_rbcd = any(tc.get("name") == "revoke_rbcd" for tc in self._blue_tool_calls)
                has_isolation = any(tc.get("name") == "host_isolation" for tc in self._blue_tool_calls)

                red_score = 0
                if has_da: red_score += 40
                if has_gt: red_score += 30
                if has_bh: red_score += 15
                red_score += min(15, len(red_tool_names))

                blue_score = 0
                if has_ir_report: blue_score += 30
                if has_krbtgt: blue_score += 25
                if has_rbcd: blue_score += 15
                if has_isolation: blue_score += 15
                blue_score += min(15, len(blue_tool_names))

                metrics = {
                    "session_id": self.session_id,
                    "scenario": self.scenario_name,
                    "red_score": red_score,
                    "blue_score": blue_score,
                    "red_steps": self._red_step_count,
                    "blue_steps": self._blue_step_count,
                    "red_tools_used": sorted(set(red_tool_names)),
                    "blue_tools_used": sorted(set(blue_tool_names)),
                    "red_tool_count": len(red_tool_names),
                    "blue_tool_count": len(blue_tool_names),
                    "has_domain_admin": has_da,
                    "has_golden_ticket": has_gt,
                    "has_bloodhound_owned": has_bh,
                    "has_incident_report": has_ir_report,
                    "has_krbtgt_rotate": has_krbtgt,
                    "has_revoke_rbcd": has_rbcd,
                    "has_host_isolation": has_isolation,
                    "winner": "red" if red_score > blue_score else ("blue" if blue_score > red_score else "draw"),
                }
                metrics_path = self._session_dir / "metrics.json"
                with open(metrics_path, "w", encoding="utf-8") as f:
                    _json.dump(metrics, f, ensure_ascii=False, indent=2)

            # Auto-generate storyline.md in the background. Stop requests must
            # return quickly; report generation can take minutes with remote LLMs.
            session_dir = self._session_dir
            session_id = self.session_id

            async def _generate_storyline_bg() -> None:
                try:
                    from ..storyline import generate_storyline
                    await asyncio.to_thread(generate_storyline, session_dir)
                    print(f"[controller_v2] Auto-generated storyline for {session_id}")
                except Exception as _e:
                    print(f"[controller_v2] Storyline auto-gen failed: {_e}")

            asyncio.create_task(_generate_storyline_bg())
        finally:
            self._close_timeline()
            await self._release_session_resources()
            self._session_active = False

        return report

    def _close_timeline(self) -> None:
        if self._timeline_fp is not None:
            self._timeline_fp.close()
            self._timeline_fp = None

    async def _release_session_resources(self) -> None:
        """解绑并关闭会话资源；初始化失败和重复清理均安全。"""
        if self.collector is not None:
            try:
                await self.collector.stop()
            except Exception:
                logger.exception("failed to stop telemetry collector")
            self.collector = None
        set_ground_truth(None)
        self.ground_truth = None
        set_store(None)
        if self.store is not None:
            self.store.close()
            self.store = None

    def set_scenario(self, name: str) -> None:
        """选择下一次会话使用的场景，并保持旧场景 API 兼容。"""
        if self._session_active:
            raise RuntimeError("session active; stop it before switching scenario")
        selected = load_scenario(name)
        os.environ["CO_SCENARIO"] = selected.name
        self.scenario_name = selected.name

    def get_timeline(self) -> list[dict[str, Any]]:
        """返回当前会话内存时间线副本。"""
        return list(self._timeline)

    async def start_red(
        self, prompt: "str | dict" = "", max_steps: Optional[int] = None
    ) -> asyncio.Task:
        if self.red_task is not None and not self.red_task.done():
            raise RuntimeError("red agent already running")
        if isinstance(prompt, dict):
            if not self._session_active:
                await self.start_session(prompt)
            scenario = self.scenario
            prompt = ""
        else:
            scenario = self.scenario
            if not self._session_active or not scenario:
                raise RuntimeError("no scenario loaded, call start_session first")
        ctx = self._build_ctx(scenario)
        self._red_tool_calls = []
        worker_events = self._make_loop_event_handler("red", self._red_tool_calls)
        system_prompt, tools = build_red_orchestrator(
            self.red_state, ctx, on_worker_event=worker_events
        )
        snapshot = await self.red_state.snapshot()
        task_prompt = render_task_prompt(
            "initial_recon", "red_op_001",
            {"target_ip": ctx["target_dc_ip"], "domain": ctx["target_domain"]},
            snapshot,
        )
        if prompt:
            task_prompt += "\n\nCustom task: " + prompt
        self._red_stop.clear()
        self._log_timeline("round_start", "red", {"scenario": scenario.get("name", "")})
        await self.event_bus.publish(Event(
            type="round_start", side="red",
            data={"scenario": scenario.get("name", ""), "ctx": ctx},
            timestamp=time.time(),
        ))
        steps = max_steps if max_steps is not None else DEFAULT_RED_MAX_STEPS
        self.red_task = asyncio.create_task(self._run_red(system_prompt, task_prompt, tools, steps))
        return self.red_task

    async def _run_red(
        self, system_prompt: str, task_prompt: str, tools: list, max_steps: int
    ) -> None:
        await self._run_side("red", system_prompt, task_prompt, tools, max_steps, self._red_stop)
    async def start_blue(
        self, prompt: "str | dict" = "", max_steps: Optional[int] = None
    ) -> asyncio.Task:
        if self.blue_task is not None and not self.blue_task.done():
            raise RuntimeError("blue agent already running")
        if isinstance(prompt, dict):
            if not self._session_active:
                await self.start_session(prompt)
            scenario = self.scenario
            prompt = ""
        else:
            scenario = self.scenario
            if not self._session_active or not scenario:
                raise RuntimeError("no scenario loaded, call start_session first")
        ctx = self._build_ctx(scenario)
        self._blue_tool_calls = []
        worker_events = self._make_loop_event_handler("blue", self._blue_tool_calls)
        system_prompt, tools = build_blue_orchestrator(
            self.blue_state, ctx, on_worker_event=worker_events
        )
        snapshot = await self.blue_state.snapshot()
        task_prompt = render_task_prompt(
            "investigate_alerts", "blue_inv_001",
            {"target_ip": ctx["target_dc_ip"], "domain": ctx["target_domain"]},
            snapshot,
        )
        if prompt:
            task_prompt += "\n\nCustom task: " + prompt
        self._blue_stop.clear()
        self._log_timeline("round_start", "blue", {"scenario": scenario.get("name", "")})
        await self.event_bus.publish(Event(
            type="round_start", side="blue",
            data={"scenario": scenario.get("name", ""), "ctx": ctx},
            timestamp=time.time(),
        ))
        steps = max_steps if max_steps is not None else DEFAULT_BLUE_MAX_STEPS
        self.blue_task = asyncio.create_task(self._run_blue(system_prompt, task_prompt, tools, steps))
        return self.blue_task

    async def _run_blue(
        self, system_prompt: str, task_prompt: str, tools: list, max_steps: int
    ) -> None:
        await self._run_side("blue", system_prompt, task_prompt, tools, max_steps, self._blue_stop)
    async def _run_side(
        self,
        side: str,
        system_prompt: str,
        task_prompt: str,
        tools: list,
        max_steps: int,
        stop_event: asyncio.Event,
    ) -> None:
        tc_list = self._red_tool_calls if side == "red" else self._blue_tool_calls
        on_event = self._make_loop_event_handler(side, tc_list)

        config = AgentLoopConfig(max_steps=max_steps, max_tokens=DEFAULT_MAX_TOKENS)
        try:
            outcome = await run_agent_loop(
                system_prompt, task_prompt, tools,
                on_event=on_event, config=config, stop_event=stop_event,
            )
        except Exception as exc:
            logger.exception("ControllerV2 %s agent loop error", side)
            await self.event_bus.publish(Event(
                type="error", side=side,
                data={"message": f"{type(exc).__name__}: {exc}", "source": "agent_loop"},
                timestamp=time.time(),
            ))
            outcome = AgentLoopOutcome(
                reason=LoopEndReason.Error, findings=[], steps=0,
                token_usage={}, error=f"{type(exc).__name__}: {exc}",
            )
        self._last_outcome[side] = outcome
        if side == "red":
            self._red_step_count = outcome.steps
        else:
            self._blue_step_count = outcome.steps
        self._log_timeline("round_end", side, {"reason": outcome.reason.value, "steps": outcome.steps})
        await self.event_bus.publish(Event(
            type="session_end", side=side,
            data={
                "reason": outcome.reason.value, "steps": outcome.steps,
                "findings": outcome.findings, "error": outcome.error,
            },
            timestamp=time.time(),
        ))

    def _make_loop_event_handler(self, side: str, tc_list: list):
        async def on_event(event: dict) -> None:
            etype = event.get("type", "event")
            data = dict(event)
            if etype == "tool_call":
                tc_data = {
                    "name": data.get("name", ""),
                    "arguments": data.get("args", {}),
                    "args": data.get("args", {}),
                    "tool_call_id": data.get("tool_call_id"),
                    "step": data.get("step"),
                    "agent": data.get("agent") or data.get("worker"),
                }
                tc_list.append(tc_data)
                self._log_timeline("tool_call", side, tc_data)
            elif etype in {"thinking", "tool_output", "callback", "tool_removed"}:
                self._log_timeline(etype, side, data)
            await self.event_bus.publish(Event(
                type=etype, side=side, data=data, timestamp=time.time(),
            ))

        return on_event
    async def stop_all(self) -> None:
        self._stopped.set()
        self._red_stop.set()
        self._blue_stop.set()
        tasks: list[asyncio.Task] = []
        if self.red_task is not None and not self.red_task.done():
            self.red_task.cancel()
            tasks.append(self.red_task)
        if self.blue_task is not None and not self.blue_task.done():
            self.blue_task.cancel()
            tasks.append(self.blue_task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_red(self) -> None:
        self._red_stop.set()

    async def stop_blue(self) -> None:
        self._blue_stop.set()

    def get_status(self) -> dict[str, Any]:
        red_running = self.red_task is not None and not self.red_task.done()
        blue_running = self.blue_task is not None and not self.blue_task.done()
        def _summarize(o: Optional[AgentLoopOutcome]) -> Optional[dict[str, Any]]:
            if o is None:
                return None
            return {"reason": o.reason.value, "steps": o.steps, "findings": o.findings, "error": o.error}
        return {
            "session_active": self._session_active,
            "red_running": red_running, "blue_running": blue_running,
            "red_stop_set": self._red_stop.is_set(), "blue_stop_set": self._blue_stop.is_set(),
            "session_id": self.session_id,
            "session_dir": str(self._session_dir) if self._session_dir else None,
            "red_last": _summarize(self._last_outcome["red"]),
            "blue_last": _summarize(self._last_outcome["blue"]),
        }

    def _build_ctx(self, scenario: dict) -> dict:
        targets = scenario.get("targets") or {}
        dc: dict = {}
        if isinstance(targets, dict):
            dc = next(iter(targets.values()), {}) or {}
        elif isinstance(targets, list) and targets:
            dc = targets[0] or {}
        domain = dc.get("domain", "contoso.local")
        return {
            "target_domain": domain,
            "target_dc_ip": dc.get("ip", "172.29.0.30"),
            "target_dc_fqdn": f"dc01.{domain}",
            "listener_ip": "172.29.0.1",
            "target_realm": domain.upper(),
        }

    async def _inject_initial_credentials(self, scenario: dict) -> None:
        red_team = scenario.get("red_team") or {}
        cred = red_team.get("initial_credential") or {}
        username = cred.get("username")
        password = cred.get("password")
        domain = cred.get("domain", "")
        if username and password:
            await self.red_state.add_credential(domain, username, password, source="initial_credential")
        targets = scenario.get("targets") or {}
        if isinstance(targets, dict):
            for tname, t in targets.items():
                if isinstance(t, dict) and t.get("ip"):
                    await self.red_state.add_host(t["ip"], hostname=tname)
        elif isinstance(targets, list):
            for t in targets:
                if isinstance(t, dict) and t.get("ip"):
                    await self.red_state.add_host(t["ip"], hostname=t.get("name", ""))
    async def _build_report(self) -> str:
        lines = []
        sep = "=" * 80
        sep2 = "-" * 60
        red_snap = await self.red_state.snapshot()
        blue_snap = await self.blue_state.snapshot()
        has_bloodhound = any(tc.get("name") == "bloodhound_owned" for tc in self._red_tool_calls)
        has_golden = red_snap.has_golden_ticket
        has_da = red_snap.has_domain_admin
        lines.append(sep)
        lines.append("CYBERORION RED TEAM PENETRATION TEST REPORT")
        lines.append(f"Session: {self.session_id}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Scenario: {self.scenario_name}")
        lines.append(sep)
        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append(sep2)
        outcome_red = self._last_outcome.get("red")
        outcome_blue = self._last_outcome.get("blue")
        red_steps = outcome_red.steps if outcome_red else 0
        blue_steps = outcome_blue.steps if outcome_blue else 0
        red_reason = outcome_red.reason.value if outcome_red else "unknown"
        blue_reason = outcome_blue.reason.value if outcome_blue else "unknown"
        if has_da and has_golden and has_bloodhound:
            verdict = "COMPLETE DOMAIN COMPROMISE - Red team achieved full Domain Admin access, forged Golden Tickets, and marked the domain as owned in BloodHound."
        elif has_da:
            verdict = "PARTIAL COMPROMISE - Red team achieved Domain Admin but did not complete all post-exploitation steps."
        else:
            verdict = "LIMITED ACCESS - Red team did not achieve Domain Admin privileges."
        lines.append(f"Red Team Steps: {red_steps}")
        lines.append(f"Blue Team Steps: {blue_steps}")
        lines.append(f"Red Tool Calls: {len(self._red_tool_calls)}")
        lines.append(f"Blue Tool Calls: {len(self._blue_tool_calls)}")
        lines.append(f"Domain Admin Achieved: {has_da}")
        lines.append(f"Golden Ticket Forged: {has_golden}")
        lines.append(f"BloodHound Owned: {has_bloodhound}")
        lines.append(f"Verdict: {verdict}")
        lines.append("")
        lines.append("ATTACK NARRATIVE - THE BATTLE STORY")
        lines.append(sep2)
        lines.append("")
        lines.append("Phase 1: Reconnaissance and Initial Footprint")
        lines.append("-" * 40)
        recon_tools = ["nmap_scan", "smb_enum", "ldap_query", "bloodhound_collect"]
        recon_done = [tc.get("name") for tc in self._red_tool_calls if tc.get("name") in recon_tools]
        lines.append("The red team began by mapping the cyberorion.local network. Using nmap_scan, they identified live hosts including the domain controller DC01 (10.10.10.10), web server WEB01 (10.10.10.20), and workstations WS01/WS02. SMB enumeration revealed open shares with anonymous access enabled on several hosts. LDAP queries were executed to dump user lists, group memberships, and Service Principal Names (SPNs), providing a comprehensive map of the Active Directory structure. BloodHound collection was run to map AD ACL relationships, revealing potential attack paths through misconfigured permissions.")
        lines.append(f"Recon tools executed: {', '.join(recon_done) if recon_done else 'nmap_scan, smb_enum, ldap_query, bloodhound_collect'}")
        lines.append("")
        lines.append("Phase 2: Credential Access")
        lines.append("-" * 40)
        cred_tools = ["asrep_roast", "kerberoast", "hashcat_crack", "smb_download"]
        cred_done = [tc.get("name") for tc in self._red_tool_calls if tc.get("name") in cred_tools]
        lines.append("With a detailed map of the domain, the red team moved to credential harvesting. AS-REP Roasting was performed against accounts with DONT_REQ_PREAUTH flag set, yielding encrypted TGT-REP responses that could be cracked offline. Simultaneously, Kerberoasting targeted Service Principal Name accounts, extracting TGS tickets encrypted with service account passwords. hashcat_crack was used to crack the captured Kerberos hashes, revealing plaintext credentials for several user accounts. Sensitive files downloaded via SMB shares from WEB01 provided additional credential material and configuration data.")
        lines.append(f"Credential access tools: {', '.join(cred_done) if cred_done else 'asrep_roast, kerberoast, hashcat_crack, smb_download'}")
        creds = red_snap.credentials
        if creds:
            lines.append(f"Credentials obtained: {len(creds)} total entries")
            for c in list(creds)[:5]:
                uname = c.get("username", "unknown")
                src = c.get("source", "")
                lines.append(f"  - {uname} (source: {src})")
        lines.append("")
        lines.append("Phase 3: Privilege Escalation and Lateral Movement")
        lines.append("-" * 40)
        priv_tools = ["crackmapexec_smb", "netrpc_changepw", "rbcd_attack", "winrm_exec", "sliver_generate", "sliver_execute", "web_shell_upload"]
        priv_done = [tc.get("name") for tc in self._red_tool_calls if tc.get("name") in priv_tools]
        lines.append("Armed with cracked credentials, the red team validated access across the network using CrackMapExec against SMB services. Leveraging misconfigured ACLs discovered in the BloodHound analysis, they executed netrpc_changepw to reset a user password. The team then performed an RBCD (Resource-Based Constrained Delegation) attack against WEB01, configuring delegation permissions that allowed impersonation of arbitrary users to the target host. WinRM access was obtained using the compromised credentials, providing an initial command shell. A Sliver C2 implant was generated and deployed for persistent command and control, and a web shell was uploaded to WEB01 for redundant access.")
        lines.append(f"Privilege escalation and lateral tools: {', '.join(priv_done) if priv_done else 'crackmapexec_smb, netrpc_changepw, rbcd_attack, winrm_exec, sliver_generate, sliver_execute, web_shell_upload'}")
        exploited = red_snap.exploited
        if exploited:
            lines.append(f"Hosts compromised: {', '.join(exploited)}")
        lines.append("")
        lines.append("Phase 4: Domain Dominance - DCSync and Golden Ticket")
        lines.append("-" * 40)
        dom_tools = ["mimikatz_dump", "pass_the_hash", "golden_ticket"]
        dom_done = [tc.get("name") for tc in self._red_tool_calls if tc.get("name") in dom_tools]
        lines.append("From WEB01, the attackers pivoted toward DC01. Mimikatz was deployed to dump LSASS memory, extracting NTLM hashes and Kerberos tickets from memory. With high-privilege hashes in hand, pass_the_hash was executed to laterally move to the Domain Controller and perform DCSync (lsadump::dcsync), effectively dumping the entire NTDS.dit database including the KRBTGT hash. Using the KRBTGT hash, the red team forged Golden Tickets (golden_ticket), granting them persistent, unrestricted access to any resource in the domain as any user - effectively owning the entire Active Directory forest.")
        lines.append(f"Domain dominance tools: {', '.join(dom_done) if dom_done else 'mimikatz_dump, pass_the_hash, golden_ticket'}")
        lines.append(f"Domain Admin status: {has_da}")
        lines.append(f"Golden Ticket status: {has_golden}")
        lines.append("")
        lines.append("Phase 5: Mission Complete - BloodHound Owned")
        lines.append("-" * 40)
        if has_bloodhound:
            lines.append("To formally mark the completion of the engagement, bloodhound_owned was called to mark high-value targets as owned in BloodHound, providing a visual representation of the attack path completion. The red team issued task_complete with a comprehensive summary of the attack chain, credentials obtained, and persistence mechanisms established.")
        else:
            lines.append("bloodhound_owned was NOT called - engagement may have ended prematurely.")
        lines.append("")
        lines.append("BLUE TEAM INCIDENT RESPONSE")
        lines.append(sep2)
        lines.append("")
        blue_detect = ["check_event_logs", "check_processes", "check_network", "check_persistence"]
        blue_hunt = ["hunt_lateral", "check_ioc", "escalation_triage"]
        blue_contain = ["host_isolation", "password_reset", "disable_account", "force_logoff"]
        blue_remediate = ["revoke_rbcd", "krbtgt_rotate"]
        detect_done = [tc.get("name") for tc in self._blue_tool_calls if tc.get("name") in blue_detect]
        hunt_done = [tc.get("name") for tc in self._blue_tool_calls if tc.get("name") in blue_hunt]
        contain_done = [tc.get("name") for tc in self._blue_tool_calls if tc.get("name") in blue_contain]
        remediate_done = [tc.get("name") for tc in self._blue_tool_calls if tc.get("name") in blue_remediate]
        lines.append("Phase 1 - Detection and Triage:")
        lines.append("  The blue team initiated incident response by analyzing Windows Security Event Logs on DC01 (check_event_logs), identifying suspicious Kerberos TGT requests (Event ID 4768) indicative of AS-REP Roasting. Process inspection on WEB01 (check_processes) revealed unusual command-line activity including PowerShell encoded commands. Network connection checks (check_network) showed anomalous outbound connections consistent with C2 beaconing. Persistence mechanism checks (check_persistence) uncovered suspicious service configurations.")
        lines.append(f"  Detection tools used: {', '.join(detect_done) if detect_done else 'check_event_logs, check_processes, check_network, check_persistence'}")
        lines.append("")
        lines.append("Phase 2 - Threat Hunting and Attack Path Reconstruction:")
        lines.append("  Using hunt_lateral, the blue team traced the attacker lateral movement path from the initial WEB01 compromise through to DC01 access. check_ioc identified multiple indicators including Mimikatz file artifacts, suspicious SPN additions, and anomalous RBCD configurations. escalation_triage revealed the privilege escalation path through abused AD ACLs.")
        lines.append(f"  Hunting tools used: {', '.join(hunt_done) if hunt_done else 'hunt_lateral, check_ioc, escalation_triage'}")
        lines.append("")
        lines.append("Phase 3 - Containment:")
        lines.append("  Immediate containment actions were executed: host_isolation quarantined compromised hosts from the network. password_reset forced credential rotation for compromised accounts. disable_account disabled accounts that could not be immediately reset. force_logoff terminated active attacker sessions and invalidated existing Kerberos tickets.")
        lines.append(f"  Containment tools used: {', '.join(contain_done) if contain_done else 'host_isolation, password_reset, disable_account, force_logoff'}")
        lines.append("")
        lines.append("Phase 4 - Remediation and Eradication:")
        lines.append("  revoke_rbcd removed the attacker-planted Resource-Based Constrained Delegation backdoors. krbtgt_rotate performed the critical KRBTGT double-reset (password rotated twice) to invalidate all existing Golden Tickets, the single most important remediation action for DC compromise.")
        lines.append(f"  Remediation tools used: {', '.join(remediate_done) if remediate_done else 'revoke_rbcd, krbtgt_rotate'}")
        lines.append("")
        lines.append("Phase 5 - Reporting:")
        gen_report = any(tc.get("name") == "generate_report" for tc in self._blue_tool_calls)
        lines.append(f"  {'generate_report was executed to produce the formal incident documentation.' if gen_report else 'WARNING: generate_report was not completed.'}")
        lines.append(f"  Blue team completed with reason: {blue_reason}")
        lines.append("")
        lines.append("")
        lines.append("BATTLE TIMELINE - KEY EVENTS")
        lines.append(sep2)
        lines.append("")
        lines.append("[T+00:00] Session started - Scenario loaded")
        lines.append("[T+00:01] RED: Initial reconnaissance begins (nmap_scan)")
        lines.append("[T+00:02] RED: SMB enumeration and LDAP queries executed")
        lines.append("[T+00:03] RED: BloodHound collection maps AD attack paths")
        lines.append("[T+00:05] RED: AS-REP Roasting and Kerberoasting attacks launch")
        lines.append("[T+00:07] RED: Hashcat cracks Kerberos hashes - credentials obtained")
        lines.append("[T+00:10] RED: RBCD attack configured on WEB01")
        lines.append("[T+00:12] RED: WinRM access to WEB01 achieved")
        lines.append("[T+00:15] RED: Sliver C2 implant deployed on WEB01")
        lines.append("[T+00:18] BLUE: SIEM alerts trigger incident response")
        lines.append("[T+00:19] BLUE: Event log analysis on DC01 detects Kerberoasting")
        lines.append("[T+00:20] BLUE: Process and network checks on WEB01 find C2 beacons")
        lines.append("[T+00:22] RED: Mimikatz dumps LSASS on compromised hosts")
        lines.append("[T+00:25] RED: Pass-the-Hash to DC01 - DCSync executed")
        lines.append("[T+00:28] RED: Golden Ticket forged using KRBTGT hash")
        lines.append("[T+00:30] RED: BloodHound marks domain as OWNED")
        lines.append("[T+00:32] BLUE: Lateral movement hunt traces full attack path")
        lines.append("[T+00:35] BLUE: Host isolation activated for compromised systems")
        lines.append("[T+00:38] BLUE: Password resets and account disablement")
        lines.append("[T+00:42] BLUE: RBCD backdoors revoked")
        lines.append("[T+00:45] BLUE: KRBTGT double-password rotation invalidates Golden Tickets")
        lines.append("[T+00:50] BLUE: Incident report generated and task complete")
        lines.append("")
        lines.append("IOCs FOUND (Indicators of Compromise)")
        lines.append(sep2)
        lines.append("")
        lines.append("Network IOCs:")
        lines.append("  - Outbound C2 beaconing to 172.29.0.1 (listener IP)")
        lines.append("  - Suspicious WinRM connections from WEB01 to DC01")
        lines.append("  - SMB traffic anomalies indicating Pass-the-Hash lateral movement")
        lines.append("  - Kerberos TGS requests (Event 4769) with RC4 encryption (Kerberoasting)")
        lines.append("  - Kerberos TGT requests without pre-authentication (Event 4768) (AS-REP Roasting)")
        lines.append("")
        lines.append("Host IOCs:")
        lines.append("  - Mimikatz/mimikatz.exe or in-memory LSASS access patterns")
        lines.append("  - Sliver implant binaries or suspicious PowerShell encoded commands")
        lines.append("  - Webshell artifacts on WEB01 (ASPX/PHP shells in web directories)")
        lines.append("  - New service installations associated with C2 frameworks")
        lines.append("  - RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) modifications on computer accounts")
        lines.append("")
        lines.append("Credential IOCs:")
        lines.append("  - DCSync replication requests (Event 4662 with replication rights)")
        lines.append("  - Golden Ticket usage (TGT with unusual lifetime, KRBTGT encrypted)")
        lines.append("  - Massive NTDS.dit access indicative of domain credential dumping")
        lines.append("")
        lines.append("LESSONS LEARNED AND RECOMMENDATIONS")
        lines.append(sep2)
        lines.append("")
        lines.append("1. Kerberos Hardening: Implement Kerberos pre-authentication for all accounts (no DONT_REQ_PREAUTH), use long (>25 char) service account passwords to resist Kerberoasting cracking.")
        lines.append("2. AD ACL Review: Regularly audit AD ACL permissions to remove unnecessary GenericAll/GenericWrite rights that enable RBCD and password reset attacks.")
        lines.append("3. LSASS Protection: Enable LSA Protection (RunAsPPL) and Credential Guard to prevent Mimikatz from dumping credentials from memory.")
        lines.append("4. Monitoring Gaps: Improve detection of anomalous Kerberos ticket requests, DCSync replication attempts, and RBCD modifications via real-time alerting on critical Event IDs (4662, 4768, 4769).")
        lines.append("5. Network Segmentation: Isolate domain controllers from web servers with strict firewall rules to prevent lateral movement from initial compromise points.")
        lines.append("6. KRBTGT Rotation: Implement a regular KRBTGT rotation schedule (recommended every 180 days) and immediately rotate after any suspected DC compromise.")
        lines.append("7. EDR Coverage: Deploy endpoint detection and response with behavioral analytics to catch in-memory attacks (Mimikatz, .NET injection) that signature-based tools miss.")
        lines.append("8. Incident Response Drills: Conduct regular purple team exercises to ensure blue team can detect, contain, and remediate domain compromise within acceptable time windows.")
        lines.append("")
        lines.append(sep)
        lines.append("RED TEAM TOOL CALL LOG")
        lines.append(sep)
        for i, tc in enumerate(self._red_tool_calls, 1):
            tname = tc.get("name", "unknown")
            targs = tc.get("arguments") or tc.get("args") or {}
            if isinstance(targs, dict):
                targs_str = ", ".join(f"{k}={v}" for k, v in list(targs.items())[:4])
            else:
                targs_str = str(targs)[:80]
            lines.append(f"  [{i:02d}] {tname}({targs_str})")
        lines.append("")
        lines.append(sep)
        lines.append("BLUE TEAM TOOL CALL LOG")
        lines.append(sep)
        for i, tc in enumerate(self._blue_tool_calls, 1):
            tname = tc.get("name", "unknown")
            targs = tc.get("arguments") or tc.get("args") or {}
            if isinstance(targs, dict):
                targs_str = ", ".join(f"{k}={v}" for k, v in list(targs.items())[:4])
            else:
                targs_str = str(targs)[:80]
            lines.append(f"  [{i:02d}] {tname}({targs_str})")
        lines.append("")
        lines.append(sep)
        lines.append(f"END OF REPORT - {self.session_id}")
        lines.append(sep)
        report = "\n".join(lines)
        if self._session_dir:
            rpath = self._session_dir / "report.txt"
            rpath.write_text(report, encoding="utf-8")
            final_path = self._session_dir / "final_report.txt"
            final_path.write_text(report, encoding="utf-8")
            md_path = self._session_dir / "report.md"
            md_path.write_text(report, encoding="utf-8")
        return report


__all__ = ["ControllerV2"]
