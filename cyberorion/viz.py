"""Terminal visualisation for the CyberOrion arena.

Enhanced: shows full step-by-step trace (thinking + tool + output) in
the terminal and HTML transcript, not just tool names.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.markdown import Markdown

console = Console(record=True, highlight=False)

_STATUS_COLOURS = {
    "open": "bright_red",
    "investigating": "yellow",
    "mitigated": "cyan",
    "verified_fixed": "green",
    "failed": "bright_red",
}


def banner() -> None:
    art = (
        "[bold cyan]"
        "  ____           _                       ____            _    _           \n"
        " / ___|   _ __ _| |_ _ __ ___   ___ _ __ / ___|___   ___ | | _| | ___ _ __ \n"
        "| |  | | | |/ _` | __| '_ ` _ \\ / _ \\ '__| |   / _ \\ / _ \\| |/ / |/ _ \\ '__|\n"
        "| |__| |_| | (_| | |_| | | | | |  __/ |  | |__| (_) | (_) |   <| |  __/ |   \n"
        " \\____\\__,_|\\__,_|\\__|_| |_| |_|\\___|_|   \\____\\___/ \\___/|_|\\_\\_|\\___|_|   \n"
        "[/bold cyan]"
    )
    console.print(art)
    console.print(
        "[bold]Red-vs-Blue autonomous arena[/bold]  -  "
        "[red]RED: CAI red-team agent[/red]  -  "
        "[blue]BLUE: CyberOrion super-agent[/blue]"
    )
    console.print(Rule(style="dim"))


def round_header(round_num: int, total_rounds: int) -> None:
    console.print()
    console.print(
        Rule(
            f"[bold white on blue] ROUND {round_num} / {total_rounds} [/bold white on blue]",
            style="blue",
        )
    )


def red_action(text: str, tool_calls: Iterable[dict] | None = None,
               trace_items: list | None = None) -> None:
    body = Text(text or "(no output)", style="red")
    console.print(Panel(body, title="[red]RED TEAM[/red]", border_style="red"))
    _print_trace(trace_items, colour="red", side="RED")
    _print_tool_calls(tool_calls, colour="red", side="RED")


def blue_action(text: str, tool_calls: Iterable[dict] | None = None,
                trace_items: list | None = None) -> None:
    body = Text(text or "(no output)", style="cyan")
    console.print(Panel(body, title="[blue]CYBERORION[/blue]", border_style="blue"))
    _print_trace(trace_items, colour="blue", side="BLUE")
    _print_tool_calls(tool_calls, colour="blue", side="BLUE")


def _print_trace(trace_items, colour, side):
    """Print step-by-step trace: thinking → tool → output."""
    if not trace_items:
        return
    console.print()
    step = 0
    for item in trace_items:
        itype = item.get("type", "")
        if itype == "thinking":
            step += 1
            text = item.get("text", "")
            if len(text) > 300:
                text = text[:300] + "..."
            console.print(
                Panel(
                    Text(text, style=f"italic {colour}"),
                    title=f"[{colour}]Step {step} — Thinking[/{colour}]",
                    border_style="dim",
                    padding=(0, 1),
                )
            )
        elif itype == "tool_call":
            tool = item.get("tool", "?")
            args = item.get("arguments", "{}")
            # Extract command if present
            cmd = args
            try:
                import json
                parsed = json.loads(args)
                cmd = parsed.get("command", parsed.get("cmd", json.dumps(parsed, ensure_ascii=False)))
            except Exception:
                pass
            if len(cmd) > 200:
                cmd = cmd[:200] + "..."
            console.print(
                f"  [{colour}]├─ TOOL:[/{colour}] [bold]{tool}[/bold]"
                f"\n  [{colour}]│  CMD:[/{colour}] [dim]{cmd}[/dim]"
            )
        elif itype == "tool_output":
            out = item.get("output", "")
            if len(out) > 500:
                out = out[:500] + f"... (+{len(out)} more chars)"
            console.print(
                f"  [{colour}]│  OUT:[/{colour}] [dim]{out}[/dim]"
            )
    console.print()


def _print_tool_calls(tool_calls, colour, side):
    if not tool_calls:
        return
    table = Table(
        title=f"[{colour}]{side} tool call summary[/{colour}]",
        show_lines=False,
        border_style="dim",
        title_style=f"bold {colour}",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Tool", style=f"bold {colour}", width=24)
    table.add_column("Status", width=10)
    table.add_column("ms", justify="right", width=8)
    for i, tc in enumerate(tool_calls, 1):
        status = tc.get("status", "?")
        status_style = "green" if status == "ok" else "bright_red" if status == "error" else "yellow"
        dur = tc.get("duration_ms")
        dur_str = f"{dur:.0f}" if isinstance(dur, (int, float)) else "-"
        table.add_row(
            str(i),
            tc.get("tool", "?"),
            Text(status, style=status_style),
            dur_str,
        )
    console.print(table)


def vuln_table(ledger: dict) -> None:
    if not ledger:
        console.print("[dim]  (vulnerability ledger is empty)[/dim]")
        return
    table = Table(
        title="[bold]Vulnerability Ledger[/bold]",
        show_lines=False,
        border_style="cyan",
    )
    table.add_column("Vuln ID", style="bold", width=22)
    table.add_column("Status", width=18)
    table.add_column("Evidence", width=60)
    for vid, entry in ledger.items():
        status = entry.get("status", "?")
        colour = _STATUS_COLOURS.get(status, "white")
        evidence = (entry.get("evidence") or "")[:60]
        table.add_row(vid, Text(status, style=colour), evidence)
    console.print(table)


def info(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")


def phase(label: str, msg: str = "") -> None:
    console.print(f"[bold magenta]\\[{label}[/bold magenta] {msg}")


def error(msg: str) -> None:
    console.print(Panel(msg, title="[bright_red]ERROR[/bright_red]", border_style="bright_red"))


def save_transcript(dir_path: str) -> tuple:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = f"{dir_path}/transcript_{ts}.html"
    text_path = f"{dir_path}/transcript_{ts}.txt"
    console.save_html(html_path)
    console.save_text(text_path)
    return html_path, text_path
