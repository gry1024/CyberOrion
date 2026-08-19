import { useEffect, useMemo, useRef, useState } from "react"
import type { Side, ThoughtStep, ThoughtStepKind } from "../types"

const COLORS: Record<ThoughtStepKind, string> = {
  thinking: "var(--terminal-text)",
  tool_call: "var(--terminal-tool)",
  tool_output: "var(--terminal-success)",
  rag_retrieval: "var(--terminal-rag)",
  rag_no_match: "var(--terminal-muted)",
  rag_unavailable: "var(--terminal-error)",
  subagent_dispatch: "var(--terminal-agent)",
  subagent_result: "var(--terminal-agent-result)",
  sop_phase: "var(--terminal-phase)",
  report: "var(--terminal-success)",
  error: "var(--terminal-error)",
  system: "var(--terminal-muted)",
}

const LABELS: Record<ThoughtStepKind, string> = {
  thinking: "thinking",
  tool_call: "tool",
  tool_output: "result",
  rag_retrieval: "kb",
  rag_no_match: "kb",
  rag_unavailable: "kb",
  subagent_dispatch: "dispatch",
  subagent_result: "agent",
  sop_phase: "phase",
  report: "report",
  error: "error",
  system: "system",
}

const ICONS: Record<ThoughtStepKind, string> = {
  thinking: "✻",
  tool_call: "⏺",
  tool_output: "⎿",
  rag_retrieval: "⏺",
  rag_no_match: "⎿",
  rag_unavailable: "✖",
  subagent_dispatch: "↳",
  subagent_result: "✓",
  sop_phase: "◆",
  report: "◆",
  error: "✖",
  system: "•",
}

function fmtTs(ts: number): string {
  if (!Number.isFinite(ts)) return "--:--:--"
  return new Date(ts * 1000).toLocaleTimeString("zh-CN", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

function safeJson(value: unknown): string {
  if (value == null || value === "") return ""
  if (typeof value === "string") return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function agentName(step: ThoughtStep, side: Side): string {
  return step.agent || step.role || step.worker_name || (side === "red" ? "red-orchestrator" : side === "blue" ? "blue-orchestrator" : "system")
}

function summaryOf(step: ThoughtStep): string {
  switch (step.kind) {
    case "tool_call":
      return `${step.tool || "工具事件"}${step.label_zh && step.label_zh !== step.tool ? ` (${step.label_zh})` : ""}`
    case "tool_output":
      return `${step.tool || "工具事件"}${step.summary_zh ? ` -> ${step.summary_zh}` : " completed"}`
    case "subagent_dispatch":
      return `${step.worker_name || step.agent || "unknown-agent"} <- ${step.task_zh || step.mission || "task dispatched"}`
    case "subagent_result":
      return `${step.worker_name || step.agent || "unknown-agent"} -> ${step.findings_zh || step.summary_zh || "result returned"}`
    case "rag_retrieval":
      return `${step.query || "knowledge query"} -> ${step.hit_count ?? step.doc_ids?.length ?? 0} hits`
    case "rag_no_match":
      return step.query ? `no match: ${step.query}` : "no relevant knowledge found"
    case "rag_unavailable":
      return step.error || step.message || "knowledge base unavailable"
    case "sop_phase":
      return `${step.phase_id ?? "?"}/${step.phase_total ?? "?"} ${step.phase_name_zh || step.phase_name || "phase"}`
    case "report":
      return "final analysis report generated"
    case "error":
      return step.message || step.error || "unknown error"
    default:
      return step.text || step.summary_zh || ""
  }
}

function detailOf(step: ThoughtStep): string {
  if (step.kind === "tool_call") return safeJson(step.args)
  if (step.kind === "tool_output") return step.output || ""
  if (step.kind === "report") return step.report || ""
  if (step.kind === "rag_retrieval") {
    const docs = step.docs?.map((doc) => `${doc.id}: ${doc.name_zh || doc.name || ""}`) ?? step.doc_titles_zh ?? step.doc_ids
    return safeJson(docs)
  }
  return ""
}

function TerminalLine({
  step,
  side,
  autoExpandReports,
}: {
  step: ThoughtStep
  side: Side
  autoExpandReports: boolean
}) {
  const [open, setOpen] = useState(step.kind === "report" && autoExpandReports)
  const summary = summaryOf(step)
  const detail = detailOf(step)
  const color = COLORS[step.kind]

  return (
    <div className="terminal-line" data-kind={step.kind}>
      <button
        type="button"
        className="terminal-line-main"
        onClick={() => detail && setOpen((value) => !value)}
        aria-expanded={detail ? open : undefined}
      >
        <span className="terminal-prompt" style={{ color }}>{ICONS[step.kind]}</span>
        <span className="terminal-content">
          <span className="terminal-meta">
            <span className="terminal-agent">{agentName(step, side)}</span>
            <span className="terminal-kind" style={{ color }}>{LABELS[step.kind]}</span>
            <span className="terminal-time">{fmtTs(step.timestamp)}</span>
          </span>
          <span className="terminal-summary" style={{ color }}>{summary || "..."}</span>
        </span>
        {detail && <span className="terminal-expand">{open ? "[-]" : "[+]"}</span>}
      </button>
      {open && detail && <pre className="terminal-detail">{detail}</pre>}
    </div>
  )
}

function normalizeKind(step: ThoughtStep): ThoughtStepKind {
  if (step.kind) return step.kind
  const legacy = step.type as ThoughtStepKind | undefined
  return legacy && legacy in LABELS ? legacy : "thinking"
}

export function ChatStream({
  steps,
  side,
  running = false,
  emptyTitle = "等待任务",
  emptyDesc = "启动后将在此显示 Agent、工具与证据事件。",
  autoExpandReports = true,
}: {
  steps: ThoughtStep[]
  side: Side
  running?: boolean
  accent?: string
  emptyTitle?: string
  emptyDesc?: string
  autoExpandReports?: boolean
}) {
  const outputRef = useRef<HTMLDivElement>(null)
  const normalized = useMemo(
    () => steps.map((step) => ({ ...step, kind: normalizeKind(step) })),
    [steps],
  )
  const tail = normalized[normalized.length - 1]
  const tailSignature = tail ? `${tail.id}:${tail.text?.length ?? tail.output?.length ?? tail.report?.length ?? 0}` : ''
  useEffect(() => {
    const el = outputRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [normalized.length, tailSignature, running])

  return (
    <div className="terminal-shell" role="log" aria-live="polite">
      <div className="terminal-titlebar">
        <span>CYBERORION://{side.toUpperCase()}</span>
        <span className={running ? "terminal-live is-running" : "terminal-live"}>
          {running ? "LIVE" : "IDLE"}
        </span>
      </div>
      <div className="terminal-output scroll-thin" ref={outputRef}>
        {normalized.length === 0 ? (
          <div className="terminal-empty">
            <div>{emptyTitle}</div>
            <span>{emptyDesc}</span>
          </div>
        ) : (
          normalized.map((step) => (
            <TerminalLine
              key={step.id}
              step={step}
              side={side}
              autoExpandReports={autoExpandReports}
            />
          ))
        )}
        {running && <div className="terminal-cursor" aria-hidden="true">_</div>}
      </div>
    </div>
  )
}
