import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { api } from "./api"
import type { Side, ThoughtStep, ThoughtStepKind } from "./types"

interface DemoEvent {
  kind: string
  type?: string
  side: string
  data: Record<string, unknown>
  timestamp: number
}

interface ReplayStep {
  side: Side
  step: ThoughtStep
}

const KINDS = new Set<ThoughtStepKind>([
  "thinking", "tool_call", "tool_output", "rag_retrieval",
  "rag_no_match", "rag_unavailable", "subagent_dispatch",
  "subagent_result", "sop_phase", "report", "error", "system",
])

function text(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined
}

export function eventToThoughtStep(event: DemoEvent, index = 0): ReplayStep {
  const data = event.data || {}
  const rawKind = event.kind || event.type || "system"
  const kind = KINDS.has(rawKind as ThoughtStepKind) ? rawKind as ThoughtStepKind : "system"
  const timestamp = Number.isFinite(event.timestamp) ? event.timestamp : Date.now() / 1000
  const side: Side = event.side === "red" || event.side === "blue" ? event.side : "system"
  const args = data.arguments ?? data.args

  return {
    side,
    step: {
      id: `demo-${timestamp}-${index}`,
      kind,
      timestamp,
      text: text(data.text) || text(data.content) || text(data.message),
      tool: text(data.name) || text(data.tool),
      label_zh: text(data.label_zh),
      summary_zh: text(data.summary_zh) || text(data.summary),
      args: typeof args === "string" || (args && typeof args === "object") ? args as string | Record<string, unknown> : undefined,
      output: text(data.output),
      agent: text(data.agent) || text(data.role) || text(data.worker_name),
      role: text(data.role),
      mission: text(data.mission),
      report: text(data.report),
      query: text(data.query),
      hit_count: typeof data.hit_count === "number" ? data.hit_count : undefined,
      worker_name: text(data.worker_name),
      task_zh: text(data.task_zh) || text(data.task),
      findings_zh: text(data.findings_zh) || text(data.findings),
      phase_id: typeof data.phase_id === "number" ? data.phase_id : undefined,
      phase_total: typeof data.phase_total === "number" ? data.phase_total : undefined,
      phase_name: text(data.phase_name),
      phase_name_zh: text(data.phase_name_zh),
      error: text(data.error),
      message: text(data.message),
    },
  }
}

export function useDemoReplay(taskType: string) {
  const [items, setItems] = useState<ReplayStep[]>([])
  const [playing, setPlaying] = useState(false)
  const [sessionId, setSessionId] = useState("")
  const timer = useRef<number | null>(null)

  const stop = useCallback(() => {
    if (timer.current !== null) window.clearInterval(timer.current)
    timer.current = null
    setPlaying(false)
  }, [])

  const clear = useCallback(() => {
    stop()
    setItems([])
    setSessionId("")
  }, [stop])

  useEffect(() => stop, [stop])

  const play = useCallback(async () => {
    stop()
    const data = await api.getDemo(taskType)
    if (!data.ok || !data.events.length) throw new Error("没有可用的高质量演示日志")
    const queue = data.events.map(eventToThoughtStep)
    setItems([])
    setSessionId(data.session_id)
    setPlaying(true)
    let cursor = 0
    timer.current = window.setInterval(() => {
      const batch = queue.slice(cursor, cursor + 2)
      cursor += batch.length
      if (batch.length) setItems((current) => [...current, ...batch])
      if (cursor >= queue.length) stop()
    }, 90)
  }, [stop, taskType])

  const redSteps = useMemo(() => items.filter((item) => item.side === "red").map((item) => item.step), [items])
  const blueSteps = useMemo(() => items.filter((item) => item.side !== "red").map((item) => item.step), [items])
  const steps = useMemo(() => items.map((item) => item.step), [items])

  return { play, stop, clear, playing, sessionId, redSteps, blueSteps, steps }
}
