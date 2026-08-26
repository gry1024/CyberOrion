// TrafficView — 流量分析视图（50/50 双栏，单按钮同时回放+分析）
// -------------------------------------------------------------
// 左 50%：流量回放（事件流 + 告警列表，replay_data 事件填充）
// 右 50%：多 agent 研判链（ChatStream 流式渲染思考/工具/报告）
// 单「开始分析」按钮 → SSE 同时驱动左右两栏。
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { useDemoReplay } from '../demoReplay'
import { pushToast } from '../toasts'
import { ChatStream } from './ChatStream'
import type { FlowAlert, FlowEvent, ThoughtStep, TrafficStatus } from '../types'

// severity -> 颜色
function sevColor(sev: string): string {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'var(--color-red)'
  if (s === 'high') return 'var(--color-amber)'
  if (s === 'medium') return 'var(--color-cyan)'
  return 'var(--color-fg-3)'
}

function fmtTs(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number, l = 2) => String(n).padStart(l, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
}

let _idCounter = 0
function nextId(): string {
  _idCounter += 1
  return `tv${_idCounter}`
}

const MAX_STEPS = 200

function capped(prev: ThoughtStep[], step: ThoughtStep): ThoughtStep[] {
  const next = [...prev, step]
  return next.length > MAX_STEPS ? next.slice(next.length - MAX_STEPS) : next
}

export function TrafficView() {
  const demo = useDemoReplay('traffic_analysis')
  const [status, setStatus] = useState<TrafficStatus | null>(null)
  const [source, setSource] = useState<string>('synthetic')
  const [csvFile, setCsvFile] = useState<string>('')
  const [maxRows, setMaxRows] = useState<number>(500)

  // 左栏：回放数据
  const [events, setEvents] = useState<FlowEvent[]>([])
  const [eventsTotal, setEventsTotal] = useState<number>(0)
  const [alerts, setAlerts] = useState<FlowAlert[]>([])
  const [selectedEvent, setSelectedEvent] = useState<FlowEvent | null>(null)

  // 右栏：agent 研判链
  const [steps, setSteps] = useState<ThoughtStep[]>([])
  const [running, setRunning] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const openThinking = useRef<Record<string, string>>({})
  const lastTool = useRef<Record<string, { tool: string; args: string }>>({})
  const scrollRef = useRef<HTMLDivElement>(null)

  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.trafficStatus()
      setStatus(s)
      if (s.sources?.length && !s.sources.includes(source)) setSource(s.sources[0])
      if (s.csv_files?.length && !csvFile) setCsvFile(s.csv_files[0])
    } catch {
      /* keep last */
    }
  }, [source, csvFile])

  useEffect(() => {
    void refreshStatus()
  }, [refreshStatus])

  // ---- SSE 事件 → ThoughtStep 转换（与 arena.tsx 逻辑一致） ----
  const handleSSEEvent = useCallback(
    (ev: { type: string; side: string; data: Record<string, unknown>; timestamp: number }) => {
      const ts = ev.timestamp || Date.now() / 1000
      const d = ev.data || {}
      const agent = typeof d.agent === 'string' ? d.agent : undefined

      switch (ev.type) {
        case 'replay_data': {
          // 左栏填充：事件流 + 告警列表
          setEvents((d.events as FlowEvent[]) ?? [])
          setEventsTotal(Number(d.events_total ?? (d.events as unknown[] | undefined)?.length ?? 0))
          setAlerts((d.alerts as FlowAlert[]) ?? [])
          break
        }
        case 'system': {
          const text = String(d.text ?? d.message ?? '')
          if (!text) break
          setSteps((p) => capped(p, { id: nextId(), kind: 'system', text, timestamp: ts }))
          break
        }
        case 'error': {
          const text = String(d.message ?? '未知错误')
          pushToast(text, { side: 'system', title: '流量分析错误' })
          setSteps((p) => capped(p, { id: nextId(), kind: 'system', text: `⚠ ${text}`, timestamp: ts }))
          break
        }
        case 'thinking': {
          const text = String(d.text ?? '')
          if (!text) break
          const agentKey = agent ?? 'rule_engine'
          const isOpen = d.delta ? openThinking.current[agentKey] : undefined
          const step: ThoughtStep = {
            id: nextId(),
            kind: 'thinking',
            text,
            agent,
            timestamp: ts,
          }
          if (!isOpen) openThinking.current[agentKey] = step.id
          setSteps((prev) => {
            if (isOpen) {
              let found = false
              const next = prev.map((s) => {
                if (s.id !== isOpen) return s
                found = true
                return { ...s, text: (s.text ?? '') + text, timestamp: ts }
              })
              if (found) return next
            }
            return capped(prev, step)
          })
          break
        }
        case 'tool_call': {
          const tool = String(d.tool ?? d.name ?? d.function ?? '')
          const argsValue = d.args ?? d.arguments ?? ''
          const args = typeof argsValue === 'string' ? argsValue : JSON.stringify(argsValue)
          lastTool.current[agent ?? 'rule_engine'] = { tool, args }
          delete openThinking.current[agent ?? 'rule_engine']
          setSteps((p) =>
            capped(p, { id: nextId(), kind: 'tool_call', tool, args, agent, timestamp: ts }),
          )
          break
        }
        case 'tool_output': {
          const output = String(d.output ?? d.result ?? '')
          const tk = agent ?? 'rule_engine'
          const { tool: previousTool } = lastTool.current[tk] ?? { tool: '' }
          const tool = previousTool || String(d.tool ?? d.name ?? d.function ?? '')
          delete openThinking.current[tk]
          setSteps((p) =>
            capped(p, { id: nextId(), kind: 'tool_output', tool, output, agent, timestamp: ts }),
          )
          break
        }
        case 'report': {
          const report = String(d.report ?? '')
          delete openThinking.current[agent ?? 'report_writer']
          setSteps((p) =>
            capped(p, {
              id: nextId(),
              kind: 'report',
              agent,
              role: agent,
              mission: '',
              report,
              timestamp: ts,
            }),
          )
          break
        }
        case 'complete': {
          const text = String(d.message ?? '流量分析完成')
          openThinking.current = {}
          lastTool.current = {}
          setRunning(false)
          abortRef.current = null
          setSteps((p) => capped(p, { id: nextId(), kind: 'system', text, timestamp: ts }))
          void refreshStatus()
          break
        }
        default:
          break
      }
    },
    [refreshStatus],
  )

  const handleStart = useCallback(() => {
    if (running) {
      abortRef.current?.abort()
      abortRef.current = null
      setRunning(false)
      return
    }
    setRunning(true)
    demo.clear()
    setSteps([])
    setEvents([])
    setEventsTotal(0)
    setAlerts([])
    setSelectedEvent(null)
    openThinking.current = {}
    lastTool.current = {}

    const ctrl = api.trafficAnalyzeStream(
      { source, csv_file: csvFile || undefined, max_rows: maxRows },
      handleSSEEvent,
      (e: Error) => {
        pushToast(`分析异常：${e.message}`, { side: 'system' })
        setRunning(false)
        abortRef.current = null
      },
      () => {
        setRunning(false)
        abortRef.current = null
      },
    )
    abortRef.current = ctrl
  }, [running, demo, source, csvFile, maxRows, handleSSEEvent])

  // 清理
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
    }
  }, [])

  // 告警统计
  const sevStats = useMemo(() => {
    const m: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const a of alerts) {
      const s = (a.severity || 'low').toLowerCase()
      m[s] = (m[s] ?? 0) + 1
    }
    return m
  }, [alerts])

  const ready = status?.ready ?? true
  const playDemo = () => void demo.play().catch((error) => {
    pushToast(`演示启动失败：${error instanceof Error ? error.message : String(error)}`, { title: '流量分析' })
  })
  const shownSteps = demo.steps.length || demo.playing ? demo.steps : steps

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* 标题行 */}
      <div
        className="flex flex-none items-center gap-2 border-b px-3 py-1.5"
        style={{ borderColor: 'var(--color-hairline)' }}
      >
        <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
          流量分析
        </span>
        <span className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
          流量回放 + 四阶段 Agent 研判
        </span>
        <span className="ml-auto font-mono text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
          {source}{source === 'cicids' && csvFile ? `:${csvFile}` : ''} · {eventsTotal} 事件 / {alerts.length} 告警
        </span>
      </div>

      {/* 双栏：左 50% 流量回放；右 50% agent 研判 */}
      <div className="flex min-h-0 flex-1">
        {/* ===== 左栏：流量回放 ===== */}
        <div className="flex min-w-0 flex-col" style={{ flex: '0 0 50%', minHeight: 0 }}>
          {/* 控制条 */}
          <div
            className="flex flex-none flex-wrap items-center gap-2 border-b px-3 py-2"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="btn"
              style={{ height: 22, padding: '0 6px', fontSize: 11 }}
              title="数据源"
            >
              {(status?.sources ?? ['synthetic', 'cicids']).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            {source === 'cicids' && (
              <select
                value={csvFile}
                onChange={(e) => setCsvFile(e.target.value)}
                className="btn"
                style={{ height: 22, padding: '0 6px', fontSize: 11, maxWidth: 180 }}
                title="CSV 文件"
              >
                {(status?.csv_files ?? []).map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            )}
            <label className="flex items-center gap-1 text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
              行数
              <input
                type="number"
                value={maxRows}
                min={50}
                max={10000}
                onChange={(e) => setMaxRows(Number(e.target.value) || 500)}
                className="btn"
                style={{ height: 22, width: 60, padding: '0 4px', fontSize: 11 }}
              />
            </label>
          </div>

          {/* 告警统计条 */}
          <div
            className="flex flex-none items-center gap-3 border-b px-3 py-1"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <span className="text-[11px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
              告警
            </span>
            {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
              <span key={s} className="flex items-center gap-1 text-[10.5px]">
                <span style={{ color: sevColor(s) }}>●</span>
                <span style={{ color: 'var(--color-fg-3)' }}>{s}</span>
                <span className="font-mono" style={{ color: 'var(--color-fg)' }}>
                  {sevStats[s]}
                </span>
              </span>
            ))}
          </div>

          {/* 告警列表（上半） */}
          <div className="scroll-thin min-h-0 overflow-y-auto" style={{ flex: '1 1 40%' }}>
            {alerts.length === 0 ? (
              <div className="px-3 py-4 text-center text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
                {running ? '等待规则引擎检测…' : '点击「回放并分析」后此处显示告警'}
              </div>
            ) : (
              alerts.map((al, i) => (
                <div
                  key={i}
                  className="border-b px-3 py-1"
                  style={{ borderColor: 'var(--color-hairline)' }}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
                      {fmtTs(al.ts)}
                    </span>
                    <span
                      className="rounded px-1 py-0 text-[9.5px] font-semibold uppercase"
                      style={{
                        color: sevColor(al.severity),
                        background: `color-mix(in srgb, ${sevColor(al.severity)} 14%, transparent)`,
                      }}
                    >
                      {al.severity}
                    </span>
                    <span className="text-[10.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
                      {al.alert_type}
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-purple)' }}>
                      {al.technique}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 font-mono text-[10px]">
                    <span style={{ color: 'var(--color-cyan)' }}>{al.src_ip}</span>
                    <span style={{ color: 'var(--color-fg-4)' }}>→</span>
                    <span style={{ color: 'var(--color-amber)' }}>{al.dst_ip}</span>
                    <span className="ml-auto" style={{ color: 'var(--color-fg-3)' }}>
                      {(al.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  {al.description && (
                    <div className="mt-0.5 text-[10.5px]" style={{ color: 'var(--color-fg-2)' }}>
                      {al.description}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {/* 事件流标题 */}
          <div
            className="flex flex-none items-center gap-2 border-t border-b px-3 py-1"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <span className="text-[11px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
              事件流
            </span>
            <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
              {events.length}/{eventsTotal}
            </span>
          </div>

          {/* 事件列表（下半） */}
          <div ref={scrollRef} className="scroll-thin min-h-0 flex-1 overflow-y-auto">
            {events.length === 0 ? (
              <div className="px-3 py-4 text-center text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
                {running ? '加载流量数据中…' : '点击「回放并分析」后此处显示事件流'}
              </div>
            ) : (
              events.map((ev, i) => {
                const selected = selectedEvent === ev
                return (
                  <button
                    key={i}
                    onClick={() => setSelectedEvent(selected ? null : ev)}
                    className="flex w-full items-center gap-2 border-b px-3 py-0.5 text-left"
                    style={{
                      borderColor: 'var(--color-hairline)',
                      background: selected ? 'var(--color-overlay)' : 'transparent',
                    }}
                  >
                    <span className="font-mono text-[9.5px]" style={{ color: 'var(--color-fg-4)' }}>
                      {fmtTs(ev.ts)}
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-cyan)' }}>
                      {ev.src_ip}
                    </span>
                    <span className="text-[9.5px]" style={{ color: 'var(--color-fg-4)' }}>
                      →
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-amber)' }}>
                      {ev.dst_ip}:{ev.dst_port}
                    </span>
                    <span
                      className="ml-auto truncate text-[10px]"
                      style={{
                        color: ev.label === 'BENIGN' ? 'var(--color-fg-3)' : 'var(--color-red)',
                      }}
                    >
                      {ev.label}
                    </span>
                  </button>
                )
              })
            )}
          </div>

          {/* 选中事件详情 */}
          {selectedEvent && (
            <div
              className="flex-none border-t px-3 py-1.5"
              style={{ borderColor: 'var(--color-hairline)', background: 'var(--color-bg-2)' }}
            >
              <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 font-mono text-[10px]">
                <span style={{ color: 'var(--color-fg-4)' }}>src</span>
                <span style={{ color: 'var(--color-cyan)' }}>{selectedEvent.src_ip}</span>
                <span style={{ color: 'var(--color-fg-4)' }}>dst</span>
                <span style={{ color: 'var(--color-amber)' }}>
                  {selectedEvent.dst_ip}:{selectedEvent.dst_port}
                </span>
                <span style={{ color: 'var(--color-fg-4)' }}>label</span>
                <span style={{ color: 'var(--color-fg)' }}>{selectedEvent.label}</span>
                <span style={{ color: 'var(--color-fg-4)' }}>technique</span>
                <span style={{ color: 'var(--color-purple)' }}>{selectedEvent.technique}</span>
              </div>
            </div>
          )}
        </div>

        {/* 1px 分隔线 */}
        <div className="w-px flex-none" style={{ background: 'var(--color-hairline)' }} />

        {/* ===== 右栏：agent 研判链（ChatStream） ===== */}
        <div className="flex min-w-0 flex-1 flex-col" style={{ minHeight: 0 }}>
          {/* 控制条：单按钮 */}
          <div
            className="flex flex-none items-center gap-2 border-b px-3 py-2"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <span className="text-[11px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
              agent 研判链
            </span>
            {running && (
              <span className="live-pulse text-[10px]" style={{ color: 'var(--color-cyan)' }}>
                ● 分析中
              </span>
            )}
            <button
              className="btn btn-primary ml-auto"
              onClick={handleStart}
              disabled={(!ready && !running) || demo.playing}
              style={{ height: 24, fontSize: 11.5 }}
            >
              {running ? '■ 停止分析' : '▶ 回放并分析'}
            </button>
            <button
              className="btn"
              onClick={playDemo}
              disabled={running || demo.playing}
              style={{ height: 24, fontSize: 11.5 }}
              title={demo.sessionId || '回放真实历史分析日志'}
            >
              {demo.playing ? '演示中' : '演示'}
            </button>
          </div>

          {/* ChatStream 流式渲染 */}
          <ChatStream
            side="blue"
            steps={shownSteps}
            running={running || demo.playing}
            accent="blue"
            emptyTitle="多 agent 流量研判"
            emptyDesc="点击「回放并分析」启动：流量回放 → 规则检测 → 语义分析 → 攻击链重建 → 报告生成"
            autoExpandReports
          />
        </div>
      </div>
    </div>
  )
}
