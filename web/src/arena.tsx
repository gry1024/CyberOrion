// Arena data layer: single WebSocket client (exp-backoff reconnect) + REST
// polling fallback, fanned out into one React context. No redux.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import type { ReactNode } from 'react'
import { api } from './api'
import { pushToast } from './toasts'
import { teamKey } from './types'
import type {
  AlertRow,
  ArenaEvent,
  BenchLiveRun,
  BenchMode,
  BenchSuite,
  ControllerStatus,
  HostState,
  HostStatus,
  ScenarioInfo,
  Side,
  TeamState,
  ThoughtStep,
  TimelineItem,
} from './types'

const MAX_STEPS_PER_SIDE = 300
const MAX_TIMELINE = 400

const RESPONSE_TOOLS = new Set(['block_ip', 'unblock_ip', 'harden_service'])
const FAILURE_PREFIXES = ['非法', '无法', '加固失败', '回滚失败', '未知 service']

interface ArenaState {
  connected: boolean
  status: ControllerStatus
  scenario: ScenarioInfo | null
  redSteps: ThoughtStep[]
  blueSteps: ThoughtStep[]
  team: TeamState
  timeline: TimelineItem[]
  alerts: AlertRow[]
  hosts: Record<string, HostStatus>
  benchLive: Record<string, BenchLiveRun>
  /** Bumped whenever a bench run completes/fails — triggers a runs refetch. */
  benchStamp: number
  refreshStatus: () => Promise<void>
  refreshAlerts: () => Promise<void>
  refreshScenario: () => Promise<void>
  clearSteps: (side: Side) => void
}

function emptyStatus(): ControllerStatus {
  return {
    red_running: false,
    blue_running: false,
    red_paused: false,
    blue_paused: false,
    session_active: false,
    session_starting: false,
    session_boot_error: '',
    pending_agent_starts: [],
    scenario: '',
    round: 0,
    ledger: {},
    red_history_count: 0,
    blue_history_count: 0,
  }
}

let counter = 0
function nextId(prefix: string): string {
  counter += 1
  return `${prefix}${counter}`
}

function capped<T>(list: T[], item: T, cap: number): T[] {
  const next = list.concat(item)
  return next.length > cap ? next.slice(next.length - cap) : next
}

/** Pull suite/mode/n out of a bench run_id like
 * `20260727_172628_attack_kb_rag_n100` (pre-suite ids lack the suite part). */
function parseBenchRunId(runId: string): {
  mode: BenchMode
  suite: BenchSuite
  n: number
} {
  const m =
    /_(malware_analysis|attack_kb|threat_intel)_(rag_fs|rag_g|sc_base|base|rag|sc)_n(\d+)/.exec(
      runId,
    ) ?? /_(rag_fs|rag_g|sc_base|base|rag|sc)_n(\d+)/.exec(runId)
  if (!m) return { mode: 'base', suite: 'malware_analysis', n: 0 }
  if (m.length === 4) {
    return { suite: m[1] as BenchSuite, mode: m[2] as BenchMode, n: Number(m[3]) }
  }
  return { suite: 'malware_analysis', mode: m[1] as BenchMode, n: Number(m[2]) }
}

/** Match a telemetry host / attack target string to a scenario target name. */
function matchTarget(
  key: string,
  scenario: ScenarioInfo | null,
): string | null {
  if (!key || !scenario) return null
  const k = key.toLowerCase()
  for (const t of scenario.targets) {
    if (
      k === t.name.toLowerCase() ||
      k === t.container.toLowerCase() ||
      k === t.ip ||
      k.includes(t.name.toLowerCase()) ||
      t.name.toLowerCase().includes(k)
    ) {
      return t.name
    }
  }
  return null
}

/** Try to pull a host/container value out of a tool-call args JSON string. */
function hostFromArgs(args: string | undefined): string {
  if (!args) return ''
  try {
    const obj = JSON.parse(args) as Record<string, unknown>
    for (const k of ['container', 'host', 'target']) {
      const v = obj[k]
      if (typeof v === 'string' && v) return v
    }
  } catch {
    /* not JSON */
  }
  return ''
}

const ArenaCtx = createContext<ArenaState | null>(null)

export function ArenaProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState<ControllerStatus>(emptyStatus())
  const [scenario, setScenario] = useState<ScenarioInfo | null>(null)
  const [redSteps, setRedSteps] = useState<ThoughtStep[]>([])
  const [blueSteps, setBlueSteps] = useState<ThoughtStep[]>([])
  const [team, setTeam] = useState<TeamState>({ active: {}, done: [], dispatched: {} })
  const [timeline, setTimeline] = useState<TimelineItem[]>([])
  const [alerts, setAlerts] = useState<AlertRow[]>([])
  const [hosts, setHosts] = useState<Record<string, HostStatus>>({})
  const [benchLive, setBenchLive] = useState<Record<string, BenchLiveRun>>({})
  const [benchStamp, setBenchStamp] = useState(0)

  // Latest tool_call per side, so a following tool_output can be attributed.
  const lastTool = useRef<Record<Side, { tool: string; args: string }>>({
    red: { tool: '', args: '' },
    blue: { tool: '', args: '' },
    system: { tool: '', args: '' },
  })
  // Open thinking-bubble step id per (side, agent). Parallel sub-agent
  // streams interleave, so "append to the last step" is wrong — each agent's
  // deltas accumulate into its own open bubble wherever it sits in the list.
  const openThinking = useRef<Record<Side, Record<string, string>>>({
    red: {},
    blue: {},
    system: {},
  })
  // Bumped on every session reset; in-flight alert fetches from before the
  // reset are discarded so stale alerts can't repopulate a fresh session.
  const alertsEpoch = useRef(0)
  const scenarioRef = useRef<ScenarioInfo | null>(null)
  scenarioRef.current = scenario

  const pushTimeline = useCallback((item: Omit<TimelineItem, 'id'>) => {
    setTimeline((prev) =>
      [{ ...item, id: nextId('t') }, ...prev].slice(0, MAX_TIMELINE),
    )
  }, [])

  const setHost = useCallback(
    (key: string, state: HostState, ts: number, note?: string) => {
      const name = matchTarget(key, scenarioRef.current)
      if (!name) return
      setHosts((prev) => {
        const cur = prev[name]
        // Keep the most recent significant state per host.
        if (cur && cur.ts > ts) return prev
        return { ...prev, [name]: { state, ts, note } }
      })
    },
    [],
  )

  const refreshStatus = useCallback(async () => {
    try {
      const st = await api.getStatus()
      setStatus(st)
      // REST request success means backend is online. WS may fail to connect
      // due to proxy/network, but as long as REST returns status we should
      // NOT show "backend offline".
      setConnected(true)
      // 后端已无活动会话（可能错过了 session_end WS 事件）：清掉残留的
      // 红蓝流与团队状态，避免终端显示上一会话的子代理输出。
      if (!st.session_active) {
        setRedSteps([])
        setBlueSteps([])
        setTeam({ active: {}, done: [], dispatched: {} })
      }
    } catch {
      // REST request failed means backend is offline.
      setConnected(false)
    }
  }, [])

  const refreshAlerts = useCallback(async () => {
    const epoch = alertsEpoch.current
    try {
      const rows = await api.getAlerts()
      // Stale response (a session reset happened while fetching) — drop it.
      if (epoch !== alertsEpoch.current) return
      setAlerts(rows)
    } catch {
      /* keep last */
    }
  }, [])

  const refreshScenario = useCallback(async () => {
    try {
      setScenario(await api.getScenario())
    } catch {
      /* backend not ready */
    }
  }, [])

  const clearSteps = useCallback((side: Side) => {
    if (side === 'red') setRedSteps([])
    else if (side === 'blue') setBlueSteps([])
  }, [])

  // ------------------------------------------------------------------ //
  // WebSocket event fan-out
  // ------------------------------------------------------------------ //
  const handleEvent = useCallback(
    (ev: ArenaEvent) => {
      const ts = ev.timestamp || Date.now() / 1000
      const d = ev.data || {}
      // Blue super-agent attribution; missing = orchestrator (legacy too).
      const agent = typeof d.agent === 'string' ? d.agent : undefined

      switch (ev.type) {
        case 'snapshot': {
          setStatus((prev) => ({ ...prev, ...(d as Partial<ControllerStatus>) }))
          // 连接时若后端没有活动会话，清空残留的红/蓝流与团队状态——
          // 避免打开页面看到上一会话（或已停止的会话）的子代理输出。
          if (!d.session_active) {
            setRedSteps([])
            setBlueSteps([])
            setTeam({ active: {}, done: [], dispatched: {} })
          }
          break
        }
        case 'error': {
          // 后端 agent_run / session_reset / telemetry_init 等失败 — 全局 toast。
          const message = String(d.message ?? '未知错误')
          pushToast(message, {
            side: ev.side,
            title:
              ev.side === 'red'
                ? '红方错误'
                : ev.side === 'blue'
                  ? '蓝方错误'
                  : '系统错误',
          })
          pushTimeline({
            kind: 'system',
            ts,
            title: `✗ ${ev.side} 错误`,
            detail: message.slice(0, 300),
            severity: 'critical',
            raw: d,
          })
          break
        }
        case 'thinking': {
          const text = String(d.text ?? '')
          const agentKey = agent ?? 'orchestrator'
          // Streaming delta chunk: append to this agent's open thinking
          // bubble (tracked per agent — parallel streams interleave), so a
          // streamed message renders as one growing bubble per agent.
          const openId = d.delta
            ? openThinking.current[ev.side][agentKey]
            : undefined
          const step: ThoughtStep = {
            id: nextId('s'),
            kind: 'thinking',
            text,
            agent,
            timestamp: ts,
          }
          if (!openId) openThinking.current[ev.side][agentKey] = step.id
          const pushStep = (prev: ThoughtStep[]): ThoughtStep[] => {
            if (openId) {
              let found = false
              const next = prev.map((s) => {
                if (s.id !== openId) return s
                found = true
                return { ...s, text: (s.text ?? '') + text, timestamp: ts }
              })
              if (found) return next
            }
            return capped(prev, step, MAX_STEPS_PER_SIDE)
          }
          if (ev.side === 'red') setRedSteps(pushStep)
          else if (ev.side === 'blue') setBlueSteps(pushStep)
          break
        }
        case 'tool_call': {
          const tool = String(d.tool ?? d.name ?? d.function ?? '')
          const argsValue = d.args ?? d.arguments ?? ''
          const args = typeof argsValue === 'string' ? argsValue : JSON.stringify(argsValue)
          lastTool.current[ev.side] = { tool, args }
          // Thinking resumes after a tool call — the next delta opens a fresh
          // bubble below the tool rows instead of growing the pre-call one.
          delete openThinking.current[ev.side][agent ?? 'orchestrator']
          const step: ThoughtStep = {
            id: nextId('s'),
            kind: 'tool_call',
            tool,
            args,
            agent,
            timestamp: ts,
          }
          if (ev.side === 'red') setRedSteps((p) => capped(p, step, MAX_STEPS_PER_SIDE))
          else if (ev.side === 'blue') {
            setBlueSteps((p) => capped(p, step, MAX_STEPS_PER_SIDE))
            // Dispatch linkage: orchestrator dispatch_task(role=X) activates
            // the orchestrator→X edge in the agent-chain panel.
            if (tool === 'dispatch_task' && (agent ?? 'orchestrator') === 'orchestrator') {
              try {
                const role = String(
                  (JSON.parse(args) as Record<string, unknown>).role ?? '',
                )
                if (role) {
                  setTeam((prev) => ({
                    ...prev,
                    dispatched: { ...prev.dispatched, [role]: ts },
                  }))
                }
              } catch {
                /* args not JSON */
              }
            }
          }
          break
        }
        case 'tool_output': {
          const output = String(d.output ?? d.result ?? '')
          const { tool: previousTool, args } = lastTool.current[ev.side]
          const tool = previousTool || String(d.tool ?? d.name ?? d.function ?? '')
          delete openThinking.current[ev.side][agent ?? 'orchestrator']
          const step: ThoughtStep = {
            id: nextId('s'),
            kind: 'tool_output',
            tool,
            output,
            agent,
            timestamp: ts,
          }
          if (ev.side === 'red') setRedSteps((p) => capped(p, step, MAX_STEPS_PER_SIDE))
          else if (ev.side === 'blue') setBlueSteps((p) => capped(p, step, MAX_STEPS_PER_SIDE))

          // Blue-side defensive actions double as timeline 处置 / 告警 items.
          if (ev.side === 'blue' && RESPONSE_TOOLS.has(tool)) {
            const failed = FAILURE_PREFIXES.some((p) => output.startsWith(p))
            if (!failed) {
              const host = hostFromArgs(args)
              pushTimeline({
                kind: 'response',
                ts,
                title: `${tool} 处置完成`,
                detail: output.slice(0, 300),
                host,
                raw: d,
              })
              if (tool === 'harden_service' || tool === 'block_ip') {
                setHost(host, 'hardened', ts, tool)
              }
            }
          }
          if (ev.side === 'blue' && tool === 'report_finding') {
            pushTimeline({
              kind: 'alert',
              ts,
              title: '蓝方上报发现 (report_finding)',
              detail: output.slice(0, 300),
              raw: d,
            })
            void refreshAlerts()
          }
          break
        }
        case 'attack': {
          // Ground-truth records carry a target; round summaries don't.
          if (typeof d.target === 'string' && d.target) {
            const success = Boolean(d.success)
            pushTimeline({
              kind: 'attack',
              ts,
              title: `${d.target} · ${String(d.technique ?? '') || '未知技术'}`,
              detail: `${String(d.action ?? '')} ${success ? '✓ 成功' : '✗ 失败'}`,
              severity: success ? 'critical' : 'medium',
              success,
              host: String(d.target),
              raw: d,
            })
            if (success) setHost(String(d.target), 'compromised', ts, String(d.technique ?? ''))
            // 红方聊天流：每次攻击作为一条系统消息（Kimi 式对局可读性）。
            const atk: ThoughtStep = {
              id: nextId('s'),
              kind: 'system',
              text: `${success ? '⚔' : '✗'} ${String(d.action ?? '')} @ ${String(d.target)}` +
                `${String(d.technique ?? '') ? ' · ' + String(d.technique) : ''}` +
                `${success ? ' ✓ 成功' : ' ✗ 失败'}`,
              timestamp: ts,
            }
            setRedSteps((p) => capped(p, atk, MAX_STEPS_PER_SIDE))
          } else {
            pushTimeline({
              kind: 'system',
              ts,
              title: '红方回合结束',
              detail: String(d.output ?? '').slice(0, 200),
              raw: d,
            })
          }
          break
        }
        case 'telemetry': {
          const sev = String(d.severity ?? 'info')
          const host = String(d.host ?? '')
          pushTimeline({
            kind: 'telemetry',
            ts,
            title: `${host} · ${String(d.source ?? '')}`,
            detail: String(d.summary ?? '').slice(0, 300),
            severity: sev,
            host,
            raw: d,
          })
          setHost(host, 'alert', ts, sev)
          // 蓝方聊天流：遥测事件作为系统消息。
          const tel: ThoughtStep = {
            id: nextId('s'),
            kind: 'system',
            text: `📡 ${host} · ${String(d.source ?? '')}：${String(d.summary ?? '').slice(0, 120)}`,
            timestamp: ts,
          }
          setBlueSteps((p) => capped(p, tel, MAX_STEPS_PER_SIDE))
          break
        }
        case 'detection': {
          pushTimeline({
            kind: 'system',
            ts,
            title: '蓝方研判回合结束',
            detail: String(d.output ?? '').slice(0, 200),
            raw: d,
          })
          break
        }
        case 'scenario': {
          // Scenario was switched server-side; re-pull topology + status.
          void refreshScenario()
          void refreshStatus()
          break
        }
        case 'bench': {
          // CyberSOCEval harness progress/completion (side = system).
          const runId = String(d.run_id ?? '')
          if (!runId) break
          const status = String(d.status ?? 'running')
          const prog = d.progress as { done?: number; total?: number } | undefined
          const llmErrors = Number(d.llm_errors ?? 0)
          setBenchLive((prev) => {
            const cur = prev[runId]
            const parsed = parseBenchRunId(runId)
            const next: BenchLiveRun = {
              run_id: runId,
              mode: cur?.mode ?? parsed.mode,
              suite: cur?.suite ?? parsed.suite,
              n: cur?.n ?? parsed.n,
              status,
              progress: {
                done: Number(prog?.done ?? cur?.progress.done ?? 0),
                total: Number(prog?.total ?? cur?.progress.total ?? parsed.n),
              },
              error: typeof d.error === 'string' ? d.error : undefined,
              llm_errors: llmErrors,
            }
            if (status === 'running') return { ...prev, [runId]: next }
            // Finished runs live in /api/bench/runs — drop from the live map.
            const rest = { ...prev }
            delete rest[runId]
            return rest
          })
          if (status !== 'running') {
            // LLM 故障不再静默：全部失败（error）或部分失败都在右上角提示。
            if (status === 'error') {
              pushToast(
                `Benchmark 运行失败：${String(d.error ?? '未知错误').slice(0, 200)}`,
                { side: 'system', title: 'Benchmark' },
              )
            } else if (llmErrors > 0) {
              pushToast(
                `Benchmark 完成，但 ${llmErrors} 题模型调用失败` +
                  (typeof d.error === 'string' ? `：${d.error.slice(0, 160)}` : ''),
                { side: 'system', title: 'Benchmark' },
              )
            }
            setBenchStamp(Date.now())
          }
          break
        }
        case 'team': {
          // Blue super-agent team: orchestrator dispatched a sub-agent
          // (spawn) or the sub-agent reported back (done). Parallel
          // dispatches carry data.seq — instances are keyed by role#seq.
          if (ev.side !== 'blue') break
          const role = String(d.role ?? '')
          if (!role) break
          const seq = typeof d.seq === 'number' ? d.seq : undefined
          const key = teamKey(role, seq)
          const mission = String(d.mission ?? '')
          const seqTag = seq != null ? ` #${seq}` : ''
          if (d.event === 'spawn') {
            setTeam((prev) => {
              // Spawn consumed the pending dispatch_task linkage for this role.
              const dispatched = { ...prev.dispatched }
              delete dispatched[role]
              return {
                active: { ...prev.active, [key]: { role, seq, mission, since: ts } },
                done: prev.done,
                dispatched,
              }
            })
            pushTimeline({
              kind: 'team',
              ts,
              title: `▸ 派遣 ${role}${seqTag}`,
              detail: mission.slice(0, 300),
              raw: d,
            })
          } else if (d.event === 'done') {
            const report = String(d.report ?? '')
            const error =
              typeof d.error === 'string' && d.error ? d.error : undefined
            setTeam((prev) => {
              const active = { ...prev.active }
              let info = active[key]
              if (info) {
                delete active[key]
              } else {
                // seq mismatch fallback: close any open instance of this role.
                const alt = Object.keys(active).find((k) => active[k].role === role)
                if (alt) {
                  info = active[alt]
                  delete active[alt]
                }
              }
              return {
                active,
                dispatched: prev.dispatched,
                done: capped(
                  prev.done,
                  {
                    id: nextId('r'),
                    role,
                    seq,
                    mission,
                    report,
                    error,
                    since: info?.since,
                    ts,
                  },
                  50,
                ),
              }
            })
            // Collapsible report card inside the blue stream.
            const card: ThoughtStep = {
              id: nextId('s'),
              kind: 'report',
              agent: role,
              role,
              mission,
              report: error ? `✗ ${error}\n\n${report}`.trim() : report,
              timestamp: ts,
            }
            delete openThinking.current.blue[role]
            setBlueSteps((p) => capped(p, card, MAX_STEPS_PER_SIDE))
            pushTimeline({
              kind: 'team',
              ts,
              title: error ? `✗ ${role}${seqTag} 超时/错误` : `✓ ${role}${seqTag} 完成`,
              detail: (error ?? report).slice(0, 300),
              severity: error ? 'critical' : undefined,
              raw: d,
            })
          }
          break
        }
        case 'reset': {
          // Target reset at session start (side = system).
          pushTimeline({
            kind: 'system',
            ts,
            title: '⟲ 靶标环境已重置',
            detail: '所有目标容器已恢复到初始快照',
            raw: d,
          })
          break
        }
        case 'session_start': {
          pushTimeline({
            kind: 'system',
            ts,
            title: '会话开始',
            detail: String(d.session_id ?? ''),
            raw: d,
          })
          // reset:true（后端会话重建标记）→ 清空全部视图状态，不留上一会话残留。
          // session_end 不清：结束后保留上一会话结果可见，只在新会话开始时擦除。
          if (d.reset) {
            setRedSteps([])
            setBlueSteps([])
            setAlerts([])
            // pushTimeline 把「会话开始」插到最前 — 只保留它，丢弃旧会话条目。
            setTimeline((prev) => prev.slice(0, 1))
            setHosts({})
            setTeam({ active: {}, done: [], dispatched: {} })
            openThinking.current = { red: {}, blue: {}, system: {} }
            // Invalidate any in-flight alerts fetch from the previous session.
            alertsEpoch.current += 1
          }
          void refreshStatus()
          void refreshAlerts()
          break
        }
        case 'session_end': {
          pushTimeline({
            kind: 'system',
            ts,
            title: '会话结束',
            detail: String(d.session_id ?? ''),
            raw: d,
          })
          // 会话结束：清空红蓝流与团队状态，终端回到空态——
          // 不做“保留上一会话结果可见”，避免打开页面看到旧对局输出。
          setRedSteps([])
          setBlueSteps([])
          setTeam({ active: {}, done: [], dispatched: {} })
          void refreshStatus()
          void refreshAlerts()
          break
        }
        case 'round_start':
        case 'round_end': {
          if (ev.side === 'system' && d.action) {
            pushTimeline({
              kind: 'system',
              ts,
              title: `${String(d.target ?? '')} ${String(d.action)}`,
              raw: d,
            })
          }
          void refreshStatus()
          break
        }
        default:
          break
      }
    },
    [pushTimeline, setHost, refreshStatus, refreshAlerts, refreshScenario],
  )

  // ------------------------------------------------------------------ //
  // WebSocket lifecycle with exponential-backoff reconnect
  // ------------------------------------------------------------------ //
  useEffect(() => {
    let closed = false
    let ws: WebSocket | null = null
    let attempts = 0
    let timer: number | null = null

    const connect = () => {
      if (closed) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      try {
        // BASE_URL is "./" for sub-path deployment. Resolving against the
        // current document keeps both /ws and /cyberorion/ws correct and
        // avoids malformed hosts such as "example.com.".
        const wsUrl = new URL('ws', window.location.href)
        wsUrl.protocol = `${proto}:`
        ws = new WebSocket(wsUrl)
      } catch {
        schedule()
        return
      }
      ws.onopen = () => {
        attempts = 0
        setConnected(true)
        void refreshStatus()
        void refreshAlerts()
        void refreshScenario()
      }
      ws.onmessage = (msg) => {
        try {
          handleEvent(JSON.parse(msg.data) as ArenaEvent)
        } catch {
          /* malformed frame */
        }
      }
      ws.onclose = () => {
        // WS drop alone does not mean backend is down; let the 4s REST poll
        // decide the online/offline state.
        schedule()
      }
      ws.onerror = () => {
        try {
          ws?.close()
        } catch {
          /* ignore */
        }
      }
    }

    const schedule = () => {
      if (closed) return
      attempts += 1
      const delay = Math.min(1000 * 2 ** attempts, 15000)
      timer = window.setTimeout(connect, delay)
    }

    connect()
    return () => {
      closed = true
      if (timer !== null) window.clearTimeout(timer)
      try {
        ws?.close()
      } catch {
        /* ignore */
      }
    }
  }, [handleEvent, refreshStatus, refreshAlerts, refreshScenario])

  // Polling fallback: status 4s, alerts 5s.
  useEffect(() => {
    const t1 = window.setInterval(() => void refreshStatus(), 4000)
    const t2 = window.setInterval(() => void refreshAlerts(), 5000)
    void refreshScenario()
    return () => {
      window.clearInterval(t1)
      window.clearInterval(t2)
    }
  }, [refreshStatus, refreshAlerts, refreshScenario])

  const value = useMemo<ArenaState>(
    () => ({
      connected,
      status,
      scenario,
      redSteps,
      blueSteps,
      team,
      timeline,
      alerts,
      hosts,
      benchLive,
      benchStamp,
      refreshStatus,
      refreshAlerts,
      refreshScenario,
      clearSteps,
    }),
    [
      connected, status, scenario, redSteps, blueSteps, team, timeline,
      alerts, hosts, benchLive, benchStamp, refreshStatus,
      refreshAlerts, refreshScenario, clearSteps,
    ],
  )

  return <ArenaCtx.Provider value={value}>{children}</ArenaCtx.Provider>
}

export function useArena(): ArenaState {
  const ctx = useContext(ArenaCtx)
  if (!ctx) throw new Error('useArena must be used inside <ArenaProvider>')
  return ctx
}
