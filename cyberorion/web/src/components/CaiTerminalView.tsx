import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { api } from '../api'
import { pushToast } from '../toasts'
import type { CaiCtfItem, CaiRecording, CaiTaskEnvironment, CaiTopTask } from '../types'

interface RunConfig {
  ctf?: CaiCtfItem
  challenge?: string
  prompt?: string
  taskType?: 'general' | 'ctf' | 'code_repair' | 'attack_chain'
  topTask?: CaiTopTask
}

type AgentFrameStatus = 'running' | 'done' | 'failed'
type AgentFrameLineKind = 'thinking' | 'tool' | 'output' | 'result' | 'error'

interface AgentFrameLine {
  id: string
  kind: AgentFrameLineKind
  text: string
}

interface AgentFrame {
  id: string
  agent: string
  title: string
  status: AgentFrameStatus
  lines: AgentFrameLine[]
}

const DEFAULT_CTF_PROMPT = 'Solve this CAI CTF challenge. Work step by step, validate the flag, and stop when the flag is confirmed.'
const AGENT_EVENT_PREFIX = '[[CYBERORION_AGENT_EVENT]]'
const TASK_TABS: Array<{ id: CaiTopTask; label: string }> = [
  { id: 'chat', label: 'Chat with CyberOrion' },
  { id: 'ctf', label: 'CTF' },
  { id: 'attack_chain', label: '复原攻击链条' },
  { id: 'code_repair', label: '修复代码漏洞' },
]
const TASK_PROMPTS: Record<NonNullable<RunConfig['taskType']>, string> = {
  general: '你是 CyberOrion。请先说明你的任务计划、可调用的 Agent、需要的证据，然后按用户输入继续。',
  ctf: DEFAULT_CTF_PROMPT,
  code_repair: '修复代码漏洞。工作区包含 src/vulnerable_app.py 和 tests/test_vulnerable_app.py。先复现 SQL 注入，再调度 CodeAgent 修复，最后运行 pytest 并输出 diff、测试结果和风险说明。',
  attack_chain: '复原攻击链条。工作区包含 evidence/timeline.jsonl、web_access.log 和 auth.log。先调用 Knowledge Agent 获取背景，再调度 Network Security Analyzer、DFIR、Replay Attack Agent 分析证据，最后输出时间线、ATT&CK 映射、事实/推断/未验证项。',
}
const REPLAY_STORAGE_KEY = 'cyberorion:cai-replay-id'
const DEMO_REPLAY_IDS: Record<CaiTopTask, string> = {
  chat: 'demo_cyberorion_chat',
  ctf: 'demo_picoctf_static_flag',
  attack_chain: 'demo_attack_chain_reconstruction',
  code_repair: 'demo_code_repair_sql_injection',
}

function wsUrl(): string {
  const url = new URL('ws/cai', new URL(import.meta.env.BASE_URL, window.location.href))
  url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.toString()
}

function difficultyRank(value: string): number {
  const v = value.toLowerCase()
  if (v.includes('very easy')) return 0
  if (v.includes('easy')) return 1
  if (v.includes('medium')) return 2
  if (v.includes('hard')) return 3
  return 4
}

function eventReplayId(event: Event): string {
  if (event instanceof CustomEvent && typeof event.detail === 'string') return event.detail
  return ''
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function textField(payload: Record<string, unknown>, key: string): string {
  const value = payload[key]
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

function shortText(value: string, limit = 3800): string {
  if (value.length <= limit) return value
  return `${value.slice(0, limit).trimEnd()}\n...（已截断）`
}

function lineForAgentEvent(payload: Record<string, unknown>): { kind: AgentFrameLineKind; text: string } | null {
  const type = textField(payload, 'type')
  if (type === 'agent_tool_call') {
    const tool = textField(payload, 'tool') || 'tool'
    const args = textField(payload, 'args')
    return { kind: 'tool', text: args ? `$ ${tool} ${args}` : `$ ${tool}` }
  }
  if (type === 'agent_tool_output') return { kind: 'output', text: shortText(textField(payload, 'output') || textField(payload, 'text')) }
  if (type === 'agent_output') return { kind: textField(payload, 'kind') === 'reasoning' ? 'thinking' : 'output', text: shortText(textField(payload, 'text') || textField(payload, 'output')) }
  if (type === 'agent_done') return { kind: 'result', text: shortText(textField(payload, 'result') || '子 Agent 已返回结果。') }
  if (type === 'agent_error') return { kind: 'error', text: shortText(textField(payload, 'error') || '子 Agent 执行失败。') }
  return null
}

function tryParseAgentEvent(text: string): Record<string, unknown> | null {
  const trimmed = text.trim()
  if (!trimmed.startsWith(AGENT_EVENT_PREFIX)) return null
  try {
    const parsed = JSON.parse(trimmed.slice(AGENT_EVENT_PREFIX.length))
    return isRecord(parsed) ? parsed : null
  } catch {
    return null
  }
}

function taskTypeFor(topTask: CaiTopTask): NonNullable<RunConfig['taskType']> {
  if (topTask === 'ctf') return 'ctf'
  if (topTask === 'attack_chain') return 'attack_chain'
  if (topTask === 'code_repair') return 'code_repair'
  return 'general'
}

function defaultDescription(topTask: CaiTopTask): string {
  if (topTask === 'ctf') return '调用 CAI 内置 CTF 目录，在授权靶场中完成挑战并验证结果。'
  if (topTask === 'attack_chain') return '读取离线日志与流量证据，调度多个 CAI Agent 复原攻击链条。'
  if (topTask === 'code_repair') return '在隔离代码工作区复现并修复漏洞，保留 diff 和测试输出。'
  return '开放式安全问答与任务规划；普通聊天不触发最终 PDF 报告。'
}

export function CaiTerminalView({ active = true }: { active?: boolean }) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const replayTimersRef = useRef<number[]>([])
  const frameCloseTimersRef = useRef<Map<string, number>>(new Map())
  const agentFrameBodyRefs = useRef<Map<string, HTMLDivElement>>(new Map())
  const agentFramesRef = useRef<HTMLDivElement | null>(null)
  const replayingRef = useRef(false)
  const [ctfs, setCtfs] = useState<CaiCtfItem[]>([])
  const [taskEnvironments, setTaskEnvironments] = useState<CaiTaskEnvironment[]>([])
  const [topTask, setTopTask] = useState<CaiTopTask>('chat')
  const [selectedName, setSelectedName] = useState('')
  const [challenge, setChallenge] = useState('')
  const [prompt, setPrompt] = useState(TASK_PROMPTS.general)
  const [running, setRunning] = useState(false)
  const [replaying, setReplaying] = useState(false)
  const [loading, setLoading] = useState(true)
  const [replayTitle, setReplayTitle] = useState('')
  const [agentFrames, setAgentFrames] = useState<AgentFrame[]>([])

  const taskType = taskTypeFor(topTask)
  const selected = useMemo(() => ctfs.find((item) => item.name === selectedName), [ctfs, selectedName])
  const selectedEnvironment = taskEnvironments.find((item) => item.id === topTask)
  const challenges = selected?.challenges ?? []
  const challengeDetail = selected?.challenge_details?.[challenge] ?? ''

  useEffect(() => {
    replayingRef.current = replaying
  }, [replaying])

  const stopReplay = useCallback(() => {
    replayTimersRef.current.forEach((timer) => window.clearTimeout(timer))
    replayTimersRef.current = []
    setReplaying(false)
  }, [])

  const clearAgentFrames = useCallback(() => {
    frameCloseTimersRef.current.forEach((timer) => window.clearTimeout(timer))
    frameCloseTimersRef.current.clear()
    agentFrameBodyRefs.current.clear()
    setAgentFrames([])
  }, [])

  const scrollAgentFrameToBottom = useCallback((id: string) => {
    const body = agentFrameBodyRefs.current.get(id)
    if (!body) return
    body.scrollTop = body.scrollHeight
    const frames = agentFramesRef.current
    if (frames) frames.scrollTop = frames.scrollHeight
  }, [])

  const stop = useCallback(() => {
    stopReplay()
    clearAgentFrames()
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) {
      termRef.current?.write('\r\n[CyberOrion] Stop requested; waiting for task shutdown...\r\n')
      ws.send(JSON.stringify({ type: 'stop' }))
      window.setTimeout(() => {
        if (wsRef.current === ws && ws.readyState === WebSocket.OPEN) ws.close()
      }, 1500)
    }
  }, [clearAgentFrames, stopReplay])

  const resetTerminal = useCallback(() => {
    termRef.current?.clear()
  }, [])

  const closeAgentFrameLater = useCallback((id: string) => {
    const existing = frameCloseTimersRef.current.get(id)
    if (existing) window.clearTimeout(existing)
    const timer = window.setTimeout(() => {
      setAgentFrames((frames) => frames.filter((frame) => frame.id !== id))
      frameCloseTimersRef.current.delete(id)
    }, 3200)
    frameCloseTimersRef.current.set(id, timer)
  }, [])

  const handleAgentEvent = useCallback((payload: Record<string, unknown>): boolean => {
    const type = textField(payload, 'type')
    const id = textField(payload, 'id')
    if (!id || !type.startsWith('agent_')) return false
    if (type === 'agent_start') {
      const timer = frameCloseTimersRef.current.get(id)
      if (timer) {
        window.clearTimeout(timer)
        frameCloseTimersRef.current.delete(id)
      }
      const agent = textField(payload, 'agent') || '子 Agent'
      const title = textField(payload, 'title') || textField(payload, 'phase') || '子任务'
      setAgentFrames((frames) => {
        const rest = frames.filter((frame) => frame.id !== id)
        return [
          ...rest,
          {
            id,
            agent,
            title,
            status: 'running',
            lines: [{ id: `${id}-start`, kind: 'thinking', text: `进入 ${agent}：${title}` }],
          },
        ]
      })
      return true
    }
    const line = lineForAgentEvent(payload)
    setAgentFrames((frames) => frames.map((frame) => {
      if (frame.id !== id) return frame
      const nextStatus: AgentFrameStatus = type === 'agent_error' ? 'failed' : type === 'agent_done' ? 'done' : frame.status
      const lastLine = frame.lines[frame.lines.length - 1]
      const mergeOutputDelta = type === 'agent_output' && lastLine?.kind === line?.kind
      const nextLines = line && line.text
        ? mergeOutputDelta && lastLine
          ? [
              ...frame.lines.slice(0, -1),
              { ...lastLine, text: lastLine.text + line.text },
            ]
          : [
              ...frame.lines,
              { id: `${id}-${frame.lines.length}-${Date.now()}`, kind: line.kind, text: line.text },
            ]
        : frame.lines
      return {
        ...frame,
        status: nextStatus,
        lines: nextLines.slice(-120),
      }
    }))
    scrollAgentFrameToBottom(id)
    if (type === 'agent_done' || type === 'agent_error') closeAgentFrameLater(id)
    return true
  }, [closeAgentFrameLater, scrollAgentFrameToBottom])

  const writeTerminalPayload = useCallback((text: string) => {
    if (text.includes(AGENT_EVENT_PREFIX)) {
      text.split(/(?<=\n)/).forEach((part) => {
        if (!part) return
        const eventPayload = tryParseAgentEvent(part)
        if (eventPayload && handleAgentEvent(eventPayload)) return
        termRef.current?.write(part)
      })
      return
    }
    termRef.current?.write(text)
  }, [handleAgentEvent])

  const playRecording = useCallback((id: string, replaySpeed: number = 1) => {
    const term = termRef.current
    if (!term || !id) return
    stop()
    api.getCaiRecording(id)
      .then((recording: CaiRecording) => {
        term.clear()
        clearAgentFrames()
        setReplayTitle(recording.title)
        setReplaying(true)
        // 贴近真实运行时长：每帧延时基于相邻帧时间差 * speed。
        // 相邻间隔上限 1500ms（避免连续长时间无输出时空等过久）；
        // 下限 12ms（保持可读节奏）。首帧 100ms 让用户感知开始。
        const speed = Math.max(0.25, Math.min(replaySpeed, 4))
        const maxStepMs = 1500
        const minStepMs = 12
        const firstDelayMs = 100
        const frames = recording.frames
        let prevT = 0
        let cumDelay = firstDelayMs
        replayTimersRef.current = frames.map((frame, index) => {
          const curT = Number(frame.t) || prevT
          const step = Math.max(0, curT - prevT) * 1000 * speed
          prevT = curT
          const delay = index === 0
            ? firstDelayMs
            : Math.min(Math.max(step, minStepMs), maxStepMs)
          cumDelay += delay
          return window.setTimeout(() => {
            writeTerminalPayload(frame.data)
            if (index === frames.length - 1) {
              setReplaying(false)
              replayTimersRef.current = []
            }
          }, cumDelay)
        })
      })
      .catch((e) => {
        setReplaying(false)
        pushToast(`CAI 回放加载失败: ${e instanceof Error ? e.message : String(e)}`, { title: 'CAI' })
      })
  }, [clearAgentFrames, stop, writeTerminalPayload])

  const start = useCallback((config: RunConfig) => {
    const term = termRef.current
    if (!term) return
    stopReplay()
    clearAgentFrames()
    if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.close()
    fitRef.current?.fit()
    term.clear()
    const ws = new WebSocket(wsUrl())
    wsRef.current = ws
    setRunning(true)
    ws.onopen = () => {
      const selectedTask = config.topTask ?? topTask
      const selectedType = config.taskType ?? taskTypeFor(selectedTask)
      const environment = taskEnvironments.find((item) => item.id === selectedTask)
      const payload: Record<string, unknown> = {
        rows: term.rows,
        cols: term.cols,
        continue_mode: false,
        CAI_AGENT_TYPE: 'cyberorion_agent',
        CAI_TASK_TYPE: selectedType,
      }
      const promptText = (config.prompt ?? '').trim()
      if (promptText) payload.prompt = promptText
      if (environment?.workdir) payload.task_workdir = environment.workdir
      if (environment) {
        payload.CAI_TASK_CONTEXT = [
          `任务：${environment.title}`,
          `任务说明：${environment.description}`,
          environment.workspace ? `工作区：${environment.workspace}` : '',
        ].filter(Boolean).join('\n')
      }
      if (config.ctf) {
        payload.CAI_TASK_TYPE = 'ctf'
        payload.CTF_NAME = config.ctf.name
        payload.CTF_INSIDE = config.ctf.ctf_inside
      }
      if (config.challenge) payload.CTF_CHALLENGE = config.challenge
      ws.send(JSON.stringify(payload))
    }
    ws.onmessage = (event) => {
      const text = String(event.data)
      try {
        const parsed: unknown = JSON.parse(text)
        if (isRecord(parsed)) {
          const type = textField(parsed, 'type')
          if (type === 'terminal_output') {
            writeTerminalPayload(textField(parsed, 'data'))
            return
          }
          if (type.startsWith('agent_') && handleAgentEvent(parsed)) return
        }
      } catch {}
      writeTerminalPayload(text)
    }
    ws.onerror = () => {
      pushToast('CAI WebSocket 连接失败', { title: 'CAI' })
      setRunning(false)
    }
    ws.onclose = () => {
      setRunning(false)
      wsRef.current = null
    }
  }, [clearAgentFrames, handleAgentEvent, stopReplay, taskEnvironments, topTask, writeTerminalPayload])

  const startCurrentTask = useCallback(() => {
    if (topTask === 'ctf') {
      if (!selected) {
        pushToast('没有可启动的 CAI CTF。请等待 catalog 加载完成或刷新页面。', { title: 'CAI' })
        return
      }
      start({ ctf: selected, challenge, prompt: prompt.trim() || DEFAULT_CTF_PROMPT, taskType: 'ctf', topTask: 'ctf' })
      return
    }
    start({ taskType, topTask, prompt: prompt.trim() || TASK_PROMPTS[taskType] })
  }, [challenge, prompt, selected, start, taskType, topTask])

  const demoReplay = useCallback(() => {
    // 优先从历史里挑最新的高质量真实 recording（status=success、有 report、frames 多），
    // 回落到内置的极简 demo。素材始终来自历史或内置 demo，禁止凭空生成。
    const taskType = taskTypeFor(topTask)
    api.pickCaiDemo(taskType)
      .then((pick) => {
        if (pick?.recording?.id) {
          playRecording(pick.recording.id)
          return
        }
        const fallback = DEMO_REPLAY_IDS[topTask]
        if (fallback) playRecording(fallback)
      })
      .catch(() => {
        const fallback = DEMO_REPLAY_IDS[topTask]
        if (fallback) playRecording(fallback)
      })
  }, [playRecording, topTask])

  useEffect(() => {
    let stale = false
    Promise.all([api.getCaiCtfs(), api.getCaiTaskEnvironments()])
      .then(([ctfData, environmentData]) => {
        if (stale) return
        setTaskEnvironments(environmentData.tasks)
        const sorted = ctfData.ctfs.slice().sort((a, b) => {
          const byDiff = difficultyRank(a.difficulty) - difficultyRank(b.difficulty)
          return byDiff || a.name.localeCompare(b.name)
        })
        setCtfs(sorted)
        const first = sorted.find((item) => item.name === 'picoctf_static_flag') ?? sorted[0]
        if (first) {
          setSelectedName(first.name)
          setChallenge(first.challenges[0] ?? '')
        }
      })
      .catch((e) => pushToast(`CAI 资源加载失败: ${e instanceof Error ? e.message : String(e)}`, { title: 'CAI' }))
      .finally(() => { if (!stale) setLoading(false) })
    return () => { stale = true }
  }, [])

  useEffect(() => {
    setPrompt(TASK_PROMPTS[taskTypeFor(topTask)])
  }, [topTask])

  useEffect(() => {
    if (!hostRef.current || termRef.current) return
    const term = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 12,
      lineHeight: 1.25,
      scrollback: 10000,
      theme: {
        background: '#05080b',
        foreground: '#d6deeb',
        cursor: '#8be9fd',
        selectionBackground: '#264f78',
      },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    term.write('\x1b[?7l')
    fit.fit()
    termRef.current = term
    fitRef.current = fit
    resetTerminal()
    const onResize = () => {
      fit.fit()
      const ws = wsRef.current
      if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
    }
    const ro = new ResizeObserver(onResize)
    ro.observe(hostRef.current)
    const disposable = term.onData((data) => {
      if (replayingRef.current) return
      const ws = wsRef.current
      if (ws?.readyState !== WebSocket.OPEN) return
      if (data.includes('\x03')) {
        ws.send(JSON.stringify({ type: 'interrupt' }))
        const rest = data.replace(/\x03/g, '')
        if (rest) ws.send(JSON.stringify({ type: 'input', data: rest }))
        return
      }
      ws.send(JSON.stringify({ type: 'input', data }))
    })
    return () => {
      disposable.dispose()
      ro.disconnect()
      stopReplay()
      clearAgentFrames()
      wsRef.current?.close()
      term.dispose()
      termRef.current = null
      fitRef.current = null
    }
  }, [clearAgentFrames, stopReplay, resetTerminal])

  useEffect(() => {
    if (!active) return
    window.setTimeout(() => {
      fitRef.current?.fit()
      termRef.current?.scrollToBottom()
    }, 0)
  }, [active])

  useEffect(() => {
    agentFrames.forEach((frame) => scrollAgentFrameToBottom(frame.id))
  }, [agentFrames, scrollAgentFrameToBottom])

  useEffect(() => {
    if (selected) setChallenge(selected.challenges[0] ?? '')
  }, [selectedName, selected])

  useEffect(() => {
    const consumeReplay = (id: string) => {
      if (!id) return
      window.localStorage.removeItem(REPLAY_STORAGE_KEY)
      const url = new URL(window.location.href)
      if (url.searchParams.get('replay')) {
        url.searchParams.delete('replay')
        window.history.replaceState({}, '', url.toString())
      }
      window.setTimeout(() => playRecording(id), 50)
    }
    const fromUrl = new URLSearchParams(window.location.search).get('replay') ?? ''
    const fromStorage = window.localStorage.getItem(REPLAY_STORAGE_KEY) ?? ''
    consumeReplay(fromUrl || fromStorage)
    const onReplay = (event: Event) => consumeReplay(eventReplayId(event))
    window.addEventListener('cai-replay-request', onReplay)
    return () => window.removeEventListener('cai-replay-request', onReplay)
  }, [playRecording])

  return (
    <div className="flex h-full min-h-0 min-w-0 flex-1 flex-col bg-[var(--color-bg)]">
      <div className="cai-task-tabs">
        {TASK_TABS.map((tab) => (
          <button key={tab.id} className={topTask === tab.id ? 'is-active' : ''} disabled={running || replaying} onClick={() => setTopTask(tab.id)}>
            {tab.label}
          </button>
        ))}
      </div>
      <div className="cai-session-layout">
        <aside className="cai-side">
          <div className="cai-side__header">
            <div className="cai-side__eyebrow">CAI · {selectedEnvironment?.available === false ? 'unavailable' : 'ready'}</div>
            <h1>{selectedEnvironment?.title ?? TASK_TABS.find((item) => item.id === topTask)?.label}</h1>
            <p>{selectedEnvironment?.description ?? defaultDescription(topTask)}</p>
          </div>
          {topTask === 'ctf' && (
            <>
              <section className="cai-control">
                <label>CTF</label>
                <select value={selectedName} onChange={(e) => setSelectedName(e.target.value)} disabled={loading || running || replaying}>
                  {ctfs.map((item) => <option key={item.name} value={item.name}>{item.name} · {item.difficulty || 'Unknown'}</option>)}
                </select>
              </section>
              <section className="cai-control">
                <label>Challenge</label>
                <select value={challenge} onChange={(e) => setChallenge(e.target.value)} disabled={running || replaying || !challenges.length}>
                  {(challenges.length ? challenges : ['']).map((item) => <option key={item || 'default'} value={item}>{item || 'Default'}</option>)}
                </select>
              </section>
            </>
          )}
          <section className="cai-control">
            <label>任务 Prompt</label>
            <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} disabled={running || replaying} rows={7} />
          </section>
          {topTask === 'ctf' && selected && (
            <section className="cai-ctf-detail">
              <div>{selected.type || 'CTF'} · {selected.difficulty || 'Unknown'} · {selected.ctf_inside ? 'ctf_inside' : 'external service'}</div>
              {selected.description && <p>{selected.description}</p>}
              {selected.instructions && <p><b>Instructions:</b> {selected.instructions}</p>}
              {challengeDetail && <p><b>{challenge || 'Challenge'}:</b> {challengeDetail}</p>}
              {selected.techniques && <code>{selected.techniques}</code>}
            </section>
          )}
          {topTask !== 'ctf' && selectedEnvironment?.workspace && (
            <section className="cai-ctf-detail">
              <div>任务工作区</div>
              <code>{selectedEnvironment.workspace}</code>
              <p>{topTask === 'attack_chain' ? '包含 timeline.jsonl、web_access.log、auth.log 证据。' : '包含漏洞代码、测试文件和可运行 pytest 环境。'}</p>
            </section>
          )}
          <div className="cai-actions">
            <button className="btn" disabled={running || replaying || (topTask === 'ctf' && !selected)} onClick={startCurrentTask}>开始</button>
            <button className="btn" disabled={!running && !replaying} onClick={stop}>Stop</button>
            <button className="btn" disabled={running || replaying} onClick={demoReplay}>Demo 回放</button>
          </div>
          <div className="cai-status">
            <span className={running || replaying ? 'is-running' : ''}>{running ? 'RUNNING' : replaying ? 'REPLAY' : 'IDLE'}</span>
            <span>{replaying ? replayTitle : loading ? 'loading resources' : `${ctfs.length} CTFs · ${taskEnvironments.length} tasks`}</span>
          </div>
        </aside>
        <div className={`cai-terminal-wrap ${agentFrames.length ? 'has-agent-frames' : ''}`}>
          {agentFrames.length > 0 && (
            <div className="cai-agent-frames" ref={agentFramesRef}>
              {agentFrames.map((frame) => (
                <section key={frame.id} className={`cai-agent-frame is-${frame.status}`}>
                  <div className="cai-agent-frame__header">
                    <span>{frame.agent}</span>
                    <small>{frame.status === 'running' ? 'RUNNING' : frame.status === 'done' ? 'RETURNING' : 'FAILED'}</small>
                  </div>
                  <div className="cai-agent-frame__title">{frame.title}</div>
                  <div
                    className="cai-agent-frame__body scroll-thin"
                    ref={(element) => {
                      if (element) agentFrameBodyRefs.current.set(frame.id, element)
                      else agentFrameBodyRefs.current.delete(frame.id)
                    }}
                  >
                    {frame.lines.map((line) => (
                      <pre key={line.id} className={`cai-agent-line is-${line.kind}`}>{line.text}</pre>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          )}
          <div ref={hostRef} className="cai-terminal" />
        </div>
      </div>
    </div>
  )
}
