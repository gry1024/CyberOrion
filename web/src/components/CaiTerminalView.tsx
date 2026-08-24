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

const DEFAULT_CTF_PROMPT = 'Solve this CAI CTF challenge. Work step by step, validate the flag, and stop when the flag is confirmed.'
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

  const stop = useCallback(() => {
    stopReplay()
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'stop' }))
      ws.close()
    }
    wsRef.current = null
  }, [stopReplay])

  const resetTerminal = useCallback(() => {
    termRef.current?.clear()
  }, [])

  const playRecording = useCallback((id: string) => {
    const term = termRef.current
    if (!term || !id) return
    stop()
    api.getCaiRecording(id)
      .then((recording: CaiRecording) => {
        term.clear()
        setReplayTitle(recording.title)
        setReplaying(true)
        const speed = 0.45
        replayTimersRef.current = recording.frames.map((frame, index) => {
          const delay = Math.min(Math.max(frame.t * 1000 * speed, index * 35), 12000)
          return window.setTimeout(() => {
            term.write(frame.data)
            if (index === recording.frames.length - 1) {
              setReplaying(false)
              replayTimersRef.current = []
            }
          }, delay)
        })
      })
      .catch((e) => {
        setReplaying(false)
        pushToast(`CAI 回放加载失败: ${e instanceof Error ? e.message : String(e)}`, { title: 'CAI' })
      })
  }, [stop])

  const start = useCallback((config: RunConfig) => {
    const term = termRef.current
    if (!term) return
    stopReplay()
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
      term.write(text)
    }
    ws.onerror = () => {
      pushToast('CAI WebSocket 连接失败', { title: 'CAI' })
      setRunning(false)
    }
    ws.onclose = () => {
      setRunning(false)
      wsRef.current = null
    }
  }, [stopReplay, taskEnvironments, topTask])

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
    playRecording(DEMO_REPLAY_IDS[topTask])
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
      convertEol: true,
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
      if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'input', data }))
    })
    return () => {
      disposable.dispose()
      ro.disconnect()
      stopReplay()
      wsRef.current?.close()
      term.dispose()
      termRef.current = null
      fitRef.current = null
    }
  }, [stopReplay, resetTerminal])

  useEffect(() => {
    if (!active) return
    window.setTimeout(() => {
      fitRef.current?.fit()
      termRef.current?.scrollToBottom()
    }, 0)
  }, [active])

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
      <div className="flex min-h-0 min-w-0 flex-1">
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
        <div className="cai-terminal-wrap"><div ref={hostRef} className="cai-terminal" /></div>
      </div>
    </div>
  )
}
