import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { api } from '../api'
import { pushToast } from '../toasts'
import type { CaiCtfItem, CaiRecording } from '../types'

interface RunConfig {
  ctf?: CaiCtfItem
  challenge?: string
  prompt?: string
  taskType?: 'general' | 'ctf' | 'code_repair' | 'attack_chain'
}

const DEFAULT_CTF_PROMPT = 'Solve this CAI CTF challenge. Work step by step, validate the flag, and stop when the flag is confirmed.'
const TASK_PROMPTS: Record<NonNullable<RunConfig['taskType']>, string> = {
  general: '',
  ctf: DEFAULT_CTF_PROMPT,
  code_repair: '修复代码漏洞。先定位并复现问题，给出最小安全修复，运行回归验证，并输出面向安全人员的漏洞修复报告。',
  attack_chain: '复原攻击链条。分析提供的日志与流量证据，建立时间线，标注受害资产、攻击来源、行为和 ATT&CK 技术，最后输出面向安全人员的结构化报告。',
}
const REPLAY_STORAGE_KEY = 'cyberorion:cai-replay-id'
const DEMO_REPLAY_ID = 'demo_picoctf_static_flag'

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

export function CaiTerminalView({ active = true }: { active?: boolean }) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const replayTimersRef = useRef<number[]>([])
  const replayingRef = useRef(false)
  const [ctfs, setCtfs] = useState<CaiCtfItem[]>([])
  const [selectedName, setSelectedName] = useState('')
  const [challenge, setChallenge] = useState('')
  const [taskType, setTaskType] = useState<NonNullable<RunConfig['taskType']>>('general')
  const [prompt, setPrompt] = useState(TASK_PROMPTS.general)
  const [running, setRunning] = useState(false)
  const [replaying, setReplaying] = useState(false)
  const [loading, setLoading] = useState(true)
  const [replayTitle, setReplayTitle] = useState('')

  const selected = useMemo(
    () => ctfs.find((item) => item.name === selectedName),
    [ctfs, selectedName],
  )
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

  const writeIntro = useCallback(() => {
    const term = termRef.current
    if (!term) return
    term.clear()
    term.write('\x1b[1;36mCAI Web Terminal\x1b[0m\r\n')
    term.write('Use the left panel to start CyberOrion, run a CyberOrion CTF, or replay a saved run.\r\n')
    term.write('This is an interactive PTY bridge: type directly in the terminal after CAI starts.\r\n')
    term.write('The terminal area renders raw CAI CLI output through PTY + ANSI.\r\n\r\n')
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
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.close()
    }
    fitRef.current?.fit()
    term.clear()
    const ws = new WebSocket(wsUrl())
    wsRef.current = ws
    setRunning(true)
    ws.onopen = () => {
      const payload: Record<string, unknown> = {
        rows: term.rows,
        cols: term.cols,
        continue_mode: false,
        CAI_AGENT_TYPE: 'cyberorion_agent',
        CAI_TASK_TYPE: config.taskType ?? 'general',
      }
      const promptText = (config.prompt ?? '').trim()
      if (promptText) payload.prompt = promptText
      if (config.ctf) {
        payload.CAI_TASK_TYPE = 'ctf'
        payload.CTF_NAME = config.ctf.name
        payload.CTF_INSIDE = config.ctf.ctf_inside
      }
      if (config.challenge) payload.CTF_CHALLENGE = config.challenge
      ws.send(JSON.stringify(payload))
    }
    ws.onmessage = (event) => term.write(String(event.data))
    ws.onerror = () => {
      pushToast('CAI WebSocket 连接失败', { title: 'CAI' })
      setRunning(false)
    }
    ws.onclose = () => {
      setRunning(false)
      wsRef.current = null
    }
  }, [stopReplay])

  const startCtf = useCallback(() => {
    if (!selected) {
      termRef.current?.write('\r\n[CAI web] No CTF selected. Load the CAI CTF catalog, select a challenge, then start again.\r\n')
      pushToast('没有可启动的 CAI CTF。请等待 catalog 加载完成或刷新页面。', { title: 'CAI' })
      return
    }
    start({
      ctf: selected,
      challenge,
      prompt: prompt.trim() || DEFAULT_CTF_PROMPT,
      taskType: 'ctf',
    })
  }, [challenge, prompt, selected, start])

  const startDemo = useCallback(() => {
    const demoPrompt = TASK_PROMPTS[taskType]
    start({ taskType, prompt: demoPrompt })
  }, [start, taskType])

  useEffect(() => {
    let stale = false
    api.getCaiCtfs()
      .then((data) => {
        if (stale) return
        const sorted = data.ctfs.slice().sort((a, b) => {
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
      .catch((e) => pushToast(`CAI CTF 列表加载失败: ${e instanceof Error ? e.message : String(e)}`, { title: 'CAI' }))
      .finally(() => { if (!stale) setLoading(false) })
    return () => { stale = true }
  }, [])

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
        black: '#000000',
        red: '#ff6b6b',
        green: '#48c78e',
        yellow: '#e7b955',
        blue: '#59a7ff',
        magenta: '#c4a7ff',
        cyan: '#5eead4',
        white: '#d6deeb',
        brightBlack: '#6b7280',
        brightRed: '#ff8787',
        brightGreen: '#69db7c',
        brightYellow: '#ffd43b',
        brightBlue: '#74c0fc',
        brightMagenta: '#d0bfff',
        brightCyan: '#99f6e4',
        brightWhite: '#ffffff',
      },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    fit.fit()
    termRef.current = term
    fitRef.current = fit
    writeIntro()

    const onResize = () => {
      fit.fit()
      const ws = wsRef.current
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
      }
    }
    const ro = new ResizeObserver(onResize)
    ro.observe(hostRef.current)
    const disposable = term.onData((data) => {
      if (replayingRef.current) return
      const ws = wsRef.current
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }))
      }
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
  }, [stopReplay, writeIntro])

  useEffect(() => {
    if (!active) return
    window.setTimeout(() => {
      fitRef.current?.fit()
      termRef.current?.scrollToBottom()
    }, 0)
  }, [active])

  useEffect(() => {
    if (!selected) return
    setChallenge(selected.challenges[0] ?? '')
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
    <div className="flex h-full min-h-0 bg-[var(--color-bg)]">
      <aside className="cai-side">
        <div className="cai-side__header">
          <div className="cai-side__eyebrow">CAI CLI</div>
          <h1>CyberOrion 终端</h1>
          <p>网页只转发 CAI PTY 输入输出；终端颜色、框线和报错都按 CLI 原样显示。</p>
        </div>

        <section className="cai-help">
          <strong>怎么使用</strong>
          <span>Start CyberOrion：启动默认主 Agent；可先选择修复代码漏洞或复原攻击链条 demo 环境。</span>
          <span>Start CyberOrion CTF：按所选 CTF / Challenge / Prompt 调用 CyberOrion 实时运行。</span>
          <span>Demo Replay：只用于演示回放，不会替代 Start CyberOrion 或 Start CyberOrion CTF。</span>
          <span>CAI 历史只列出真实运行记录；演示素材只从 Demo Replay 手动进入。</span>
          <span>如果 CTF 镜像或 registry token 缺失，错误会原样显示在终端并写入历史。</span>
        </section>

        <section className="cai-control">
          <label>任务环境</label>
          <select
            value={taskType}
            onChange={(e) => {
              const next = e.target.value as NonNullable<RunConfig['taskType']>
              setTaskType(next)
              if (next !== 'ctf') setPrompt(TASK_PROMPTS[next])
            }}
            disabled={running || replaying}
          >
            <option value="general">通用安全任务</option>
            <option value="code_repair">Demo · 修复代码漏洞</option>
            <option value="attack_chain">Demo · 复原攻击链条</option>
          </select>
        </section>

        <section className="cai-control">
          <label>CTF</label>
          <select
            value={selectedName}
            onChange={(e) => setSelectedName(e.target.value)}
            disabled={loading || running || replaying}
          >
            {ctfs.map((item) => (
              <option key={item.name} value={item.name}>
                {item.name} · {item.difficulty || 'Unknown'}
              </option>
            ))}
          </select>
        </section>

        <section className="cai-control">
          <label>Challenge</label>
          <select value={challenge} onChange={(e) => setChallenge(e.target.value)} disabled={running || replaying || !challenges.length}>
            {(challenges.length ? challenges : ['']).map((item) => (
              <option key={item || 'default'} value={item}>{item || 'Default'}</option>
            ))}
          </select>
        </section>

        <section className="cai-control">
          <label>CTF Prompt</label>
          <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} disabled={running || replaying} rows={4} />
        </section>

        {selected && (
          <section className="cai-ctf-detail">
            <div>{selected.type || 'CTF'} · {selected.difficulty || 'Unknown'} · {selected.ctf_inside ? 'ctf_inside' : 'external service'}</div>
            {selected.description && <p>{selected.description}</p>}
            {selected.instructions && <p><b>Instructions:</b> {selected.instructions}</p>}
            {challengeDetail && <p><b>{challenge || 'Challenge'}:</b> {challengeDetail}</p>}
            {Object.keys(selected.challenge_details || {}).length > 0 && (
              <div className="cai-task-list">
                <b>全部任务</b>
                {Object.entries(selected.challenge_details).map(([name, detail]) => (
                  <p key={name}><b>{name}:</b> {detail || 'No detail provided by CAI catalog.'}</p>
                ))}
              </div>
            )}
            {selected.techniques && <code>{selected.techniques}</code>}
            {selected.source && <code>{selected.source}</code>}
          </section>
        )}

        <div className="cai-actions">
          <button
            className="btn"
            disabled={running || replaying || !selected}
            onClick={startCtf}
          >
            Start CyberOrion CTF
          </button>
          <button className="btn" disabled={running || replaying} onClick={startDemo}>
            Start CyberOrion
          </button>
          <button className="btn" disabled={running || replaying} onClick={() => playRecording(DEMO_REPLAY_ID)}>
            Demo Replay
          </button>
          <button className="btn" disabled={!running && !replaying} onClick={stop}>
            Stop
          </button>
        </div>

        <div className="cai-status">
          <span className={running || replaying ? 'is-running' : ''}>{running ? 'RUNNING' : replaying ? 'REPLAY' : 'IDLE'}</span>
          <span>{replaying ? replayTitle : loading ? 'loading catalog' : `${ctfs.length} CTFs`}</span>
        </div>
      </aside>

      <div className="min-w-0 flex-1 p-2">
        <div ref={hostRef} className="cai-terminal" />
      </div>
    </div>
  )
}
