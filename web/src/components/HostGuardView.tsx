// HostGuard: server maintenance based on CyberOrion blue team architecture.
// UI = chat interface (Kimi/ChatGPT/Claude style), streaming output, tool calls, markdown.

import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { pushToast } from '../toasts'
import { MarkdownView } from './MarkdownView'
import { FadeIn } from './FadeIn'

interface ChatEvent {
  type: 'system' | 'thinking' | 'tool_call' | 'tool_output' | 'report' | 'error'
  side: string
  data: Record<string, unknown>
  timestamp: number
}

interface ChatMessage {
  role: 'user' | 'agent'
  content: string
  events?: ChatEvent[]
}

interface ConnectionStatus {
  connected: boolean
  host?: string
  username?: string
  port?: number
  system_info?: string
}

const AGENT_COLORS: Record<string, { color: string; label: string; icon: string }> = {
  recon_agent: { color: 'var(--color-blue)', label: '系统侦察', icon: '🔍' },
  scanner_agent: { color: 'var(--color-cyan)', label: '安全扫描', icon: '🛡' },
  analyst_agent: { color: 'var(--color-purple)', label: '威胁分析', icon: '⚡' },
  hardener_agent: { color: 'var(--color-green)', label: '加固建议', icon: '🔧' },
  guard_agent: { color: 'var(--color-amber)', label: '主机卫士', icon: '🤖' },
}

function agentMeta(agent: string | undefined) {
  return AGENT_COLORS[agent ?? 'guard_agent'] ?? AGENT_COLORS.guard_agent
}

function streamSSE(
  url: string,
  body: unknown,
  onEvent: (ev: ChatEvent) => void,
  onDone: () => void,
  onError?: (e: Error) => void,
): AbortController {
  const c = new AbortController()
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: c.signal,
  }).then(async (r: Response) => {
    if (!r.ok || !r.body) { onError?.(new Error(`HTTP ${r.status}`)); return }
    const rd = r.body.getReader(), dec = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await rd.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let i
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, i)
        buf = buf.slice(i + 2)
        for (const line of frame.split('\n')) {
          const t = line.trim()
          if (!t.startsWith('data:')) continue
          try { onEvent(JSON.parse(t.slice(5).trim())) } catch { /* skip */ }
        }
      }
    }
    onDone()
  }).catch((e: Error) => { if (e.name !== 'AbortError') onError?.(e) })
  return c
}

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function AgentAvatar({ color, size = 24 }: { color: string; size?: number }) {
  return (
    <span className="flex flex-none select-none items-center justify-center rounded-full" style={{ width: size, height: size, background: color }}>
      <svg viewBox="0 0 24 24" width={size * 0.58} height={size * 0.58} fill="none" aria-hidden>
        <circle cx="12" cy="8.6" r="3.6" fill="#fff" />
        <path d="M4.5 21c0-4.2 3.4-6.6 7.5-6.6s7.5 2.4 7.5 6.6z" fill="#fff" />
      </svg>
    </span>
  )
}

function ConnectForm({ onConnected }: { onConnected: () => void }) {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [keyFile, setKeyFile] = useState<File | null>(null)
  const [connecting, setConnecting] = useState(false)
  const [error, setError] = useState('')

  const connect = useCallback(async () => {
    if (!host.trim()) { setError('请输入服务器 IP 或域名'); return }
    setConnecting(true); setError('')
    try {
      const r = await api.hostguardConnect({ host: host.trim(), port: parseInt(port) || 22, username: username.trim() || 'root', password, keyFile })
      if (r.ok) { pushToast(`已连接到 ${host}`, { title: '主机卫士' }); onConnected() }
      else { setError(r.error || '连接失败') }
    } catch (e) { setError(e instanceof Error ? e.message : '连接请求失败') }
    finally { setConnecting(false) }
  }, [host, port, username, password, keyFile, onConnected])

  return (
    <div className="flex min-h-0 flex-1 items-center justify-center overflow-y-auto p-6">
      <FadeIn className="w-full max-w-[480px]">
        <form
          className="panel p-6"
          onSubmit={(event) => {
            event.preventDefault()
            void connect()
          }}
        >
          <div className="mb-4 flex items-center gap-2">
            <span className="text-[20px]">🛡</span>
            <h2 className="text-[14px] font-semibold text-fg">主机卫士</h2>
            <span className="text-[11px] text-text-3">连接服务器开始维护</span>
          </div>
          <div className="mb-4 rounded border border-blue/30 bg-blue/5 p-3 text-[11px] leading-relaxed text-text-2">
            <div className="mb-1 font-medium text-blue">需要提供的信息：</div>
            <div>• 服务器 IP 地址或域名</div>
            <div>• SSH 端口（默认 22）</div>
            <div>• 登录用户名（默认 root）</div>
            <div>• 密码 或 SSH 私钥文件（上传）（二选一）</div>
            <div className="mt-1.5 text-text-3">连接成功后，将自动按 CyberOrion 蓝方架构（侦察→扫描→分析→加固）进行扫描分析。</div>
          </div>
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-text-3">服务器 IP / 域名 *</label>
              <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="例如 192.168.1.100" className="w-full rounded border border-hairline bg-panel-2 px-3 py-1.5 text-[12px] text-fg outline-none transition-colors focus:border-blue/50" />
            </div>
            <div className="flex gap-3">
              <div className="flex-1">
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-text-3">端口</label>
                <input value={port} onChange={(e) => setPort(e.target.value)} className="w-full rounded border border-hairline bg-panel-2 px-3 py-1.5 text-[12px] text-fg outline-none transition-colors focus:border-blue/50" />
              </div>
              <div className="flex-1">
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-text-3">用户名</label>
                <input value={username} onChange={(e) => setUsername(e.target.value)} className="w-full rounded border border-hairline bg-panel-2 px-3 py-1.5 text-[12px] text-fg outline-none transition-colors focus:border-blue/50" />
              </div>
            </div>
            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-text-3">密码</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="密码认证（需要 sshpass）" className="w-full rounded border border-hairline bg-panel-2 px-3 py-1.5 text-[12px] text-fg outline-none transition-colors focus:border-blue/50" />
            </div>
            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-text-3">SSH 私钥文件</label>
              <input type="file" accept=".pem,.key,.p8,id_rsa" onChange={(e) => setKeyFile(e.target.files?.[0] ?? null)} placeholder="例如 ~/.ssh/id_rsa（密钥认证）" className="w-full rounded border border-hairline bg-panel-2 px-3 py-1.5 text-[12px] text-fg outline-none transition-colors focus:border-blue/50" />
            </div>
          </div>
          {error && <div className="mt-3 rounded border border-attacker/40 bg-attacker/5 p-2 text-[11px] text-attacker">{error}</div>}
          <button type="submit" disabled={connecting || !host.trim()} className="mt-4 w-full rounded bg-blue px-4 py-2 text-[12px] font-medium text-bg transition-colors hover:bg-blue/80 disabled:opacity-40">
            {connecting ? '连接中…' : '连接服务器'}
          </button>
        </form>
      </FadeIn>
    </div>
  )
}

function EventRow({ ev }: { ev: ChatEvent }) {
  const [expanded, setExpanded] = useState(false)
  const agent = String(ev.data.agent || 'guard_agent')
  const meta = agentMeta(agent)

  if (ev.type === 'system') {
    const text = String(ev.data.text || ev.data.message || '')
    if (!text) return null
    return <div className="fade-in py-1 text-center text-[10px] text-text-3">{text}</div>
  }
  if (ev.type === 'error') {
    return <div className="fade-in rounded border border-attacker/40 bg-attacker/5 px-3 py-1.5 text-[11px] text-attacker">⚠ {String(ev.data.message || '未知错误')}</div>
  }
  if (ev.type === 'tool_call') {
    const tool = String(ev.data.tool || '')
    const args = String(ev.data.args || '')
    return (
      <div className="fade-in flex items-center gap-1.5 py-px pl-8">
        <span className="font-mono text-[10px] text-text-4">{fmtTs(ev.timestamp)}</span>
        <span className="rounded px-1.5 py-px text-[10px] font-medium" style={{ color: meta.color, background: `${meta.color}15` }}>🔧 {tool}</span>
        {args && <span className="truncate font-mono text-[10px] text-text-3" title={args}>{args}</span>}
      </div>
    )
  }
  if (ev.type === 'tool_output') {
    const tool = String(ev.data.tool || '')
    const output = String(ev.data.output || '')
    return (
      <div className="fade-in pl-8">
        <button onClick={() => setExpanded(!expanded)} className="text-[10px] text-text-3 transition-colors hover:text-fg">{expanded ? '▼' : '▶'} {tool} 执行结果</button>
        {expanded && <pre className="scroll-thin mt-0.5 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded border-l-2 border-hairline py-0.5 pl-3 font-mono text-[10px] leading-relaxed text-text-2">{output}</pre>}
      </div>
    )
  }
  if (ev.type === 'thinking') {
    const text = String(ev.data.text || '')
    if (!text) return null
    if (ev.data.delta === true) return <span className="text-[12px] leading-relaxed" style={{ color: meta.color }}>{text}</span>
    return (
      <div className="fade-in flex gap-2 py-1">
        <AgentAvatar color={meta.color} size={22} />
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-[11px] font-semibold" style={{ color: meta.color }}>{meta.icon} {meta.label} Agent</span>
            <span className="font-mono text-[9px] text-text-4">{fmtTs(ev.timestamp)}</span>
          </div>
          <div className="mt-0.5 text-[12px] leading-relaxed text-text-1">{text}</div>
        </div>
      </div>
    )
  }
  if (ev.type === 'report') {
    const report = String(ev.data.report || '')
    if (!report) return null
    return (
      <div className="fade-in flex gap-2 py-1">
        <AgentAvatar color={meta.color} size={22} />
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-[11px] font-semibold" style={{ color: meta.color }}>{meta.icon} {meta.label} 报告</span>
            <span className="font-mono text-[9px] text-text-4">{fmtTs(ev.timestamp)}</span>
          </div>
          <div className="mt-1 rounded border-l-2 border-hairline pl-3"><MarkdownView markdown={report} className="md-inline" /></div>
        </div>
      </div>
    )
  }
  return null
}

function MessageGroup({ msg, streaming }: { msg: ChatMessage; streaming: boolean }) {
  if (msg.role === 'user') {
    return <div className="fade-in flex justify-end py-2"><div className="max-w-[80%] rounded-lg bg-blue/15 px-3 py-1.5 text-[12px] text-fg">{msg.content}</div></div>
  }
  const events = msg.events || []
  const renderedEvents: ChatEvent[] = []
  let currentDelta = ''
  for (const ev of events) {
    if (ev.type === 'thinking' && ev.data.delta === true) { currentDelta += String(ev.data.text || '') }
    else {
      if (currentDelta) {
        renderedEvents.push({ type: 'thinking', side: 'blue', data: { agent: events[0]?.data?.agent || 'guard_agent', text: currentDelta, delta: false }, timestamp: ev.timestamp })
        currentDelta = ''
      }
      renderedEvents.push(ev)
    }
  }
  if (currentDelta) {
    renderedEvents.push({ type: 'thinking', side: 'blue', data: { agent: events[0]?.data?.agent || 'guard_agent', text: currentDelta, delta: false }, timestamp: events[events.length - 1]?.timestamp || Date.now() / 1000 })
  }
  return (
    <div className="py-1">
      {renderedEvents.map((ev, i) => <EventRow key={i} ev={ev} />)}
      {streaming && <div className="flex items-center gap-1 py-1 pl-8 text-[10px] text-text-3"><span className="live-pulse inline-block h-1.5 w-1.5 rounded-full bg-blue" />处理中…</div>}
    </div>
  )
}

export function HostGuardView() {
  const [status, setStatus] = useState<ConnectionStatus>({ connected: false })
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [streamingIdx, setStreamingIdx] = useState(-1)
  const abortRef = useRef<AbortController | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  const checkStatus = useCallback(async () => {
    try {
      const s = await api.hostguardStatus()
      setStatus(s)
      if (s.connected && messages.length === 0) {
        setMessages([{ role: 'agent', content: '', events: [{ type: 'system', side: 'system', data: { text: `已连接到 ${s.host}（${s.username}@${s.host}:${s.port}）。点击"开始扫描"启动自动分析，或在下方输入问题。` }, timestamp: Date.now() / 1000 }] }])
      }
    } catch { setStatus({ connected: false }) }
  }, [messages.length])

  useEffect(() => { checkStatus() }, [checkStatus])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages])

  const handleEvents = useCallback((idx: number) => {
    return (ev: ChatEvent) => {
      setMessages((prev) => {
        const next = [...prev]
        if (next[idx] && next[idx].role === 'agent') { next[idx] = { ...next[idx], events: [...(next[idx].events || []), ev] } }
        return next
      })
    }
  }, [])

  const startScan = useCallback(() => {
    if (streaming) return
    const idx = messages.length
    setMessages((prev) => [...prev, { role: 'agent', content: '', events: [] }])
    setStreaming(true); setStreamingIdx(idx)
    abortRef.current = streamSSE(api.hostguardScanURL(), {}, handleEvents(idx),
      () => { setStreaming(false); setStreamingIdx(-1) },
      (e: Error) => { setStreaming(false); setStreamingIdx(-1); pushToast(`扫描失败：${e.message}`, { title: '主机卫士' }) })
  }, [streaming, messages.length, handleEvents])

  const sendMessage = useCallback(() => {
    const msg = input.trim()
    if (!msg || streaming) return
    setInput('')
    setMessages((prev) => [...prev, { role: 'user', content: msg }])
    const idx = messages.length + 1
    setMessages((prev) => [...prev, { role: 'agent', content: '', events: [] }])
    setStreaming(true); setStreamingIdx(idx)
    abortRef.current = streamSSE(api.hostguardChatURL(), { message: msg }, handleEvents(idx),
      () => { setStreaming(false); setStreamingIdx(-1) },
      (e: Error) => { setStreaming(false); setStreamingIdx(-1); pushToast(`请求失败：${e.message}`, { title: '主机卫士' }) })
  }, [input, streaming, messages.length, handleEvents])

  const disconnect = useCallback(async () => {
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null }
    try { await api.hostguardDisconnect() } catch { /* ignore */ }
    setStatus({ connected: false })
    // 改进：断开保留 messages 历史，让用户可回顾
  }, [])

  const clearConversation = useCallback(() => {
    if (streaming) return
    setMessages([])
    setInput('')
    setStreamingIdx(-1)
  }, [streaming])

  if (!status.connected) return <ConnectForm onConnected={checkStatus} />

  return (
    <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <header className="flex flex-none items-center gap-3 border-b border-hairline px-5 py-2">
        <span className="text-[16px]">🛡</span>
        <div className="flex items-baseline gap-2">
          <span className="text-[13px] font-semibold text-fg">主机卫士</span>
          <span className="font-mono text-[11px] text-text-3">{status.username}@{status.host}:{status.port}</span>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={startScan} disabled={streaming} className="rounded bg-blue px-3 py-1 text-[11px] font-medium text-bg transition-colors hover:bg-blue/80 disabled:opacity-40">{streaming ? '扫描中…' : '开始扫描'}</button>
          <button onClick={clearConversation} disabled={streaming} className="rounded bg-overlay px-3 py-1 text-[11px] text-text-3 transition-colors hover:bg-hover hover:text-text-2 disabled:opacity-40">清空对话</button>
          <button onClick={disconnect} className="rounded bg-overlay px-3 py-1 text-[11px] text-text-3 transition-colors hover:bg-hover hover:text-attacker">断开</button>
        </div>
      </header>
      <div ref={scrollRef} className="scroll-thin min-h-0 flex-1 overflow-y-auto px-5 py-3">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2">
            <div className="text-[28px]">🛡</div>
            <div className="text-[13px] text-text-3">主机卫士已就绪</div>
            <div className="text-[11px] text-text-4">点击"开始扫描"启动自动分析，或在下方输入问题</div>
          </div>
        ) : (
          <div className="mx-auto max-w-[900px]">
            {messages.map((msg, i) => <MessageGroup key={i} msg={msg} streaming={streaming && i === streamingIdx} />)}
            <div ref={bottomRef} />
          </div>
        )}
      </div>
      <footer className="flex flex-none items-center gap-2 border-t border-hairline px-5 py-3">
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() } }} placeholder={streaming ? '处理中…' : '输入问题，例如"检查系统开放端口"'} disabled={streaming} className="flex-1 rounded-lg border border-hairline bg-panel-2 px-3 py-2 text-[12px] text-fg outline-none transition-colors focus:border-blue/50 disabled:opacity-50" />
        <button onClick={sendMessage} disabled={streaming || !input.trim()} className="rounded-lg bg-blue px-4 py-2 text-[12px] font-medium text-bg transition-colors hover:bg-blue/80 disabled:opacity-40">发送</button>
      </footer>
    </main>
  )
}
