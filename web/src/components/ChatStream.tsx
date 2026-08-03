// ChatStream — 平铺聊天流（Cursor 风格：无气泡无卡片，分隔线分区）
// 消息形态：
//  - thinking    → agent 名 + 流式文本（12.5px，行内）
//  - tool_call   → 行内工具标签 + 参数（点击展开）
//  - tool_output → 折叠工具结果（点击展开）
//  - report      → 子代理报告（点击展开 md）
//  - system      → 灰色小字（攻击命中 / 遥测 / 回合标记）
import { useEffect, useRef, useState } from 'react'
import { blueRoleOf } from '../types'
import { MarkdownView } from './MarkdownView'
import type { ThoughtStep, Side } from '../types'

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('zh-CN', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
  })
}

const TOOL_ZH: Record<string, string> = {
  dispatch_task: '派遣子代理',
  analyze_logs: '日志分析',
  check_telemetry: '遥测检查',
  harden_service: '加固服务',
  block_ip: '封禁 IP',
  report_finding: '上报发现',
  verify_intrusion: '失陷排查',
  scan: '端口扫描',
  exploit: '漏洞利用',
  escalate: '权限提升',
  persist: '植入持久化',
  attack: '发起攻击',
  collect: '信息收集',
}

interface AgentMeta {
  label: string
  color: string
}

function metaOf(agent: string | undefined, side: Side): AgentMeta {
  if (side === 'red') return { label: '红方', color: 'var(--color-red)' }
  const r = blueRoleOf(agent ?? 'orchestrator')
  if (r) return { label: r.name, color: r.colorVar }
  return { label: '调度指挥', color: 'var(--color-blue)' }
}

function ToolCall({ step, side }: { step: ThoughtStep; side: Side }) {
  const [open, setOpen] = useState(false)
  const isRed = side === 'red'
  const zh = TOOL_ZH[step.tool ?? '']
  return (
    <div className="fade-in flex flex-wrap items-center gap-1.5 py-px">
      <span className="flex-none font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>{fmtTs(step.timestamp)}</span>
      <span className="kimi-toolcard" style={isRed ? { color: 'var(--color-red)', background: 'var(--color-red-soft)' } : { color: 'var(--color-tool)', background: 'var(--color-cyan-soft)' }}>
        {isRed ? '⚔' : '⚙'} {zh || step.tool}
      </span>
      {step.args && (
        <button className="kimi-toolcard" onClick={() => setOpen((v) => !v)}>
          {open ? '收起' : '参数'}
        </button>
      )}
      {open && step.args && (
        <pre className="scroll-thin w-full overflow-x-auto whitespace-pre-wrap break-all border-l-2 py-0.5 pl-3 font-mono text-[11px]" style={{ borderColor: 'var(--color-line)', color: 'var(--color-fg-2)' }}>
          {step.args}
        </pre>
      )}
    </div>
  )
}

function ToolOutput({ step }: { step: ThoughtStep }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="fade-in pl-6">
      <button
        onClick={() => setOpen((v) => !v)}
        className="text-[10.5px] transition-colors hover:text-[var(--color-fg)]"
        style={{ color: 'var(--color-fg-3)' }}
      >
        {open ? '▾' : '▸'} {step.tool} 结果
      </button>
      {open && (
        <pre className="scroll-thin overflow-x-auto whitespace-pre-wrap break-words border-l-2 py-0.5 pl-3 font-mono text-[11px] leading-relaxed" style={{ borderColor: 'var(--color-line)', color: 'var(--color-output)' }}>
          {step.output}
        </pre>
      )}
    </div>
  )
}

function Report({ step, side }: { step: ThoughtStep; side: Side }) {
  const [open, setOpen] = useState(false)
  const meta = metaOf(step.role ?? step.agent, side)
  const hasError = step.report?.startsWith('✗')
  return (
    <div className="fade-in pl-6">
      <button
        onClick={() => setOpen((v) => !v)}
        className="text-[11.5px] font-medium transition-opacity hover:opacity-80"
        style={{ color: hasError ? 'var(--color-red)' : meta.color }}
      >
        {open ? '▾' : '▸'} {meta.label} 报告{hasError ? '（异常）' : ''}
      </button>
      {open && step.report && (
        <div className="mt-1 border-l-2 pl-3" style={{ borderColor: 'var(--color-line)' }}>
          <MarkdownView markdown={step.report} />
        </div>
      )}
    </div>
  )
}

function StepRow({ step, side, isLast }: { step: ThoughtStep; side: Side; isLast: boolean }) {
  if (step.kind === 'system') {
    return (
      <div className="fade-in py-px text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
        {step.text}
      </div>
    )
  }
  if (step.kind === 'thinking' && step.text) {
    const meta = metaOf(step.agent, side)
    return (
      <div className="fade-in py-px">
        <div className="flex items-baseline gap-2">
          <span className="text-[11px] font-semibold" style={{ color: meta.color }}>{meta.label}</span>
          <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>{fmtTs(step.timestamp)}</span>
        </div>
        <div className="stream-thinking whitespace-pre-wrap break-words">
          {step.text}
          {isLast && <span className="cursor-blink" />}
        </div>
      </div>
    )
  }
  if (step.kind === 'tool_call') return <ToolCall step={step} side={side} />
  if (step.kind === 'tool_output' && step.output) return <ToolOutput step={step} />
  if (step.kind === 'report') return <Report step={step} side={side} />
  return null
}

export function ChatStream({
  side,
  steps,
  running,
  accent,
  emptyTitle,
  emptyDesc,
}: {
  side: Side
  steps: ThoughtStep[]
  running: boolean
  accent: 'red' | 'blue'
  emptyTitle: string
  emptyDesc: string
}) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const stickBottom = useRef(true)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    if (stickBottom.current) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [steps])

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    stickBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 60
  }

  const accentColor = accent === 'red' ? 'var(--color-red)' : 'var(--color-blue)'

  return (
    <section className="flex min-h-0 flex-1 flex-col" style={{ minHeight: 0 }}>
      {/* 栏头：一行 */}
      <div className="flex flex-none items-center gap-1.5 border-b px-2 py-1" style={{ borderColor: 'var(--color-hairline)' }}>
        <span className="dot" style={{ background: accentColor }} />
        <span className="text-[11.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
          {emptyTitle.split('（')[0]}
        </span>
        {running && <span className="text-[10.5px]" style={{ color: accentColor }}>运行中</span>}
      </div>

      <div ref={scrollRef} onScroll={onScroll} className="scroll-thin min-h-0 flex-1 overflow-y-auto px-2 py-1">
        {steps.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-0.5 py-10">
            <div className="text-[12px]" style={{ color: 'var(--color-fg-3)' }}>{emptyTitle}</div>
            <div className="text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>{emptyDesc}</div>
          </div>
        ) : (
          steps.map((s, i) => (
            <StepRow key={s.id} step={s} side={side} isLast={i === steps.length - 1 && s.kind === 'thinking' && running} />
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </section>
  )
}
