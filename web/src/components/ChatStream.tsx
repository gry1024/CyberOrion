// ChatStream — Kimi 式聊天流渲染（红/蓝共用）
// 消息形态（每条 = 一个流式消息，像 chat 输出）：
//  - thinking    → 助手消息（agent 头像 + 名字 + 流式文本 + 光标）
//  - tool_call   → 工具胶囊卡（点击展开 args JSON）
//  - tool_output → 折叠「工具结果」卡（点击展开原文）
//  - report      → 子代理报告卡（可展开 md 渲染）
//  - system      → 居中细字系统条（攻击命中 / 遥测 / 回合标记）
import { useEffect, useRef, useState } from 'react'
import { blueRoleOf } from '../types'
import { MarkdownView } from './MarkdownView'
import type { ThoughtStep, Side } from '../types'

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('zh-CN', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** 工具英文名 → 中文展示名（技术标识保持英文，展示加中文说明）。 */
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

function toolLabel(tool: string): string {
  if (!tool) return '工具'
  return TOOL_ZH[tool] ?? tool
}

interface AgentMeta {
  key: string
  label: string
  color: string
  glyph: string
}

function metaOf(agent: string | undefined, side: Side): AgentMeta {
  if (side === 'red') {
    return { key: 'red', label: '红方攻击者', color: 'var(--color-red)', glyph: '攻' }
  }
  const r = blueRoleOf(agent ?? 'orchestrator')
  if (r) {
    return {
      key: r.key,
      label: r.name,
      color: r.colorVar,
      glyph: r.key === 'orchestrator' ? '指' : r.key.slice(0, 1),
    }
  }
  return { key: 'orchestrator', label: '调度指挥', color: 'var(--color-blue)', glyph: '指' }
}

function AgentAvatar({ meta, size = 22 }: { meta: AgentMeta; size?: number }) {
  return (
    <span
      className="flex-none select-none rounded-full text-center font-medium"
      style={{
        width: size,
        height: size,
        lineHeight: `${size}px`,
        fontSize: size * 0.52,
        color: '#fff',
        background: meta.color,
      }}
    >
      {meta.glyph}
    </span>
  )
}

function ToolCallCard({ step, side }: { step: ThoughtStep; side: Side }) {
  const [open, setOpen] = useState(false)
  const isRed = side === 'red'
  return (
    <div className="fade-in flex flex-wrap items-center gap-2">
      <span className="ml-7" style={{ color: 'var(--color-fg-4)', fontSize: 11 }}>{fmtTs(step.timestamp)}</span>
      <button
        className={`kimi-toolcard ${isRed ? 'is-red' : 'is-blue'}`}
        onClick={() => setOpen((v) => !v)}
        title={open ? '收起参数' : '展开参数'}
      >
        <span style={{ fontSize: 10 }}>{isRed ? '⚔' : '🛠'}</span>
        {toolLabel(step.tool ?? '')}
        {step.tool && TOOL_ZH[step.tool] && (
          <span className="ml-1 font-mono text-[10px] font-normal opacity-70">{step.tool}</span>
        )}
      </button>
      {step.args && (
        <button
          className="kimi-toolcard"
          style={{ opacity: 0.85 }}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? '收起参数' : '查看参数'}
        </button>
      )}
      {open && step.args && (
        <pre className="scroll-thin mt-1 w-full overflow-x-auto whitespace-pre-wrap break-all rounded-lg border px-3 py-2 font-mono text-[11.5px] leading-relaxed" style={{ borderColor: 'var(--color-line)', background: 'var(--color-panel-2)', color: 'var(--color-fg-2)' }}>
          {step.args}
        </pre>
      )}
    </div>
  )
}

function ToolOutputCard({ step }: { step: ThoughtStep }) {
  const [open, setOpen] = useState(false)
  const out = step.output ?? ''
  return (
    <div className="fade-in ml-7">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 rounded-lg border px-3 py-1.5 text-left transition-colors hover:bg-[var(--color-overlay)]"
        style={{ borderColor: 'var(--color-hairline)', background: 'var(--color-panel)' }}
      >
        <span style={{ fontSize: 10, color: 'var(--color-fg-4)' }}>{open ? '▾' : '▸'}</span>
        <span className="text-[12px] font-medium" style={{ color: 'var(--color-fg-3)' }}>
          工具结果 · {step.tool}
        </span>
        <span className="ml-auto truncate font-mono text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
          {fmtTs(step.timestamp)}
        </span>
      </button>
      {open && (
        <pre className="scroll-thin mt-1 overflow-x-auto whitespace-pre-wrap break-words rounded-lg border px-3 py-2 font-mono text-[11.5px] leading-relaxed" style={{ borderColor: 'var(--color-line)', background: 'var(--color-panel-2)', color: 'var(--color-output)' }}>
          {out}
        </pre>
      )}
    </div>
  )
}

function ReportCard({ step, side }: { step: ThoughtStep; side: Side }) {
  const [open, setOpen] = useState(false)
  const meta = metaOf(step.role ?? step.agent, side)
  const hasError = step.report?.startsWith('✗')
  return (
    <div className="fade-in ml-7 overflow-hidden rounded-xl border" style={{ borderColor: 'var(--color-hairline)', background: 'var(--color-panel)' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors hover:bg-[var(--color-overlay)]"
      >
        <AgentAvatar meta={meta} size={26} />
        <span className="text-[13px] font-medium" style={{ color: hasError ? 'var(--color-red)' : 'var(--color-fg)' }}>
          {meta.label} 报告
        </span>
        {hasError && <span className="chip" style={{ color: 'var(--color-red)', background: 'var(--color-red-soft)' }}>异常</span>}
        <span className="ml-auto text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
          {open ? '收起' : '展开'} {open ? '▾' : '▸'}
        </span>
      </button>
      {open && step.report && (
        <div className="border-t px-4 py-3" style={{ borderColor: 'var(--color-hairline)' }}>
          <MarkdownView markdown={step.report} />
        </div>
      )}
    </div>
  )
}

function StepRow({
  step,
  side,
  isLast,
}: {
  step: ThoughtStep
  side: Side
  isLast: boolean
}) {
  if (step.kind === 'system') {
    return (
      <div className="fade-in flex justify-center py-0.5">
        <span className="max-w-full truncate rounded-full px-3 py-0.5 text-[11px]" style={{ color: 'var(--color-fg-3)', background: 'var(--color-overlay)' }}>
          {step.text}
        </span>
      </div>
    )
  }
  if (step.kind === 'thinking' && step.text) {
    const meta = metaOf(step.agent, side)
    return (
      <div className="fade-in flex gap-2.5 px-3 py-1">
        <AgentAvatar meta={meta} />
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-[12.5px] font-semibold" style={{ color: meta.color }}>
              {meta.label}
            </span>
            <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
              {fmtTs(step.timestamp)}
            </span>
          </div>
          <div className="stream-thinking whitespace-pre-wrap break-words">
            {step.text}
            {isLast && <span className="cursor-blink" />}
          </div>
        </div>
      </div>
    )
  }
  if (step.kind === 'tool_call') {
    return <ToolCallCard step={step} side={side} />
  }
  if (step.kind === 'tool_output' && step.output) {
    return <ToolOutputCard step={step} />
  }
  if (step.kind === 'report') {
    return <ReportCard step={step} side={side} />
  }
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
  // 用户主动上滑（离开底部 >80px）时暂停自动滚动，回到底部附近恢复。
  const stickBottom = useRef(true)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    if (stickBottom.current) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [steps])

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    const dist = el.scrollHeight - el.scrollTop - el.clientHeight
    stickBottom.current = dist < 80
  }

  const accentColor = accent === 'red' ? 'var(--color-red)' : 'var(--color-blue)'

  return (
    <section
      className="panel flex min-h-0 flex-1 flex-col"
      style={{ minHeight: 0, flex: '1 1 0' }}
    >
      {/* 栏标题 — Kimi 式：细分隔 + 圆点状态 */}
      <div className="flex flex-none items-center gap-2.5 px-4 py-2.5">
        <span className="dot" style={{ background: accentColor, boxShadow: running ? `0 0 6px ${accentColor}` : 'none' }} />
        <span className="text-[13.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
          {emptyTitle.split('（')[0]}
        </span>
        {running && (
          <span className="flex items-center gap-1.5 text-[11px] font-medium" style={{ color: accentColor }}>
            <span className="live-pulse dot" style={{ background: accentColor }} />
            运行中
          </span>
        )}
        <span className="ml-auto font-mono text-[11px] tabular-nums" style={{ color: 'var(--color-fg-4)' }}>
          {String(steps.length).padStart(3, '0')} 条消息
        </span>
      </div>
      <div className="mx-4 border-t" style={{ borderColor: 'var(--color-hairline)' }} />

      {/* 消息流 */}
      <div ref={scrollRef} onScroll={onScroll} className="scroll-thin min-h-0 flex-1 overflow-y-auto py-2.5">
        {steps.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-1 py-16">
            <div className="text-[15px] font-semibold" style={{ color: 'var(--color-fg-3)' }}>
              {emptyTitle}
            </div>
            <div className="max-w-[240px] text-center text-[12px] leading-relaxed" style={{ color: 'var(--color-fg-4)' }}>
              {emptyDesc}
            </div>
          </div>
        ) : (
          steps.map((s, i) => (
            <StepRow
              key={s.id}
              step={s}
              side={side}
              isLast={i === steps.length - 1 && s.kind === 'thinking' && running}
            />
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </section>
  )
}
