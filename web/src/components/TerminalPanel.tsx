// 红/蓝终端面板: center-stage live output for one side — thinking, tool
// calls and tool outputs in a mono, terminal-like stream. Auto-scrolls to
// the bottom, pauses when the user scrolls up (with a jump-to-latest pill).
// The blue panel additionally hosts the AGENT CHAIN workflow panel
// (orchestrator + dispatched sub-agents as a node-flow graph), stream
// filtering by agent, and collapsible sub-agent report cards inline.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useArena } from '../arena'
import type { ThoughtStep } from '../types'
import { AgentChain, roleZh } from './AgentChain'

type TermSide = 'red' | 'blue'

const SIDE_META: Record<
  TermSide,
  { name: string; en: string; accent: string; border: string; dim: string }
> = {
  red: {
    name: '红方终端',
    en: 'RED AGENT',
    accent: 'text-attacker',
    border: 'border-attacker/40',
    dim: 'text-attacker/50',
  },
  blue: {
    name: '蓝方终端',
    en: 'BLUE TEAM',
    accent: 'text-text-1',
    border: 'border-hairline',
    dim: 'text-text-2',
  },
}

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** Small gray [watcher] tag prefixing sub-agent stream lines. */
function AgentTag({ agent }: { agent?: string }) {
  if (!agent || agent === 'orchestrator') return null
  return (
    <span className="mr-1.5 flex-none select-none font-mono text-[9px] text-[#86868b]">
      [{agent}]
    </span>
  )
}

/** Collapsible sub-agent report card (team "done" event). */
function ReportCard({ step }: { step: ThoughtStep }) {
  const [open, setOpen] = useState(false)
  const report = step.report ?? ''
  const summary = report.split('\n').find((l) => l.trim())?.trim() ?? ''
  return (
    <div
      className="mx-2 my-1 cursor-pointer rounded-r-md border-l-2 border-[#636366] bg-raised/60 px-3 py-1.5 transition-colors hover:bg-raised"
      onClick={() => setOpen((v) => !v)}
    >
      <div className="flex items-center gap-2">
        <span className="flex-none text-[10px] text-success">✓</span>
        <span className="flex-none rounded border border-hairline px-1 py-px font-mono text-[9px] text-[#c7c7cc]">
          {step.role}
        </span>
        <span className="flex-none text-[10px] font-medium text-[#ececf0]">
          {roleZh(step.role ?? '')}报告
        </span>
        <span className="truncate text-[10px] text-[#86868b]" title={step.mission}>
          {step.mission}
        </span>
        <span className="ml-auto flex-none font-mono text-[9px] text-[#636366]">
          {open ? '▾ 收起' : '▸ 展开'}
        </span>
      </div>
      {!open && summary && (
        <div className="mt-0.5 truncate pl-5 font-mono text-[10px] text-[#86868b]">
          {summary}
        </div>
      )}
      {open && (
        <pre className="scroll-thin mt-1.5 max-h-72 overflow-y-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-[1.6] text-[#d1d1d6]">
          {report}
        </pre>
      )}
    </div>
  )
}

function StepRow({ step, side }: { step: ThoughtStep; side: TermSide }) {
  const meta = SIDE_META[side]
  const ts = (
    <span className="mr-2 flex-none select-none font-mono text-[9px] tabular-nums text-[#86868b]">
      {fmtTime(step.timestamp)}
    </span>
  )
  if (step.kind === 'report') {
    return <ReportCard step={step} />
  }
  if (step.kind === 'thinking') {
    return (
      <div className="flex px-3 py-0.5">
        {ts}
        <AgentTag agent={step.agent} />
        <div className="whitespace-pre-wrap break-words font-mono text-[13px] leading-[1.6] text-[#c7c7cc]">
          {step.text}
        </div>
      </div>
    )
  }
  if (step.kind === 'tool_call') {
    return (
      <div className={`mt-1 border-l-2 ${meta.border} bg-overlay/60 px-3 py-1`}>
        <span className={`select-none font-mono text-[11px] ${meta.dim}`}>❯ </span>
        <AgentTag agent={step.agent} />
        <span className="font-mono text-[13px] font-semibold text-[#f5f5f7]">
          {step.tool}
        </span>
        {step.args && (
          <span className="ml-2 break-all font-mono text-[11px] text-[#a1a1a6]">
            {step.args}
          </span>
        )}
      </div>
    )
  }
  return (
    <div className="border-l-2 border-[#3a3a3c] bg-raised/40 px-3 py-1">
      {step.tool && (
        <span className="mr-2 select-none font-mono text-[10px] text-[#86868b]">
          ↩ {step.tool}
        </span>
      )}
      <AgentTag agent={step.agent} />
      <span className="whitespace-pre-wrap break-all font-mono text-[12px] leading-5 text-[#d1d1d6]">
        {(step.output ?? '').slice(0, 1200)}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Terminal panel
// ---------------------------------------------------------------------------

export function TerminalPanel({
  side,
  className = 'flex-1',
}: {
  side: TermSide
  className?: string
}) {
  const { redSteps, blueSteps, team, status, clearSteps } = useArena()
  const allSteps = side === 'red' ? redSteps : blueSteps
  const meta = SIDE_META[side]

  // Blue-only stream filter: 'all' | 'orchestrator' | <role>.
  const [filter, setFilter] = useState('all')
  useEffect(() => {
    if (filter === 'all' || filter === 'orchestrator') return
    if (
      !(filter in team.active) &&
      !(filter in team.dispatched) &&
      !team.done.some((d) => d.role === filter)
    ) {
      setFilter('all')
    }
  }, [filter, team])

  const steps = useMemo(() => {
    if (side !== 'blue' || filter === 'all') return allSteps
    return allSteps.filter((s) => (s.agent ?? 'orchestrator') === filter)
  }, [side, filter, allSteps])

  const running = side === 'red' ? status.red_running : status.blue_running
  const paused = side === 'red' ? status.red_paused : status.blue_paused
  const stateLabel = running ? (paused ? '暂停' : '运行') : '空闲'
  const stateDot = running
    ? paused
      ? 'bg-warning'
      : 'bg-success live-pulse'
    : 'bg-text-3'

  const boxRef = useRef<HTMLDivElement>(null)
  const [pinned, setPinned] = useState(true) // follow latest output

  const onScroll = useCallback(() => {
    const el = boxRef.current
    if (!el) return
    // Consider "at bottom" when within 24px of the end.
    setPinned(el.scrollHeight - el.scrollTop - el.clientHeight < 24)
  }, [])

  useEffect(() => {
    const el = boxRef.current
    if (el && pinned) el.scrollTop = el.scrollHeight
  }, [steps.length, pinned])

  const jumpToLatest = useCallback(() => {
    const el = boxRef.current
    if (el) el.scrollTop = el.scrollHeight
    setPinned(true)
  }, [])

  return (
    <section
      className={`panel flex min-h-0 min-w-0 flex-col overflow-hidden ${className}`}
    >
      {/* header strip */}
      <header className="flex flex-none items-center gap-2.5 border-b border-hairline px-3 py-2">
        <span className={`h-1.5 w-1.5 rounded-full ${stateDot}`} />
        <span className={`text-[11px] font-semibold ${meta.accent}`}>{meta.name}</span>
        <span className="text-[9px] uppercase tracking-[0.2em] text-[#636366]">
          {meta.en}
        </span>
        <span className="rounded-full bg-overlay px-2 py-px text-[9px] text-[#a1a1a6]">
          {stateLabel}
        </span>
        <div className="ml-auto flex items-center gap-3">
          <span className="font-mono text-[9px] tabular-nums text-text-3">
            {steps.length} 步
          </span>
          <button
            onClick={() => clearSteps(side)}
            className="rounded-full bg-overlay px-2.5 py-px text-[9px] text-[#a1a1a6] transition-colors hover:bg-hover hover:text-neutral-200"
          >
            清空
          </button>
        </div>
      </header>

      {/* blue agent-chain workflow panel */}
      {side === 'blue' && (
        <AgentChain
          team={team}
          blueRunning={status.blue_running}
          filter={filter}
          onFilter={setFilter}
        />
      )}

      {/* stream */}
      <div className="relative flex min-h-0 flex-1 flex-col bg-ink">
        <div
          ref={boxRef}
          onScroll={onScroll}
          className="scroll-thin min-h-0 flex-1 space-y-0.5 overflow-y-auto overflow-x-hidden py-2"
        >
          {steps.map((s) => (
            <StepRow key={s.id} step={s} side={side} />
          ))}
          {steps.length === 0 && (
            <div className="flex h-full items-center justify-center">
              <div className="text-center">
                <div className={`font-mono text-[11px] ${meta.dim}`}>
                  {side === 'red' ? 'red@arena' : 'blue@arena'}:~$
                </div>
                <div className="mt-1 font-mono text-[10px] text-[#636366]">
                  {filter !== 'all'
                    ? `当前过滤 [${filter}] 暂无输出`
                    : `等待${meta.name.slice(0, 2)} Agent 输出…`}
                </div>
              </div>
            </div>
          )}
        </div>
        {!pinned && steps.length > 0 && (
          <button
            onClick={jumpToLatest}
            className={`absolute bottom-3 left-1/2 -translate-x-1/2 rounded-full border ${meta.border}
              bg-ink px-3 py-1 font-mono text-[10px] ${meta.accent} transition-colors hover:bg-overlay`}
          >
            ↓ 回到最新
          </button>
        )}
      </div>
    </section>
  )
}
