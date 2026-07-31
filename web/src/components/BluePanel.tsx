// 蓝方面板（Part B 重构）：每个 agent 自己的栏 ——
//   顶部 = 紧凑 chain strip（~64px，指挥官 + 角色节点 + 状态脉冲边，全局地图）；
//   下方 = 动态 per-agent 面板行（横向滚动；≤2 个时 2 列网格铺满）：
//     orchestrator 面板常驻；角色被派遣（spawn）时出现自己的面板，
//     内含该 agent 的 thinking/tool_call/tool_output 流（按 data.agent 过滤、
//     自动滚动），完成后追加可折叠【结论】区（team done 报告）。
// 面板状态：执行中 = 顶部绿色扫线动画；完成 = 绿色顶边。

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useArena } from '../arena'
import type { TeamState, ThoughtStep } from '../types'
import { ROLE_META } from './AgentChain'

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

type AgentStatus = 'running' | 'done' | 'idle'

function statusDot(st: AgentStatus): string {
  return st === 'running'
    ? 'bg-accent live-pulse'
    : st === 'done'
      ? 'bg-accent/60'
      : 'bg-text-3'
}

// ---------------------------------------------------------------------------
// 紧凑 chain strip（全局地图）
// ---------------------------------------------------------------------------

function StripNode({
  role,
  status,
  mission,
}: {
  role: string
  status: AgentStatus
  mission?: string
}) {
  const meta = ROLE_META[role] ?? { zh: role, glyph: '·' }
  return (
    <div
      title={mission || role}
      className={`flex flex-none items-center gap-1.5 rounded-lg border px-2 py-1 ${
        status === 'running'
          ? 'border-accent/40 bg-accent/5'
          : status === 'done'
            ? 'border-accent/20 bg-white/[0.02]'
            : 'border-hairline bg-white/[0.02]'
      }`}
    >
      <span className="text-[10px] text-accent/90">{meta.glyph}</span>
      <span className="text-[10px] font-medium text-text-1">{meta.zh}</span>
      <span className="font-mono text-[8px] text-text-3">{role}</span>
      <span className={`h-1.5 w-1.5 rounded-full ${statusDot(status)}`} />
    </div>
  )
}

function StripEdge({ live }: { live: boolean }) {
  return (
    <svg width="26" height="4" className="flex-none" aria-hidden>
      <line
        x1="0"
        y1="2"
        x2="26"
        y2="2"
        stroke={live ? '#5ed29c' : '#3a3f3c'}
        strokeWidth={live ? 1.5 : 1}
        strokeDasharray={live ? '5 5' : undefined}
        className={live ? 'edge-flow' : undefined}
      />
    </svg>
  )
}

function ChainStrip({
  roles,
  team,
  blueRunning,
}: {
  roles: string[]
  team: TeamState
  blueRunning: boolean
}) {
  const statusOf = (role: string): AgentStatus => {
    if (role === 'orchestrator') return blueRunning ? 'running' : 'idle'
    if (role in team.active) return 'running'
    if (team.done.some((d) => d.role === role)) return 'done'
    return 'idle'
  }
  const runningCount = Object.keys(team.active).length
  return (
    <div className="flex h-16 flex-none items-center gap-1 overflow-x-auto overflow-y-hidden border-b border-hairline px-3">
      <span className="eyebrow mr-1 flex-none !text-[8px]">工作流</span>
      <StripNode
        role="orchestrator"
        status={statusOf('orchestrator')}
        mission="红蓝对抗总指挥 · 任务派发"
      />
      {roles.map((role) => {
        const st = statusOf(role)
        // 派遣瞬间（3s 内）边也脉冲，提示「指挥官 → X」刚刚发生。
        const dispatchedAt = team.dispatched[role] ?? 0
        const live =
          st === 'running' || Date.now() / 1000 - dispatchedAt < 3
        return (
          <span key={role} className="flex flex-none items-center gap-1">
            <StripEdge live={live} />
            <StripNode
              role={role}
              status={st}
              mission={
                team.active[role]?.mission ??
                [...team.done].reverse().find((d) => d.role === role)?.mission
              }
            />
          </span>
        )
      })}
      {roles.length === 0 && (
        <span className="flex-none pl-2 text-[10px] text-text-3">
          等待指挥官 dispatch_task 派发子 Agent
        </span>
      )}
      <span className="ml-auto flex-none pl-3 font-mono text-[9px] text-text-3">
        {runningCount > 0 && <span className="text-accent">{runningCount} 执行中 · </span>}
        {team.done.length} 完成
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// per-agent stream rows
// ---------------------------------------------------------------------------

function BlueStepRow({ step }: { step: ThoughtStep }) {
  const ts = (
    <span className="mr-2 flex-none select-none font-mono text-[9px] tabular-nums text-text-3">
      {fmtTime(step.timestamp)}
    </span>
  )
  if (step.kind === 'thinking') {
    return (
      <div className="flex px-2.5 py-0.5">
        {ts}
        <div className="whitespace-pre-wrap break-words font-mono text-[11.5px] leading-[1.55] text-[#b9c2bd]">
          {step.text}
        </div>
      </div>
    )
  }
  if (step.kind === 'tool_call') {
    return (
      <div className="mt-1 border-l-2 border-accent/40 bg-white/[0.03] px-2.5 py-1">
        <span className="select-none font-mono text-[10px] text-accent/60">❯ </span>
        <span className="font-mono text-[11.5px] font-semibold text-text-1">
          {step.tool}
        </span>
        {step.args && (
          <span className="ml-2 break-all font-mono text-[10px] text-text-2">
            {step.args}
          </span>
        )}
      </div>
    )
  }
  return (
    <div className="border-l-2 border-white/10 bg-white/[0.015] px-2.5 py-1">
      {step.tool && (
        <span className="mr-2 select-none font-mono text-[9px] text-text-3">
          ↩ {step.tool}
        </span>
      )}
      <span className="whitespace-pre-wrap break-all font-mono text-[10.5px] leading-5 text-[#c9d1cc]">
        {(step.output ?? '').slice(0, 1200)}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// per-agent panel
// ---------------------------------------------------------------------------

function AgentPanel({
  role,
  team,
  steps,
  blueRunning,
  className = '',
}: {
  role: string
  team: TeamState
  steps: ThoughtStep[]
  blueRunning: boolean
  className?: string
}) {
  const meta = ROLE_META[role] ?? { zh: role, glyph: '·' }
  const isOrch = role === 'orchestrator'
  const status: AgentStatus = isOrch
    ? blueRunning
      ? 'running'
      : 'idle'
    : role in team.active
      ? 'running'
      : team.done.some((d) => d.role === role)
        ? 'done'
        : 'idle'
  const mission = isOrch
    ? '红蓝对抗总指挥 · 任务派发与汇总'
    : (team.active[role]?.mission ??
      [...team.done].reverse().find((d) => d.role === role)?.mission ??
      '')
  // 该角色最近一次完成的报告（结论区）。
  const report = isOrch
    ? null
    : ([...team.done].reverse().find((d) => d.role === role) ?? null)
  const [reportOpen, setReportOpen] = useState(false)

  const boxRef = useRef<HTMLDivElement>(null)
  const [pinned, setPinned] = useState(true)
  const onScroll = useCallback(() => {
    const el = boxRef.current
    if (!el) return
    setPinned(el.scrollHeight - el.scrollTop - el.clientHeight < 24)
  }, [])
  useEffect(() => {
    const el = boxRef.current
    if (el && pinned) el.scrollTop = el.scrollHeight
  }, [steps.length, pinned])

  const topEdge =
    status === 'running'
      ? 'agent-running-line border-t border-t-accent/50'
      : status === 'done'
        ? 'border-t border-t-accent/50'
        : 'border-t border-t-hairline'

  return (
    <section
      className={`panel flex min-h-0 min-w-0 flex-col overflow-hidden ${topEdge} ${className}`}
    >
      <header className="flex flex-none items-center gap-1.5 border-b border-hairline px-2.5 py-1.5">
        <span className="text-[11px] text-accent/90">{meta.glyph}</span>
        <span className="text-[11px] font-semibold text-text-1">{meta.zh}</span>
        <span className="font-mono text-[9px] text-text-3">{role}</span>
        <span className={`h-1.5 w-1.5 flex-none rounded-full ${statusDot(status)}`} />
        <span
          className="min-w-0 truncate text-[9px] text-text-2"
          title={mission}
        >
          {mission}
        </span>
        <span className="ml-auto flex-none font-mono text-[9px] tabular-nums text-text-3">
          {steps.length}
        </span>
      </header>

      <div
        ref={boxRef}
        onScroll={onScroll}
        className="scroll-thin min-h-0 flex-1 space-y-0.5 overflow-y-auto overflow-x-hidden py-1.5"
      >
        {steps.map((s) => (
          <BlueStepRow key={s.id} step={s} />
        ))}
        {steps.length === 0 && (
          <div className="flex h-full items-center justify-center px-4 text-center font-mono text-[10px] text-text-3">
            {status === 'running' ? '执行中，等待输出…' : '暂无输出'}
          </div>
        )}
      </div>
      {!pinned && steps.length > 0 && (
        <button
          onClick={() => {
            const el = boxRef.current
            if (el) el.scrollTop = el.scrollHeight
            setPinned(true)
          }}
          className="mx-auto mb-1 flex-none rounded-full border border-accent/30 bg-ink px-2.5 py-px font-mono text-[9px] text-accent hover:bg-white/5"
        >
          ↓ 最新
        </button>
      )}

      {report && (
        <div className="flex-none border-t border-hairline">
          <button
            onClick={() => setReportOpen((v) => !v)}
            className="flex w-full items-center gap-1.5 px-2.5 py-1 text-left transition-colors hover:bg-white/[0.03]"
          >
            <span className="text-[9px] text-accent">✓</span>
            <span className="eyebrow !text-[8px]">结论</span>
            {!reportOpen && (
              <span className="min-w-0 truncate font-mono text-[9px] text-text-3">
                {report.report.split('\n').find((l) => l.trim())?.trim()}
              </span>
            )}
            <span className="ml-auto flex-none font-mono text-[9px] text-text-3">
              {reportOpen ? '▾' : '▸'}
            </span>
          </button>
          {reportOpen && (
            <pre className="scroll-thin max-h-44 overflow-y-auto whitespace-pre-wrap break-words px-2.5 pb-2 font-mono text-[10.5px] leading-[1.55] text-[#c9d1cc]">
              {report.report}
            </pre>
          )}
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// 蓝方面板（header + chain strip + per-agent panels）
// ---------------------------------------------------------------------------

export function BluePanel({ className = 'flex-1' }: { className?: string }) {
  const { blueSteps, team, status, clearSteps } = useArena()

  // 子代理面板顺序：首次出现次序（done → active → dispatched 去重）。
  const roles = useMemo(() => {
    const seen: string[] = []
    const push = (r: string) => {
      if (r && r !== 'orchestrator' && !seen.includes(r)) seen.push(r)
    }
    for (const d of team.done) push(d.role)
    for (const r of Object.keys(team.active)) push(r)
    for (const r of Object.keys(team.dispatched)) push(r)
    return seen
  }, [team])

  // 按 agent 拆分蓝方流；orchestrator 含无 agent 标签的 legacy 事件。
  // kind==="report" 的卡片不进流（结论区独立展示）。
  const stepsByAgent = useMemo(() => {
    const map = new Map<string, ThoughtStep[]>()
    map.set('orchestrator', [])
    for (const r of roles) map.set(r, [])
    for (const s of blueSteps) {
      if (s.kind === 'report') continue
      const key = s.agent ?? 'orchestrator'
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(s)
    }
    return map
  }, [blueSteps, roles])

  const agents = useMemo(() => ['orchestrator', ...roles], [roles])
  const stateLabel = status.blue_running
    ? status.blue_paused
      ? '暂停'
      : '运行'
    : '空闲'

  return (
    <section
      className={`panel flex min-h-0 min-w-0 flex-col overflow-hidden ${className}`}
    >
      {/* header strip */}
      <header className="flex flex-none items-center gap-2.5 border-b border-hairline px-3 py-2">
        <span
          className={`h-1.5 w-1.5 rounded-full ${
            status.blue_running
              ? status.blue_paused
                ? 'bg-warning'
                : 'bg-accent live-pulse'
              : 'bg-text-3'
          }`}
        />
        <span className="text-[11px] font-semibold text-accent">蓝方团队</span>
        <span className="font-display text-[9px] font-bold uppercase tracking-[0.2em] text-text-3">
          Blue Team
        </span>
        <span className="rounded-full bg-white/5 px-2 py-px text-[9px] text-text-2">
          {stateLabel}
        </span>
        <div className="ml-auto flex items-center gap-3">
          <span className="font-mono text-[9px] tabular-nums text-text-3">
            {blueSteps.length} 步 · {agents.length} Agent
          </span>
          <button
            onClick={() => clearSteps('blue')}
            className="rounded-full bg-white/5 px-2.5 py-px text-[9px] text-text-2 transition-colors hover:bg-white/10 hover:text-neutral-200"
          >
            清空
          </button>
        </div>
      </header>

      {/* 紧凑工作流地图 */}
      <ChainStrip roles={roles} team={team} blueRunning={status.blue_running} />

      {/* per-agent 面板区：≤2 个时 2 列网格铺满，否则横向滚动行 */}
      {agents.length <= 2 ? (
        <div
          className={`grid min-h-0 flex-1 gap-3 p-3 ${
            agents.length === 1 ? 'grid-cols-1' : 'grid-cols-2'
          }`}
        >
          {agents.map((role) => (
            <AgentPanel
              key={role}
              role={role}
              team={team}
              steps={stepsByAgent.get(role) ?? []}
              blueRunning={status.blue_running}
            />
          ))}
        </div>
      ) : (
        <div className="scroll-thin flex min-h-0 flex-1 gap-3 overflow-x-auto overflow-y-hidden p-3">
          {agents.map((role) => (
            <AgentPanel
              key={role}
              role={role}
              team={team}
              steps={stepsByAgent.get(role) ?? []}
              blueRunning={status.blue_running}
              className="w-[340px] flex-none"
            />
          ))}
        </div>
      )}
    </section>
  )
}
