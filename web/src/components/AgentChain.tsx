// 蓝方 AGENT CHAIN — dify/fastgpt-style workflow run visualization for the
// blue terminal: 【指挥官 orchestrator】 node on the left, sub-agent nodes
// spawned to the right in spawn order, connected by thin edges that pulse
// (animated stroke-dashoffset) while that agent runs. Node = role glyph +
// name + status ring (执行中 white pulse / 完成 green ✓) + 1-line mission.
// Click a node to filter the blue stream to that agent.

import { useMemo, useState } from 'react'
import type { TeamState } from '../types'

/** Sub-agent roster: role glyph + Chinese name. */
export const ROLE_META: Record<string, { zh: string; glyph: string }> = {
  orchestrator: { zh: '指挥官', glyph: '◆' },
  watcher: { zh: '哨兵', glyph: '◉' },
  analyst: { zh: '研判', glyph: '◎' },
  responder: { zh: '处置', glyph: '▣' },
  hunter: { zh: '狩猎', glyph: '⌖' },
}

export function roleZh(role: string): string {
  return ROLE_META[role]?.zh ?? role
}

const NODE_W = 150
const NODE_H = 66
const EDGE_GAP = 34
const PAD_X = 12
const PANEL_H = 110

type NodeStatus = 'idle' | 'dispatched' | 'running' | 'done'

function ChainNode({
  x,
  role,
  status,
  mission,
  selected,
  onClick,
}: {
  x: number
  role: string
  status: NodeStatus
  mission?: string
  selected: boolean
  onClick: () => void
}) {
  const meta = ROLE_META[role] ?? { zh: role, glyph: '·' }
  const ring =
    status === 'running' || status === 'dispatched'
      ? 'border-white/60'
      : status === 'done'
        ? 'border-success/50'
        : 'border-hairline'
  return (
    <button
      onClick={onClick}
      title={mission || role}
      className={`absolute flex flex-col items-start gap-0.5 rounded-xl border bg-overlay px-3 py-2
        text-left transition-colors hover:border-[#86868b] ${ring} ${
          selected ? 'bg-hover' : ''
        }`}
      style={{ left: x, top: (PANEL_H - NODE_H) / 2, width: NODE_W, height: NODE_H }}
    >
      <div className="flex w-full items-center gap-1.5">
        <span className="flex-none text-[11px] text-text-1">{meta.glyph}</span>
        <span className="truncate text-[11px] font-medium text-text-1">
          {meta.zh}
        </span>
        <span className="ml-auto flex-none">
          {status === 'running' && (
            <span className="live-pulse block h-1.5 w-1.5 rounded-full bg-white" />
          )}
          {status === 'dispatched' && (
            <span className="live-pulse block h-1.5 w-1.5 rounded-full bg-[#86868b]" />
          )}
          {status === 'done' && (
            <span className="text-[10px] text-success">✓</span>
          )}
        </span>
      </div>
      <div className="w-full truncate font-mono text-[9px] text-text-2">{role}</div>
      <div className="w-full truncate text-[9px] text-[#86868b]">
        {mission || (status === 'done' ? '已完成' : status === 'idle' ? '待命' : '…')}
      </div>
    </button>
  )
}

export function AgentChain({
  team,
  blueRunning,
  filter,
  onFilter,
}: {
  team: TeamState
  blueRunning: boolean
  filter: string
  onFilter: (f: string) => void
}) {
  const [open, setOpen] = useState(true)

  // Sub-agent nodes in spawn order: completions first (oldest), then active,
  // then roles only seen via dispatch_task edges.
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

  const statusOf = (role: string): NodeStatus => {
    if (role === 'orchestrator') return blueRunning ? 'running' : 'idle'
    if (role in team.active) return 'running'
    if (team.done.some((d) => d.role === role)) return 'done'
    if (role in team.dispatched) return 'dispatched'
    return 'idle'
  }

  const missionOf = (role: string): string | undefined =>
    team.active[role]?.mission ??
    [...team.done].reverse().find((d) => d.role === role)?.mission

  const totalW = PAD_X * 2 + (roles.length + 1) * NODE_W + roles.length * EDGE_GAP
  const runningCount = Object.keys(team.active).length

  const pick = (key: string) => onFilter(filter === key ? 'all' : key)

  return (
    <div className="flex-none border-b border-hairline bg-raised/40">
      {/* header strip — always visible, toggles the chain body */}
      <div className="flex items-center gap-2 px-3 py-1.5">
        <button
          onClick={() => setOpen((v) => !v)}
          className="flex items-center gap-1.5 text-[8px] uppercase tracking-[0.2em] text-[#636366] transition-colors hover:text-neutral-300"
        >
          <span>{open ? '▾' : '▸'}</span> 工作流 · Agent Chain
        </button>
        {runningCount > 0 && (
          <span className="flex items-center gap-1 font-mono text-[9px] text-neutral-400">
            <span className="live-pulse inline-block h-1 w-1 rounded-full bg-white" />
            {runningCount} 执行中
          </span>
        )}
        {team.done.length > 0 && (
          <span className="font-mono text-[9px] text-success/70">
            {team.done.length} 完成
          </span>
        )}
        {filter !== 'all' && (
          <button
            onClick={() => onFilter('all')}
            className="ml-auto rounded-full border border-hairline px-2 py-px font-mono text-[9px] text-neutral-400 transition-colors hover:border-[#636366] hover:text-neutral-200"
          >
            过滤 [{filter}] ✕
          </button>
        )}
      </div>

      {open && (
        <div className="scroll-thin overflow-x-auto overflow-y-hidden px-0 pb-2">
          <div className="relative" style={{ width: totalW, height: PANEL_H }}>
            {/* edges: orchestrator → each sub-agent */}
            <svg
              className="absolute inset-0"
              width={totalW}
              height={PANEL_H}
              viewBox={`0 0 ${totalW} ${PANEL_H}`}
            >
              {roles.map((role, i) => {
                const x1 = PAD_X + NODE_W
                const x2 = PAD_X + (i + 1) * (NODE_W + EDGE_GAP)
                const y = PANEL_H / 2
                const st = statusOf(role)
                const live = st === 'running' || st === 'dispatched'
                return (
                  <line
                    key={role}
                    x1={x1}
                    y1={y}
                    x2={x2}
                    y2={y}
                    stroke={live ? '#d1d1d6' : '#3a3a3c'}
                    strokeWidth={live ? 1.5 : 1}
                    strokeDasharray={live ? '5 5' : undefined}
                    className={live ? 'edge-flow' : undefined}
                  />
                )
              })}
            </svg>

            <ChainNode
              x={PAD_X}
              role="orchestrator"
              status={statusOf('orchestrator')}
              mission="红蓝对抗总指挥 · 任务派发"
              selected={filter === 'orchestrator'}
              onClick={() => pick('orchestrator')}
            />
            {roles.map((role, i) => (
              <ChainNode
                key={role}
                x={PAD_X + (i + 1) * (NODE_W + EDGE_GAP)}
                role={role}
                status={statusOf(role)}
                mission={missionOf(role)}
                selected={filter === role}
                onClick={() => pick(role)}
              />
            ))}
            {roles.length === 0 && (
              <div
                className="absolute flex items-center text-[10px] text-[#636366]"
                style={{ left: PAD_X + NODE_W + EDGE_GAP, top: 0, height: PANEL_H }}
              >
                等待指挥官 dispatch_task 派发子 Agent — watcher / analyst /
                responder / hunter
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
