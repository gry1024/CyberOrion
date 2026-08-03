// DispatchGraph — 蓝方派遣状态条（Cursor 式：一行平铺，无卡片）
// 指挥官 + 四角色：人像头像 + 名称（agent 后缀）+ 状态点，
// 点击打开 AgentDetailModal —— 每个角色是可随时调用的 sub-agent。
import { useState } from 'react'
import { useArena } from '../arena'
import { BLUE_ROLES } from '../types'
import type { TeamState } from '../types'
import { AgentDetailModal } from './AgentDetailModal'

type RoleStatus = 'idle' | 'dispatching' | 'running' | 'done' | 'error'

const ROLES = BLUE_ROLES.filter((r) => r.key !== 'orchestrator').map((r) => ({
  key: r.key,
  label: r.name,
  color: r.colorVar,
}))

function roleStatus(role: string, team: TeamState): RoleStatus {
  if (Object.keys(team.active).some((k) => team.active[k].role === role)) return 'running'
  if (team.dispatched[role]) return 'dispatching'
  const dones = team.done.filter((d) => d.role === role)
  if (dones.length > 0) return dones[dones.length - 1].error ? 'error' : 'done'
  return 'idle'
}

function statusColor(s: RoleStatus): string {
  if (s === 'running' || s === 'dispatching') return 'var(--color-amber)'
  if (s === 'done') return 'var(--color-green)'
  if (s === 'error') return 'var(--color-red)'
  return 'var(--color-fg-4)'
}

/** 人像头像：角色色圆底 + 白色人像剪影。 */
function Persona({ color, size = 16 }: { color: string; size?: number }) {
  return (
    <span
      className="flex flex-none select-none items-center justify-center rounded-full"
      style={{ width: size, height: size, background: color }}
    >
      <svg viewBox="0 0 24 24" width={size * 0.62} height={size * 0.62} fill="none" aria-hidden>
        <circle cx="12" cy="8.6" r="3.6" fill="#fff" />
        <path d="M4.5 21c0-4.2 3.4-6.6 7.5-6.6s7.5 2.4 7.5 6.6z" fill="#fff" />
      </svg>
    </span>
  )
}

export function DispatchGraph() {
  const { team, status } = useArena()
  const [detail, setDetail] = useState<string | null>(null)
  const blueRunning = status.blue_running
  const orchestratorActive =
    Object.keys(team.active).length > 0 ||
    Object.keys(team.dispatched).length > 0 ||
    blueRunning
  const errCount = team.done.filter((d) => d.error).length

  return (
    <div className="flex flex-none flex-wrap items-center gap-x-3 gap-y-0.5 border-b px-2 py-1" style={{ borderColor: 'var(--color-hairline)' }}>
      {/* 指挥官 */}
      <button
        onClick={() => setDetail('orchestrator')}
        className="flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11.5px] transition-colors hover:bg-[var(--color-overlay)]"
        style={{ color: orchestratorActive ? 'var(--color-amber)' : 'var(--color-fg-2)' }}
      >
        <Persona color={orchestratorActive ? 'var(--color-amber)' : 'var(--color-fg-4)'} />
        调度指挥 agent
      </button>
      {ROLES.map((r) => {
        const st = roleStatus(r.key, team)
        return (
          <button
            key={r.key}
            onClick={() => setDetail(r.key)}
            className="flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11.5px] transition-colors hover:bg-[var(--color-overlay)]"
            style={{ color: 'var(--color-fg-2)' }}
          >
            <Persona color={r.color} />
            {r.label} agent
            <span className="dot" style={{ background: statusColor(st), boxShadow: st === 'running' || st === 'dispatching' ? `0 0 4px ${statusColor(st)}` : 'none' }} />
          </button>
        )
      })}
      {errCount > 0 && (
        <span className="text-[10.5px]" style={{ color: 'var(--color-red)' }}>{errCount} 出错</span>
      )}
      {team.done.length > 0 && (
        <span className="text-[10.5px]" style={{ color: 'var(--color-green)' }}>✓ {team.done.length}</span>
      )}
      {detail && <AgentDetailModal roleKey={detail} onClose={() => setDetail(null)} />}
    </div>
  )
}
