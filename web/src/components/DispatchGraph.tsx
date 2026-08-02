// DispatchGraph — 蓝方派遣链路（紧凑版）
// 竖向结构：标题行 → 指挥官行 → 分叉连线 → 四角色一行。
// 全部节点可点击打开 AgentDetailModal；角色状态 = 空闲/派遣中/运行中/完成/出错。
import { useState } from 'react'
import { useArena } from '../arena'
import { BLUE_ROLES } from '../types'
import type { TeamState } from '../types'
import { AgentDetailModal } from './AgentDetailModal'

type RoleStatus = 'idle' | 'dispatching' | 'running' | 'done' | 'error'

interface RoleMeta { key: string; label: string; color: string; glyph: string }

const ROLES: RoleMeta[] = BLUE_ROLES.filter((r) => r.key !== 'orchestrator').map((r) => ({
  key: r.key,
  label: r.name,
  color: r.colorVar,
  glyph: r.key === 'orchestrator' ? '指' : r.key.slice(0, 1),
}))

function roleStatus(role: string, team: TeamState): RoleStatus {
  const activeKeys = Object.keys(team.active).filter((k) => team.active[k].role === role)
  if (activeKeys.length > 0) return 'running'
  if (team.dispatched[role]) return 'dispatching'
  const dones = team.done.filter((d) => d.role === role)
  if (dones.length > 0) return dones[dones.length - 1].error ? 'error' : 'done'
  return 'idle'
}

function statusLabel(s: RoleStatus): string {
  return { running: '运行中', dispatching: '派遣中', done: '完成', error: '出错', idle: '空闲' }[s]
}
function statusColor(s: RoleStatus): string {
  if (s === 'running' || s === 'dispatching') return 'var(--color-amber)'
  if (s === 'done') return 'var(--color-green)'
  if (s === 'error') return 'var(--color-red)'
  return 'var(--color-fg-4)'
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
    <section className="panel flex flex-none flex-col">
      {/* 标题行 */}
      <div className="flex flex-none items-center gap-2 px-3 py-1.5">
        <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
          蓝方团队
        </span>
        <span className="eyebrow">派遣链路</span>
        <span className="ml-auto flex items-center gap-2">
          {errCount > 0 && (
            <span className="chip" style={{ color: 'var(--color-red)', background: 'var(--color-red-soft)' }}>
              {errCount} 出错
            </span>
          )}
          {team.done.length > 0 && (
            <span className="chip" style={{ color: 'var(--color-green)', background: 'var(--color-green-soft)' }}>
              ✓ {team.done.length}
            </span>
          )}
          {blueRunning && (
            <span className="flex items-center gap-1.5 text-[11.5px] font-medium" style={{ color: 'var(--color-amber)' }}>
              <span className="live-pulse dot" style={{ background: 'var(--color-amber)' }} />
              指挥中
            </span>
          )}
        </span>
      </div>

      {/* 指挥官行 */}
      <div className="flex flex-none items-center gap-3 px-3">
        <button
          role="button"
          onClick={() => setDetail('orchestrator')}
          className="flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-1.5 transition-colors hover:bg-[var(--color-panel-2)]"
          style={{
            borderColor: orchestratorActive ? 'var(--color-cmd)' : 'var(--color-line)',
            background: orchestratorActive ? 'var(--color-panel-2)' : 'var(--color-panel)',
          }}
          title="查看 调度指挥 详情"
        >
          <span
            className="flex h-[22px] w-[22px] items-center justify-center rounded-full text-[11px] font-bold text-[#161616]"
            style={{ background: 'var(--color-cmd)', boxShadow: orchestratorActive ? '0 0 10px var(--color-cmd)' : 'none' }}
          >
            指
          </span>
          <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>调度指挥</span>
          <span className="flex items-center gap-1 text-[11px]" style={{ color: statusColor(orchestratorActive ? 'running' : 'idle') }}>
            {orchestratorActive && <span className="live-pulse dot" style={{ background: 'var(--color-amber)' }} />}
            {orchestratorActive ? '调度中' : '空闲'}
          </span>
        </button>

        {/* 分叉连线 */}
        <svg width="60" height="18" viewBox="0 0 60 18" className="flex-none" aria-hidden>
          {ROLES.map((r, i) => {
            const x = 34 + (i * 26) / (ROLES.length - 1)
            return (
              <path
                key={r.key}
                d={`M0 9 C 12 9, 12 9, ${x - 6} ${9 - (i % 2) * 2} L ${x} ${9 - (i % 2) * 2}`}
                stroke="var(--color-line-2)"
                strokeWidth="1"
                fill="none"
                opacity="0.6"
              />
            )
          })}
        </svg>
      </div>

      {/* 四角色一行 */}
      <div className="flex flex-none gap-2 px-3 pb-2.5 pt-1">
        {ROLES.map((r) => {
          const st = roleStatus(r.key, team)
          const active = st === 'running' || st === 'dispatching'
          return (
            <button
              key={r.key}
              role="button"
              onClick={() => setDetail(r.key)}
              className="flex min-w-0 flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-lg border px-2 py-1.5 transition-colors hover:bg-[var(--color-panel-2)]"
              style={{
                borderColor: active ? r.color : 'var(--color-line)',
                background: active ? 'var(--color-panel-2)' : 'var(--color-panel)',
              }}
              title={`查看 ${r.label} 详情`}
            >
              <span
                className="flex h-[18px] w-[18px] flex-none items-center justify-center rounded-full text-[10px] font-bold text-white"
                style={{ background: r.color, boxShadow: active ? `0 0 6px ${r.color}` : 'none' }}
              >
                {r.glyph}
              </span>
              <span className="truncate text-[12px] font-medium" style={{ color: 'var(--color-fg)' }}>
                {r.label}
              </span>
              <span className="flex flex-none items-center gap-1 text-[10.5px]" style={{ color: statusColor(st) }}>
                {active && <span className="live-pulse dot" style={{ background: statusColor(st) }} />}
                {statusLabel(st)}
              </span>
            </button>
          )
        })}
      </div>

      {detail && <AgentDetailModal roleKey={detail} onClose={() => setDetail(null)} />}
    </section>
  )
}
