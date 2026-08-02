// AgentDetailModal — 蓝队角色详情弹窗（portal 到 body 的 Modal）。
// 展示：职责 duty / 负责范围 scope / 工具列表（英文原名 — 中文说明）/
// 当前状态（运行中·显示当前 mission / 派遣中 / 空闲）+ 已完成报告数。
// 角色数据一律取自 BLUE_ROLES（唯一事实源），状态由 useArena 的 team 计算。
import { useArena } from '../arena'
import { blueRoleOf } from '../types'
import { Modal } from './Modal'

export function AgentDetailModal({ roleKey, onClose }: { roleKey: string; onClose: () => void }) {
  const { team, status } = useArena()
  const role = blueRoleOf(roleKey)
  if (!role) return null

  const isOrchestrator = role.key === 'orchestrator'
  const running = Object.values(team.active).filter((a) => a.role === roleKey)

  let stateLabel: string
  let stateColor: string
  let mission: string | undefined
  if (isOrchestrator) {
    const active = Object.keys(team.active).length > 0 || Object.keys(team.dispatched).length > 0 || status.blue_running
    stateLabel = active ? '运行中' : '空闲'
    stateColor = active ? 'var(--color-amber)' : 'var(--color-fg-4)'
  } else if (running.length > 0) {
    stateLabel = '运行中'
    stateColor = 'var(--color-amber)'
    mission = running[0].mission
    if (running.length > 1) mission += `（并行 ×${running.length}）`
  } else if (team.dispatched[roleKey]) {
    stateLabel = '派遣中'
    stateColor = 'var(--color-amber)'
  } else {
    stateLabel = '空闲'
    stateColor = 'var(--color-fg-4)'
  }

  const reports = team.done.filter((d) => d.role === roleKey)
  const doneErr = reports.filter((d) => d.error).length

  return (
    <Modal title={`${role.name}（${role.key}）`} onClose={onClose} width="w-[560px]">
      <div className="flex flex-col gap-4">
        {/* 状态条：当前状态（运行中带当前任务）+ 已完成报告数 */}
        <div
          className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg px-3 py-2 font-mono text-[11px]"
          style={{
            background: 'var(--color-panel)',
            border: '1px solid var(--color-line)',
            borderLeft: `2px solid ${role.colorVar}`,
          }}
        >
          <span className="flex items-center gap-1.5" style={{ color: stateColor }}>
            {stateLabel !== '空闲' && (
              <span className="live-pulse inline-block h-1.5 w-1.5 rounded-full" style={{ background: stateColor }} />
            )}
            状态：{stateLabel}
          </span>
          {mission && <span style={{ color: 'var(--color-fg-3)' }}>任务：{mission}</span>}
          <span className="ml-auto" style={{ color: 'var(--color-fg-3)' }}>
            报告：
            <span style={{ color: doneErr > 0 ? 'var(--color-red)' : 'var(--color-green)' }}>
              {reports.length}
            </span>
            {doneErr > 0 && <span style={{ color: 'var(--color-red)' }}>（{doneErr} 出错）</span>}
          </span>
        </div>

        {/* 职责 */}
        <div>
          <div className="eyebrow mb-1">职责</div>
          <p className="text-[12.5px] leading-relaxed" style={{ color: 'var(--color-fg-2)' }}>{role.duty}</p>
        </div>

        {/* 负责范围 */}
        <div>
          <div className="eyebrow mb-1">负责范围</div>
          <p className="text-[12.5px]" style={{ color: 'var(--color-fg-2)' }}>{role.scope}</p>
        </div>

        {/* 工具列表 */}
        <div>
          <div className="eyebrow mb-1">工具（{role.tools.length}）</div>
          <ul className="flex flex-col gap-1">
            {role.tools.map((t) => (
              <li
                key={t.name}
                className="flex items-baseline gap-2 rounded border px-2.5 py-1.5"
                style={{ borderColor: 'var(--color-line)', background: 'var(--color-panel)' }}
              >
                <code className="font-mono text-[11px]" style={{ color: 'var(--color-cyan)' }}>{t.name}</code>
                <span className="text-[11px]" style={{ color: 'var(--color-fg-4)' }}>—</span>
                <span className="min-w-0 flex-1 text-[11.5px]" style={{ color: 'var(--color-fg-2)' }}>{t.desc}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Modal>
  )
}
