// AgentDetailModal — 角色档案弹窗
// v1 蓝队：状态条 · 职责/调用条件/输出规范/通信逻辑 · System Prompt · 工具详解。
// v2 红蓝：职责 · 工具列表 · ATT&CK 技术映射（数据来自前端 RED_V2_ROLES/BLUE_V2_ROLES）。
import { useEffect, useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { v2RoleColor, v2RoleOf, RED_V2_ROLES, BLUE_V2_ROLES } from '../types'
import type { AgentRoleSpec, V2Role } from '../types'
import { Modal } from './Modal'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
        {title}
      </div>
      {children}
    </div>
  )
}

/** v2 角色运行状态：从 team/status 推断（红队看 red_running，蓝队看 team 派遣）。 */
function useV2RoleState(role: V2Role) {
  const { team, status } = useArena()
  const isOrchestrator = role.key === 'orchestrator'
  const running = Object.values(team.active).filter((a) => a.role === role.key)
  const dispatched = team.dispatched[role.key]
  const reports = team.done.filter((d) => d.role === role.key)
  const doneErr = reports.filter((d) => d.error).length

  let stateLabel: string
  let stateColor: string
  if (isOrchestrator) {
    const active =
      role.side === 'red'
        ? status.red_running
        : Object.keys(team.active).length > 0 ||
          Object.keys(team.dispatched).length > 0 ||
          status.blue_running
    stateLabel = active ? '运行中' : '空闲'
    stateColor = active ? 'var(--color-amber)' : 'var(--color-fg-4)'
  } else if (running.length > 0) {
    stateLabel = '运行中'
    stateColor = 'var(--color-amber)'
  } else if (dispatched) {
    stateLabel = '派遣中'
    stateColor = 'var(--color-amber)'
  } else if (reports.length > 0) {
    stateLabel = reports[reports.length - 1].error ? '出错' : '已完成'
    stateColor = reports[reports.length - 1].error ? 'var(--color-red)' : 'var(--color-green)'
  } else {
    stateLabel = '空闲'
    stateColor = 'var(--color-fg-4)'
  }
  return { stateLabel, stateColor, reports, doneErr }
}

/** v2 角色档案主体：职责 + 工具列表 + ATT&CK 技术映射。 */
function V2RoleBody({ role }: { role: V2Role }) {
  const { stateLabel, stateColor, reports, doneErr } = useV2RoleState(role)
  const color = v2RoleColor(role.colorVar)
  const sideLabel = role.side === 'red' ? '红队 v2' : '蓝队 v2'
  const sideColor = role.side === 'red' ? 'var(--color-red)' : 'var(--color-blue)'

  return (
    <div className="scroll-thin max-h-[75vh] space-y-4 overflow-y-auto pr-1">
      {/* 状态条 */}
      <div className="flex items-center gap-2 border-b pb-2" style={{ borderColor: 'var(--color-hairline)' }}>
        <span
          className="dot"
          style={{
            background: stateColor,
            boxShadow: stateLabel === '运行中' || stateLabel === '派遣中' ? `0 0 5px ${stateColor}` : 'none',
          }}
        />
        <span className="text-[11px] font-semibold" style={{ color: stateColor }}>{stateLabel}</span>
        <span className="text-[10.5px]" style={{ color: sideColor }}>{sideLabel}</span>
        <span className="ml-auto font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
          完成 {reports.length}{doneErr > 0 ? ` · 出错 ${doneErr}` : ''}
        </span>
      </div>

      {/* 职责 */}
      <Section title="职责与特殊之处">
        <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>{role.duty}</div>
      </Section>

      {/* 工具列表 */}
      <Section title={`工具列表（${role.tools.length}）`}>
        <div className="flex flex-wrap gap-1.5">
          {role.tools.map((t) => (
            <span
              key={t}
              className="kimi-toolcard"
              style={{ color, background: `color-mix(in srgb, ${color} 12%, transparent)`, borderColor: 'transparent' }}
            >
              {t}
            </span>
          ))}
        </div>
      </Section>

      {/* ATT&CK 技术映射 */}
      <Section title={`ATT&CK 技术映射（${role.techniques.length}）`}>
        <div className="space-y-1">
          {role.techniques.map((tc) => {
            const idx = tc.indexOf(' ')
            const id = idx > 0 ? tc.slice(0, idx) : tc
            const name = idx > 0 ? tc.slice(idx + 1) : ''
            return (
              <div key={tc} className="flex items-baseline gap-2 border-l-2 pl-3" style={{ borderColor: color }}>
                <span className="font-mono text-[11px] font-semibold" style={{ color }}>{id}</span>
                <span className="text-[11px]" style={{ color: 'var(--color-fg-2)' }}>{name}</span>
              </div>
            )
          })}
        </div>
      </Section>
    </div>
  )
}

export function AgentDetailModal({ roleKey, onClose, v2: v2Mode = false, side }: { roleKey: string; onClose: () => void; v2?: boolean; side?: 'red' | 'blue' }) {
  // v2 角色：走前端常量档案，无需后端 /api/agents/roles。
  let v2: V2Role | undefined
  if (v2Mode) {
    if (side === 'red') v2 = RED_V2_ROLES.find((r) => r.key === roleKey)
    else if (side === 'blue') v2 = BLUE_V2_ROLES.find((r) => r.key === roleKey)
    else v2 = v2RoleOf(roleKey)
  }
  if (v2) {
    return (
      <Modal title={`${v2.name} agent · v2 角色档案`} onClose={onClose} width="w-[720px]">
        <V2RoleBody role={v2} />
      </Modal>
    )
  }
  // v1 蓝队角色：原有逻辑，从 /api/agents/roles 加载完整档案。
  return <V1RoleDetail roleKey={roleKey} onClose={onClose} />
}

/** v1 蓝队角色档案（保留原有逻辑：System Prompt + 工具详解）。 */
function V1RoleDetail({ roleKey, onClose }: { roleKey: string; onClose: () => void }) {
  const { team, status } = useArena()
  const [specs, setSpecs] = useState<AgentRoleSpec[] | null>(null)
  const [promptOpen, setPromptOpen] = useState(false)

  useEffect(() => {
    let stale = false
    api.getAgentRoles().then((rs) => {
      if (!stale) setSpecs(rs)
    }).catch(() => {})
    return () => { stale = true }
  }, [])

  const spec = specs?.find((s) => s.key === roleKey)
  if (!spec) {
    return (
      <Modal title="Agent 详情" onClose={onClose} width="w-[640px]">
        <div className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>角色档案加载中…</div>
      </Modal>
    )
  }

  const isOrchestrator = spec.key === 'orchestrator'
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
    <Modal title={`${spec.name} agent · 角色档案`} onClose={onClose} width="w-[720px]">
      <div className="scroll-thin max-h-[75vh] space-y-4 overflow-y-auto pr-1">
        <div className="flex items-center gap-2 border-b pb-2" style={{ borderColor: 'var(--color-hairline)' }}>
          <span className="dot" style={{ background: stateColor, boxShadow: stateLabel === '运行中' ? `0 0 5px ${stateColor}` : 'none' }} />
          <span className="text-[11px] font-semibold" style={{ color: stateColor }}>{stateLabel}</span>
          {mission && (
            <span className="truncate text-[10.5px]" style={{ color: 'var(--color-fg-3)' }}>
              当前任务：{mission}
            </span>
          )}
          <span className="ml-auto font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
            完成 {reports.length}{doneErr > 0 ? ` · 出错 ${doneErr}` : ''}
          </span>
        </div>

        <Section title="职责与特殊之处">
          <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>{spec.duty}</div>
        </Section>
        <Section title="什么条件下被调用">
          <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>{spec.invocation}</div>
        </Section>
        <Section title="输出规范">
          <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>{spec.output}</div>
        </Section>
        <Section title="通信逻辑">
          <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>{spec.comms}</div>
        </Section>

        <Section title="System Prompt（原文）">
          <button
            onClick={() => setPromptOpen((v) => !v)}
            className="rounded px-2 py-0.5 text-[10.5px] transition-colors hover:bg-[var(--color-overlay)]"
            style={{ color: 'var(--color-fg-3)' }}
          >
            {promptOpen ? '▾ 收起' : `▸ 展开（${spec.system_prompt.length} 字符）`}
          </button>
          {promptOpen && (
            <pre className="scroll-thin mt-1.5 max-h-[320px] overflow-auto whitespace-pre-wrap break-words border-l-2 pl-3 font-mono text-[10.5px] leading-[1.6]" style={{ borderColor: 'var(--color-line)', color: 'var(--color-fg-2)' }}>
              {spec.system_prompt}
            </pre>
          )}
        </Section>

        <Section title={`工具详解（${spec.tools.length}）`}>
          <div className="space-y-2">
            {spec.tools.map((t) => (
              <div key={t.name} className="border-l-2 pl-3" style={{ borderColor: 'var(--color-line)' }}>
                <div className="font-mono text-[11.5px] font-semibold" style={{ color: 'var(--color-tool)' }}>
                  {t.name}
                </div>
                {t.description && (
                  <div className="mt-0.5 text-[11px] leading-5" style={{ color: 'var(--color-fg-2)' }}>
                    {t.description}
                  </div>
                )}
                {t.params.length > 0 && (
                  <table className="mt-1 w-full text-[10.5px]">
                    <tbody>
                      {t.params.map((p) => (
                        <tr key={p.name} className="align-baseline">
                          <td className="w-32 py-px pr-2 font-mono" style={{ color: 'var(--color-fg-3)' }}>
                            {p.name}
                            <span className="ml-1" style={{ color: 'var(--color-fg-4)' }}>{p.type}</span>
                          </td>
                          <td className="py-px" style={{ color: 'var(--color-fg-2)' }}>
                            {p.desc}
                            {p.default !== undefined && p.default !== '' && (
                              <span className="ml-1 font-mono" style={{ color: 'var(--color-fg-4)' }}>
                                默认 {String(p.default)}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            ))}
          </div>
        </Section>
      </div>
    </Modal>
  )
}
