// AgentDetailModal — 蓝队角色完整档案弹窗
// 章节：状态条 · 职责/调用条件/输出规范/通信逻辑 · System Prompt（原文）·
// 工具详解（概述 + 参数级 schema）。数据来自 GET /api/agents/roles
// （后端从 blue_team._ROLE_SPECS 提取的真实 system prompt 与工具定义）。
import { useEffect, useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import type { AgentRoleSpec } from '../types'
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

export function AgentDetailModal({ roleKey, onClose }: { roleKey: string; onClose: () => void }) {
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
    // 档案未加载：至少展示基本状态，不阻塞。
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
        {/* 状态条 */}
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

        {/* 职责与调用条件 */}
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

        {/* System Prompt 原文 */}
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

        {/* 工具详解 */}
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
