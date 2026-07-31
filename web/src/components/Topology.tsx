// 拓扑: compact vertical list of scenario targets with muted status dots.

import { useArena } from '../arena'
import type { HostState, TargetInfo } from '../types'
import { Panel } from './Panel'

const STATE_META: Record<HostState, { label: string; dot: string; text: string }> = {
  normal: { label: '正常', dot: 'bg-text-3', text: 'text-text-2' },
  alert: { label: '遥测告警', dot: 'bg-warning', text: 'text-warning' },
  compromised: { label: '确认失陷', dot: 'bg-attacker', text: 'text-attacker' },
  hardened: { label: '已加固', dot: 'bg-success', text: 'text-success' },
}

function TargetRow({ target }: { target: TargetInfo }) {
  const { hosts } = useArena()
  const hs = hosts[target.name]
  const state: HostState = hs?.state ?? 'normal'
  const meta = STATE_META[state]

  return (
    <div className="rounded border border-hairline bg-raised px-2.5 py-2">
      <div className="flex items-center gap-2">
        <span className={`h-1.5 w-1.5 flex-none rounded-full ${meta.dot}`} />
        <span className="truncate text-[11px] font-medium text-neutral-200">
          {target.name}
        </span>
        <span className={`ml-auto flex-none text-[9px] ${meta.text}`}>{meta.label}</span>
      </div>
      <div className="mt-1 pl-3.5 font-mono text-[9px] text-neutral-600">
        {target.ip} · {target.container}
      </div>
      <div className="mt-1 flex flex-wrap gap-1 pl-3.5">
        {target.services.map((s) => (
          <span
            key={s.name}
            className="rounded bg-overlay px-1.5 py-px font-mono text-[9px] text-neutral-500"
            title={`container:${s.container_port}`}
          >
            {s.name}:{s.host_port}
          </span>
        ))}
      </div>
      {hs?.note && (
        <div className={`mt-1 truncate pl-3.5 text-[9px] ${meta.text}`}>{hs.note}</div>
      )}
    </div>
  )
}

export function Topology() {
  const { scenario, hosts } = useArena()
  const targets = scenario?.targets ?? []
  const compromised = Object.values(hosts).filter((h) => h.state === 'compromised').length
  const alerting = Object.values(hosts).filter((h) => h.state === 'alert').length

  return (
    <Panel
      title="拓扑"
      right={
        <span className="font-mono text-[9px] normal-case tracking-normal text-neutral-600">
          {scenario?.network.subnet ?? ''}
        </span>
      }
      className="min-h-0 flex-1"
    >
      <div className="scroll-thin min-h-0 flex-1 space-y-1.5 overflow-y-auto p-3">
        {targets.map((t) => (
          <TargetRow key={t.name} target={t} />
        ))}
        {targets.length === 0 && (
          <div className="py-8 text-center text-[10px] text-neutral-600">
            等待场景加载…
          </div>
        )}
      </div>
      {/* summary + legend */}
      <div className="flex-none border-t border-hairline px-2.5 py-1.5">
        <div className="mb-1 font-mono text-[9px] text-neutral-600">
          失陷 {compromised} · 告警 {alerting} · 节点 {targets.length}
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {(Object.keys(STATE_META) as HostState[]).map((k) => (
            <div key={k} className="flex items-center gap-1">
              <span className={`h-1.5 w-1.5 rounded-full ${STATE_META[k].dot}`} />
              <span className="text-[9px] text-neutral-600">{STATE_META[k].label}</span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  )
}
