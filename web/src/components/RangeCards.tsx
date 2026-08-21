// RangeCards — 作战台顶部三张靶场卡片(web_basic / web_plus / ad_domain)。
// 仅负责场景选择；红蓝启停统一由 OpsConsole 控制，避免「一键启动」与
// 「一任务一靶机环境」语义冲突。
import { useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { pushToast } from '../toasts'

interface RangeSpec {
  id: string
  name: string
  tagline: string
}

const RANGES: RangeSpec[] = [
  {
    id: 'web_basic',
    name: 'Web 基础',
    tagline: 'DVWA + 弱口令 SSH + Log4Shell Solr,默认 3 靶机',
  },
  {
    id: 'web_plus',
    name: 'Web 加强',
    tagline: '基础之上叠加 WebGoat + VAmPI,扩展 5 靶机',
  },
  {
    id: 'ad_domain',
    name: 'AD 域',
    tagline: 'Samba4 AD,AS-REP / Kerberoasting / ADCS / 委派',
  },
]

export function RangeCards() {
  const { status, scenario, refreshStatus, refreshScenario } = useArena()
  const [busy, setBusy] = useState<string | null>(null)
  const active = status.session_active
  const currentId = scenario?.name ?? status.scenario ?? ''

  const switchTo = async (id: string) => {
    if (busy) return
    if (id === currentId) return
    setBusy(id)
    try {
      await api.selectScenario(id)
      await refreshScenario()
      await refreshStatus()
    } catch (e) {
      pushToast(`切换靶场失败：${e instanceof Error ? e.message : String(e)}`, {
        title: '作战台',
      })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div
      className="flex flex-none gap-2 overflow-x-auto border-b px-3 py-2"
      style={{ borderColor: 'var(--color-hairline)' }}
    >
      {RANGES.map((r) => {
        const isCurrent = r.id === currentId
        const isRunning = isCurrent && active
        const ringStyle = isCurrent
          ? { borderColor: 'var(--color-accent)', background: 'var(--color-bg-2)' }
          : { borderColor: 'var(--color-hairline)', background: 'var(--color-bg-2)' }
        const statusLabel = isRunning ? '● 运行中' : isCurrent ? '◐ 已选中' : '○ 未启动'
        const statusColor = isRunning
          ? 'var(--color-green)'
          : isCurrent
            ? 'var(--color-accent)'
            : 'var(--color-fg-4)'
        return (
          <div
            key={r.id}
            role="button"
            tabIndex={0}
            onClick={() => void switchTo(r.id)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                void switchTo(r.id)
              }
            }}
            className="min-w-[200px] cursor-pointer border px-3 py-2 transition-colors"
            style={ringStyle}
            title={`选中 ${r.name}（不启动；红蓝启停请用 OpsConsole）`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
                {r.name}
              </span>
              <span
                className="font-mono text-[10px]"
                style={{ color: statusColor }}
              >
                {statusLabel}
              </span>
            </div>
            <div
              className="mt-0.5 font-mono text-[10px]"
              style={{ color: 'var(--color-fg-4)' }}
            >
              {r.id}
            </div>
            <div
              className="mt-1 truncate text-[11px]"
              style={{ color: 'var(--color-fg-3)' }}
              title={r.tagline}
            >
              {r.tagline}
            </div>
            <div
              className="mt-1 truncate font-mono text-[10px]"
              style={{ color: 'var(--color-fg-4)' }}
            >
              {isCurrent ? '点击重新选择或到 OpsConsole 启红蓝' : '点击选中'}
            </div>
          </div>
        )
      })}
    </div>
  )
}