// 告警: compact list for the left rail — verdict badge, confidence bar,
// technique tag, status; click to expand evidence.

import { useState } from 'react'
import { useArena } from '../arena'
import type { AlertRow } from '../types'
import { Panel } from './Panel'

function verdictCls(v: string): string {
  const key = v.toLowerCase()
  if (key.includes('malicious')) return 'border-attacker/40 text-attacker'
  if (key.includes('suspicious')) return 'border-warning/40 text-warning'
  if (key.includes('benign')) return 'border-success/40 text-success'
  return 'border-hairline text-text-2'
}

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function AlertCard({ alert }: { alert: AlertRow }) {
  const [open, setOpen] = useState(false)
  const conf = Math.round((alert.confidence || 0) * 100)
  return (
    <div
      className="cursor-pointer rounded border border-hairline bg-raised px-2 py-1.5 transition-colors hover:border-neutral-600"
      onClick={() => setOpen((v) => !v)}
    >
      <div className="flex items-center gap-1.5">
        <span className={`flex-none rounded border px-1 py-px text-[9px] ${verdictCls(alert.verdict)}`}>
          {alert.verdict || 'unknown'}
        </span>
        {alert.technique && (
          <span className="flex-none rounded bg-overlay px-1 py-px text-[9px] text-neutral-400">
            {alert.technique}
          </span>
        )}
        <span className="truncate font-mono text-[10px] text-neutral-300">{alert.host}</span>
        <span
          className={`ml-auto flex-none text-[9px] ${
            alert.status === 'open' ? 'text-warning' : 'text-success'
          }`}
        >
          {alert.status}
        </span>
      </div>
      <div className="mt-1.5 flex items-center gap-2">
        <div className="h-px flex-1 bg-neutral-800">
          <div
            className={`h-full ${
              conf >= 70 ? 'bg-attacker' : conf >= 40 ? 'bg-warning' : 'bg-text-3'
            }`}
            style={{ width: `${Math.min(conf, 100)}%` }}
          />
        </div>
        <span className="font-mono text-[9px] tabular-nums text-neutral-600">
          {conf}% · {fmtTime(alert.ts)}
        </span>
      </div>
      {open && (
        <pre className="scroll-thin mt-1.5 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded border border-hairline bg-ink p-2 font-mono text-[10px] leading-4 text-neutral-400">
          {alert.evidence || '(no evidence)'}
          {alert.source_tool ? `\n\n[source: ${alert.source_tool}]` : ''}
        </pre>
      )}
    </div>
  )
}

export function AlertsPanel() {
  const { alerts } = useArena()
  const openCount = alerts.filter((a) => a.status === 'open').length
  return (
    <Panel
      title="告警"
      right={
        <span className="font-mono text-[9px] normal-case tracking-normal text-neutral-600">
          {alerts.length} 条{openCount > 0 ? ` · ${openCount} open` : ''}
        </span>
      }
      className="min-h-0 flex-1"
    >
      <div className="scroll-thin min-h-0 flex-1 space-y-1.5 overflow-y-auto p-3">
        {alerts.map((a) => (
          <AlertCard key={a.id} alert={a} />
        ))}
        {alerts.length === 0 && (
          <div className="py-8 text-center text-[10px] text-neutral-600">
            暂无告警 — 蓝方 report_finding 后出现
          </div>
        )}
      </div>
    </Panel>
  )
}
