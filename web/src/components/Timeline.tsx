// 事件时间线: dense reverse-chronological merged live feed for the right rail.

import { useEffect, useMemo, useRef, useState } from 'react'
import { useArena } from '../arena'
import type { TimelineItem, TimelineKind } from '../types'
import { Panel } from './Panel'

const KIND_META: Record<TimelineKind, { label: string; cls: string; dot: string }> = {
  attack: { label: '攻击', cls: 'border-attacker/40 text-attacker', dot: 'bg-attacker' },
  telemetry: { label: '遥测', cls: 'border-warning/40 text-warning', dot: 'bg-warning' },
  alert: { label: '告警', cls: 'border-hairline text-text-1', dot: 'bg-defender' },
  response: { label: '处置', cls: 'border-success/40 text-success', dot: 'bg-success' },
  team: { label: '团队', cls: 'border-hairline text-[#ececf0]', dot: 'bg-white' },
  system: { label: '系统', cls: 'border-hairline text-text-2', dot: 'bg-text-3' },
}

const SEV_CLS: Record<string, string> = {
  critical: 'text-attacker',
  high: 'text-warning',
  medium: 'text-warning/70',
  low: 'text-text-2',
  info: 'text-text-3',
}

const FILTERS: Array<{ key: TimelineKind | 'all'; label: string }> = [
  { key: 'all', label: '全部' },
  { key: 'attack', label: '攻击' },
  { key: 'telemetry', label: '遥测' },
  { key: 'alert', label: '告警' },
  { key: 'response', label: '处置' },
  { key: 'team', label: '团队' },
  { key: 'system', label: '系统' },
]

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function Item({ item }: { item: TimelineItem }) {
  const [open, setOpen] = useState(false)
  const meta = KIND_META[item.kind]
  return (
    <div
      className="cursor-pointer border-b border-hairline/60 px-2.5 py-1.5 transition-colors hover:bg-overlay/60"
      onClick={() => setOpen((v) => !v)}
    >
      <div className="flex items-center gap-1.5">
        <span className={`h-1.5 w-1.5 flex-none rounded-full ${meta.dot}`} />
        <span className="flex-none font-mono text-[9px] tabular-nums text-[#86868b]">
          {fmtTime(item.ts)}
        </span>
        <span className={`flex-none rounded border px-1 py-px text-[9px] ${meta.cls}`}>
          {meta.label}
        </span>
        {item.severity && (
          <span className={`flex-none text-[9px] uppercase ${SEV_CLS[item.severity] ?? SEV_CLS.info}`}>
            {item.severity}
          </span>
        )}
        {item.kind === 'attack' && item.success !== undefined && (
          <span className={`flex-none text-[10px] ${item.success ? 'text-attacker' : 'text-neutral-600'}`}>
            {item.success ? '✓' : '✗'}
          </span>
        )}
      </div>
      <div className="mt-0.5 truncate pl-3 text-[12px] text-[#ececf0]">{item.title}</div>
      {item.detail && (
        <div className="mt-0.5 truncate pl-3 text-[10px] text-[#86868b]">
          {item.detail}
        </div>
      )}
      {open && item.raw && (
        <pre className="scroll-thin mt-1.5 max-h-48 overflow-auto rounded border border-hairline bg-ink p-2 font-mono text-[10px] leading-4 text-[#c7c7cc]">
          {JSON.stringify(item.raw, null, 2)}
        </pre>
      )}
    </div>
  )
}

export function Timeline() {
  const { timeline } = useArena()
  const [filter, setFilter] = useState<TimelineKind | 'all'>('all')
  const [autoScroll, setAutoScroll] = useState(true)
  const boxRef = useRef<HTMLDivElement>(null)

  const items = useMemo(
    () => (filter === 'all' ? timeline : timeline.filter((t) => t.kind === filter)),
    [timeline, filter],
  )

  useEffect(() => {
    if (autoScroll && boxRef.current) boxRef.current.scrollTop = 0
  }, [items.length, autoScroll])

  return (
    <Panel
      title="事件时间线"
      className="min-h-0 flex-1"
      right={
        <label className="flex cursor-pointer items-center gap-1 text-[9px] normal-case tracking-normal text-neutral-600">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="h-3 w-3 accent-neutral-500"
          />
          自动滚动
        </label>
      }
    >
      {/* filter chips */}
      <div className="flex flex-none flex-wrap items-center gap-1 border-b border-hairline px-2 py-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`rounded border px-1.5 py-px text-[9px] transition-colors ${
              filter === f.key
                ? 'border-neutral-500 bg-overlay text-neutral-200'
                : 'border-hairline text-neutral-600 hover:border-neutral-600 hover:text-neutral-400'
            }`}
          >
            {f.label}
          </button>
        ))}
        <span className="ml-auto font-mono text-[9px] text-neutral-700">
          {items.length}
        </span>
      </div>
      <div ref={boxRef} className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        {items.map((it) => (
          <Item key={it.id} item={it} />
        ))}
        {items.length === 0 && (
          <div className="py-16 text-center text-[10px] text-neutral-600">
            暂无事件 — 启动会话后此处滚动显示攻击 / 遥测 / 告警 / 处置
          </div>
        )}
      </div>
    </Panel>
  )
}
