// 红蓝对垒: center-axis duel timeline — RED attacks on the left, BLUE
// detections/responses on the right, system events centered. A dashed link
// connects each attack to the alert that later detected it (same technique).
// Flat Cursor style: no cards, no rounding beyond dots, 12px type.

import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { SessionDetail, SessionTimelineRow } from '../types'

// Duel palette (design-specified hex).
const RED = '#f0626f'
const AMBER = '#e8a33d'
const GREEN = '#5ec06e'
const BLUE = '#7ab2ff' // blue-team events
const GRAY = '#8a8f98'

type Side = 'left' | 'right' | 'center'

const ROW_META: Record<
  SessionTimelineRow['kind'],
  { side: Side; color: string; label: string }
> = {
  attack: { side: 'left', color: RED, label: '攻击' },
  alert: { side: 'right', color: AMBER, label: '检测' },
  response: { side: 'right', color: GREEN, label: '处置' },
  event: { side: 'center', color: GRAY, label: '系统' },
}

type Filter = 'all' | 'attack' | 'alert' | 'response'

const FILTERS: Array<{ key: Filter; label: string }> = [
  { key: 'all', label: '全部' },
  { key: 'attack', label: '攻击' },
  { key: 'alert', label: '检测' },
  { key: 'response', label: '处置' },
]

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function DuelTimeline({ detail }: { detail: SessionDetail }) {
  const [filter, setFilter] = useState<Filter>('all')

  const sorted = useMemo(
    () => [...detail.timeline].sort((a, b) => a.ts - b.ts),
    [detail.timeline],
  )
  const rows = useMemo(
    () => (filter === 'all' ? sorted : sorted.filter((r) => r.kind === filter)),
    [sorted, filter],
  )

  // attack -> alert links: same technique, alert fires strictly after.
  const links = useMemo(() => {
    const out: Array<{ from: number; to: number }> = []
    for (let i = 0; i < rows.length; i++) {
      const a = rows[i]
      if (a.kind !== 'attack' || !a.technique) continue
      const j = rows.findIndex(
        (r, k) => k > i && r.kind === 'alert' && r.technique === a.technique,
      )
      if (j !== -1) out.push({ from: i, to: j })
    }
    return out
  }, [rows])

  const scrollRef = useRef<HTMLDivElement | null>(null)
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const rowRefs = useRef<Array<HTMLDivElement | null>>([])
  const [lines, setLines] = useState<
    Array<{ x1: number; y1: number; x2: number; y2: number }>
  >([])

  // Auto-scroll to the newest (bottom) event whenever data or filter changes.
  useLayoutEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [detail, filter])

  // Measure row offsets to draw the dashed attack->alert connectors.
  useLayoutEffect(() => {
    const wrap = wrapRef.current
    if (!wrap) return
    const cx = wrap.getBoundingClientRect().width / 2
    const next = links
      .map(({ from, to }) => {
        const a = rowRefs.current[from]
        const b = rowRefs.current[to]
        if (!a || !b) return null
        return {
          x1: cx - 10,
          y1: a.offsetTop + a.offsetHeight / 2,
          x2: cx + 10,
          y2: b.offsetTop + b.offsetHeight / 2,
        }
      })
      .filter((l): l is NonNullable<typeof l> => l !== null)
    setLines((prev) =>
      prev.length === next.length &&
      prev.every(
        (l, i) =>
          l.x1 === next[i].x1 &&
          l.y1 === next[i].y1 &&
          l.x2 === next[i].x2 &&
          l.y2 === next[i].y2,
      )
        ? prev
        : next,
    )
  }, [links, rows])

  if (sorted.length === 0) {
    return <div className="py-16 text-center text-[11px] text-text-3">暂无时间线数据</div>
  }

  const content = (r: SessionTimelineRow, meta: (typeof ROW_META)['attack']) => (
    <div className="min-w-0">
      <div className="flex items-center gap-2">
        <span
          className="flex-none text-[9px] font-medium tracking-wider"
          style={{ color: meta.color }}
        >
          {meta.label}
        </span>
        <span className="truncate text-[12px] text-text-1">{r.title}</span>
        <span className="flex-none font-mono text-[9px] tabular-nums text-text-3">
          {fmtTime(r.ts)}
        </span>
        {r.kind === 'attack' && r.success !== undefined && (
          <span
            className="flex-none text-[10px]"
            style={{ color: r.success ? RED : GRAY }}
          >
            {r.success ? '✓' : '✗'}
          </span>
        )}
      </div>
      {r.detail && (
        <div className="mt-0.5 text-[10px] leading-4 text-text-3">{r.detail}</div>
      )}
      {r.technique && (
        <div className="mt-0.5 font-mono text-[9px]" style={{ color: `${meta.color}cc` }}>
          {r.technique}
        </div>
      )}
    </div>
  )

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-none items-center gap-1 border-b border-hairline px-3 py-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`rounded px-2.5 py-0.5 text-[10px] transition-colors ${
              filter === f.key ? 'bg-ink font-medium text-bg' : 'text-text-3 hover:text-fg'
            }`}
          >
            {f.label}
          </button>
        ))}
        <span className="ml-auto flex-none text-[9px] text-text-3">
          {rows.length} 个事件
        </span>
      </div>
      <div ref={scrollRef} className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div ref={wrapRef} className="relative py-2">
          {/* center axis */}
          <div className="pointer-events-none absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-hairline" />
          {/* dashed attack->alert connectors */}
          <svg
            className="pointer-events-none absolute inset-0 h-full w-full"
            style={{ overflow: 'visible' }}
          >
            {lines.map((l, i) => (
              <line
                key={i}
                x1={l.x1}
                y1={l.y1}
                x2={l.x2}
                y2={l.y2}
                stroke={BLUE}
                strokeWidth={1}
                strokeDasharray="3 3"
                opacity={0.55}
              />
            ))}
          </svg>
          {rows.length === 0 && (
            <div className="py-10 text-center text-[11px] text-text-3">无该类型事件</div>
          )}
          {rows.map((r, i) => {
            const meta = ROW_META[r.kind]
            const bind = (el: HTMLDivElement | null) => {
              rowRefs.current[i] = el
            }
            if (meta.side === 'center') {
              return (
                <div
                  key={i}
                  ref={bind}
                  className="flex items-center gap-2 px-6 py-1.5"
                >
                  <span
                    className="h-1.5 w-1.5 flex-none rounded-full"
                    style={{ background: meta.color }}
                  />
                  <div className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                    <span className="flex-none text-[9px] font-medium tracking-wider" style={{ color: meta.color }}>
                      {meta.label}
                    </span>
                    <span className="text-[12px] text-text-2">{r.title}</span>
                    <span className="flex-none font-mono text-[9px] tabular-nums text-text-3">
                      {fmtTime(r.ts)}
                    </span>
                  </div>
                  {r.detail && (
                    <span className="min-w-0 truncate text-[10px] text-text-3">
                      {r.detail}
                    </span>
                  )}
                </div>
              )
            }
            const left = meta.side === 'left'
            return (
              <div
                key={i}
                ref={bind}
                className="grid grid-cols-[1fr_14px_1fr] items-start gap-2 px-4 py-1.5"
              >
                <div className={left ? 'flex flex-col items-end text-right' : undefined}>
                  {left ? content(r, meta) : null}
                </div>
                <div className="flex justify-center pt-1.5">
                  <span
                    className="h-1.5 w-1.5 flex-none rounded-full"
                    style={{ background: meta.color }}
                  />
                </div>
                <div>{left ? null : content(r, meta)}</div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
