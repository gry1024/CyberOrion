// 历史 tab: full-page session replay — left session list, right detail with
// 1) AI 复盘 (auto-generated, no manual trigger needed)
// 2) 战役统计 strip
// 3) tabbed: 红蓝对垒 / 时间线(分页+颜色优化) / 工具调用 / 报告
// "告警与攻击" tab 已移除（storyline 自动生成后不再需要）。

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { pushToast } from '../toasts'
import { Modal } from './Modal'
import type {
  ScoreMetrics,
  SessionDetail,
  SessionInfo,
  SessionTimelineRow,
  SessionToolCall,
} from '../types'
import { MarkdownView } from './MarkdownView'
import { FadeIn } from './FadeIn'
import { DuelTimeline } from './DuelTimeline'

function fmtMtime(mtime: number): string {
  const d = new Date(mtime * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// ---------------------------------------------------------------------------
// AI 复盘 (storyline) — 自动显示，无需手动触发
// ---------------------------------------------------------------------------

function StorylineSection({
  sessionId,
  initial,
}: {
  sessionId: string
  initial: string | null
}) {
  const [md, setMd] = useState<string | null>(initial)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(false)
  const pollRef = useRef<number | null>(null)

  useEffect(() => {
    setMd(initial)
    setGenerating(false)
    setError('')
    if (pollRef.current !== null) window.clearInterval(pollRef.current)
    pollRef.current = null
  }, [sessionId, initial])

  useEffect(
    () => () => {
      if (pollRef.current !== null) window.clearInterval(pollRef.current)
    },
    [],
  )

  const startPolling = useCallback(() => {
    if (pollRef.current !== null) window.clearInterval(pollRef.current)
    pollRef.current = window.setInterval(() => {
      api
        .getStoryline(sessionId)
        .then((r) => {
          if (r.storyline_md) {
            setMd(r.storyline_md)
            setGenerating(false)
            if (pollRef.current !== null) window.clearInterval(pollRef.current)
            pollRef.current = null
          }
        })
        .catch(() => {
          /* 404 while generating — keep polling */
        })
    }, 3000)
  }, [sessionId])

  const generate = (force: boolean) => {
    setError('')
    setGenerating(true)
    api
      .generateStoryline(sessionId, force)
      .then((r) => {
        if (r.storyline_md) {
          setMd(r.storyline_md)
          setGenerating(false)
        } else {
          startPolling()
        }
      })
      .catch((e) => {
        setGenerating(false)
        const msg = e instanceof Error ? e.message : '后端未响应'
        setError(`生成请求失败 — ${msg}`)
        pushToast(`故事线生成失败：${msg}`, { side: 'system', title: 'AI 复盘' })
      })
  }

  return (
    <section className="panel flex-none overflow-hidden">
      <header className="panel-title">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-fg-4" />
        <span className="text-text-1">AI 复盘</span>
        <div className="ml-auto flex items-center gap-2">
          {md && (
            <>
              <button
                onClick={() => setExpanded(true)}
                className="rounded bg-overlay px-2 py-px text-[9px] normal-case tracking-normal text-text-3 transition-colors hover:bg-hover hover:text-text-2"
                title="全屏展开故事线复盘"
              >
                ⛶ 全屏展开
              </button>
              <button
                onClick={() => generate(true)}
                disabled={generating}
                className="rounded bg-overlay px-2 py-px text-[9px] normal-case tracking-normal text-text-3 transition-colors hover:bg-hover hover:text-text-2 disabled:opacity-40"
              >
                {generating ? '生成中…' : '重新生成'}
              </button>
            </>
          )}
        </div>
      </header>
      <div className="scroll-thin max-h-72 overflow-y-auto p-4">
        {md ? (
          <MarkdownView markdown={md} />
        ) : generating ? (
          <div className="flex items-center gap-2 py-4 text-[11px] text-text-3">
            <span className="live-pulse inline-block h-1.5 w-1.5 rounded-full bg-fg-4" />
            AI 正在复盘整场对抗，通常需要十几秒…
          </div>
        ) : (
          <div className="flex items-center gap-3 py-2">
            <button
              onClick={() => generate(false)}
              className="rounded bg-text-1 px-3 py-1 text-[11px] font-medium text-bg transition-colors hover:bg-text-2"
            >
              生成 AI 复盘
            </button>
            <span className="text-[10px] text-text-2">
              {error || '用 LLM 基于完整时间线生成战役故事复盘'}
            </span>
          </div>
        )}
      </div>

      {/* 全屏展开：大字号完整故事线 */}
      {expanded && md && (
        <Modal
          title="AI 战役复盘 · 全屏"
          onClose={() => setExpanded(false)}
          width="w-[1000px]"
        >
          <div className="scroll-thin max-h-[82vh] overflow-y-auto pr-2">
            <div className="text-[14.5px] leading-[1.85]">
              <MarkdownView markdown={md} className="md-doc" />
            </div>
          </div>
        </Modal>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// 战役统计 strip
// ---------------------------------------------------------------------------

function StatCell({ label, value, tone = 'text-text-1' }: {
  label: string
  value: string
  tone?: string
}) {
  return (
    <div className="px-4 py-2.5">
      <div className="text-[8px] uppercase tracking-[0.15em] text-text-2">{label}</div>
      <div className={`mt-0.5 text-[13px] font-medium tabular-nums ${tone}`}>
        {value}
      </div>
    </div>
  )
}

function BattleStats({ detail }: { detail: SessionDetail }) {
  const m: ScoreMetrics | null = detail.metrics
  const isTraffic = detail.id.includes('traffic') || (detail.alerts.length > 0 && detail.attacks.length === 0 && detail.counts.attacks === 0)
  return (
    <section className="panel flex-none overflow-hidden">
      <div className="flex divide-x divide-hairline overflow-x-auto">
        {!isTraffic && (
          <>
            <StatCell label="攻击" value={String(detail.counts.attacks)} tone="text-attacker" />
            <StatCell label="已验证" value={String(detail.counts.verified)} tone="text-attacker/70" />
          </>
        )}
        <StatCell label="告警" value={String(detail.counts.alerts)} />
        <StatCell label="处置/事件" value={String(detail.counts.events)} tone="text-success" />
        {m && !isTraffic && (
          <>
            <StatCell label="检出率" value={`${(m.detection_rate * 100).toFixed(0)}%`} />
            <StatCell label="MTTD" value={m.mttd_sec != null ? `${m.mttd_sec.toFixed(1)}s` : '--'} />
            <StatCell label="蓝队分" value={m.blue_score.toFixed(1)} tone="text-success" />
            <StatCell label="红队分" value={m.red_score.toFixed(1)} tone="text-attacker" />
          </>
        )}
        {m && isTraffic && (
          <>
            {m.event_count != null && <StatCell label="流量事件" value={String(m.event_count)} />}
            {m.alert_count != null && <StatCell label="告警数" value={String(m.alert_count)} />}
            {m.critical_count != null && <StatCell label="严重" value={String(m.critical_count)} tone="text-attacker" />}
            {m.high_count != null && <StatCell label="高危" value={String(m.high_count)} tone="text-warning" />}
          </>
        )}
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// detail tabs
// ---------------------------------------------------------------------------

/** 时间线颜色配置：根据 kind + side 返回标签、徽章样式、圆点样式 */
function getTimelineColors(r: SessionTimelineRow): { label: string; badge: string; dot: string; titleColor: string } {
  // 从 title 中推断 side（如 "RED tool:", "BLUE output:" 等）
  const title = (r.title || '').toUpperCase()
  const side = title.startsWith('RED') ? 'red' : title.startsWith('BLUE') ? 'blue' : 'system'

  if (r.kind === 'attack') {
    return {
      label: '攻击',
      badge: 'border-attacker/50 bg-attacker/10 text-attacker font-semibold',
      dot: 'bg-attacker',
      titleColor: 'text-attacker/90',
    }
  }
  if (r.kind === 'alert') {
    return {
      label: '告警',
      badge: 'border-warning/50 bg-warning/10 text-warning font-semibold',
      dot: 'bg-warning',
      titleColor: 'text-warning/90',
    }
  }
  if (r.kind === 'response') {
    return {
      label: '处置',
      badge: 'border-success/50 bg-success/10 text-success font-semibold',
      dot: 'bg-success',
      titleColor: 'text-success/90',
    }
  }
  // event: 根据 side 区分颜色
  if (side === 'red') {
    return {
      label: '红方',
      badge: 'border-red/40 bg-red/5 text-red/80 font-medium',
      dot: 'bg-red/70',
      titleColor: 'text-red/80',
    }
  }
  if (side === 'blue') {
    return {
      label: '蓝方',
      badge: 'border-blue/40 bg-blue/5 text-blue/80 font-medium',
      dot: 'bg-blue/70',
      titleColor: 'text-blue/80',
    }
  }
  return {
    label: '系统',
    badge: 'border-hairline bg-overlay/50 text-text-2 font-medium',
    dot: 'bg-fg-4/60',
    titleColor: 'text-text-2',
  }
}

const PAGE_SIZE = 50

function TimelineTab({ rows }: { rows: SessionTimelineRow[] }) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE)
  const sorted = useMemo(() => [...rows].sort((a, b) => a.ts - b.ts), [rows])

  // Reset pagination when rows change (switching sessions)
  useEffect(() => {
    setVisibleCount(PAGE_SIZE)
  }, [rows])

  if (sorted.length === 0) {
    return <div className="py-16 text-center text-[11px] text-text-3">暂无时间线数据</div>
  }

  const visible = sorted.slice(0, visibleCount)
  const hasMore = visibleCount < sorted.length

  return (
    <div>
      {/* 统计摘要 */}
      <div className="border-b border-hairline/60 bg-overlay/30 px-4 py-1.5 text-[10px] text-text-3">
        共 {sorted.length} 条事件
        {hasMore && <span className="ml-2 text-text-4">（当前显示前 {visible.length} 条）</span>}
      </div>
      {visible.map((r, i) => {
        const colors = getTimelineColors(r)
        return (
          <div key={i} className="flex gap-3 border-b border-hairline/60 px-4 py-2 transition-colors hover:bg-overlay/30">
            <span className="w-16 flex-none pt-0.5 text-right font-mono text-[10px] tabular-nums text-text-3">
              {fmtTime(r.ts)}
            </span>
            <span className={`mt-1.5 h-2 w-2 flex-none rounded-full ${colors.dot}`} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className={`flex-none rounded border px-1.5 py-px text-[9px] ${colors.badge}`}>
                  {colors.label}
                </span>
                <span className={`truncate text-[12px] ${colors.titleColor}`}>{r.title}</span>
                {r.kind === 'attack' && r.success !== undefined && (
                  <span className={`flex-none text-[10px] font-bold ${r.success ? 'text-attacker' : 'text-text-3'}`}>
                    {r.success ? '✓' : '✗'}
                  </span>
                )}
                {r.technique && (
                  <span className="flex-none rounded bg-purple/10 border border-purple/30 px-1 py-px font-mono text-[9px] text-purple">
                    {r.technique}
                  </span>
                )}
              </div>
              {r.detail && (
                <div className="mt-0.5 text-[10px] leading-4 text-text-2">{r.detail}</div>
              )}
            </div>
          </div>
        )
      })}
      {hasMore && (
        <button
          onClick={() => setVisibleCount(visibleCount + PAGE_SIZE)}
          className="w-full border-t border-hairline/60 py-2.5 text-[11px] text-text-3 transition-colors hover:bg-overlay/50 hover:text-fg"
        >
          加载更多（剩余 {sorted.length - visibleCount} 条）
        </button>
      )}
    </div>
  )
}

/** 摘要像散文/报告（含 markdown 结构）→ MarkdownView 渲染；
 * 像原始日志/命令输出 → 保持 mono 原样。 */
function looksLikeProse(s: string): boolean {
  return /(^|\n)\s*(#{1,4}\s|[-*]\s|\d+\.\s|【[^】]+】)|\*\*[^*]+\*\*/.test(s)
}

function ToolCallsTab({ rows }: { rows: SessionToolCall[] }) {
  const [openIdx, setOpenIdx] = useState<number | null>(null)
  if (rows.length === 0) {
    return <div className="py-16 text-center text-[11px] text-text-3">暂无工具调用记录</div>
  }
  return (
    <table className="w-full text-[11px]">
      <thead className="sticky top-0 bg-raised text-[9px] uppercase tracking-[0.15em] text-text-2">
        <tr>
          <th className="py-2 pl-4 text-left font-normal">时间</th>
          <th className="text-left font-normal">方</th>
          <th className="text-left font-normal">工具</th>
          <th className="text-left font-normal">参数</th>
          <th className="pr-4 text-right font-normal">结果</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <Fragment key={i}>
            <tr
              onClick={() => setOpenIdx(openIdx === i ? null : i)}
              className="cursor-pointer border-t border-hairline/60 text-text-2 transition-colors hover:bg-overlay/50"
            >
              <td className="py-1.5 pl-4 font-mono tabular-nums text-text-2">
                {fmtTime(r.ts)}
              </td>
              <td>
                <span className={`rounded px-1 py-px text-[9px] font-medium ${
                  r.side === 'red'
                    ? 'bg-attacker/10 text-attacker border border-attacker/30'
                    : 'bg-blue/10 text-blue border border-blue/30'
                }`}>
                  {r.side === 'red' ? '红方' : '蓝方'}
                </span>
              </td>
              <td className="font-mono text-text-1">{r.tool}</td>
              <td className="max-w-0 w-[45%] truncate pr-3 font-mono text-[10px] text-text-2" title={r.args}>
                {r.args}
              </td>
              <td className={`pr-4 text-right font-bold ${r.ok ? 'text-success' : 'text-attacker'}`}>
                {r.ok ? '✓' : '✗'}
              </td>
            </tr>
            {openIdx === i && r.summary && (
              <tr className="border-t border-hairline/40">
                <td colSpan={5} className="px-4 py-2">
                  {looksLikeProse(r.summary) ? (
                    <div className="scroll-thin max-h-52 overflow-y-auto rounded border border-hairline bg-panel-2 px-3 py-2 text-fg">
                      <MarkdownView markdown={r.summary} className="md-inline" />
                    </div>
                  ) : (
                    <pre className="scroll-thin max-h-40 overflow-auto whitespace-pre-wrap break-all rounded border border-hairline bg-panel-2 p-2 font-mono text-[10px] leading-4 text-text-2">
                      {r.summary}
                    </pre>
                  )}
                </td>
              </tr>
            )}
          </Fragment>
        ))}
      </tbody>
    </table>
  )
}

// ---------------------------------------------------------------------------
// session detail (right side)
// ---------------------------------------------------------------------------

type DetailTab = 'duel' | 'timeline' | 'tools' | 'report'

function SessionDetailView({ session }: { session: SessionInfo }) {
  const [detail, setDetail] = useState<SessionDetail | null>(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<DetailTab>('timeline')

  useEffect(() => {
    setDetail(null)
    setError('')
    setTab('timeline')
    api
      .getSessionDetail(session.id)
      .then(setDetail)
      .catch(() => setError('会话详情读取失败 — 后端可能尚未实现 /detail'))
  }, [session.id])

  const isTraffic = (session.type ?? 'arena') === 'traffic_analysis'
  const tabs: Array<{ key: DetailTab; label: string }> = isTraffic
    ? [
        { key: 'timeline', label: `时间线 ${detail ? detail.timeline.length : ''}` },
        { key: 'report', label: '报告' },
      ]
    : [
        { key: 'duel', label: '红蓝对垒' },
        { key: 'timeline', label: `时间线 ${detail ? detail.timeline.length : ''}` },
        { key: 'tools', label: `工具调用 ${detail ? detail.tool_calls.length : ''}` },
        { key: 'report', label: '报告' },
      ]

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto scroll-thin pr-1">
      {error && <div className="panel flex-none p-3 text-[11px] text-attacker">{error}</div>}
      {!error && !detail && (
        <div className="panel flex-none p-3 text-[11px] text-text-3">加载中…</div>
      )}
      {detail && (
        <>
          <StorylineSection sessionId={session.id} initial={detail.storyline_md} />
          <BattleStats detail={detail} />
          <section className="panel flex min-h-[320px] flex-1 flex-col overflow-hidden">
            <div className="flex flex-none items-center gap-1 border-b border-hairline px-3 py-1.5">
              {tabs.map((t) => (
                <button
                  key={t.key}
                  onClick={() => setTab(t.key)}
                  className={`rounded px-2.5 py-0.5 text-[10px] transition-colors ${
                    tab === t.key
                      ? 'bg-ink font-medium text-bg'
                      : 'text-text-3 hover:text-fg'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              {tab === 'duel' && <DuelTimeline detail={detail} />}
              {tab === 'timeline' && <TimelineTab rows={detail.timeline} />}
              {tab === 'tools' && <ToolCallsTab rows={detail.tool_calls} />}
              {tab === 'report' &&
                (detail.report_md ? (
                  <div className="p-5">
                    <MarkdownView markdown={detail.report_md} />
                  </div>
                ) : (
                  <div className="py-16 text-center text-[11px] text-text-3">
                    该会话没有 report.md
                  </div>
                ))}
            </div>
          </section>
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// session list helpers (grouped by type)
// ---------------------------------------------------------------------------

function SessionGroupHeader({ title, count }: { title: string; count: number }) {
  return (
    <div className="flex items-center gap-2 px-3 pt-3 pb-1">
      <span className="text-[9px] uppercase tracking-[0.15em] text-text-3">{title}</span>
      <span className="text-[9px] tabular-nums text-text-4">{count}</span>
      <span className="ml-2 h-px flex-1 bg-hairline" />
    </div>
  )
}

function SessionListItem({
  s,
  selected,
  onSelect,
}: {
  s: SessionInfo
  selected: boolean
  onSelect: (s: SessionInfo) => void
}) {
  const isTraffic = (s.type ?? 'arena') === 'traffic_analysis'
  return (
    <button
      onClick={() => onSelect(s)}
      className={`mb-1 flex w-full flex-col gap-1 px-3 py-1.5 text-left transition-colors ${
        selected ? 'bg-panel' : 'hover:bg-overlay'
      }`}
    >
      <div className="flex w-full items-center gap-2">
        <span
          className={`flex-none rounded border px-1 py-px text-[9px] tracking-normal ${
            isTraffic ? 'border-blue/40 text-blue' : 'border-attacker/40 text-attacker'
          }`}
        >
          {isTraffic ? '流量分析' : '作战台'}
        </span>
        <span className="truncate font-mono text-[11px] text-text-1">{s.id}</span>
        {s.score != null && (
          <span className="ml-auto flex-none rounded border border-success/40 px-1 py-px font-mono text-[9px] tabular-nums text-success">
            {s.score.toFixed(1)}
          </span>
        )}
      </div>
      <div className="w-full truncate text-[9px] text-text-3">
        {s.scenario || '默认靶场'}
      </div>
      <div className="flex w-full items-center gap-2 text-[9px] text-text-2">
        <span className="font-mono">{fmtMtime(s.mtime)}</span>
        <span className="ml-auto flex gap-1.5 font-mono">
          <span title="report.md" className={s.has_report ? 'text-text-2' : 'text-text-3'}>
            ▤
          </span>
          <span title="metrics" className={s.has_metrics ? 'text-text-2' : 'text-text-3'}>
            ◈
          </span>
        </span>
      </div>
    </button>
  )
}

// ---------------------------------------------------------------------------
// view
// ---------------------------------------------------------------------------

export function HistoryView() {
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [selected, setSelected] = useState<SessionInfo | null>(null)

  const arenaSessions = useMemo(
    () => sessions.filter((s) => (s.type ?? 'arena') === 'arena'),
    [sessions],
  )
  const trafficSessions = useMemo(
    () => sessions.filter((s) => (s.type ?? 'arena') === 'traffic_analysis'),
    [sessions],
  )

  const load = useCallback(() => {
    api
      .getSessions()
      .then(setSessions)
      .catch(() => setSessions([]))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden px-5 pb-4">
      <div className="flex flex-none items-baseline gap-4 px-1">
        <h1 className="text-[13px] font-semibold leading-none tracking-normal text-fg">
          历史
        </h1>
        <span className="text-[11px] text-text-3">会话回放</span>
      </div>
      <div className="flex min-h-0 flex-1 overflow-hidden">
      {/* left: session list */}
      <FadeIn className="flex w-[280px] flex-none flex-col overflow-hidden border-r border-hairline">
      <aside className="panel flex min-h-0 w-full flex-1 flex-col overflow-hidden">
        <header className="panel-title">
          <span>历史会话</span>
          <button
            onClick={load}
            className="ml-auto rounded bg-overlay px-2 py-px text-[9px] normal-case tracking-normal text-text-3 transition-colors hover:bg-hover hover:text-text-2"
          >
            刷新
          </button>
        </header>
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">
          {sessions.length === 0 && (
            <div className="py-16 text-center text-[11px] text-text-3">
              暂无历史会话
            </div>
          )}
          {arenaSessions.length > 0 && (
            <>
              <SessionGroupHeader title="作战台" count={arenaSessions.length} />
              {arenaSessions.map((s) => (
                <SessionListItem
                  key={s.id}
                  s={s}
                  selected={selected?.id === s.id}
                  onSelect={setSelected}
                />
              ))}
            </>
          )}
          {trafficSessions.length > 0 && (
            <>
              <SessionGroupHeader title="流量分析" count={trafficSessions.length} />
              {trafficSessions.map((s) => (
                <SessionListItem
                  key={s.id}
                  s={s}
                  selected={selected?.id === s.id}
                  onSelect={setSelected}
                />
              ))}
            </>
          )}
        </div>
      </aside>
      </FadeIn>

      {/* right: detail */}
      <FadeIn delay={0.08} className="flex min-h-0 flex-1 flex-col overflow-hidden pl-3 pr-1">
      {selected ? (
        <SessionDetailView key={selected.id} session={selected} />
      ) : (
        <div className="panel flex flex-1 items-center justify-center">
          <div className="text-center">
            <div className="text-[13px] font-medium text-text-3">选择一个会话</div>
            <div className="mt-1 text-[11px] text-text-2">
              AI 复盘 · 战役统计 · 红蓝对垒 · 完整时间线 · 工具调用 · 报告
            </div>
          </div>
        </div>
      )}
      </FadeIn>
      </div>
    </main>
  )
}
