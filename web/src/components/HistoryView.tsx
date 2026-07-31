// 历史 tab: full-page session replay — left session list, right detail with
// ① AI 复盘 (storyline, generate-on-demand) ② 战役统计 strip ③ tabbed
// 完整时间线 / 工具调用 / 告警与攻击 / 报告. All endpoints fail soft: the
// backend may still be in flight, so 404/empty render empty states.

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { pushToast } from '../toasts'
import type {
  ScoreMetrics,
  SessionDetail,
  SessionInfo,
  SessionTimelineRow,
  SessionToolCall,
} from '../types'
import { MarkdownView } from './MarkdownView'

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

/** Defensive field read for loosely-typed truth rows. */
function cell(row: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = row[k]
    if (v != null && v !== '') return String(v)
  }
  return ''
}

// ---------------------------------------------------------------------------
// AI 复盘 (storyline) — render, or generate + poll
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
          // 202 {status:"generating"} — poll the GET endpoint.
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
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-white" />
        <span className="text-text-1">AI 复盘</span>
        <div className="ml-auto flex items-center gap-2">
          {md && (
            <button
              onClick={() => generate(true)}
              disabled={generating}
              className="rounded-full bg-overlay px-2.5 py-px text-[9px] normal-case tracking-normal text-neutral-400 transition-colors hover:bg-hover hover:text-neutral-200 disabled:opacity-40"
            >
              {generating ? '生成中…' : '重新生成'}
            </button>
          )}
        </div>
      </header>
      <div className="scroll-thin max-h-72 overflow-y-auto p-4">
        {md ? (
          <MarkdownView markdown={md} />
        ) : generating ? (
          <div className="flex items-center gap-2 py-4 text-[11px] text-neutral-400">
            <span className="live-pulse inline-block h-1.5 w-1.5 rounded-full bg-white" />
            AI 正在复盘整场对抗，通常需要几十秒…
          </div>
        ) : (
          <div className="flex items-center gap-3 py-2">
            <button
              onClick={() => generate(false)}
              className="rounded-full bg-text-1 px-4 py-1.5 text-[11px] font-medium text-black transition-colors hover:bg-white"
            >
              生成 AI 复盘
            </button>
            <span className="text-[10px] text-text-2">
              {error || '由 LLM 基于完整时间线生成战役叙事'}
            </span>
          </div>
        )}
      </div>
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
      <div className={`mt-0.5 font-mono text-[15px] font-semibold tabular-nums ${tone}`}>
        {value}
      </div>
    </div>
  )
}

function BattleStats({ detail }: { detail: SessionDetail }) {
  const m: ScoreMetrics | null = detail.metrics
  return (
    <section className="panel flex-none overflow-hidden">
      <div className="flex divide-x divide-hairline overflow-x-auto">
        <StatCell label="攻击" value={String(detail.counts.attacks)} tone="text-attacker" />
        <StatCell
          label="已验证"
          value={String(detail.counts.verified)}
          tone="text-attacker/70"
        />
        <StatCell label="告警" value={String(detail.counts.alerts)} />
        <StatCell label="处置/事件" value={String(detail.counts.events)} tone="text-success" />
        {m && (
          <>
            <StatCell
              label="检测率"
              value={`${(m.detection_rate * 100).toFixed(0)}%`}
            />
            <StatCell
              label="MTTD"
              value={m.mttd_sec != null ? `${m.mttd_sec.toFixed(1)}s` : '--'}
            />
            <StatCell
              label="蓝队分"
              value={m.blue_score.toFixed(1)}
              tone="text-success"
            />
            <StatCell
              label="红队分"
              value={m.red_score.toFixed(1)}
              tone="text-attacker"
            />
          </>
        )}
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// detail tabs
// ---------------------------------------------------------------------------

const KIND_META: Record<
  SessionTimelineRow['kind'],
  { label: string; cls: string; dot: string }
> = {
  attack: { label: '攻击', cls: 'border-attacker/40 text-attacker', dot: 'bg-attacker' },
  alert: { label: '告警', cls: 'border-hairline text-text-1', dot: 'bg-white' },
  event: { label: '事件', cls: 'border-warning/40 text-warning', dot: 'bg-warning' },
  response: { label: '处置', cls: 'border-success/40 text-success', dot: 'bg-success' },
}

function TimelineTab({ rows }: { rows: SessionTimelineRow[] }) {
  const sorted = useMemo(() => [...rows].sort((a, b) => a.ts - b.ts), [rows])
  if (sorted.length === 0) {
    return <div className="py-16 text-center text-[11px] text-neutral-600">暂无时间线数据</div>
  }
  return (
    <div>
      {sorted.map((r, i) => {
        const meta = KIND_META[r.kind] ?? KIND_META.event
        return (
          <div key={i} className="flex gap-3 border-b border-hairline/60 px-4 py-2">
            <span className="w-16 flex-none pt-0.5 text-right font-mono text-[10px] tabular-nums text-[#86868b]">
              {fmtTime(r.ts)}
            </span>
            <span className={`mt-1.5 h-1.5 w-1.5 flex-none rounded-full ${meta.dot}`} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className={`flex-none rounded border px-1 py-px text-[9px] ${meta.cls}`}>
                  {meta.label}
                </span>
                <span className="truncate text-[12px] text-[#ececf0]">{r.title}</span>
                {r.kind === 'attack' && r.success !== undefined && (
                  <span className={`flex-none text-[10px] ${r.success ? 'text-attacker' : 'text-neutral-600'}`}>
                    {r.success ? '✓' : '✗'}
                  </span>
                )}
                {r.technique && (
                  <span className="flex-none rounded bg-overlay px-1 py-px font-mono text-[9px] text-neutral-400">
                    {r.technique}
                  </span>
                )}
              </div>
              {r.detail && (
                <div className="mt-0.5 text-[10px] leading-4 text-[#86868b]">{r.detail}</div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function ToolCallsTab({ rows }: { rows: SessionToolCall[] }) {
  const [openIdx, setOpenIdx] = useState<number | null>(null)
  if (rows.length === 0) {
    return <div className="py-16 text-center text-[11px] text-neutral-600">暂无工具调用记录</div>
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
              className="cursor-pointer border-t border-hairline/60 text-neutral-300 transition-colors hover:bg-overlay/50"
            >
              <td className="py-1.5 pl-4 font-mono tabular-nums text-text-2">
                {fmtTime(r.ts)}
              </td>
              <td className={r.side === 'red' ? 'text-attacker/80' : ''}>{r.side}</td>
              <td className="font-mono text-text-1">{r.tool}</td>
              <td className="max-w-0 w-[45%] truncate pr-3 font-mono text-[10px] text-text-2" title={r.args}>
                {r.args}
              </td>
              <td className={`pr-4 text-right ${r.ok ? 'text-success' : 'text-attacker'}`}>
                {r.ok ? '✓' : '✗'}
              </td>
            </tr>
            {openIdx === i && r.summary && (
              <tr className="border-t border-hairline/40">
                <td colSpan={5} className="px-4 py-2">
                  <pre className="scroll-thin max-h-40 overflow-auto whitespace-pre-wrap break-all rounded border border-hairline bg-ink p-2 font-mono text-[10px] leading-4 text-[#c7c7cc]">
                    {r.summary}
                  </pre>
                </td>
              </tr>
            )}
          </Fragment>
        ))}
      </tbody>
    </table>
  )
}

function TruthTab({ detail }: { detail: SessionDetail }) {
  const { alerts, attacks } = detail
  return (
    <div className="p-4">
      <div className="mb-2 text-[10px] uppercase tracking-widest text-text-2">
        告警（{alerts.length}）
      </div>
      {alerts.length === 0 ? (
        <div className="py-6 text-center text-[11px] text-neutral-600">无告警</div>
      ) : (
        <table className="mb-6 w-full text-[11px]">
          <thead className="text-[9px] uppercase tracking-[0.15em] text-text-3">
            <tr>
              <th className="pb-1.5 text-left font-normal">时间</th>
              <th className="text-left font-normal">主机</th>
              <th className="text-left font-normal">技术</th>
              <th className="text-left font-normal">判定</th>
              <th className="text-right font-normal">置信度</th>
              <th className="text-right font-normal">状态</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a, i) => (
              <tr key={i} className="border-t border-hairline/60 text-neutral-300">
                <td className="py-1.5 font-mono tabular-nums text-text-2">
                  {cell(a, 'ts') ? fmtTime(Number(a.ts)) : '--'}
                </td>
                <td className="font-mono">{cell(a, 'host') || '--'}</td>
                <td className="font-mono text-text-2">{cell(a, 'technique') || '--'}</td>
                <td>{cell(a, 'verdict') || '--'}</td>
                <td className="text-right font-mono tabular-nums">
                  {a.confidence != null ? `${Math.round(Number(a.confidence) * 100)}%` : '--'}
                </td>
                <td className="text-right">{cell(a, 'status') || '--'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="mb-2 text-[10px] uppercase tracking-widest text-text-2">
        攻击真值（{attacks.length}）
      </div>
      {attacks.length === 0 ? (
        <div className="py-6 text-center text-[11px] text-neutral-600">无攻击记录</div>
      ) : (
        <table className="w-full text-[11px]">
          <thead className="text-[9px] uppercase tracking-[0.15em] text-text-3">
            <tr>
              <th className="pb-1.5 text-left font-normal">时间</th>
              <th className="text-left font-normal">目标</th>
              <th className="text-left font-normal">技术</th>
              <th className="text-left font-normal">动作</th>
              <th className="text-right font-normal">结果</th>
            </tr>
          </thead>
          <tbody>
            {attacks.map((a, i) => {
              const ok = a.success === true || a.success === 'true'
              return (
                <tr key={i} className="border-t border-hairline/60 text-neutral-300">
                  <td className="py-1.5 font-mono tabular-nums text-text-2">
                    {cell(a, 'ts') ? fmtTime(Number(a.ts)) : '--'}
                  </td>
                  <td className="font-mono">{cell(a, 'target', 'host') || '--'}</td>
                  <td className="font-mono text-text-2">{cell(a, 'technique') || '--'}</td>
                  <td className="max-w-0 w-[40%] truncate pr-3 text-text-2">
                    {cell(a, 'action') || '--'}
                  </td>
                  <td className={`text-right ${ok ? 'text-attacker' : 'text-neutral-600'}`}>
                    {ok ? '✓ 成功' : '✗ 失败'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// session detail (right side)
// ---------------------------------------------------------------------------

type DetailTab = 'timeline' | 'tools' | 'truth' | 'report'

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

  const tabs: Array<{ key: DetailTab; label: string }> = [
    { key: 'timeline', label: `时间线 ${detail ? detail.timeline.length : ''}` },
    { key: 'tools', label: `工具调用 ${detail ? detail.tool_calls.length : ''}` },
    { key: 'truth', label: '告警与攻击' },
    { key: 'report', label: '报告' },
  ]

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto scroll-thin pr-1">
      {error && <div className="panel flex-none p-6 text-[11px] text-attacker">{error}</div>}
      {!error && !detail && (
        <div className="panel flex-none p-6 text-[11px] text-neutral-600">加载中…</div>
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
                  className={`rounded-full px-3 py-1 text-[10px] transition-colors ${
                    tab === t.key
                      ? 'bg-[#48484a] font-medium text-white'
                      : 'text-neutral-500 hover:text-neutral-200'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              {tab === 'timeline' && <TimelineTab rows={detail.timeline} />}
              {tab === 'tools' && <ToolCallsTab rows={detail.tool_calls} />}
              {tab === 'truth' && <TruthTab detail={detail} />}
              {tab === 'report' &&
                (detail.report_md ? (
                  <div className="p-5">
                    <MarkdownView markdown={detail.report_md} />
                  </div>
                ) : (
                  <div className="py-16 text-center text-[11px] text-neutral-600">
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
// view
// ---------------------------------------------------------------------------

export function HistoryView() {
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [selected, setSelected] = useState<SessionInfo | null>(null)

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
    <main className="flex min-h-0 flex-1 gap-4 overflow-hidden p-5">
      {/* left: session list */}
      <aside className="panel flex w-[320px] flex-none flex-col overflow-hidden">
        <header className="panel-title">
          <span>历史会话</span>
          <button
            onClick={load}
            className="ml-auto rounded-full bg-overlay px-2.5 py-px text-[9px] normal-case tracking-normal text-neutral-400 transition-colors hover:bg-hover hover:text-neutral-200"
          >
            刷新
          </button>
        </header>
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">
          {sessions.length === 0 && (
            <div className="py-16 text-center text-[11px] text-neutral-600">
              暂无历史会话
            </div>
          )}
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={() => setSelected(s)}
              className={`mb-1.5 flex w-full flex-col gap-1 rounded-lg border px-3 py-2 text-left transition-colors ${
                selected?.id === s.id
                  ? 'border-[#636366] bg-overlay'
                  : 'border-hairline bg-raised hover:border-[#48484a]'
              }`}
            >
              <div className="flex w-full items-center gap-2">
                <span className="truncate font-mono text-[11px] text-text-1">{s.id}</span>
                {s.score != null && (
                  <span className="ml-auto flex-none rounded-full border border-success/40 px-1.5 py-px font-mono text-[9px] tabular-nums text-success">
                    {s.score.toFixed(1)}
                  </span>
                )}
              </div>
              <div className="flex w-full items-center gap-2 text-[9px] text-text-2">
                <span className="font-mono">{fmtMtime(s.mtime)}</span>
                <span className="ml-auto flex gap-1.5 font-mono">
                  <span title="report.md" className={s.has_report ? 'text-neutral-300' : 'text-text-3'}>
                    ▤
                  </span>
                  <span title="metrics" className={s.has_metrics ? 'text-neutral-300' : 'text-text-3'}>
                    ◈
                  </span>
                </span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      {/* right: detail */}
      {selected ? (
        <SessionDetailView key={selected.id} session={selected} />
      ) : (
        <div className="panel flex flex-1 items-center justify-center">
          <div className="text-center">
            <div className="text-[13px] font-medium text-text-1">选择一个会话</div>
            <div className="mt-1 text-[11px] text-text-2">
              AI 复盘 · 战役统计 · 完整时间线 · 工具调用 · 告警与攻击真值 · 报告
            </div>
          </div>
        </div>
      )}
    </main>
  )
}
