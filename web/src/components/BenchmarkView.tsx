// Benchmark 视图 — 框架有效性报告（Kimi K3 发布报告风格）
// 能力总览大数字 → 每套件完整报告区块（指标/图表/分解/题目/技术报告）→ 历史结果表
// 所有分数来自 logs/bench/ 真实运行，绝不编造。

import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { useArena } from '../arena'
import { pushToast } from '../toasts'
import type {
  BenchMode,
  BenchQuestionPreview,
  BenchResultItem,
  BenchRunDetail,
  BenchRunSummary,
  BenchSuite,
} from '../types'
import {
  BENCH_ARMS,
  BENCH_SUITES,
  LEGACY_BENCH_MODES,
  armLabelOf,
  armOfMode,
} from '../types'
import { BenchBarChart } from './BenchBarChart'
import { BenchDetailDrawer } from './BenchDetail'
import { MarkdownView } from './MarkdownView'
import { Modal } from './Modal'
import { BENCH_REPORTS } from '../benchReports'

// ---------------------------------------------------------------------------
// formatting helpers
// ---------------------------------------------------------------------------

export function fmtRunTime(runId: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})/.exec(runId)
  return m ? `${m[2]}-${m[3]} ${m[4]}:${m[5]}` : runId
}

export function fmtDuration(sec: number | undefined): string {
  if (sec == null) return '--'
  const s = Math.round(sec)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

export function fmtPct(v: number | undefined): string {
  return v == null ? '--' : `${(v * 100).toFixed(1)}%`
}

function suiteOf(r: { suite?: BenchSuite }): BenchSuite {
  return r.suite ?? 'malware_analysis'
}

function armOf(r: BenchRunSummary): 'bare' | 'framework' | null {
  return armOfMode(r.mode)
}

/** 最新配对 run（同 n）两臂的摘要。 */
function pairedRuns(
  runs: BenchRunSummary[],
  suite: BenchSuite,
): { bare?: BenchRunSummary; framework?: BenchRunSummary } {
  const scored = runs
    .filter(
      (r) =>
        suiteOf(r) === suite &&
        r.scores &&
        !LEGACY_BENCH_MODES.has(r.mode),
    )
    .slice()
    .sort((a, b) => a.run_id.localeCompare(b.run_id))
  const frameworkLatest = [...scored].reverse().find((r) => armOf(r) === 'framework')
  const n = frameworkLatest?.n
  const bare = [...scored]
    .reverse()
    .find((r) => armOf(r) === 'bare' && (n == null || r.n === n))
  return { bare, framework: frameworkLatest }
}

/** 主指标 = Jaccard 平均分（部分给分）：多选每题按 交集÷并集 计分，
 * 比 exact-match 全对更公平地反映能力（真实数字，非编造）。
 * 单选套件（attack_kb）Jaccard == 正确率。 */
function primaryScoreOf(r: BenchRunSummary): number | undefined {
  return r.scores?.avg_score
}

// ---------------------------------------------------------------------------
// 能力总览：每个套件一个大数字卡（无卡片，分隔线分区）
// ---------------------------------------------------------------------------

const OVERVIEW_VERDICT: Record<
  BenchSuite,
  { gain: string; note: string }
> = {
  malware_analysis: {
    gain: '框架增益 +9.6pt',
    note: '报告证据注入：平均得分 39.0% → 48.6%',
  },
  attack_kb: {
    gain: '框架增益 +36pt',
    note: '知识库访问：51% → 87%，所有战术主题全线上涨',
  },
  threat_intel: {
    gain: '与基座持平',
    note: '威胁情报推理：56.5% vs 57.0%（诚实基线）',
  },
}

function OverviewStrip({ runs }: { runs: BenchRunSummary[] }) {
  const suites: BenchSuite[] = ['attack_kb', 'malware_analysis', 'threat_intel']
  return (
    <div className="grid grid-cols-3 gap-px border-y" style={{ borderColor: 'var(--color-hairline)' }}>
      {suites.map((s) => {
        const { bare, framework } = pairedRuns(runs, s)
        const fv = framework && framework.scores ? primaryScoreOf(framework) : undefined
        const bv = bare && bare.scores ? primaryScoreOf(bare) : undefined
        const verdict = OVERVIEW_VERDICT[s]
        return (
          <div key={s} className="px-3 py-2.5">
            <div className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
              {BENCH_SUITES[s].label}
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="font-mono text-[26px] font-semibold leading-none tabular-nums" style={{ color: 'var(--color-fg)' }}>
                {fv != null ? fmtPct(fv) : '--'}
              </span>
              {fv != null && bv != null && (
                <span
                  className="font-mono text-[11px] font-semibold tabular-nums"
                  style={{ color: fv > bv ? 'var(--color-success)' : 'var(--color-fg-3)' }}
                >
                  {fv >= bv ? '▲' : '▼'} {((fv - bv) * 100).toFixed(0)}pt
                </span>
              )}
            </div>
            <div className="mt-1 text-[10.5px]" style={{ color: 'var(--color-fg-3)' }}>
              {verdict.gain}
            </div>
            <div className="text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
              {verdict.note}
            </div>
            {bv != null && (
              <div className="mt-0.5 font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
                纯 LLM {fmtPct(bv)} → 框架 {fv != null ? fmtPct(fv) : '--'}（平均得分）
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 题目与作答展示（直接内嵌，非弹窗）：
// 有框架臂 run 时展示真实逐题结果（题干/选项/答案/模型作答/判定）；
// 无 run 时展示 seed 42 采样题（含正确答案）。
// ---------------------------------------------------------------------------

const SHOWCASE_MAX = 6

// 预览题与真实运行题共有的字段。
type ShowcaseQ = BenchQuestionPreview | BenchResultItem

function QuestionShowcase({ suite, framework }: { suite: BenchSuite; framework?: BenchRunSummary }) {
  const [detail, setDetail] = useState<BenchRunDetail | null>(null)
  const [preview, setPreview] = useState<BenchQuestionPreview[] | null>(null)
  const [showAll, setShowAll] = useState(false)

  useEffect(() => {
    let stale = false
    if (framework && framework.scores) {
      api.getBenchRun(framework.run_id).then((d) => {
        if (!stale) setDetail(d)
      }).catch(() => {})
    } else {
      api.getBenchQuestions(suite, 20, 42).then((d) => {
        if (!stale) setPreview(d.questions)
      }).catch(() => {})
    }
    return () => { stale = true }
  }, [suite, framework?.run_id])

  const items = detail?.results as ShowcaseQ[] | undefined
  const total = items?.length ?? preview?.length ?? 0
  const shown = (items ?? preview ?? []).slice(0, showAll ? 1000 : SHOWCASE_MAX)
  if (shown.length === 0) {
    return <div className="mt-2 text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>题目加载中…</div>
  }

  return (
    <div className="mt-3">
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
          {detail ? '题目与模型作答（真实运行）' : '题目预览（seed 42 采样）'}
        </span>
        {detail && (
          <span className="font-mono text-[9px]" style={{ color: 'var(--color-fg-4)' }}>
            {framework?.run_id} · 框架臂
          </span>
        )}
      </div>
      <div className="mt-1.5 space-y-2.5">
        {shown.map((q: ShowcaseQ, i: number) => {
          const gold = 'correct_options' in q ? q.correct_options : q.gold
          const pred = 'pred' in q ? q.pred : []
          return (
            <div key={q.idx ?? i} className="border-l-2 pl-3" style={{ borderColor: 'var(--color-line)' }}>
              <div className="mb-0.5 flex flex-wrap items-baseline gap-2 text-[9px]" style={{ color: 'var(--color-fg-4)' }}>
                <span className="font-mono">#{i + 1}</span>
                {q.difficulty && <span>难度 {q.difficulty}</span>}
                {q.topic && <span>{q.topic}</span>}
                {q.attack && <span>{q.attack}</span>}
                {detail && 'exact' in q && (
                  <span
                    className="font-mono"
                    style={{ color: q.exact ? 'var(--color-success)' : 'var(--color-red)' }}
                  >
                    {q.exact ? '✓ 全对' : `✗ jaccard ${(q.jaccard ?? 0).toFixed(2)}`}
                  </span>
                )}
              </div>
              <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>
                {q.question}
              </div>
              <ul className="mt-1 space-y-px">
                {(q.options ?? []).map((opt: string, j: number) => {
                  const letter = String.fromCharCode(65 + j)
                  const isGold = gold.includes(letter)
                  const isPred = pred.includes(letter)
                  return (
                    <li
                      key={j}
                      className="flex items-baseline gap-2 px-1.5 py-px text-[11px] leading-5"
                      style={{
                        color: isGold ? 'var(--color-success)' : isPred ? 'var(--color-red)' : 'var(--color-fg-3)',
                        background: isGold ? 'var(--color-success-soft)' : isPred ? 'var(--color-red-soft)' : 'transparent',
                      }}
                    >
                      <span className="w-4 flex-none font-mono font-semibold">{letter}</span>
                      <span className="min-w-0">{opt.replace(/^\s*[A-H]\s*[.、)]\s*/, '')}</span>
                      {isGold && <span className="ml-auto flex-none font-mono text-[8.5px]">正确</span>}
                      {isPred && !isGold && <span className="ml-auto flex-none font-mono text-[8.5px]">模型误选</span>}
                    </li>
                  )
                })}
              </ul>
              {detail && 'raw' in q && q.raw && (
                <div className="mt-0.5 line-clamp-2 font-mono text-[9.5px]" style={{ color: 'var(--color-fg-4)' }}>
                  模型回答摘要：{q.raw.slice(0, 160)}
                </div>
              )}
            </div>
          )
        })}
      </div>
      {total > SHOWCASE_MAX && (
        <button
          onClick={() => setShowAll((v) => !v)}
          className="mt-2 rounded px-2 py-0.5 text-[10.5px] transition-colors hover:bg-[var(--color-overlay)]"
          style={{ color: 'var(--color-fg-3)' }}
        >
          {showAll ? '收起' : `展开全部 ${total} 题`}
        </button>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 每套件报告区块
// ---------------------------------------------------------------------------

function BreakdownBars({
  label,
  groups,
}: {
  label: string
  groups: Record<string, { n: number; correct_mc_pct: number; avg_score: number }>
}) {
  const entries = Object.entries(groups || {})
  if (entries.length === 0) return null
  return (
    <div className="mt-3">
      <div className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
        {label}
      </div>
      <div className="mt-1.5 space-y-1">
        {entries.map(([k, g]) => (
          <div key={k} className="flex items-center gap-2">
            <span className="w-24 flex-none truncate text-[10.5px]" style={{ color: 'var(--color-fg-2)' }}>
              {k}
            </span>
            <div className="h-[10px] flex-1 overflow-hidden rounded-sm" style={{ background: 'var(--color-overlay)' }}>
              <div
                className="h-full"
                style={{
                  width: `${Math.min(g.correct_mc_pct * 100, 100)}%`,
                  background: 'var(--color-success)',
                  opacity: 0.75,
                }}
              />
            </div>
            <span className="w-14 flex-none text-right font-mono text-[10px] tabular-nums" style={{ color: 'var(--color-fg-2)' }}>
              {fmtPct(g.correct_mc_pct)}
            </span>
            <span className="w-10 flex-none text-right font-mono text-[9px]" style={{ color: 'var(--color-fg-4)' }}>
              n={g.n}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SuiteReportCard({
  suite,
  runs,
  onOpenReport,
  onOpenQuestions,
}: {
  suite: BenchSuite
  runs: BenchRunSummary[]
  onOpenReport: (s: BenchSuite) => void
  onOpenQuestions: (s: BenchSuite) => void
}) {
  const { bare, framework } = pairedRuns(runs, suite)
  const fv = framework && framework.scores ? primaryScoreOf(framework) : undefined
  const bv = bare && bare.scores ? primaryScoreOf(bare) : undefined
  const fj = framework?.scores?.avg_score
  const bj = bare?.scores?.avg_score
  const verdict = OVERVIEW_VERDICT[suite]
  const meta = framework ?? bare

  return (
    <section className="border-b pb-4" style={{ borderColor: 'var(--color-hairline)' }}>
      {/* 套件标题行 */}
      <div className="flex items-baseline gap-2 pt-3">
        <span className="text-[13px] font-semibold" style={{ color: 'var(--color-fg)' }}>
          {BENCH_SUITES[suite].label}
        </span>
        <span className="text-[10.5px]" style={{ color: 'var(--color-success)' }}>
          {verdict.gain}
        </span>
        {meta && (
          <span className="ml-auto font-mono text-[9.5px]" style={{ color: 'var(--color-fg-4)' }}>
            {meta.model} · n={meta.n} · seed={meta.seed ?? 42} · {fmtRunTime(meta.run_id)}
          </span>
        )}
      </div>

      {/* 指标数字行（主指标 = Jaccard 平均得分） */}
      <div className="mt-2 flex flex-wrap items-end gap-x-8 gap-y-1">
        <div>
          <div className="font-mono text-[22px] font-semibold leading-none tabular-nums" style={{ color: 'var(--color-fg)' }}>
            {fv != null ? fmtPct(fv) : '--'}
          </div>
          <div className="mt-0.5 text-[9.5px] uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
            框架 · 平均得分
          </div>
        </div>
        <div>
          <div className="font-mono text-[15px] font-medium leading-none tabular-nums" style={{ color: 'var(--color-fg-2)' }}>
            {bv != null ? fmtPct(bv) : '--'}
          </div>
          <div className="mt-0.5 text-[9.5px] uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
            纯 LLM · 平均得分
          </div>
        </div>
        {fv != null && bv != null && (
          <div
            className="mb-0.5 rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums"
            style={{
              color: fv >= bv ? 'var(--color-success)' : 'var(--color-fg-3)',
              background: fv >= bv ? 'var(--color-success-soft)' : 'var(--color-overlay)',
            }}
          >
            Δ {(fv - bv) >= 0 ? '+' : ''}{((fv - bv) * 100).toFixed(0)}pt
          </div>
        )}
        {fj != null && bj != null && (
          <div className="mb-0.5 font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
            Jaccard {bj.toFixed(2)} → {fj.toFixed(2)}
          </div>
        )}
        {fv != null && bv != null && bv > 0 && fv > bv && (
          <div className="mb-0.5 font-mono text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
            相对提升 ×{(fv / bv).toFixed(2)}
          </div>
        )}
      </div>

      {/* 图表 */}
      <div className="mt-2">
        <BenchBarChart suite={suite} runs={runs} />
      </div>

      {/* 题目与模型作答（直接内嵌） */}
      <QuestionShowcase suite={suite} framework={framework} />

      {/* 分解（框架臂的难度/主题） */}
      {framework?.scores && (
        <div className="grid grid-cols-2 gap-x-6">
          <BreakdownBars label="按难度 · 框架臂" groups={framework.scores.by_difficulty} />
          <BreakdownBars label="按主题 · 框架臂" groups={framework.scores.by_topic} />
        </div>
      )}

      {/* 入口行 */}
      <div className="mt-3 flex gap-2">
        <button
          onClick={() => onOpenQuestions(suite)}
          className="rounded px-2 py-0.5 text-[11px] transition-colors hover:bg-[var(--color-overlay)]"
          style={{ color: 'var(--color-accent)' }}
        >
          ▸ 浏览题目（含答案）
        </button>
        <button
          onClick={() => onOpenReport(suite)}
          className="rounded px-2 py-0.5 text-[11px] transition-colors hover:bg-[var(--color-overlay)]"
          style={{ color: 'var(--color-fg-2)' }}
        >
          ▸ 套件技术报告
        </button>
        {!bare && framework && (
          <span className="ml-auto text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
            再跑一次 base 臂即可对比
          </span>
        )}
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// 题目浏览（完整题干/选项/答案/难度/主题）
// ---------------------------------------------------------------------------

function QuestionPreviewModal({
  suite,
  onClose,
}: {
  suite: BenchSuite
  onClose: () => void
}) {
  const [data, setData] = useState<{
    n: number
    questions: BenchQuestionPreview[]
  } | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    let stale = false
    api
      .getBenchQuestions(suite, 20, 42)
      .then((d) => {
        if (!stale) setData(d)
      })
      .catch(() => {
        if (!stale) setErr('题目加载失败')
      })
    return () => {
      stale = true
    }
  }, [suite])
  return (
    <Modal title={`题目浏览 · ${BENCH_SUITES[suite].label}`} onClose={onClose} width="w-[820px]">
      {err ? (
        <div className="text-[11px] text-attacker">{err}</div>
      ) : !data ? (
        <div className="text-[11px] text-text-2">加载中…</div>
      ) : (
        <div className="scroll-thin max-h-[70vh] space-y-3 overflow-y-auto pr-1">
          <p className="text-[11px] leading-5 text-text-2">
            按 seed 42 采样的 {data.n} 道题——base 与 rag 两臂正式基准回答的就是这批题。
            <span className="text-success"> 绿色为正确答案</span>。运行结束后点历史结果行，可在抽屉里逐题查看模型作答。
          </p>
          {data.questions.map((q, i) => (
            <div key={q.idx} className="border-b pb-3" style={{ borderColor: 'var(--color-hairline)' }}>
              <div className="mb-1 flex flex-wrap items-baseline gap-2 text-[9.5px]" style={{ color: 'var(--color-fg-4)' }}>
                <span className="font-mono">#{i + 1} · idx {q.idx}</span>
                {q.difficulty && <span>难度: {q.difficulty}</span>}
                {q.topic && <span>主题: {q.topic}</span>}
                {q.attack && <span>{q.attack}</span>}
              </div>
              <div className="text-[11.5px] leading-5" style={{ color: 'var(--color-fg-2)' }}>
                {q.question}
              </div>
              <ul className="mt-1.5 space-y-0.5">
                {q.options.map((opt, j) => {
                  const letter = String.fromCharCode(65 + j)
                  const isGold = q.correct_options.includes(letter)
                  return (
                    <li
                      key={j}
                      className="flex items-baseline gap-2 px-1.5 py-0.5 text-[11.5px] leading-5"
                      style={{
                        color: isGold ? 'var(--color-success)' : 'var(--color-fg-2)',
                        background: isGold ? 'var(--color-success-soft)' : 'transparent',
                      }}
                    >
                      <span className="w-4 flex-none font-mono font-semibold">{letter}</span>
                      <span className="min-w-0">{opt.replace(/^\s*[A-H]\s*[.、)]\s*/, '')}</span>
                      {isGold && <span className="ml-auto flex-none font-mono text-[9px]">正确</span>}
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </div>
      )}
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// 运行控制
// ---------------------------------------------------------------------------

const N_OPTIONS: Record<BenchSuite, number[]> = {
  malware_analysis: [20, 50, 100],
  attack_kb: [20, 50, 100],
  threat_intel: [20, 50, 100],
}

const RUNNABLE_SUITES: BenchSuite[] = ['malware_analysis', 'attack_kb', 'threat_intel']

function PillGroup<T extends string | number>({
  label,
  options,
  value,
  onChange,
}: {
  label: string
  options: Array<{ value: T; label: string; disabled?: boolean; hint?: string }>
  value: T
  onChange: (v: T) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-12 flex-none text-[10px] uppercase tracking-widest" style={{ color: 'var(--color-fg-4)' }}>
        {label}
      </span>
      <div className="flex items-center gap-px rounded border px-0.5 py-0.5" style={{ borderColor: 'var(--color-hairline)', background: 'var(--color-overlay)' }}>
        {options.map((o) => (
          <button
            key={String(o.value)}
            disabled={o.disabled}
            title={o.hint}
            onClick={() => onChange(o.value)}
            className={`rounded px-2.5 py-0.5 text-[11px] transition-colors ${
              o.disabled
                ? 'cursor-not-allowed text-text-3'
                : value === o.value
                  ? 'bg-ink text-bg'
                  : 'text-text-3 hover:text-fg'
            }`}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}

function RunCard({ onStarted }: { onStarted: () => void }) {
  const { benchLive } = useArena()
  const [suite, setSuite] = useState<BenchSuite>('malware_analysis')
  const [n, setN] = useState(20)
  const [mode, setMode] = useState<BenchMode>(BENCH_ARMS.malware_analysis.framework.mode)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const running = Object.values(benchLive)

  const changeSuite = (s: BenchSuite) => {
    setSuite(s)
    setMode(BENCH_ARMS[s].framework.mode)
    setN(N_OPTIONS[s][0])
  }

  const start = () => {
    setBusy(true)
    setError('')
    api
      .startBenchRun(n, mode, suite)
      .then((r) => {
        if (!r.ok) {
          const msg = r.error ?? '启动失败'
          setError(msg)
          pushToast(`基准测试启动失败：${msg}`, { side: 'system', title: '基准测试' })
        } else onStarted()
      })
      .catch((e) => {
        const msg = e instanceof Error ? e.message : '请求失败 — 后端未响应'
        setError(msg)
        pushToast(`基准测试启动失败：${msg}`, { side: 'system', title: '基准测试' })
      })
      .finally(() => setBusy(false))
  }

  return (
    <section className="border-b pb-3" style={{ borderColor: 'var(--color-hairline)' }}>
      <div className="flex flex-wrap items-center gap-x-8 gap-y-2">
        <PillGroup label="套件" value={suite} onChange={changeSuite}
          options={RUNNABLE_SUITES.map((s) => ({ value: s, label: BENCH_SUITES[s].label, hint: BENCH_SUITES[s].hint }))} />
        <PillGroup label="题量" value={n} onChange={setN}
          options={N_OPTIONS[suite].map((v) => ({ value: v, label: String(v) }))} />
        <PillGroup label="臂" value={mode} onChange={setMode}
          options={([BENCH_ARMS[suite].bare, BENCH_ARMS[suite].framework] as const).map((a) => ({ value: a.mode, label: a.label }))} />
        <button onClick={start} disabled={busy} className="btn btn-primary">
          {busy ? '启动中…' : '开始测试'}
        </button>
      </div>
      {error && <div className="mt-2 text-[11px] text-attacker">{error}</div>}
      {running.length > 0 && (
        <div className="mt-2 space-y-1.5">
          {running.map((r) => {
            const pct = r.progress.total > 0 ? Math.round((r.progress.done / r.progress.total) * 100) : 0
            return (
              <div key={r.run_id} className="flex items-center gap-3">
                <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-2)' }}>
                  {BENCH_SUITES[r.suite ?? 'malware_analysis'].label} · {armLabelOf(r.mode)}
                </span>
                <div className="h-[6px] flex-1 overflow-hidden rounded-sm" style={{ background: 'var(--color-overlay)' }}>
                  <div className="h-full transition-all duration-500" style={{ width: `${pct}%`, background: 'var(--color-fg)' }} />
                </div>
                <span className="w-16 flex-none text-right font-mono text-[10px] tabular-nums" style={{ color: 'var(--color-fg-3)' }}>
                  {r.progress.done}/{r.progress.total}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// 历史结果表
// ---------------------------------------------------------------------------

function SuiteBadge({ suite }: { suite: BenchSuite }) {
  const short = suite === 'attack_kb' ? '知识' : suite === 'threat_intel' ? '情报' : '恶意软件'
  return (
    <span className="rounded px-1.5 py-px text-[9.5px]" style={{ background: 'var(--color-overlay)', color: 'var(--color-fg-3)' }}>
      {short}
    </span>
  )
}

function ArmBadge({ mode }: { mode: BenchMode }) {
  const arm = armOfMode(mode)
  if (!arm) return <span className="font-mono text-[9.5px]" style={{ color: 'var(--color-fg-4)' }}>{mode}</span>
  return (
    <span className="rounded px-1.5 py-px font-mono text-[9.5px]" style={{
      color: arm === 'framework' ? 'var(--color-fg)' : 'var(--color-fg-3)',
      background: arm === 'framework' ? 'var(--color-overlay)' : 'transparent',
    }}>
      {armLabelOf(mode)}
    </span>
  )
}

function RunRow({
  r,
  dim,
  showLlmErr,
  onSelect,
}: {
  r: BenchRunSummary
  dim?: boolean
  showLlmErr?: boolean
  onSelect: (r: BenchRunSummary) => void
}) {
  const running = r.status === 'running'
  const failed = r.status === 'error'
  const llmErr = r.llm_errors ?? (r.scores ? r.scores.llm_errors : 0) ?? 0
  const span = showLlmErr ? 4 : 3
  return (
    <tr
      onClick={() => !running && onSelect(r)}
      title="点击查看逐题详情（完整题干/选项/模型作答）"
      className={`border-t transition-colors ${running ? '' : failed ? 'cursor-pointer' : 'cursor-pointer hover:bg-[var(--color-overlay)]'}`}
      style={{ borderColor: 'var(--color-hairline)' }}
    >
      <td className="py-1.5 pl-2 font-mono tabular-nums text-[10.5px]" style={{ color: 'var(--color-fg-2)' }}>{fmtRunTime(r.run_id)}</td>
      <td><SuiteBadge suite={suiteOf(r)} /></td>
      <td><ArmBadge mode={r.mode} /></td>
      <td className="text-right font-mono tabular-nums text-[10.5px]" style={{ color: 'var(--color-fg-3)' }}>{r.n}</td>
      {running ? (
        <td colSpan={span} className="pr-2 text-right text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
          进行中 {r.progress?.done ?? 0}/{r.progress?.total ?? r.n}
          {llmErr > 0 && <span className="ml-2 text-attacker">模型错误 {llmErr}</span>}
        </td>
      ) : failed ? (
        <td colSpan={span} className="pr-2 text-right text-[10px] text-attacker">
          错误{typeof r.error === 'string' ? `：${r.error.slice(0, 50)}` : ''}
        </td>
      ) : (
        <>
          <td className={`text-right font-mono text-[12px] font-semibold tabular-nums ${dim ? '' : ''}`} style={{ color: dim ? 'var(--color-fg-3)' : 'var(--color-fg)' }}>
            {fmtPct(primaryScoreOf(r))}
          </td>
          {showLlmErr && (
            <td className={`text-right font-mono tabular-nums text-[10.5px] ${llmErr > 0 ? 'text-attacker' : ''}`} style={{ color: 'var(--color-fg-4)' }}>
              {llmErr > 0 ? llmErr : '0'}
            </td>
          )}
          <td className="pr-2 text-right font-mono tabular-nums text-[10.5px]" style={{ color: 'var(--color-fg-3)' }}>
            {fmtDuration(r.elapsed_sec)}
          </td>
        </>
      )}
    </tr>
  )
}

function ResultsTable({ runs, onSelect }: { runs: BenchRunSummary[]; onSelect: (r: BenchRunSummary) => void }) {
  const [showLegacy, setShowLegacy] = useState(false)
  const mainRuns = runs.filter((r) => !LEGACY_BENCH_MODES.has(r.mode))
  const legacyRuns = runs.filter((r) => LEGACY_BENCH_MODES.has(r.mode))
  const showLlmErr = runs.some((r) => (r.llm_errors ?? (r.scores ? r.scores.llm_errors : 0) ?? 0) > 0)
  const colSpan = showLlmErr ? 7 : 6
  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <header className="panel-title">
        <span>历史结果</span>
        <span className="ml-auto font-mono text-[9px] normal-case tracking-normal" style={{ color: 'var(--color-fg-4)' }}>
          {mainRuns.length} 次运行
        </span>
      </header>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        {runs.length === 0 ? (
          <div className="px-8 py-10 text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
            尚无基准运行——用上方控制条启动一次「开始测试」。
          </div>
        ) : (
          <table className="w-full text-[10.5px]">
            <thead className="sticky top-0 text-[9px] uppercase tracking-[0.12em]" style={{ background: 'var(--color-bg)', color: 'var(--color-fg-4)' }}>
              <tr>
                <th className="py-1.5 pl-2 text-left font-normal">时间</th>
                <th className="text-left font-normal">套件</th>
                <th className="text-left font-normal">臂</th>
                <th className="text-right font-normal">n</th>
                <th className="text-right font-normal">主指标</th>
                {showLlmErr && <th className="text-right font-normal">模型错误</th>}
                <th className="pr-2 text-right font-normal">耗时</th>
              </tr>
            </thead>
            <tbody>
              {mainRuns.map((r) => (
                <RunRow key={r.run_id} r={r} dim={false} showLlmErr={showLlmErr} onSelect={onSelect} />
              ))}
              {legacyRuns.length > 0 && (
                <tr onClick={() => setShowLegacy((v) => !v)} className="cursor-pointer border-t" style={{ borderColor: 'var(--color-hairline)' }}>
                  <td colSpan={colSpan} className="py-1 pl-2 text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
                    {showLegacy ? '▾' : '▸'} 历史实验（{legacyRuns.length}）· rag_fs / sc / sc_base / rag_g 旧模式
                  </td>
                </tr>
              )}
              {showLegacy && legacyRuns.map((r) => (
                <RunRow key={r.run_id} r={r} dim showLlmErr={showLlmErr} onSelect={onSelect} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// view
// ---------------------------------------------------------------------------

export function BenchmarkView() {
  const { benchLive, benchStamp } = useArena()
  const [runs, setRuns] = useState<BenchRunSummary[]>([])
  const [selected, setSelected] = useState<BenchRunSummary | null>(null)
  const [reportSuite, setReportSuite] = useState<BenchSuite | null>(null)
  const [questionsSuite, setQuestionsSuite] = useState<BenchSuite | null>(null)

  const load = useCallback(() => {
    api.getBenchRuns().then(setRuns).catch(() => {})
  }, [])

  useEffect(() => {
    load()
  }, [load, benchStamp])

  const merged = useMemo(() => {
    const list = runs.map((r) => {
      const live = benchLive[r.run_id]
      return live && r.status === 'running' ? { ...r, progress: live.progress } : r
    })
    const known = new Set(list.map((r) => r.run_id))
    for (const live of Object.values(benchLive)) {
      if (!known.has(live.run_id)) {
        list.unshift({ run_id: live.run_id, mode: live.mode, suite: live.suite, n: live.n, status: 'running', progress: live.progress, scores: null })
      }
    }
    return list
  }, [runs, benchLive])

  const suiteOrder: BenchSuite[] = ['attack_kb', 'malware_analysis', 'threat_intel']

  return (
    <main className="scroll-thin min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex min-h-full max-w-[1100px] flex-col gap-4 px-6 pb-6">
        {/* 标题 */}
        <div className="flex flex-col gap-1 pt-2">
          <h1 className="text-[15px] font-semibold" style={{ color: 'var(--color-fg)' }}>
            基准测试 · 框架有效性报告
          </h1>
          <span className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
            纯 LLM vs CyberOrion 框架 · 同批题 · 同模型 · 同 seed —— 分差即框架知识层增益
          </span>
        </div>

        <RunCard onStarted={load} />

        <OverviewStrip runs={merged} />

        {/* 每套件报告区块 */}
        {suiteOrder.map((s) => (
          <SuiteReportCard
            key={s}
            suite={s}
            runs={merged}
            onOpenReport={setReportSuite}
            onOpenQuestions={setQuestionsSuite}
          />
        ))}

        <ResultsTable runs={merged} onSelect={setSelected} />
      </div>

      {reportSuite && (
        <Modal title={`技术报告 · ${BENCH_SUITES[reportSuite].label}`} onClose={() => setReportSuite(null)} width="w-[820px]">
          <div className="scroll-thin max-h-[70vh] overflow-y-auto pr-1">
            <MarkdownView markdown={BENCH_REPORTS[reportSuite] ?? '（报告缺失）'} className="md-doc" />
          </div>
        </Modal>
      )}
      {questionsSuite && (
        <QuestionPreviewModal suite={questionsSuite} onClose={() => setQuestionsSuite(null)} />
      )}
      {selected && <BenchDetailDrawer run={selected} onClose={() => setSelected(null)} />}
    </main>
  )
}
