// Benchmark 视图: 框架价值对比 —
// 运行卡片(CyberGym 主套件 + CyberSOCEval; 裸模型 vs 框架臂 + 实时进度) ·
// 论文风格分组柱状图 BenchBarChart (每套件一张, Δ 徽章) · 历史结果表格
// (attack_kb 已废弃, 历史运行置灰; legacy 实验模式折叠)。

import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { useArena } from '../arena'
import { pushToast } from '../toasts'
import type { BenchMode, BenchRunSummary, BenchSuite } from '../types'
import {
  BENCH_ARMS,
  BENCH_SUITES,
  LEGACY_BENCH_MODES,
  armOfMode,
  isCyberGymScores,
  primaryScoreOf,
} from '../types'
import { BenchBarChart } from './BenchBarChart'
import { BenchDetailDrawer } from './BenchDetail'

// ---------------------------------------------------------------------------
// formatting helpers (run_id looks like `20260801_015004_cybergym_framework_n1`)
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

/** Pre-suite runs are malware_analysis. */
function suiteOf(r: { suite?: BenchSuite }): BenchSuite {
  return r.suite ?? 'malware_analysis'
}

function SuiteBadge({ suite }: { suite: BenchSuite }) {
  const meta = BENCH_SUITES[suite]
  if (suite === 'attack_kb') {
    // 已废弃套件: 历史运行保留但置灰 + 删除线
    return (
      <span
        title={meta.hint}
        className="rounded-full bg-overlay px-2 py-px text-[9px] text-text-3"
      >
        <span className="line-through">attack_kb</span> · 已废弃
      </span>
    )
  }
  return (
    <span
      title={meta.hint}
      className={`rounded-full px-2 py-px text-[9px] ${
        suite === 'cybergym'
          ? 'border border-accent/50 text-accent'
          : 'bg-overlay text-neutral-400'
      }`}
    >
      {suite === 'cybergym' ? 'CyberGym' : 'CyberSOCEval'}
    </span>
  )
}

/** 臂徽章: 裸模型 (vanilla/base) 灰, 框架 (framework/rag) 绿, legacy 模式描边。 */
function ArmBadge({ mode }: { mode: BenchMode }) {
  const arm = armOfMode(mode)
  if (!arm) {
    return (
      <span className="rounded-full border border-hairline px-2 py-px font-mono text-[10px] text-text-3">
        {mode}
      </span>
    )
  }
  return arm === 'framework' ? (
    <span
      title="CyberOrion 框架臂"
      className="rounded-full border border-accent/50 px-2 py-px font-mono text-[10px] font-medium text-accent"
    >
      {mode}
    </span>
  ) : (
    <span
      title="裸模型臂"
      className="rounded-full bg-overlay px-2 py-px font-mono text-[10px] text-neutral-400"
    >
      {mode}
    </span>
  )
}

// ---------------------------------------------------------------------------
// run card
// ---------------------------------------------------------------------------

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
    <div className="flex items-center gap-3">
      <span className="w-14 flex-none text-[10px] uppercase tracking-widest text-text-2">
        {label}
      </span>
      <div className="flex items-center rounded-full border border-hairline bg-white/[0.03] p-0.5">
        {options.map((o) => (
          <button
            key={String(o.value)}
            disabled={o.disabled}
            title={o.hint}
            onClick={() => onChange(o.value)}
            className={`rounded-full px-3 py-1 font-display text-[11px] font-bold tracking-wide transition-colors ${
              o.disabled
                ? 'cursor-not-allowed text-text-3'
                : value === o.value
                  ? 'bg-white/5 text-accent'
                  : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}

/** 可发起对比的套件 (attack_kb 已废弃, 不出现在运行卡片)。 */
const RUNNABLE_SUITES: BenchSuite[] = ['cybergym', 'malware_analysis']

const N_OPTIONS: Record<BenchSuite, number[]> = {
  cybergym: [1, 3, 5],
  malware_analysis: [20, 50, 100],
  attack_kb: [20, 50, 100],
}

function RunCard({ onStarted }: { onStarted: () => void }) {
  const { benchLive } = useArena()
  const [suite, setSuite] = useState<BenchSuite>('cybergym')
  const [n, setN] = useState(1)
  const [mode, setMode] = useState<BenchMode>(
    BENCH_ARMS.cybergym.framework.mode,
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const running = Object.values(benchLive)

  const changeSuite = (s: BenchSuite) => {
    setSuite(s)
    setMode(BENCH_ARMS[s].framework.mode)
    const ns = N_OPTIONS[s]
    setN(ns[0])
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
          pushToast(`Benchmark 启动失败：${msg}`, {
            side: 'system',
            title: 'Benchmark',
          })
        } else onStarted()
      })
      .catch((e) => {
        const msg = e instanceof Error ? e.message : '请求失败 — 后端未响应'
        setError(msg)
        pushToast(`Benchmark 启动失败：${msg}`, {
          side: 'system',
          title: 'Benchmark',
        })
      })
      .finally(() => setBusy(false))
  }

  return (
    <section className="panel flex-none p-5">
      <div className="flex flex-wrap items-center gap-x-10 gap-y-4">
        <PillGroup
          label="套件"
          value={suite}
          onChange={changeSuite}
          options={RUNNABLE_SUITES.map((s) => ({
            value: s,
            label: BENCH_SUITES[s].label,
            hint: BENCH_SUITES[s].hint,
          }))}
        />
        <PillGroup
          label={suite === 'cybergym' ? '任务数' : '题量'}
          value={n}
          onChange={setN}
          options={N_OPTIONS[suite].map((v) => ({ value: v, label: String(v) }))}
        />
        <PillGroup
          label="臂"
          value={mode}
          onChange={setMode}
          options={(
            [BENCH_ARMS[suite].bare, BENCH_ARMS[suite].framework] as const
          ).map((a) => ({
            value: a.mode,
            label: a.label,
          }))}
        />
        <span className="text-[10px] text-text-2">
          {BENCH_SUITES[suite].hint}
        </span>
        <button
          onClick={start}
          disabled={busy}
          className="btn-pill btn-primary ml-auto !px-5 !py-2 !text-[11px]"
        >
          {busy ? '启动中…' : '开始测试'}
        </button>
      </div>
      {error && <div className="mt-3 text-[11px] text-attacker">{error}</div>}

      {/* live progress for each concurrent run */}
      {running.length > 0 && (
        <div className="mt-4 space-y-2.5 border-t border-hairline pt-4">
          {running.map((r) => {
            const pct =
              r.progress.total > 0
                ? Math.round((r.progress.done / r.progress.total) * 100)
                : 0
            return (
              <div key={r.run_id} className="flex items-center gap-3">
                <SuiteBadge suite={r.suite ?? 'malware_analysis'} />
                <ArmBadge mode={r.mode} />
                <span className="font-mono text-[10px] text-text-2">
                  {fmtRunTime(r.run_id)}
                </span>
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-white/5">
                  <div
                    className="h-full rounded-full bg-accent transition-all duration-500"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-16 flex-none text-right font-mono text-[10px] tabular-nums text-neutral-300">
                  {r.progress.done}/{r.progress.total}
                </span>
                {(r.llm_errors ?? 0) > 0 && (
                  <span className="flex-none font-mono text-[10px] tabular-nums text-attacker">
                    模型错误 {r.llm_errors}/{r.progress.done}
                  </span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// comparison charts — one paper-style bar chart per suite with ≥1 scored run
// ---------------------------------------------------------------------------

function CompareCharts({ runs }: { runs: BenchRunSummary[] }) {
  const suites = useMemo(() => {
    const seen = new Set<BenchSuite>()
    for (const r of runs) {
      if (r.scores && !LEGACY_BENCH_MODES.has(r.mode)) seen.add(suiteOf(r))
    }
    // CyberGym first — 主基准; attack_kb 已废弃, 不参与对比图。
    return (['cybergym', 'malware_analysis'] as BenchSuite[]).filter((s) =>
      seen.has(s),
    )
  }, [runs])
  if (suites.length === 0) return null
  return (
    <>
      {suites.map((s) => (
        <BenchBarChart key={s} suite={s} runs={runs} />
      ))}
    </>
  )
}

// ---------------------------------------------------------------------------
// results table
// ---------------------------------------------------------------------------

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
  const suite = suiteOf(r)
  const running = r.status === 'running'
  const failed = r.status === 'error'
  const llmErr =
    r.llm_errors ??
    (r.scores && !isCyberGymScores(r.scores) ? r.scores.llm_errors : 0) ??
    0
  const span = showLlmErr ? 4 : 3
  return (
    <tr
      onClick={() => !running && onSelect(r)}
      className={`border-t border-hairline/60 transition-colors ${
        running
          ? 'text-text-2'
          : failed
            ? 'cursor-pointer bg-attacker/[0.06] text-attacker/90 hover:bg-attacker/10'
            : `cursor-pointer hover:bg-white/[0.03] ${dim ? 'text-text-3' : 'text-neutral-300'}`
      }`}
    >
      <td className="py-2.5 pl-5 font-mono tabular-nums">{fmtRunTime(r.run_id)}</td>
      <td>
        <SuiteBadge suite={suite} />
      </td>
      <td>
        <ArmBadge mode={r.mode} />
      </td>
      <td className="text-right font-mono tabular-nums">{r.n}</td>
      {running ? (
        <td colSpan={span} className="pr-5 text-right text-[10px]">
          进行中 {r.progress?.done ?? 0}/{r.progress?.total ?? r.n} …
          {llmErr > 0 && (
            <span className="ml-2 text-attacker">模型错误 {llmErr}</span>
          )}
        </td>
      ) : failed ? (
        <td colSpan={span} className="pr-5 text-right text-[10px] text-attacker/80">
          错误{typeof r.error === 'string' ? `：${r.error.slice(0, 60)}` : ''}
        </td>
      ) : (
        <>
          <td
            title={suite === 'cybergym' ? '最终提交成功率' : '选择题正确率'}
            className={`text-right font-mono text-[13px] font-semibold tabular-nums ${
              dim ? 'text-text-2' : 'text-text-1'
            }`}
          >
            {fmtPct(primaryScoreOf(r))}
          </td>
          {showLlmErr && (
            <td
              className={`text-right font-mono tabular-nums ${
                llmErr > 0 ? 'text-attacker' : 'text-text-3'
              }`}
            >
              {llmErr > 0 ? llmErr : '0'}
            </td>
          )}
          <td className="pr-5 text-right font-mono tabular-nums text-text-2">
            {fmtDuration(r.elapsed_sec)}
          </td>
        </>
      )}
    </tr>
  )
}

function ResultsTable({
  runs,
  onSelect,
}: {
  runs: BenchRunSummary[]
  onSelect: (r: BenchRunSummary) => void
}) {
  const [showLegacy, setShowLegacy] = useState(false)
  const mainRuns = runs.filter((r) => !LEGACY_BENCH_MODES.has(r.mode))
  const legacyRuns = runs.filter((r) => LEGACY_BENCH_MODES.has(r.mode))
  // 任一运行出现 LLM 错误时显示「模型错误」列（平时不占位）。
  const showLlmErr = runs.some(
    (r) =>
      (r.llm_errors ??
        (r.scores && !isCyberGymScores(r.scores) ? r.scores.llm_errors : 0) ??
        0) > 0,
  )
  const colSpan = showLlmErr ? 7 : 6

  return (
    <section className="panel flex min-h-0 flex-1 flex-col">
      <header className="panel-title">
        <span>历史结果</span>
        <span className="ml-auto font-mono text-[9px] normal-case tracking-normal text-text-3">
          {mainRuns.length} 次运行
        </span>
      </header>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        {runs.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 px-8 py-16 text-center">
            <div className="text-[13px] font-medium text-text-1">尚无基准运行</div>
            <div className="max-w-md text-[11px] leading-5 text-text-2">
              基准对比「裸模型」与「CyberOrion 框架」两臂：CyberGym
              真实漏洞复现为主基准，CyberSOCEval 多选问答为辅助。各跑一次两臂
              即可看到框架带来的提升。
            </div>
          </div>
        ) : (
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-raised text-[9px] uppercase tracking-[0.15em] text-text-2">
              <tr>
                <th className="py-2 pl-5 text-left font-normal">时间</th>
                <th className="text-left font-normal">套件</th>
                <th className="text-left font-normal">臂</th>
                <th className="text-right font-normal">n</th>
                <th className="text-right font-normal">主指标</th>
                {showLlmErr && (
                  <th className="text-right font-normal text-attacker/70">模型错误</th>
                )}
                <th className="pr-5 text-right font-normal">耗时</th>
              </tr>
            </thead>
            <tbody>
              {mainRuns.map((r) => (
                <RunRow
                  key={r.run_id}
                  r={r}
                  dim={suiteOf(r) === 'attack_kb'}
                  showLlmErr={showLlmErr}
                  onSelect={onSelect}
                />
              ))}
              {legacyRuns.length > 0 && (
                <tr
                  onClick={() => setShowLegacy((v) => !v)}
                  className="cursor-pointer border-t border-hairline bg-white/[0.02] text-text-2 transition-colors hover:bg-white/[0.04]"
                >
                  <td colSpan={colSpan} className="py-1.5 pl-5 text-[10px]">
                    {showLegacy ? '▾' : '▸'} 历史实验（{legacyRuns.length}）·
                    rag_fs / sc / sc_base / rag_g 旧模式对比运行
                  </td>
                </tr>
              )}
              {showLegacy &&
                legacyRuns.map((r) => (
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

  const load = useCallback(() => {
    api
      .getBenchRuns()
      .then(setRuns)
      .catch(() => {
        /* keep last */
      })
  }, [])

  // initial + whenever a run completes (benchStamp bumps on WS bench done/error)
  useEffect(() => {
    load()
  }, [load, benchStamp])

  // merge live WS progress into any running rows the server returned
  const merged = useMemo(() => {
    const list = runs.map((r) => {
      const live = benchLive[r.run_id]
      return live && r.status === 'running'
        ? { ...r, progress: live.progress }
        : r
    })
    const known = new Set(list.map((r) => r.run_id))
    for (const live of Object.values(benchLive)) {
      if (!known.has(live.run_id)) {
        list.unshift({
          run_id: live.run_id,
          mode: live.mode,
          suite: live.suite,
          n: live.n,
          status: 'running',
          progress: live.progress,
          scores: null,
        })
      }
    }
    return list
  }, [runs, benchLive])

  return (
    <main className="scroll-thin min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex min-h-full max-w-[1100px] flex-col gap-4 p-6">
        <div className="flex items-baseline gap-3">
          <h1 className="text-[17px] font-semibold text-text-1">Benchmark</h1>
          <span className="text-[11px] text-text-2">
            框架带来了多少提升 · 裸模型 vs CyberOrion 框架 · CyberGym
            真实漏洞复现为主基准
          </span>
        </div>
        <RunCard onStarted={load} />
        <CompareCharts runs={merged} />
        <ResultsTable runs={merged} onSelect={setSelected} />
      </div>
      {selected && (
        <BenchDetailDrawer run={selected} onClose={() => setSelected(null)} />
      )}
    </main>
  )
}
