// 论文风格对比柱状图 (paper-style grouped bar chart): 每个套件一张图,
// X 组 = 指标, 每组两根柱子 — 裸模型 (gray) vs CyberOrion 框架 (green),
// 取每臂最近一次有分数的运行; 柱顶数值标签, 0–100% 轴 + 25/50/75 细网格线,
// 右上角图例 (含该次运行 n 与日期) + Δ 徽章 (首指标 框架 − 裸模型, 单位 pt)。
// CyberGym 图下方附逐任务对比小表 (vanilla ✓/✗ | framework ✓/✗)。

import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type {
  BenchAnyScores,
  BenchRunDetail,
  BenchRunSummary,
  BenchSuite,
  CyberGymTaskResult,
} from '../types'
import {
  BENCH_ARMS,
  BENCH_SUITES,
  LEGACY_BENCH_MODES,
  armOfMode,
  isCyberGymResult,
  isCyberGymScores,
} from '../types'
import { fmtRunTime } from './BenchmarkView'

const COLOR_BARE = '#6b7280'
const COLOR_FRAMEWORK = '#5ed29c'

// ---------------------------------------------------------------------------
// metric definitions per suite
// ---------------------------------------------------------------------------

interface MetricDef {
  key: string
  label: string
  get: (scores: BenchAnyScores) => number | undefined
}

function metricsFor(suite: BenchSuite): MetricDef[] {
  if (suite === 'cybergym') {
    return [
      {
        key: 'any_of_pct',
        label: '成功率 ANY-OF',
        get: (s) => (isCyberGymScores(s) ? s.any_of_pct : undefined),
      },
      {
        key: 'success_pct',
        label: '最终提交成功率',
        get: (s) => (isCyberGymScores(s) ? s.success_pct : undefined),
      },
    ]
  }
  return [
    {
      key: 'correct_mc_pct',
      label: '正确率',
      get: (s) => (!isCyberGymScores(s) ? s.correct_mc_pct : undefined),
    },
    {
      key: 'avg_score',
      label: 'JACCARD',
      get: (s) => (!isCyberGymScores(s) ? s.avg_score : undefined),
    },
  ]
}

function fmtPctLabel(v: number): string {
  return `${(v * 100).toFixed(1)}%`
}

/** Latest scored run of one arm (run_id starts with a sortable timestamp). */
function latestOfArm(
  runs: BenchRunSummary[],
  arm: 'bare' | 'framework',
): BenchRunSummary | undefined {
  return [...runs].reverse().find((r) => armOfMode(r.mode) === arm)
}

// ---------------------------------------------------------------------------
// per-task mini-table (cybergym): makes framework wins concrete
// ---------------------------------------------------------------------------

function TaskMark({ r }: { r: CyberGymTaskResult | undefined }) {
  if (!r) return <span className="text-text-3">—</span>
  return r.success ? (
    <span className="font-semibold text-accent">✓</span>
  ) : (
    <span className="text-text-3">✗</span>
  )
}

function CyberGymTaskTable({
  bare,
  framework,
}: {
  bare: BenchRunSummary
  framework: BenchRunSummary
}) {
  const [results, setResults] = useState<{
    bare?: CyberGymTaskResult[]
    framework?: CyberGymTaskResult[]
  }>({})

  useEffect(() => {
    let alive = true
    const pick = (d: BenchRunDetail) =>
      (d.results ?? []).filter(isCyberGymResult)
    Promise.all([api.getBenchRun(bare.run_id), api.getBenchRun(framework.run_id)])
      .then(([b, f]) => {
        if (alive) setResults({ bare: pick(b), framework: pick(f) })
      })
      .catch(() => {
        /* table stays hidden */
      })
    return () => {
      alive = false
    }
  }, [bare.run_id, framework.run_id])

  const rows = useMemo(() => {
    if (!results.bare || !results.framework) return []
    const byId = (list: CyberGymTaskResult[]) =>
      new Map(list.map((r) => [r.task_id, r]))
    const b = byId(results.bare)
    const f = byId(results.framework)
    return [...new Set([...b.keys(), ...f.keys()])].sort().map((id) => ({
      id,
      project: b.get(id)?.project ?? f.get(id)?.project ?? '?',
      bare: b.get(id),
      framework: f.get(id),
    }))
  }, [results])

  if (rows.length === 0) return null
  return (
    <div className="mt-4 border-t border-hairline pt-4">
      <div className="mb-2 text-[10px] uppercase tracking-widest text-text-2">
        逐任务对比 · 最终提交口径
      </div>
      <table className="w-full text-[11px]">
        <thead className="text-[9px] uppercase tracking-[0.15em] text-text-3">
          <tr>
            <th className="pb-1.5 text-left font-normal">task_id</th>
            <th className="pb-1.5 text-left font-normal">项目</th>
            <th className="pb-1.5 text-center font-normal">
              {BENCH_ARMS.cybergym.bare.label}
            </th>
            <th className="pb-1.5 text-center font-normal">
              {BENCH_ARMS.cybergym.framework.label}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const fwWin = !!row.framework?.success && !row.bare?.success
            return (
              <tr
                key={row.id}
                className={`border-t border-hairline/60 ${
                  fwWin ? 'bg-accent/[0.06]' : ''
                }`}
              >
                <td className="py-1.5 pr-2 font-mono text-neutral-300">{row.id}</td>
                <td className="py-1.5 pr-2 text-text-2">{row.project}</td>
                <td className="py-1.5 text-center">
                  <TaskMark r={row.bare} />
                </td>
                <td className="py-1.5 text-center">
                  <TaskMark r={row.framework} />
                  {fwWin && (
                    <span className="ml-1.5 rounded-full border border-accent/40 px-1.5 py-px text-[9px] text-accent">
                      框架胜
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------
// chart
// ---------------------------------------------------------------------------

/** Bar path with only the top corners rounded (rounded-t-[2px]). */
function barPath(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, h, w / 2)
  return `M ${x} ${y + h} L ${x} ${y + rr} Q ${x} ${y} ${x + rr} ${y} ` +
    `L ${x + w - rr} ${y} Q ${x + w} ${y} ${x + w} ${y + rr} L ${x + w} ${y + h} Z`
}

export function BenchBarChart({
  suite,
  runs,
}: {
  suite: BenchSuite
  runs: BenchRunSummary[]
}) {
  const scored = useMemo(
    () =>
      runs
        .filter(
          (r) =>
            (r.suite ?? 'malware_analysis') === suite &&
            r.scores &&
            !LEGACY_BENCH_MODES.has(r.mode),
        )
        .slice()
        .sort((a, b) => a.run_id.localeCompare(b.run_id)),
    [runs, suite],
  )
  const bare = latestOfArm(scored, 'bare')
  const framework = latestOfArm(scored, 'framework')
  if (scored.length === 0 || (!bare && !framework)) return null

  const metrics = metricsFor(suite)
  const arms = BENCH_ARMS[suite]

  // ---- paired? otherwise dashed empty state -------------------------------
  if (!bare || !framework) {
    const have = bare ?? framework!
    const haveArm = bare ? arms.bare : arms.framework
    const missingArm = bare ? arms.framework : arms.bare
    const firstMetric = have.scores ? metrics[0].get(have.scores) : undefined
    return (
      <section className="panel flex-none p-5">
        <ChartHeader
          suite={suite}
          bare={bare}
          framework={framework}
          delta={null}
        />
        <div className="rounded-xl border border-dashed border-hairline px-6 py-10 text-center">
          <div className="text-[12px] text-text-2">
            暂无成对数据——先各跑一次 {arms.bare.mode} 和 {arms.framework.mode}
          </div>
          <div className="mt-2 text-[10px] text-text-3">
            已有 {haveArm.label}（n={have.n} · {fmtRunTime(have.run_id)}
            {firstMetric != null
              ? ` · ${metrics[0].label} ${fmtPctLabel(firstMetric)}`
              : ''}
            ）；再跑一次 {missingArm.mode} 即可对比
          </div>
        </div>
      </section>
    )
  }

  // ---- paired chart ---------------------------------------------------------
  const values = metrics.map((m) => ({
    ...m,
    bare: bare.scores ? m.get(bare.scores) : undefined,
    framework: framework.scores ? m.get(framework.scores) : undefined,
  }))
  const delta =
    values[0].bare != null && values[0].framework != null
      ? values[0].framework - values[0].bare
      : null

  const W = 660
  const H = 240
  const PAD = { l: 46, r: 20, t: 26, b: 34 }
  const plotW = W - PAD.l - PAD.r
  const plotH = H - PAD.t - PAD.b
  const yBase = H - PAD.b
  const y = (v: number) => PAD.t + (1 - Math.max(0, Math.min(v, 1))) * plotH
  const barW = 36
  const barGap = 12
  const groupW = barW * 2 + barGap
  const groupX = (i: number) => PAD.l + (plotW * (i + 0.5)) / metrics.length - groupW / 2

  return (
    <section className="panel flex-none p-5">
      <ChartHeader suite={suite} bare={bare} framework={framework} delta={delta} />
      <svg viewBox={`0 0 ${W} ${H}`} className="mt-1 w-full">
        {/* horizontal hairline gridlines 25/50/75 + baseline */}
        {[0.25, 0.5, 0.75].map((f) => (
          <line
            key={f}
            x1={PAD.l}
            x2={W - PAD.r}
            y1={y(f)}
            y2={y(f)}
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="1"
          />
        ))}
        <line
          x1={PAD.l}
          x2={W - PAD.r}
          y1={yBase}
          y2={yBase}
          stroke="rgba(255,255,255,0.14)"
          strokeWidth="1"
        />
        {/* y ticks */}
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <text
            key={f}
            x={PAD.l - 8}
            y={y(f) + 3}
            textAnchor="end"
            fontSize="9"
            fill="#4a524e"
            fontFamily="ui-monospace, Menlo, monospace"
          >
            {Math.round(f * 100)}%
          </text>
        ))}
        {/* grouped bars */}
        {values.map((m, i) => {
          const gx = groupX(i)
          return (
            <g key={m.key}>
              {([
                { v: m.bare, color: COLOR_BARE, x: gx },
                { v: m.framework, color: COLOR_FRAMEWORK, x: gx + barW + barGap },
              ] as const).map(
                (b, j) =>
                  b.v != null && (
                    <g key={j}>
                      <path
                        d={barPath(b.x, y(b.v), barW, Math.max(yBase - y(b.v), 1), 2)}
                        fill={b.color}
                      />
                      <text
                        x={b.x + barW / 2}
                        y={y(b.v) - 6}
                        textAnchor="middle"
                        fontSize="11"
                        fill="#f2f5f3"
                        fontFamily="ui-monospace, Menlo, monospace"
                      >
                        {fmtPctLabel(b.v)}
                      </text>
                    </g>
                  ),
              )}
              <text
                x={gx + groupW / 2}
                y={H - 10}
                textAnchor="middle"
                fontSize="10"
                fill="#8a938f"
                letterSpacing="0.08em"
                fontFamily='"Plus Jakarta Sans", "Inter", "PingFang SC", sans-serif'
              >
                {m.label}
              </text>
            </g>
          )
        })}
      </svg>
      {suite === 'cybergym' && (
        <>
          <div className="mt-2 text-[9px] leading-4 text-text-3">
            口径：最终提交成功率 = 最后一次提交的 PoC 崩溃漏洞版且不影响修复版
            （CyberGym 官方 checker 判定）；any-of = 任意一次提交满足同条件。
          </div>
          <CyberGymTaskTable bare={bare} framework={framework} />
        </>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// header: title + legend (arm names + run n/date) + Δ badge on first metric
// ---------------------------------------------------------------------------

function ChartHeader({
  suite,
  bare,
  framework,
  delta,
}: {
  suite: BenchSuite
  bare?: BenchRunSummary
  framework?: BenchRunSummary
  delta: number | null
}) {
  const arms = BENCH_ARMS[suite]
  const legend = (
    [
      { run: bare, color: COLOR_BARE, name: arms.bare.label },
      { run: framework, color: COLOR_FRAMEWORK, name: arms.framework.label },
    ] as const
  ).filter((l) => l.run)
  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
      <span className="text-[10px] uppercase tracking-widest text-text-2">
        裸模型 vs 框架
      </span>
      <span
        title={BENCH_SUITES[suite].hint}
        className={`rounded-full px-2 py-px text-[9px] ${
          suite === 'cybergym'
            ? 'border border-accent/50 text-accent'
            : 'bg-overlay text-neutral-400'
        }`}
      >
        {BENCH_SUITES[suite].label}
      </span>
      <span className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-text-2">
        {legend.map((l) => (
          <span key={l.name} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2 w-2 rounded-[2px]"
              style={{ background: l.color }}
            />
            {l.name}
            <span className="font-mono text-[9px] text-text-3">
              n={l.run!.n} · {fmtRunTime(l.run!.run_id)}
            </span>
          </span>
        ))}
        {delta != null && (
          <span
            title="首指标：框架 − 裸模型（百分点）"
            className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold tabular-nums ${
              delta > 0
                ? 'border-accent/40 bg-accent/10 text-accent'
                : delta < 0
                  ? 'border-attacker/40 bg-attacker/10 text-attacker'
                  : 'border-hairline text-text-2'
            }`}
          >
            {delta > 0 ? '+' : ''}
            {(delta * 100).toFixed(1)}pt
          </span>
        )}
      </span>
    </div>
  )
}
