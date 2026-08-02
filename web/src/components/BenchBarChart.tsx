// 标准分组柱状图（参考大模型发布时的跑分评估图）：
// Y 轴 = 得分（0-100%，刻度 + 网格线 + 轴标题），X 轴 = 指标组
// （选择题正确率 / Jaccard 得分，组下双行字标），每组两根柱 —
// DeepSeek（纯 LLM 基座，半透明）vs DeepSeek + CyberOrion 防御框架
// （实心白），柱顶数值，图例含每次运行的 n 与日期，右上 Δ 徽章，
// 图下方逐字说明指标含义。

import { useMemo } from 'react'
import type {
  BenchRunSummary,
  BenchScores,
  BenchSuite,
} from '../types'
import {
  BENCH_ARMS,
  BENCH_SUITES,
  LEGACY_BENCH_MODES,
  armOfMode,
} from '../types'
import { fmtRunTime } from './BenchmarkView'
import { useTheme } from '../theme'

// 图表色板跟随明暗主题（SVG 不消费 CSS 变量，需显式取值）。
export interface ChartPalette {
  bare: string
  framework: string
  axis: string
  grid: string
  tick: string
  label: string
  labelSoft: string
  value: string
}

function chartPalette(theme: 'light' | 'dark'): ChartPalette {
  const dark = theme === 'dark'
  return {
    bare: dark ? 'rgba(255,255,255,0.30)' : 'rgba(0,0,0,0.25)',
    framework: dark ? '#f5f5f5' : '#111',
    axis: dark ? 'rgba(255,255,255,0.20)' : 'rgba(0,0,0,0.15)',
    grid: dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)',
    tick: dark ? 'rgba(255,255,255,0.55)' : 'rgba(0,0,0,0.55)',
    label: dark ? 'rgba(255,255,255,0.70)' : 'rgba(0,0,0,0.70)',
    labelSoft: dark ? 'rgba(255,255,255,0.55)' : 'rgba(0,0,0,0.55)',
    value: dark ? '#fff' : '#111',
  }
}

// ---------------------------------------------------------------------------
// metric definitions per suite
// ---------------------------------------------------------------------------

interface MetricDef {
  key: string
  label: string
  desc: string
  get: (scores: BenchScores) => number | undefined
}

function metricsFor(_suite: BenchSuite): MetricDef[] {
  return [
    {
      key: 'correct_mc_pct',
      label: '选择题正确率',
      desc: 'exact-match 全对比例',
      get: (s) => s.correct_mc_pct,
    },
    {
      key: 'avg_score',
      label: 'Jaccard 得分',
      desc: '部分分（交集 ÷ 并集）',
      get: (s) => s.avg_score,
    },
  ]
}

function fmtPctLabel(v: number): string {
  return `${(v * 100).toFixed(1)}%`
}

/** Latest scored run of one arm (runs already sorted oldest-first). */
function latestOfArm(
  runs: BenchRunSummary[],
  arm: 'bare' | 'framework',
): BenchRunSummary | undefined {
  return [...runs].reverse().find((r) => armOfMode(r.mode) === arm)
}

/** 基座模型展示名：deepseek-* -> "DeepSeek"，其余取模型短名。 */
export function modelLabel(model: string | undefined): string {
  const m = (model || '').toLowerCase()
  if (m.startsWith('deepseek')) return 'DeepSeek'
  return model || 'LLM'
}

// ---------------------------------------------------------------------------
// chart
// ---------------------------------------------------------------------------

/** Bar path with only the top corners rounded. */
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
  const theme = useTheme()
  const C = chartPalette(theme)
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
  const baseModel = modelLabel((bare ?? framework)?.model)

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
          baseModel={baseModel}
          palette={C}
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

  const W = 700
  const H = 264
  const PAD = { l: 56, r: 18, t: 22, b: 48 }
  const plotW = W - PAD.l - PAD.r
  const plotH = H - PAD.t - PAD.b
  const yBase = H - PAD.b
  const y = (v: number) => PAD.t + (1 - Math.max(0, Math.min(v, 1))) * plotH
  const barW = 42
  const barGap = 16
  const groupW = barW * 2 + barGap
  const groupX = (i: number) =>
    PAD.l + (plotW * (i + 0.5)) / metrics.length - groupW / 2

  return (
    <section className="panel flex-none p-5">
      <ChartHeader
        suite={suite}
        bare={bare}
        framework={framework}
        delta={delta}
        baseModel={baseModel}
        palette={C}
      />

      <svg viewBox={`0 0 ${W} ${H}`} className="mt-1 w-full">
        {/* Y 轴标题（旋转）：得分（%） */}
        <text
          transform={`translate(15 ${PAD.t + plotH / 2}) rotate(-90)`}
          textAnchor="middle"
          fontSize="9.5"
          letterSpacing="0.14em"
          fill={C.tick}
          fontFamily='"Barlow", "PingFang SC", sans-serif'
        >
          得分（%）
        </text>

        {/* Y 轴竖线 */}
        <line x1={PAD.l} x2={PAD.l} y1={PAD.t} y2={yBase}
              stroke={C.axis} strokeWidth="1" />

        {/* 网格线 + Y 刻度标签（0/25/50/75/100） */}
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <g key={f}>
            <line
              x1={PAD.l}
              x2={W - PAD.r}
              y1={y(f)}
              y2={y(f)}
              stroke={f === 0 ? C.axis : C.grid}
              strokeWidth="1"
            />
            <text
              x={PAD.l - 8}
              y={y(f) + 3}
              textAnchor="end"
              fontSize="9.5"
              fill={C.tick}
              fontFamily="ui-monospace, Menlo, monospace"
            >
              {Math.round(f * 100)}%
            </text>
          </g>
        ))}

        {/* 分组柱 + 柱顶数值 + X 轴组标签 */}
        {values.map((m, i) => {
          const gx = groupX(i)
          return (
            <g key={m.key}>
              {([
                { v: m.bare, color: C.bare, x: gx },
                { v: m.framework, color: C.framework, x: gx + barW + barGap },
              ] as const).map(
                (b, j) =>
                  b.v != null && (
                    <g key={j}>
                      <path
                        d={barPath(b.x, y(b.v), barW, Math.max(yBase - y(b.v), 1), 3)}
                        fill={b.color}
                      />
                      <text
                        x={b.x + barW / 2}
                        y={y(b.v) - 7}
                        textAnchor="middle"
                        fontSize="12.5"
                        fill={C.value}
                        fontFamily='"Instrument Serif", Georgia, serif'
                        fontStyle="italic"
                      >
                        {fmtPctLabel(b.v)}
                      </text>
                    </g>
                  ),
              )}
              {/* X 轴组标签：指标名 + 说明 */}
              <text
                x={gx + groupW / 2}
                y={H - 28}
                textAnchor="middle"
                fontSize="11.5"
                fill={C.label}
                fontFamily='"Barlow", "PingFang SC", sans-serif'
              >
                {m.label}
              </text>
              <text
                x={gx + groupW / 2}
                y={H - 13}
                textAnchor="middle"
                fontSize="8.5"
                fill={C.tick}
                fontFamily="ui-monospace, Menlo, monospace"
              >
                {m.desc}
              </text>
            </g>
          )
        })}
      </svg>

      {/* 指标含义说明 */}
      <p className="mt-3 border-t border-hairline/60 pt-2.5 text-[10px] leading-5 text-text-3">
        两组柱均为 <span className="text-text-2">得分越高越好</span>：
        选择题正确率 = 答案与标准选项完全一致的比例（全对才算对）；
        Jaccard 得分 = 部分得分（预测选项与标准选项的<b>交集 ÷ 并集</b>，
        多选漏选/误选都会扣分）。两臂回答<b>同一批题目</b>、同一个基座
        模型，唯一差异是 CyberOrion 防御框架注入的知识库层，柱高差即
        框架增益（Δ）。
      </p>
    </section>
  )
}

// ---------------------------------------------------------------------------
// header: 套件 + 基座模型 + 图例（臂名/n/日期）+ Δ 徽章
// ---------------------------------------------------------------------------

function ChartHeader({
  suite,
  bare,
  framework,
  delta,
  baseModel,
  palette,
}: {
  suite: BenchSuite
  bare?: BenchRunSummary
  framework?: BenchRunSummary
  delta: number | null
  baseModel: string
  palette: ChartPalette
}) {
  const legend = (
    [
      { run: bare, color: palette.bare, name: `${baseModel}（纯 LLM 基座）` },
      {
        run: framework,
        color: palette.framework,
        name: `${baseModel} + CyberOrion 防御框架`,
      },
    ] as const
  ).filter((l) => l.run)
  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="flex flex-col gap-1">
        <span className="text-[13px] font-semibold text-text-1">
          {BENCH_SUITES[suite].label}
        </span>
        <span className="text-[9px] tracking-wide text-text-3">
          基座模型：{baseModel}（{bare?.model ?? framework?.model}）
        </span>
      </div>
      <span className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-text-2">
        {legend.map((l) => (
          <span key={l.name} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2.5 w-2.5 rounded-[3px]"
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
            title="首指标（选择题正确率）：框架 − 基座（百分点）"
            className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold tabular-nums ${
              delta > 0
                ? 'border-line bg-panel text-fg'
                : delta < 0
                  ? 'border-attacker/40 bg-attacker/10 text-attacker'
                  : 'border-hairline text-text-2'
            }`}
          >
            Δ {delta > 0 ? '+' : ''}
            {(delta * 100).toFixed(1)}pt
          </span>
        )}
      </span>
    </div>
  )
}
