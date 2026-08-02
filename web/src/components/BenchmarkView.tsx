// Benchmark 视图: 框架价值对比 —
// 运行卡片(CyberSOCEval; 裸模型 vs 框架臂 + 实时进度) ·
// 论文风格分组柱状图 BenchBarChart (每套件一张, Δ 徽章) · 历史结果表格
// (legacy 实验模式折叠)。

import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { useArena } from '../arena'
import { pushToast } from '../toasts'
import type {
  BenchMode,
  BenchQuestionPreview,
  BenchRunSummary,
  BenchSuite,
} from '../types'
import {
  BENCH_ARMS,
  BENCH_SUITES,
  LEGACY_BENCH_MODES,
  armLabelOf,
  armOfMode,
  primaryScoreOf,
} from '../types'
import { BenchBarChart } from './BenchBarChart'
import { BenchDetailDrawer } from './BenchDetail'
import { FadeIn } from './FadeIn'
import { MarkdownView } from './MarkdownView'
import { Modal } from './Modal'

// ---------------------------------------------------------------------------
// formatting helpers (run_id looks like `20260727_172628_malware_analysis_rag_n100`)
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
  const name = suite === 'attack_kb' ? 'ATT&CK 知识' : 'CyberSOCEval'
  return (
    <span
      title={meta.hint}
      className="rounded-full bg-overlay px-2 py-px text-[9px] text-text-3"
    >
      {name}
    </span>
  )
}

/** 臂徽章: 纯 LLM (vanilla/base) 灰, CyberOrion 框架 (framework/rag) 白,
 * legacy 实验模式描边。 */
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
      title="CyberOrion 框架臂（知识库层：两段式检索 + playbook 注入 + 作答规则）"
      className="rounded-full border border-hairline px-2 py-px font-mono text-[10px] font-medium text-fg"
    >
      {armLabelOf(mode)}
    </span>
  ) : (
    <span
      title="纯 LLM 对照臂（无框架增强）"
      className="rounded-full bg-overlay px-2 py-px font-mono text-[10px] text-text-3"
    >
      {armLabelOf(mode)}
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
      <div className="flex items-center rounded-full border border-hairline bg-overlay p-0.5">
        {options.map((o) => (
          <button
            key={String(o.value)}
            disabled={o.disabled}
            title={o.hint}
            onClick={() => onChange(o.value)}
            className={`rounded-full px-3 py-1 text-[11px] font-semibold tracking-wide transition-colors ${
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

/** 可发起对比的套件。 */
const RUNNABLE_SUITES: BenchSuite[] = [
  'malware_analysis',
  'attack_kb',
  'threat_intel',
]

/** 「ⓘ 套件说明」弹窗内容（静态 markdown，按套件）。 */
const SUITE_DOCS: Record<string, string> = {
  malware_analysis: `## CyberSOCEval · 恶意软件分析问答

**环境**：Meta PurpleLlama CyberSOCEval 的 malware_analysis 数据集，609 道
多选题（沙箱报告行为分析、ATT&CK 技术识别）。固定 seed 采样，两臂回答
**同一批**题目，保证可比。

**任务**：每题选出所有正确选项（1 个或多个），最后一行严格输出
\`ANSWER: ["A","C"]\`；容错解析器从自然语言回答中提取选项字母。

**对 AI 的期望**：以题目描述的恶意软件行为为依据**逐项裁决**，宁缺毋滥；
禁止弃答（必须给出最佳猜测）。rag 臂额外注入知识库检索结果
（ATT&CK 技术 / 恶意软件家族 / 沙箱报告解读知识）——只可参考，无关条目
必须忽略。

**评分**：**exact-match 正确率**（主指标）+ Jaccard 部分分，按难度 / 主题
分组统计；解析失败与 LLM 调用失败单独计数，绝不静默成 0 分。

**两臂对比（框架有效性）**：同一批题目、同一模型，唯一差异是框架的
知识库层——Δ 即框架增益。
- \`base\` 纯 LLM——单次 LLM 调用，裸提示（无框架增强）；
- \`rag\` CyberOrion 框架——两段式检索（家族类别+题干，低分则并入选项
  重检）+ 家族行为 playbook 确定性注入 + 禁止弃答/逐项裁决作答规则。`,
  attack_kb: `## ATT&CK 知识检索 · 知识库访问能力测试

**设计**：从 KB（ATT&CK 技术文档）取 detection 描述摘录作题干，5 个技术编号
选项中选出正确项（同战术干扰项，确定性洗牌）。**答案就在知识库里**——
纯 LLM 只能靠记忆背诵，框架臂把检索结果注入提示即可对号甄别。

**这就是框架有效性最直接的证据**：两臂同 seed 同批题同模型，唯一差异是
框架的知识库层。实测（deepseek-v4-flash, n=100, seed=42）：纯 LLM 51% →
CyberOrion 框架 87%（+36pt），所有战术主题全线上涨。

**评分**：单选题 exact-match 正确率（= Jaccard）。解析失败与 LLM 调用
失败单独计数。`,
}

function SuiteInfoModal({
  suite,
  onClose,
}: {
  suite: BenchSuite
  onClose: () => void
}) {
  return (
    <Modal title="套件说明" onClose={onClose} width="w-[680px]">
      <MarkdownView
        markdown={SUITE_DOCS[suite] ?? SUITE_DOCS.malware_analysis}
        className="md-doc"
      />
    </Modal>
  )
}

/** 题目预览：按 seed 采样展示具体题目与正确答案（与正式基准同采样逻辑）。 */
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
    <Modal
      title={`题目预览 · ${BENCH_SUITES[suite].label}`}
      onClose={onClose}
      width="w-[760px]"
    >
      {err ? (
        <div className="text-[11px] text-attacker">{err}</div>
      ) : !data ? (
        <div className="text-[11px] text-text-2">加载中…</div>
      ) : (
        <div className="scroll-thin max-h-[70vh] space-y-4 overflow-y-auto pr-1">
          <p className="text-[11px] leading-5 text-text-2">
            按 seed 42 采样的 {data.n} 道题（base 与 rag 两臂正式基准回答的
            就是这批题）。<span className="text-success">绿色为正确答案</span>；
            运行结束后点历史结果行，可在抽屉里逐题查看模型的作答与原始回答。
          </p>
          {data.questions.map((q, i) => (
            <div key={q.idx} className="rounded-lg border border-hairline/60 p-3">
              <div className="mb-1.5 flex items-baseline gap-2 text-[9px] text-text-3">
                <span className="font-mono">#{i + 1} (idx {q.idx})</span>
                {q.difficulty && <span>{q.difficulty}</span>}
                {q.topic && <span>{q.topic}</span>}
                {q.attack && <span>{q.attack}</span>}
              </div>
              <div className="text-[11px] leading-5 text-text-2">
                {q.question}
              </div>
              <ul className="mt-2 space-y-0.5">
                {q.options.map((opt, j) => {
                  const letter = String.fromCharCode(65 + j)
                  const isGold = q.correct_options.includes(letter)
                  return (
                    <li
                      key={j}
                      className={`flex items-baseline gap-2 rounded px-2 py-0.5 text-[11px] leading-5 ${
                        isGold
                          ? 'bg-success/[0.07] text-success'
                          : 'text-text-2'
                      }`}
                    >
                      <span className="w-4 flex-none font-mono font-semibold">
                        {letter}
                      </span>
                      <span className="min-w-0">
                        {opt.replace(/^\s*[A-H]\s*[.、)]\s*/, '')}
                      </span>
                      {isGold && (
                        <span className="ml-auto flex-none font-mono text-[9px]">
                          正确
                        </span>
                      )}
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

const N_OPTIONS: Record<BenchSuite, number[]> = {
  malware_analysis: [20, 50, 100],
  attack_kb: [20, 50, 100],
  threat_intel: [20, 50, 100],
}

function RunCard({ onStarted }: { onStarted: () => void }) {
  const { benchLive } = useArena()
  const [suite, setSuite] = useState<BenchSuite>('malware_analysis')
  const [n, setN] = useState(20)
  const [mode, setMode] = useState<BenchMode>(
    BENCH_ARMS.malware_analysis.framework.mode,
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [infoOpen, setInfoOpen] = useState(false)
  const [previewOpen, setPreviewOpen] = useState(false)

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
          pushToast(`基准测试启动失败：${msg}`, {
            side: 'system',
            title: '基准测试',
          })
        } else onStarted()
      })
      .catch((e) => {
        const msg = e instanceof Error ? e.message : '请求失败 — 后端未响应'
        setError(msg)
        pushToast(`基准测试启动失败：${msg}`, {
          side: 'system',
          title: '基准测试',
        })
      })
      .finally(() => setBusy(false))
  }

  return (
    <section className="liquid-glass-strong flex-none rounded-[1.25rem] p-5">
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
          label="题量"
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
          onClick={() => setPreviewOpen(true)}
          title="按 seed 采样预览题目（含正确答案）"
          className="btn-pill btn-ghost px-2!"
        >
          题目预览
        </button>
        <button
          onClick={() => setInfoOpen(true)}
          title="环境 / 任务 / 期望 / 评分方式"
          className="btn-pill btn-ghost px-2!"
        >
          ⓘ 套件说明
        </button>
        <button
          onClick={start}
          disabled={busy}
          className="btn-pill btn-primary ml-auto px-5! py-2! text-[11px]!"
        >
          {busy ? '启动中…' : '开始测试'}
        </button>
      </div>
      {infoOpen && (
        <SuiteInfoModal suite={suite} onClose={() => setInfoOpen(false)} />
      )}
      {previewOpen && (
        <QuestionPreviewModal
          suite={suite}
          onClose={() => setPreviewOpen(false)}
        />
      )}
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
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-overlay">
                  <div
                    className="h-full rounded-full bg-text-1 transition-all duration-500"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-16 flex-none text-right font-mono text-[10px] tabular-nums text-text-3">
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
    // 两套件都参与对比图。
    return (['malware_analysis', 'attack_kb'] as BenchSuite[]).filter((s) =>
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
    (r.scores ? r.scores.llm_errors : 0) ??
    0
  const span = showLlmErr ? 4 : 3
  return (
    <tr
      onClick={() => !running && onSelect(r)}
      title="点击查看逐题详情（完整题干/选项/模型作答）"
      className={`border-t border-hairline/60 transition-colors ${
        running
          ? 'text-text-2'
          : failed
            ? 'cursor-pointer bg-attacker/[0.06] text-attacker/90 hover:bg-attacker/10'
            : `cursor-pointer hover:bg-overlay ${dim ? 'text-text-3' : 'text-text-2'}`
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
            title="选择题正确率"
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
        (r.scores ? r.scores.llm_errors : 0) ??
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
              框架有效性对比：纯 LLM vs CyberOrion 框架——同一批题目、同一
              模型，唯一差异是框架注入的知识库层。各跑一次两臂即可看到框架
              增益；想先看看题目长什么样，点运行卡片里的「题目预览」。
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
                  dim={false}
                  showLlmErr={showLlmErr}
                  onSelect={onSelect}
                />
              ))}
              {legacyRuns.length > 0 && (
                <tr
                  onClick={() => setShowLegacy((v) => !v)}
                  className="cursor-pointer border-t border-hairline bg-panel-2/60 text-text-2 transition-colors hover:bg-panel-2"
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
      <div className="mx-auto flex min-h-full max-w-[1100px] flex-col gap-4 px-6 pb-6">
        <div className="flex flex-col gap-1">
          <h1 className="text-[20px] font-semibold text-fg">
            基准测试
          </h1>
          <span className="text-[13px] text-text-3">
            框架有效性对比 · 纯 LLM vs CyberOrion 框架 · 同一批题目同一模型 ·
            CyberSOCEval 知识问答基准
          </span>
        </div>
        <FadeIn>
          <RunCard onStarted={load} />
        </FadeIn>
        <FadeIn delay={0.08} className="flex flex-col gap-4">
          <CompareCharts runs={merged} />
        </FadeIn>
        <FadeIn delay={0.16} className="flex min-h-0 flex-1 flex-col">
          <ResultsTable runs={merged} onSelect={setSelected} />
        </FadeIn>
      </div>
      {selected && (
        <BenchDetailDrawer run={selected} onClose={() => setSelected(null)} />
      )}
    </main>
  )
}
