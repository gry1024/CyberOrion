// Benchmark 详情抽屉: 问答套件 → 按难度柱状条 + 按主题表格 + 逐题详情
// (完整题干/选项/gold vs pred/模型原始回答 markdown)。单题完整数据在展开时
// 经 /api/bench/run/{id}/task/{idx} 惰性拉取（旧运行缺什么显示什么）。

import { useEffect, useState } from 'react'
import { api } from '../api'
import type {
  BenchResultItem,
  BenchRunDetail,
  BenchRunSummary,
} from '../types'
import { armLabelOf } from '../types'
import { fmtDuration, fmtPct, fmtRunTime } from './BenchmarkView'
import { MarkdownView } from './MarkdownView'

const DIFF_ORDER = ['easy', 'medium', 'hard']

function GroupBar({
  label,
  n,
  pct,
  score,
}: {
  label: string
  n: number
  pct: number
  score: number
}) {
  return (
    <div className="flex items-center gap-3">
      <span className="w-16 flex-none text-[11px] text-text-2">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-overlay">
        <div
          className="h-full rounded-full bg-text-1"
          style={{ width: `${Math.min(pct * 100, 100)}%` }}
        />
      </div>
      <span className="w-14 flex-none text-right font-mono text-[10px] tabular-nums text-text-1">
        {fmtPct(pct)}
      </span>
      <span className="w-16 flex-none text-right font-mono text-[9px] tabular-nums text-text-3">
        n={n} · {score.toFixed(2)}
      </span>
    </div>
  )
}

/** 展开时惰性拉取单题完整详情（题干补全）。 */
function useTaskDetail(runId: string, idx: number, enabled: boolean) {
  const [task, setTask] = useState<BenchResultItem | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    if (!enabled || task || failed) return
    let stale = false
    api
      .getBenchTask(runId, idx)
      .then((d) => {
        if (!stale) setTask(d.task)
      })
      .catch(() => {
        if (!stale) setFailed(true)
      })
    return () => {
      stale = true
    }
  }, [enabled, task, failed, runId, idx])
  return { task, loading: enabled && !task && !failed }
}

// ---------------------------------------------------------------------------
// QA 套件：逐题 drill-down
// ---------------------------------------------------------------------------

function OptionList({ q }: { q: BenchResultItem }) {
  if (!q.options?.length) return null
  const gold = new Set(q.gold)
  const pred = new Set(q.pred)
  return (
    <ul className="space-y-1">
      {q.options.map((opt, i) => {
        const letter = String.fromCharCode(65 + i)
        const isGold = gold.has(letter)
        const isPred = pred.has(letter)
        return (
          <li
            key={i}
            className={`flex items-baseline gap-2 rounded px-2 py-0.5 text-[11px] leading-5 ${
              isGold
                ? 'bg-success/[0.07] text-success'
                : isPred
                  ? 'bg-attacker/[0.07] text-attacker/80'
                  : 'text-text-2'
            }`}
          >
            <span className="w-4 flex-none font-mono font-semibold">{letter}</span>
            <span className="min-w-0">{opt.replace(/^\s*[A-H]\s*[.、)]\s*/, '')}</span>
            <span className="ml-auto flex-none font-mono text-[9px]">
              {isGold && isPred ? '正确·已选' : isGold ? '正确·漏选' : isPred ? '误选' : ''}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

function QuestionDrill({ q }: { q: BenchResultItem }) {
  return (
    <div className="space-y-2.5 border-t border-hairline/50 px-3 py-2.5">
      {/* 完整题干 */}
      <MarkdownView markdown={q.question} className="md-inline" />
      {/* 选项（gold/pred 高亮） */}
      <OptionList q={q} />
      {/* gold vs pred 判定 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px]">
        <span className="text-success">正确 [{q.gold.join(',')}]</span>
        <span className={q.exact ? 'text-text-1' : 'text-attacker/80'}>
          模型 [{q.pred.join(',') || '—'}]
        </span>
        <span className={q.exact ? 'text-success' : 'text-attacker/80'}>
          {q.exact ? '✓ 完全匹配' : '✗ 不完全匹配'}
        </span>
        <span className="text-text-3">Jaccard 得分 {q.jaccard.toFixed(2)}</span>
        {!q.parse_ok && <span className="text-warning">解析失败</span>}
      </div>
      {/* 模型原始回答（可折叠 markdown） */}
      {q.raw && (
        <details className="rounded-lg border border-hairline/50 bg-panel-2/60">
          <summary className="cursor-pointer px-2.5 py-1.5 text-[10px] text-text-2 transition-colors hover:text-fg">
            模型原始回答（推理过程）
          </summary>
          <div className="scroll-thin max-h-64 overflow-y-auto px-2.5 pb-2">
            <MarkdownView markdown={q.raw} className="md-inline" />
          </div>
        </details>
      )}
    </div>
  )
}

function QuestionRow({
  runId,
  item,
  idx,
}: {
  runId: string
  item: BenchResultItem
  idx: number
}) {
  const [open, setOpen] = useState(false)
  const { task, loading } = useTaskDetail(runId, idx, open)
  const full = task ?? item
  return (
    <div className="rounded-lg border border-hairline/60">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors hover:bg-overlay"
      >
        <span className="flex-none font-mono text-[10px] tabular-nums text-text-3">
          #{idx + 1}
        </span>
        <span className="flex-none rounded bg-overlay px-1.5 py-px text-[9px] text-text-2">
          {item.difficulty}
        </span>
        <span className="min-w-0 truncate text-[11px] text-text-2">
          {item.question}
        </span>
        <span
          className={`ml-auto flex-none font-mono text-[10px] ${
            item.exact ? 'text-success' : 'text-attacker/70'
          }`}
        >
          {item.exact ? '✓' : '✗'}
        </span>
        <span className="flex-none font-mono text-[9px] text-text-3">
          {open ? '▾' : '▸'}
        </span>
      </button>
      {open &&
        (loading ? (
          <div className="border-t border-hairline/50 px-3 py-2 text-[10px] text-text-3">
            加载题目详情…
          </div>
        ) : (
          <QuestionDrill q={full} />
        ))}
    </div>
  )
}

function QuestionsSection({
  run,
  detail,
}: {
  run: BenchRunSummary
  detail: BenchRunDetail | null
}) {
  const items = detail?.results ?? []
  const [showAll, setShowAll] = useState(false)
  if (items.length === 0) return null
  const wrongFirst = [...items].sort((a, b) => Number(a.exact) - Number(b.exact))
  const shown = showAll ? wrongFirst : wrongFirst.slice(0, 20)
  const idxOf = (item: BenchResultItem) => items.indexOf(item)
  return (
    <section>
      <div className="mb-2.5 flex items-baseline gap-2 text-[10px] uppercase tracking-widest text-text-2">
        <span>逐题详情 · 错题优先</span>
        <span className="font-mono normal-case tracking-normal text-text-3">
          {items.filter((i) => !i.exact).length} 错 / {items.length} 题
        </span>
      </div>
      <div className="space-y-1.5">
        {shown.map((item) => (
          <QuestionRow
            key={idxOf(item)}
            runId={run.run_id}
            item={item}
            idx={idxOf(item)}
          />
        ))}
      </div>
      {items.length > 20 && (
        <button
          onClick={() => setShowAll((v) => !v)}
          className="mt-2 rounded-full bg-overlay px-3 py-1 text-[10px] text-text-3 transition-colors hover:bg-raised hover:text-text-1"
        >
          {showAll ? '▾ 只显示前 20 题' : `▸ 展开全部 ${items.length} 题`}
        </button>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// drawer
// ---------------------------------------------------------------------------

export function BenchDetailDrawer({
  run,
  onClose,
}: {
  run: BenchRunSummary
  onClose: () => void
}) {
  const [detail, setDetail] = useState<BenchRunDetail | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setDetail(null)
    setError('')
    api
      .getBenchRun(run.run_id)
      .then(setDetail)
      .catch(() => setError('运行详情读取失败'))
  }, [run.run_id])

  const suite = run.suite ?? 'malware_analysis'
  const qaScores = detail?.scores ?? run.scores
  const overall = qaScores?.correct_mc_pct ?? 0
  const topics = Object.entries(qaScores?.by_topic ?? {}).sort(
    (a, b) => a[1].correct_mc_pct - b[1].correct_mc_pct,
  )
  const diffs = DIFF_ORDER.filter((d) => qaScores?.by_difficulty?.[d]).map(
    (d) => [d, qaScores!.by_difficulty[d]] as const,
  )

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/25" onClick={onClose}>
      <aside
        className="liquid-glass-strong scroll-thin m-4 flex w-[680px] flex-none flex-col gap-5 overflow-y-auto rounded-[1.25rem] p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* header */}
        <div className="flex items-start gap-3">
          <div>
            <div className="font-mono text-[13px] font-medium text-text-1">
              {run.run_id}
            </div>
            <div className="mt-1 text-[11px] text-text-2">
              {fmtRunTime(run.run_id)} · {suite} · {armLabelOf(run.mode)}
              （{run.mode}）· n={run.n}
              {detail?.model ? ` · ${detail.model}` : ''}
              {detail?.seed != null ? ` · seed ${detail.seed}` : ''}
              {detail?.rag_top_k ? ` · top_k ${detail.rag_top_k}` : ''}
              {run.elapsed_sec != null ? ` · ${fmtDuration(run.elapsed_sec)}` : ''}
            </div>
          </div>
          <button
            onClick={onClose}
            className="ml-auto rounded-full bg-overlay px-3 py-1 text-[10px] text-text-3 transition-colors hover:bg-hover hover:text-text-1"
          >
            关闭 ✕
          </button>
        </div>

        {error && <div className="text-[11px] text-attacker">{error}</div>}

        {!qaScores ? (
          !error && <div className="text-[11px] text-text-2">加载中…</div>
        ) : (
          <>
              {/* headline metrics */}
              <div className="grid grid-cols-3 divide-x divide-hairline rounded-xl border border-hairline">
                <div className="px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
                    选择题正确率
                  </div>
                  <div className="mt-1 font-serif text-3xl italic tabular-nums text-text-1">
                    {fmtPct(qaScores.correct_mc_pct)}
                  </div>
                </div>
                <div className="px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
                    平均得分
                  </div>
                  <div className="mt-1 font-serif text-3xl italic tabular-nums text-text-1">
                    {qaScores.avg_score.toFixed(3)}
                  </div>
                </div>
                <div className="px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
                    解析失败
                  </div>
                  <div
                    className={`mt-1 font-serif text-3xl italic tabular-nums ${
                      qaScores.parse_fail > 0 ? 'text-warning' : 'text-text-1'
                    }`}
                  >
                    {qaScores.parse_fail}
                  </div>
                </div>
              </div>

              {/* by difficulty */}
              {diffs.length > 0 && (
                <section>
                  <div className="mb-2.5 text-[10px] uppercase tracking-widest text-text-2">
                    按难度
                  </div>
                  <div className="space-y-2">
                    {diffs.map(([d, g]) => (
                      <GroupBar
                        key={d}
                        label={d}
                        n={g.n}
                        pct={g.correct_mc_pct}
                        score={g.avg_score}
                      />
                    ))}
                  </div>
                </section>
              )}

              {/* by topic — weakest first, weak ones in muted red */}
              {topics.length > 0 && (
                <section>
                  <div className="mb-2.5 text-[10px] uppercase tracking-widest text-text-2">
                    按主题 · 弱项优先
                  </div>
                  <table className="w-full text-[11px]">
                    <thead className="text-[9px] uppercase tracking-[0.15em] text-text-3">
                      <tr>
                        <th className="pb-1.5 text-left font-normal">主题</th>
                        <th className="pb-1.5 text-right font-normal">n</th>
                        <th className="pb-1.5 text-right font-normal">正确率</th>
                        <th className="pb-1.5 text-right font-normal">平均得分</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topics.map(([topic, g]) => {
                        const weak = g.correct_mc_pct < overall
                        return (
                          <tr key={topic} className="border-t border-hairline/60">
                            <td
                              className={`py-1.5 pr-2 ${
                                weak ? 'text-attacker/70' : 'text-text-2'
                              }`}
                            >
                              {topic}
                            </td>
                            <td className="py-1.5 text-right font-mono tabular-nums text-text-2">
                              {g.n}
                            </td>
                            <td
                              className={`py-1.5 text-right font-mono tabular-nums ${
                                weak ? 'text-attacker/70' : 'text-text-1'
                              }`}
                            >
                              {fmtPct(g.correct_mc_pct)}
                            </td>
                            <td className="py-1.5 text-right font-mono tabular-nums text-text-2">
                              {g.avg_score.toFixed(3)}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </section>
              )}

              {/* 逐题 drill-down */}
              <QuestionsSection run={run} detail={detail} />
          </>
        )}
      </aside>
    </div>
  )
}
