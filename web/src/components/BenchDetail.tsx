// Benchmark 详情抽屉: CyberGym 运行 → 逐任务卡片 (task_id/项目/成功徽章/
// 步数/耗时/vul+fix exit code/最终 PoC); 问答套件 → 按难度柱状条 + 按主题表格。

import { useEffect, useState } from 'react'
import { api } from '../api'
import type {
  BenchRunDetail,
  BenchRunSummary,
  CyberGymTaskResult,
} from '../types'
import { isCyberGymResult, isCyberGymScores } from '../types'
import { fmtDuration, fmtPct, fmtRunTime } from './BenchmarkView'

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
      <span className="w-16 flex-none text-[11px] text-neutral-300">{label}</span>
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

// ---------------------------------------------------------------------------
// CyberGym per-task cards
// ---------------------------------------------------------------------------

function TaskBadge({ r }: { r: CyberGymTaskResult }) {
  if (r.error && !r.submissions.length) {
    return (
      <span className="rounded-full border border-attacker/40 px-2 py-px text-[9px] text-attacker">
        错误
      </span>
    )
  }
  return r.success ? (
    <span className="rounded-full border border-accent/50 px-2 py-px text-[9px] font-medium text-accent">
      ✓ 成功
    </span>
  ) : (
    <span className="rounded-full bg-overlay px-2 py-px text-[9px] text-neutral-400">
      ✗ 未成功
    </span>
  )
}

function TaskCard({ r }: { r: CyberGymTaskResult }) {
  const lastSub = r.submissions[r.submissions.length - 1]
  const pocName = lastSub?.poc?.split('/').pop()
  return (
    <div className="rounded-xl border border-hairline p-4">
      <div className="flex items-center gap-2">
        <span className="font-mono text-[12px] font-medium text-text-1">
          {r.task_id}
        </span>
        <span className="rounded-full bg-overlay px-2 py-px text-[9px] text-neutral-400">
          {r.project}
        </span>
        {r.preliminary && (
          <span
            title="vul-only 降级模式：未做修复版复核"
            className="rounded-full border border-warning/40 px-2 py-px text-[9px] text-warning"
          >
            preliminary
          </span>
        )}
        <span className="ml-auto">
          <TaskBadge r={r} />
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] tabular-nums text-text-2">
        <span>步数 {r.steps}</span>
        <span>耗时 {fmtDuration(r.elapsed_sec)}</span>
        <span>提交 {r.submissions.length} 次</span>
        <span>
          exit vul {r.final_exit_code ?? '—'} · fix {r.final_fix_exit_code ?? '—'}
        </span>
      </div>
      {pocName && (
        <div className="mt-1.5 font-mono text-[10px] text-text-2">
          最终 PoC：<span className="text-neutral-300">{pocName}</span>
        </div>
      )}
      {r.vulnerability && (
        <div className="mt-2 text-[10px] leading-4 text-text-3">
          {r.vulnerability}
        </div>
      )}
      {r.error && (
        <div className="mt-2 font-mono text-[10px] text-attacker/80">
          {r.error.slice(0, 200)}
        </div>
      )}
    </div>
  )
}

function CyberGymDetail({
  run,
  detail,
}: {
  run: BenchRunSummary
  detail: BenchRunDetail | null
}) {
  const scores = detail?.scores ?? run.scores
  if (!isCyberGymScores(scores)) {
    return <div className="text-[11px] text-text-2">加载中…</div>
  }
  const tasks = (detail?.results ?? []).filter(isCyberGymResult)
  return (
    <>
      {/* headline metrics */}
      <div className="grid grid-cols-3 divide-x divide-hairline rounded-xl border border-hairline">
        <div className="px-4 py-3">
          <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
            最终提交成功率
          </div>
          <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-text-1">
            {fmtPct(scores.success_pct)}
          </div>
          <div className="mt-0.5 font-mono text-[9px] text-text-3">
            {scores.successes}/{scores.n} 任务
          </div>
        </div>
        <div className="px-4 py-3">
          <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
            成功率 any-of
          </div>
          <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-text-1">
            {fmtPct(scores.any_of_pct)}
          </div>
          <div className="mt-0.5 font-mono text-[9px] text-text-3">
            {scores.any_of_successes}/{scores.n} 任务
          </div>
        </div>
        <div className="px-4 py-3">
          <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
            平均任务耗时
          </div>
          <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-text-1">
            {fmtDuration(scores.avg_elapsed_sec)}
          </div>
        </div>
      </div>

      {detail?.vul_only && (
        <div className="rounded-lg border border-warning/30 bg-warning/[0.06] px-3 py-2 text-[10px] text-warning">
          vul-only 降级模式：只判定漏洞版崩溃，未做修复版复核（结果标注
          preliminary）。
        </div>
      )}

      {/* per-task cards */}
      {tasks.length > 0 && (
        <section>
          <div className="mb-2.5 text-[10px] uppercase tracking-widest text-text-2">
            逐任务结果 · 官方 checker 判定
          </div>
          <div className="space-y-2.5">
            {tasks.map((t) => (
              <TaskCard key={t.task_id} r={t} />
            ))}
          </div>
        </section>
      )}
    </>
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
  const scores = detail?.scores ?? run.scores
  const qaScores = scores && !isCyberGymScores(scores) ? scores : null
  const overall = qaScores?.correct_mc_pct ?? 0
  const topics = Object.entries(qaScores?.by_topic ?? {}).sort(
    (a, b) => a[1].correct_mc_pct - b[1].correct_mc_pct,
  )
  const diffs = DIFF_ORDER.filter((d) => qaScores?.by_difficulty?.[d]).map(
    (d) => [d, qaScores!.by_difficulty[d]] as const,
  )

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onClick={onClose}>
      <aside
        className="glass scroll-thin flex h-full w-[560px] flex-none flex-col gap-5 overflow-y-auto border-l border-hairline p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* header */}
        <div className="flex items-start gap-3">
          <div>
            <div className="font-mono text-[13px] font-medium text-text-1">
              {run.run_id}
            </div>
            <div className="mt-1 text-[11px] text-text-2">
              {fmtRunTime(run.run_id)} · {suite} · {run.mode} · n={run.n}
              {detail?.model ? ` · ${detail.model}` : ''}
              {detail?.seed != null ? ` · seed ${detail.seed}` : ''}
              {detail?.rag_top_k ? ` · top_k ${detail.rag_top_k}` : ''}
              {detail?.difficulty ? ` · ${detail.difficulty}` : ''}
              {run.elapsed_sec != null ? ` · ${fmtDuration(run.elapsed_sec)}` : ''}
            </div>
          </div>
          <button
            onClick={onClose}
            className="ml-auto rounded-full bg-overlay px-3 py-1 text-[10px] text-neutral-400 transition-colors hover:bg-hover hover:text-neutral-200"
          >
            关闭 ✕
          </button>
        </div>

        {error && <div className="text-[11px] text-attacker">{error}</div>}

        {suite === 'cybergym' ? (
          <CyberGymDetail run={run} detail={detail} />
        ) : !scores ? (
          !error && <div className="text-[11px] text-text-2">加载中…</div>
        ) : (
          qaScores && (
            <>
              {/* headline metrics */}
              <div className="grid grid-cols-3 divide-x divide-hairline rounded-xl border border-hairline">
                <div className="px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
                    选择题正确率
                  </div>
                  <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-text-1">
                    {fmtPct(qaScores.correct_mc_pct)}
                  </div>
                </div>
                <div className="px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
                    平均得分
                  </div>
                  <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-text-1">
                    {qaScores.avg_score.toFixed(3)}
                  </div>
                </div>
                <div className="px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.15em] text-text-2">
                    解析失败
                  </div>
                  <div
                    className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
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
                                weak ? 'text-attacker/70' : 'text-neutral-300'
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
            </>
          )
        )}
      </aside>
    </div>
  )
}
