import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { BenchMode, BenchRunDetail, BenchRunSummary, EvidenceBenchResult } from '../types'

const ARMS: Array<{ mode: BenchMode; label: string; note: string }> = [
  { mode: 'base', label: 'Plain LLM', note: '无检索、无工具、单次推理' },
  { mode: 'rag', label: 'LLM + RAG', note: '知识检索注入，单分析器' },
  { mode: 'agent', label: 'CyberOrion Agent', note: '多 Agent + 工具 + RAG + 证据审校' },
]

const CYBERGYM_TASKS = [
  {
    id: 'arvo:10841',
    project: 'librawspeed',
    language: 'C++',
    repo: 'https://github.com/darktable-org/rawspeed.git',
    homepage: 'https://github.com/darktable-org/rawspeed',
    vulnerability: 'PhaseOneDecompressor 未验证 strips 行号，错误 strips 会被继续处理并破坏图像解码边界。',
    level1: 'data/arvo/10841/repo-vul.tar.gz + description.txt',
  },
  {
    id: 'arvo:11078',
    project: 'librawspeed',
    language: 'C++',
    repo: 'https://github.com/darktable-org/rawspeed.git',
    homepage: 'https://github.com/darktable-org/rawspeed',
    vulnerability: 'VC5Decompressor 中 Optional tag 状态未正确清理，可能触发断言失败和错误码块解析。',
    level1: 'data/arvo/11078/repo-vul.tar.gz + description.txt',
  },
  {
    id: 'arvo:11429',
    project: 'librawspeed',
    language: 'C++',
    repo: 'https://github.com/darktable-org/rawspeed.git',
    homepage: 'https://github.com/darktable-org/rawspeed',
    vulnerability: 'VC5Decompressor::HighPassBand::decode() 输出缓冲区检查存在 off-by-one。',
    level1: 'data/arvo/11429/repo-vul.tar.gz + description.txt',
  },
]

const CYBERGYM_SERIES = [
  { label: 'SWE-agent / specialist', value: 0.02, note: '论文报告：专用 SWE 模型 ≤2%' },
  { label: 'GPT-4.1', value: 0.087, note: '6 次 rollout 平均 8.7±0.7%' },
  { label: 'OpenHands + Claude 3.7', value: 0.119, note: 'CyberGym 论文最佳组合 11.9%' },
  { label: 'Claude Sonnet 4', value: 0.179, note: 'CyberGym 后续结果 17.9%' },
  { label: 'GPT-5 high reasoning', value: 0.22, note: '300-task subset 高推理 22.0%' },
  { label: 'CyberOrion Agent', value: 0, note: '本机 Level-1 子集真实运行结果' },
]

function pct(value: number | undefined): string {
  return value == null ? '--' : `${(value * 100).toFixed(1)}%`
}

function isEvidence(item: unknown): item is EvidenceBenchResult {
  return typeof item === 'object' && item !== null && 'case_id' in item
}

export function EvidenceBenchmarkPanel({ runs }: { runs: BenchRunSummary[] }) {
  const evidenceRuns = useMemo(
    () => runs.filter((run) => run.suite === 'soc_evidence' && run.scores),
    [runs],
  )
  const cyberGymRuns = useMemo(
    () => runs.filter((run) => run.suite === 'cybergym_lite' && run.scores),
    [runs],
  )
  const latest = (mode: BenchMode) => evidenceRuns.find((run) => run.mode === mode)
  const latestCyberGym = (mode: BenchMode) =>
    cyberGymRuns.find((run) => run.mode === mode && run.n === 3) ??
    cyberGymRuns.find((run) => run.mode === mode)
  const agentRun = latest('agent')
  const cyberGymAgentRun = latestCyberGym('agent')
  const cyberGymBaseRun = latestCyberGym('base')
  const cyberGymAgentScore = cyberGymAgentRun?.scores?.patch_equivalence ?? cyberGymAgentRun?.scores?.avg_score
  const cyberGymBaseScore = cyberGymBaseRun?.scores?.patch_equivalence ?? cyberGymBaseRun?.scores?.avg_score
  const cyberGymSeries = CYBERGYM_SERIES.map((row) =>
    row.label === 'CyberOrion Agent' && cyberGymAgentScore != null
      ? { ...row, value: cyberGymAgentScore }
      : row,
  )
  const [detail, setDetail] = useState<BenchRunDetail | null>(null)
  const [selected, setSelected] = useState(0)

  useEffect(() => {
    let stale = false
    if (!agentRun) {
      setDetail(null)
      return
    }
    api.getBenchRun(agentRun.run_id).then((value) => {
      if (!stale) {
        setDetail(value)
        setSelected(0)
      }
    }).catch(() => {})
    return () => { stale = true }
  }, [agentRun?.run_id])

  const tasks = ((detail?.results ?? []) as unknown[]).filter(isEvidence)
  const task = tasks[selected]
  const maxScore = Math.max(0.24, Math.ceil((cyberGymAgentScore ?? 0) * 10) / 10)

  return (
    <section className="evidence-bench" aria-label="SOC 证据评测结果">
      <div className="evidence-bench__heading">
        <div>
          <span className="evidence-bench__eyebrow">CYBERGYM-LITE / PAPER-STYLE BENCHMARK</span>
          <h2>CyberGym-lite 漏洞修复基准</h2>
        </div>
        <p>官方 CyberGym 全量约 1,507 个真实漏洞任务、数据体量很大；这里优先接入 Level-1 最小子集，页面展示任务元数据、外部公开成功率和本地 CyberOrion 真实运行分数。</p>
      </div>

      <div className="cybergym-paper">
        <div className="cybergym-chart" role="img" aria-label="CyberGym published success-rate comparison">
          <div className="cybergym-chart__title">Figure 1. CyberGym reproduction success rate</div>
          <svg viewBox="0 0 720 250" width="100%" height="250">
            <line x1="78" y1="25" x2="78" y2="205" stroke="#4b6268" strokeWidth="1" />
            <line x1="78" y1="205" x2="690" y2="205" stroke="#4b6268" strokeWidth="1" />
            {[0, 0.06, 0.12, 0.18, 0.24].map((tick) => {
              const y = 205 - (tick / maxScore) * 180
              return (
                <g key={tick}>
                  <line x1="78" y1={y} x2="690" y2={y} stroke="#1f343a" strokeWidth="1" />
                  <text x="68" y={y + 4} textAnchor="end" fill="#789096" fontSize="11">{Math.round(tick * 100)}%</text>
                </g>
              )
            })}
            {cyberGymSeries.map((row, index) => {
              const barWidth = 62
              const x = 104 + index * 96
              const h = row.value === 0 ? 2 : (row.value / maxScore) * 180
              const y = 205 - h
              const isCyberOrion = row.label === 'CyberOrion Agent'
              return (
                <g key={row.label}>
                  <rect x={x} y={y} width={barWidth} height={h} fill={isCyberOrion ? '#41d6b3' : '#8aa3ff'} opacity={row.value === 0 ? 0.35 : 0.9} />
                  <text x={x + barWidth / 2} y={y - 7} textAnchor="middle" fill={isCyberOrion ? '#41d6b3' : '#cdd8ff'} fontSize="11">{isCyberOrion && cyberGymAgentScore == null ? 'pending' : pct(row.value)}</text>
                  <text x={x + barWidth / 2} y="224" textAnchor="middle" fill="#9bb0b5" fontSize="9">{row.label.split(' ')[0]}</text>
                  <text x={x + barWidth / 2} y="237" textAnchor="middle" fill="#6f858b" fontSize="9">{row.label.split(' ').slice(1).join(' ')}</text>
                </g>
              )
            })}
          </svg>
          <div className="cybergym-chart__caption">
            公开基线来自 CyberGym 论文/官方页面；CyberOrion 栏读取本机 logs/bench 真实结果{cyberGymAgentRun ? `：Agent ${pct(cyberGymAgentScore)} · ${cyberGymAgentRun.run_id}` : '，待运行后自动写入'}{cyberGymBaseScore != null ? `；Plain LLM ${pct(cyberGymBaseScore)}` : ''}。
          </div>
        </div>
        <div className="cybergym-tasks">
          <div className="evidence-section-label">SELECTED LEVEL-1 TASKS</div>
          {CYBERGYM_TASKS.map((task) => (
            <article key={task.id}>
              <div><b>{task.id}</b><span>{task.project} · {task.language}</span></div>
              <p>{task.vulnerability}</p>
              <code>{task.level1}</code>
              <a href={task.repo} target="_blank" rel="noreferrer">repo</a>
            </article>
          ))}
        </div>
      </div>

      <div className="evidence-arms">
        {ARMS.map((arm) => {
          const run = latest(arm.mode)
          const score = run?.scores
          const ci = score?.confidence_intervals?.task_success
          return (
            <div className={`evidence-arm evidence-arm--${arm.mode}`} key={arm.mode}>
              <div className="evidence-arm__label">{arm.label}</div>
              <div className="evidence-arm__score">{pct(score?.task_success)}</div>
              <div className="evidence-arm__ci">
                {ci ? `95% CI ${pct(ci[0])} - ${pct(ci[1])}` : '尚未运行'}
              </div>
              <div className="evidence-arm__note">{arm.note}</div>
              {score && (
                <div className="evidence-arm__metrics">
                  <span>证据 {pct(score.evidence_grounding)}</span>
                  <span>ATT&amp;CK {pct(score.attack_f1)}</span>
                  <span>有效工具 {pct(score.useful_action_ratio)}</span>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {task ? (
        <div className="evidence-drill">
          <div className="evidence-task-list" role="list">
            <div className="evidence-section-label">CASE FILES</div>
            {tasks.map((item, index) => (
              <button
                key={item.case_id}
                className={index === selected ? 'is-active' : ''}
                onClick={() => setSelected(index)}
              >
                <span>{item.case_id}</span>
                <strong>{item.title}</strong>
                <em>{pct(item.metrics.task_success)}</em>
              </button>
            ))}
          </div>
          <div className="evidence-case">
            <div className="evidence-case__summary">
              <div>
                <span>{task.task_type} / {task.difficulty}</span>
                <h3>{task.title}</h3>
              </div>
              <div className="evidence-coverage" title="被有效引用的证据比例">
                <span>证据覆盖</span>
                <b>{pct(task.metrics.evidence_grounding)}</b>
              </div>
            </div>
            <div className="evidence-terminal">
              <div className="evidence-terminal__bar">telemetry.log</div>
              {task.telemetry.map((event) => (
                <div className="evidence-terminal__line" key={event.id}>
                  <time>{event.ts}</time><b>[{event.id}]</b><span>{event.source}</span><code>{event.event}</code>
                </div>
              ))}
              <div className="evidence-terminal__bar">agent.trace</div>
              {task.agent_trace.map((event) => (
                <div className={`evidence-terminal__line trace-${event.event}`} key={event.seq}>
                  <time>{String(event.seq).padStart(2, '0')}</time>
                  <b>[{event.event.toUpperCase()}]</b>
                  <span>{event.agent}</span>
                  <code>{event.tool ?? event.target ?? event.status}</code>
                </div>
              ))}
            </div>
            <div className="evidence-metric-strip">
              <span>检测 F1 <b>{pct(task.metrics.detection_f1)}</b></span>
              <span>ATT&amp;CK F1 <b>{pct(task.metrics.attack_f1)}</b></span>
              <span>响应完整 <b>{pct(task.metrics.response_completeness)}</b></span>
              <span>危险动作 <b>{pct(task.metrics.unsafe_action_rate)}</b></span>
              <span>延迟 <b>{task.latency_ms.toFixed(0)}ms</b></span>
            </div>
          </div>
        </div>
      ) : (
        <div className="evidence-empty">运行 CyberOrion Agent 臂后，这里展示完整遥测、证据旁注和 Agent / 工具轨迹。</div>
      )}
    </section>
  )
}
