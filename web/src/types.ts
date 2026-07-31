// Shared types for the CyberOrion SOC command-center frontend.

export type Side = 'red' | 'blue' | 'system'

/** Top-level view switch in the header. */
export type ViewKey = 'arena' | 'bench' | 'history' | 'kb'

export interface ArenaEvent {
  type: string
  side: Side
  data: Record<string, unknown>
  timestamp: number
}

export interface ThoughtStep {
  id: string
  kind: 'thinking' | 'tool_call' | 'tool_output' | 'report'
  text?: string
  tool?: string
  args?: string
  output?: string
  /** Blue sub-agent attribution (missing = orchestrator / legacy). */
  agent?: string
  /** kind === 'report': collapsed sub-agent report card in the blue stream. */
  role?: string
  mission?: string
  report?: string
  timestamp: number
}

// ---------------------------------------------------------------------------
// Blue super-agent team (orchestrator + dispatched sub-agents)
// ---------------------------------------------------------------------------

export type BlueAgentRole =
  | 'orchestrator'
  | 'watcher'
  | 'analyst'
  | 'responder'
  | 'hunter'

/** WS {"type":"team","side":"blue","data":{...}} payload. */
export interface TeamEventData {
  event: 'spawn' | 'done'
  role: string
  mission: string
  /** Present on done — structured 【发现/证据/建议/已执行动作】 report. */
  report?: string
}

export interface TeamAgentInfo {
  mission: string
  since: number
}

export interface TeamReport {
  id: string
  role: string
  mission: string
  report: string
  ts: number
}

export interface TeamState {
  /** role -> info for currently dispatched sub-agents. */
  active: Record<string, TeamAgentInfo>
  /** Completed sub-agent reports, oldest first. */
  done: TeamReport[]
  /**
   * role -> ts of the last orchestrator `dispatch_task(role=…)` tool call.
   * Drives the "dispatch linkage" edge highlight in the agent-chain panel.
   */
  dispatched: Record<string, number>
}

export interface ControllerStatus {
  red_running: boolean
  blue_running: boolean
  red_paused: boolean
  blue_paused: boolean
  session_active: boolean
  scenario: string
  round: number
  ledger: Record<string, unknown>
  red_history_count: number
  blue_history_count: number
  summary?: unknown
}

export interface ScenarioList {
  scenarios: string[]
  active: string
}

// ---------------------------------------------------------------------------
// P6: scenario / telemetry / score / history
// ---------------------------------------------------------------------------

export interface ServiceInfo {
  name: string
  container_port: number
  host_port: number
  proto: string
}

export interface TargetInfo {
  name: string
  ip: string
  container: string
  services: ServiceInfo[]
}

export interface ScenarioInfo {
  name: string
  network: { subnet: string }
  targets: TargetInfo[]
}

export interface AlertRow {
  id: number
  ts: number
  session_id: string
  host: string
  technique: string
  verdict: string
  confidence: number
  evidence: string
  status: string
  source_tool: string
}

export interface TelemetryEventRow {
  id: number
  ts: number
  session_id: string
  host: string
  source: string
  technique: string
  severity: string
  summary: string
  raw: string
}

export interface ScoreMetrics {
  window_sec: number
  totals: {
    attacks_total: number
    attacks_verified: number
    alerts: number
    alerts_malicious: number
  }
  tp: number
  fn: number
  fp: number
  detection_rate: number
  fp_rate: number
  mttd_sec: number | null
  detections: Array<Record<string, unknown>>
  missed: Array<Record<string, unknown>>
  false_positives: Array<Record<string, unknown>>
  per_technique: Record<string, { attacks: number; detected: number; detection_rate: number }>
  per_target: Record<string, { attacks: number; detected: number; detection_rate: number }>
  response: { total: number; responded: number; response_rate: number }
  blue_score: number
  red_score: number
}

export interface SessionInfo {
  id: string
  dir: string
  has_report: boolean
  has_metrics: boolean
  score: number | null
  mtime: number
}

// ---------------------------------------------------------------------------
// Session detail (history tab) — GET /api/sessions/{id}/detail
// ---------------------------------------------------------------------------

/** One row of the session-detail merged timeline. */
export interface SessionTimelineRow {
  ts: number
  kind: 'attack' | 'alert' | 'event' | 'response'
  title: string
  detail?: string
  technique?: string
  success?: boolean
}

/** One row of the session-detail tool-call log. */
export interface SessionToolCall {
  ts: number
  side: string
  tool: string
  args: string
  ok: boolean
  summary?: string
}

export interface SessionDetail {
  id: string
  has_report: boolean
  has_metrics: boolean
  metrics: ScoreMetrics | null
  report_md: string | null
  storyline_md: string | null
  timeline: SessionTimelineRow[]
  tool_calls: SessionToolCall[]
  alerts: Array<Record<string, unknown>>
  attacks: Array<Record<string, unknown>>
  counts: {
    events: number
    alerts: number
    attacks: number
    verified: number
  }
}

/** GET/POST /api/sessions/{id}/storyline. */
export interface StorylineResult {
  storyline_md?: string
  cached?: boolean
  llm?: string
  /** Present on HTTP 202 while the storyline is being generated. */
  status?: string
}

// ---------------------------------------------------------------------------
// Knowledge base (知识图谱 tab)
// ---------------------------------------------------------------------------

/** GET /api/kb/stats */
export interface KbStats {
  total: number
  by_type: Record<string, number>
  embedding: boolean
}

/** GET /api/kb/tactics — one column of the ATT&CK matrix. */
export interface KbTactic {
  tactic: string
  name_cn: string
  count: number
  techniques: Array<{ id: string; name: string; has_detection: boolean }>
}

/** GET /api/kb/search — one hit. */
export interface KbSearchHit {
  id: string
  type: string
  name: string
  score: number
  excerpt: string
}

/** GET /api/kb/doc/{id} — full document. */
export interface KbDoc {
  id: string
  type: string
  name: string
  tactics: string[]
  text: string
  mitigations?: Array<{ id: string; name: string }>
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

export type TimelineKind =
  | 'attack'
  | 'telemetry'
  | 'alert'
  | 'response'
  | 'team'
  | 'system'

export interface TimelineItem {
  id: string
  kind: TimelineKind
  ts: number
  title: string
  detail?: string
  severity?: string
  success?: boolean
  host?: string
  raw?: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Topology host status
// ---------------------------------------------------------------------------

export type HostState = 'normal' | 'alert' | 'compromised' | 'hardened'

export interface HostStatus {
  state: HostState
  ts: number
  note?: string
}

// ---------------------------------------------------------------------------
// Benchmark (CyberSOCEval before/after harness)
// ---------------------------------------------------------------------------

/** Mode semantics are per-suite: cybergym → vanilla|framework (arms),
 * others → base|rag (+ legacy experiment modes). */
export type BenchMode =
  | 'base'
  | 'rag'
  | 'rag_fs'
  | 'sc'
  | 'sc_base'
  | 'rag_g'
  | 'vanilla'
  | 'framework'

/** Bench suites — run_id format `<ts>_<suite>_<mode>_n<n>`; old runs default
 * to malware_analysis server-side. */
export type BenchSuite = 'cybergym' | 'malware_analysis' | 'attack_kb'

export const BENCH_SUITES: Record<
  BenchSuite,
  { label: string; hint: string; deprecated?: boolean }
> = {
  cybergym: {
    label: 'CyberGym · 漏洞 PoC 复现',
    hint: '真实漏洞复现，以官方 checker 判定（crashes vul 且不 crash fix）',
  },
  malware_analysis: {
    label: 'CyberSOCEval · 恶意软件分析',
    hint: '多选知识问答，衡量通用安全知识',
  },
  attack_kb: {
    label: 'ATT&CK 知识检索',
    hint: '已废弃：评估质量不达标，仅保留历史记录',
    deprecated: true,
  },
}

/** Comparison arm: 裸模型 (vanilla/base) vs CyberOrion 框架 (framework/rag). */
export type BenchArm = 'bare' | 'framework'

export function armOfMode(mode: BenchMode): BenchArm | null {
  if (mode === 'vanilla' || mode === 'base') return 'bare'
  if (mode === 'framework' || mode === 'rag') return 'framework'
  return null // legacy experiment modes — excluded from comparisons
}

/** Per-suite arm naming (run card / badges / chart legend). */
export const BENCH_ARMS: Record<
  BenchSuite,
  { bare: { mode: BenchMode; label: string }; framework: { mode: BenchMode; label: string } }
> = {
  cybergym: {
    bare: { mode: 'vanilla', label: 'vanilla · 裸模型' },
    framework: { mode: 'framework', label: 'framework · CyberOrion 框架' },
  },
  malware_analysis: {
    bare: { mode: 'base', label: 'base · 裸模型' },
    framework: { mode: 'rag', label: 'rag · 知识库增强' },
  },
  attack_kb: {
    bare: { mode: 'base', label: 'base · 裸模型' },
    framework: { mode: 'rag', label: 'rag · 知识库增强' },
  },
}

/** Modes kept server-side for comparison experiments, hidden from the UI. */
export const LEGACY_BENCH_MODES: ReadonlySet<string> = new Set([
  'rag_fs',
  'sc',
  'sc_base',
  'rag_g',
])

export interface BenchGroupScore {
  n: number
  correct_mc_pct: number
  avg_score: number
}

export interface BenchScores {
  n: number
  correct_mc_pct: number
  avg_score: number
  parse_fail: number
  /** LLM 调用失败的题目数（endpoint 故障不再静默成全 0 分）。 */
  llm_errors?: number
  by_difficulty: Record<string, BenchGroupScore>
  by_topic: Record<string, BenchGroupScore>
}

/** CyberGym scores — see bench/cybergym_bench.py compute_scores().
 * success_pct = final-submission 口径（最后提交的 PoC 崩 vul 且不崩 fix）；
 * any_of_pct = 任意一次提交满足同条件的参考口径。 */
export interface CyberGymScores {
  n: number
  successes: number
  success_pct: number
  any_of_successes: number
  any_of_pct: number
  avg_elapsed_sec: number
  by_project: Record<string, { n: number; success: number }>
}

export type BenchAnyScores = BenchScores | CyberGymScores

export function isCyberGymScores(
  s: BenchAnyScores | null | undefined,
): s is CyberGymScores {
  return !!s && 'success_pct' in s
}

/** Headline metric of a finished run (final-submission success for cybergym,
 * exact-match accuracy otherwise), as a 0..1 fraction. */
export function primaryScoreOf(r: {
  suite?: BenchSuite
  scores: BenchAnyScores | null
}): number | undefined {
  if (!r.scores) return undefined
  if (isCyberGymScores(r.scores)) return r.scores.success_pct
  return r.scores.correct_mc_pct
}

export function primaryScoreLabel(suite: BenchSuite | undefined): string {
  return suite === 'cybergym' ? '最终提交成功率' : '选择题正确率'
}

/** One row of GET /api/bench/runs (or an in-process running run). */
export interface BenchRunSummary {
  run_id: string
  mode: BenchMode
  /** Missing on pre-suite runs — treat as 'malware_analysis'. */
  suite?: BenchSuite
  n: number
  seed?: number
  model?: string
  elapsed_sec?: number
  scores: BenchAnyScores | null
  status?: string
  progress?: { done: number; total: number }
  error?: string | null
  /** LLM 失败题数（运行中实时 + 完成后最终值）。 */
  llm_errors?: number
  path?: string | null
}

export interface BenchResultItem {
  idx: number
  topic: string
  difficulty: string
  attack?: string
  question: string
  gold: string[]
  pred: string[]
  raw: string
  parse_ok: boolean
  exact: boolean
  jaccard: number
}

/** CyberGym per-task result — see cybergym_bench._run_task()/_final_verdict(). */
export interface CyberGymSubmission {
  poc: string
  exit_code: number | null
  output?: string
  fix_exit_code?: number
}

export interface CyberGymTaskResult {
  task_id: string
  project: string
  vulnerability?: string
  steps: number
  submissions: CyberGymSubmission[]
  /** framework arm only: judge-verified flag. */
  verified?: boolean
  elapsed_sec: number
  success: boolean
  success_any: boolean
  final_exit_code: number | null
  final_fix_exit_code: number | null
  /** vul-only 降级模式：未做修复版复核。 */
  preliminary?: boolean
  error?: string | null
}

export function isCyberGymResult(
  r: BenchResultItem | CyberGymTaskResult,
): r is CyberGymTaskResult {
  return 'task_id' in r
}

/** GET /api/bench/run/{run_id} — full detail incl. per-task/question results. */
export interface BenchRunDetail extends BenchRunSummary {
  started_at?: number
  finished_at?: number
  rag_top_k?: number
  /** cybergym runs: per-task results; QA suites: per-question results. */
  results?: Array<BenchResultItem | CyberGymTaskResult>
  /** cybergym-only run metadata. */
  difficulty?: string
  vul_only?: boolean
  task_ids?: string[]
  budget?: { max_steps: number; task_timeout: number }
}

/** Live state of a running bench run, fed by WS `bench` events. */
export interface BenchLiveRun {
  run_id: string
  mode: BenchMode
  suite: BenchSuite
  n: number
  status: string
  progress: { done: number; total: number }
  error?: string
  llm_errors?: number
}
