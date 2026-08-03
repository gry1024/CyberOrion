// Shared types for the CyberOrion SOC command-center frontend.

export type Side = 'red' | 'blue' | 'system'

/** Top-level view switch in the header. */
export type ViewKey = 'arena' | 'bench' | 'history' | 'kb' | 'docs'

export interface ArenaEvent {
  type: string
  side: Side
  data: Record<string, unknown>
  timestamp: number
}

export interface ThoughtStep {
  id: string
  kind: 'thinking' | 'tool_call' | 'tool_output' | 'report' | 'system'
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

/** 一个蓝队角色可用的工具（英文原名 + 中文说明）。 */
export interface BlueRoleTool {
  name: string
  desc: string
}

/** 蓝队角色元信息 — 前端唯一事实源，供 DispatchGraph / BlueStream /
 * AgentDetailModal 共用。name 为具体职责名，colorVar 沿用既有色板。 */
export interface BlueRole {
  key: BlueAgentRole
  name: string
  duty: string
  scope: string
  colorVar: string
  tools: BlueRoleTool[]
}

/** 蓝队角色定义（具体职责命名）：
 * orchestrator=调度指挥 / watcher=遥测巡检 / analyst=事件研判 /
 * responder=响应处置 / hunter=失陷排查。scope 均为同一靶场三台靶机。 */
export const BLUE_ROLES: BlueRole[] = [
  {
    key: 'orchestrator',
    name: '调度指挥',
    duty: '组织防御：派遣子代理、汇总结论、上报告警（report_finding 是评分接口）',
    scope: '靶机：DVWA / weak_ssh / Log4Shell（三台）',
    colorVar: 'var(--color-cmd)',
    tools: [
      { name: 'dispatch_task', desc: '派遣子代理' },
      { name: 'report_finding', desc: '上报告警' },
      { name: 'search_attack_kb', desc: '知识检索' },
      { name: 'lookup_technique', desc: '技术查询' },
    ],
  },
  {
    key: 'watcher',
    name: '遥测巡检',
    duty: '全面巡查日志、网络端口、进程、文件基线，找出可疑迹象（爆破、注入、webshell）',
    scope: '靶机：DVWA / weak_ssh / Log4Shell（三台）',
    colorVar: 'var(--color-watcher)',
    tools: [
      { name: 'query_logs', desc: '日志查询' },
      { name: 'network_summary', desc: '网络快照' },
      { name: 'process_audit', desc: '进程审计' },
      { name: 'file_integrity', desc: '文件完整性' },
      { name: 'list_alerts', desc: '查看告警' },
    ],
  },
  {
    key: 'analyst',
    name: '事件研判',
    duty: '把可疑线索定性：ATT&CK 技术编号、受害主机、来源 IP、失陷程度与处置建议',
    scope: '靶机：DVWA / weak_ssh / Log4Shell（三台）',
    colorVar: 'var(--color-analyst)',
    tools: [
      { name: 'triage_alert', desc: '告警关联研判' },
      { name: 'query_logs', desc: '日志查询' },
      { name: 'list_alerts', desc: '查看告警' },
      { name: 'search_attack_kb', desc: '知识检索' },
      { name: 'lookup_technique', desc: '技术查询' },
    ],
  },
  {
    key: 'responder',
    name: '响应处置',
    duty: '对已确认威胁执行处置：封禁来源 IP、加固服务、清除后门/webshell/恶意进程',
    scope: '靶机：DVWA / weak_ssh / Log4Shell（三台）',
    colorVar: 'var(--color-responder)',
    tools: [
      { name: 'block_ip', desc: '封禁来源IP' },
      { name: 'unblock_ip', desc: '解除封禁' },
      { name: 'harden_service', desc: '服务加固' },
      { name: 'remediate', desc: '修复清理（锁账户/删文件/杀进程）' },
    ],
  },
  {
    key: 'hunter',
    name: '失陷排查',
    duty: '深挖文件篡改与可疑进程（webshell/后门/下载执行），确认后现场清理',
    scope: '靶机：DVWA / weak_ssh / Log4Shell（三台）',
    colorVar: 'var(--color-hunter)',
    tools: [
      { name: 'file_integrity', desc: '文件完整性' },
      { name: 'process_audit', desc: '进程审计' },
      { name: 'remediate', desc: '修复清理' },
    ],
  },
]

/** 按 key 查角色元信息（未知 key 返回 undefined）。 */
export function blueRoleOf(key: string): BlueRole | undefined {
  return BLUE_ROLES.find((r) => r.key === key)
}

/** WS {"type":"team","side":"blue","data":{...}} payload. */
export interface TeamEventData {
  event: 'spawn' | 'done'
  role: string
  mission: string
  /** Dispatch sequence number — parallel dispatches each get their own seq. */
  seq?: number
  /** Present on done — structured 【发现/证据/建议/已执行动作】 report. */
  report?: string
  /** Present on done when the sub-agent timed out or errored. */
  error?: string
}

/** Key of one dispatch instance: `role#seq`, or bare `role` when the backend
 * sends no seq (legacy). One role can have several concurrent instances. */
export function teamKey(role: string, seq?: number): string {
  return seq != null ? `${role}#${seq}` : role
}

export interface TeamAgentInfo {
  role: string
  seq?: number
  mission: string
  since: number
}

export interface TeamReport {
  id: string
  role: string
  seq?: number
  mission: string
  report: string
  /** Set when the sub-agent timed out or errored (renders as ✗). */
  error?: string
  /** Spawn ts, carried over so the node can show total elapsed time. */
  since?: number
  ts: number
}

export interface TeamState {
  /** teamKey(role, seq) -> info for currently running sub-agent instances. */
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

/** GET /api/scenario/info — 场景简报（含目标与红蓝期望，无 ground truth）。 */
export interface ScenarioTargetDetail extends TargetInfo {
  logs: Record<string, string>
}

export interface ScenarioDetail {
  name: string
  description: string
  mode: string
  briefing: string
  network: { subnet: string }
  targets: ScenarioTargetDetail[]
  red_objectives: string[]
  blue_objectives: string[]
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
  scenario: string
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

/** Mode semantics: QA suites → base|rag (+ legacy experiment modes). */
export type BenchMode =
  | 'base'
  | 'rag'
  | 'rag_fs'
  | 'sc'
  | 'sc_base'
  | 'rag_g'

/** Bench suites — run_id format `<ts>_<suite>_<mode>_n<n>`; old runs default
 * to malware_analysis server-side. */
export type BenchSuite = 'malware_analysis' | 'attack_kb' | 'threat_intel'

export const BENCH_SUITES: Record<
  BenchSuite,
  { label: string; hint: string; deprecated?: boolean }
> = {
  malware_analysis: {
    label: 'CyberSOCEval · 恶意软件分析',
    hint: '多选知识问答，衡量通用安全知识',
  },
  attack_kb: {
    label: 'ATT&CK 知识检索',
    hint: '知识库访问能力测试：题干摘录来自 KB，答案就在知识库中——纯 LLM 靠记忆、框架臂靠检索注入，分差即框架知识层的价值（实测 +36pt）',
  },
  threat_intel: {
    label: '威胁情报推理 · CrowdStrike',
    hint: '基于 CrowdStrike 真实威胁报告的防御决策多选题：安全控制测试方法论 / 检测建议 / 缓解措施，题干自包含威胁上下文（588 题）',
  },
}

/** Comparison arm: 纯 LLM (vanilla/base) vs CyberOrion 框架 (framework/rag).
 * 框架有效性对比的两臂：同 seed 同批题同模型，分差即框架增益。 */
export type BenchArm = 'bare' | 'framework'

export function armOfMode(mode: BenchMode): BenchArm | null {
  if (mode === 'base') return 'bare'
  if (mode === 'rag') return 'framework'
  return null // legacy experiment modes — excluded from comparisons
}

/** Per-suite arm naming (run card / badges / chart legend). */
export const BENCH_ARMS: Record<
  BenchSuite,
  { bare: { mode: BenchMode; label: string }; framework: { mode: BenchMode; label: string } }
> = {
  malware_analysis: {
    bare: { mode: 'base', label: '纯 LLM · base' },
    framework: { mode: 'rag', label: 'CyberOrion 框架 · rag' },
  },
  attack_kb: {
    bare: { mode: 'base', label: '纯 LLM · base' },
    framework: { mode: 'rag', label: 'CyberOrion 框架 · rag' },
  },
  threat_intel: {
    bare: { mode: 'base', label: '纯 LLM · base' },
    framework: { mode: 'rag', label: 'CyberOrion 框架 · rag' },
  },
}

/** 臂的展示名；legacy 实验模式（不在对比中）原样返回 mode。 */
export function armLabelOf(mode: BenchMode): string {
  const arm = armOfMode(mode)
  if (arm === 'framework') return 'CyberOrion 框架'
  if (arm === 'bare') return '纯 LLM'
  return mode
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

/** Headline metric of a finished run (exact-match accuracy), as a 0..1
 * fraction. */
export function primaryScoreOf(r: {
  suite?: BenchSuite
  scores: BenchScores | null
}): number | undefined {
  if (!r.scores) return undefined
  return r.scores.correct_mc_pct
}

export function primaryScoreLabel(_suite: BenchSuite | undefined): string {
  return '选择题正确率'
}

/** GET /api/bench/questions — 题目预览（含答案），与正式基准同采样逻辑。 */
export interface BenchQuestionPreview {
  idx: number
  question: string
  options: string[]
  correct_options: string[]
  topic?: string
  difficulty?: string
  attack?: string
}

/** One row of GET /api/bench/runs (or an in-process running run). */
export interface BenchRunSummary {
  run_id: string
  mode: BenchMode
  /** 对比臂：bare=纯 LLM / framework=CyberOrion 框架（旧运行由 mode 推导）。 */
  arm?: BenchArm | null
  /** Missing on pre-suite runs — treat as 'malware_analysis'. */
  suite?: BenchSuite
  n: number
  seed?: number
  model?: string
  elapsed_sec?: number
  scores: BenchScores | null
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
  /** 新运行的完整选项（旧运行由 /task/{idx} 端点从题库补全）。 */
  options?: string[]
  gold: string[]
  pred: string[]
  raw: string
  parse_ok: boolean
  exact: boolean
  jaccard: number
}

/** GET /api/bench/run/{run_id} — full detail incl. per-question results. */
export interface BenchRunDetail extends BenchRunSummary {
  started_at?: number
  finished_at?: number
  rag_top_k?: number
  /** 逐题可读报告路径（logs/bench/<run_id>.md，完整题干/选项/回答）。 */
  report?: string | null
  /** QA suites: per-question results. */
  results?: BenchResultItem[]
  budget?: { max_steps: number; task_timeout: number }
}

/** GET /api/bench/run/{run_id}/task/{idx} — 单题完整 drill-down。 */
export interface BenchTaskDetail {
  run_id: string
  suite: BenchSuite
  mode?: string
  idx: number
  n: number
  task: BenchResultItem
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
