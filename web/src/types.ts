// Shared types for the CyberOrion SOC command-center frontend.

export type Side = 'red' | 'blue' | 'system'

/** Top-level view switch in the header. */
export type ViewKey = 'cai' | 'arena' | 'traffic' | 'bench' | 'history' | 'hostguard' | 'kb' | 'skills' | 'docs'

export interface CaiCtfItem {
  name: string
  difficulty: string
  type: string
  description: string
  instructions: string
  techniques: string
  caibench: string
  ctf_inside: boolean
  challenges: string[]
  challenge_details: Record<string, string>
  source: string
}

export interface CaiCtfCatalog {
  count: number
  source: string
  ctfs: CaiCtfItem[]
}

export type CaiTopTask = 'chat' | 'ctf' | 'attack_chain' | 'code_repair'

export interface CaiTaskEnvironment {
  id: CaiTopTask
  task_type: 'general' | 'ctf' | 'attack_chain' | 'code_repair'
  title: string
  description: string
  workdir: string
  workspace: string
  available: boolean
  demo: boolean
}

export interface CaiRecordingFrame {
  t: number
  data: string
}

export interface CaiRecordingSummary {
  id: string
  title: string
  kind: 'demo' | 'ctf' | 'terminal' | string
  ctf_name: string
  challenge: string
  status: string
  duration_sec: number
  created_at: string
  summary: string
  source: 'builtin' | 'live' | string
  frame_count: number
  has_report: boolean
  report_url?: string
}

export interface CaiRecording extends CaiRecordingSummary {
  ended_at?: string
  exit_code?: number | null
  frames: CaiRecordingFrame[]
}

export interface ArenaEvent {
  type: string
  side: Side
  data: Record<string, unknown>
  timestamp: number
}

/** M4：扩展至 11 种 kind（含 3 种 RAG 事件 + 2 种子 Agent + SOP + error）。 */
export type ThoughtStepKind =
  | 'thinking'
  | 'tool_call'
  | 'tool_output'
  | 'rag_retrieval'
  | 'rag_no_match'
  | 'rag_unavailable'
  | 'subagent_dispatch'
  | 'subagent_result'
  | 'sop_phase'
  | 'report'
  | 'error'
  | 'system'

export interface ThoughtStep {
  id: string
  kind: ThoughtStepKind
  type?: string  // legacy 字段，兼容
  text?: string
  tool?: string
  /** 后端预生成的中文标签（tool_call） */
  label_zh?: string
  /** 后端预生成的中文摘要（tool_output） */
  summary_zh?: string
  args?: string | Record<string, unknown>
  output?: string
  /** Blue sub-agent attribution */
  agent?: string
  role?: string
  mission?: string
  report?: string
  /** RAG 检索字段 */
  query?: string
  hit_count?: number
  total_chars?: number
  doc_ids?: string[]
  doc_titles_zh?: string[]
  docs?: Array<{ id: string; name_zh?: string; name?: string; detection?: string; description?: string }>
  intent?: string
  error?: string
  message?: string
  /** 子 Agent 派遣字段 */
  worker_name?: string
  task_zh?: string
  findings_zh?: string
  /** SOP 阶段字段 */
  phase_id?: number
  phase_total?: number
  phase_name?: string
  phase_name_zh?: string
  suggested_workers?: string[]
  strict?: boolean
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

/** 工具参数（来自 FunctionTool 的 params_json_schema）。 */
export interface AgentToolParam {
  name: string
  type: string
  default?: unknown
  desc: string
}

/** 工具详解（FunctionTool：概述 + 参数级说明）。 */
export interface AgentToolSpec {
  name: string
  description: string
  params: AgentToolParam[]
}

/** GET /api/agents/roles — 蓝队角色完整档案（Agent 详情弹窗用）。 */
export interface AgentRoleSpec {
  key: string
  title: string
  name: string
  system_prompt: string
  tools: AgentToolSpec[]
  duty: string
  invocation: string
  output: string
  comms: string
  color: string
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

/** 流量分析多 agent 流水线角色（与蓝队竞技场角色独立，共用 ChatStream 渲染）。
 *  key 与 pipeline.py 中 SSE 事件的 agent 字段一致。 */
export const TRAFFIC_ROLES: BlueRole[] = [
  {
    key: 'rule_engine' as BlueAgentRole,
    name: '规则引擎',
    duty: '纯规则阈值检测：端口扫描/DoS/暴力破解/Web攻击/C2外联，处理全量事件生成告警摘要',
    scope: '全量流量事件',
    colorVar: 'var(--color-rule-engine)',
    tools: [],
  },
  {
    key: 'sem_analyst' as BlueAgentRole,
    name: '语义分析',
    duty: 'LLM 语义研判：对告警摘要做 ATT&CK 映射、威胁定性、严重度评估',
    scope: '告警摘要',
    colorVar: 'var(--color-sem-analyst)',
    tools: [],
  },
  {
    key: 'chain_recon' as BlueAgentRole,
    name: '攻击链重建',
    duty: 'LLM 聚合告警重建攻击者时间线，讲好攻击故事',
    scope: '告警 + 语义分析',
    colorVar: 'var(--color-chain-recon)',
    tools: [],
  },
  {
    key: 'report_writer' as BlueAgentRole,
    name: '报告生成',
    duty: '汇总全部分析生成结构化 Markdown 分析报告',
    scope: '全部分析产物',
    colorVar: 'var(--color-report-writer)',
    tools: [],
  },
]

/** 按 key 查角色元信息（未知 key 返回 undefined）。
 *  先查蓝队竞技场角色，再查流量分析角色，供 ChatStream 统一渲染。 */
export function blueRoleOf(key: string): BlueRole | undefined {
  return BLUE_ROLES.find((r) => r.key === key)
    ?? TRAFFIC_ROLES.find((r) => r.key === key)
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
  session_starting?: boolean
  session_boot_error?: string
  pending_agent_starts?: string[]
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
  type?: 'arena' | 'traffic_analysis'
  window_sec?: number
  totals?: {
    attacks_total: number
    attacks_verified: number
    alerts: number
    alerts_malicious: number
  }
  tp?: number
  fn?: number
  fp?: number
  detection_rate?: number
  fp_rate?: number
  mttd_sec: number | null
  detections?: Array<Record<string, unknown>>
  missed?: Array<Record<string, unknown>>
  false_positives?: Array<Record<string, unknown>>
  per_technique?: Record<string, { attacks: number; detected: number; detection_rate: number }>
  per_target?: Record<string, { attacks: number; detected: number; detection_rate: number }>
  response?: { total: number; responded: number; response_rate: number }
  blue_score?: number | null
  red_score?: number
  // Traffic-analysis optional fields
  event_count?: number
  alert_count?: number
  critical_count?: number
  high_count?: number
}

export interface SessionInfo {
  id: string
  dir: string
  has_report: boolean
  has_metrics: boolean
  score: number | null
  scenario: string
  mtime: number
  type: 'arena' | 'traffic_analysis'
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
  session_type: 'arena' | 'traffic_analysis'
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
  // technique fields
  description?: string
  detection?: string
  mitigations?: string[] | Array<{ id: string; name: string }>
  platforms?: string[]
  data_sources?: string[]
  permissions_required?: string[]
  defense_bypassed?: string[]
  is_subtechnique?: boolean
  // cve fields
  cvss?: number | null
  attack_vector?: string
  cwe?: string[]
  affected_products?: string[]
  published?: string
  // software fields
  software_types?: string[]
  // regulation fields
  category?: string
  issuer?: string
  effective_date?: string
  key_articles?: string
  url?: string
  // auto-update metadata
  _source?: string
  _updated?: string
}


/** GET /api/kb/list — one item in the paginated document list. */
export interface KbListItem {
  id: string
  type: string
  name: string
  source: string
  updated: string
  published: string
  cvss: number | null
  text_preview: string
  tactics: string[]
  category: string
  attack_vector: string
  cwe: string[]
  affected_products: string[]
  url: string
}

/** GET /api/kb/list — paginated response. */
export interface KbListResponse {
  total: number
  offset: number
  limit: number
  type: string
  items: KbListItem[]
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
  | 'single'
  | 'agent'
  | 'paired'
  | 'compare'
  | 'rag_fs'
  | 'sc'
  | 'sc_base'
  | 'rag_g'

/** Bench suites — run_id format `<ts>_<suite>_<mode>_n<n>`; old runs default
 * to malware_analysis server-side. */
export type BenchSuite =
  | 'malware_analysis' | 'threat_intel' | 'secalertbench' | 'excytin' | 'cage2'
  | 'soc_contract' | 'soc_evidence' | 'attack_kb' | 'cybergym_lite' | 'live_paired'

export const BENCH_SUITES: Record<
  BenchSuite,
  { label: string; hint: string; deprecated?: boolean }
> = {
  soc_evidence: {
    label: 'SOC 证据评测',
    hint: '开放式告警研判、攻击链重建与响应规划；衡量证据引用、ATT&CK F1、工具效率和安全性',
  },
  soc_contract: {
    label: 'SUPER-AGENT 机制契约',
    hint: '12 个独立内部 runtime-loop 案例，只验证工具失败恢复、证据约束与安全边界，不进入公开主榜',
  },
  malware_analysis: {
    label: 'CyberSOCEval · 恶意软件分析',
    hint: '多选知识问答，衡量通用安全知识',
  },
  attack_kb: {
    label: 'ATT&CK 知识检索',
    hint: '知识库访问能力测试：题干摘录来自 KB；仅作为内部检索链路工程验证',
  },
  threat_intel: {
    label: '威胁情报推理 · CrowdStrike',
    hint: '基于 CrowdStrike 真实威胁报告的防御决策多选题：安全控制测试方法论 / 检测建议 / 缓解措施，题干自包含威胁上下文（588 题）',
  },
  cybergym_lite: {
    label: 'CyberGym Lite',
    hint: '官方 CyberGym Level-1 小体积漏洞修复任务；用隐藏补丁做等价评分，适合快速展示 CyberOrion Agent 分数',
  },
  secalertbench: {
    label: 'SecAlertBench · 企业告警',
    hint: '8,322 条外部企业 SOC 告警；展示 Macro-F1、攻击召回率和误报率',
  },
  excytin: {
    label: 'ExCyTIn · 多源调查',
    hint: 'ACESEvals 多表遥测调查；比较普通 LLM、单代理与 SUPER-AGENT',
  },
  cage2: {
    label: 'CAGE-2 · 自主防御',
    hint: '官方 CybORG 防御环境原生 reward；评测 Analyze/Remove/Restore 闭环',
  },
  live_paired: {
    label: 'Paired Live Docker',
    hint: 'CLI/代码显式 harness 专用；相同攻击计划、快照和多 seed 的三臂安全配对，不允许网页自动重置 Docker',
  },
}

/** Comparison arm: 纯 LLM (vanilla/base) vs CyberOrion 框架 (framework/rag).
 * 框架有效性对比的两臂：同 seed 同批题同模型，分差即框架增益。 */
export type BenchArm = 'bare' | 'rag' | 'single' | 'framework'

export function armOfMode(mode: BenchMode): BenchArm | null {
  if (mode === 'base') return 'bare'
  if (mode === 'rag') return 'rag'
  if (mode === 'single') return 'single'
  if (mode === 'agent') return 'framework'
  return null // legacy experiment modes — excluded from comparisons
}

/** Per-suite arm naming (run card / badges / chart legend). */
export const BENCH_ARMS: Record<
  BenchSuite,
  { bare: { mode: BenchMode; label: string }; framework: { mode: BenchMode; label: string } }
> = {
  soc_evidence: {
    bare: { mode: 'base', label: 'Plain LLM' },
    framework: { mode: 'agent', label: 'CyberOrion Agent' },
  },
  soc_contract: {
    bare: { mode: 'base', label: 'Plain LLM' },
    framework: { mode: 'agent', label: '契约验证' },
  },
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
  cybergym_lite: {
    bare: { mode: 'base', label: 'Plain LLM' },
    framework: { mode: 'agent', label: 'CyberOrion Agent' },
  },
  secalertbench: {
    bare: { mode: 'base', label: 'Plain LLM' },
    framework: { mode: 'agent', label: 'SUPER-AGENT' },
  },
  excytin: {
    bare: { mode: 'base', label: 'Plain LLM' },
    framework: { mode: 'agent', label: 'SUPER-AGENT' },
  },
  cage2: {
    bare: { mode: 'base', label: '直接策略' },
    framework: { mode: 'agent', label: 'SUPER-AGENT' },
  },
  live_paired: {
    bare: { mode: 'paired', label: 'Paired protocol' },
    framework: { mode: 'paired', label: 'Paired protocol' },
  },
}

/** 臂的展示名；legacy 实验模式（不在对比中）原样返回 mode。 */
export function armLabelOf(mode: BenchMode): string {
  const arm = armOfMode(mode)
  if (arm === 'framework') return 'CyberOrion 框架'
  if (arm === 'bare') return '纯 LLM'
  if (arm === 'rag') return 'LLM + RAG'
  if (arm === 'single') return '单体 ReAct'
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
  patch_equivalence?: number
  macro_f1?: number
  attack_recall?: number
  false_positive_rate?: number
  answer_accuracy?: number
  official_reward?: number | null
  native_reward?: number
  mean_reward?: number
  reward_std?: number
  pr_auc?: number
  brier_score?: number
  expected_calibration_error_10bin?: number
  triage_cost?: number
  availability_penalty?: number
  restore_actions?: number
  illegal_actions?: number
  parse_fail: number
  /** LLM 调用失败的题目数（endpoint 故障不再静默成全 0 分）。 */
  llm_errors?: number
  by_difficulty: Record<string, BenchGroupScore>
  by_topic: Record<string, BenchGroupScore>
  task_success?: number
  detection_f1?: number
  attack_f1?: number
  evidence_grounding?: number
  unsupported_claim_rate?: number
  response_completeness?: number
  unsafe_action_rate?: number
  tool_call_validity?: number
  useful_action_ratio?: number
  confidence_intervals?: Record<string, [number, number] | null>
  failure_taxonomy?: Record<string, number>
  avg_latency_ms?: number
  estimated_tokens?: number
}

/** Headline metric of a finished run (exact-match accuracy), as a 0..1
 * fraction. */
export function primaryScoreOf(r: {
  suite?: BenchSuite
  scores: BenchScores | null
}): number | undefined {
  if (!r.scores) return undefined
  if (r.suite === 'cybergym_lite') return r.scores.patch_equivalence ?? r.scores.avg_score
  if (r.suite === 'soc_evidence') return r.scores.task_success ?? r.scores.avg_score
  if (r.suite === 'soc_contract') return r.scores.task_success ?? r.scores.avg_score
  if (r.suite === 'secalertbench') return r.scores.macro_f1 ?? r.scores.avg_score
  if (r.suite === 'excytin') return r.scores.official_reward ?? r.scores.native_reward ?? r.scores.answer_accuracy ?? r.scores.avg_score
  if (r.suite === 'cage2') return r.scores.mean_reward ?? r.scores.avg_score
  if (r.suite === 'live_paired') return r.scores.avg_score
  return r.scores.correct_mc_pct
}

export function primaryScoreLabel(suite: BenchSuite | undefined): string {
  if (suite === 'cybergym_lite') return '补丁等价分'
  if (suite === 'soc_evidence') return '任务成功率'
  if (suite === 'soc_contract') return '契约通过率'
  if (suite === 'secalertbench') return 'Macro-F1'
  if (suite === 'excytin') return '调查得分'
  if (suite === 'cage2') return '环境奖励'
  if (suite === 'live_paired') return '配对 Arena 分'
  return '选择题正确率'
}

/** GET /api/bench/questions — 题目预览（含答案），与正式基准同采样逻辑。 */
export interface BenchQuestionPreview {
  idx?: number
  question?: string
  options?: string[]
  correct_options?: string[]
  task_id?: string
  project_name?: string
  project_homepage?: string
  project_main_repo?: string
  project_language?: string
  vulnerability_description?: string
  difficulty_level?: string
  task_difficulty?: Record<string, string[]>
  visible_level1_artifacts?: string[]
  artifact_sizes?: Record<string, number>
  key_fix_actions?: string[]
  expected_files?: string[]
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
  profile?: 'daily' | 'publication'
  methodology_status?: 'official_compatible' | 'external_track' | 'engineering_only' | 'legacy_invalid_gold_v1'
  benchmark_provenance?: Record<string, unknown> | null
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

export interface EvidenceTelemetry {
  id: string
  source: string
  ts: string
  event: string
}

export interface EvidenceTraceEvent {
  seq: number
  agent: string
  event: string
  tool?: string | null
  target?: string
  status: string
  useful: boolean
}

export interface EvidenceBenchResult {
  idx: number
  case_id: string
  task_type: string
  title: string
  difficulty: string
  prompt: string
  telemetry: EvidenceTelemetry[]
  gold: Record<string, unknown>
  prediction: Record<string, unknown>
  agent_trace: EvidenceTraceEvent[]
  metrics: Record<string, number>
  failure_tags: string[]
  parse_ok: boolean
  latency_ms: number
  estimated_tokens: number
}

export interface CyberGymLiteMetrics {
  parse_ok: boolean
  exact: boolean
  patch_equivalence: number
  file_score: number
  invariant_score: number
  diff_similarity: number
  has_patch_shape: boolean
  answer_files: string[]
  gold_files: string[]
  token_hits: Array<{ token: string; hit: boolean }>
}

export interface CyberGymLiteResult {
  idx: number
  task_id: string
  project_name: string
  project_homepage: string
  project_main_repo: string
  project_language: string
  vulnerability_description: string
  difficulty: string
  title: string
  visible_level1_artifacts: string[]
  artifact_sizes: Record<string, number>
  expected_files: string[]
  gold_changed_files: string[]
  gold_patch_excerpt: string
  key_fix_actions: string[]
  raw: string
  metrics: CyberGymLiteMetrics
  parse_ok: boolean
  llm_error: boolean
  error?: string | null
  agent_trace: EvidenceTraceEvent[]
  failure_tags: string[]
  latency_ms: number
  estimated_tokens: number
}

/** GET /api/bench/run/{run_id} — full detail incl. per-question results. */
export interface BenchRunDetail extends BenchRunSummary {
  started_at?: number
  finished_at?: number
  rag_top_k?: number
  /** 逐题可读报告路径（logs/bench/<run_id>.md，完整题干/选项/回答）。 */
  report?: string | null
  /** QA suites: per-question results. */
  results?: Array<BenchResultItem | EvidenceBenchResult | CyberGymLiteResult>
  budget?: { max_steps: number; task_timeout: number }
}

/** GET /api/bench/run/{run_id}/task/{idx} — 单题完整 drill-down。 */
export interface BenchTaskDetail {
  run_id: string
  suite: BenchSuite
  mode?: string
  idx: number
  n: number
  task: BenchResultItem | EvidenceBenchResult | CyberGymLiteResult
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
// ---------------------------------------------------------------------------
// 流量分析（流量回放 + 蓝队 agent 分析）
// ---------------------------------------------------------------------------

/** 一条流量事件（CICIDS/synthetic 回放产生的网络流）。 */
export interface FlowEvent {
  ts: number
  src_ip: string
  dst_ip: string
  dst_port: number
  /** 流量标签：BENIGN / 攻击类型（DDoS / Brute Force / SQLi …）。 */
  label: string
  /** ATT&CK 技术编号（无则空串）。 */
  technique: string
  /** 攻击大类（告警着色用）。 */
  attack_type: string
}

/** 一条检测告警（流量触发的蓝队检测/研判结果）。 */
export interface FlowAlert {
  ts: number
  src_ip: string
  dst_ip: string
  /** 告警类型（如 SSH 爆破、SQL 注入）。 */
  alert_type: string
  /** ATT&CK 技术。 */
  technique: string
  /** 严重级别：critical / high / medium / low。 */
  severity: string
  /** 置信度 0..1。 */
  confidence: number
  /** 告警描述。 */
  description: string
  /** 证据摘要。 */
  evidence: string
}
/** GET /api/traffic/status — 流量回放服务状态。 */
export interface TrafficStatus {
  ready: boolean
  sources: string[]
  csv_files: string[]
  replaying: boolean
}

/** POST /api/traffic/replay — 回放结果。 */
export interface TrafficReplayResult {
  ok: boolean
  events?: FlowEvent[]
  alerts?: FlowAlert[]
  source?: string
  csv_file?: string
  rows?: number
  events_count?: number
  events_total?: number
  alerts_count?: number
  replay_limit?: number
  label_distribution?: Record<string, number>
  alert_distribution?: Record<string, number>
  error?: string
}

// ---------------------------------------------------------------------------
// v2 multi-role architecture (red 7 workers + 1 orchestrator / blue 4 workers + 1 orchestrator)
// Corresponds to backend cyberorion/agents/v2/{red,blue}_workers.py and controller_v2.py.
// ---------------------------------------------------------------------------

/** v2 role interface: tools is a string array, with ATT&CK technique mapping. */
export interface V2Role {
  /** Role unique key (matches backend AgentRole enum). */
  key: string
  /** Chinese display name. */
  name: string
  /** Duty summary. */
  duty: string
  /** CSS color variable name (e.g. '--color-recon', wrapped via v2RoleColor as var(...)). */
  colorVar: string
  /** Tool list (English names, may include wildcards like 'dispatch_*'). */
  tools: string[]
  /** ATT&CK technique mapping (ID + name). */
  techniques: string[]
  /** Side. */
  side: 'red' | 'blue'
}

/** Red team v2 worker roles (7) + orchestrator.
 *  Order matches backend AgentRole enum: recon -> credential_access -> cracker ->
 *  acl -> privesc -> lateral -> coercion -> orchestrator. */
export const RED_V2_ROLES: V2Role[] = [
  {
    key: 'recon',
    name: '侦察',
    duty: '网络扫描/枚举/BloodHound',
    colorVar: '--color-recon',
    tools: ['nmap', 'netexec', 'bloodhound', 'ldapsearch'],
    techniques: ['T1595 Active Scanning', 'T1018 Remote System Discovery', 'T1087 Account Discovery'],
    side: 'red',
  },
  {
    key: 'credential_access',
    name: '凭据获取',
    duty: 'Kerberoasting/AS-REP/密码喷洒',
    colorVar: '--color-cred',
    tools: ['secretsdump', 'kerberoast', 'lsassy'],
    techniques: ['T1558 Steal or Forge Kerberos Tickets', 'T1110 Brute Force', 'T1003 OS Credential Dumping'],
    side: 'red',
  },
  {
    key: 'cracker',
    name: '破解',
    duty: 'hashcat/john 离线破解',
    colorVar: '--color-crack',
    tools: ['hashcat', 'john'],
    techniques: ['T1110 Brute Force', 'T1555 Credentials from Password Stores'],
    side: 'red',
  },
  {
    key: 'acl',
    name: 'ACL 滥用',
    duty: 'BloodHound 路径/ACL 攻击',
    colorVar: '--color-acl',
    tools: ['bloodyAD', 'pywhisker', 'dacl_edit'],
    techniques: ['T1098 Account Manipulation', 'T1078 Valid Accounts'],
    side: 'red',
  },
  {
    key: 'privesc',
    name: '提权',
    duty: 'ADCS/委派/CVE 利用',
    colorVar: '--color-privesc',
    tools: ['certipy', 'nopac', 'printnightmare'],
    techniques: ['T1068 Exploitation for Privilege Escalation', 'T1556 Modify Authentication Process'],
    side: 'red',
  },
  {
    key: 'lateral',
    name: '横向移动',
    duty: 'PSExec/WMI/WinRM/SSH',
    colorVar: '--color-lateral',
    tools: ['psexec', 'wmiexec', 'evil-winrm'],
    techniques: ['T1021 Remote Services', 'T1077 Windows Admin Shares', 'T1059 Command and Scripting Interpreter'],
    side: 'red',
  },
  {
    key: 'coercion',
    name: '强制认证',
    duty: 'Responder/ntlmrelayx/PetitPotam',
    colorVar: '--color-coercion',
    tools: ['responder', 'ntlmrelayx', 'petitpotam'],
    techniques: ['T1557 Adversary-in-the-Middle', 'T1187 Forced Authentication'],
    side: 'red',
  },
  {
    key: 'orchestrator',
    name: '编排器',
    duty: '任务分发/状态管理',
    colorVar: '--color-orch',
    tools: ['dispatch_*', 'get_*'],
    techniques: ['T1059 Command and Scripting Interpreter'],
    side: 'red',
  },
]

/** Blue team v2 roles (4 workers + 1 orchestrator). */
export const BLUE_V2_ROLES: V2Role[] = [
  {
    key: 'triage',
    name: '分诊',
    duty: '告警评估/IOC 提取/严重性路由',
    colorVar: '--color-triage',
    tools: ['query_logs', 'list_alerts', 'run_detection'],
    techniques: ['T1027 Obfuscated Files or Information', 'T1071 Application Layer Protocol'],
    side: 'blue',
  },
  {
    key: 'threat_hunter',
    name: '威胁狩猎',
    duty: 'MITRE 检测/证据验证/攻击链重建',
    colorVar: '--color-hunter',
    tools: ['run_parallel_detections', 'lookup_technique'],
    techniques: ['T1059 Command and Scripting Interpreter', 'T1070 Indicator Removal'],
    side: 'blue',
  },
  {
    key: 'lateral_analyst',
    name: '横向分析',
    duty: '多主机追踪/横向移动图',
    colorVar: '--color-lat-analyst',
    tools: ['network_summary', 'track_host'],
    techniques: ['T1021 Remote Services', 'T1077 Windows Admin Shares'],
    side: 'blue',
  },
  {
    key: 'escalation_triage',
    name: '升级审查',
    duty: '高危审查/跨调查关联',
    colorVar: '--color-escalation',
    tools: ['query_logs', 'run_detection'],
    techniques: ['T1486 Data Encrypted for Impact', 'T1499 Endpoint Denial of Service'],
    side: 'blue',
  },
  {
    key: 'orchestrator',
    name: 'SOC 指挥官',
    duty: '调查生命周期管理',
    colorVar: '--color-blue-orch',
    tools: ['dispatch_*', 'complete_investigation'],
    techniques: ['T1059 Command and Scripting Interpreter'],
    side: 'blue',
  },
]

/** Wrap v2 colorVar as a CSS-ready var(...) value.
 *  Accepts both bare names ('--color-xxx') and already-wrapped ('var(--color-xxx)'). */
export function v2RoleColor(colorVar: string): string {
  if (colorVar.startsWith('var(')) return colorVar
  return `var(${colorVar})`
}

/** Look up a v2 role by key (red first, then blue). */
export function v2RoleOf(key: string): V2Role | undefined {
  return RED_V2_ROLES.find((r) => r.key === key)
    ?? BLUE_V2_ROLES.find((r) => r.key === key)
}

/** Check if a key is a v2 role (used by DispatchGraph / AgentDetailModal to switch UI). */
export function isV2Role(key: string): boolean {
  return Boolean(v2RoleOf(key))
}

export interface SkillInfo {
  name: string
  description: string
}

export interface SkillsCatalog {
  red: SkillInfo[]
  blue: SkillInfo[]
  total: number
}

export interface SkillDetail {
  side: 'red' | 'blue'
  name: string
  content: string
}
