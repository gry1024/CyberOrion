// Thin REST client for the CyberOrion backend.

import type {
  AgentRoleSpec,
  AlertRow,
  BenchMode,
  BenchQuestionPreview,
  BenchRunDetail,
  BenchRunSummary,
  BenchSuite,
  BenchTaskDetail,
  ControllerStatus,
  KbDoc,
  KbSearchHit,
  KbStats,
  KbTactic,
  KbListResponse,
  ScenarioDetail,
  ScenarioInfo,
  ScenarioList,
  ScoreMetrics,
  SessionDetail,
  SessionInfo,
  SkillDetail,
  SkillsCatalog,
  StorylineResult,
  TelemetryEventRow,
  TrafficReplayResult,
  TrafficStatus,
} from './types'

// 生产部署到 /cyberorion/ 子目录时，所有 API 路径需加前缀；
// 开发环境 VITE_BASE=/ → BASE_URL 为 '/'，前缀自然消除。
const BASE = import.meta.env.BASE_URL
function url(path: string): string {
  return BASE + path.replace(/^\//, '')
}

async function post(path: string, body?: unknown): Promise<unknown> {
  let r: Response
  try {
    r = await fetch(url(path), {
      method: 'POST',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? null : JSON.stringify(body),
    })
  } catch {
    throw new Error(`POST ${path} 请求失败 — 后端未响应`)
  }
  const data: unknown = await r.json().catch(() => ({}))
  if (!r.ok) {
    const msg =
      (data as { error?: string })?.error ?? `HTTP ${r.status}`
    throw new Error(msg)
  }
  return data
}

async function postFormData(path: string, fields: Record<string, unknown>): Promise<unknown> {
  const fd = new FormData()
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === null || v === '') continue
    fd.append(k, v as string | Blob)
  }
  let r: Response
  try {
    r = await fetch(url(path), { method: 'POST', body: fd })
  } catch {
    throw new Error('POST ' + path + ' failed')
  }
  const data: unknown = await r.json().catch(() => ({}))
  if (!r.ok) {
    const msg = (data as { error?: string })?.error ?? 'HTTP ' + r.status
    throw new Error(msg)
  }
  return data
}

async function get(path: string): Promise<unknown> {
  const r = await fetch(url(path))
  if (!r.ok) throw new Error(`GET ${path} -> ${r.status}`)
  return r.json()
}

async function getText(path: string): Promise<string> {
  const r = await fetch(url(path))
  if (!r.ok) throw new Error(`GET ${path} -> ${r.status}`)
  return r.text()
}

export const api = {
  getStatus: () => get('/api/status') as Promise<ControllerStatus>,
  getScenario: () => get('/api/scenario') as Promise<ScenarioInfo>,
  getScenarios: () => get('/api/scenarios') as Promise<ScenarioList>,
  selectScenario: (name: string) =>
    post('/api/scenario/select', { name }) as Promise<{
      ok: boolean
      active?: string
      error?: string
    }>,
  getAlerts: () => get('/api/alerts') as Promise<AlertRow[]>,
  getEvents: (limit = 100) =>
    get(`/api/events?limit=${limit}`) as Promise<TelemetryEventRow[]>,
  getSessions: () => get('/api/sessions') as Promise<SessionInfo[]>,
  getSessionReport: (id: string) =>
    get(`/api/sessions/${id}/report`) as Promise<{ id: string; report: string }>,
  getSessionMetrics: (id: string) =>
    get(`/api/sessions/${id}/metrics`) as Promise<ScoreMetrics>,
  getSessionDetail: (id: string) =>
    get(`/api/sessions/${id}/detail`) as Promise<SessionDetail>,
  getSessionRawTimeline: (id: string) =>
    getText(`/api/sessions/${id}/timeline/raw`),
  getStoryline: (id: string) =>
    get(`/api/sessions/${id}/storyline`) as Promise<StorylineResult>,
  /** 202 {status:"generating"} when a generation is queued/in flight. */
  generateStoryline: (id: string, force = false) =>
    post(`/api/sessions/${id}/storyline`, force ? { force: true } : {}) as Promise<StorylineResult>,

  // ---- demo replay (演示回放，素材来自历史 session，禁止捏造) ----
  listDemos: () =>
    get('/api/demo') as Promise<{
      demos: Array<{ task_type: string; session_id: string; available: boolean }>
    }>,
  getDemo: (taskType: string) =>
    get(`/api/demo/${taskType}`) as Promise<{
      ok: boolean
      task_type: string
      session_id: string
      event_count: number
      events: Array<{
        kind: string
        type?: string
        side: string
        data: Record<string, unknown>
        timestamp: number
      }>
      note?: string
    }>,

  getKbStats: () => get('/api/kb/stats') as Promise<KbStats>,
  getKbTactics: () => get('/api/kb/tactics') as Promise<KbTactic[]>,
  kbSearch: (q: string, k = 8) =>
    get(`/api/kb/search?q=${encodeURIComponent(q)}&k=${k}`) as Promise<
      KbSearchHit[]
    >,
  getKbDoc: (id: string) =>
    get(`/api/kb/doc/${encodeURIComponent(id)}`) as Promise<KbDoc>,
  getKbList: (params: { type?: string; offset?: number; limit?: number; q?: string }) =>
    get(`/api/kb/list?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => [k === 'type' ? 'doc_type' : k, String(v)]) as [string, string][]).toString()}`) as Promise<KbListResponse>,
  getKbAutoUpdateStatus: () =>
    get('/api/kb/auto-update/status') as Promise<{
      daemon_running: boolean
      last_run: {
        started_at: string
        cve_fetched: number
        regulation_fetched: number
        added: number
        elapsed_sec: number
        errors: string[]
      } | null
      history: Array<Record<string, unknown>>
    }>,
  triggerKbUpdate: () =>
    post('/api/kb/auto-update', {}) as Promise<{
      ok: boolean
      result: Record<string, unknown>
    }>,

  startBenchRun: (n: number, mode: BenchMode, suite: BenchSuite) =>
    post('/api/bench/run', { n, mode, suite }) as Promise<{
      ok: boolean
      run_id?: string
      error?: string
    }>,
  getBenchRuns: () => get('/api/bench/runs') as Promise<BenchRunSummary[]>,
  getBenchRun: (runId: string) =>
    get(`/api/bench/run/${runId}`) as Promise<BenchRunDetail>,
  /** 单题完整 drill-down（QA 补全题干选项）。 */
  getBenchTask: (runId: string, idx: number) =>
    get(`/api/bench/run/${runId}/task/${idx}`) as Promise<BenchTaskDetail>,
  /** 题目预览：按 seed 采样 n 道题（含正确答案），与正式基准同逻辑。 */
  getBenchQuestions: (suite: BenchSuite, n: number, seed = 42) =>
    get(
      `/api/bench/questions?suite=${suite}&n=${n}&seed=${seed}`,
    ) as Promise<{
      suite: BenchSuite
      n: number
      seed: number
      questions: BenchQuestionPreview[]
    }>,

  getScenarioInfo: () => get('/api/scenario/info') as Promise<ScenarioDetail>,
  getAbout: () => get('/api/about') as Promise<{ markdown: string }>,
  getAgentRoles: () => get('/api/agents/roles') as Promise<AgentRoleSpec[]>,

  sessionStart: () => post('/api/session/start'),
  sessionStop: () => post('/api/session/stop'),
  redStart: () => post('/api/red/start'),
  redPause: () => post('/api/red/pause'),
  redResume: () => post('/api/red/resume'),
  redStop: () => post('/api/red/stop'),
  blueStart: () => post('/api/blue/start'),
  bluePause: () => post('/api/blue/pause'),
  blueResume: () => post('/api/blue/resume'),
  blueStop: () => post('/api/blue/stop'),
  bluePatrolStart: () => post('/api/blue/patrol/start'),
  bluePatrolStop: () => post('/api/blue/patrol/stop'),

  // ---- 流量分析（CICIDS/synthetic 流量回放 + 蓝队 agent 分析） ----
  /** 启动流量回放：返回事件流与触发告警。 */
  trafficReplay: (opts: { source?: string; csv_file?: string; max_rows?: number }) =>
    post('/api/traffic/replay', opts) as Promise<TrafficReplayResult>,
  /** 查询流量回放服务状态（可用数据源 / CSV 文件清单）。 */
  trafficStatus: () => get('/api/traffic/status') as Promise<TrafficStatus>,
  /** 调用蓝队 agent 对当前流量窗口做分析（输出流式告警研判）。 */
  trafficAnalyze: (opts: Record<string, unknown>) =>
    post('/api/traffic/analyze', opts) as Promise<{ ok: boolean; output?: string; error?: string }>,

  trafficAnalyzeStream: (
    opts: Record<string, unknown>,
    onEvent: (ev: { type: string; side: string; data: Record<string, unknown>; timestamp: number }) => void,
    onError?: (e: Error) => void,
    onComplete?: () => void,
  ): AbortController => {
    const c = new AbortController()
    fetch(url('/api/traffic/analyze'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(opts), signal: c.signal }).then(async (r: Response) => {
      if (!r.ok || !r.body) { onError?.(new Error(`HTTP ${r.status}`)); return }
      const rd = r.body.getReader(), dec = new TextDecoder()
      let buf = ''
      for (;;) { const { done, value } = await rd.read(); if (done) break; buf += dec.decode(value, { stream: true }); let i; while ((i = buf.indexOf('\n\n')) >= 0) { const f = buf.slice(0, i); buf = buf.slice(i + 2); for (const l of f.split('\n')) { const t = l.trim(); if (!t.startsWith('data:')) continue; try { onEvent(JSON.parse(t.slice(5).trim())) } catch {} } } }
      onComplete?.()
    }).catch((e: Error) => { if (e.name !== 'AbortError') onError?.(e) })
    return c
  },

  // ---- v2 multi-role architecture API (controller_v2.py) ----
  /** Start v2 session (default scenario web_basic, CTF-style red-team vs blue-team). */
  startV2Session: (scenario: string = 'web_basic') =>
    post('/api/v2/session/start', { scenario }) as Promise<{
      ok: boolean
      session_id?: string
      error?: string
    }>,
  /** Start v2 red team orchestrator (optional task prompt). */
  startV2Red: (prompt: string = '') =>
    post('/api/v2/red/start', { prompt }) as Promise<{ ok: boolean; error?: string }>,
  /** Start v2 blue team orchestrator. */
  startV2Blue: (prompt: string = '') =>
    post('/api/v2/blue/start', { prompt }) as Promise<{ ok: boolean; error?: string }>,
  /** Stop v2 red team. */
  stopV2Red: () => post('/api/v2/red/stop', {}) as Promise<{ ok: boolean; error?: string }>,
  /** Stop v2 blue team. */
  stopV2Blue: () => post('/api/v2/blue/stop', {}) as Promise<{ ok: boolean; error?: string }>,
  /** Stop current v2 session. */
  stopV2Session: () => post('/api/v2/session/stop', {}) as Promise<{ ok: boolean; error?: string }>,

  getSkills: () => get('/api/skills') as Promise<SkillsCatalog>,
  getSkillDetail: (side: string, name: string) =>
    get(`/api/skills/${side}/${name}`) as Promise<SkillDetail>,

  // ---- hostguard (host maintenance) ----
  hostguardConnect: (opts: { host: string; port: number; username: string; password: string; keyFile?: File | null }) =>
    postFormData('/api/hostguard/connect', opts as Record<string, unknown>) as Promise<{ ok: boolean; host?: string; key_used?: boolean; system_info?: string; error?: string }>,
  hostguardStatus: () => get('/api/hostguard/status') as Promise<{ connected: boolean; host?: string; username?: string; port?: number; system_info?: string }>,
  hostguardDisconnect: () => post('/api/hostguard/disconnect', {}) as Promise<{ ok: boolean }>,
  hostguardScanURL: () => url('/api/hostguard/scan'),
  hostguardChatURL: () => url('/api/hostguard/chat'),
}

export type { AgentRoleSpec } from './types'
