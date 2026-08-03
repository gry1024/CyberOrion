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
  ScenarioDetail,
  ScenarioInfo,
  ScenarioList,
  ScoreMetrics,
  SessionDetail,
  SessionInfo,
  StorylineResult,
  TelemetryEventRow,
} from './types'

async function post(path: string, body?: unknown): Promise<unknown> {
  let r: Response
  try {
    r = await fetch(path, {
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

async function get(path: string): Promise<unknown> {
  const r = await fetch(path)
  if (!r.ok) throw new Error(`GET ${path} -> ${r.status}`)
  return r.json()
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
  getStoryline: (id: string) =>
    get(`/api/sessions/${id}/storyline`) as Promise<StorylineResult>,
  /** 202 {status:"generating"} when a generation is queued/in flight. */
  generateStoryline: (id: string, force = false) =>
    post(`/api/sessions/${id}/storyline`, force ? { force: true } : {}) as Promise<StorylineResult>,

  getKbStats: () => get('/api/kb/stats') as Promise<KbStats>,
  getKbTactics: () => get('/api/kb/tactics') as Promise<KbTactic[]>,
  kbSearch: (q: string, k = 8) =>
    get(`/api/kb/search?q=${encodeURIComponent(q)}&k=${k}`) as Promise<
      KbSearchHit[]
    >,
  getKbDoc: (id: string) =>
    get(`/api/kb/doc/${encodeURIComponent(id)}`) as Promise<KbDoc>,

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
}

export type { AgentRoleSpec } from './types'
