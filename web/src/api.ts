// Thin REST client for the CyberOrion backend.

async function post(path: string): Promise<unknown> {
  const r = await fetch(path, { method: 'POST' })
  return r.json()
}

async function get(path: string): Promise<unknown> {
  const r = await fetch(path)
  return r.json()
}

export const api = {
  getStatus: () => get('/api/status') as Promise<import('./types').ControllerStatus>,
  getLedger: () => get('/api/ledger') as Promise<import('./types').StateSnapshot>,
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
