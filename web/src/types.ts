// Shared types for the CyberOrion arena frontend.

export type Side = 'red' | 'blue' | 'system'

export type EventType =
  | 'thinking'
  | 'tool_call'
  | 'tool_output'
  | 'attack'
  | 'detection'
  | 'harden'
  | 'round_start'
  | 'round_end'
  | 'session_start'
  | 'session_end'
  | 'snapshot'
  | 'heartbeat'

export interface ArenaEvent {
  type: EventType
  side: Side
  data: Record<string, unknown>
  timestamp: number
}

export interface ThoughtStep {
  id: string
  kind: 'thinking' | 'tool_call' | 'tool_output'
  text?: string
  tool?: string
  args?: string
  output?: string
  timestamp: number
}

export interface LedgerEntry {
  vuln_id: string
  status: string
  evidence: string
  history: Array<{ status: string; evidence: string; at: number }>
  extra?: Record<string, unknown>
  scope?: 'global' | 'session'
}

export interface ControllerStatus {
  red_running: boolean
  blue_running: boolean
  red_paused: boolean
  blue_paused: boolean
  round: number
  ledger: Record<string, LedgerEntry>
  red_history_count: number
  blue_history_count: number
}

export interface StateSnapshot {
  global_state: Record<string, unknown>
  session_state: Record<string, unknown>
  ledger: {
    global: Record<string, LedgerEntry>
    session: Record<string, LedgerEntry>
    merged: Record<string, LedgerEntry>
  }
}
