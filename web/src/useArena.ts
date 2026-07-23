// React hook managing the WebSocket connection and live event state.

import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { ArenaEvent, ControllerStatus, LedgerEntry, Side, ThoughtStep } from './types'

const MAX_STEPS_PER_SIDE = 200

interface UseArenaResult {
  connected: boolean
  status: ControllerStatus
  redSteps: ThoughtStep[]
  blueSteps: ThoughtStep[]
  ledger: Record<string, LedgerEntry>
  lastEvent: ArenaEvent | null
  refresh: () => Promise<void>
  clearSteps: (side: Side) => void
}

function emptyStatus(): ControllerStatus {
  return {
    red_running: false,
    blue_running: false,
    red_paused: false,
    blue_paused: false,
    round: 0,
    ledger: {},
    red_history_count: 0,
    blue_history_count: 0,
  }
}

let stepCounter = 0
function nextId(): string {
  stepCounter += 1
  return 's' + stepCounter
}

function appendStep(prev: ThoughtStep[], step: ThoughtStep, cap = MAX_STEPS_PER_SIDE): ThoughtStep[] {
  const next = prev.concat(step)
  return next.length > cap ? next.slice(next.length - cap) : next
}

export function useArena(): UseArenaResult {
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState<ControllerStatus>(emptyStatus())
  const [redSteps, setRedSteps] = useState<ThoughtStep[]>([])
  const [blueSteps, setBlueSteps] = useState<ThoughtStep[]>([])
  const [ledger, setLedger] = useState<Record<string, LedgerEntry>>({})
  const [lastEvent, setLastEvent] = useState<ArenaEvent | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    try {
      const s = await api.getStatus()
      setStatus(s)
      setLedger(s.ledger || {})
    } catch {
      /* keep last known state */
    }
  }, [])

  const clearSteps = useCallback((side: Side) => {
    if (side === 'red') setRedSteps([])
    else if (side === 'blue') setBlueSteps([])
  }, [])

  useEffect(() => {
    let closed = false

    const connect = () => {
      if (closed) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const url = proto + '://' + window.location.host + '/ws'
      let ws: WebSocket
      try {
        ws = new WebSocket(url)
      } catch {
        scheduleReconnect()
        return
      }
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        refresh()
      }
      ws.onclose = () => {
        setConnected(false)
        scheduleReconnect()
      }
      ws.onerror = () => {
        try { ws.close() } catch { /* ignore */ }
      }
      ws.onmessage = (msg) => {
        let ev: ArenaEvent
        try {
          ev = JSON.parse(msg.data)
        } catch {
          return
        }
        handleMessage(ev)
      }
    }

    const scheduleReconnect = () => {
      if (closed) return
      if (reconnectTimer.current != null) return
      reconnectTimer.current = window.setTimeout(() => {
        reconnectTimer.current = null
        connect()
      }, 1500)
    }

    const handleMessage = (ev: ArenaEvent) => {
      setLastEvent(ev)
      const side: Side = ev.side
      const ts = ev.timestamp
      const data = ev.data || {}

      if (ev.type === 'snapshot') {
        const s = (data as { status?: ControllerStatus }).status
        if (s) {
          setStatus(s)
          setLedger(s.ledger || {})
        }
        return
      }
      if (ev.type === 'heartbeat') return

      if (side === 'red' || side === 'blue') {
        if (ev.type === 'thinking') {
          const text = String(data.text || '')
          if (text) {
            const step: ThoughtStep = { id: nextId(), kind: 'thinking', text, timestamp: ts }
            if (side === 'red') setRedSteps((p) => appendStep(p, step))
            else setBlueSteps((p) => appendStep(p, step))
          }
        } else if (ev.type === 'tool_call') {
          const tool = String(data.tool || '?')
          const args = String(data.args || '')
          const step: ThoughtStep = { id: nextId(), kind: 'tool_call', tool, args, timestamp: ts }
          if (side === 'red') setRedSteps((p) => appendStep(p, step))
          else setBlueSteps((p) => appendStep(p, step))
        } else if (ev.type === 'tool_output') {
          const output = String(data.output || '')
          const step: ThoughtStep = { id: nextId(), kind: 'tool_output', output, timestamp: ts }
          if (side === 'red') setRedSteps((p) => appendStep(p, step))
          else setBlueSteps((p) => appendStep(p, step))
        }
      }

      if (
        ev.type === 'session_start' || ev.type === 'session_end' ||
        ev.type === 'round_start' || ev.type === 'round_end' ||
        ev.type === 'attack' || ev.type === 'detection'
      ) {
        Promise.resolve().then(() => refresh())
      }
    }

    connect()

    return () => {
      closed = true
      if (reconnectTimer.current != null) {
        window.clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
      if (wsRef.current) {
        try { wsRef.current.close() } catch { /* ignore */ }
        wsRef.current = null
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const t = window.setInterval(refresh, 4000)
    return () => window.clearInterval(t)
  }, [refresh])

  return { connected, status, redSteps, blueSteps, ledger, lastEvent, refresh, clearSteps }
}
