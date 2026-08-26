// Global error toast bus — module-level store so both the WS data layer
// (arena.tsx) and plain REST callers (Header controls, bench run card, ...)
// can surface failures without prop drilling. Never silent.

export type ToastSide = 'red' | 'blue' | 'system'

export interface Toast {
  id: number
  side: ToastSide
  title?: string
  message: string
  ts: number
}

type Listener = (t: Toast) => void

let seq = 0
const listeners = new Set<Listener>()

/** Push a toast; every subscriber (the <Toaster/>) renders it. */
export function pushToast(
  message: string,
  opts: { side?: ToastSide; title?: string } = {},
): void {
  const t: Toast = {
    id: ++seq,
    side: opts.side ?? 'system',
    title: opts.title,
    message: String(message || '未知错误').slice(0, 500),
    ts: Date.now(),
  }
  for (const fn of listeners) fn(t)
}

export function subscribeToasts(fn: Listener): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}
