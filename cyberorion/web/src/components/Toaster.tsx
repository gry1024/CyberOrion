// 全局 toast：右下角堆叠（Cursor 式：平铺小条，无圆角卡）。

import { useEffect, useState } from 'react'
import { subscribeToasts } from '../toasts'
import type { Toast, ToastSide } from '../toasts'

const SIDE_COLOR: Record<ToastSide, string> = {
  red: 'var(--color-red)',
  blue: 'var(--color-blue)',
  system: 'var(--color-fg-3)',
}

const AUTO_DISMISS_MS = 8000

function ToastCard({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const color = SIDE_COLOR[toast.side] ?? SIDE_COLOR.system
  useEffect(() => {
    const t = window.setTimeout(onClose, AUTO_DISMISS_MS)
    return () => window.clearTimeout(t)
  }, [onClose])
  return (
    <div
      role="alert"
      className="pointer-events-auto w-[320px] border px-3 py-2"
      style={{
        background: 'var(--color-bg-2)',
        borderColor: 'var(--color-line-2)',
        borderLeft: `2px solid ${color}`,
      }}
    >
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide" style={{ color }}>
          {toast.title ?? '系统'}
        </span>
        <button
          onClick={onClose}
          className="ml-auto flex-none text-[11px] leading-none text-[var(--color-fg-4)] transition-colors hover:text-[var(--color-fg)]"
          aria-label="关闭"
        >
          ✕
        </button>
      </div>
      <div className="whitespace-pre-wrap break-words pt-0.5 font-mono text-[11px] leading-[1.5]" style={{ color: 'var(--color-fg-2)' }}>
        {toast.message}
      </div>
    </div>
  )
}

export function Toaster() {
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(
    () =>
      subscribeToasts((t) =>
        setToasts((prev) => [...prev.slice(-4), t]),
      ),
    [],
  )

  if (toasts.length === 0) return null
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[90] flex flex-col items-end gap-1.5">
      {toasts.map((t) => (
        <ToastCard
          key={t.id}
          toast={t}
          onClose={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
        />
      ))}
    </div>
  )
}
