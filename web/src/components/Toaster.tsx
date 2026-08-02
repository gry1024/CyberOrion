// 全局错误 toast：右上角堆叠，8s 自动消失，可手动关闭。
// Kimi 式：白卡片 + 左侧语义色条 + 细边框。

import { useEffect, useState } from 'react'
import { subscribeToasts } from '../toasts'
import type { Toast, ToastSide } from '../toasts'

const SIDE_STYLE: Record<ToastSide, { border: string; label: string; color: string }> = {
  red: { border: 'var(--color-red)', label: '红方', color: 'var(--color-red)' },
  blue: { border: 'var(--color-blue)', label: '蓝方', color: 'var(--color-blue)' },
  system: { border: 'var(--color-fg-3)', label: '系统', color: 'var(--color-fg-3)' },
}

const AUTO_DISMISS_MS = 8000

function ToastCard({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const meta = SIDE_STYLE[toast.side] ?? SIDE_STYLE.system
  useEffect(() => {
    const t = window.setTimeout(onClose, AUTO_DISMISS_MS)
    return () => window.clearTimeout(t)
  }, [onClose])
  return (
    <div
      role="alert"
      className="pointer-events-auto w-[340px] overflow-hidden rounded-xl border bg-[var(--color-panel)]"
      style={{
        borderColor: 'var(--color-line-2)',
        borderLeft: `3px solid ${meta.border}`,
        boxShadow: '0 8px 28px rgba(0, 0, 0, 0.10)',
      }}
    >
      <div className="flex items-center gap-2 px-4 pt-2.5">
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: meta.color }}>
          {toast.title ?? `${meta.label}错误`}
        </span>
        <button
          onClick={onClose}
          className="ml-auto flex-none text-[12px] leading-none text-[var(--color-fg-4)] transition-colors hover:text-[var(--color-fg)]"
          aria-label="关闭"
        >
          ✕
        </button>
      </div>
      <div className="whitespace-pre-wrap break-words px-4 pb-2.5 pt-1 font-mono text-[11.5px] leading-[1.55]" style={{ color: 'var(--color-fg-2)' }}>
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
        setToasts((prev) => [...prev.slice(-4), t]), // 最多 5 条
      ),
    [],
  )

  if (toasts.length === 0) return null
  return (
    <div className="pointer-events-none fixed right-4 top-4 z-[90] flex flex-col items-end gap-2">
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
