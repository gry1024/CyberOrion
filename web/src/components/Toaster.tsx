// 全局错误 toast：右上角堆叠，8s 自动消失，可手动关闭。
// 数据来源：WS type="error" 事件 + 关键 REST 操作失败（见 api.ts 调用方）。

import { useEffect, useState } from 'react'
import { subscribeToasts } from '../toasts'
import type { Toast, ToastSide } from '../toasts'

const SIDE_STYLE: Record<ToastSide, { border: string; label: string; text: string }> = {
  red: { border: 'border-l-attacker', label: '红方', text: 'text-attacker' },
  blue: { border: 'border-l-accent', label: '蓝方', text: 'text-accent' },
  system: { border: 'border-l-warning', label: '系统', text: 'text-warning' },
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
      className={`glass pointer-events-auto w-[340px] rounded-xl border border-hairline
        border-l-2 ${meta.border} px-3.5 py-2.5 shadow-lg shadow-black/40`}
    >
      <div className="flex items-center gap-2">
        <span className={`text-[9px] font-bold uppercase tracking-[0.2em] ${meta.text}`}>
          {toast.title ?? `${meta.label}错误`}
        </span>
        <button
          onClick={onClose}
          className="ml-auto flex-none text-[11px] leading-none text-text-3 transition-colors hover:text-neutral-200"
          aria-label="关闭"
        >
          ✕
        </button>
      </div>
      <div className="mt-1 whitespace-pre-wrap break-words font-mono text-[11px] leading-[1.5] text-[#d1d1d6]">
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
    <div className="pointer-events-none fixed right-4 top-16 z-[90] flex flex-col items-end gap-2">
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
