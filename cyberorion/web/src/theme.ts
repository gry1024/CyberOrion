// 明暗主题工具：Sidebar 切换 .dark 类，这里提供订阅与 CSS 变量读取。
// 供 canvas/SVG 渲染器（KbGraph、BenchBarChart）在主题切换时重绘。

import { useEffect, useState } from 'react'

export type Theme = 'light' | 'dark'

export function isDark(): boolean {
  return typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
}

/** 订阅 <html> 的 class 变化（主题切换）并返回当前主题。 */
export function useTheme(): Theme {
  const [theme, setTheme] = useState<Theme>(() => (isDark() ? 'dark' : 'light'))
  useEffect(() => {
    const obs = new MutationObserver(() => {
      const next = isDark() ? 'dark' : 'light'
      setTheme((prev) => (prev === next ? prev : next))
    })
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])
  return theme
}

/** 读取当前主题下的 CSS 变量值（如 --color-fg）。空串表示变量未定义。 */
export function readCssVar(name: string): string {
  if (typeof document === 'undefined') return ''
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}
