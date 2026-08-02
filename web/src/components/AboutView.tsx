// 文档 tab — GitHub-README 风格渲染 docs/FRAMEWORK.md（/api/about）：
// 居中单栏（max-w 860px）、Barlow 正文（.md-doc，无 serif 艺术字）、左侧
// 迷你目录（## 节锚点，点击滚动定位）。

import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { FadeIn } from './FadeIn'
import { MarkdownView } from './MarkdownView'

export function AboutView() {
  const [md, setMd] = useState<string | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .getAbout()
      .then((r) => setMd(r.markdown))
      .catch(() => setError('文档读取失败 — 后端可能未就绪'))
  }, [])

  // ## 节标题 → 迷你目录
  const toc = useMemo(() => {
    if (!md) return []
    return md
      .split('\n')
      .filter((l) => l.startsWith('## '))
      .map((l) => l.slice(3).trim())
  }, [md])

  const scrollTo = (title: string) => {
    const heads = document.querySelectorAll('.md-doc h2')
    for (const h of Array.from(heads)) {
      if (h.textContent?.trim() === title) {
        h.scrollIntoView({ behavior: 'smooth', block: 'start' })
        return
      }
    }
  }

  return (
    <main className="scroll-thin min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex max-w-[1100px] gap-8 px-6 pb-10 pt-8">
        {/* 迷你目录（宽屏时显示） */}
        {toc.length > 0 && (
          <nav className="sticky top-8 hidden h-fit w-[160px] flex-none flex-col gap-1.5 self-start min-[1500px]:flex">
            <span className="eyebrow mb-1 text-[9px]!">目录</span>
            {toc.map((t) => (
              <button
                key={t}
                onClick={() => scrollTo(t)}
                className="text-left text-[11px] leading-4 text-[var(--color-fg-4)] transition-colors hover:text-[var(--color-fg)]"
              >
                {t}
              </button>
            ))}
          </nav>
        )}
        <FadeIn className="min-w-0 max-w-[860px] flex-1">
          {error && <div className="text-[12px] text-attacker">{error}</div>}
          {!error && !md && (
            <div className="text-[12px] text-text-2">加载中…</div>
          )}
          {md && <MarkdownView markdown={md} className="md-doc" />}
        </FadeIn>
      </div>
    </main>
  )
}
