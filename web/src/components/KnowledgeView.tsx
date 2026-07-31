// 知识图谱 tab: 蓝方知识底蕴 — stats strip (总文档数 / 分类型 chips / 检索
// 模式), left search column (semantic search over the KB), main ATT&CK
// tactic×technique matrix (MITRE Navigator style, monochrome), and a shared
// doc detail drawer used by both search hits and matrix cells.
// All endpoints fail soft: 404/empty render empty states, never crash.

import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { KbDoc, KbSearchHit, KbStats, KbTactic } from '../types'
import { KbGraph } from './KbGraph'

const TYPE_META: Record<string, string> = {
  technique: 'ATT&CK 技术',
  software: '软件',
  group: '组织',
  mitigation: '缓解',
  malware: '恶意软件',
  sandbox_report: '沙箱指南',
}

function typeLabel(t: string): string {
  return TYPE_META[t] ?? t
}

// ---------------------------------------------------------------------------
// doc detail drawer (shared by search results and matrix cells)
// ---------------------------------------------------------------------------

function DocDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [doc, setDoc] = useState<KbDoc | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setDoc(null)
    setError('')
    api
      .getKbDoc(id)
      .then(setDoc)
      .catch(() => setError('文档读取失败 — 后端可能尚未实现 /api/kb/doc'))
  }, [id])

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onClick={onClose}>
      <aside
        className="glass scroll-thin flex h-full w-[560px] flex-none flex-col gap-4 overflow-y-auto border-l border-hairline p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-3">
          <div className="min-w-0">
            <div className="font-mono text-[10px] text-text-2">{id}</div>
            <div className="mt-0.5 text-[15px] font-semibold text-text-1">
              {doc?.name ?? '加载中…'}
            </div>
          </div>
          <button
            onClick={onClose}
            className="ml-auto flex-none rounded-full bg-overlay px-3 py-1 text-[10px] text-neutral-400 transition-colors hover:bg-hover hover:text-neutral-200"
          >
            关闭 ✕
          </button>
        </div>

        {error && <div className="text-[11px] text-attacker">{error}</div>}

        {doc && (
          <>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="rounded-full border border-hairline px-2 py-px text-[10px] text-neutral-300">
                {typeLabel(doc.type)}
              </span>
              {(doc.tactics ?? []).map((t) => (
                <span
                  key={t}
                  className="rounded-full bg-overlay px-2 py-px font-mono text-[10px] text-text-2"
                >
                  {t}
                </span>
              ))}
            </div>

            {doc.mitigations && doc.mitigations.length > 0 && (
              <section>
                <div className="mb-1.5 text-[10px] uppercase tracking-widest text-text-2">
                  缓解措施
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {doc.mitigations.map((m) => (
                    <span
                      key={m.id}
                      className="rounded border border-success/30 px-2 py-0.5 text-[10px] text-success/90"
                      title={m.id}
                    >
                      {m.name}
                    </span>
                  ))}
                </div>
              </section>
            )}

            <section>
              <div className="mb-1.5 text-[10px] uppercase tracking-widest text-text-2">
                正文
              </div>
              <div className="whitespace-pre-wrap break-words rounded-xl border border-hairline bg-ink p-4 text-[12px] leading-[1.7] text-[#d1d1d6]">
                {doc.text}
              </div>
            </section>
          </>
        )}
      </aside>
    </div>
  )
}

// ---------------------------------------------------------------------------
// stats strip
// ---------------------------------------------------------------------------

function StatsStrip({ stats }: { stats: KbStats | null }) {
  if (!stats) {
    return (
      <div className="panel flex-none px-5 py-4 text-[11px] text-neutral-600">
        知识库统计不可用 — 后端 /api/kb/stats 未就绪
      </div>
    )
  }
  return (
    <div className="panel flex flex-none flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
      <div>
        <div className="font-mono text-3xl font-semibold tabular-nums text-text-1">
          {stats.total.toLocaleString()}
        </div>
        <div className="text-[9px] uppercase tracking-[0.2em] text-text-2">
          知识库文档
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(stats.by_type).map(([t, n]) => (
          <span
            key={t}
            className="rounded-full border border-hairline px-2.5 py-0.5 text-[10px] text-neutral-300"
          >
            {typeLabel(t)}{' '}
            <span className="font-mono tabular-nums text-text-1">{n}</span>
          </span>
        ))}
      </div>
      <div className="ml-auto flex items-center gap-2 text-[10px] text-text-2">
        检索模式
        <span className="rounded-full bg-overlay px-2.5 py-0.5 font-medium text-neutral-200">
          {stats.embedding ? 'embedding 向量' : 'BM25'}
        </span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// search column
// ---------------------------------------------------------------------------

function SearchColumn({ onOpen }: { onOpen: (id: string) => void }) {
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<KbSearchHit[]>([])
  const [searched, setSearched] = useState(false)
  const [busy, setBusy] = useState(false)

  const run = useCallback(() => {
    const query = q.trim()
    if (!query) return
    setBusy(true)
    api
      .kbSearch(query)
      .then((r) => {
        setHits(r)
        setSearched(true)
      })
      .catch(() => {
        setHits([])
        setSearched(true)
      })
      .finally(() => setBusy(false))
  }, [q])

  const maxScore = Math.max(...hits.map((h) => h.score), 0.001)

  return (
    <aside className="panel flex w-[340px] flex-none flex-col overflow-hidden">
      <header className="panel-title">
        <span>知识检索</span>
      </header>
      <div className="flex flex-none gap-2 border-b border-hairline p-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && run()}
          placeholder="搜索 ATT&CK / 恶意软件 / 组织…"
          className="min-w-0 flex-1 rounded-lg border border-hairline bg-ink px-3 py-1.5 text-[12px] text-neutral-200 outline-none transition-colors placeholder:text-text-3 focus:border-neutral-600"
        />
        <button
          onClick={run}
          disabled={busy || !q.trim()}
          className="btn-pill btn-primary flex-none !px-3.5 !py-1.5"
        >
          {busy ? '…' : '检索'}
        </button>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">
        {hits.map((h) => (
          <button
            key={h.id}
            onClick={() => onOpen(h.id)}
            className="mb-1.5 flex w-full flex-col gap-1 rounded-lg border border-hairline bg-raised px-3 py-2 text-left transition-colors hover:border-[#48484a]"
          >
            <div className="flex w-full items-center gap-2">
              <span className="flex-none rounded border border-hairline px-1.5 py-px text-[9px] text-text-2">
                {typeLabel(h.type)}
              </span>
              <span className="truncate text-[12px] font-medium text-text-1">
                {h.name}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-0.5 flex-1 overflow-hidden rounded-full bg-overlay">
                <div
                  className="h-full rounded-full bg-[#86868b]"
                  style={{ width: `${Math.min((h.score / maxScore) * 100, 100)}%` }}
                />
              </div>
              <span className="flex-none font-mono text-[9px] tabular-nums text-text-3">
                {h.score.toFixed(3)}
              </span>
            </div>
            <div className="line-clamp-2 text-[10px] leading-4 text-[#86868b]">
              {h.excerpt}
            </div>
          </button>
        ))}
        {searched && hits.length === 0 && (
          <div className="py-12 text-center text-[11px] text-neutral-600">
            无结果（或检索服务未就绪）
          </div>
        )}
        {!searched && (
          <div className="py-12 text-center text-[11px] text-neutral-600">
            输入关键词，回车检索蓝方知识库
          </div>
        )}
      </div>
    </aside>
  )
}

// ---------------------------------------------------------------------------
// ATT&CK matrix
// ---------------------------------------------------------------------------

function Matrix({
  tactics,
  onOpen,
}: {
  tactics: KbTactic[]
  onOpen: (id: string) => void
}) {
  if (tactics.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-[11px] text-neutral-600">
        ATT&CK 矩阵不可用 — 后端 /api/kb/tactics 未就绪
      </div>
    )
  }
  return (
    <div className="scroll-thin min-h-0 flex-1 overflow-auto">
      <div className="flex min-w-max gap-px bg-hairline p-px">
        {tactics.map((t) => (
          <div key={t.tactic} className="flex w-[168px] flex-none flex-col gap-px">
            {/* column header */}
            <div className="flex-none bg-white/[0.04] px-2.5 py-2" title={t.tactic}>
              <div className="truncate text-[11px] font-semibold text-text-1">
                {t.name_cn || t.tactic}
              </div>
              <div className="mt-0.5 flex items-baseline justify-between">
                <span className="truncate font-mono text-[8px] uppercase tracking-wider text-text-3">
                  {t.tactic}
                </span>
                <span className="font-mono text-[9px] tabular-nums text-text-2">
                  {t.count}
                </span>
              </div>
            </div>
            {/* technique cells */}
            {t.techniques.map((tech) => (
              <button
                key={tech.id}
                title={`${tech.id} · ${tech.name}`}
                onClick={() => onOpen(tech.id)}
                className="flex flex-col gap-0.5 bg-white/[0.03] px-2.5 py-1.5 text-left transition-colors hover:bg-white/[0.07]"
              >
                <span className="font-mono text-[9px] text-text-2">{tech.id}</span>
                <span className="line-clamp-2 text-[10px] leading-[1.35] text-[#d1d1d6]">
                  {tech.name}
                </span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// view
// ---------------------------------------------------------------------------

export function KnowledgeView() {
  const [stats, setStats] = useState<KbStats | null>(null)
  const [tactics, setTactics] = useState<KbTactic[]>([])
  const [docId, setDocId] = useState<string | null>(null)
  const [mode, setMode] = useState<'graph' | 'matrix'>('graph')

  useEffect(() => {
    api
      .getKbStats()
      .then(setStats)
      .catch(() => setStats(null))
    api
      .getKbTactics()
      .then(setTactics)
      .catch(() => setTactics([]))
  }, [])

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 overflow-hidden p-5">
      <div className="flex flex-none items-baseline gap-3">
        <h1 className="text-[17px] font-semibold text-text-1">知识图谱</h1>
        <span className="font-serif text-[13px] italic text-accent/80">
          attack knowledge, mapped
        </span>
        <span className="text-[11px] text-text-2">
          蓝方知识底蕴 · ATT&CK + Malpedia + 沙箱指南
        </span>
      </div>
      <StatsStrip stats={stats} />
      <div className="flex min-h-0 flex-1 gap-4 overflow-hidden">
        <SearchColumn onOpen={setDocId} />
        <section className="panel relative flex min-w-0 flex-1 flex-col overflow-hidden">
          <header className="panel-title">
            <span>{mode === 'graph' ? 'ATT&CK 网络' : 'ATT&CK 矩阵'}</span>
            {/* 图谱 / 矩阵 切换 */}
            <div className="ml-2 flex items-center rounded-full border border-hairline bg-white/[0.03] p-0.5 normal-case">
              {(
                [
                  ['graph', '图谱'],
                  ['matrix', '矩阵'],
                ] as const
              ).map(([k, label]) => (
                <button
                  key={k}
                  onClick={() => setMode(k)}
                  className={`rounded-full px-3 py-0.5 font-display text-[10px] font-bold tracking-wide transition-colors ${
                    mode === k
                      ? 'bg-white/5 text-accent'
                      : 'text-neutral-400 hover:text-neutral-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <span className="ml-auto font-mono text-[9px] normal-case tracking-normal text-text-3">
              {tactics.length} 战术 · {tactics.reduce((a, t) => a + t.count, 0)} 技术
            </span>
          </header>
          {mode === 'graph' ? (
            tactics.length === 0 ? (
              <div className="flex h-full items-center justify-center text-[11px] text-neutral-600">
                知识图谱不可用 — 后端 /api/kb/tactics 未就绪
              </div>
            ) : (
              <KbGraph tactics={tactics} onOpen={setDocId} />
            )
          ) : (
            <Matrix tactics={tactics} onOpen={setDocId} />
          )}
        </section>
      </div>
      {docId && <DocDrawer id={docId} onClose={() => setDocId(null)} />}
    </main>
  )
}
