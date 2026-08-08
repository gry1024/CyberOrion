// 知识图谱 tab: FastGPT 风格知识库浏览器
// 左侧数据集列表（按类型分组）+ 右侧文档表格 + 顶部搜索 + 详情抽屉
// 展示所有知识库文本内容：ATT&CK / CVE 0day / 监管法规 / 恶意软件 / 组织 / 缓解 / 沙箱

import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { KbDoc, KbListResponse, KbStats, KbSearchHit } from '../types'
import { FadeIn } from './FadeIn'

// 数据集定义（按 type 分组，FastGPT 风格的左侧知识库列表）
const DATASETS: Array<{ key: string; label: string; icon: string; desc: string }> = [
  { key: 'technique', label: 'ATT&CK 技术库', icon: 'TA', desc: 'MITRE ATT&CK 攻击技术' },
  { key: 'cve', label: '0day 漏洞库', icon: 'CV', desc: 'NVD 高危漏洞 (CVSS≥7.0)' },
  { key: 'regulation', label: '监管法规库', icon: 'RG', desc: '国内网络安全法律法规' },
  { key: 'software', label: '恶意软件库', icon: 'MW', desc: 'Malpedia 恶意软件家族' },
  { key: 'group', label: '威胁组织库', icon: 'GP', desc: 'APT 组织档案' },
  { key: 'mitigation', label: '缓解措施库', icon: 'MT', desc: 'ATT&CK 缓解策略' },
  { key: 'sandbox_report', label: '沙箱指南库', icon: 'SB', desc: '沙箱分析参考' },
]

const TYPE_LABEL: Record<string, string> = {
  technique: 'ATT&CK 技术',
  software: '恶意软件',
  group: '威胁组织',
  mitigation: '缓解措施',
  malware: '恶意软件',
  sandbox_report: '沙箱指南',
  regulation: '监管法规',
  cve: 'CVE 漏洞',
}

function typeLabel(t: string): string {
  return TYPE_LABEL[t] ?? t
}

// ---------------------------------------------------------------------------
// 自动更新状态栏（精简版）
// ---------------------------------------------------------------------------
interface AutoUpdateStatus {
  daemon_running: boolean
  last_run: {
    started_at: string
    cve_fetched: number
    regulation_fetched: number
    added: number
    elapsed_sec: number
    errors: string[]
  } | null
}

function AutoUpdateBar({ status, onRefresh }: {
  status: AutoUpdateStatus | null
  onRefresh: () => void
}) {
  const [updating, setUpdating] = useState(false)
  const lastRun = status?.last_run
  const lastTime = lastRun?.started_at
    ? new Date(lastRun.started_at).toLocaleString('zh-CN', { hour12: false })
    : null

  const handleManualUpdate = () => {
    setUpdating(true)
    api.triggerKbUpdate().finally(() => {
      setUpdating(false)
      onRefresh()
    })
  }

  return (
    <div className="flex flex-none items-center gap-3 px-1 py-2 text-[11px]">
      <span className="flex items-center gap-1.5">
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{
            background: status?.daemon_running ? '#34c759' : 'var(--color-fg-4)',
            boxShadow: status?.daemon_running ? '0 0 6px rgba(52,199,89,0.5)' : 'none',
          }}
        />
        <span className="text-text-2">
          {status?.daemon_running ? '自动更新守护进程运行中' : '守护进程未运行'}
        </span>
      </span>
      {lastTime && (
        <span className="text-text-3">
          上次更新: {lastTime}
          {lastRun && lastRun.added > 0 && (
            <span className="ml-1 text-text-2">
              新增 {lastRun.cve_fetched} CVE + {lastRun.regulation_fetched} 监管 → +{lastRun.added}
            </span>
          )}
        </span>
      )}
      <button
        onClick={handleManualUpdate}
        disabled={updating}
        className="ml-auto rounded border border-hairline bg-overlay px-2.5 py-0.5 text-[10px] text-text-2 transition-colors hover:bg-hover hover:text-text-1 disabled:opacity-50"
      >
        {updating ? '更新中...' : '手动更新'}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// 文档详情抽屉（展示完整文本内容）
// ---------------------------------------------------------------------------
function DocDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [doc, setDoc] = useState<KbDoc | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setDoc(null)
    setError('')
    api
      .getKbDoc(id)
      .then((d) => setDoc(d as KbDoc))
      .catch(() => setError('文档读取失败 — 后端可能尚未实现 /api/kb/doc'))
  }, [id])

  // 将 doc 的所有字段渲染为可读文本
  const renderDocContent = (doc: any) => {
    const sections: Array<{ title: string; content: string }> = []
    if (doc.description) sections.push({ title: '描述', content: String(doc.description) })
    if (doc.detection) sections.push({ title: '检测要点', content: String(doc.detection) })
    if (doc.mitigations && (doc.mitigations as Array<{ id: string; name: string }>).length > 0) {
      sections.push({
        title: '缓解措施',
        content: (doc.mitigations as Array<{ id: string; name: string }>).map((m) => `- ${m.name} (${m.id})`).join('\n'),
      })
    }
    if (doc.cvss) sections.push({ title: 'CVSS 评分', content: String(doc.cvss) })
    if (doc.attack_vector) sections.push({ title: '攻击向量', content: String(doc.attack_vector) })
    if (doc.cwe && (doc.cwe as string[]).length > 0) sections.push({ title: 'CWE', content: (doc.cwe as string[]).join(', ') })
    if (doc.affected_products && (doc.affected_products as string[]).length > 0) {
      sections.push({ title: '受影响产品', content: (doc.affected_products as string[]).join(', ') })
    }
    if (doc.key_articles) sections.push({ title: '关键条款', content: String(doc.key_articles) })
    if (doc.issuer) sections.push({ title: '颁布机构', content: String(doc.issuer) })
    if (doc.effective_date) sections.push({ title: '生效日期', content: String(doc.effective_date) })
    if (doc.url) sections.push({ title: '来源链接', content: String(doc.url) })
    if (doc.text) sections.push({ title: '完整文本', content: String(doc.text) })

    return sections
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/25" onClick={onClose}>
      <aside
        className="scroll-thin flex h-full w-[640px] flex-none flex-col gap-4 overflow-y-auto border-l border-hairline bg-bg p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="font-mono text-[10px] text-text-3">{id}</div>
            <div className="mt-1 text-[16px] font-semibold text-text-1">
              {doc?.name ?? '加载中…'}
            </div>
          </div>
          <button
            onClick={onClose}
            className="ml-auto flex-none rounded bg-overlay px-3 py-1 text-[11px] text-text-3 transition-colors hover:bg-hover hover:text-text-1"
          >
            关闭
          </button>
        </div>

        {error && <div className="text-[11px] text-attacker">{error}</div>}

        {doc && (
          <>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="rounded border border-hairline px-2 py-px text-[10px] text-text-2">
                {typeLabel((doc as any).type)}
              </span>
              {((doc as any).tactics as string[] | undefined)?.map((t: string) => (
                <span key={t} className="rounded bg-overlay px-2 py-px font-mono text-[10px] text-text-3">
                  {t}
                </span>
              ))}
              {((doc as any).cvss) != null && (
                <span className="rounded bg-red-50 px-2 py-px font-mono text-[10px] text-attacker">
                  CVSS {(doc as any).cvss}
                </span>
              )}
            </div>

            {renderDocContent(doc).map((s, i) => (
              <section key={i}>
                <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-text-3">
                  {s.title}
                </div>
                {s.title === '完整文本' || s.title === '关键条款' || s.title === '描述' ? (
                  <div className="whitespace-pre-wrap break-words text-[12px] leading-[1.75] text-fg">
                    {s.content}
                  </div>
                ) : (
                  <div className="text-[12px] leading-[1.7] text-text-2">{s.content}</div>
                )}
              </section>
            ))}
          </>
        )}
      </aside>
    </div>
  )
}

// ---------------------------------------------------------------------------
// 主视图：FastGPT 风格知识库浏览器
// ---------------------------------------------------------------------------
export function KnowledgeView() {
  const [stats, setStats] = useState<KbStats | null>(null)
  const [auStatus, setAuStatus] = useState<AutoUpdateStatus | null>(null)
  const [activeType, setActiveType] = useState<string>('technique')
  const [list, setList] = useState<KbListResponse | null>(null)
  const [searchQ, setSearchQ] = useState('')
  const [searchHits, setSearchHits] = useState<KbSearchHit[]>([])
  const [searchMode, setSearchMode] = useState(false)
  const [docId, setDocId] = useState<string | null>(null)
  const [page, setPage] = useState(0)
  const pageSize = 50

  const fetchAuStatus = useCallback(() => {
    api.getKbAutoUpdateStatus().then(setAuStatus).catch(() => {})
  }, [])

  const fetchList = useCallback((type: string, p: number) => {
    api
      .getKbList({ type, offset: p * pageSize, limit: pageSize })
      .then(setList)
      .catch(() => setList(null))
  }, [])

  useEffect(() => {
    api.getKbStats().then(setStats).catch(() => setStats(null))
    fetchAuStatus()
    fetchList(activeType, 0)
    const timer = setInterval(fetchAuStatus, 60000)
    return () => clearInterval(timer)
  }, [fetchAuStatus, fetchList, activeType])

  const handleSelectDataset = (type: string) => {
    setActiveType(type)
    setSearchMode(false)
    setSearchQ('')
    setPage(0)
    fetchList(type, 0)
  }

  const handlePage = (newPage: number) => {
    setPage(newPage)
    fetchList(activeType, newPage)
  }

  const handleSearch = () => {
    const q = searchQ.trim()
    if (!q) {
      setSearchMode(false)
      fetchList(activeType, page)
      return
    }
    setSearchMode(true)
    api.kbSearch(q, 20).then(setSearchHits).catch(() => setSearchHits([]))
  }

  const activeDataset = DATASETS.find((d) => d.key === activeType)

  return (
    <main className="flex min-h-0 flex-1 flex-col overflow-hidden px-5 pb-4">
      {/* 标题栏 */}
      <div className="flex flex-none items-baseline gap-4 px-1 pt-1">
        <h1 className="text-[13px] font-semibold text-fg">知识图谱</h1>
        <span className="eyebrow">攻击知识，尽收眼底</span>
        <span className="ml-auto text-[11px] text-text-3">
          共 {stats?.total.toLocaleString() ?? '—'} 篇文档
        </span>
      </div>

      {/* 自动更新状态栏 */}
      <FadeIn className="flex-none">
        <AutoUpdateBar status={auStatus} onRefresh={fetchAuStatus} />
      </FadeIn>

      {/* 搜索栏 */}
      <FadeIn delay={0.04} className="flex-none">
        <div className="flex items-center gap-2 px-1 py-2">
          <input
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="搜索全部知识库（ATT&CK / CVE / 监管法规 / 恶意软件…）"
            className="min-w-0 flex-1 rounded border border-hairline bg-panel px-3 py-1.5 text-[12px] text-fg outline-none transition-colors placeholder:text-text-3 focus:border-line-3"
          />
          <button
            onClick={handleSearch}
            className="btn-pill btn-primary flex-none px-4! py-1.5!"
          >
            搜索
          </button>
          {searchMode && (
            <button
              onClick={() => {
                setSearchMode(false)
                setSearchQ('')
                fetchList(activeType, page)
              }}
              className="btn-pill flex-none border border-hairline px-3 py-1.5 text-[11px] text-text-2 hover:bg-hover"
            >
              返回列表
            </button>
          )}
        </div>
      </FadeIn>

      {/* 主体：左侧数据集 + 右侧文档表格 */}
      <FadeIn delay={0.08} className="flex min-h-0 flex-1 gap-4 overflow-hidden pt-1">
        {/* 左侧：数据集列表（FastGPT 风格） */}
        <aside className="flex w-[220px] flex-none flex-col gap-1 overflow-y-auto">
          <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-widest text-text-3">
            数据集
          </div>
          {DATASETS.map((ds) => {
            const count = stats?.by_type?.[ds.key] ?? 0
            const active = activeType === ds.key && !searchMode
            return (
              <button
                key={ds.key}
                onClick={() => handleSelectDataset(ds.key)}
                className={`flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors ${
                  active ? 'bg-overlay' : 'hover:bg-overlay/50'
                }`}
              >
                <span
                  className={`flex h-7 w-7 flex-none items-center justify-center rounded-md text-[10px] font-bold ${
                    active ? 'bg-ink text-bg' : 'bg-overlay text-text-2'
                  }`}
                >
                  {ds.icon}
                </span>
                <span className="min-w-0 flex-1">
                  <span className={`block truncate text-[12px] ${active ? 'font-semibold text-text-1' : 'text-text-2'}`}>
                    {ds.label}
                  </span>
                  <span className="block truncate text-[10px] text-text-3">
                    {count > 0 ? `${count.toLocaleString()} 篇` : ds.desc}
                  </span>
                </span>
              </button>
            )
          })}
        </aside>

        {/* 右侧：文档表格 / 搜索结果 */}
        <section className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-lg border border-hairline">
          {/* 表头 */}
          <header className="flex flex-none items-center gap-3 border-b border-hairline px-4 py-2.5">
            <span className="text-[12px] font-semibold text-text-1">
              {searchMode ? `搜索结果（${searchHits.length} 条）` : activeDataset?.label}
            </span>
            {!searchMode && (
              <span className="text-[10px] text-text-3">
                {activeDataset?.desc}
              </span>
            )}
            {!searchMode && list && (
              <span className="ml-auto text-[10px] text-text-3">
                第 {page * pageSize + 1}-{Math.min((page + 1) * pageSize, list.total)} 条 / 共 {list.total} 条
              </span>
            )}
          </header>

          {/* 内容区 */}
          <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
            {searchMode ? (
              /* 搜索结果列表 */
              <div className="divide-y divide-hairline">
                {searchHits.map((h) => (
                  <button
                    key={h.id}
                    onClick={() => setDocId(h.id)}
                    className="flex w-full flex-col gap-1 px-4 py-2.5 text-left transition-colors hover:bg-overlay"
                  >
                    <div className="flex items-center gap-2">
                      <span className="flex-none rounded border border-hairline px-1.5 py-px text-[9px] text-text-3">
                        {typeLabel(h.type)}
                      </span>
                      <span className="truncate text-[12px] font-medium text-text-1">{h.name}</span>
                      <span className="ml-auto flex-none font-mono text-[9px] text-text-3">{h.score.toFixed(3)}</span>
                    </div>
                    <span className="line-clamp-1 text-[10px] text-text-3">{h.excerpt}</span>
                  </button>
                ))}
                {searchHits.length === 0 && (
                  <div className="py-16 text-center text-[11px] text-text-3">无搜索结果</div>
                )}
              </div>
            ) : list && list.items.length > 0 ? (
              /* 文档表格 */
              <div className="divide-y divide-hairline">
                {/* 表头行 */}
                <div className="flex items-center gap-3 px-4 py-1.5 text-[10px] font-medium uppercase tracking-wider text-text-3">
                  <span className="w-[40%]">名称</span>
                  <span className="w-[15%]">ID</span>
                  <span className="w-[20%]">来源</span>
                  <span className="w-[15%]">更新时间</span>
                  <span className="w-[10%] text-right">详情</span>
                </div>
                {list.items.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setDocId(item.id)}
                    className="flex w-full items-center gap-3 px-4 py-2 text-left transition-colors hover:bg-overlay"
                  >
                    <span className="w-[40%] min-w-0">
                      <span className="block truncate text-[12px] text-text-1">{item.name}</span>
                      <span className="block truncate text-[10px] text-text-3">{item.text_preview}</span>
                    </span>
                    <span className="w-[15%] truncate font-mono text-[10px] text-text-2">{item.id}</span>
                    <span className="w-[20%] truncate text-[10px] text-text-3">{item.source || '—'}</span>
                    <span className="w-[15%] truncate text-[10px] text-text-3">
                      {item.updated ? new Date(item.updated).toLocaleDateString('zh-CN') : item.published || '—'}
                    </span>
                    <span className="w-[10%] text-right text-[10px] text-text-2">查看 →</span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="py-16 text-center text-[11px] text-text-3">
                {list ? '该数据集暂无文档' : '加载中…'}
              </div>
            )}
          </div>

          {/* 分页 */}
          {!searchMode && list && list.total > pageSize && (
            <footer className="flex flex-none items-center justify-center gap-2 border-t border-hairline px-4 py-2">
              <button
                onClick={() => handlePage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="rounded border border-hairline px-3 py-0.5 text-[10px] text-text-2 transition-colors hover:bg-hover disabled:opacity-30"
              >
                上一页
              </button>
              <span className="text-[10px] text-text-3">
                {page + 1} / {Math.ceil(list.total / pageSize)}
              </span>
              <button
                onClick={() => handlePage(page + 1)}
                disabled={(page + 1) * pageSize >= list.total}
                className="rounded border border-hairline px-3 py-0.5 text-[10px] text-text-2 transition-colors hover:bg-hover disabled:opacity-30"
              >
                下一页
              </button>
            </footer>
          )}
        </section>
      </FadeIn>

      {/* 文档详情抽屉 */}
      {docId && <DocDrawer id={docId} onClose={() => setDocId(null)} />}
    </main>
  )
}