import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { api } from '../api'
import { pushToast } from '../toasts'
import type { CaiRecording, CaiRecordingSummary } from '../types'
import '@xterm/xterm/css/xterm.css'

const REPLAY_STORAGE_KEY = 'cyberorion:cai-replay-id'

function fmtDate(value: string): string {
  if (!value) return '--'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function fmtDuration(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '--'
  if (value < 60) return `${value.toFixed(1)}s`
  const minutes = Math.floor(value / 60)
  const seconds = Math.round(value % 60)
  return `${minutes}m ${seconds}s`
}

function requestReplay(id: string): void {
  window.localStorage.setItem(REPLAY_STORAGE_KEY, id)
  window.dispatchEvent(new CustomEvent('cai-replay-request', { detail: id }))
}

function openReport(id: string): void {
  window.open(api.getCaiReportURL(id), '_blank', 'noopener,noreferrer')
}

function RecordingCard({
  item,
  onDetail,
}: {
  item: CaiRecordingSummary
  onDetail: (id: string) => void
}) {
  return (
    <article className="cai-history-card">
      <div className="cai-history-card__main">
        <div className="cai-history-card__title">
          <span>{item.title || item.id}</span>
          <code>{item.source}</code>
        </div>
        <p>{item.summary || 'CAI terminal recording'}</p>
        <div className="cai-history-card__meta">
          <span>{fmtDate(item.created_at)}</span>
          <span>{item.kind}</span>
          <span>{item.status}</span>
          <span>{fmtDuration(item.duration_sec)}</span>
          <span>{item.frame_count} frames</span>
          {item.ctf_name && <span>{item.ctf_name}{item.challenge ? ` / ${item.challenge}` : ''}</span>}
        </div>
      </div>
      <div className="cai-history-card__actions">
        <button className="btn" onClick={() => onDetail(item.id)}>
          详情
        </button>
        <button className="btn" onClick={() => requestReplay(item.id)}>
          回放
        </button>
        <button
          className="btn"
          onClick={() => openReport(item.id)}
          disabled={!item.has_report}
          title={item.has_report ? '浏览最终 PDF 报告' : '该任务未生成 PDF 报告'}
        >
          报告
        </button>
      </div>
    </article>
  )
}

function StaticTerminalLog({ data }: { data: string }) {
  const hostRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!hostRef.current) return

    const term = new Terminal({
      convertEol: true,
      cursorBlink: false,
      disableStdin: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 11,
      lineHeight: 1.25,
      scrollback: Math.max(10000, data.split('\n').length + 1000),
      theme: {
        background: '#05080b',
        foreground: '#d6deeb',
        cursor: '#05080b',
        selectionBackground: '#264f78',
        black: '#000000',
        red: '#ff6b6b',
        green: '#48c78e',
        yellow: '#e7b955',
        blue: '#59a7ff',
        magenta: '#c4a7ff',
        cyan: '#5eead4',
        white: '#d6deeb',
        brightBlack: '#6b7280',
        brightRed: '#ff8787',
        brightGreen: '#69db7c',
        brightYellow: '#ffd43b',
        brightBlue: '#74c0fc',
        brightMagenta: '#d0bfff',
        brightCyan: '#99f6e4',
        brightWhite: '#ffffff',
      },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    fit.fit()
    term.write(data || 'No terminal output recorded.')

    const ro = new ResizeObserver(() => fit.fit())
    ro.observe(hostRef.current)
    return () => {
      ro.disconnect()
      term.dispose()
    }
  }, [data])

  return <div ref={hostRef} className="cai-detail-log" />
}

function DetailModal({
  recording,
  onClose,
}: {
  recording: CaiRecording
  onClose: () => void
}) {
  const fullLog = useMemo(
    () => recording.frames.map((frame) => frame.data).join(''),
    [recording.frames],
  )

  return (
    <div className="cai-detail-backdrop" onClick={onClose}>
      <section className="cai-detail-modal" onClick={(e) => e.stopPropagation()}>
        <header className="cai-detail-modal__header">
          <div>
            <h2>{recording.title || recording.id}</h2>
            <p>{recording.summary || '完整 CAI 终端输出记录'}</p>
          </div>
          <button className="btn" onClick={onClose}>关闭</button>
        </header>

        <div className="cai-detail-meta">
          <span>ID: {recording.id}</span>
          <span>Source: {recording.source}</span>
          <span>Kind: {recording.kind}</span>
          <span>Status: {recording.status}</span>
          <span>Started: {fmtDate(recording.created_at)}</span>
          <span>Duration: {fmtDuration(recording.duration_sec)}</span>
          {recording.exit_code !== undefined && <span>Exit: {recording.exit_code ?? 'n/a'}</span>}
          {recording.ctf_name && <span>CTF: {recording.ctf_name}</span>}
          {recording.challenge && <span>Challenge: {recording.challenge}</span>}
          <span>Frames: {recording.frames.length}</span>
        </div>

        <div className="cai-detail-actions">
          <button className="btn" onClick={() => requestReplay(recording.id)}>在终端回放</button>
        </div>

        <StaticTerminalLog data={fullLog} />
      </section>
    </div>
  )
}

export function HistoryView() {
  const [recordings, setRecordings] = useState<CaiRecordingSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState<CaiRecording | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    api.getCaiRecordings()
      .then((data) => setRecordings(data.recordings))
      .catch((e) => {
        setRecordings([])
        pushToast(`CAI 历史加载失败: ${e instanceof Error ? e.message : String(e)}`, { title: 'CAI 历史' })
      })
      .finally(() => setLoading(false))
  }, [])

  const openDetail = useCallback((id: string) => {
    setDetailLoading(true)
    api.getCaiRecording(id)
      .then(setDetail)
      .catch((e) => pushToast(`CAI 详情加载失败: ${e instanceof Error ? e.message : String(e)}`, { title: 'CAI 历史' }))
      .finally(() => setDetailLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return (
    <main className="cai-history">
      <header className="cai-history__header">
        <div>
          <h1>CAI 运行历史</h1>
          <p>这里记录 CAI 终端完整输出；每条记录支持回放和静态全量详情。</p>
        </div>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? '刷新中' : '刷新'}
        </button>
      </header>

      {detailLoading && <div className="cai-history__empty">详情加载中...</div>}

      <section className="cai-history__list">
        {recordings.length === 0 ? (
          <div className="cai-history__empty">
            暂无 CAI 记录。先在 CAI 终端运行一次，或使用 Demo Replay。
          </div>
        ) : (
          recordings.map((item) => <RecordingCard key={item.id} item={item} onDetail={openDetail} />)
        )}
      </section>

      {detail && <DetailModal recording={detail} onClose={() => setDetail(null)} />}
    </main>
  )
}
