// TrafficView — 流量分析视图（Cursor 式：平铺双栏，无卡片）
// -------------------------------------------------------------
// 左 40%：流量回放控制 + 事件流；
// 右 60%：告警统计 + 告警列表 + 蓝队 agent 分析输出。
// 独立组件，通过 REST 调用 /api/traffic/* 自管回放与分析，不依赖 ArenaView 运行状态。
import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { pushToast } from '../toasts'
import type { FlowAlert, FlowEvent, TrafficStatus } from '../types'

// severity -> 颜色：critical=红 / high=琥珀 / medium=青 / low=灰
function sevColor(sev: string): string {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'var(--color-red)'
  if (s === 'high') return 'var(--color-amber)'
  if (s === 'medium') return 'var(--color-cyan)'
  return 'var(--color-fg-3)'
}

// 时间戳 -> HH:MM:SS.mmm 短格式
function fmtTs(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number, l = 2) => String(n).padStart(l, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
}

export function TrafficView() {
  // ---- 服务状态 + 回放选项 ----
  const [status, setStatus] = useState<TrafficStatus | null>(null)
  const [source, setSource] = useState<string>('cicids')
  const [csvFile, setCsvFile] = useState<string>('')
  const [maxRows, setMaxRows] = useState<number>(200)

  // ---- 回放结果 ----
  const [events, setEvents] = useState<FlowEvent[]>([])
  const [alerts, setAlerts] = useState<FlowAlert[]>([])
  const [selectedEvent, setSelectedEvent] = useState<FlowEvent | null>(null)

  // ---- 加载状态 ----
  const [replaying, setReplaying] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState<string>('')

  // 挂载时拉取服务状态，预填可选数据源 / CSV 文件
  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.trafficStatus()
      setStatus(s)
      if (s.sources?.length && !s.sources.includes(source)) setSource(s.sources[0])
      if (s.csv_files?.length && !csvFile) setCsvFile(s.csv_files[0])
    } catch (e) {
      pushToast(`流量服务状态查询失败：${(e as Error).message}`, { side: 'system' })
    }
  }, [source, csvFile])

  useEffect(() => {
    void refreshStatus()
  }, [refreshStatus])

  // 启动流量回放
  const handleReplay = useCallback(async () => {
    setReplaying(true)
    setSelectedEvent(null)
    try {
      const res = await api.trafficReplay({
        source,
        csv_file: csvFile || undefined,
        max_rows: maxRows,
      })
      if (res.ok) {
        setEvents(res.events ?? [])
        setAlerts(res.alerts ?? [])
        pushToast(`回放完成：${res.events?.length ?? 0} 事件 / ${res.alerts?.length ?? 0} 告警`, {
          side: 'blue',
          title: '流量回放',
        })
      } else {
        pushToast(`回放失败：${res.error ?? '未知错误'}`, { side: 'system' })
      }
    } catch (e) {
      pushToast(`回放异常：${(e as Error).message}`, { side: 'system' })
    } finally {
      setReplaying(false)
    }
  }, [source, csvFile, maxRows])

  // 调用蓝队 agent 分析当前流量窗口
  const handleAnalyze = useCallback(async () => {
    setAnalyzing(true)
    setAnalysis('')
    try {
      const res = await api.trafficAnalyze({
        source,
        csv_file: csvFile || undefined,
        max_rows: maxRows,
        events_count: events.length,
        alerts_count: alerts.length,
      })
      if (res.ok) {
        setAnalysis(res.output ?? '(空输出)')
      } else {
        pushToast(`分析失败：${res.error ?? '未知错误'}`, { side: 'system' })
      }
    } catch (e) {
      pushToast(`分析异常：${(e as Error).message}`, { side: 'system' })
    } finally {
      setAnalyzing(false)
    }
  }, [source, csvFile, maxRows, events.length, alerts.length])

  // 告警按严重级别统计
  const sevStats = useMemo(() => {
    const m: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const a of alerts) {
      const s = (a.severity || 'low').toLowerCase()
      m[s] = (m[s] ?? 0) + 1
    }
    return m
  }, [alerts])

  const ready = status?.ready ?? false

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* 标题行（同 ArenaView 风格） */}
      <div
        className="flex flex-none items-center gap-2 border-b px-3 py-1.5"
        style={{ borderColor: 'var(--color-hairline)' }}
      >
        <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
          流量分析
        </span>
        <span className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
          CICIDS 回放 · 蓝队研判
        </span>
        <span className="ml-auto font-mono text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
          {events.length} 事件 / {alerts.length} 告警
        </span>
      </div>

      {/* 双栏：左 40% 流量回放 + 事件流；右 60% 告警 + 分析 */}
      <div className="flex min-h-0 flex-1">
        {/* ===== 左栏：回放控制 + 事件流 ===== */}
        <div className="flex min-w-0 flex-col" style={{ flex: '0 0 40%', minHeight: 0 }}>
          {/* 回放控制条 */}
          <div
            className="flex flex-none flex-wrap items-center gap-2 border-b px-3 py-2"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="btn"
              style={{ height: 22, padding: '0 6px', fontSize: 11 }}
              title="数据源"
            >
              {(status?.sources ?? ['cicids', 'synthetic']).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <select
              value={csvFile}
              onChange={(e) => setCsvFile(e.target.value)}
              className="btn"
              style={{ height: 22, padding: '0 6px', fontSize: 11, maxWidth: 160 }}
              title="CSV 文件"
            >
              {(status?.csv_files ?? []).map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1 text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
              行数
              <input
                type="number"
                value={maxRows}
                min={10}
                max={5000}
                onChange={(e) => setMaxRows(Number(e.target.value) || 200)}
                className="btn"
                style={{ height: 22, width: 60, padding: '0 4px', fontSize: 11 }}
              />
            </label>
            <button
              className="btn btn-primary"
              onClick={handleReplay}
              disabled={replaying || !ready}
              style={{ height: 22, fontSize: 11 }}
            >
              {replaying ? '回放中…' : '▶ 回放'}
            </button>
          </div>

          {/* 事件流标题 */}
          <div
            className="flex flex-none items-center gap-2 border-b px-3 py-1"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <span className="text-[11px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
              流量事件
            </span>
            <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
              {events.length}
            </span>
          </div>

          {/* 事件列表 */}
          <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
            {events.length === 0 ? (
              <div className="px-3 py-6 text-center text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
                点击「▶ 回放」开始流量回放
              </div>
            ) : (
              events.map((ev, i) => {
                const selected = selectedEvent === ev
                return (
                  <button
                    key={i}
                    onClick={() => setSelectedEvent(selected ? null : ev)}
                    className="flex w-full items-center gap-2 border-b px-3 py-1 text-left"
                    style={{
                      borderColor: 'var(--color-hairline)',
                      background: selected ? 'var(--color-overlay)' : 'transparent',
                    }}
                  >
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
                      {fmtTs(ev.ts)}
                    </span>
                    <span className="font-mono text-[10.5px]" style={{ color: 'var(--color-cyan)' }}>
                      {ev.src_ip}
                    </span>
                    <span className="text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
                      →
                    </span>
                    <span className="font-mono text-[10.5px]" style={{ color: 'var(--color-amber)' }}>
                      {ev.dst_ip}:{ev.dst_port}
                    </span>
                    <span className="ml-auto truncate text-[10.5px]" style={{ color: 'var(--color-fg-2)' }}>
                      {ev.label}
                    </span>
                  </button>
                )
              })
            )}
          </div>

          {/* 选中事件详情 */}
          {selectedEvent && (
            <div
              className="flex-none border-t px-3 py-2"
              style={{ borderColor: 'var(--color-hairline)', background: 'var(--color-bg-2)' }}
            >
              <div className="mb-1 text-[10.5px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
                事件详情
              </div>
              <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 font-mono text-[10.5px]">
                <span style={{ color: 'var(--color-fg-4)' }}>src</span>
                <span style={{ color: 'var(--color-cyan)' }}>{selectedEvent.src_ip}</span>
                <span style={{ color: 'var(--color-fg-4)' }}>dst</span>
                <span style={{ color: 'var(--color-amber)' }}>
                  {selectedEvent.dst_ip}:{selectedEvent.dst_port}
                </span>
                <span style={{ color: 'var(--color-fg-4)' }}>label</span>
                <span style={{ color: 'var(--color-fg)' }}>{selectedEvent.label}</span>
                <span style={{ color: 'var(--color-fg-4)' }}>technique</span>
                <span style={{ color: 'var(--color-purple)' }}>{selectedEvent.technique}</span>
                <span style={{ color: 'var(--color-fg-4)' }}>attack_type</span>
                <span style={{ color: 'var(--color-red)' }}>{selectedEvent.attack_type}</span>
              </div>
            </div>
          )}
        </div>

        {/* 1px 分隔线 */}
        <div className="w-px flex-none" style={{ background: 'var(--color-hairline)' }} />

        {/* ===== 右栏：告警统计 + 告警列表 + 分析输出 ===== */}
        <div className="flex min-w-0 flex-1 flex-col" style={{ minHeight: 0 }}>
          {/* 告警统计条 */}
          <div
            className="flex flex-none items-center gap-4 border-b px-3 py-1.5"
            style={{ borderColor: 'var(--color-hairline)' }}
          >
            <span className="text-[11px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
              检测告警
            </span>
            <span className="flex items-center gap-1 text-[10.5px]">
              <span style={{ color: 'var(--color-red)' }}>●</span>
              <span style={{ color: 'var(--color-fg-3)' }}>critical</span>
              <span className="font-mono" style={{ color: 'var(--color-fg)' }}>
                {sevStats.critical}
              </span>
            </span>
            <span className="flex items-center gap-1 text-[10.5px]">
              <span style={{ color: 'var(--color-amber)' }}>●</span>
              <span style={{ color: 'var(--color-fg-3)' }}>high</span>
              <span className="font-mono" style={{ color: 'var(--color-fg)' }}>
                {sevStats.high}
              </span>
            </span>
            <span className="flex items-center gap-1 text-[10.5px]">
              <span style={{ color: 'var(--color-cyan)' }}>●</span>
              <span style={{ color: 'var(--color-fg-3)' }}>medium</span>
              <span className="font-mono" style={{ color: 'var(--color-fg)' }}>
                {sevStats.medium}
              </span>
            </span>
            <span className="flex items-center gap-1 text-[10.5px]">
              <span style={{ color: 'var(--color-fg-3)' }}>●</span>
              <span style={{ color: 'var(--color-fg-3)' }}>low</span>
              <span className="font-mono" style={{ color: 'var(--color-fg)' }}>
                {sevStats.low}
              </span>
            </span>
            <button
              className="btn btn-primary ml-auto"
              onClick={handleAnalyze}
              disabled={analyzing || events.length === 0}
              style={{ height: 22, fontSize: 11 }}
            >
              {analyzing ? '分析中…' : '⟳ agent 研判'}
            </button>
          </div>

          {/* 告警列表（上半） */}
          <div className="scroll-thin min-h-0 flex-1 overflow-y-auto" style={{ flex: '1 1 50%' }}>
            {alerts.length === 0 ? (
              <div className="px-3 py-6 text-center text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
                回放后此处显示触发的告警
              </div>
            ) : (
              alerts.map((al, i) => (
                <div
                  key={i}
                  className="border-b px-3 py-1.5"
                  style={{ borderColor: 'var(--color-hairline)' }}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
                      {fmtTs(al.ts)}
                    </span>
                    <span
                      className="rounded px-1.5 py-0 text-[9.5px] font-semibold uppercase"
                      style={{
                        color: sevColor(al.severity),
                        background: `color-mix(in srgb, ${sevColor(al.severity)} 14%, transparent)`,
                      }}
                    >
                      {al.severity}
                    </span>
                    <span className="text-[10.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
                      {al.alert_type}
                    </span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--color-purple)' }}>
                      {al.technique}
                    </span>
                    <span className="ml-auto font-mono text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
                      conf {(al.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 font-mono text-[10px]">
                    <span style={{ color: 'var(--color-cyan)' }}>{al.src_ip}</span>
                    <span style={{ color: 'var(--color-fg-4)' }}>→</span>
                    <span style={{ color: 'var(--color-amber)' }}>{al.dst_ip}</span>
                  </div>
                  <div className="mt-0.5 text-[10.5px]" style={{ color: 'var(--color-fg-2)' }}>
                    {al.description}
                  </div>
                  {al.evidence && (
                    <div className="mt-0.5 font-mono text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
                      ▸ {al.evidence}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {/* agent 分析输出（下半） */}
          <div
            className="flex flex-col border-t"
            style={{ borderColor: 'var(--color-hairline)', flex: '1 1 50%' }}
          >
            <div
              className="flex flex-none items-center gap-2 border-b px-3 py-1"
              style={{ borderColor: 'var(--color-hairline)' }}
            >
              <span className="text-[11px] font-semibold" style={{ color: 'var(--color-fg-2)' }}>
                蓝队 agent 研判
              </span>
              {analyzing && (
                <span className="live-pulse text-[10px]" style={{ color: 'var(--color-cyan)' }}>
                  ● 分析中
                </span>
              )}
            </div>
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-2">
              {analysis ? (
                <pre
                  className="whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed"
                  style={{ color: 'var(--color-fg)' }}
                >
                  {analysis}
                </pre>
              ) : (
                <div className="text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
                  点击「⟳ agent 研判」调用蓝队 agent 对当前流量窗口做分析。
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
