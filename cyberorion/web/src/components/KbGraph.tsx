// 知识图谱网络视图（Part C）：Obsidian 风格的 tactic→technique 力导向图。
// - 节点：13 个战术（大，绿色）+ 其下技术（小，灰；has_detection 带细环）；
// - 边：technique → tactic；
// - 布局：手写力导向模拟（网格桶排斥 + 边弹簧 + 向心重力，rAF 驱动，
//   alpha 冷却后停止积分），canvas 渲染 —— 710 节点无 React 重渲染开销；
// - 交互：拖拽节点（拖动时固定）、悬停高亮邻居（其余淡出）、点击技术节点
//   打开 doc drawer、滚轮缩放（以光标为中心）、空白拖拽平移、搜索跳转高亮。

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { KbTactic } from '../types'
import { useTheme } from '../theme'

interface GNode {
  id: string
  kind: 'tactic' | 'tech'
  label: string
  ring: boolean
  x: number
  y: number
  vx: number
  vy: number
  fx: number | null
  fy: number | null
  r: number
  neighbors: number[]
}

interface GEdge {
  a: number
  b: number
}

interface Graph {
  nodes: GNode[]
  edges: GEdge[]
}

// 画布调色板：跟随明暗主题（canvas 不消费 CSS 变量，显式取值）。
function palette(theme: 'light' | 'dark') {
  return theme === 'dark'
    ? {
        accent: '#f5f5f5',
        edgeHot: 'rgba(255,255,255,0.45)',
        edgeNormal: 'rgba(255,255,255,0.10)',
        edgeDim: 'rgba(255,255,255,0.04)',
        tacticFill: 'rgba(255,255,255,0.10)',
        labelStrong: 'rgba(255,255,255,0.90)',
        labelWeak: 'rgba(255,255,255,0.55)',
        techHi: '#e0e0e0',
        techBase: '#9aa39e',
        ring: 'rgba(255,255,255,0.45)',
      }
    : {
        accent: '#111',
        edgeHot: 'rgba(0,0,0,0.10)',
        edgeNormal: 'rgba(0,0,0,0.03)',
        edgeDim: 'rgba(0,0,0,0.015)',
        tacticFill: 'rgba(0,0,0,0.06)',
        labelStrong: 'rgba(0,0,0,0.85)',
        labelWeak: 'rgba(0,0,0,0.55)',
        techHi: '#333',
        techBase: '#8a8a8a',
        ring: 'rgba(0,0,0,0.45)',
      }
}
const REP_RADIUS2 = 240 * 240

function buildGraph(tactics: KbTactic[]): Graph {
  const nodes: GNode[] = []
  const edges: GEdge[] = []
  const tacticIdx = new Map<string, number>()
  const techIdx = new Map<string, number>()

  // 战术节点：均匀摆在圆周上作为初始布局。
  const R = 340
  tactics.forEach((t, i) => {
    const ang = (i / Math.max(tactics.length, 1)) * Math.PI * 2
    tacticIdx.set(t.tactic, nodes.length)
    nodes.push({
      id: t.tactic,
      kind: 'tactic',
      label: t.name_cn || t.tactic,
      ring: false,
      x: Math.cos(ang) * R + (Math.random() - 0.5) * 30,
      y: Math.sin(ang) * R + (Math.random() - 0.5) * 30,
      vx: 0,
      vy: 0,
      fx: null,
      fy: null,
      r: 13,
      neighbors: [],
    })
  })

  // 技术节点（跨战术去重）：初始位置在其首个战术附近。
  tactics.forEach((t) => {
    const ti = tacticIdx.get(t.tactic)!
    const home = nodes[ti]
    for (const tech of t.techniques) {
      let ni = techIdx.get(tech.id)
      if (ni === undefined) {
        ni = nodes.length
        techIdx.set(tech.id, ni)
        nodes.push({
          id: tech.id,
          kind: 'tech',
          label: tech.name,
          ring: tech.has_detection,
          x: home.x + (Math.random() - 0.5) * 130,
          y: home.y + (Math.random() - 0.5) * 130,
          vx: 0,
          vy: 0,
          fx: null,
          fy: null,
          r: 3.2,
          neighbors: [],
        })
      }
      edges.push({ a: ni, b: ti })
      nodes[ni].neighbors.push(ti)
      nodes[ti].neighbors.push(ni)
    }
  })
  return { nodes, edges }
}

/** 单步力积分：排斥（提前按距离裁剪）+ 边弹簧 + 向心重力。 */
function simStep(g: Graph, alpha: number): void {
  const { nodes, edges } = g
  // 排斥
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i]
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j]
      let dx = a.x - b.x
      let dy = a.y - b.y
      const d2 = dx * dx + dy * dy
      if (d2 > REP_RADIUS2) continue
      const d = Math.sqrt(d2) || 0.01
      // 战术间排斥更强，避免大节点堆叠。
      const big = a.kind === 'tactic' && b.kind === 'tactic' ? 6 : 1
      const f = ((520 * big) / d2) * alpha
      dx = (dx / d) * f
      dy = (dy / d) * f
      a.vx += dx
      a.vy += dy
      b.vx -= dx
      b.vy -= dy
    }
  }
  // 弹簧
  for (const e of edges) {
    const a = nodes[e.a]
    const b = nodes[e.b]
    const dx = b.x - a.x
    const dy = b.y - a.y
    const d = Math.sqrt(dx * dx + dy * dy) || 0.01
    const f = ((d - 46) / d) * 0.028 * alpha
    a.vx += dx * f
    a.vy += dy * f
    b.vx -= dx * f
    b.vy -= dy * f
  }
  // 向心 + 积分（阻尼）
  for (const n of nodes) {
    n.vx -= n.x * 0.0016 * alpha
    n.vy -= n.y * 0.0016 * alpha
    if (n.fx !== null && n.fy !== null) {
      n.x = n.fx
      n.y = n.fy
      n.vx = 0
      n.vy = 0
      continue
    }
    n.vx *= 0.82
    n.vy *= 0.82
    n.x += n.vx
    n.y += n.vy
  }
}

export function KbGraph({
  tactics,
  onOpen,
}: {
  tactics: KbTactic[]
  onOpen: (id: string) => void
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const graphRef = useRef<Graph | null>(null)
  const viewRef = useRef({ ox: 0, oy: 0, k: 1 }) // screen = world*k + offset
  const hoverRef = useRef(-1)
  const searchRef = useRef(-1)
  const dragRef = useRef<{ idx: number; moved: boolean } | null>(null)
  const panRef = useRef<{ sx: number; sy: number; ox: number; oy: number } | null>(null)
  const alphaRef = useRef(1)
  const [query, setQuery] = useState('')
  // 主题切换时重绘：palette 随主题取色。
  const theme = useTheme()
  const P = palette(theme)

  const graph = useMemo(() => buildGraph(tactics), [tactics])
  graphRef.current = graph

  const techCount = useMemo(
    () => graph.nodes.filter((n) => n.kind === 'tech').length,
    [graph],
  )

  // 世界 -> 屏幕 / 屏幕 -> 世界
  const toWorld = useCallback((sx: number, sy: number) => {
    const v = viewRef.current
    return { x: (sx - v.ox) / v.k, y: (sy - v.oy) / v.k }
  }, [])

  const hitTest = useCallback(
    (sx: number, sy: number): number => {
      const g = graphRef.current
      if (!g) return -1
      const v = viewRef.current
      const w = toWorld(sx, sy)
      let best = -1
      let bestD = Infinity
      for (let i = 0; i < g.nodes.length; i++) {
        const n = g.nodes[i]
        const dx = n.x - w.x
        const dy = n.y - w.y
        const d = Math.sqrt(dx * dx + dy * dy)
        const rr = n.kind === 'tactic' ? n.r + 6 : n.r + 4 / v.k
        if (d < rr && d < bestD) {
          best = i
          bestD = d
        }
      }
      return best
    },
    [toWorld],
  )

  // 主循环：模拟（冷却后停止积分）+ 每帧重绘。
  useEffect(() => {
    const canvas = canvasRef.current
    const container = containerRef.current
    if (!canvas || !container) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let raf = 0
    let W = 0
    let H = 0
    const dpr = Math.min(window.devicePixelRatio || 1, 2)

    const resize = () => {
      const rect = container.getBoundingClientRect()
      W = rect.width
      H = rect.height
      canvas.width = Math.max(1, W * dpr)
      canvas.height = Math.max(1, H * dpr)
      canvas.style.width = `${W}px`
      canvas.style.height = `${H}px`
      // 初始视野：把初始布局（半径 ~500）装进画布。
      const v = viewRef.current
      if (v.k === 1 && v.ox === 0 && v.oy === 0) {
        v.k = Math.min(W, H) / 1100
        v.ox = W / 2
        v.oy = H / 2
      }
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(container)

    const draw = () => {
      const g = graphRef.current
      if (!g) return
      // 模拟：alpha 冷却后停止（拖拽/搜索会重新升温）。
      if (alphaRef.current > 0.005) {
        alphaRef.current *= 0.996
        simStep(g, alphaRef.current)
        simStep(g, alphaRef.current)
      }

      const v = viewRef.current
      const hover = hoverRef.current
      const match = searchRef.current
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)
      ctx.setTransform(dpr * v.k, 0, 0, dpr * v.k, dpr * v.ox, dpr * v.oy)

      const dimOthers = hover >= 0
      const isHi = (i: number) =>
        hover >= 0 && (i === hover || g.nodes[hover].neighbors.includes(i))

      // 边
      ctx.lineWidth = 0.6 / v.k
      for (const e of g.edges) {
        const a = g.nodes[e.a]
        const b = g.nodes[e.b]
        const hot =
          hover >= 0 &&
          (e.a === hover || e.b === hover) &&
          (isHi(e.a) && isHi(e.b))
        ctx.strokeStyle = hot
          ? P.edgeHot
          : dimOthers
            ? P.edgeDim
            : P.edgeNormal
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()
      }

      // 节点
      for (let i = 0; i < g.nodes.length; i++) {
        const n = g.nodes[i]
        const alpha = dimOthers && !isHi(i) ? 0.13 : 1
        ctx.globalAlpha = alpha
        if (n.kind === 'tactic') {
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
          ctx.fillStyle = P.tacticFill
          ctx.fill()
          ctx.lineWidth = 1.4 / v.k
          ctx.strokeStyle = P.accent
          ctx.stroke()
          ctx.beginPath()
          ctx.arc(n.x, n.y, 3, 0, Math.PI * 2)
          ctx.fillStyle = P.accent
          ctx.fill()
          ctx.font = `600 ${11 / v.k}px Barlow, sans-serif`
          ctx.textAlign = 'center'
          ctx.fillStyle = P.labelStrong
          ctx.fillText(n.label, n.x, n.y - n.r - 6 / v.k)
        } else {
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
          ctx.fillStyle = i === hover ? P.techHi : P.techBase
          ctx.fill()
          if (n.ring) {
            ctx.beginPath()
            ctx.arc(n.x, n.y, n.r + 2, 0, Math.PI * 2)
            ctx.lineWidth = 0.8 / v.k
            ctx.strokeStyle = P.ring
            ctx.stroke()
          }
          // 放大后显示技术名；悬停/搜索命中始终显示。
          if (v.k >= 1.9 || i === hover || i === match) {
            ctx.font = `${9.5 / v.k}px Barlow, sans-serif`
            ctx.textAlign = 'center'
            ctx.fillStyle =
              i === hover || i === match
                ? P.labelStrong
                : P.labelWeak
            ctx.fillText(
              n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label,
              n.x,
              n.y - n.r - 4 / v.k,
            )
          }
        }
        // 搜索命中的脉冲环
        if (i === match) {
          const t = (Date.now() / 500) % 2
          ctx.globalAlpha = Math.max(0, 1 - t / 2)
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r + 4 + t * 10, 0, Math.PI * 2)
          ctx.lineWidth = 1.2 / v.k
          ctx.strokeStyle = P.accent
          ctx.stroke()
        }
        ctx.globalAlpha = 1
      }
      raf = requestAnimationFrame(draw)
    }
    raf = requestAnimationFrame(draw)
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
    }
  }, [P])

  // ------------------------------------------------------------------ //
  // 交互
  // ------------------------------------------------------------------ //
  const localPos = (e: React.MouseEvent | React.WheelEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect()
    return { x: e.clientX - rect.left, y: e.clientY - rect.top }
  }

  const onMouseDown = (e: React.MouseEvent) => {
    const p = localPos(e)
    const idx = hitTest(p.x, p.y)
    if (idx >= 0) {
      dragRef.current = { idx, moved: false }
      const n = graphRef.current!.nodes[idx]
      const w = toWorld(p.x, p.y)
      n.fx = w.x
      n.fy = w.y
      alphaRef.current = Math.max(alphaRef.current, 0.3)
    } else {
      const v = viewRef.current
      panRef.current = { sx: p.x, sy: p.y, ox: v.ox, oy: v.oy }
    }
  }

  const onMouseMove = (e: React.MouseEvent) => {
    const p = localPos(e)
    if (dragRef.current) {
      const n = graphRef.current!.nodes[dragRef.current.idx]
      const w = toWorld(p.x, p.y)
      n.fx = w.x
      n.fy = w.y
      dragRef.current.moved = true
      return
    }
    if (panRef.current) {
      const v = viewRef.current
      v.ox = panRef.current.ox + (p.x - panRef.current.sx)
      v.oy = panRef.current.oy + (p.y - panRef.current.sy)
      return
    }
    const idx = hitTest(p.x, p.y)
    hoverRef.current = idx
    if (canvasRef.current) {
      canvasRef.current.style.cursor =
        idx >= 0 ? 'pointer' : 'grab'
    }
  }

  const onMouseUp = (e: React.MouseEvent) => {
    if (dragRef.current) {
      const { idx, moved } = dragRef.current
      const n = graphRef.current!.nodes[idx]
      n.fx = null
      n.fy = null
      dragRef.current = null
      if (!moved && n.kind === 'tech') onOpen(n.id)
    }
    panRef.current = null
    void e
  }

  const onWheel = (e: React.WheelEvent) => {
    const p = localPos(e)
    const v = viewRef.current
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12
    const k = Math.min(4, Math.max(0.25, v.k * factor))
    // 以光标为中心缩放
    v.ox = p.x - ((p.x - v.ox) / v.k) * k
    v.oy = p.y - ((p.y - v.oy) / v.k) * k
    v.k = k
  }

  // 搜索：匹配 id 或名称，居中 + 高亮脉冲。
  const jumpTo = useCallback(
    (q: string) => {
      const g = graphRef.current
      const canvas = canvasRef.current
      const query = q.trim().toLowerCase()
      searchRef.current = -1
      if (!g || !canvas || !query) return
      const idx = g.nodes.findIndex(
        (n) =>
          n.id.toLowerCase().includes(query) ||
          n.label.toLowerCase().includes(query),
      )
      if (idx < 0) return
      searchRef.current = idx
      const n = g.nodes[idx]
      const v = viewRef.current
      const rect = canvas.getBoundingClientRect()
      v.k = Math.max(v.k, 1.2)
      v.ox = rect.width / 2 - n.x * v.k
      v.oy = rect.height / 2 - n.y * v.k
    },
    [],
  )

  return (
    <div className="relative flex min-h-0 flex-1 flex-col">
      {/* 图内搜索 */}
      <div className="absolute left-3 top-3 z-10 flex items-center gap-2">
        <input
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            if (!e.target.value.trim()) searchRef.current = -1
          }}
          onKeyDown={(e) => e.key === 'Enter' && jumpTo(query)}
          placeholder="搜索技术编号 / 名称，回车定位…"
          className="w-[240px] rounded-full border border-hairline bg-panel px-3.5 py-1.5 text-[11px] text-fg outline-none transition-colors placeholder:text-text-3 focus:border-line-3"
        />
        <span className="glass rounded-full border border-hairline px-2.5 py-1 font-mono text-[9px] text-text-2">
          {tactics.length} 战术 · {techCount} 技术
        </span>
      </div>
      <div className="absolute bottom-3 left-3 z-10 flex items-center gap-3 font-mono text-[9px] text-text-3">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full border border-accent bg-accent/20" />
          战术
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#8a8a8a]" />
          技术
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full border border-accent/50" />
          含检测规则
        </span>
        <span>滚轮缩放 · 拖拽平移/节点 · 点击技术看文档</span>
      </div>
      <div ref={containerRef} className="min-h-0 flex-1">
        <canvas
          ref={canvasRef}
          className="block h-full w-full"
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={() => {
            hoverRef.current = -1
            panRef.current = null
            if (dragRef.current) {
              const n = graphRef.current!.nodes[dragRef.current.idx]
              n.fx = null
              n.fy = null
              dragRef.current = null
            }
          }}
          onWheel={onWheel}
        />
      </div>
    </div>
  )
}
