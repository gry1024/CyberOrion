// ArenaView — 作战台（Cursor 式：平铺双栏，无卡片）
// 顶部一行标题；中部红/蓝双栏（蓝方为主）；底部控制条。
import { useArena } from '../arena'
import { ChatStream } from './ChatStream'
import { DispatchGraph } from './DispatchGraph'
import { OpsConsole } from './OpsConsole'

export function ArenaView() {
  const { status, scenario, redSteps, blueSteps } = useArena()
  const sceneName = scenario?.name || status.scenario || '默认靶场'

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* 标题行 */}
      <div className="flex flex-none items-center gap-2 border-b px-3 py-1.5" style={{ borderColor: 'var(--color-hairline)' }}>
        <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>作战台</span>
        <span className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>{sceneName}</span>
        <span className="ml-auto text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
          红 {status.red_running ? '●' : '○'} · 蓝 {status.blue_running ? '●' : '○'}
        </span>
      </div>

      {/* 双栏输出：蓝方 60%，红方 40%，中间 1px 分隔 */}
      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-col" style={{ flex: '0 0 40%', minHeight: 0 }}>
          <ChatStream
            side="red"
            steps={redSteps}
            running={Boolean(status.red_running)}
            accent="red"
            emptyTitle="红方攻击流"
            emptyDesc="点击「一键开始」后，红方攻击智能体开始侦察与渗透。"
          />
        </div>
        <div className="w-px flex-none" style={{ background: 'var(--color-hairline)' }} />
        <div className="flex min-w-0 flex-1 flex-col" style={{ minHeight: 0 }}>
          <DispatchGraph />
          <ChatStream
            side="blue"
            steps={blueSteps}
            running={Boolean(status.blue_running)}
            accent="blue"
            emptyTitle="蓝方防御流"
            emptyDesc="蓝方调度指挥派遣子代理检测、研判与处置攻击。"
          />
        </div>
      </div>

      {/* 控制条 */}
      <div className="flex-none border-t px-3 py-1.5" style={{ borderColor: 'var(--color-hairline)' }}>
        <OpsConsole />
      </div>
    </div>
  )
}
