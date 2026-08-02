// ArenaView — 作战台（Kimi 式双栏聊天流）
// 顶部：标题行（作战台 + 一键开始）
// 中部：左=红方攻击流（40%），右=蓝方防御流（60%，派遣图 + 聊天流）
// 底部：控制条（OpsConsole，含场景选择与靶场情报入口）
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
      <div className="flex flex-none items-center gap-3 px-5 pb-2.5 pt-4">
        <div className="min-w-0">
          <h1 className="text-[16px] font-semibold leading-tight tracking-tight" style={{ color: 'var(--color-fg)' }}>
            作战台
          </h1>
          <div className="truncate text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
            {sceneName} · 自主红蓝对抗 · 流式输出
          </div>
        </div>
      </div>

      {/* 双栏输出：蓝方 60%，红方 40% */}
      <div className="flex min-h-0 flex-1 gap-2.5 px-4 pb-2.5">
        {/* 红方：攻击流 */}
        <div className="flex min-w-0 flex-col" style={{ flex: '0 0 40%', minHeight: 0 }}>
          <ChatStream
            side="red"
            steps={redSteps}
            running={Boolean(status.red_running)}
            accent="red"
            emptyTitle="等待攻击者进场"
            emptyDesc="点击下方「一键开始」，红方攻击智能体将开始侦察与渗透，全程流式呈现。"
          />
        </div>
        {/* 蓝方：派遣图 + 防御流（主体空间） */}
        <div className="flex min-w-0 flex-1 flex-col gap-2.5" style={{ minHeight: 0 }}>
          <DispatchGraph />
          <ChatStream
            side="blue"
            steps={blueSteps}
            running={Boolean(status.blue_running)}
            accent="blue"
            emptyTitle="等待指挥官下达指令"
            emptyDesc="蓝方调度指挥将按需派遣子代理（遥测巡检 / 事件研判 / 响应处置 / 失陷排查），工具调用与报告将流式呈现。"
          />
        </div>
      </div>

      {/* 控制条 */}
      <div className="flex-none px-4 pb-3.5">
        <OpsConsole />
      </div>
    </div>
  )
}
