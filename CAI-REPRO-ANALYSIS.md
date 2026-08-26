# CAI 复现分析（面向 CTF 实战 + 防御性轻量 bench）

> 目标：在不搬运 CAI 全部能力的前提下，提取并复现对**网络安全防御**与**CTF 实战**最关键的部分，让 **DeepSeek** API 直接驱动一套基于 ReAct 的多 Agent 体系，能跑得动、能展示效果。
>
> 本文档基于 cai-latest/（CAI 主仓库已克隆在同目录）源码逐文件审阅得出，所有结论均指向具体文件与行级位置。

---

## 0. 我们的复现边界

| 维度 | CAI 原生 | 我们的复现 | 原因 |
|---|---|---|---|
| 模型 | alias1/alias2（OpenAI 兼容，多为闭源强模型） | DeepSeek Chat / DeepSeek Reasoner（API 兼容 OpenAI Chat Completions） | 模型约束 |
| 内存/CPU | 大型 bench（cybersoceval、CVE-Bench 全套） | Cybench 轻量子集 + 自建 CTF 容器 | 服务器限制 |
| 工具栈 | 90+ 安全工具 | core 6 件套：generic_linux_command / fetch_url / execute_code / ssh_command / shodan / web_search | 防御侧刚需 + DeepSeek 上下文省着用 |
| 侧重点 | 攻击为主（Red Team 默认） | 防御 + CTF 双轨（Blue Team / DFIR + CTF one_tool） | 赛题取向 |
| UI | TUI + REPL + API | CLI 单跑 + Python SDK 直接调用 | 简化部署 |

> 复现不等于 1:1 翻译，而是用 CAI 的架构骨架（Agent / Tools / Handoffs / Pattern / Guardrails）喂 DeepSeek。

---

## 1. CAI 的 Agent 全景（与我们复现相关的部分）

CAI 把安全角色全部封装成独立 Agent 实例（每个 .py 一个），并在 cai/agents/__init__.py 用 pkgutil.iter_modules 自动发现。

### 1.1 防御/响应侧（优先复现）

| Agent | 文件 | 工具集 | 系统提示词 | 必要性 |
|---|---|---|---|---|
| Blue Team Agent | cai/agents/blue_teamer.py | generic_linux_command, run_ssh_command_with_credentials, execute_code, WEB_INTEL_TOOLS（= fetch_url），可选 Todo_list 和 web_search | prompts/system_blue_team_agent.md，使用 TRACE 循环 | 必复现 |
| Blue Team GCTR | cai/agents/blue_teamer_gctr.py | 在 Blue Team 基础上叠加 gctr_mixin.CTRHooks，每 N 次交互跑一次博弈分析 | 同上 + game-theoretic wrapper | 进阶复现 |
| DFIR Agent | cai/agents/dfir.py | generic_linux_command, run_ssh_command_with_credentials, execute_code, think, WEB_INTEL_TOOLS，可选 shodan_search / google_search / web_search | prompts/system_dfir_agent.md | 必复现 |
| Network Traffic Analyzer | cai/agents/network_traffic_analyzer.py | capture_traffic（tcpdump 封装）+ 通用工具 | 流量分析专项 | 视赛题 |
| Memory Analysis / Reverse Eng. | memory_analysis_agent.py / reverse_engineering_agent.py | 专用取证工具 | 取证/逆向 | 视赛题 |
| Compliance Agent | cai/agents/compliance_agent.py | GRC 类（HIPAA/GDPR/ISO） | 合规审计 | 不复现 |

### 1.2 攻击/测试侧（用于 CTF 与自检）

| Agent | 文件 | 关键差异 | 必要性 |
|---|---|---|---|
| Red Team Agent | cai/agents/red_teamer.py | 额外挂载了 input_guardrails + output_guardrails（prompt injection / 危险命令拦截） | CTF 自检用 |
| CTF one_tool Agent | cai/agents/one_tool.py | 只给一个工具 generic_linux_command + guardrails；对应 prompt system_ctf_agent.md | CTF 主力 |
| Flag Discriminator | cai/agents/flag_discriminator.py | handoffs 列表包含 handoff(one_tool_agent)，抓到 flag 就完，没抓到就回灌给 ctf agent 继续 | CTF 后处理 |
| Bug Bounter | cai/agents/bug_bounter.py | HackerOne/PortSwigger 报告导向 | 不复现 |
| Web Pentester | cai/agents/web_pentester.py | 偏 OWASP Top 10 | 视赛题 |

### 1.3 编排/元层（必须复现）

| Agent | 文件 | 角色 | 必要性 |
|---|---|---|---|
| Orchestration Agent | cai/agents/orchestration_agent.py | 顶层调度，工具：check_available_agents, analyze_task_requirements, run_specialist, run_parallel_specialists, run_dual_approach_contest，模型默认带 -thinking 后缀 | 元控制器 |
| Selection Agent | cai/agents/selection_agent.py | 基于关键词选择最合适的 specialist | ★★☆ |
| Thought Agent | cai/agents/thought.py | 只带一个 think 工具的反思 agent | Swarm 内常用 |

> 注意：Orchestration 强依赖 -thinking 后缀模型（如 deepseek-reasoner），DeepSeek Reasoner 完美对应。

---

## 2. 工具（Tools）—— CAI 的 Actuator

CAI 的工具按 kill chain 分目录，全部基于 OpenAI function calling 协议。我们只需要复现以下 6 个 core 工具就能覆盖防御 + CTF 双场景：

| 工具 | 文件 | 功能 | 接口签名（简化） | DeepSeek 兼容性 |
|---|---|---|---|---|
| generic_linux_command | cai/tools/reconnaissance/generic_linux_command.py | 统一 shell 入口：本地 / CTF 容器 / SSH 后台会话 / 交互式 tail&ssh | (command, timeout, session_id, interactive, working_directory) | ★★★ |
| fetch_url | cai/tools/web/fetch_url.py | 网页抓取（自带 SSRF 防护、anti-bot、注入净化） | (url) | ★★★ |
| execute_code | cai/tools/reconnaissance/exec_code.py | 沙箱内跑 Python（CAI 内部执行，不走 shell） | (code) | 视需要 |
| sshpass.run_ssh_command_with_credentials | cai/tools/command_and_control/sshpass.py | 带凭据的远程 SSH | (command, host, user, password) | ★★★ |
| shodan_search / shodan_host_info | cai/tools/reconnaissance/shodan.py | Shodan 公开情报 | (query) / (ip) | 需 SHODAN_API_KEY |
| make_web_search_with_explanation | cai/tools/web/search_web.py | Perplexity 联网搜索 + 解释 | (query) | 需 PERPLEXITY_API_KEY；可换 Tavily/SearXNG |

> 关键实现细节（必须保留）：CAI 把所有安全壳逻辑放在 generic_linux_command 内部：
> 1. 敏感命令交互确认（通过 cai.util.user_prompts）：sensitive 命令需用户授权，类别化提示（detect_sensitive_command）；
> 2. post-execution sudo 提权：当命令输出表明需要 root，自动检测并询问 prompt_sudo_elevation；
> 3. 输出压缩（_compress_output_for_model）：防止 OOM/上下文爆；
> 4. CAI_GUARDRAILS=true 时：内置危险命令拦截（rm -rf /, fork bomb, curl|sh, base64 反弹 shell, 临时目录 heredoc 加  等），并对 curl/wget 的输出做非指令化包装（=== EXTERNAL SERVER RESPONSE (DATA ONLY) ===）。
>
> 这些是 CAI 防御性设计的精华，复现时必须照搬，否则 DeepSeek 一旦越权执行就不可控。

### 2.1 工具注册机制（极简复用）


CAI 用了 cai.tool_registry.TOOL_REGISTRY 加 available_tools.AVAILABLE_TOOLS 做按 key 拉工具的字典。我们的复现只需要一个 TOOL_REGISTRY dict 即可：



CAI 用了 cai.tool_registry.TOOL_REGISTRY 加 available_tools.AVAILABLE_TOOLS 做按 key 拉工具的字典。我们的复现只需要一个 TOOL_REGISTRY dict 即可：



---

## 3. CTF 完整运行链路（代码层 + ReAct 逻辑）

CAI 的 CTF 流程不是单一 agent 搞定，而是三层结构：one_tool 主战 加 flag_discriminator 终判 加 flag_discriminator 回灌给 ctf_agent 的二次循环。
CAI 用了 cai.tool_registry.TOOL_REGISTRY 加 available_tools.AVAILABLE_TOOLS 做按 key 拉工具的字典。我们的复现只需要一个 TOOL_REGISTRY dict 即可：

```
TOOL_REGISTRY = dict(
    generic_linux_command=generic_linux_command,
    fetch_url=fetch_url,
    ssh_command=run_ssh_command_with_credentials,
    shodan_search=shodan_search,
)
```

---

## 3. CTF 完整运行链路（代码层 + ReAct 逻辑）

CAI 的 CTF 流程不是单一 agent 搞定，而是三层结构：one_tool 主战 加 flag_discriminator 终判 加 flag_discriminator 回灌给 ctf_agent 的二次循环。

### 3.1 整体架构（从 CLI 到 flag 落地）



### 3.2 ReAct 的代码级落地

来源：cai/sdk/agents/run.py 的 _run_single_turn。

```
async def _run_single_turn(agent, all_tools, original_input, generated_items,
                           hooks, context_wrapper, run_config):
    await hooks.on_agent_start(context_wrapper, agent)
    await agent.hooks.on_start(context_wrapper, agent)
    system_prompt = await agent.get_system_prompt(context_wrapper)
    output_schema   = self._get_output_schema(agent)
    handoffs        = self._get_handoffs(agent)
    model           = self._get_model(agent, run_config)
    model_settings  = agent.model_settings.resolve(...)

    # 调 LLM = DeepSeek Chat Completions API
    new_response = await model.get_response(
        system_instructions=system_prompt,
        input=[...original_input..., ...generated_items...],
        model_settings=model_settings,
        tools=all_tools,
        output_schema=output_schema,
        handoffs=handoffs,
    )

    processed = RunImpl.process_model_response(...)
    return await RunImpl.execute_tools_and_side_effects(...)
```

> 每次 _run_single_turn = 一次 Reason (LLM) -> Act (tool) -> Observe (tool result)，即经典 ReAct 范式。tool_use_behavior 默认 run_llm_again，所以每次工具调用后 LLM 会再次推理。

### 3.3 工具调用与容器执行

来源：cai/caibench/ctf.py 的 CTF.get_shell：


```
```
def get_shell(command, detach=False, timeout=60):
    if detach:
        # 此处拼接字符串，未使用 f-string 以避免 heredoc 解析问题
        cmd = exec + command
        return container.exec_run([/bin/sh, -c, cmd], detach=True).output
    else:
        # 同样用 % 格式化或拼接
        result = container.exec_run(/bin/sh -c timeout + str(timeout) +  + command,
                                    tty=True, stdin=True, stdout=True, stderr=True)
        return result.output.decode(utf-8).strip()
```

即 generic_linux_command 通过 docker.ExecRun 把命令塞进目标容器内部，超时默认 60s。

### 3.4 Handoffs 通信协议

来源：cai/sdk/agents/handoffs.py：

```
@dataclass
class Handoff:
    tool_name: str                      # 例如 transfer_to_one_tool_agent
    tool_description: str
    input_json_schema: dict
    on_invoke_handoff: Callable         # 返回 Agent
    agent_name: str
    input_filter: Callable | None
```

机制：Handoff 在工具层面就是一个特殊 function tool。LLM 决定调用 transfer_to_one_tool_agent，CAI 把它解析为 AgentUpdatedStreamEvent，随后在 _run_single_turn 里切换 agent：

```
current_agent = turn_result.next_step.new_agent
if has_bidirectional_handoff:
    current_agent.model.message_history = previous_agent.model.message_history
```

跨 agent 通信 = 共享 model.message_history（OpenAI messages 数组）。DeepSeek Chat 完美兼容。

### 3.5 完整 CTF 执行示例（复现视角）

```
async def ctf_solve(ctf_name, ip, model_name=deepseek-chat):
    ctf = CTF(name=ctf_name, subnet=172.18.0.0/24, ip_address=ip)
    ctf.start_ctf()
    agent = Agent(
        name=CTF agent,
        instructions=load_prompt(system_ctf_agent.md),
        tools=[generic_linux_command],
        input_guardrails=[prompt_injection_guardrail],
        output_guardrails=[command_execution_guardrail],
        model=OpenAIChatCompletionsModel(
            model=model_name,
            openai_client=AsyncOpenAI(
                api_key=os.environ[DEEPSEEK_API_KEY],
                base_url=https://api.deepseek.com/v1,
            ),
        ),
    )
    runner = Runner(agent=agent, max_turns=20, hooks=TracingHooks())
    result = await runner.run(input=目标 IP + ip + ，挑战： + ctf.get_instructions())
    return ctf.check_flag(result.final_output, challenge=FLAG)
```

---

## 4. Bench 选择与可运行性

CAI 的 bench 分四类：
1. Knowledge bench（CTI 问答）—— 只调 LLM，无环境。
2. Container-based CTF（cybench / base / auto-pen-bench / cyber_range / rctf2）—— 需 Docker 镜像，轻量。
3. A&D Attack-Defense CTF —— 多容器协同，重。
4. Vulnerability research（cybersoceval / CVE-Bench）—— 极度重。

我们服务器资源有限，只取第 1 加 第 2 类子集，且只挑 works == true 的镜像（来自 cai/caibench/ctf-jsons/ctf_configs.jsonl，共 133 条通过验证）。

### 4.1 Knowledge bench（理论性能，跑得起）

来源：cai-latest/benchmarks/eval.py。

| Bench | 数据来源 | 任务 | 推荐度 | 跑法 |
|---|---|---|---|---|
| CyberMetric | benchmarks/cybermetric/CyberMetric-2-v1.json | 多选网安常识题 | 必跑 | python benchmarks/eval.py --model deepseek-chat --dataset_file benchmarks/cybermetric/CyberMetric-2-v1.json --eval cybermetric --backend openai |
| SecEval | benchmarks/seceval/eval/datasets/questions-2.json | 同上，更偏应用 | 推荐 | --eval seceval |
| CTI Bench | benchmarks/cti_bench/data/*.tsv | 威胁情报 加 多选 | 推荐 | --eval cti_bench |
| CyberPII-Bench | benchmarks/cyberPII-bench/memory01_gold.csv | PII 实体识别 | 必跑（贴合防御） | --eval cyberpii-bench |

> 全部走 Chat Completions 协议，DeepSeek API 直接接。

### 4.2 容器 CTF（CTF 实战展示）

镜像源在 ctf_configs.jsonl，全部为 registry.gitlab.com/aliasrobotics/alias_research/caiextensions/pentestperf:NAME，匿名拉取会 401。复现侧两套方案：

- 方案 A：自己 docker build，按 source 字段（picoCTF / vulnhub 等）准备。
- 方案 B（推荐）：用现成镜像（kalilinux/kali-rolling 是 CAI 默认），手写小型 CTF 题目端到端演示。

#### 推荐复现的子集

| 主题 | 来源 | 题目 | 适配理由 |
|---|---|---|---|
| Web 防御 | base | picoctf_static_flag（Very Easy, 静态分析） | 最简链路，验证管线 |
| Web 攻击基础 | base | kiddoctf（Very Easy, Linux/编码/Base64） | 训练 CTF one_tool agent |
| Web 漏洞 | auto-pen-bench | ws_vm5 / ws_vm6（Very Easy, RCE）、ws_vm2（Easy, Path Traversal） | 对应 Blue Team 修复视角 |
| 认证/凭据 | auto-pen-bench | ac_vm1 到 ac_vm4（Easy, 认证绕过） | 对应 Blue Team 凭据加固 |
| 漏洞复现 | auto-pen-bench | cve-2024-36401、cve-2021-43798、cve-2022-22965 | 真实 CVE |
| 协议/取证 | cybench | dinoauth（Medium, OAuth2）、avatar（Easy, 隐写） | 给 DFIR agent |
| 网段 / 横向 | cyber_range | colddbox（Easy, WP+SSH 提权）、intrusion（Easy, 取证） | 多步串联 ReAct |

> 不推荐：cybench Very Hard、attack_defense、cybersoceval / CVE-Bench。

### 4.3 落地最小工程量

| 步骤 | 工作量 | 说明 |
|---|---|---|
| bench_runner.py（约 150 行） | 1 人·半天 | 解析 ctf_configs -> docker run -> 调 agent -> check_flag |
| 复刻 CTF 类（约 200 行） | 0.5 人·天 | 照搬 cai/caibench/ctf.py 保留 start/get_shell/check_flag |
| DeepSeek adapter | 0.5 人·天 | AsyncOpenAI(base_url=https://api.deepseek.com/v1) |
| 复刻 6 件工具 | 1 人·天 | 重点是 generic_linux_command 的 sudo/会话/压缩 |
| Runner 主循环 | 1 人·天 | 直接用 OpenAI Agents SDK 原版 |
| guardrails | 0.5 人·天 | 复用 CAI 正则即可 |

> 合计 约 4 到 5 人·天即可端到端跑通（含一个 web RCE 题目）。

---

## 5. 我们怎么做，怎么实际运行

> 一句话总结：DeepSeek Chat 当主力 + DeepSeek Reasoner 当 Orchestrator 的 thinking 模型，复刻 6 件工具 加 Blue/DFIR/CTF 三个 Agent 加 Container 化靶机。

### 5.1 最小可用架构（MVP）

```
deepseek-chat (主力工具调用) + deepseek-reasoner (编排决策)
         |
         v
   OpenAI Agents SDK (原版即可)
         |
         v
   自实现 6 件工具 (generic_linux_command / fetch_url / execute_code /
                    sshpass / shodan / web_search)
         |
         v
   3 类 Agent:
     . Blue Team  (防御, 加 guardrails)
     . DFIR       (取证响应)
     . CTF one_tool (攻击 + 取 flag)
   + 1 编排器:
     . Orchestration (deepseek-reasoner) -> 选/调上面三 agent
         |
         v
   靶机: 自己 docker build 的 PicoCTF-style 题目
         |
         v
   JSONL 日志 (trace) + CyberMetric 分数
```

### 5.2 30 秒起步运行

```
mkdir cyber-defense-agent && cd cyber-defense-agent
python -m venv .venv && source .venv/bin/activate
pip install openai-agents httpx docker

cp ../cai-latest/src/cai/prompts/system_blue_team_agent.md ./prompts/
cp ../cai-latest/src/cai/prompts/system_ctf_agent.md        ./prompts/
cp ../cai-latest/src/cai/prompts/system_dfir_agent.md       ./prompts/
cp ../cai-latest/src/cai/agents/guardrails.py               ./guardrails.py

cat > .env <<ENVEOF
DEEPSEEK_API_KEY=sk-REPLACE_ME
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
CAI_MODEL=deepseek-chat
CAI_AGENT_TYPE=blue_team
CAI_GUARDRAILS=true
ENVEOF

docker run -d --name target --network ctf-net --ip 172.18.0.10 \
  -e FLAG=flag_demo alpine:latest \
  sh -c echo flag_demo > /flag.txt && httpd -f -p 80

python run_blue_team.py --target 172.18.0.10
```




### 5.2 30 秒起步运行
### 5.3 跑通后的进阶

| 目标 | 做法 |
|---|---|
| CTF 实操 | CAI_AGENT_TYPE=ctf_agent + one_tool，跑 kiddoctf |
| A&D 防御 | CAI_AGENT_TYPE=blueteam_agent + CAI_PLAN=true，跑 colddbox |
| DFIR 取证 | cybench/avatar（隐写）作为靶场 |
| 理论对标 | CyberMetric + CyberPII-Bench，写入实验报告 |
| 多 Agent 协同 | 启动 orchestration_agent，观察分派 blue_team / dfir |

### 5.4 避坑清单

1. CAI_GUARDRAILS 必须开：CAI 默认 false。DeepSeek 在含 base64/curl 的 CTF 输出里非常容易被诱导执行恶意命令。
2. deepseek-reasoner 的 system prompt：DeepSeek Reasoner 会折叠 system 到 reasoning context，复现侧只给一个 system prompt，其它进 input 数组。
3. CAI_MAX_TURNS 别无限：50 turn 也能烧到几十元。设 CAI_MAX_TURNS=20、CAI_PRICE_LIMIT=2。
4. CTF 容器 --network ctf-net：否则 get_shell 走不到靶机。
5. 别跑 cybersoceval / CVE-Bench：磁盘 + 显存 50 GB 加，DeepSeek 收益小。

---

## 6. 复现范围速查表

| 模块 | 是否复现 | 来源文件 |
|---|---|---|
| Agent（Blue/DFIR/CTF/Orchestration/Thought/FlagDisc） | 是 | cai/agents/blue_teamer.py / dfir.py / one_tool.py / orchestration_agent.py / thought.py / flag_discriminator.py |
| Agent（其他十几种） | 否 | cai/agents/*.py |
| 6 件核心工具 | 是 | cai/tools/reconnaissance / web / command_and_control |
| 沙箱型 CodeAgent | 否 | cai/agents/codeagent.py（独立 Python 子运行时，体积大） |
| TUI / REPL / MUI | 否（用 CLI） | cai/tui / repl / mui |
| Tracing | 是 简化（JSONL） | cai/sdk/agents/tracing |
| Guardrails | 是 | cai/agents/guardrails.py |
| CTF 容器运行时 | 是 | cai/caibench/ctf.py |
| CyberMetric / SecEval / CyberPII bench | 是 | benchmarks/eval.py |
| CVE-Bench / cybersoceval | 否（资源不允许） | benchmarks/cvebench / cybersoceval |
| Caibench 全套镜像 | 部分（自建） | cai/caibench/ctf-jsons/ctf_configs.jsonl |
| A&D Attack-Defense | 否 | docs/cai_benchmark.md Attack-Defense |

---

## 7. 参考源码索引

| 用途 | 路径（相对 cai-latest/） |
|---|---|
| Agent 自动发现 | cai/agents/__init__.py |
| Agent 数据结构与工具挂载 | cai/sdk/agents/agent.py |
| **ReAct 主循环** | cai/sdk/agents/run.py |
| Handoff 协议 | cai/sdk/agents/handoffs.py |
| 防御 Agent | cai/agents/blue_teamer.py |
| 取证 Agent | cai/agents/dfir.py |
| CTF Agent | cai/agents/one_tool.py |
| 元控制 Agent | cai/agents/orchestration_agent.py |
| Prompt Injection 拦截 | cai/agents/guardrails.py |
| 统一 shell 工具 | cai/tools/reconnaissance/generic_linux_command.py |
| CTF 容器管理 | cai/caibench/ctf.py |
| 146 个 CTF 配置（133 个已验证） | cai/caibench/ctf-jsons/ctf_configs.jsonl |
| Blue Team prompt（TRACE 循环） | cai/prompts/system_blue_team_agent.md |
| CTF one_tool prompt | cai/prompts/system_ctf_agent.md |
| 配置中心 | cai/config.py |
| 多 Agent 协同 Pattern | cai/agents/patterns/pattern.py |
| Knowledge bench 入口 | benchmarks/eval.py |
| 8 大支柱综述 | docs/cai_architecture.md |
| Bench 分类与运行细节 | docs/cai_benchmark.md |

所有路径相对仓库根 cai-latest/。
