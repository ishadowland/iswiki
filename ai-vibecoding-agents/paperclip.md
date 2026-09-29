# Paperclip — 管理 AI agent 干活的「公司级」控制平面

> 学习笔记 · 调研时间 2026-09-29
> 仓库: <https://github.com/paperclipai/paperclip> · 官网: <https://paperclip.ing> · 文档: <https://docs.paperclip.ing>
> License: MIT · 语言: TypeScript (84 MB) + Rust (2.6 MB, runner) · ⭐ **92,766** · 15,889 forks · ~202 contributors
> 默认分支: **`master`**(不是 main) · 202 contributors · 5,998 open issues · 450 watchers
> 最新版: **v2026.916.1**(2026-09-21 release)/ npm latest `2026.916.1` · canary `2026.928.0-canary.10`(2026-09-28)
> 调研方式: GitHub API + README + `doc/` 全量目录清点 + `packages/adapters/` 逐个枚举 + npm registry JSON + 本机环境核对

## 一句话定位

**Paperclip 把「一堆散装的 coding agent」变成「一家有 org chart、有预算、有审批门、有审计日志的公司」** —— Node.js 服务端 + React 控制台,自带嵌入式 PostgreSQL,你能把 Claude Code / Codex / Cursor / OpenCode / Pi / Gemini / Kimi / Grok / OpenClaw / **Hermes** 全部拉进来当员工,派工、盯进度、卡预算、审产出。官方金句:**"If OpenClaw is an employee, Paperclip is the company."**

## 三种使用方式

| 方式 | 入口 | 适用场景 | 代价 |
|---|---|---|---|
| **托管安装(推荐)** | `curl -fsSLO https://paperclip.ing/install.sh` + 校验 sha256 + `bash install.sh` | 一台机器跑完整 Paperclip,含后台服务(Linux systemd user unit / macOS LaunchAgent) | 会自动 bootstrap Node.js 24.11+;脚本从站点同源下载,自己审 |
| **npx 试用** | `npx --registry https://registry.npmjs.org paperclipai onboard --yes`<br>`npx paperclipai test-drive` | 零安装试跑;`test-drive` 建独立临时数据目录 + 一个 CEO agent,前台跑,不起服务、不建第一个任务 | 无常驻数据,退出后目录保留 |
| **源码 / Docker** | `git clone && pnpm install && pnpm dev`(`:3100`)<br>或 `docker build -t paperclip-local .` | 想改代码 / 塞 adapter plugin / 生产自建 Postgres | 需要 pnpm 9.15+(本机没装);Docker 镜像已预装 git/gh/ripgrep + Claude/Codex/OpenCode CLI |

**非交互式托管安装**(自动化脚本用):

```bash
curl -fsSL https://paperclip.ing/install.sh | bash -s -- --no-prompt --no-onboard
paperclipai onboard --yes
```

> ⚠️ 管道形式要求 Node.js / npm / npx 已存在。如果安装器需要自己装 Node,它会调用带特权的包管理器命令 —— **这种情况必须先下载脚本人工审,不要走管道**。

## 核心架构:12 个子系统

```
┌──────────────────────────────────────────────────────────────┐
│                       PAPERCLIP SERVER                       │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │
│  │Identity & │  │  Work &   │  │ Heartbeat │  │Governance │  │
│  │  Access   │  │   Tasks   │  │ Execution │  │& Approvals│  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘  │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │
│  │ Org Chart │  │Workspaces │  │  Plugins  │  │  Budget   │  │
│  │ & Agents  │  │ & Runtime │  │           │  │ & Costs   │  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘  │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │
│  │ Routines  │  │ Secrets & │  │ Activity  │  │  Company  │  │
│  │& Schedules│  │  Storage  │  │ & Events  │  │Portability│  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘  │
└──────────────────────────────────────────────────────────────┘
         ▲              ▲              ▲              ▲
   ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
   │  Claude   │  │   Codex   │  │   CLI     │  │ HTTP/web  │
   │   Code    │  │           │  │  agents   │  │   bots    │
   └───────────┘  └───────────┘  └───────────┘  └───────────┘
```

官方给的 4 大支柱(产品叙事,不是技术分层):

| Pillar | 面向谁 | 覆盖 |
|---|---|---|
| **Agentic Task Manager** | 日常 | 任务 + 审批/评审门 + 主动型 coworker + 可审计的 routine/workflow + 从 diff / 截图 / 测试验产出 |
| **Org Chart for Agents** | 管理者 | 人机混合 org chart、职责划分、委派、治理(谁能干什么)、scoped secrets |
| **Agent Employee Training** | 赋能者 | Skill Studio + 全公司共享 skill、evals + 保存测试跑分、主动学习闭环 + 质量指标、agent 绩效评估 |
| **Agentic OS** | IT / 平台 | 跨 provider runtime、沙箱 + 集成 + MCP server、SSO / GRC / RBAC / 成本控制、数据隐私 + 内部 trace |

### 关键技术机制(这几点是真做过设计的)

| 机制 | 说明 |
|---|---|
| **Atomic execution** | 任务 checkout 和预算扣减是原子的 —— 不会两个 agent 抢同一个任务,不会烧穿预算 |
| **Persistent agent state** | agent 跨 heartbeat 恢复同一 task 上下文,不是每次从零开始 |
| **Runtime skill injection** | agent 在运行时学 Paperclip 工作流和项目上下文,不靠重训 |
| **Governance with rollback** | 审批门强制执行,配置改动有 revision,可安全回滚 |
| **Goal-aware execution** | 任务携带完整 goal 祖先链,agent 看得见「为什么做」而不只是标题 |
| **Company portability** | 整个组织(agents/skills/projects/routines/issues)导出导入,带 secret 脱敏 + 冲突处理 |
| **真多公司隔离** | 每个 entity 都 company-scoped,一个部署跑 N 家公司,数据 + 审计链完全分开 |

### 数据模型(任务层)

```
Workspace
  Initiatives          (roadmap 级目标,跨季度)
    Projects           (有终点的交付物,可跨团队)
      Milestones       (项目内的阶段)
        Issues         (工作单元,核心实体)  ← CLI 里叫 issue,UI copy 里叫 task
          Sub-issues   (子任务)
```

`Issues` 字段:`id` / `identifier`(如 `PAP-123`,team key + 自增)/ `title` / `description` / `status` / `priority`(0-4)/ `estimate`。附加概念:一等公民的 blocker 依赖、comments、documents(带 revision + lock + restore)、attachments、work products、labels、inbox state。

### 内置 adapter 全清单(实测 `packages/adapters/` 目录)

| adapter | 运行方式 |
|---|---|
| `claude_local` | 本地 CLI 子进程 |
| `codex_local` | 本地 CLI(ACP) |
| `cursor_local` / `cursor_cloud` | 本地 / 云端 |
| `gemini_local` | 本地 CLI |
| `grok_local` | 本地 CLI |
| `kimi_local` | 本地 CLI |
| `opencode_local` | 本地 CLI |
| `pi_local` | 本地 CLI |
| `openclaw_gateway` | 远端 gateway(WebSocket + device pairing) |
| **`hermes`(`hermes_local`)** | **本地 `hermes` CLI 子进程** |
| **`hermes-gateway`(`hermes_gateway`)** | **HTTP/SSE 调已在跑的 Hermes API server** |

外部 adapter plugin 可动态加载装进来(Adapter manager),不用 fork 主仓。

### MCP 工具治理模型

```
Application ──▶ Connection ──▶ Catalog(tool schema)
                                   │
                          Profile(allow/deny)
                                   │ 绑到
                                   ▼
                    agent / project / routine / issue / company
                                   │
Agent tool call ──policy──▶ Gateway(policy engine) ──decision──▶ Tool call result
```

Paperclip 既能**作为 MCP endpoint** 被别人连,也能**当 MCP gateway** 管控别人的 tool 调用。策略 + 风险分级 + 审批流 + call 事件审计,`authenticated + public` 模式下本地 stdio MCP runtime slot 默认 fail closed(需显式设 `PAPERCLIP_TRUSTED_MCP_RUNTIME_HOST`),远程 HTTP MCP 是推荐路径。

## 安装与最小使用

```bash
# 1. 托管安装(带 checksum 校验)
curl -fsSLO https://paperclip.ing/install.sh
curl -fsSLO https://paperclip.ing/install.sh.sha256
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c install.sh.sha256
else
  shasum -a 256 -c install.sh.sha256
fi
bash install.sh

# 2. 零安装试跑(隔离数据目录 + 一个 CEO agent,前台,不起服务)
ANTHROPIC_API_KEY=... npx paperclipai test-drive
ANTHROPIC_API_KEY=... npx paperclipai test-drive --no-browser

# 3. 源码开发
git clone https://github.com/paperclipai/paperclip.git
cd paperclip && pnpm install && pnpm dev     # API server → http://localhost:3100
```

**要求:Node.js 24.11+ / pnpm 9.15+。** `pnpm dev` 不设 `DATABASE_URL` 时自动拉起嵌入式 PostgreSQL,数据落 `~/.paperclip/instances/default/db/`,零配置。

### 常用 CLI 速查

```bash
npx paperclipai doctor                                     # 配置/存储/DB/日志/端口 体检
npx paperclipai service install|start|stop|status|logs -f   # macOS=LaunchAgent, Linux=systemd user unit
npx paperclipai configure --section storage                # local_disk(默认) / s3

# 工单
npx paperclipai issue list --company-id <id> [--status todo,in_progress]
npx paperclipai issue create --company-id <id> --title "..." [--priority high]
npx paperclipai issue checkout <issue-id> --agent-id <id>   # 原子 checkout
npx paperclipai issue release <issue-id>
npx paperclipai issue document:put <issue-id> <key> --body-file ./plan.md
npx paperclipai issue work-product:create <issue-id> --payload-json '{"type":"pull_request"}'

# 组织 / 目标 / agent
npx paperclipai goal create --company-id <id> --title "Grow revenue" [--level company]
npx paperclipai agent list --company-id <id>
npx paperclipai project create --company-id <id> --name "Launch Site"

# prompt handoff:直接创建工单并唤醒 agent(不建 chat session)
npx paperclipai agent-prompt <agent-name-or-id> <agent-api-key> "Prompt here"
npx paperclipai agent prompt --agent <id> --api-key-env PAPERCLIP_API_KEY "..." [--no-wake]

# heartbeat / run 观察
npx paperclipai heartbeat run --agent-id <id>
npx paperclipai run list --company-id <id> [--agent-id <id>]
npx paperclipai run events <run-id> [--after-seq 0] [--limit 200]
npx paperclipai run cancel <run-id>
npx paperclipai run watchdog-decision <run-id> --decision continue

# 定时任务
npx paperclipai routine create --company-id <id> --payload-json '{...}'
```

### 🔴 CLI 调用安全:永远用 `npx paperclipai`,不要用 `pnpm paperclipai`

官方在 `doc/CLI.md` 第一节专门讲这个,值得抄:

- **`pnpm paperclipai <cmd> <args>` 不安全** —— pnpm 把参数拼成 `/bin/sh` 命令串,shell 会先展开 `` ` ``、`$()`、`$NAME`。恶意 issue 正文 / comment / 模型输出可以变成任意命令执行,还能把环境变量值泄进持久化的参数里。CLI 侧任何检查都拦不住,因为 shell 跑在 CLI 启动之前。
- **安全形式**:`npx paperclipai <cmd> <args>` —— npx 直接跑二进制,参数是惰性 `argv`,不过 shell。
- **`pnpm exec paperclipai` 直接是坏的** —— 根 workspace 不依赖 `paperclipai` 包,binary 不会被链进 `node_modules/.bin`。
- `pnpm paperclipai` 只在**完全字面量**的生命周期/初始化命令上可接受(白名单在 `server/src/__tests__/cli-invocation-safety.test.ts`,fail-closed 测试守着):`run` / `onboard` / `onboard --yes` / `doctor` / `configure --section <name>` / `connect` / `env-lab up|down` / `context show|list` / `worktree ensure-seeded` / `worktree env`。
- 文档里写命令示例只准用**静态占位符**(如 `<host>`),不准出现活的 `$( )` / `$NAME` —— 读者自己的 shell 会先展开。

### 本地存储布局

```
~/.paperclip/                                  # PAPERCLIP_HOME
└── instances/default/                         # PAPERCLIP_INSTANCE_ID
    ├── config.json  .env
    ├── db/                                    # 嵌入式 PostgreSQL 数据
    ├── data/storage/  data/backups/
    ├── logs/
    ├── secrets/master.key                     # local_encrypted 主密钥
    ├── workspaces/  projects/  companies/     # agent 执行目录 / 每公司 adapter home
    └── codex-home/
```

## 跟我们的关系 ⭐

**Paperclip 内置了一等公民的 Hermes adapter,而且分两种模式 —— 这不是「顺便支持」,是官方文档专门写了 onboarding 章节(`doc/HERMES_GATEWAY_ONBOARDING.md` / `HERMES_GATEWAY_SMOKE.md`)。**

### 1. 我们现成的 3 个 Hermes gateway 可以直接被 Paperclip「hire」

| 我们的资产 | Paperclip 里的对应物 |
|---|---|
| Hermes v0.19.1(git 安装,`~/.hermes/hermes-agent`) | 前提条件,已满足 |
| 飞书 gateway(launchd 守护) | `hermes_gateway` adapter,Paperclip 通过 HTTP/SSE 调它 |
| curator / stock / coder 三个 profile | 三个 Paperclip agent,各有 org chart 位置、预算、权限 |
| Hermes API server(默认 8642) | `adapterConfig.apiBaseUrl` |
| 我们的 cron 定时任务(简报 / 收盘总结) | Paperclip `routines`(cron / webhook / API 三种 trigger,自动建工单 + 唤醒 agent) |

**两种 adapter 怎么选:**

| | `hermes_local` | `hermes_gateway` |
|---|---|---|
| 怎么跑 | Paperclip 起 `hermes chat -q` 子进程 | 不起 Hermes,只是 HTTP/SSE 调已在跑的 API server |
| 适合 | Paperclip 和 Hermes 同机同信任域 | Hermes 已在跑 / 跨机 / Docker / 私有网 / TLS 端点 |
| 会话延续 | `--resume` flag + `sessionCodec` 校验迁移 | `POST /v1/runs` + SSE 流 + 轮询兜底 + `POST /v1/runs/{id}/stop` |

我们的架构是 3 个 launchd 守护的 gateway,**应该走 `hermes_gateway`** —— 不要让 Paperclip 再 fork 一批 `hermes chat` 子进程跟我们已有的守护进程抢资源/抢 session。

**三个 key 必须分清(官方明确警告):**

| key | 方向 | 谁生成 |
|---|---|---|
| Hermes 推理 provider key | Hermes → OpenRouter/Anthropic 等 | 用户自己配 |
| **Hermes gateway key**(`API_SERVER_KEY`) | **Paperclip → Hermes** | 我们起 gateway 时生成 |
| **Paperclip agent key** | **Hermes → Paperclip** | Paperclip 批准 join request 后由 Hermes claim 一次 |

**不能复用**。同一个值当两个用 = Paperclip 能拿 Hermes 的身份反过来调 Paperclip。

**Join 流程(CLI 版,可 copy-paste):**

```bash
# Paperclip 侧建 invite
npx paperclipai invite create --company-id <company-id> --payload-json '{"requestType":"agent"}'

# Hermes 侧提交 join(结构体,官方原文)
{
  "requestType": "agent",
  "agentName": "Hermes Gateway Engineer",
  "adapterType": "hermes_gateway",
  "capabilities": "Hermes gateway agent with code, browser, web, and file tools.",
  "agentDefaultsPayload": {
    "apiBaseUrl": "http://127.0.0.1:8642",     # Paperclip 调 Hermes 的地址
    "apiKey": "<= API_SERVER_KEY>",
    "paperclipApiUrl": "http://127.0.0.1:3100", # Hermes 调 Paperclip 的地址
    "sessionKeyStrategy": "issue"
  }
}

# Paperclip 侧批准
npx paperclipai join list --company-id <company-id> --status pending_approval
npx paperclipai join approve <request-id> --company-id <company-id>

# Hermes 侧 claim 一次性 agent key(敏感,别贴进 comment / log / prompt)
npx paperclipai join claim-key <request-id> --claim-secret <secret>
```

### 2. 反向:从 Hermes 侧建 Paperclip 任务

Paperclip 也提供了反向通道 —— 在 Hermes 里说一句话就创建/更新 Paperclip 工单,靠 `paperclip-task-bridge` skill + `node ./paperclip-task.mjs`:

```bash
node ./paperclip-task.mjs list-assigned
node ./paperclip-task.mjs create-task --parent-id "<approved-parent-issue-id>" \
  --title "Investigate checkout failures" --description "Capture failing request and root cause."
node ./paperclip-task.mjs comment --issue PAP-123 --body "Found the failing request path."
node ./paperclip-task.mjs update-status --issue PAP-123 --status in_review --comment "Ready for review."
```

环境变量:`PAPERCLIP_API_URL` / `PAPERCLIP_BRIDGE_API_KEY` / `PAPERCLIP_COMPANY_ID` / `PAPERCLIP_AGENT_ID` / `PAPERCLIP_RUN_ID`。

**⚠️ bridge key 必须是 `scope.kind = "task_bridge"` 且带 `parentIssueId` 或 `projectId` 边界** —— 官方明说:不要用普通的 claimed agent API key 跑面向互联网的 Hermes chat / webhook task-bridge。这条对我们尤其重要,我们有飞书 webhook 入口。

### 3. 本机现状核对(2026-09-29 实测)

| 项 | 状态 | 结论 |
|---|---|---|
| Node.js | `v24.13.0` | ✅ 满足 ≥24.11 |
| pnpm | ❌ 未安装 | 源码安装路线要补;`npx` 路线不需要 |
| Hermes | `v0.19.1 (2026.7.30)` upstream cb11a7e2 | ✅ |
| Hermes gateway 进程 | ✅ 在跑(PID 69368) | 但 8642 没在 listen → API server 没开(`API_SERVER_ENABLED` 未设) |
| 端口 3100 / 8642 / 3111 / 9119 | 全空 | ✅ Paperclip 默认 3100 无冲突(不符合我们 5 位数端口偏好,但这是别人项目的约定) |
| `~/.paperclip` | 不存在 | 干净,首次安装无冲突 |
| iswiki 已有 Paperclip 提及 | `openopc.md` / `openclaw-awd-arena.md` | ⭐ 数字已过期,见下 |

### 4. 纠正 iswiki 里的过期数据

`ai-vibecoding-agents/openopc.md` 第 319-440 行有一整节「Paperclip vs OpenOPC 深度对比」,里面写的是 **79,264 ⭐ / 14,531 forks**(调研时间 2026-08-24)。**一个月的实数:92,766 ⭐ / 15,889 forks,涨了 3,500 stars。** 结论不变(Paperclip 是生产级平台,OpenOPC 是角色扮演模拟器),但倍率已经从 54x/57x 变成 **64x/63x**。同时 openopc 里那张对比表没提到 Hermes adapter —— 现在 Paperclip 明确支持 Hermes(本地 + gateway 两种),这反而**加强了**「Paperclip = 平台」的判断。

## 实战建议与风险点

### ✅ 值得抄的设计

1. **Atomic checkout + 预算硬停** —— 我们多 profile 场景下最怕的就是两个 agent 抢同一个 cron 任务 + 烧穿 token 预算。这个模型值得单独抽出来抄。
2. **配置改动有 revision + 可 restore** —— 对应我们 `config.yaml` / `config.json` 的改动管理,现在缺这层。
3. **MCP 工具治理四层拆解**(Application / Connection / Catalog / Profile)+ policy engine —— 我们 hermes 的 `enabled_toolsets` 只有粗粒度开关,Paperclip 这套 allow/deny + 风险分级 + 审批 + call 审计粒度细得多。
4. **`test-drive` 这个命令形态** —— 「隔离临时数据目录 + 一个 CEO agent + 前台跑 + 不起服务 + 退出后目录保留」,比 `docker run --rm` 更适合试玩 agent 编排类工具。
5. **`pnpm paperclipai` 的 shell 注入告警** —— 这是官方自己在 README 顶部用整节篇幅警告的坑,任何「CLI 包装脚本」类项目都该抄这条 fail-closed 白名单测试。

### ⚠️ 风险 / 注意

| 风险 | 说明 |
|---|---|
| **默认开启匿名 telemetry** | 不采集个人信息 / issue 正文 / prompt / 文件路径 / secret,私有仓引用按 per-install salt 哈希。但**默认是开的**。关:`PAPERCLIP_TELEMETRY_DISABLED=1` / `DO_NOT_TRACK=1` / `CI=true` 自动关 / config 里 `telemetry.enabled: false`。我们要自建的话**默认就该关**。 |
| **成熟度错觉** | 2026-03-02 建仓,7 个月,92k ⭐,5,998 open issues,单周发 10+ 个 canary。极度激进 —— 意味着 API / schema / adapter type 都可能在你没注意的时候变。 |
| **版本号是日期式的** | `2026.916.1` = 2026 年第 91 天第 1 版。npm 上 7 个月发了 **1601 个版本**。别用 semver 心智,会误判稳定性。 |
| **默认分支是 `master`** | 抄配置 / 写脚本拉代码时容易踩。 |
| **强 Node 依赖** | 要求 Node ≥24.11。我们本机 24.13 刚好够,但 macOS 13.6 本身能给到的 Node 上限要注意。 |
| **默认端口 3100 + 嵌入式 PG** | 符合我们「避开常见端口」的习惯冲突。跑真实例建议 `--bind tailnet` 或走反向代理,别直接 `lan` 暴露。 |
| **`test-drive` 的凭据泄露面** | `--api-key` 会进 shell history 和 `ps` 输出,官方明说是「explicit tradeoff」。**用导出的规范环境变量或 `--api-key-env`**。 |
| **install.sh 同源校验** | sha256 和脚本同源,只能防传输/发布失误,防不了源被改。要独立托管源得用 release-tag 或 commit-pinned 的 GitHub 副本。 |
| **OpenClaw 的 device pairing 坑** | 官方 onboarding 文档自己承认:第一次 gateway run 可能仍返回 `pairing required`,要去 OpenClaw 里单独批设备 —— 这跟 Paperclip 的 invite 批是两回事。选 `hermes_gateway` 没这问题,这也是我推荐我们走 Hermes 路线的理由之一。 |

### 🚀 建议的落地路径(如果要试)

```bash
# 阶段 0:零安装试跑,不污染现有环境(Node 24.13 已满足)
npx --registry https://registry.npmjs.org paperclipai test-drive --no-browser
# 注意:默认会用 3100 起步的第一个空闲端口

# 阶段 1:起一个 hermes_gateway 给它 hire
export API_SERVER_KEY="$(openssl rand -hex 32)"
API_SERVER_ENABLED=true hermes gateway run --replace --accept-hooks   # 默认 8642
# → Paperclip onboard --bind loopback → invite create → join → approve → claim-key

# 阶段 2:把 cron 迁过来
# 我们的 daily-news-briefing / market-close-summary 用例改成 paperclip routine(cron trigger)

# 阶段 3:评估是否把 Hermes 作为上游 orchestrator(反过来 Paperclip 当执行层)
```

**先做阶段 0**。一个 Node 依赖 + 内嵌 PG 的平台,值得先隔离试一次再决定要不要把 3 个 gateway 挂进去。

## 版本节奏

| 通道 | 最新 | 日期 | 备注 |
|---|---|---|---|
| GitHub release | `v2026.916.1` | 2026-09-21 | 26 个 release,master 上还持续在推 |
| npm `latest` | `2026.916.1` | 2026-09-21 | stable |
| npm `beta` | `2026.921.0-beta.1` | — | |
| npm `canary` | `2026.928.0-canary.10` | 2026-09-28 | 一周 10 个 |
| npm `nightly` | `2026.928.0-nightly.0` | — | |
| Docker | `ghcr.io/paperclipai/paperclip:sha-<FULL_SHA>` | — | 多平台 + Sigstore attestation,不可变 digest |

release 节奏:约每 1-3 周一个 `v` tag,canary 每日多发。

## 路线图状态(官方 `ROADMAP.md`)

✅ 已交付 19 项:plugin 系统 / OpenClaw & claw-style agent 员工 / `companies.sh` 整组织导入导出 / AGENTS.md 配置 / Skills Manager + Studio + Store / 定时 Routines / 预算 / agent 评审与审批 / 多人类用户 / Cloud & Sandbox agents(e2b / Cloudflare / Daytona / Modal / Novita / 自建 K8s)/ Artifacts & Work Products / Deep Planning / Enforced Outcomes(watchdog + recovery + review gate)/ MCP Tool Gateway / Secrets Manager per-agent / Activity log / 自愈 run / agent evals

⚪ 未做:Memory & Knowledge / MAXIMIZER MODE / Work Queues / Self-Organization / 自动组织学习 / CEO Chat / Desktop App / bring-your-own-ticket-system(Asana / Linear / Jira)/ Connected Apps

🟡 半:Cloud 多租户隔离(company Import/Export 已发)

> 注意:Memory 还在 ⚪ —— 这对我们(hermes 有成熟 chromamem + FTS5 记忆)是**差异化优势**,别把自己的记忆能力白送进 Paperclip。

## 可观测性

| 通道 | 开关 | 说明 |
|---|---|---|
| OpenTelemetry | 设 `OTEL_EXPORTER_OTLP_ENDPOINT` 即激活 | 只 trace server。支持 `grpc` / `http/protobuf` / `http/json`(`OTEL_EXPORTER_OTLP_PROTOCOL`)。SDK 相关是 optional peer dep,要自己装 |
| Sentry 前端 | `SENTRY_DSN_FRONTEND` | `@sentry/browser` 固定 `10.71.0` |
| Sentry 后端 | `SENTRY_DSN_BACKEND` | `@opentelemetry` / Sentry 都是可选,不装不报错 |
| 活动日志 | 内置 | 所有 mutating action + heartbeat 状态变更 + 成本事件 + 审批 + 评论 + work product,持久化可审计 |

## 参考链接

- 仓库: <https://github.com/paperclipai/paperclip>(⚠️ 默认分支 `master`)
- 官网: <https://paperclip.ing>
- 文档: <https://docs.paperclip.ing>
- 安装脚本: <https://paperclip.ing/install.sh>
- 安装文档: `doc/INSTALLING.md` · `doc/DOCKER.md` · `doc/DEPLOYMENT-MODES.md`
- **Hermes 接入(跟我们最相关)**:
  - `doc/HERMES_GATEWAY_ONBOARDING.md`
  - `doc/HERMES_GATEWAY_SMOKE.md`
  - `packages/adapters/hermes/README.md`
  - `packages/adapters/hermes-gateway/README.md`(deprecated 兼容 shim)
- CLI 参考: `doc/CLI.md`(1172 行,§9 开头就有 shell 注入告警)
- 设计哲学: `DESIGN.md`(token 层是 `ui/src/index.css` 单源、UI copy 统一用 "task" 不用 "issue")
- 产品愿景: `doc/GOAL.md` / `doc/PRODUCT.md`
- 任务模型: `doc/TASKS.md`
- MCP 治理: `doc/MCP-ACCESS-GOVERNANCE.md` / `doc/MCP-RUNTIME-OPERATIONS.md`
- 数据库: `doc/DATABASE.md`(Drizzle ORM + 嵌入式 PG)
- 架构文档: `doc/architecture/`(`paperclip-runner.md` / `durable-continuation-scheduler.md` / `native-status-arbitration.md`)
- 路线图: `ROADMAP.md`
- OpenClaw 接入(对照看,踩坑记录很实在): `doc/OPENCLAW_ONBOARDING.md`
- 插件生态: <https://github.com/gsxdsm/awesome-paperclip>
- Discord: <https://discord.gg/m4HZY7xNG3> · Twitter: <https://x.com/papercliping>

## 相关笔记

- [openopc](openopc.md) — 里面有一整节 Paperclip 对比(⭐ 数据已过期,见本文「纠正 iswiki 里的过期数据」)
- [openclaw-awd-arena](openclaw-awd-arena.md) — 多 agent 编排的另一个方向(容器隔离对抗)
- [paseo](paseo.md) — 桌面 + 移动端多 agent 编排器,轻量路线
- [lobeHub](lobeHub.md) — 「首席 Agent 运营官」定位跟 Paperclip 高度重叠,可以对照看谁做得更深
- [bagidea-office](bagidea-office.md) — 同样主打「AI 员工/公司」叙事,但走可视化桌面路线
