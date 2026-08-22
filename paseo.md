# Paseo — Multi-Agent Orchestrator (Desktop + Mobile)

> 学习笔记 · 调研时间 2026-08-22
> 仓库: <https://github.com/getpaseo/paseo>
> 官网: <https://paseo.sh>
> 作者: moboudra (Twitter @moboudra)
> ⭐ 14,573 · 1,542 forks · TypeScript · 113 MB repo · License: Other (custom)
> Created: 2025-10-13 · v0.5.0-beta.4 (2026-08-21)

## 一句话定位

**"One interface for Claude Code, Codex, Copilot, OpenCode, and Pi agents"** —— Paseo 是一个**多 agent 编排器**:本地 daemon + 多端客户端(desktop / mobile / web / CLI),**统一管理多个 coding agent**(切换 provider / worktree / review / preview / ship),**跨设备**(iOS + Android + macOS + Windows + Linux + Web)。

## 5 大核心特性

| 特性 | 描述 |
|---|---|
| **Self-hosted** | Agent 跑在你的机器上(用你的 tools / configs / skills) |
| **Multi-provider** | Claude Code / Codex / Copilot / OpenCode / Pi (+34 more) |
| **Voice control** | Dictate tasks,talk through problems |
| **Cross-device** | iOS / Android / desktop / web / CLI |
| **Privacy-first** | 无 telemetry / tracking / 强制登录 |

## 跟 iswiki 现有工具的关系

| 工具 | 关系 |
|---|---|
| [mattpocock-skills](mattpocock-skills.md) | 🟡 都是 "skill-driven agent" 生态 |
| [i-have-adhd](i-have-adhd.md) | 🟡 都是 SKILL.md 风格,被 Paseo 用 |
| [codex-security](codex-security.md) | 🟢 Codex 是 Paseo 的 provider之一 |
| [qoder-security](qoder-security.md) | 🟡 类似 multi-provider IDE 思路 |
| [remix-reference-video-prompt](remix-reference-video-prompt.md) | ⚪ 视频生成 |
| [mapcn](mapcn.md) | ⚪ 地图 |
| [kage](kage.md) | ⚪ Web 艺术 |
| [Logue](Logue.md) | ⚪ MLX AI |

## 12 个 packages (monorepo)

```
packages/
├── app/                          # main app?
├── cli/                          # command line (@getpaseo/cli)
├── client/                       # TS SDK (@getpaseo/client)
├── desktop/                      # Desktop app (Electron?)
├── expo-two-way-audio/           # mobile voice
├── highlight/                    # syntax highlighting
├── plugin/                       # plugin system (NEW in 0.5.0)
├── protocol/                     # wire protocol
├── relay/                        # E2E encrypted relay for cross-device
├── server/                       # daemon (server-side)
└── website/                      # docs site (Astro + Wrangler)
```

## 5 大功能模块 (from SKILL.md)

### 1. Projects (CLI)
```bash
paseo project create [path]
paseo project ls
paseo project rename <id> <name>
paseo project delete <id>
```

### 2. Workspaces (MCP)
- `create_workspace` — isolation: `local` 或 `worktree`
  - worktree modes: `branch-off` / `checkout-branch` / `checkout-pr`
- `list_workspaces`
- `archive_workspace` — 删除,但 local dir 保留
- `rename_workspace`

### 3. Workspace scripts (configured in `paseo.json`)
- `list_workspace_scripts` / `start_workspace_script` / `stop_workspace_script`

### 4. Agents (核心!)
- **`create_agent`** — required: `title`, `provider`, `initialPrompt`  
  provider format: `claude/opus`, `codex/gpt-5.4`
- `send_agent_prompt` — follow-ups to existing agent
- `update_agent` — runtime changes
- `list_agents` / `archive_agent`

### 5. Agent profiles + provider discovery
- `list_profiles` — named launch bundles
- `list_providers` / `list_models` / `inspect_provider`
- Codex fast mode: `settings: { features: { "fast_mode": true } }`

### 6. Schedules + heartbeats
- `create_schedule` — cron-based agents
- `create_heartbeat` — cron-based prompts to you (PR/build babysitting)
- `delete_heartbeat`

## 安装 + 启动

```bash
# CLI
npm install -g @getpaseo/cli
paseo
# 启动本地 daemon + 问你是否 enable E2E encrypted relay

# Docker
docker run -d --name paseo \
  -p 6767:6767 \
  -e PASEO_PASSWORD=change-me \
  -v "$PWD/paseo-home:/home/paseo" \
  -v "$PWD:/workspace" \
  ghcr.io/getpaseo/paseo:latest

# Desktop app (recommended)
# Download from paseo.sh/download
# Open app → daemon 自动启动
# 配手机: Settings → your host → Pair Device
```

## 4 大 CLI 示例

```bash
# Run agent with specific provider + worktree
paseo run --provider claude/opus-4.6 "implement user auth"
paseo run --provider codex/gpt-5.5 --worktree feature-x "implement feature X"

# Stream live output
paseo attach abc123

# Follow-up task
paseo send abc123 "also add tests"

# Run on remote daemon
paseo --host workstation.local:6767 run "run the full test suite"
```

## TypeScript SDK

```ts
import { createPaseoClient } from "@getpaseo/client";

const client = createPaseoClient({ url: "ws://127.0.0.1:6767/ws" });
await client.connect();

const agent = await client.agents.create({
  config: { provider: "codex/gpt-5.5" },
  cwd: "/Users/me/dev/storefront",
  prompt: "Review the current diff and name the riskiest change.",
});

const result = await agent.waitForFinish();
console.log(result.lastMessage);

await client.close();
```

## Skills (给 agent)

Paseo 自己也用 skill 体系,**教你 agent 如何 orchestration**:

```bash
npx skills add getpaseo/paseo
```

6 个 skills in `skills/`:
- `paseo-advisor`
- `paseo-committee`
- `paseo-handoff`
- `paseo-help`
- `paseo-plugin`
- `paseo`

## 5 个"工作场景"(Homepage)

| 场景 | 描述 |
|---|---|
| **Orchestrate from desk and phone** | 桌面启动,手机继续 |
| **Paseo Hub (NEW)** | GitHub / Slack / Discord 集成 |
| **Review, preview, ship** | fix-auth → worktree → Preview → Review → Commit → PR → Merge |
| **Fully scriptable** | CLI / cron / schedules / heartbeats |
| **Loved by developers** | User testimonials |

## Recent Updates (v0.5.0-beta series)

### v0.5.0-beta.4 (2026-08-21)
- ✅ Plugin themes in Settings → Appearance
- ✅ **MiniMax Code** added to one-click ACP provider catalog (#3457)
- ✅ Project filtering in sidebar
- ✅ Active-turn steering for OpenCode (#3580)
- ✅ Separate content text sizing
- ✅ Live sheets for tool-call groups

### v0.5.0-beta.1 (2026-08-18)
- ✅ **Plugin system** (experimental)
- ✅ Workspace labels
- ✅ **Steering for Codex and Claude** (send into running turn instead of interrupting)

## 5 大 Plugins (示例)

`.plugins/`:
- `catppuccin` (theme)
- `linear` (Linear 集成)
- `local-plugin`

## 5 大 Server Deps (核心 provider SDKs)

```json
{
  "@agentclientprotocol/sdk": "^0.17.1",   // ACP 协议
  "@anthropic-ai/claude-agent-sdk": "^0.3.220",  // Claude Code
  "@anthropic-ai/sdk": "^0.104.2",        // Anthropic API
  "openai": "^6.44.0",                     // Codex
  "pino": "^10.2.0"                        // logger
}
```

→ **Provider SDKs + ACP protocol** = 抽象层

## 6 个 Provider 文档示例 (from SKILL.md)

```ts
// Provider format
provider: "claude/opus-4.6"
provider: "codex/gpt-5.5"
provider: "claude/opus"     // shorthand
provider: "openai/gpt-5"    // Codex GPT-5

// Codex fast mode
settings: {
  features: { "fast_mode": true }
}
```

## 4 大 README README 引用项目 (footer)

- **Claude Code** · Codex · OpenCode · All providers
- **Conductor** · Superset · OpenChamber · Happy Coder · Codex App · Claude Desktop · OpenCode Desktop

→ **竞品**:Conductor (早期 pioneer) / Superset / OpenChamber 等

## 12 个 topics on GitHub

```
ade · agents · android · claude-code · codex · copilot ·
developer-tools · hermes · ios · linux · mobile · orchestration ·
pi · windows
```

**关键发现**:`hermes` 在 topics — 可能是 Hermes agent 兼容 / sponsor / 同名项目。**没有 README 提**,所以**只是关键词共现**(可能是 GitHub 自动建议)。

## 4 大国际化 README

- `README.md` (英文)
- `README.zh-CN.md` (简体中文)
- `README.ja.md` (日本語)
- `README.ko.md` (한국어)

## 4 大 Philosophy (README 引述)

> "It's built around **freedom of choice**: use the provider you want, run it on your **own infrastructure**, and keep your workflow portable."

> "Self-hosted: Agents run on your machine with your full dev environment. Use your tools, your configs, and your skills."

> "Multi-provider: Claude Code, Codex, Copilot, OpenCode, and Pi through the same interface. **Pick the right model for each job.**" 

> "**Privacy-first**: Paseo doesn't have any telemetry, tracking, or forced log-ins."

## 类似 / 对比项目

| 项目 | 同样 | 区别 |
|---|---|---|
| **Claude Desktop** | Desktop app | 只能 Claude |
| **Codex App** | Desktop app | 只能 Codex |
| **OpenCode Desktop** | Desktop + 多 provider | open source only |
| **Conductor** | Multi-provider | Mac-only (早期) |
| **Superset** | Multi-provider | 商业模式 |
| **OpenChamber** | Multi-provider | - |
| **Happy Coder** | Multi-provider | Mobile-first |

→ **Paseo 优势**:跨 iOS/Android + 自托管 + privacy-first + 无强制登录

## 风险与限制

- **Other license** (custom) — 非 Apache/MIT,商业使用前 read LICENSE
- **v0.5.0-beta** — 还在 beta 阶段(快速迭代)
- **Plugin system experimental** — 不稳定 API
- **No telemetry** = 你自己监控 + debug
- **954 open issues** — 项目活跃,但维护负担大
- **Provider SDK breaking changes** — 依赖 Anthropic / OpenAI SDK 升级
- **Mobile 性能** — Android workspace-switch stalls (已在 fix)
- **iOS codex 字符 retain** — 已 fix (commit 0.5.0-beta.3)
- **依赖 min SDK** — 需要 Node 22+ / Python 3 / Docker 任意

## 跟 Hermes 的关系

**Hermes agent 不在 Paseo README/providers**。
**GitHub topics `hermes` 是 GitHub 自动共现**(Hermes-agent / Hermes JS 等同类项目)。
Paseo 跟 Hermes 都是 **agent ecosystem**,但 **不是互操作**(no shared protocol):
- Hermes:CLI / Discord / Telegram gateway + skills/plugins
- Paseo:Desktop / mobile orchestration + cross-provider agent management

**未来可能**: Paseo 写 Hermes plugin? Hermes 写 Paseo plugin? 都可能 — 双方都支持 plugin + skill systems。

## 适用人群

| ✅ 适合 | ❌ 不适合 |
|---|---|
| **多 provider 用户**(Claude + Codex + Copilot) | 单 provider 死忠 |
| **Desktop + mobile 切换** | 只在固定一台机器用 |
| **Privacy / 自托管 需求** | 想要 SaaS + 同步 |
| **复杂 worktree / PR 工作流** | 单文件 demo |
| **iOS / Android 用户** | 纯 Linux CLI 用户 |
| **CLI 自动化**(cron / heartbeat) | 一次性脚本 |

## 类似 iswiki 工具对比

| 工具 | 关系 |
|---|---|
| [codex-security](codex-security.md) | Codex **provider** in Paseo |
| [qoder-security](qoder-security.md) | 类似 multi-provider IDE 思路 |
| [mattpocock-skills](mattpocock-skills.md) | 都是 "skill-driven agent" |
| [i-have-adhd](i-have-adhd.md) | 都是 SKILL.md 风格 |

## 关联资料

- 仓库: <https://github.com/getpaseo/paseo>
- 官网: <https://paseo.sh>
- Docs: <https://paseo.sh/docs>
- Changelog: <https://github.com/getpaseo/paseo/releases>
- Twitter: <https://x.com/moboudra>
- Discord: <https://discord.gg/jz8T2uahpH>
- Reddit: <https://www.reddit.com/r/PaseoAI/>
- Docker: `ghcr.io/getpaseo/paseo:latest`
- SKILL.md: <https://github.com/getpaseo/paseo/blob/main/skills/paseo/SKILL.md>
- Plugin SDK: `@getpaseo/plugin`
- TS SDK: `@getpaseo/client`