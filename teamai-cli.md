# teamai-cli (Tencent) — 团队级 AI Agent Harness

> 学习笔记 · 调研时间 2026-08-22
> 仓库: <https://github.com/Tencent/teamai-cli>
> 作者: Tencent (Apache 2.0 / MIT)
> ⭐ 533 · 51 forks · TypeScript · 3 MB repo · 13 open issues · 89 commits
> Created 2026-04-27 · Updated 2026-08-22 (active) · v0.20.0

## 一句话定位

**"The team harness for AI agents"** —— 腾讯开源的 **Git-native 团队 AI 工具管理 CLI**。在一个 git 仓里集中管**技能 / 规则 / 文档 / 经验**,通过 `push → MR → merge → pull` 流,自动同步给团队成员的 Claude Code / Codex / CodeBuddy / WorkBuddy 等多个 AI 工具。

## 5 大核心价值

| 价值 | 描述 |
|---|---|
| **Git-native** | 技能/规则/文档/version 全部走 git,**版本控制 + Code Review + MR** |
| **Multi-agent** | 一个团队仓,自动注入到 Claude Code / Codex / CodeBuddy / WorkBuddy |
| **Team-shared** | 多人协作者 skill 共享,**避免重复造轮子** |
| **Knowledge base** | 自动 session learning + BM25 + codebase graph recall |
| **Single source of truth** | 全团队**统一 harness**,不用每人手动 install skill |

## 4 大适应场景

| 场景 | teamai-cli 解决方案 |
|---|---|
| **多人团队 coding agent 配置散落** | 团队 git 仓,统一管 |
| **AI skill 升级靠 "you know, run this command"** | 自动 pull on session start |
| **最佳实践靠 "doc wiki"** (低使用率) | 自动 session share + recall |
| **项目级 / 用户级 / 跨团队 skill 冲突** | 三层 scope(user / project / inherit) |

## 完整架构 (README 内容提取)

### 4 大组件

| 组件 | 作用 |
|---|---|
| **`teamai init`** | 初始化:OAuth + link repo + 注册成员 + inject hooks |
| **`teamai push`** | 推本地资源 → 创建分支 + MR |
| **`teamai pull`** | SessionStart hook 自动拉最新资源 + 注入到本地 AI tool |
| **`teamai recall`** | 搜索团队知识库 (BM25 + graph-boost) |

### 3 种 scope

```bash
# 1) Project-scope (默认) - 资源装在项目目录
teamai init https://github.com/yourorg/yourrepo

# 2) User-scope - 资源装在 ~/
teamai init https://github.com/yourorg/yourrepo --scope user

# 3) 3 层 - 项目活跃 + 继承 user-scope 安全资源
teamai init https://github.com/yourorg/project-repo --inherit-user-scope
```

### 4 种 init 模式

```bash
# Standard: 团队仓
teamai init https://github.com/yourorg/yourrepo

# Single-repo: 项目仓 = 团队仓
teamai init .
teamai init . --agent claude,codex

# 从 template
teamai init https://github.com/teamai-hub/template-name
```

## 完整工作流 (`push → MR → pull`)

```
teamai push → create branch + MR
                  ↓
       reviewer approves + merges
                  ↓
       SessionStart hook → teamai pull
                  ↓
       同步到本地 AI 工具:
         ~/.claude/skills/
         ~/.codex/skills/
         ~/.cursor/skills/
         ~/.codebuddy/skills/
```

## 6 大 Feature 深度(借鉴目标)

### 1. Team Hooks (跨工具 hook 注入)

**`hooks/hooks.yaml`**:
```yaml
hooks:
  - id: block-secret
    description: Scan for secrets before commit
    event: PreToolUse
    matcher: Bash
    command: 'bash -lc "~/.teamai/team-scripts/scan-secret.sh" || true'
    tools: [claude, cursor]
```

**CLI**:
```bash
teamai hooks list     # 列出 effective hooks
teamai hooks inject   # 重新注入到所有 AI tool
teamai hooks remove   # 移除
```

### 2. Team MCP Servers (中央 mcp.yaml)

```yaml
# mcp/mcp.yaml
servers:
  - name: gpu-analysis
    transport: http
    url: https://example.com/api/mcp
    headers:
      Authorization: Bearer ${GPU_...KEN}
```

`teamai pull` 自动写到各工具的 native config。

**关键**:`${VAR}` 解析 — secrets 不进 git

### 3. Cross-Team Skill Subscription

```bash
teamai source add https://github.com/other-team/teamai-public.git --name other-team
teamai source list
teamai source browse other-team
teamai source remove other-team
```

→ 订阅**其他团队**的公开 skill 仓,**自动同步**

### 4. Automatic Friction Scoring + Learnings

**Stop hook 自动评分**:
- **friction signal**: 你 interrupt AI / 拒绝 tool / AI retry failing tool
- **Long-but-routine session** → 不 trigger
- **High-friction session** → AI 建议:`/teamai-share-learnings`

```text
[teamai] This session may contain a problem worth documenting: 
you interrupted the AI twice, the AI retried failing tools 8 times.

Task: Fix duplicate project-level Hook injection

Consider running /teamai-share-learnings to summarize what you learned
and share it with your team.
```

→ **自动 capture 团队踩坑经验**

### 5. Team Knowledge Recall (BM25 + graph-boost)

```bash
teamai recall "port conflict"
# → 1/2 MR review caught a port-conflict bug ★1 [user]
# → 2/2 Deployment configuration best practices [project]
# → Matched: conflict | Missing: port
```

**Search 涵盖 4 类**:
- **learnings** (session 经验)
- **docs** (团队文档)
- **rules** (编码规则)
- **skills** (每个 SKILL.md)

**Ranking**: BM25 + graph-boost

### 6. Codebase Knowledge Graph (`teamai import`)

```bash
teamai import --from-repo https://github.com/org/repo
teamai import --from-org myorg       # 批量
teamai codebase --lint                # 健康检查
```

**Graph 内容**:
- Components
- Interfaces
- Configs
- Cross-repo import edges

→ **`teamai recall` 用 graph-boost re-ranking**

## 内置 2 个 skills(详细结构)

```
skills/
├── team-wiki-codebase/                          # 知识库 skill
│   ├── SKILL.md                                 # 入口
│   ├── README.md
│   ├── references/
│   │   ├── agents/
│   │   │   ├── graph-rag-agent.md
│   │   │   └── kb-doc-generator.md
│   │   ├── methodology/                         # 4 阶段方法论
│   │   │   ├── phase0-collection.md
│   │   │   ├── phase1-reverse-engineering.md
│   │   │   ├── phase2-document-types.md
│   │   │   ├── phase3-ai-enhancement.md
│   │   │   └── phase4-quality.md
│   │   └── templates/
│   │       └── project-overview.md
│   └── scripts/
│       ├── scan_repo.py
│       └── validate_kb.py
└── teamai-share-learnings/SKILL.md              # session sharing skill

agents/
└── teamai-recall.md                              # recall subagent
```

## 完整 CLI 命令表(20+)

| 命令 | 描述 |
|---|---|
| `teamai init` | 初始化: OAuth / link repo / 注入 hooks |
| `teamai pull` | 拉资源 + 注入 |
| `teamai push` | 推本地 → MR |
| `teamai status` | 本地 vs 远端 diff |
| `teamai contribute` | 分享 session 经验 |
| `teamai recall <q>` | BM25 + graph search |
| `teamai recall enable/disable/status` | toggle |
| `teamai import` | import knowledge (--dir, --from-repo, --from-org, --from-mr, --from-iwiki) |
| `teamai codebase --lint` | graph health |
| `teamai ci extract-mr --url` | CI: extract from MR + post comment |
| `teamai members` | list team members |
| `teamai roles` | manage roles + namespaces |
| `teamai skill exclude add/remove/list` | exclude unwanted skills |
| `teamai source` | cross-team subscriptions |
| `teamai remove <type> <name>` | remove resource + MR |
| `teamai session save` | privacy-scrubbed session summary |
| `teamai digest` | weekly team usage digest |
| `teamai doctor` | diagnose config issues |
| `teamai uninstall` | 移除所有 teamai 资源 |
| `teamai hooks list/inject/remove` | hooks 管理 |

**Global options**: `--dry-run`, `--verbose`

## 6 大 **可借鉴到 Fireside** 的特性

### 借鉴 #1: 多 AI tool 自动注入 ⭐⭐⭐

**teamai-cli 做**:
- `teamai init` → 自动写 `.claude/settings.json` / `.codex/hooks.json`
- `teamai pull` → SessionStart hook 自动拉最新

**Fireside 可抄**:
- **当前**:Fireside 是 **Go + embedded dashboard + loopback only**
- **可加**:`fireside setup --with-teamai` 集成
- **实际建议**:**teamai-cli 已经支持多 tool 注入**,Fireside 只需**支持作为 teamai 的"目标 tool"**(提供 `.fireside/hooks.json` schema)
- **具体**:写一个 **teamai adapter for Fireside** — teamai 知道 `fireside` agent 存在

### 借鉴 #2: Team hooks cross-tool ⭐⭐⭐

**teamai 做**:`hooks/hooks.yaml` 集中定义,自动注入 4 个 tool

**Fireside 可抄**:
- 当前:Fireside 没有"统一 hook 系统"
- 建议:**Fireside 暴露 `/.fireside/hooks.yaml` schema**:
  ```yaml
  hooks:
    - id: log-broadcast
      event: msg.broadcast
      command: "tee /var/log/fireside/broadcast.log"
  ```
- **益处**:团队自定义 hook,自动 apply 到所有 Fireside 部署

### 借鉴 #3: Skill sync 协议 ⭐⭐⭐

**teamai 做**:`teamai push → MR → pull` 把 skill 推到团队,自动 apply

**Fireside 可抄**:
- 当前:Fireside 没有 skill 概念
- 建议:**Fireside skill model**:
  - `/skills` 目录(跟 Hermes / opencode 兼容)
  - `.fireside/skills/{name}/SKILL.md` schema
  - `fireside skill install <github-url>` 类似 `teamai source add`
- **益处**:Fireside 接入 1000+ 现有 agentskills.io 库(mattpocock-skills, anthropic-cybersecurity-skills 等)

### 借鉴 #4: Session friction 自动 capture ⭐⭐⭐

**teamai 做**:Stop hook 自动评分 session,**建议 share learnings**

**Fireside 可抄**:
- 当前:Fireside 没有 persistent session 概念
- **建议**:**Fireside session end hook**:
  ```yaml
  hooks:
    - id: session-friction
      event: session.end
      command: "fireside-cli friction-score"
  ```
- **friction signals**:
  - 用户 "stop" AI mid-task
  - 用户拒绝 tool call
  - AI retry 同一 tool >3 次
  - 用户手动修正 AI 输出
- **益处**:Sprint 1.5 准备 — Fireside session review 直接进 backlog

### 借鉴 #5: Knowledge recall (BM25 + graph) ⭐⭐

**teamai 做**:`teamai recall` 搜索 learnings/docs/rules/skills

**Fireside 可抄**:
- 当前:Fireside 没有"团队知识库"
- **建议**:**Fireside team knowledge**:
  - `.teamai/` 类似 `.fireside/` 目录
  - session friction 自动写入 `.fireside/learnings/`
  - `/recall` 命令给 agent 调阅
- **益处**:Fireside agents 获得"团队记忆"—— Sprint 1 之前的问题不再重犯

### 借鉴 #6: CI 集成 (extract-mr from MR) ⭐⭐

**teamai 做**:`teamai ci extract-mr --url` 在 CI 中跑,**自动从 MR 提取 knowledge**

**Fireside 可抄**:
- 当前:Fireside 没有 CI hook
- 建议:**Fireside CI action**:
  ```yaml
  # .github/workflows/fireside-learn.yml
  on: pull_request
  jobs:
    learn:
      steps:
        - run: fireside-cli ci extract-mr --url ${{ github.event.pull_request.html_url }}
  ```
- **益处**:每个 PR 自动提取 knowledge → 团队 recall 增强

## 7 大 不建议借鉴

| ❌ 不适合 | 原因 |
|---|---|
| **Tencent 内部绑定** | teamai 是腾讯专用,内部 mirror `git.woa.com` (TGit) |
| **复杂 MR flow** | Fireside 是 single user,不需要 MR review |
| **CI 深度集成** | Fireside 不跟 git workflow |
| **Codebase graph** | Fireside 目标不是 codebase analysis |
| **B2B 团队版定位** | Fireside 定位是 personal AI agent |
| **simple-git 强依赖** | Fireside 不需要 git 仓 |
| **multi-agent 同步** | Fireside 是单 app,单 agent |

## 跟 iswiki 现有工具对比

| 工具 | 类似 | 区别 |
|---|---|---|
| [mattpocock-skills](mattpocock-skills.md) | 25 skills 集合 | 团队/个人,无 git 协作 |
| [i-have-adhd](i-have-adhd.md) | 单一 skill | 跨 8 AI 工具 |
| [paseo](paseo.md) | multi-agent 编排 | 编排 vs 团队 sync |
| [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md) | 817 skills | 个人 install,无团队仓 |
| [codex-security](codex-security.md) | 单 tool | CLI scanner |

## 4 大类似项目

| 项目 | 定位 | 区别 |
|---|---|---|
| **agentskills.io** | 技能标准 | 没有团队 sync 工具 |
| **OpenAI Codex CLI** | 单 AI tool | 不管团队 |
| **Claude Code plugins** | Anthropic marketplace | 中心化 vs git-distributed |
| **SST / SSTeam** | dev 平台 | 通用 vs AI-specific |

## 5 大风险与限制

- **Tencent 内部优先** — issues 处理可能偏内部
- **"Other" license on GitHub** — README 标 MIT,但需 confirm
- **CLI 复杂度高** — 20+ 命令,学习曲线
- **Multi-tool 兼容性** — 持续维护负担(每个 tool 版本变化)
- **Git-only** — 不能用其他 source control

## 关联资料

- 仓库: <https://github.com/Tencent/teamai-cli>
- npm: <https://www.npmjs.com/package/teamai-cli>
- 模板 org: <https://github.com/teamai-hub>
- 中文 README: `README.zh-CN.md`
- Discord: <https://discord.gg/gervEZm58g> (user) / <https://discord.gg/DeHHxPnfZF> (dev)
- License: MIT
- 内部 mirror: `@tencent/teamai-cli` on tnpm

## 🎯 TL;DR (你问的"Fireside 借鉴")

| Feature | 借鉴价值 | 实现成本 |
|---|---|---|
| **多 AI tool 自动注入** | ⭐⭐⭐ | 中(写 .fireside/hooks.json schema + teamai adapter) |
| **Team hooks cross-tool** | ⭐⭐⭐ | 低(Sprint 1.5 即可做) |
| **Skill sync 协议** | ⭐⭐⭐ | 中(可一次性接入 1000+ skills 库) |
| **Session friction 自动 capture** | ⭐⭐⭐ | 中(集成到 Sprint review) |
| **Knowledge recall (BM25 + graph)** | ⭐⭐ | 高(需要 graph infra) |
| **CI 集成 (extract-mr)** | ⭐⭐ | 低(单一 action) |

**Top 3 推荐**(按 ROI 排序):
1. **Skill sync 协议** — 接入 agentskills.io 生态,mattpocock + anthropic + 1000+ libraries
2. **Session friction 自动 capture** — 写 .fireside/learnings/,**直接 feed backlog**
3. **Team hooks cross-tool** — `.fireside/hooks.yaml` schema,加 `fireside hook` 命令

== **3 个** 是"Sprint 1 之后增量"→ Sprint 1.5 / 2 候选。
== **CI 集成** 可放 v0.3 单独做。
== **Knowledge graph** 复杂度高,跳过。