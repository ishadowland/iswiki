# mattpocock/skills — Matt Pocock 的 "Real Engineering" Skills 集合

> 学习笔记 · 调研时间 2026-08-15
> 仓库: <https://github.com/mattpocock/skills>
> 文档: <https://skills.sh/mattpocock/skills>
> 作者: Matt Pocock (Total TypeScript / aihero.dev · 60,000+ newsletter subscribers)
> License: MIT · ⭐ 218k · 18.8k forks · 425 commits · 89 branches

## 一句话定位

**"Skills For Real Engineers — not vibe coding"** —— Matt Pocock 把他在 Total TypeScript / aihero.dev 工作中**每天用的 AI agent skills** 直接从自己的 `.agents/` 目录开源出来。**2 维分类**(User-invoked / Model-invoked × Engineering / Productivity),覆盖软件工程的**4 大常见失败模式**(对齐 / 简洁 / 反馈 / 设计)。

## 跟 vibe-coding 工具对比

| 维度 | GSD / BMAD / Spec-Kit | **mattpocock/skills** |
|---|---|---|
| 哲学 | Agent **owns** 整个流程 | Agent **assists** ,**用户保留控制** |
| 流程 | 锁定端到端 | 小而**可组合**, 用户挑着用 |
| 适配性 | 单一流 | **decade 经验 + 跨语言** |
| 修改 | 不透明 | 用户可 hack, modify |
| 模型绑定 | 特定 agent | **any model** |
| 失败模式覆盖 | 通常单点 | **4 个 failure modes** 全覆盖 |

## 4 个失败模式 + 对应 Skill (核心哲学)

### #1 Agent 没做你想要的事 → `/grill-me` + `/grill-with-docs`

**问题**: 最大失败模式 = **misalignment**。Agent 不知道你想要什么,写完发现不对。

**Fix**:
- [`/grill-me`](skills/productivity/grill-me/) — 通用 grilling session (非代码)
- [`/grill-with-docs`](skills/engineering/grill-with-docs/) — **同时建立领域模型** (domain model + CONTEXT.md + ADR inline)

> "The fix is a **grilling session** - getting the agent to ask you detailed questions"
> — Matt Pocock

### #2 Agent 太啰嗦 → `/grill-with-docs` (UBL)

**问题**: 20 字能说清的,agent 用 200 字。Agent 进了项目就要学 jargon。

**Fix**: **Ubiquitous Language (UBL)** — `CONTEXT.md` 建立共享语言:
- **BEFORE**: "There's a problem when a lesson inside a section of a course is made 'real'"
- **AFTER**: "There's a problem with the materialization cascade"

→ **每个 session 节省 tokens** + 代码导航更容易 + 命名一致

### #3 代码不 work → `/tdd` + `/diagnosing-bugs`

**问题**: 即使对齐了,agent 写出来还是 crap — 因为**没 feedback loop**。

**Fix**:
- [`/tdd`](skills/engineering/tdd/) — **red-green-refactor** loop,vertical slice 一次一个 feature
- [`/diagnosing-bugs`](skills/engineering/diagnosing-bugs/) — **disciplined diagnosis loop** (red on this bug → minimise → hypothesise → instrument → fix → regression-test)

### #4 写出来是 big ball of mud → `/improve-codebase-architecture` + `/to-spec`

**问题**: Agent 加速 coding,**也加速 software entropy**。

**Fix**:
- [`/to-spec`](skills/engineering/to-spec/) — quizzes 你要 touch 哪些模块, 然后**生成 spec**
- [`/improve-codebase-architecture`](skills/engineering/improve-codebase-architecture/) — 扫描 codebase, 找出 **deepening opportunities** (深模块),输出可视化 HTML report,grill through 候选

> "It is a survey, not a rescue: on a genuinely old codebase it will find real candidates, but it won't untangle the mud for you."

## 2 维分类 (Engineering × Productivity × User/Model invoked)

### Engineering

**User-invoked** (用户主动 / 编排):

| Skill | 用途 |
|---|---|
| **ask-matt** | Router — 问哪个 skill 适合你的情况 |
| **grill-with-docs** | Grilling + 领域模型 + CONTEXT.md + ADR inline |
| **triage** | Issue 状态机 (triage roles) |
| **improve-codebase-architecture** | 扫 codebase + 可视化 HTML report |
| **setup-matt-pocock-skills** | 一次性配置 (issue tracker / labels / doc layout) |
| **to-spec** | 当前对话 → spec → issue tracker |
| **to-tickets** | Plan/spec → tracer-bullet tickets (含 blocking edges) |
| **implement** | Spec/tickets → TDD 实施 + code-review |
| **wayfinder** | **Huge work** → shared map of decision tickets |

**Model-invoked** (agent 自动 reach for):

| Skill | 用途 |
|---|---|
| **prototype** | 一次性 prototype (单 HTML file 或多 UI 变体) |
| **diagnosing-bugs** | 难的 bug / 性能 regression,严格循环 |
| **research** | 高可信 primary sources + 引用 Markdown |
| **tdd** | red-green-refactor |
| **domain-modeling** | Active domain model + glossary + CONTEXT.md + ADRs |
| **codebase-design** | Deep modules: **a lot of behavior behind a small interface** |
| **code-review** | **2-axis review** (Standards + Spec) - parallel sub-agents |
| **resolving-merge-conflicts** | 逐 hunk 解决,**never `--abort`** |
| **wizard** | Interactive bash wizard (人要做的事) |

### Productivity

**User-invoked**:

| Skill | 用途 |
|---|---|
| **grill-me** | Grilling (无 doc / 非代码) |
| **handoff** | 当前对话 → handoff 文档 |
| **teach** | 多 session teaching (stateful workspace) |
| **to-questionnaire** | Decision → Markdown questionnaire |
| **wait-what** | 消息没落地 → **plain-English re-pitch** with CONTEXT.md |

**Model-invoked**:

| Skill | 用途 |
|---|---|
| **grilling** | **Reusable interview primitive** (被 grill-me/grill-with-docs/triage/wayfinder/improve-codebase-architecture 复用) |
| **writing-for-agents** | 写给 agents 的文档 (skills / AGENTS.md / CLAUDE.md) |

## 2 种安装路径 (核心选择)

> "Two ways in, two philosophies."

### 路径 A: Claude Code plugin (managed, read-only)

```bash
# 或 session 内:
/plugin install mattpocock-skills
```

- 在 Claude Code **官方 marketplace** — 装上自动更新
- **subscribe, not fork** — read-only bundle
- 用户不修改代码

### 路径 B: skills.sh (editable)

```bash
npx skills@latest add mattpocock/skills
```

- **让你选** 哪些 skills + 哪些 agents
- 文件 copy 到项目,**你可以 hack**
- 手动 `npx skills update` 拉新版本

**不能两个都装** — "Installing both leaves you with every skill twice"

## 3 步上手

### Step 1: 装

(选 A 或 B)

### Step 2: 跑 `/setup-matt-pocock-skills` (每个 repo 一次)

问用户 3 个问题:
- 用哪个 issue tracker (GitHub / Linear / 本地文件)
- `/triage` 用什么 labels
- docs 存在哪里

### Step 3: 完成 — 开始用

## 核心设计哲学 (Matt 的话)

> "These skills are designed to be **small, easy to adapt, and composable**."
> "They **work with any model**."
> "They're based on **decades of engineering experience**."
> "Hack around with them. Make them your own. Enjoy."

## 5 个最 popular skills (Matt 标注)

1. **`/grill-me`** / **`/grill-with-docs`** — "Most popular skills"
2. **`/tdd`** — TDD discipline
3. **`/diagnosing-bugs`** — Bug debugging loop
4. **`/improve-codebase-architecture`** — Code quality survey
5. **`/to-spec`** + **`/to-tickets`** — Planning

## 高级设计模式

### "Tracer-bullet tickets" (to-tickets)

不是"完全计划再开工",而是:
- 拆 plan → tickets,每个 ticket 声明 **blocking edges**
- 写在本地文件 OR issue tracker (native blocking links)
- 一次一个 ticket,顺着 edges 解

### "Wayfinder" (Huge work)

> "Plan a huge chunk of work, more than one agent session can hold, as a **shared map of decision tickets** on the issue tracker — resolve them one at a time until the way to the destination is clear."

→ **跨 session 持久规划** — 像 GPT-4 / Codex 的"超长 planning"

### "Grilling primitive"

`grilling` (model-invoked) 是 **reusable interview primitive**,被:
- `grill-me` (user-invoked)
- `grill-with-docs` (user-invoked)
- `triage` (user-invoked)
- `wayfinder` (user-invoked)
- `improve-codebase-architecture` (user-invoked)

**复用** — 一个底层 interview loop,**5 个上层 skill 各自封装特定 grilling 场景**

## 文件结构

```
mattpocock/skills/
├── README.md
├── CHANGELOG.md        ← versioned (changesets)
├── CLAUDE.md           ← symlink (for Claude Code)
├── AGENTS.md           ← symlink (for Codex)
├── CONTEXT.md          ← 他自己项目的 domain model
├── .agents/            ← Codex-native
│   ├── adr/            ← 18 个 ADR (架构决策记录)
│   └── skills/
├── .claude-plugin/     ← Claude Code plugin
├── skills/
│   ├── engineering/    ← 18 个 engineering skills
│   └── productivity/   ← 7 个 productivity skills
├── docs/               ← 站点生成
├── scripts/            ← 工具脚本
└── .out-of-scope/      ← 设计为 out-of-scope 的 ideas
```

**Symlinks** (CLAUDE.md / AGENTS.md):
- Matt 让 **同一个文件同时供 Claude Code + Codex 读**
- 1 份 skills,2 个 agent 系统

## Changesets + Versioning

- 每个 skill **独立 versioned** (changesets)
- `npx skills update` 拉新版本时 **only changed skills**
- 详细 changelog 在 `CHANGELOG.md`

## 18 个 Engineering Skills 详细

| # | Skill | Type | Purpose |
|---|---|---|---|
| 1 | ask-matt | User | Router |
| 2 | grill-with-docs | User | Grilling + domain model |
| 3 | triage | User | Issue 状态机 |
| 4 | improve-codebase-architecture | User | Deepening scan |
| 5 | setup-matt-pocock-skills | User | 一次性 setup |
| 6 | to-spec | User | Conversation → spec |
| 7 | to-tickets | User | Plan → tickets |
| 8 | implement | User | Build via TDD |
| 9 | wayfinder | User | Huge work planning |
| 10 | prototype | Model | Throwaway prototype |
| 11 | diagnosing-bugs | Model | Disciplined loop |
| 12 | research | Model | Cited research |
| 13 | tdd | Model | red-green-refactor |
| 14 | domain-modeling | Model | Active UBL |
| 15 | codebase-design | Model | Deep modules |
| 16 | code-review | Model | 2-axis parallel |
| 17 | resolving-merge-conflicts | Model | Intent-based resolve |
| 18 | wizard | Model | Interactive bash wizard |

## 适用人群

| ✅ 适合 | ❌ 不适合 |
|---|---|
| **真实工程**(已生产) | vibe coding 玩具 |
| 长生命周期 codebase | 一次性 prototype |
| 多人/多 session 协作 | 单人短 session |
| 想坚持 TDD / design discipline | "Just ship it" 心态 |
| 用 Claude Code / Codex / Cursor | 用 vim + grep |
| 想要**可控** AI 流程 | 想要 "AI 全自动" |

## 风险与限制

- **Massive scope** — 18 + 7 = 25 skills,要 time investment 学会
- **English-first** — 主要 README + docs 是英文,中文翻译看 fork (`mattpocock-skills-zh`)
- **Opinionated** — Matt's specific style,不一定适合你
- **Replaces vs augments** — 不是替你思考,是辅助思考
- **Setup mandatory** — 必须先跑 `/setup-matt-pocock-skills` 才能用工程类
- **Plugin vs editable** — 二选一不能并存

## 安装到 Hermes (2026-08-18)

实际安装到 Hermes coder profile (network recovered):

```
~/.hermes/profiles/coder/skills/productivity/
├── grill-me/                  # user-invoked entry point
│   ├── SKILL.md               # upstream + Hermes frontmatter
│   ├── LICENSE                # MIT
│   └── agents/openai.yaml     # Codex metadata
└── grilling/                  # model-invoked primitive
    ├── SKILL.md               # upstream + Hermes frontmatter
    ├── LICENSE                # MIT
    └── agents/openai.yaml
```

**关键 insight (发现后调整 install)**:
- Matt 上游 `grill-me` 只有 **7 行**(只是 wrapper),真实逻辑在 `grilling` skill
- 所以安装需要 **2 个 skills**(mirror 上游结构)

**Hermes frontmatter 加在保留上游 OpenAI format 之上**:
- `version` / `author` / `license` / `platforms`
- `metadata.hermes.tags` / `related_skills` / `fallback_for_toolsets`
- `upstream.{repo,path,license}` 引用来源

## 类似项目对比

| 项目 | 哲学 | Scope | Stars |
|---|---|---|---|
| **mattpocock/skills** | 可组合 + 小 + 用户控 | 25 skills | 218k |
| GSD (Get-Shit-Done) | Agent owns | 1 大 workflow | - |
| BMAD-METHOD | Agent owns | 1 大 workflow | - |
| Spec-Kit | Agent owns | spec-driven | - |
| Anthropic skills (官方) | Agent assists | 较少 | - |
| OpenAI Codex skills | Agent assists | 较少 | - |

**Matt 的差异化**:
- "用户保留控制" vs 其他"Agent 全包"
- "可组合 + 小" vs "1 大 workflow"
- "Decade 经验 + 跨语言" vs "特定 tech stack"

## 跟其他 iswiki 工具的关系

| 工具 | 关系 |
|---|---|
| [i-have-adhd](i-have-adhd.md) | 🟡 都是 prompt skill,但 i-have-adhd 是输出风格,Matt 的是 workflow |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | 🟡 都是 SKILL.md 级别 prompt,生态类似 |
| [codex-security](codex-security.md) | 🟢 Codex 可装,Matt 也支持 Codex |
| [qoder-security](qoder-security.md) | ⚪ 安全 |
| [i-have-adhd](i-have-adhd.md) | 🟡 都是 skill (前面已提) |
| [remix-reference-video-prompt](remix-reference-video-prompt.md) | 🟡 同样是 prompt skill |

## 关联资料

- 仓库: <https://github.com/mattpocock/skills>
- skills.sh: <https://skills.sh/mattpocock/skills>
- Matt's newsletter (60k subscribers): <https://www.aihero.dev/s/skills-newsletter>
- Total TypeScript: <https://www.totaltypescript.com/>
- Matt Pocock 个人: <https://mattpocock.com/>
- 中文翻译: <https://github.com/devcxl/mattpocock-skills-zh> (213 ⭐)
- OpenCode 包装: <https://github.com/mcdays94/pocock-agents>
- call-matt orchestrator: <https://github.com/KoukkuAi/call-matt>
- Codex 中文插件: <https://github.com/zhangyilin666/mattpocock-skills-zh-CN-codex>

## Skills 生态: 观察

- **Anthropic 官方 skills** (<https://github.com/anthropics/skills>): 较少,偏输出格式
- **OpenAI Codex skills**: `~/.codex/skills/`,system-level
- **Vercel skills / Next.js**: 部分 dev agent 内置
- **Qoder / Cursor**: 部分内置 + 第三方 skills.sh 兼容
- **Kimi**: `kimi.plugin.json` 格式

→ **"SKILL.md 是新 README"** — 每个 AI agent 工具都在 adopt
