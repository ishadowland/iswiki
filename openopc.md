# OpenOPC (HKUDS) — Build Your Personal AI-Native Company

> 学习笔记 · 调研时间 2026-08-24
> 仓库: <https://github.com/HKUDS/OpenOPC>
> 介绍文章: <https://mp.weixin.qq.com/s/gtnbluXZ_fwPKSVH2bNgDQ> ("AI辉" 公众号, 2026-08-23)
> 作者: **HKUDS** (Data Intelligence Lab @ HKU, 香港大学)
> ⭐ 1,456 · 253 forks · Python · **MIT License** · 12 MB · 18 open issues
> Created 2026-07-01 (1.5 个月) · v0.1.0

## 一句话定位

**"Build Your Personal AI-Native Company — Self-Built, Self-Run, Self-Grown"** —— HKUDS 港大实验室开源的 **AI 公司模拟器**。给一个目标,自动起草组织架构 + 招聘 AI 员工 + 派单执行 + 复盘沉淀经验。**Office UI 用 Phaser 游戏引擎做的** (React + Phaser) — 像素风办公室,AI 员工在里面干活实时可见。

## 跟 iswiki 现有工具的关系

| 工具 | 关系 |
|---|---|
| [paseo](paseo.md) | 🟡 都是 multi-agent 编排;Paseo 跨设备,OpenOPC 单组织 |
| [mattpocock-skills](mattpocock-skills.md) | 🟡 都是 skill 体系;Matt 是通用,OpenOPC 是 role |
| [teamai-cli](teamai-cli.md) | 🟡 都是团队/agent 工具;teamai-cli 同步 skill,OpenOPC 自建公司 |
| [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md) | ⚪ 单一垂直 |
| [codex-security](codex-security.md) | ⚪ 安全 |

## 3 Self 框架(核心设计)

| Self | 含义 | 对应"开公司" |
|---|---|---|
| **Self-Built** (自建) | 起草组织架构 + 招聘 AI 员工 | "先招人再干活" |
| **Self-Run** (自运转) | 任务状态机 + 5 种工作模式 | "团队自动推进到交付" |
| **Self-Grown** (自成长) | 复盘 + 经验蒸馏 + 共享 playbook | "干完活 + 经验沉淀" |

## 9 大行业模板 (开箱即用)

```
.opc/config/company_orgs/
├── org_corporate_config.yaml            # 大企业
├── org_cross-border-ecommerce_config.yaml  # 跨境电商
├── org_game-development-studio_config.yaml  # 游戏开发
├── org_quantum_harbor_config.yaml       # 量子(?)
├── org_research-report-studio_config.yaml   # 研报
├── org_software-development_config.yaml  # 软件开发
└── org_vc-investment-firm_config.yaml   # VC 投资
```

投资尽调 / 短视频制作 / 游戏原型 — **官方都放了 demo**。

## 3 大关键工程设计

### 1. 任务依赖 DAG + 并行推进

- **经理拆解任务时定义依赖图**:
  - 无依赖 → **并行**跑
  - 有依赖 → 等前置完成
- **拒绝和阻塞结构化传播**(消灭 Agent 之间"即兴协调"的混乱)
- **"流程纪律比聪明更重要"**

### 2. 两级阻塞处理

- **团队内部阻塞**:
  - 一条 `blocking` 消息自动暂停发送方
  - **激活最能解决它的角色**
- **超出团队权限**:
  - **运行时直接升级到人类老板**
- **人只在真正需要人类判断的时刻被叫进来** — 其余时间不用盯

### 3. 经验复用 = 老员工越用越顺手

- **功劳记到角色头上** + 锅也记到对应角色
- **私有经验档案** (每个员工自己的)
- **共享 playbook** (反复出现的教训升级)
- **新员工入职直接继承** playbook
- **AI 员工的离职率是零,经验只增不减**

## 4 大 "AI 员工" talent library

`.opc/prompts/talent/` 下的**角色 prompt** 库 (sample):

### Academic (学术)
- `academic-anthropologist`
- `academic-geographer`
- `academic-historian`
- `academic-narratologist`
- `academic-psychologist`

### Design (设计)
- `design-brand-guardian`
- `design-image-prompt-engineer`
- `design-inclusive-visuals-specialist`
- `design-ui-designer`
- `design-ux-architect`
- `design-ux-researcher`
- `design-visual-storyteller`
- `design-whimsy-injector`

### Engineering (工程)
- `engineering-ai-data-remediation-engineer`
- `engineering-ai-engineer`
- `engineering-autonomous-optimization-architect`
- `engineering-backend-architect`
- `engineering-cms-developer`
- (...更多)

### Talent Prompt Frontmatter Schema
```yaml
---
name: AI Engineer
description: Expert AI/ML engineer...
color: blue          # 用于 Office UI 颜色
emoji: 🤖            # 用于 office UI 头像
vibe: Turns ML models into production features that actually scale.
---

# AI Engineer Agent
## 🧠 Your Identity & Memory
## 🎯 Your Core Mission
## 🚨 Critical Rules You Must Follow
## 📋 Your Core Capabilities
...
```

→ **每个 talent = 1 个 markdown file** + `color` + `emoji` + `vibe` (前台办公室可见)

## 5 种工作模式 (Self-Run 核心)

| Mode | 含义 |
|---|---|
| **执行** (execute) | AI 员工直接做任务 |
| **委派** (delegate) | 经理派单给下级/外部 |
| **审查** (review) | 验收 + 反馈 |
| **整合** (integrate) | 多员工输出合并 |
| **返工** (revise) | 不达标 → 重新做 |

## Task Mode (单 Agent 工作台)

- 也支持 **Task Mode** — 单 Agent 工作台形态 (无需"开公司")
- **可接** OpenOPC Native / Codex / Claude Code / Cursor / OpenCode
- **当 LobeChat 平替用**
- **产品路径**: 轻度用户先尝单 Agent → 尝到甜头 → 升级成 AI 公司

## 5 大核心依赖 (pyproject.toml)

| Dep | 作用 |
|---|---|
| **litellm==1.82.1** | 统一多 LLM provider 接口 |
| **chromadb>=0.4.0** | Vector DB (RAG / 知识库) |
| **aiosqlite>=0.19.0** | 异步 SQLite (local) |
| **playwright>=1.40** | 浏览器自动化 |
| **mcp>=1.0.0** | **MCP 协议支持** ✓ |

## 11 大 Optional Channels (扩展消息渠道)

`channels-*` extras:
- `telegram` (python-telegram-bot)
- `whatsapp` (websockets)
- `discord` (discord.py)
- `feishu` (lark-oapi) — **飞书** ✓
- `mochat` (python-socketio)
- `dingtalk` (钉钉) ✓
- `email` (空)
- `slack` (slack-sdk)
- `qq` (qq-botpy) ✓
- `matrix` (matrix-nio)
- `channels-all` = 上 10 个合一

→ **完整国内支持**(飞书/钉钉/QQ)+ **国际**(Telegram/Discord/Slack)

## 5 步上手 (官方 quick start)

```bash
# 1) Clone
git clone https://github.com/HKUDS/OpenOPC.git
cd OpenOPC

# 2) Python 3.10+ (官方推荐 uv)
uv venv --python 3.12
uv sync

# 3) 配置 LLM API Key (按 .env.example)

# 4) 启动 Office UI
opc ui
# 或 Task Mode
opc task
```

## 完整目录结构 (12 MB)

```
OpenOPC/
├── README.md                  # 38 KB (英文)
├── README.zh-CN.md            # 35 KB (中文)
├── pyproject.toml             # 项目配置 (MIT, hatchling)
├── .opc/                       # 用户/团队配置 (242 files)
│   ├── config/company_orgs/   # 7+ 公司模板
│   └── prompts/talent/         # 大量 talent prompt (设计/学术/工程...)
├── opc/                        # 核心代码 (441 files)
│   ├── (services / agents / dashboard / etc.)
├── tests/                      # 完整测试 (130 files)
├── skills/                     # 公开 skills (8 files)
├── config/                     # 配置 (6 files)
├── docs/                       # 文档 (19 files)
├── scripts/                    # 脚本 (3 files)
└── .github/, .codex/           # CI + 工具集成
```

## 4 大**借鉴价值**(可抄到 Fireside / 其他)

### 借鉴 #1: Talent Prompt 模式 ⭐⭐⭐

**OpenOPC 做**:每个 "AI 员工" = 1 个 markdown prompt,frontmatter 含 `color` + `emoji` + `vibe` + `description` + `name`

**Fireside 可抄**:
- Fireside 当前没有"角色"概念
- 可加 **`.fireside/agents/`** 目录
- 每个 agent = 1 markdown
- frontmatter: `name`, `role`, `color`, `emoji`, `system_prompt`
- **Office UI** = 像素风 avatars 在房间里干活

### 借鉴 #2: 任务依赖 DAG ⭐⭐⭐

**OpenOPC 做**:
- 经理拆解任务时定义 DAG
- 无依赖并行,有依赖等前置
- 阻塞/拒绝结构化传播

**Fireside 可抄**:
- 当前:Fireside 消息是 FIFO broadcast
- 可加 **`/task`** 命令创建 DAG
- 或集成 Paseo 的 workspace DAG

### 借鉴 #3: 两级阻塞处理 ⭐⭐⭐

**OpenOPC 做**:
- 内部 blocking → 自动激活最合适角色
- 外部 blocking → 升级到人类

**Fireside 可抄**:
- "人只在需要时被叫进来" 是 Fireside 哲学的天然延伸
- 适用于 Sprint 1.5:AI 卡住时通知用户,平时不打扰

### 借鉴 #4: 经验沉淀 = 老员工越用越顺手 ⭐⭐⭐

**OpenOPC 做**:
- 私有经验档案 (每个员工)
- 共享 playbook (反复出现的教训)
- 新员工继承 playbook

**Fireside 可抄**:
- Fireside session friction 自动 capture (跟 [teamai-cli](teamai-cli.md) 一样)
- 写入 `.fireside/learnings/`
- 下次 session 自动 recall

## 7 大**不建议直接借鉴**(Fireside 定位不同)

| ❌ 不适合 Fireside | 原因 |
|---|---|
| **完整 Phaser Office UI** | Fireside 是 CLI / dashboard,不需要 3D 可视化 |
| **30+ talent library** | Fireside 是 single-user,不需要"AI 员工"概念 |
| **MCP 完整支持** | Fireside 自己就是 agent,不需要 MCP server |
| **7+ 公司模板** | Fireside 是聊天应用,不是公司模拟 |
| **多 channel (Telegram/飞书/Slack)** | Fireside 已经是 Hermes,自带 gateway |
| **Playwright 浏览器自动化** | Fireside 是 backend,dashboard 已嵌 |
| **完整 RAG (chromadb)** | Fireside 知识库走 SQL 即可 |

## HKUDS 团队其他项目 (信誉背书)

| 项目 | ⭐ | 类别 |
|---|---|---|
| **LightRAG** | 39,000+ | RAG 框架 |
| **CLI-Anything** | 47,000+ | CLI 工具生成器 |
| **AI-Trader** | 21,000+ | AI 交易 |
| **OpenOPC** | 1,456 | **AI 公司模拟** (新) |

→ **"HKUDS = 顶配 + 早期红利"** — 1.5 个月 1.5k 星 + 完整工程

## 5 大 适用 / 不适用

| ✅ 适合 | ❌ 不适合 |
|---|---|
| **个人开发者**(1 人公司) | 大企业 (有现成 PMO) |
| **重复性任务**(内容 / 数据 / 报告) | 高度创新 / 0 day research |
| **边界清晰任务**(可拆解为角色) | 单次短任务 |
| **有 Python 经验** | 不愿装 Python 3.10+ |
| **想用 AI 杠杆** | 想要 SOTA 单一最聪明 agent |
| **愿意试早期项目** | 想要 production-stable |
| 中文 / 英文都行 (双语 README) |  |

## 5 大风险

- **Token 成本** — 复杂任务跑一次不便宜,**先小项目试**
- **早期项目** — 1.5 个月 1.5k 星,API 仍在变
- **GitHub API License=None** — README 标 MIT,但 API 还没识别(typical 早期)
- **依赖多** — 18 个 deps (含 playwright, mcp, chromadb)
- **无 web UI** — 只能用 Office UI (Phaser) + CLI

## 跟 iswiki 现有工具对比

| 维度 | OpenOPC | [paseo](paseo.md) | [teamai-cli](teamai-cli.md) | [mattpocock-skills](mattpocock-skills.md) |
|---|---|---|---|---|
| 定位 | 一人公司 AI 模拟 | Multi-agent 编排 | 团队 skill 同步 | 25 通用 skills |
| 哲学 | 自建公司 | 跨设备编排 | git-native sync | small + composable |
| 用户 | 个人 | 个人 / 团队 | 团队 | 个人 / 团队 |
| Frontmatter | `name`/`color`/`emoji`/`vibe` | - | - | agentskills.io standard |
| UI | Phaser Office | Desktop/Mobile/CLI | CLI | - |
| MCP | ✅ | ✅ | ✅ | - |
| 多人协作 | ❌ 单公司 | ❌ | ✅ git 协作 | ❌ |

## 关联资料

- 仓库: <https://github.com/HKUDS/OpenOPC>
- HKUDS: <https://github.com/HKUDS>
- 文章: <https://mp.weixin.qq.com/s/gtnbluXZ_fwPKSVH2bNgDQ> (AI辉, 2026-08-23)
- 介绍: "Build Your Personal AI-Native Company"
- License: MIT
- 团队姊妹项目: LightRAG / CLI-Anything / AI-Trader

## 🎯 TL;DR

**OpenOPC = "AI 员工 + 流程 + 经验"的三位一体**:

| Self | 解决 | 对比 |
|---|---|---|
| **Self-Built** | "雇谁" | 单 agent 不知道雇谁 |
| **Self-Run** | "怎么跑" | 单 agent 不知道任务依赖 |
| **Self-Grown** | "怎么变好" | 单 agent 不复盘 |

**Top 3 借鉴**(按 ROI):
1. **Talent Prompt Frontmatter Schema** (color + emoji + vibe) — 5 min 抄
2. **任务依赖 DAG** — 1-2h 加 `/task` 命令
3. **两级阻塞处理** — 0.5h 加 notification 策略

**Top 3 不必抄**:
- Phaser Office UI
- 30+ talent library
- 7+ 公司模板

== **跟 Hermes / Fireside 关系**:
- **OpenOPC = 一个人 + 多个 AI 员工**(公司模拟)
- **Hermes = 一个人 + 一个 AI**(multi-channel)
- **Fireside = 多个人 + 多 AI**(实时通信)
- **三者互补,不竞争**