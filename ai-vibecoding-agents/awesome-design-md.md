# awesome-design-md — 给 AI agent 喂的"大厂设计语言档案"合集

> 学习笔记 · 调研时间 2026-10-09 · 来源文章 2026-10-09
> 仓库: <https://github.com/VoltAgent/awesome-design-md> · 官网: <https://getdesign.md> · 文档/SPEC: <https://stitch.withgoogle.com/docs/design-md/overview/>
> License: MIT · ⭐ 120,017 · 13,387 forks · 313 open issues · 460 subscribers
> 建仓 2026-03-31 · 最近 push 2026-10-05 · 10 个 gh topics (设计-md · google-stitch · vibe-coding · landing-page 等)
> 调研来源: 公众号「AI科技驿站」《10 万星！awesome-design-md》(已用 GitHub API + raw DESGIN.md + Google Blog + HN 多源核验, 数据校正见 §9)
> **类别**: Agent Skill · 设计系统 · AI 代码生成约束

## TL;DR

VoltAgent 维护的 **73 份大厂设计系统档案** —— 把 Stripe / Linear / Claude / Vercel / Notion / Spotify / 法拉利 等公司公开可见的视觉语言(色板、字体、组件、Do's and Don'ts)写成 `DESIGN.md` 单文件,**丢到项目根目录**,AI 编程 agent(Codex / Claude Code / Cursor / Windsurf / 任何 AGENT SKILL 兼容工具)就会"按这个味道"写 UI。**跟 [i-have-adhd](i-have-adhd.md)(输出风格)、[ipAsLogoSkill](ipAsLogoSkill.md)(图生成的 prompt 约束) 同源** —— 都是 "Agent Skill 范式":用 markdown 给 agent 立契约,可与 [awesome-agent-skills](awesome-agent-skills.md) 的 Design/UI 那一档呼应。**原 spec 是 Google Stitch 2026-04-21 开源的 DESIGN.md 格式**(Cassia Xu / Google Labs),本仓是消费 spec 的下游合集,不是 Google 官方仓。

---

## 0.5 配图速览

本笔记全程使用 ASCII 图(上游 `cdn.voltagent.dev` 图床 在本网络环境被 hardline 拦截),配图 4 张全部 ASCII 绘制,符合 CONTRIBUTING §4.1 "架构图可用 ASCII 替代" 与 §3 "ASCII 图优先" 两原则。

| 章节 | 视觉内容 | 意义 |
|---|---|---|
| §4 架构 A | 9 节 DESIGN.md SPEC 结构 + YAML frontmatter | 介绍"一份 DESIGN.md 长什么样" |
| §4 架构 B | AGENTS.md ↔ DESIGN.md 双文档分工 | 区分"代码怎么搭 / 项目该长什么样" |
| §5 协议栈 | DESIGN.md 文件 → 用户项目 → AI agent 流向 | 一次使用的数据流 |
| §6 矩阵 | 9 大类 × 8 主流派的二维分布矩阵 | 73 份入档的整体调色板 |

| 场景 | 数字摘要 |
|---|---|
| 仓库规模 | `74 个 design-md/<site>/ 子目录, 每目录 = 1× DESIGN.md + 1× README.md` |
| ★ 增长 | 建仓 3 个月 12 万 ★,10/9 当天 API 实测 120,017(公众号原文 10.8 万 = 滞后 ~6,000 ★) |
| SPEC 出处 | Google Stitch 开源, `DESIGN.md count-73` 徽章 |

---

## 1. 一句话定位

把"大厂设计系统"(Stripe purple / Linear 极简 / Notion serif 等)提前抽成单文件 markdown —— `DESIGN.md` —— 放进项目根目录,AI 编程 agent 写 UI 自动照着那个调色板走。**Google 是 spec 出处**(Stitch 设计系统 2026-04-21 开源 DESIGN.md 格式),VoltAgent 是最大规模的下游合集(74 个 site)。

---

## 2. 核心数据

| 字段 | 值 | 来源 / 备注 |
|---|---|---|
| License | MIT | GitHub API · `license.key=mit` |
| ★ 数 | 120,017 | GitHub API(2026-10-09)|
| Forks | 13,387 | GitHub API |
| Open issues | 313 | 印证社区活跃度高 |
| Subscribers | 460 | watchers + starred 通知真实数 |
| 建仓 | 2026-03-31 (不到 7 个月) | API `created_at` |
| 最近 push | 2026-10-05 (4 天前) | API `pushed_at` |
| 仓根文件 | `README.md` 257 行 / `LICENSE` 1KB / `CONTRIBUTING.md` 912B / `design-md/` 子目录 | 仓根 CONTENTS 实测 |
| 子目录数 | **74 个 design-md/<site>/** | GitHub API `/contents/design-md` 实测 |
| 每个子目录文件 | **DESIGN.md + README.md 两文件,无 preview.html** | API 抽 stripe/claude 三目录实测一致 |
| DESIGN.md 章节 | 10 个 H2 节(Overview / Colors / Typography / Layout / Elevation & Depth / Shapes / Components / Do's and Don'ts / Responsive Behavior / **Iteration Guide**)| grep 实测(README 表只列 9 节,少算 Iteration Guide)|
| 文件大小 | Stripe 24,354 bytes · Linear ~24KB · **Claude 最大 33,586 bytes** | API size 字段 |
| Google Blog 公告 | 2026-04-21,Cassia Xu | <https://blog.google/innovation-and-ai/models-and-research/google-labs/stitch-design-md/> |
| AGENTS.md 术语 | "AGENTS.md: How to build the project; DESIGN.md: How the project should look and feel" | README 配套表 |
| 文档格式 | YAML frontmatter(色块 + 字体 + 阴影 + components 等) + Markdown body(Do's and Don'ts / Responsive 等)| Stripe.md 实测 |

---

## 3. 它要解决的实际问题(公众号"症状 → DESIGN.md 解法"对照表)

| AI 默认出图的痛 | DESIGN.md 的对应约束 |
|---|---|
| 给 AI 说 "做 Linear 那种极简风",AI 凭印象猜,十有八九是大圆角 + 紫色渐变(AI 见过最多的那一套) | Linear 的 DESIGN.md 直接告诉它:窄字距-1.4px、Sohne 替代字体、超大留白、`{typography.body-md}` 默认 15px |
| 设计规范在 Figma 里,AI 看不到 | 设计语言抽到 `DESIGN.md` 单文件,放进项目根目录 → agent 一打开就读 |
| 色值靠感觉,每次都重新调 | Stripe `colors.primary: "#533afd"`、按下态 `#2e2b8c`、边框 `#e3e8ee` 都写入 YAML frontmatter,token 化 + 语义命名 |
| 字体参数模糊(标题多大、行高多少) | Stripe `display-xxl: 56px / weight 300 / lineHeight 1.03 / letter-spacing -1.4px / ss01` —— 字特性参数都进文件 |
| AI 自由发挥,渐变 / 阴影 / 玻璃质感全上 | `## Do's and Don'ts` 段直接列禁单:不滥用 300 以上的字重、紫色只做 CTA 不做正文、把 pill 改成圆角是 brand 崩盘 |
| 改一遍 prompt 就丢上下文,要重写 | `DESIGN.md` 是文件级 context,放进 git 后每次 agent 都能读,跨会话语义不掉 |
| 不同 agent 凭不同 prompt 理解不一致 | 任何 agent 都按文件读;GitHub Copilot / Claude Code / Cursor / Codex / Windsurf / Replit Agent / Bolt / Lovable 都兼容(SKILL.md 风格的开放格式)|
| "想用 Linear 的风格但 Linear 用了商业字体 Sohne" | DESIGN.md 主动声明"Note on Font Substitutes"段:商用字体列 fallback(`sohne-var, 'SF Pro Display', system-ui, -apple-system, sans-serif`)|
| 设计档案散落在 Figma/JSON/Notion,agent 看不懂 | 单 markdown 文件,任何能读 markdown 的 agent 都行(Google Stitch 原文:"Markdown is the format LLMs read best")|
| "我想要的网站没在 73 份里" | 通过 `https://getdesign.md/request` 提需求,支持公开和私有请求 |

---

## 4. 核心:一份 DESIGN.md 长什么样(架构原理)

### 4.1 一份 DESIGN.md = YAML frontmatter(机读)+ Markdown body(人 + agent 共读)

以 Stripe DESIGN.md(`design-md/stripe/DESIGN.md`,24KB)为例:

```yaml
# YAML frontmatter — agent-friendly,可机读解析
---
version: alpha
name: Stripi-Inspired-design-analysis
description: An inspired interpretation of Stripi's design language —
  a financial-infrastructure brand built on a deep navy ink, an electric
  indigo primary, and a recurring atmospheric gradient mesh...

colors:
  primary: "#533afd"
  primary-deep: "#4434d4"
  primary-press: "#2e2b8c"
  primary-soft: "#665efd"
  primary-bg-subdued-hover: "#b9b9f9"
  brand-dark-900: "#1c1e54"
  ink: "#0d253d"
  ink-secondary: "#273951"
  ink-mute: "#64748d"
  canvas: "#ffffff"
  canvas-soft: "#f6f9fc"
  hairline: "#e3e8ee"

typography:
  display-xxl:
    fontFamily: "sohne-var, 'SF Pro Display', system-ui, ..."
    fontSize: 56px
    fontWeight: 300
    lineHeight: 1.03
    letterSpacing: -1.4px
    fontFeature: ss01        # ← stylistic-set 1,字体特性参数
```

```markdown
# Markdown body — 人 + agent 共读

## Overview                  # 1 段:设计语言基调和关键观察
## Colors                    # 色板分组(Brand & Accent / Surface / Text / Semantic)
## Typography                # Font Family / Hierarchy / Principles / Note on Font Substitutes
## Layout                    # Spacing System / Grid & Container / Whitespace Philosophy
## Elevation & Depth         # Decorative Depth(Stripe 特有的 gradient mesh)
## Shapes                    # Border Radius Scale + Photography Geometry
## Components                # Buttons / Cards / Inputs / Navigation / Pills / Signature
## Do's and Don'ts           # 设计红线 + 反面清单
## Responsive Behavior       # Breakpoints / Touch Targets / Collapsing / Image Behavior
## Iteration Guide           # ← README 表里**漏列**的最后一节
```

**Iteration Guide**(公众号 + README 表里都没列)实际是 **第 10 节** —— 以 Stripe 为例,它包含 `npx @google/design.md lint DESIGN.md` 这种命令行 lint 工具的提示,说明 Google 还在持续扩 SPEC,VoltAgent 跟得紧。

### 4.2 "AGENTS.md ↔ DESIGN.md" 双文档分工(README 的核心创新叙事)

```
项目根目录
├── AGENTS.md        ← 给 Coding agent: 怎么搭项目
│                     (build / test / lint 命令、目录约定、依赖管理)
└── DESIGN.md        ← 给 Design agent: 项目该长什么样
                      (色板 · 字体 · 组件 · Do's and Don'ts)
```

| 文件 | 读者 | 它规定什么 |
|---|---|---|
| `AGENTS.md` | Coding agent | 项目怎么搭(commands / structure / lint) |
| `DESIGN.md` | Design agent | 项目长什么样(tokens / components / guardrails) |

> 出处: README "What is DESIGN.md?" 章节,明确说 "AGENTS.md and DESIGN.md work together to give AI agents complete context"。
>
> ⚠️ **本句的版权归属**: 这是 VoltAgent 营销话术,Google Stitch 原 spec 没说这件事。这是 VoltAgent 给 awesome-design-md 加的额外一层"绑定"叙事,让 DESIGN.md 与 AGENTS.md 配对使用更顺。

### 4.3 使用一次的数据流

```
┌────────────────────────────────────────────┐
│ 项目根目录                                  │
│  ├── DESIGN.md  (从 awesome-design-md 复制)│
│  └── AGENTS.md   (项目自身)                │
└────────────────────────────────────────────┘
                  ↓ agent 读
┌────────────────────────────────────────────┐
│ AI 编程 agent(Codex / Claude Code / Cursor) │
│   1. 解析 DESIGN.md YAML → tokens          │
│   2. 解析 Markdown body → 设计哲学          │
│   3. 用户说"做个落地页" → agent 按 tokens   │
│      出图,内容框架按组件表配置              │
└────────────────────────────────────────────┘
                  ↓
┌────────────────────────────────────────────┐
│ 输出 UI: 完整的 font / color / component    │
│          但视觉气质 = DESIGN.md 描述那个公司 │
└────────────────────────────────────────────┘
```

**为什么比 "prompt 里写 Linear 风格" 强**:
- 持久:文件级 context 跨会话,不用每次重写 prompt
- 准确:把"风格印象"翻译成机器可读的 token + 行为规则
- 可审计:`git diff` 看设计变更,`npx @google/design.md lint` 校验合规

### 4.4 三种使用方式(适配用户角色)

| 角色 | 用法 | 入口 |
|---|---|---|
| **独立开发者** | `git clone` 全仓,挑一份拷到项目根,跟 agent 说"按这个风格做" | `git clone https://github.com/VoltAgent/awesome-design-md.git` |
| **不想 clone 只想用一份** | 直接去 `https://getdesign.md/<site>/design-md` 看 + 下载(本网络环境 access 太慢,云防火墙) | 单页 URL,74 个对应路径 |
| **想要 Discord 风格 / 复古风格** | 提交请求 | `https://getdesign.md/request` 公开或私有 |
| **看色板 / 字体长什么样** | (README 说)preview.html 在仓里,**但实测每目录只有 DESIGN.md + README.md** —— 子 README 已迁到 getdesign.md/<site>/design-md; 真正预览在站上 | https://getdesign.md/ 各子页 |

### 4.5 子 agent 并行(可选路径)

> 公众号提到"在 Codex 里实测一次" 一节,**完整复现**:

```bash
# 1. 拷一份到项目根
cp design-md/linear.app/DESIGN.md /your/project/DESIGN.md

# 2. 跟 agent(Codex/Claude Code)说一句话
# "读一下项目根目录的 DESIGN.md,严格按里面的设计语言,给我做一个 SaaS 产品的落地页"

# 3. 跟没 DESIGN.md 的对照组
# (跑同样 prompt,但项目根没有 DESIGN.md)
```

**对照结果**(公众号原话):
- 有 DESIGN.md → 窄字距大标题、克制留白、Linear 风
- 无 DESIGN.md → 渐变背景 + 紫色主色 + 大圆角卡片(典型 AI 模板味)

---

## 5. 73/74 份覆盖矩阵(ASCII 分布图,按 README 的 8 大类)

```
                  ╱───────────── 复古区(2 份) ─────────────╲
                 │                                          │
              Dell 1996 / Nintendo 2001                    │
                 │                                          │
AI 平台 ────► Claude · Cohere · ElevenLabs · Mistral · Ollama · OpenCode · Replicate · Runway · Together · VoltAgent · xAI · Minimax (12)
Dev 工具 ───► Cursor · Expo · Lovable · Raycast · Superhuman · Vercel · Warp (7)
Backend ────► ClickHouse · Composio · HashiCorp · MongoDB · PostHog · Sanity · Sentry · Supabase (8)
SaaS ────────► Cal.com · Intercom · Linear · Mintlify · Notion · Resend · Zapier (7)
Creative ────► Airtable · Clay · Figma · Framer · Miro · Webflow (6)
Fintech ─────► Binance · Coinbase · Kraken · Mastercard · Revolut · Stripe · Wise (7)
Retail ──────► Airbnb · Meta · Nike · Shopify · Starbucks (5)
Media/Tech ─► Apple · HP · IBM · NVIDIA · Pinterest · PlayStation · SpaceX · Spotify · TheVerge · Uber · Vodafone · WIRED (12)
Automotive ─► BMW · BMW-M · Bugatti · Ferrari · Lamborghini · Renault · Tesla (7)

            ════════════════════════════════════════════════
            小计 = 12+7+8+7+6+7+5+12+7 = 71,余 3 份属于 README
            未明确归类的(可能 BMW·BMW-M 也合并): 共 73 份(README)
            GitHub API 实测 design-md/ 下有 74 个子目录,差 1
```

**为什么 73 vs 74 差异** (≈ 这个是 §9 数据校正段的素材之一):
- README 徽章写 `DESIGN.md count-73`
- GitHub API 实测 `/contents/design-md` = **74 个目录** (airbnb 起,vodafone/wise/webflow/wire/x.ai/zapier 止,共 74)
- 推测: badge 是单文件维护脚本生成,有 1 个 lag(大概率是 `figma/` 目录被加进去但还没补对应 DESIGN.md,或 README 还没同步)

---

## 6. 安装 / 兼容性

```bash
# 方案 A:整仓 clone(73+ 份全要)
git clone https://github.com/VoltAgent/awesome-design-md.git
# 所有文档在 design-md/ 下,每个 site 一个文件夹

# 方案 B:只要一份(推荐 — 仓 ≈ 25MB+,挑一个拷)
curl -L -o ./DESIGN.md \
  "https://raw.githubusercontent.com/VoltAgent/awesome-design-md/main/design-md/linear.app/DESIGN.md"

# 方案 C:走站点(配 preview / dark mode)
# https://getdesign.md/linear.app/design-md  ← 含 dark hero + 组件目录
# (本网络环境访问慢)

# 方案 D:跟 agent 说
# "按照根目录 DESIGN.md 里的设计规范,实现这个页面"
```

**兼容 agent**(README 自称 + 实践侧):
| 工具 | 说明 |
|---|---|
| **Codex** | OpenAI,跟 AGENTS.md 同思路,实测体验同 vector |
| **Claude Code** | Anthropic,默认读项目根文件 |
| **Cursor** | 编辑器级,自动 index 项目根 |
| **Windsurf** | Cascade 引擎,项目根文件加载 |
| **Replit Agent / Bolt / Lovable** | SaaS,读项目根文件 |
| **任何能读 markdown 的 agent** | Google Stitch 原话:"Markdown is the format LLMs read best, so there's nothing to parse or configure" |

---

## 7. 与同类对比(找定位)

| 项目 | 关系 |
|---|---|
| **[i-have-adhd](i-have-adhd.md)** | ✅ 同 Agent Skill 范式,该改 *输出节奏*,awesome-design-md 改 *视觉语言输出约束* |
| **[ipAsLogoSkill](ipAsLogoSkill.md)** | ✅ 同一思路推到 logo 生成:用 SKILL.md 把"圆润极简可爱 IP logo"的硬约束写给 agent |
| **[awesome-agent-skills](awesome-agent-skills.md)** | ✅ 1497+ skill 官方索引;本仓是它的 Design/UI 类的典型样本(Anthropic frontend-design、OpenAI figma-* 同类)|
| **[img2threejs](img2threejs.md)** | 🟡 同 Agent Skill 范式,但负责"看图 → Three.js 代码",上游接 figma/web screenshot |
| **[openclaw-awd-arena](openclaw-awd-arena.md)** | ⚪ 不同主题,Agent 攻防 |
| **Google Stitch 本体** | ✅ upstream SPEC 出处,Google 自家是消费方(Stitch 工具生成 DESIGN.md) |
| **Figma Tokens / Style Dictionary** | 🟡 同样 token 化思路,但输出是 JSON / SCSS 给编译器;awesome-design-md 输出 markdown 给 AI agent |
| **Midjourney / SD 参考图 prompt 库** | 🔴 prompt 集合的 *反义词*:中规矩 ⬌ 自由发挥 |
| **bolt.new / Lovable 的 system prompt** | 🟡 各自有内置 prompt,但 awesome-design-md 让用户能"换皮" |

**对比 Google Stitch 本体**: Stitch 是 Google 自家工具,**让 Stitch 用户导出 DESIGN.md 给 Google 的 AI agent 用**,属于"in-house spec";awesome-design-md 是**公开仓库收集 73 个外部产品的 DESIGN.md 实例** —— 类似 "awesome-mcp-servers" 把 MCP 协议下的实例攒起来。本仓补的是 *第三方产品* 设计语言,不是 Google 自家案例。

---

## 8. 跟我们的关系

**适用场景画像**(公众号原文 4 类):

| 角色 | 用法 |
|---|---|
| **独立开发者做 side project** | 选一套成熟规范打底,避免"程序员页面丑" |
| **黑客松 / demo / 原型验证** | 一份 DESIGN.md + 一句 prompt = 看着像样的 UI |
| **小团队起步,没设计师** | 借现成设计语言过渡,等有钱再请设计师 |
| **长期项目风格统一** | 一份 DESIGN.md 长期挂在根目录,所有 agent 生成新页都指给它看 |

**多启发 3 件事**:

1. **"MARKDOWN 给 AGENT 立契约"** — [i-have-adhd](i-have-adhd.md)(输出风格)、[ipAsLogoSkill](ipAsLogoSkill.md)(图生成约束)、本仓(视觉语言)三例印证了同一范式:**Agent Skill = 纯 markdown 文件 + 硬约束段(Constraints / Do's and Don'ts)+ 开放格式兼容多 agent**。**未来自己写 skill 给 agent,模板 = DESCRIPTION frontmatter + 工作流 + token / 风格 / 行为禁单**。
2. **"AGENTS.md + DESIGN.md 双文档" 是创作叙事** — VoltAgent 在 README 里造了这个绑定说法,本质让"项目根目录"成为 agent context 的天然入口。**给自己的项目加同款: root 加 `AGENTS.md`(给 Codex/Claude) 解释"怎么搭", root 加 `SKILL.md`(给 agent skill) 解释"该怎么写 prompt", 即可让所有 agent 一打开就读到约定**。
3. **大公司是设计语言 "Public Domain" 的施主** — Stripe / Linear / Spotify 的设计语言都是公开 CSS 能抓的(本仓用的是"公开可见 CSS 值"),版权不清不浊。**公众号原话:** "借人家的设计语言做自己的东西,我个人觉得问题不大,按我的理解,设计风格本身不在版权保护的范围里。但别顺手把人家的文案和图片素材也搬走" —— 这条在 §9 仍会展开。

**别学的 1 件事**:

1. **不要把"badge 数据"等同"权威数据"**:README 徽章 `DESIGN.md count-73` 与 GitHub API 实测的 `design-md/` 74 子目录差 1 —— 任何公开仓库的 build-time badge 都有 lag, **以 API 实时为准**。本笔记 §9 就是以此修正的。

**已知坑**(README + 子 README 互相矛盾时优先信子 README):
| 坑 | 真相 |
|---|---|
| README 表格说每个 DESIGN.md 配 `preview.html` + `preview-dark.html` | 子 README 写"Details have been moved to https://getdesign.md/<site>/design-md"—— **仓里没这两个 html,真预览在 getdesign.md 各子页** |
| 把 73 份当完整数 | 实际 API 数 74,README badge 滞后 |
| 想用开源版 Sohne / Stripe 字体 | 有些是商业字体;Stripe 文档主动给 fallback,但落地页里出图前要装或购字体 |
| 风格分不清"借鉴" 和"侵权" | 设计风格 = 不受版权保护的具体组合,文案 / Logo / 商品图素材独立计算 |

---

## 9. 数据校正(源文 vs 远端核实 + 多源印证)

| 用户口述 | 远端核实(API/raw 抓取)| 来源 |
|---|---|---|
| 10.8 万 ★ | **120,017 ★**(2026-10-09)| <https://api.github.com/repos/VoltAgent/awesome-design-md> |
| "把大厂的设计语言提前提取好" | 实测:每个 `DESIGN.md` 是 YAML + Markdown,**只是"提取公开 CSS"**,部分是有"inspired by"的 interpretation | design-md/stripe/README.md "Design system details have been moved to: ..." |
| 73 份 | 实际 74 份子目录(README badge 滞后 +1)| API `/contents/design-md` |
| "配套 preview.html / preview-dark.html" | **仓内不存在这两个文件** —— 子 README 实际写"已迁到 getdesign.md/<site>/design-md",真预览在站上,非仓内 | API contents 实测 + 设计规范 README.md |
| "DESIGN.md 是 Google Stitch 推出来的新玩法" | ✅ 真实(Stitch 设计系统 2026-04-21 开源 SPEC, Cassia Xu)| <https://blog.google/innovation-and-ai/models-and-research/google-labs/stitch-design-md/> |
| 9 节结构(公众号 + README 都引)| 实测 10 节:**少了 Iteration Guide**(`npx @google/design.md lint DESIGN.md`)| design-md/stripe/DESIGN.md H2 实测 |
| DESIGN.md 数与设计美学数能对上 | 部分 DESIGN.md 文案带"(inspired by)" 字样(如 `Stripi-Inspired-design-analysis`),**复刻是 interpretation, 不是 pixel-perfect 1:1 复制**| design-md/stripe/DESIGN.md frontmatter name 字段 |
| "Design system 文件类型" | 实测每个子目录 = 1× DESIGN.md + 1× README.md;**无任何 HTML / preview 文件** | API contents 抽查 stripe / claude / linear.app |

**§9 附加 · 多源交叉**:

| 源 | URL | 关键事实 |
|---|---|---|
| Google Labs 官方公告 | <https://blog.google/innovation-and-ai/models-and-research/google-labs/stitch-design-md/> | "Today, we're open-sourcing the draft specification for DESIGN.md, so it can be used across any single tool or platform" — Cassia Xu, Software Engineer, 2026-04-21 |
| GitHub API metadata | <https://api.github.com/repos/VoltAgent/awesome-design-md> | 120,017★ · 13,387 forks · 313 open issues · topics: design-md, google-stitch, landing-page, vibe-coding, vibe-design, vibecoding, figma, design-system, design-tokens, awesome-list |
| HN (DeathArrow 帖 2026-05-18) | <https://news.ycombinator.com/item?id=48177822> | 4 pts · 0 comments · 0 kids → 反证公共讨论热度<仓库 ★ 量级;大部分 star 来自 GitHub explore 而非 HN 流量 |
| 子 README 真相 | <https://raw.githubusercontent.com/VoltAgent/awesome-design-md/main/design-md/stripe/README.md> | "Design system details have been moved to: https://getdesign.md/stripe/design-md" —— 证明仓内只是精简 markdown,真预览在站上 |
| 衍生生态 | <https://github.com/bergside/awesome-design-md-skills> | HN Show HN 同期出现的 "DESIGN.md → skill" 二次封装尝试,印证概念外溢 |

⚠️ **未找到的源**(本任务主动声明):
- 中文媒体评述:**掘金 / 知乎 / 36Kr / CSDN / cnblogs / InfoQ 均无独立评述**(Bing / Brave / Google 多搜索引擎限定均空)。中文圈能见度**显著低于英文圈**,公众号「AI科技驿站」是少数深度评测。
- ProductHunt / Medium / DEV.to / Reddit: 搜索 HTTP 200 但 SPA 渲染 + 反爬,无具体 URL 可取证,跳过。
- 仓主博客 / VoltAgent 创始人 twitter: 同步页有"Ranked #150 globally on GitHub"自夸字样(SEO 营销话术,未单独采信)。

---

## 10. 一句话哲学(选段)

> "DESIGN.md in Stitch lets you export or import your design rules from project to project, so you don't have to reinvent the wheel every time you start a design in Stitch." — Google Blog, 2026-04-21

> "**Markdown is the format LLMs read best**, so there's nothing to parse or configure." — awesome-design-md README

> "**Instead of guessing intent, AI agents can know exactly what a color is for, and can validate their choices against WCAG accessibility rules.**" — Google Blog (核心承诺:不是"让 AI 更聪明",是"让 AI 有可校验的设计依据")

> "DESIGN.md is 1 of the Web Standards Now Endorsed by AI." —— 借用 Google Blog 标题语义

**核心范式归纳**: "**给 agent 立契约 = 单 markdown 文件 + token + 行为禁单**" —— 这与 [i-have-adhd](i-have-adhd.md)、[ipAsLogoSkill](ipAsLogoSkill.md)、[awesome-agent-skills](awesome-agent-skills.md) 同源。三仓并读,可完整理解 "Agent Skill" 这一当代 AI 编程范式。

---

## 参考链接

**一手 / 上游**:
- 仓库: <https://github.com/VoltAgent/awesome-design-md>
- 官网(<https://getdesign.md>): 单页包含 /request 申请通道与每个 site 的 deep preview
- Google Stitch DESIGN.md SPEC: <https://stitch.withgoogle.com/docs/design-md/overview/> + <https://stitch.withgoogle.com/docs/design-md/specification/>(两页为 SPA shell,需 JS 渲染)
- Google Blog 公告: <https://blog.google/innovation-and-ai/models-and-research/google-labs/stitch-design-md/>
- 衍生仓: <https://github.com/bergside/awesome-design-md-skills>

**调研原始材料**:
- 公众号「AI科技驿站」: <https://mp.weixin.qq.com/s/l5DKitEfaYOk2Zle41sBXg>
- HN 同主题帖( DeathArrow 2026-05-18): <https://news.ycombinator.com/item?id=48177822>
- HN 同期高光贴( getdesign.md Show HN 2026-04-10): 11 pts · 6 c

**仓内相关笔记**:
- [i-have-adhd](i-have-adhd.md) — Agent Skill 范式 · *输出风格约束*(同 MODE 思维)
- [ipAsLogoSkill](ipAsLogoSkill.md) — Agent Skill 范式 · *图像生成约束*(同 MODE 思维,LOGO 单图)
- [awesome-agent-skills](awesome-agent-skills.md) — 1497+ skill 官方索引,本仓是它的设计类典型样本
- [img2threejs](img2threejs.md) — 上游接图 / 下游接 Three.js
- [OpenKimiPPTSkill](OpenKimiPPTSkill.md) · [CnDemSkill](CnDemSkill.md) — Agent Skill 范式的另外两个样本(PPT / DEM 地形)

**多源研究档案(本次任务副产物)**: `assets/awesome-design-md/sources-report.md`
