# Home Repo 模式 — Matt Pocock 的多仓 agent 组织法

> 学习笔记 · 调研时间 2026-11-16
> 官方文章: <https://www.aihero.dev/the-home-repo-pattern>（7 min read · Updated Nov 12, 2026）
> 字典条目: <https://aihero.dev/ai-coding-dictionary/home-repo> · 一手 markdown: <https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Home%20Repo.md>
> 视频: <https://www.youtube.com/watch?v=hWe-j78vNpc>（The Home Repo: The effortless multi-repo agent setup · 8:53 · 253K views）
> 🎬 **视频字幕已完整提取并逐句核对**（255 句，`en-orig` 轨道，2026-11-16）—— 本文 §七 与 §9.3 的补充内容均出自字幕一手原话
> 作者: Matt Pocock（AI Hero / Total TypeScript）· 相关仓: `mattpocock/skills`（⭐325,498）· `mattpocock/dictionary-of-ai-coding`（⭐5,499）

> **本篇与已有两篇的关系**：[mattpocock-skills](mattpocock-skills.md) 讲的是**单个 skill 仓的结构**，本篇讲的是**多个仓怎么组织**。[mattpocock-skills-1-3](mattpocock-skills-1-3.md) 拆的是 v1.3 的三个新 skill。**三篇互补，不重叠** —— 本篇不重复 skills 仓本身的内容，专注「Home Repo 这个模式」。

## 一句话定位

**把「所有 agent 的启动目录」收敛成一个仓库** —— skills、AGENTS.md、共享文档都放这里，AGENTS.md 里只放指向其他仓的**导航指针**；agent 始终在这个仓里启动，需要哪个仓就按指针打开或 clone 哪个。**代码不动，只动「家」在哪。**

## 一、它解决的到底是什么问题

原文的第一句问题陈述就点得很准：

> "When a project spans several repos, an agent started in one of them sees only that repo. Each repo ends up with its own copy of the skills and the agent setup, and planning a feature that crosses repos means working without the whole overview."

拆成三个具体痛点：

| 痛点 | 具体表现 | Home Repo 的解法 |
|---|---|---|
| **看不见全局** | agent 在 A 仓启动就只知道 A 仓 | 指针让 agent 能按需打开/clone B、C 仓 |
| **复制漂移** | 每个仓各存一份 skills，版本慢慢分叉 | **只留一份**，放 Home Repo |
| **跨仓功能缺全局视角** | 做跨仓特性时没有全景 | 在 Home Repo 里 grill 这个功能（不是分散在各仓里问） |

Home Repo 给出三个收益（原文原话）：
1. One place for your steering files and tooling
2. One place to run all your agents
3. Sweeping changes across multiple repos from a single session

## 二、三层结构：什么进、什么留

这是整个模式的核心，也是最容易做错的地方。**用官方那张对照表**（来自字典条目，比文章里的更完整）：

| 放进 Home Repo | 留在各自仓里 |
|---|---|
| 跨仓用到的 skills | 仓的代码 |
| AGENTS.md（带每个仓的指针） | 它自己的 AGENTS.md、构建和测试命令 |
| 共享文档：编码规范、术语表、系统级决策 | 只关于那个仓的文档 |
| 工具，比如连外部服务的 CLI | |

⭐ **一句话记住**：**「能推导出的一律不留，推导不出的才留」** —— 各仓自己的 build/test 命令、代码结构，agent 从代码就能看出来，不需要共享；只有「跨仓成立、且代码里读不出来」的东西（编码规范、术语表、系统级决策、跨仓 skills）才该上移。

**代码永远留在原地**，每个仓保留自己的 git history、remote 和 issue tracker。Home Repo 只做「家」，不做「代码仓库」。

## 三、导航指针（context pointer）

指针是 Home Repo 的最小构件，官方单独给了定义：

> "Each pointer is a **context pointer**: one line naming the repo, where it lives on disk, and where to clone it from if it's missing."

### 3.1 指针长什么样

```markdown
## Other Repos
Storefront (Next.js app): ~/repos/acme/storefront. Clone from git@github.com:acme/storefront.git if missing.
Payments API: ~/repos/acme/payments-api. Read its AGENTS.md before changing it.
AI Hero: ~/repos/ai/ai-hero (git pull to view latest, likely out of date)
```

**一行四要素**：名字 + 是什么 + 本地路径 + 缺失时从哪 clone。**需要时加 hint**（"Read its AGENTS.md before changing it"）。

### 3.2 指针背后的成本模型（这是最有价值的部分）

字典里 `Context pointer` 词条把「为什么用指针而不是内联内容」讲得比任何文章都清楚：

> "The reason to use a pointer (instead of inlining the content) is **cost**. A pointer is one line in the context window. The document behind it might be thousands of tokens, but **those tokens cost nothing until the agent actually follows the pointer**."

数字对比：**把一份 2,000 token 的部署 runbook 内联进 AGENTS.md，每个 session 都要付这 2,000 token；换成一行 `deploy process: see internal/deploy.md`，只有真正部署的 session 才加载。**

而且 `Progressive disclosure` 词条补了**第二个成本维度**：

> "context is a cost **twice over**. Every token loaded up front is billed as **input tokens** on every turn, and every token spends **attention budget** whether the agent needs it or not."

⭐ **注意力稀释**这个论点比 token 成本更重要：`AGENTS.md` 里塞满风格指南、部署手册、数据库约定，**会让 agent 在所有这些方面都变差** —— 当前任务真正需要的指令被无关指令埋掉了。

⚠️ 词条给的**可观测征兆**值得记住：
> "The tell is an agent that ignores rules you know are in its context: they're in there, but buried."

**「agent 忽略了你知道它 context 里有」的规则 —— 就是被稀释了。**

### 3.3 指针必须带「何时该读」的描述

词条明确说：**光秃秃的路径 agent 没有理由跟随**。

> "A bare path is a pointer the agent has no reason to follow; 'see internal/deploy.md' with no hint of what's inside gets skipped by a session that needed it. Write the line so it matches how tasks present: **'release, deploy, or rollback — read internal/deploy.md first'**."

⭐ **指针的描述要按「任务怎么出现」来写**，而不是按「文件里有什么」来写。这是一条可直接套用的写法规则。

## 四、官方 setup prompt 的四步（可直接抄）

文章给了一个可以贴进 agent 的 prompt，核心是**「在批准前只读」**。这是它设计上最聪明的一环 —— 把整个建仓过程变成一次 grill。

### 4.1 prompt 的工作规则（原文）

```
## How to work
- Look up every fact yourself (filesystem, git, gh), using subagents for wide searches.
  Bring me only decisions.
- Put decisions to me in rounds. Number each question, give your recommended answer,
  and word it so "yes" accepts it. A question that depends on one still open waits
  for a later round.
- Until I approve the plan in Step 3, only read.
- Secrets stay where they are: leave .env and other secret files unread.
```

四个约束逐条解读：

| 约束 | 作用 |
|---|---|
| **自己查事实，只带决策来** | 避免 agent 拿一堆已存在的事实来问人 |
| **分轮提问 + 编号 + 给推荐答案 + 措辞成「yes 即接受」** | 这是**可执行的 grill**：一轮问一组，依赖未决问题的往后排 |
| **批准前只读** | ⭐ 关键安全阀 —— 整个过程零副作用 |
| **不动 secrets** | `.env` 等文件保持未读 |

> ⭐ 这套「How to work」本身就是 Matt 的 **Grilling** 方法论（字典里有专门词条：agent 苏格拉底式地逐个决策提问，不猜默认值）。**Home Repo 的 prompt 本身就是 grilling 的一个完整实例** —— 注意它与本仓已有的 [mattpocock-skills-1-3](mattpocock-skills-1-3.md) 里 `grill-with-docs` 的关系。

### 4.2 四步

| 步骤 | 做什么 | 完成判据 |
|---|---|---|
| **Step 1 · 清点仓库** | 找 home 目录下的每个 git 仓（跳过依赖目录），记 path / remote / 可见性 / 最后提交日；第一轮问 4 个问题：Home Repo 指向哪些仓、它住哪（**推荐新建一个私有仓**放旁边）、个人还是团队共享、harness 加载哪个文件（AGENTS.md / CLAUDE.md / 两个都要） | 每个仓都标记了 in / out，另外 3 问已答 |
| **Step 2 · 清点共享物料** | 列出所有 skill（含 `~/.claude/skills` 等用户级目录）、所有 AGENTS.md/CLAUDE.md、所有给 agent 写的文档（编码规范、术语表、ADR），分四桶：`shared` / `duplicate`（**diff 出哪份最新**）/ `repo-specific` / `installed`（来自已发布仓或 marketplace） | 每项**恰好落在一个桶**里 |
| **Step 3 · 敲定方案** | 出一张表：每项 → 现状 → 去向；并展示 Home Repo 的 AGENTS.md（含 Other Repos 段）；未决问题继续分轮问 | **用户批准表格 + AGENTS.md** |
| **Step 4 · 执行** | ①建 Home Repo 和 AGENTS.md（harness 加载别的文件就加一行指向 AGENTS.md）②把 shared 项**整个 skill 文件夹**拷进去 ③在每个子仓**新建本地分支**，删掉搬走的副本，repo-specific 留下 ④在 Home Repo 里 commit（**push 由人决定**） | 表格每行都被执行；**汇报每行结果、每个仓建了哪些分支、跳过了什么及原因** |

⭐ Step 4 的两个细节很讲究：
- **「skill 文件夹整个搬」** —— 不是把 SKILL.md 抽出来，是连目录一起走
- **「push 由人决定」** —— agent 可以 commit，但 push 是人的决定。原文在 prompt 里明写 `Commit in the Home Repo. Pushing is my call.`
- **子仓用「新本地分支」改** —— 不是直接改 master，历史与 remote 都不受影响

### 4.3 规模与退化策略

| 仓数量 | 做法 | 来源 |
|---|---|---|
| **20–40 个** | 一仓一行指针，完全够用 | 视频原话："This setup works for **maybe 20 30 40 repos** possibly" |
| **~400 个** | 一仓一行太多 → **改用渐进披露**：每个业务领域一个文件，指针指向那个文件 | 文章 FAQ + 视频："It wouldn't scale to like 400 repos" |
| **几千个** | skills 的消费者够多了 → **用 skills marketplace 更合适** | 文章 FAQ |

渐进披露的样子：

```markdown
## Other Repos
Billing (invoices, payments, tax): see repos/billing.md
Storefront (web and mobile apps): see repos/storefront.md
Internal tools: see repos/internal.md
```

## 五、关键设计决策：为什么是「仓」而不是 `~/.claude/skills`

原文 FAQ 里这个问答点出了整个模式的价值观：

> "**Why a repo, and not `~/.claude/skills`?** The ideal end state is that **everyone uses the same skills, kept in the project**. A user folder is the stopgap until then. A Home Repo is a project: **its skills are versioned with git, and a team can share it**."

三层递进：

```
~/.claude/skills（用户目录）      →  只有你一个人能用，没版本、不能共享
        ↓
Home Repo（git 仓）              →  ⭐ 版本化、可共享、可 review
        ↓
「everyone uses the same skills, kept in the project」（理想终局）→ 不再是「某人的 skills」，而是「项目的 skills」
```

⭐ **这是从「个人配置」到「项目资产」的定位转变** —— 用户目录是过渡态，仓才是终态。

## 六、边界与不适用的场景

官方明确划了几条界：

| 问题 | 官方回答 |
|---|---|
| **能上 monorepo 吗** | "A monorepo is a good fit when you can have one. **A Home Repo replaces it when you can't**" —— 典型原因是**公私仓混用**（有些仓必须公开、有些必须私有）或**团队不接受 monorepo** |
| **用 git submodule 吗** | "You can. At 5-10 repos a submodules-style setup is fine. **Plain pointers do the same job without submodules.**" |
| **需要 CLI 吗** | "**No.** Pointers in AGENTS.md and the tools you already have are enough to start." —— 工具是 later，不是前提 |
| **CLAUDE.md 还是 AGENTS.md** | 文章统一写 AGENTS.md，但明确"**Put the pointers in whichever file your harness loads**"，Claude Code 加载 CLAUDE.md |
| **agent 会 clone 还是用磁盘上的** | "**Both.** 如果仓已在指针路径上就在那工作，不在就 clone 到那" |
| **worktree 怎么配** | "**Each repo is cloned once.** Each feature gets a worktree inside that clone, so several agents can work in one repo at the same time." |
| **issue 放哪** | agent 能访问每个仓的 issue tracker，可以一起理解；让它按归属分别开 issue 也行 |
| **CI 里能用吗** | 能 —— software factory 场景把 Home Repo 放进 sandbox，它按需 clone 其他仓 |
| **team 能共享吗** | 能 —— **对团队来说，Home Repo 就是你们共享的那个东西**，所有人在里面跑 agent |

⭐ 注意最后一条：**共享的是 Home Repo 本身**，不是「每个人的 skills 各自同步」—— 这跟 §五 的三层递进是同一个逻辑。

## 七、⭐ 未公开的部分（重要边界）

⚠️ **Matt 没有公开他自己的 home repo**，而且明确说过为什么：

> "these skills are **private** skills. In other words, these are skills that I do not want to release for whatever reason because they are **extremely good and extremely sensitive to my business**."

推论：
- **范式公开，实例不公开** —— 能照搬结构，照搬不了内容
- 他公开的是**另一个仓** `mattpocock/skills`（那是从 `.agents/` 目录开源出来的**通用** skills），**不是** home repo 本身
- 视频里展示 home repo 的界面时，讲的是结构（CLAUDE.md / skills / wiki / tooling），**没说也不打算给内容**

⭐ 另一个他提到的点值得记：**home repo 里还放了一个巨大的 wiki** —— "an enormous wiki of all of the data that is kind of sensitive to my business... essentially a **LLM Wiki, Karpathy style**"。且他明确说：**「自从用了 home repo，我为自己 agent 做的工具变得更加大胆了」**（因为工具和上下文都在一处，迭代成本低）。

🎬 **视频字幕补充的三条细节**（文章里没有）：

1. **「用户目录」为什么不够** —— 他的理由比文章更具体：用户目录里的东西 "because it's kind of **invisible to the user**"，用户不会主动更新它，"they'll probably fall behind what the global setup is"；而且用户目录是**用户自己改自己**的地方，"instead of how the **team** wants them to work" → **个人偏好 vs 团队标准**的冲突，这是他反对用户目录的核心理由。
2. **home repo 的定位是「业务的工具层」** —— "the home repo becomes the **tooling that links all different parts of your business** up together, not only the code, but giving access to the agent to really **rich data sources**"。他举了具体集成：Gmail / Slack / Discord / YouTube / GitHub / GCal / AI Hero / Buffer，以及「一次性 HTML 报告」。→ 这解释了为什么工具会「有机生长」在 home repo 里：所有东西都集中在一处，且**永远只从一个地方启动 agent**。
3. **它同时是「知识库」** —— "I'm able to **query it**, able to extract really, really rich data from it that goes into **course creation**, goes into **content creation**"。他明确说 wiki 的生成与维护会另开一期视频讲。

⚠️ **注意视频里的用词不一致**：他口头说的是 "**claw.md**"（AGENTS.md 的口语转写），文章和字典里统一写 AGENTS.md。

## 八、跟我们的关系

### 8.1 ⭐ 本机已经踩中了这个模式要解决的问题

我们本机 `~/.hermes/` 下有 **两个 skills 根目录**：
- `/Users/test/.hermes/skills/`（default profile）—— 46 个 skill
- `/Users/test/.hermes/profiles/general/skills/`（general profile）—— 35 个 skill

实测比对结果（2026-11-16）：

| 项 | 数量 |
|---|---:|
| 两处都有同名 skill | 12 |
| ✅ 内容完全相同 | 10 |
| ⚠️ **内容已漂移** | **2** |
| 只在 general 里有 | 23 |
| 只在 default 里有 | 217 |

**两个已漂移的正是**：
- `research/grounded-citations`
- `autonomous-ai-agents/hermes-agent`

⭐ **这就是 Home Repo 要根治的病，且本机已有可验证的实例**。漂移的后果是实的：同一份 skill 在两个 profile 下行为不一致，而且**改一处不会同步另一处**（本会话开头就遇到过 `software-development/github` 与 `software-development` 同名冲突导致 skill_view 无法加载 —— 这正是「重复 + 漂移」在文件系统上的表现）。

### 8.2 本机的 4 个仓天然适合 Home Repo

```
/Users/test/.hermes/repos/
├── iswiki                      public   2026-11-16
├── power-trading-vpp-knowledge private  2026-11-15
├── pv-intel                    public   2026-11-12
└── reader                      private  2026-11-11
```

**⭐ 完美命中官方说的「公私混用」场景** —— 这正是 Home Repo 存在的理由：
- `iswiki` / `pv-intel` 是 **public**
- `power-trading-vpp-knowledge` / `reader` 是 **private**

→ **不能上 monorepo**（public 仓塞进 private 组合会泄露），但**正是 Home Repo 的目标场景**。

而且这 4 个仓**确实存在跨仓协作**：
- `power-trading-vpp-knowledge` 的政策归档规范 与 `pv-intel` 的评审口径有交叉（之前发现 `发改能源〔2025〕1360号` 两仓重叠）
- `iswiki` 与 `pv-intel` 都是 public 笔记仓，但一个走 mdBook、一个走七段式，索引规范不同
- 本机已有 `~/.hermes/repos/` 这个**统一的仓根目录** —— 正是 Home Repo 要求的「home directory」布局

### 8.3 可落地的三个动作

| 优先级 | 动作 | 说明 |
|---|---|---|
| ⭐⭐ | **建 `~/.hermes/home/` 作为 Home Repo** | 放：跨 profile 共享的 skill（按 §2 的 shared 桶）、一份统一 `AGENTS.md`（含 4 个仓的指针）、跨仓约定（索引规范、commit message 风格、推送策略） |
| ⭐⭐ | **解掉 skills 重复** | 把 general / default 两处的 12 个同名 skill 收敛成一份（Home Repo 或单一 skill 根），**注意 default 与 general 是不同 profile，跨 profile 共享需确认 Hermes 是否支持**（本 skill 的运行边界明确写着「不要修改其他 profile 的 skills」） |
| ⭐ | **把 Home Repo 的 AGENTS.md 当「跨仓导航」** | 现有 memory 里已有本机 gateway / profile 等约定，但**分散在各 skill 里**；Home Repo 的 AGENTS.md 可以成为唯一入口，其余用 context pointer 指过去 |

⚠️ **8.3 第二条要谨慎**：本机 memory 明确写着「`/Users/test/.hermes/skills/` 属于不同 profile，**不要**擅自修改另一个 profile 的 skills/plugins/cron/memories，除非用户明确指示」。**跨 profile 收敛 skill 是需要用户拍板的决策，不能自动做。**

### 8.4 一条可以直接抄的指针写法

按 §3.3 的规则（描述按任务出现方式写），针对本机 4 仓：

```markdown
## Other Repos
iswiki (mdBook 技术调研笔记, public): ~/.hermes/repos/iswiki.
  Clone from git@github.com:ishadowland/iswiki.git if missing.
  写调研笔记前先读它的 README.md — 索引规范在文件里.
power-trading-vpp-knowledge (电力交易/虚拟电厂知识库, private):
  ~/.hermes/repos/power-trading-vpp-knowledge.
  政策类内容必须先归档原文并核验, 见其 references/政策原文/README.md.
pv-intel (光伏情报库, public): ~/.hermes/repos/pv-intel.
  评审产物只做方向级, 不下沉到具体产品.
reader (共读书稿工作副本, private): ~/.hermes/repos/reader.
  这是工作副本, 权威副本在 reader 仓.
```

⭐ 注意每条都带 **hint**（「先读它的 README.md」「政策类必须先归档核验」），这正是 §3.3 要求的 —— **否则 agent 没有理由跟随指针**。

## 九、⚠️ 三个我认为该存疑的点

> 💡 以下是本笔记的分析判断，不是 Matt 的原话。

### 9.1 「共享 skills」的权限与路径问题，官方没讲

Home Repo 假设 skills 放在**仓里**，agent 从仓启动就能发现。但我们本机是**多 profile + 多 harness**（general / stock / curator / coder 四个飞书机器人各一个 profile，各自有独立的 skills 目录），且 Hermes 明确禁止跨 profile 修改 skills。

**官方方案没有回答**：Home Repo 的 skills 怎么让**另一个 profile 的另一个 agent** 也能读到？符号链接？复制？mount？还是必须每个 profile 都放一份（那就回到了漂移问题）？

⚠️ 这不是小问题 —— 它决定这个模式在**多 agent 并行**场景下能不能落地。

### 9.2 「所有仓的 issue tracker 一起理解」在权限上要求很高

FAQ 说 "The agent can reach every repo's issue tracker, so it can make sense of them together"。这要求 agent 同时持有**多个仓的写权限**（至少读+开 issue）。

⚠️ 与 Home Repo 自己的安全姿态有张力：prompt 里明写 "**Secrets stay where they are: leave .env and other secret files unread**" —— 对 secrets 这么克制，却默认 agent 能开所有仓的 issue。**一个跨所有仓的凭据，本身就是个高价值攻击面。**

### 9.3 「约 20 个仓」是经验值，不是算出来的（视频已确认）

**视频字幕已把这条答案补上**（一手原话）：

> "This setup works for **maybe 20 30 40 repos** possibly. **It wouldn't scale to like 400 repos.**"

所以：
- ✅ 「20」**确实是经验值**，不是 token 预算推算 —— Matt 自己说的是 "maybe"，且实际区间是 **20–40**（比文章写的「约 20」宽松一倍）
- ✅ 400 档的**渐进披露**做法，视频给的具体形态与文章 FAQ 一致："instead of linking to the raw repos, you would just say, okay, here are the **front end repos**, here are the **back end repos**, and here are the **internal repos**"
- ⚠️ **但成本模型上的疑问仍然成立**：按「指针 = 一行、约 10-20 token」算，40 个指针 ≈ 400–800 token，**远没到上下文预算瓶颈**。真正的瓶颈是 **agent 的选择困难**（文章 400 档的原话 "too many decisions for the agent to choose between"）—— 也就是**注意力**而非 token。这两个是不同的约束，官方把它们混在一起说了。

⭐ 视频还补了一条文章没写的**判断依据**：Matt 说 progressive disclosure 之后，"the agent would just be able to find the right repo based on just **simple file system tactics**" —— 也就是说**渐进披露不只是省 token，而是给 agent 一个可搜索的分层结构**。

## 参考链接

- **官方文章（主源）**: <https://www.aihero.dev/the-home-repo-pattern>
- **AI Coding Dictionary 条目**: <https://aihero.dev/ai-coding-dictionary/home-repo>
- **字典条目的一手 markdown**: <https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Home%20Repo.md>
- **相关词条**: [Context pointer](https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Context%20pointer.md) · [Progressive disclosure](https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Progressive%20disclosure.md) · [AGENTS.md](https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/AGENTS.md.md) · [Grilling](https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Grilling.md) · [Software factory](https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Software%20factory.md) · [Sandbox](https://github.com/mattpocock/dictionary-of-ai-coding/blob/main/dictionary/Sandbox.md)
- **视频**: <https://www.youtube.com/watch?v=hWe-j78vNpc>（8:53 · 253K views）
- **相关仓**: <https://github.com/mattpocock/skills>（⭐325,498）· <https://github.com/mattpocock/dictionary-of-ai-coding>（⭐5,499）· <https://github.com/mattpocock/sandcastle>（⭐9,106）
- **相关笔记**: [mattpocock-skills](mattpocock-skills.md) · [mattpocock-skills-1-3](mattpocock-skills-1-3.md) · [awesome-agent-skills](awesome-agent-skills.md)
