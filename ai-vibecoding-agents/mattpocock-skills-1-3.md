# mattpocock/skills v1.3 — implement-spec / pr / retro 三个新 skill 拆解

> 学习笔记 · 调研时间 2026-10-18
> 视频: <https://youtu.be/QqhyqMvdx5Q>（Gary Chen · 28 万星 · 643 秒 · 2026-10-17 发布 · 官方 zh-TW 自动字幕全提取）
> 仓库: <https://github.com/mattpocock/skills> · 官网: <https://aihero.dev/skills> · 文档: <https://skills.sh/mattpocock/skills>
> License: MIT · 语言: Shell · ⭐ 294,790 · 🍴 24,726 · 2,016 commits · 189 open issues
> 版本: **v1.3.1**（2026-10-04 发布，plugin.json 实测）· 20 engineering + 7 productivity skills

## 一句话定位

**v1.3 把 Matt 的 skill 工作流从「单线五步」补成「闭环七步」** —— 新增 `implement-spec`（任务图并行施工）、`pr`（证据式 PR body）、`retro`（改环境不改代码的事后复盘），同时删掉 `resolving-merge-conflicts` 并把 `CONTEXT.md` 全线改名为 `GLOSSARY.md`。

> **本篇是 [mattpocock-skills](mattpocock-skills.md) 的 v1.3 续篇。** 那篇是 2026-08 的 v1.2 基线（18 engineering + 7 productivity），本篇覆盖三个新 skill 的底层设计 + 一手核验的 7 处纠偏。⚠️ 两篇的 `CONTEXT.md` 约定**已失效**，见 §7。

## 旧流程五步 → 新流程七步（视频主线）

原 1.2 流程停在「写完代码 + 审完」就断了；v1.3 把整条管线接成闭环：

```
【v1.2 · 五步 · 断在这里】
grill-with-docs → to-spec → to-tickets → implement → code-review ──✗

【v1.3 · 闭环】
grill-with-docs → to-spec → to-tickets → ⤵ implement-spec / implement
                                            ↓
                              code-review → pr → retro
                                        ↑_______|
                                    （改进环境，喂下一轮）
```

三个新 skill 分别补的是这三段：

| 新 skill | 补的是哪一段 | 调用方式 |
|---|---|---|
| `implement-spec` | 「implement 之后没下文」—— 10 张 ticket 要人肉循环 10 次 | **user-invoked**（`disable-model-invocation: true`） |
| `pr` | 「code-review 之后没人敢 merge」—— 人类审查速度成瓶颈 | **model-invoked**（agent 写 PR body 时自动触发） |
| `retro` | 「整条链跑完没人复盘」—— AI 中途犯了什么错你永远不知道 | **user-invoked** |

**视频的判断（作者的观察，可直接引用）**：
- 「Matt 认为现在的开发效率瓶颈在於人類審核 PR，而瓶頸在哪，AI 就應該在哪裡施力」——瓶颈从「写代码」转移到了「审代码」
- 「當 AI 寫程式寫得越來越快，身為人類開發者，我們的工作其實正在不斷往後移」→ 派工 / 验收 / 维护环境

## 三种使用方式（安装 / 调用 / 路由）

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **Claude Code plugin** | `claude plugin install mattpocock-skills@claude-plugins-official` | 想自动更新、不改源码 |
| **skills.sh / 其他 harness** | `npx skills@latest add mattpocock/skills -a <agent>` | 想 hack 文件；Codex / Copilot / Gemini CLI 各有对应命令 |
| **直接读 SKILL.md 抄思路** | `raw.githubusercontent.com/.../skills/engineering/<name>/SKILL.md` | 不用 Claude Code，只搬背后的 prompt 技巧 |

**不能两个都装**（实测 README 原文）：*"Installing both leaves you with every skill twice."*

## `implement-spec` —— 任务图并行（本篇最有价值的一段）

### 痛点（视频 2:43 讲得最准）

一份 spec 拆出 7~10+ 张 ticket，你要一張一張叫 agent，等它跑完、检查、清空 context，再下下一个 prompt —— **「其實你就是在扮演一個人肉版的 loop，在 AI 時代下這是一個有點愚蠢的行為」**。作者为此自己写过 `implement-tickets` skill，还私訊问过 Matt 会不会开 worktree 多线并行；Matt 当时的回覆大意是会用 Claude Code 或 Sandcastle 处理，所以没正式做成 skill。

### 底层设计：task graph 而非 list

实测 SKILL.md 原文的关键句：

> "The tickets are not a list of steps. They are a **task graph** with blocking relationships between them. This means there is always a **frontier** of tickets which are ready to be grabbed."

翻译成机制：

```
        spec #87
           │
     ┌─────┴─────┐
   #88         #89          ← 同时可做，改首页按钮 / 调设置页排版
     │           │
   #90         #91          ← 同时可做，修登录 bug
     │           │
     └─────┬─────┘
           │
          #92               ← 被阻塞，等前面的落地
```

- **frontier**（前沿）= 所有 blocker 都已落地的 ticket 集合，**同一时刻全部并行开工**
- **context pointer 而非粘贴摘要** —— subagent 之间靠指向 spec / ticket / 探索笔记 / 前序 commit 的**指针**通信，编排者的 context window 才留得住整张图
- **探索独立成一个 subagent**，笔记存到 repo 外的目录，让 implementer 只管实现

### integration branch 机制

全部落在**一条** integration branch 上。每个 implementer 三步：

1. 确认自己的 worktree **基于 integration branch**（不是就 reset）
2. 用 `tdd` red-green 一片一片建 ticket
3. **回报完成前先把 integration branch tip merge 进自己分支** —— 这样落库时是 fast-forward，不会有冲突解决

实测 SKILL.md 9 步全流程：读图 → 可选探索 agent → 建 integration 分支 → 起 implementer → merger agent 合入 → frontier 变化就再起一批 → 全票完成后 `code-review` 一次并交给**单个** fix agent → 标 ready 或按 tracker 关票 → 清理 worktree。

### ⚠️ 5 个实测坑（视频没讲，官方文档才有）

| 坑 | 现象 | 官方给的解法 |
|---|---|---|
| **worktree 只含 git track 的东西** | 依赖 gitignore 的 fixture / 本地 DB / 凭证的测试在 worktree 里**静默 skip 还能报绿** | 这类 ticket 让编排者在主 checkout 跑 |
| **GitHub blocked-by 不准** | tracker 的 blocked 计数只在 blocker **close** 时下降，而那是整轮结束 —— 「**blocked tickets 永远不会开工**」 | 让编排者**自己按 integration branch 的 merge 记录**算 frontier |
| **并行撞同一文件** | 两个 frontier ticket 都往 message catalogue / config registry 加东西；实测有人的 web 和 mobile ticket 都加了 `blockedSince` / `blockedOn` 两个字符串 | 补一条 blocking edge 让它们串行，或在探索笔记里定死名字 |
| **code-review 中途跑** | 它拿整份 spec 对比代码，没建的票全算 failure → 触发「建票 → 再审」死循环，实测有人 5 张票跑了 **4 小时** | 只在最后跑一次；看到第二次全量审查就让它停下来 |
| **subagent 不继承 tdd 指令** | 从 1 张票扩到整份 spec 后 red-green 就断了 | v1.3 已修（每个 implementer 显式 `Call the Skill tool with tdd`） |

### 对 Sandcastle 的定位（常被误解）

官方文档明确写了，这段值得抄进自己的方案：

> "`implement-spec` puts an agent in charge of orchestration **inside one harness session**... For work that is truly AFK, a **deterministic loop** (Sandcastle, a shell script, a CI job) is **faster, cheaper, and more reliable**, because no agent makes the orchestration decisions."

即：`implement-spec` 换成「一个 agent 编排」；真要无人值守，**确定性脚本比 agent 编排更划算**。Sandcastle（Matt 本人的仓，⭐ 8,494 / MIT / 实测仍在活跃维护，2026-10-16 有 push）是这条路的现成实现。

## `pr` —— 让人类几十秒建立信任

**定位纠偏（视频没说清）**：`pr` 是**格式参考**，不是工作流。它**不 push 分支、不开 PR、不决定放什么进去**，只规定 PR body 该长什么样。

### 三段式模板

| 段 | 内容 | 为什么这么写 |
|---|---|---|
| **Summary** | 不用段落，用**最小的视觉**讲清改动 —— 伪代码 / 调用树 / 组件树 / 文件树 / Mermaid / 整形 diff，**六选一，偶尔多个，极少全上** | 审查者 diff 已经开着，body 的职责是先给形状 |
| **Evidence** | 强制**前后对比**：截图（视觉改动最强证据）或「之前失败、现在通过」的具体测试（写成伪代码）/ 变了的那行 console 输出 | 「只要强制要求证据，AI 就會真的在背景跑一次測試、截一張圖，而不是嘴上說說我都看過了」 |
| **Merge Danger** | **one-way door 还是 two-way door** + **blast radius** | 把「能合吗」从 gut feeling 变成一句**可以被反驳的断言** |

two-way door = 便宜可回滚；one-way door = 破坏性迁移 / 删公开 API / 难以逆转的决定。blast radius 点名「如果改错了会坏什么」：布局跳动、API 消费者、移动端响应式。

> **Summary 的视觉菜单出处**：Skill 的 `CREDITS.md` 实测写明，抄自 Dex Horthy 的 `show-me` skill（humanlayer 仓），几乎逐字搬运。引用时要注明。

### ⚠️ 4 个实测坑

| 坑 | 说明 |
|---|---|
| **不能盲信 agent 自己评的门** | 写代码的和打分的同一个 agent。它说「two-way, blast radius 小」时最可疑。实测原话：*"rolling back a commit won't unsend a batch of emails"* —— 灰度发布在第一批写入前是 two-way，写进去之后就不是了 |
| **跟你仓里的 PR 模板冲突** | `pr` **完全不读** `.github/pull_request_template.md`，自己带一套模板 → agent 同时收到两条互相矛盾的指令。解法：在仓的 agent 文档里把 Summary/Evidence/Merge Danger 塞进仓模板下面 |
| **Mermaid 在终端不渲染** | GitHub/GitLab 渲染 Mermaid，终端不渲染，看起来像乱码。CLI harness 用户用 ASCII Mermaid renderer，或让 agent 附一份 HTML |
| **body 会过期 + 不处理 review 评论** | 它只写一次就停；PR 改了 body 就 stale。**不会**帮你分拣别人 / review bot 回来的评论 |

**能追溯的建议**：让 agent 写之前手里有 ticket 或 spec（不只是 diff），并把你们仓里「永远算 one-way」的事（schema 迁移、对外发布、删除）写进 agent 会读到的地方。

## `retro` —— 改环境，不改代码

### 核心二分

`retro` **只提议，不动手**。任何改动都要你点头（这是刻意设计：有人被 auto-hook 挡过好改动 —— *"burned by auto-hooks that blocked good changes"*）。也没有 dry-run。

它找的是**环境漏洞**，不是代码 bug：agent 找了 20 次工具调用才找到的文件、工具本该拦下却没拦的错误、审查者漏掉的主观判断失误。

### 七类发现 → 修在哪

| session 里出了什么问题 | 用什么修 |
|---|---|
| agent 花了很久才找到某个文件/事实 | 一条 **navigation pointer**（放在它已经会读的文件里） |
| 犯了工具本该能抓的错误 | **自动化检查**：lint 规则 / 类型 / 测试 / pre-commit hook / CI job |
| 审查者漏掉了主观判断类的错误 | `CODING_STANDARDS.md` 里给**审查 agent** 的规则 |
| `AGENTS.md` / `CLAUDE.md` 太大 | 把里面的引导挪到 standards 或 checks |
| 某次工具调用很贵却回报很少 | 精简或替换那个工具 |
| 引导文件里一堆「写了但什么也不改变」的指令 | 删掉这些 **no-ops** |
| agent 需要但拿不到的信息 | 放宽它的访问：把 dev server 日志 tee 到文件、给只读访问 |

### 最有价值的一条原则：standards 属于审查者，不属于实现者

> 实现 agent 的 context pressure 最大（要探索 + 写代码 + 调 bug）；审查 agent 拿到的是一份 diff，仅此而已。所以新规则要放在**有余力执行它的地方** —— 审查。它**永远不进 `AGENTS.md`**，因为那玩意每个 session 都往 context window 灌，不管用不用得上。

配套的严格二分（官方原文）：**mechanical 违规**（禁用 API、import 形状、文件位置）→ 做成会失败的确定性检查，因为「a check can fail and a sentence in a standards file can't」；只有真需要主观判断的才写成文字。另外：**仓里一个护栏都没有**（没有 pre-commit hook，也没有跑 lint+typecheck+test 的 CI），这本身就是一条发现。

### ⚠️ 最强的一条批评（写进去的，必须知道）

用户实测反馈：「job 一完成，AI 就會忘記 session 中間的掙扎，然後編造 generic advice 來滿足 retro 的分類」。

- 对策：每条提案必须能**指回 session 里的某个具体时刻**；指不回去的丢掉
- 代价：它很难编出不相关内容，但也可能**过度看重这一段 session 恰好在讲的东西**
- 严重度排序也只是初稿 —— 「一个安静但昂贵的错误，可能排在了一个吵闹但廉价的错误后面」
- **它从不复审上个月提的 lint 规则**：只看一个 session，判断不了某条规则现在是否老是在好代码上误报。**清理检查仍得你亲手做 —— 「一条老是在好代码上报错的规则，就是该删它的信号」**

这条批评对本篇的「跟我们的关系」段直接产生影响。

## 一手核验：视频 vs 官方仓库（7 处）

| # | 视频的说法 | 官方实测 | 判定 |
|---|---|---|---|
| 1 | 「Matt 推出了 1.3 版，新增 implement-spec、pr、retro 三個 Skill」 | ✅ 完全属实，且 v1.3.1 已于 2026-10-04 发布 | **准确** |
| 2 | 「舊流程五步：grill-me / to-spec / to-tickets / implement / code-review」 | ✅ 属实。实测主链为 `grill-with-docs → to-spec → to-tickets → implement → code-review → retro`，`pr` 插在 review 与 retro 之间 | **基本准确**（详见 #6） |
| 3 | 「Matt 本人最喜歡 Retro」 | ✅ 无法核实为公开事实（属作者转述），但 CHANGELOG 中 `retro` 确为 1.3 三个 graduate 之一，且描述最完整 | **作者转述，无法一手核实** |
| 4 | 「兩支子 Agent 在各自獨立的 worktree 裡同時施工」 | ✅ SKILL.md 逐字印证，且更进一步：merger subagent、探索 subagent、fix subagent 分工明确 | **准确且视频讲得更浅** |
| 5 | 「implement-spec 讓 AI 照依賴關係並行」 | ✅ 「task graph」/「frontier」原文直出 | **准确** |
| 6 | 视频全程按五步讲旧流程 | ⚠️ **v1.3.0 同时删掉了 `resolving-merge-conflicts`**，且把 `CONTEXT.md` / `CONTEXT-MAP.md` **全线改名为 `GLOSSARY.md` / `GLOSSARY-MAP.md`**，影响 11 个 skill + docs | **视频完全未提这两项破坏性变更** |
| 7 | 未提 pr 的来源 | 视频说「Matt 寫的」 | ⚠️ **Summary 视觉菜单抄自 Dex Horthy 的 `show-me`**，Skill 自带 `CREDITS.md` 注明「几乎逐字搬运」 | **归属需修正** |

**另一处版本号纠偏**：视频发布于 2026-10-17，但仓库最新 tag 是 **v1.3.1（2026-10-04）**，不是 1.3.0；plugin.json 实测 `version: 1.3.1`。

## ⚠️ 对已有笔记的失效提醒

本篇要动 [mattpocock-skills](mattpocock-skills.md) 的两处 —— **该篇写于 v1.2，以下两条已失效**：

1. **`CONTEXT.md` → `GLOSSARY.md`**：v1.3.0 把这个约定改名，影响 domain-modeling / grill-with-docs / improve-codebase-architecture / setup-matt-pocock-skills / triage / tdd / diagnosing-bugs / ask-matt / codebase-design / wait-what / pr 共 11 个 skill + 文档站。已有文件需 `git mv`。**那篇笔记里 6 处提到 `CONTEXT.md` 都要改。**
2. **skill 数量与清单**：18 → 20 engineering（+implement-spec +pr +retro −resolving-merge-conflicts），18.8k → 24.7k forks，⭐ 218k → 294,790。

## 跟我们的关系

按视频作者的思路（「沒在用 Matt 的 skill，也能把背後的做法搬進自己的工作流」），可迁移的四件事：

### 1. `implement-spec` 的 task-graph 思路 → Hermes 的并行 delegation

Hermes 已有 `delegate_task`，但目前的模式是「我拆好任务清单 → 一次性 batch 发 3 个」。`implement-spec` 的前沿思想补了一块：

- **关键差异不是「能不能并行」，而是「谁决定现在能并行什么」**。Hermes 的 batch 是静态列表；task graph 是动态 frontier —— #88 落地后 #92 立刻可开工，不需要我再发一轮指令
- **可以直接借用的 prompt 技巧**（视频 3:46 明确给了这句，且这是全片最可迁移的一句）：
  > 「只要在 Prompt 請它先拆成細項並標註每項之間的 Dependency，也就是依賴關係，再由不同的 Subagent 並行處理就好」
  → 用在任何不支持 worktree 的 harness 上，包括 Hermes。**代价与官方一致**：worktree 只含 git track 的东西，Hermes 的 subagent 共用同一份工作区，比 worktree 的隔离更弱，撞文件的概率更高
- **5 个坑同样适用于 Hermes**，尤其「GitHub blocked-by 不准 → 自己按 merge 记录算 frontier」和「review 中途跑会死循环 4 小时」

### 2. `retro` 的「改环境不改代码」→ 跟 Hermes 现有的 retro 类工作直接同构

Hermes 已有 `change-quiz`（skill，写完工作产出变更报告）和 `reference-hunt`（拿现有代码当 spec），方向一致：**产出沉淀，不产幻觉**。

`retro` 补的是它们没做的一块 —— **产出落到环境改动上，而不是又一份报告**。最值得直接搬的是它的严格二分：

| 错误类型 | Hermes 现状 | `retro` 的做法 |
|---|---|---|
| mechanical（路径写错、命令错） | 靠记忆下次注意 | **写成检查，让它会失败** |
| judgement（架构风格、代码品味） | 写进 memory | 写进 reviewer 读的 standards 文件 |

这跟记忆里那条「笔记写入铁律」正好互补 —— 那条治的是**执行层**的静默失败（patch 静默失败要读回验证），`retro` 治的是**规则该沉淀在哪**。

⚠️ 但 `retro` 自己被实测批评「会编造 generic advice 填分类」。**照搬时必须保留它的失败模式**：每条提案都要能指回 session 的具体时刻，指不回去就丢。

### 3. `pr` 的 one-way / two-way door → 跟我们的 commit + 直推 main 策略正面对撞

本仓 iswiki 遵循 SKILL.md §5「用户没说要 push → 本地 commit 不 push，等确认」，且**直推 main 不开 PR**。`pr` 的 Merge Danger 那一段**恰好能给这套策略补一块**：

- iswiki 的改动**全部是 two-way door**（纯文档追加，git 可回滚），所以 blast radius 小 → 直推 main 的风险确实低
- 但**「要不要开 PR」这个问题本身该有一个明写的断言**，而不是靠习惯。当前 iswiki 仓没有 PR 流程，所以直推是对的
- 值得借的是**摘录硬规则进 commit body** 的习惯 —— 官方建议：把仓里「永远算 one-way」的事（schema 迁移 / 对外发布 / 删除）写进 agent 会读到的地方。iswiki 的对应清单就是：**不要 force push、不要删历史笔记（SKILL.md §6 要求标失效保留快照）、不要改坏 mdbook 引用路径**

### 4. 装不装？—— 建议**不装**，只借三段 prompt

| 选项 | 判断 |
|---|---|
| 装进 Hermes coder profile | ❌ **不建议**。三点理由：① 20+7 个 skill 的量对 Hermes 是重复建设 —— Hermes 已有 `implementation-plan` / `writing-plans` / `subagent-driven-development` / `interactive-debugging`，跟 grill/to-spec/to-tickets/implement 重叠严重；② 它假设 Claude Code / Codex 的 harness（有 worktree、有 Skill tool、有 session log），Hermes 三样都不完全等价；③ 上游**近期极活跃**（实测 2016 commits、2 个月发了 4 个 minor/patch），changelog 实测有大量「修 bug 改措辞」的 patch，跟进成本高 |
| 搬 `implement-spec` 的 task-graph 写法 | ✅ **推荐**，就是上面第 1 条那句 prompt 技巧 |
| 搬 `retro` 的环境二分法 | ✅ **推荐**，成本极低（一个 checklist），收益是让规则沉淀到对的地方 |
| 搬 `pr` 的三段式 | 🟡 **可选**。我们几乎不开 PR，但 one-way/two-way 这个判断值得内化成「要不要停下来问用户」的标准 |

**注意**：那篇 v1.2 笔记记录了「2026-08-18 已装到 Hermes coder profile 的 grill-me + grilling」。如果那是真的，**需要复核** —— 本篇不建议再扩装，但已有的两个 skill 值得留着（`grill-me` 只是 7 行 wrapper，逻辑在 `grilling`，正是 task-graph 那类「用 CLI 逻辑而不是 LLM 判断」的例子）。

## 实战建议 / 风险点

| 风险 | 说明 | 对策 |
|---|---|---|
| **task graph 假并行** | blocking edge 是「从 ticket 文本猜哪个文件会被碰」，猜错就撞车 | 让探索 agent 在开跑前先探 shared file，把「两票都要动的文件」显式写成 edge |
| **无 UI 改动的 Evidence 空档** | iswiki 这类纯文档改动没有截图 | 用「之前这条链接 404 / 现在能点开」或「README 索引从 N 条变 N+1 条」当 before-after |
| **retro 的造谣风险** | 见上文实测批评 | 硬规则：提案必须指回具体时刻，否则丢弃 |
| **over-engineering 倾向** | 5 张票以下、线性依赖的工作用 `implement-spec` 是浪费 | 官方原话：小改动没有真图就直接用 `implement` |
| **GLOSSARY 改名未同步** | 我们若已按 `CONTEXT.md` 约定建过文件，升级后 skills 读不到 | `git mv CONTEXT.md GLOSSARY.md`，先做这步再升版本 |

## 参考链接

- 视频: <https://youtu.be/QqhyqMvdx5Q>（Gary Chen · 《28 萬星的 Matt Pocock skill 更新拆解！》）
- 仓库: <https://github.com/mattpocock/skills> · Releases: <https://github.com/mattpocock/skills/releases>
- CHANGELOG（1.3.0 三个 graduate 的完整说明）: <https://github.com/mattpocock/skills/blob/main/CHANGELOG.md>
- 三篇官方文档: [`implement-spec`](https://aihero.dev/skills-implement-spec) · [`pr`](https://aihero.dev/skills-pr) · [`retro`](https://aihero.dev/skills-retro)
- `pr` 的视觉菜单出处（`show-me`）: <https://github.com/humanlayer/humanlayer>
- Sandcastle（确定性 AFK 编排）: <https://github.com/mattpocock/sandcastle>
- 中文翻译（对照阅读）: <https://github.com/devcxl/mattpocock-skills-zh> · <https://github.com/CNife/learn-mattpocock-skills>
- 同作者前作: [reaVideoReview](reaVideoReview.md)（Gary Chen 的视频一手拆解范式）

## 相关笔记

| 笔记 | 关系 |
|---|---|
| [mattpocock-skills](mattpocock-skills.md) | 本篇的 v1.2 基线；⚠️ 其 `CONTEXT.md` 约定与 skill 清单已被 v1.3 推翻 |
| [reaVideoReview](reaVideoReview.md) | 同一作者同一手法（一手字幕 + 一手核验纠偏） |
| [awesome-agent-skills](awesome-agent-skills.md) | 1497+ skill 全集索引，本篇是其子集深挖 |
| [paseo](paseo.md) | 跨 agent 编排器，与 task-graph 并行思路对照 |
