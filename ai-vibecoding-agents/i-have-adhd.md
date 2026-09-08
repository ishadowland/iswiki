# i-have-adhd — AI 编程助手的 ADHD-friendly 输出 Skill

> 学习笔记 · 调研时间 2026-08-12 · 最近更新 2026-09-01
> 仓库: <https://github.com/ayghri/i-have-adhd>
> 文档: <INSTALL.md> · <SKILL.md> · License: MIT · ⭐ 26.1k (1.6k forks · 169 commits · v0.2.0)
> 灵感来源: *The Adult ADHD Tool Kit* by J. Russell Ramsay & Anthony L. Rostain
> 补充材料: 程序汪「一个SKILL.md拿下2.3万Star」深度解读 (2026-09-01)

## 一句话定位

**一个 prompt-level 的输出风格 Skill** —— 教你的 AI coding agent (Claude Code / Codex / Cursor / Gemini CLI / Kimi / Qwen / Antigravity / OpenCode / Pi) 把回答写成 **"action-first、numbered、no-preamble"** 的形式,适合 ADHD 读者(以及所有人,因为信息密度更高)。**不需要 ADHD 诊断**。

## 跟其他 iswiki 工具的关系

| 工具 | 关系 |
|---|---|
| [codex-security](codex-security.md) | ✅ 都是 Codex 可装的 plugin/skill,互补 |
| [qoder-security](qoder-security.md) | 🟡 Qoder 内嵌安全,本 skill 是输出风格 |
| [Strix](Strix.md) | ⚪ 不相关 |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | 🟡 Kimi 体系内的 skill(本 skill 支持 Kimi) |

## 10 条规则(全文在 SKILL.md)

| # | 规则 | 例子 |
|---|---|---|
| 1 | **Lead with the next action** | 跑 `npm install jsonwebtoken`,然后编辑 `src/auth.ts:42` |
| 2 | **Number multi-step tasks** | 1. 打开 2. 替换 3. 测试 |
| 3 | **End with one concrete next action** | "Next: 跑 `npm test` 并贴首个失败行" |
| 4 | **Suppress tangents** | "另一个 stale dep 先放一边" |
| 5 | **Restate state every turn** | "Step 3 of 5 done: schema 更新" |
| 6 | **Specific time estimates** | "约 15 分钟(如有测试),半天(否则)" |
| 7 | **Make wins visible** | "Login 现在能用 magic link 了" |
| 8 | **Matter-of-fact errors** | "auth.spec.ts:42 fail: 401. 缺 auth header. 加 `Authorization: Bearer ***`" |
| 9 | **Cap lists at 5** | 5 个 ranked > 10 个 unranked |
| 10 | **No preamble / recap / closer** | 禁用 "Great question" / "Hope this helps" / "Let me know" |

## Before / After 真实例子

| Before (verbose) | After (i-have-adhd) |
|---|---|
| "Great question! Let me think about this. Your auth flow has a few moving pieces: the middleware, the token verification, and the cookie handling. Looking at `src/auth.ts`, the `verifyToken` function (around lines 42-58) seems to be using an older `jsonwebtoken` API. One approach would be to update the package and rewrite that function. After making the change, you'd want to run the auth tests to confirm nothing breaks. By the way, you might also want to look at your dependency versions overall. Hope this helps! Let me know if you want to dig deeper." | "Run `npm install jsonwebtoken@latest`, then edit `src/auth.ts:42`.<br><br>1. Open `src/auth.ts`<br>2. Replace `verifyToken` (lines 42–58) with the snippet below<br>3. Run `npm test -- auth.spec.ts`<br><br>Next: paste the first failing line if any test fails." |

## 5 个 ADHD 真相驱动 10 条规则

> 来源: SKILL.md "What ADHD changes about reading"

1. **Working memory is small** — 不在屏上的就忘。不要说"记住 X"
2. **Knowing != Doing** — "懂了" 和 "做" 之间的摩擦是死亡之谷
3. **Starting is hardest** — 第一个 action 必须明显、小、能现在做
4. **Time feels uniform** — "一点工作" 和 "几小时" 听起来一样,模糊估计失败
5. **Dopamine is scarce** — 可视进度重要,被埋没的胜利不会 register

## "When to break the rules" — 6 个例外

1. 用户说 "explain" / "walk me through" — 完整解释,仍无 preamble/closer
2. **Destructive action ahead** (`rm -rf`, force push, schema migration) — 先确认,安全 > 简洁
3. **Debug spiral** — 连续 3 turn "still broken" 就停,命名假设,问 1 个诊断问题
4. **Real ambiguity** — 1 个简短的澄清问题胜过猜
5. **A rule fights the task** — 任务赢。例如 "what are my options" 给 2-4 ranked
6. **A rule fights the harness** — system prompt > skill,工具调用要 announce

## Pre-send check(发之前必删)

1. 第一句如果是 "我准备做什么" — 删
2. 最后一句如果是 "anything else?" / recap — 删
3. 任何 "by the way" — 删
4. 任何无信息的 hedging ("perhaps", "might", "could possibly") — 删
5. 任何 idiom/figurative phrase ("circle back", "get the ball rolling") — 替换成字面 action

**最后 verify**: **如果读者只看首尾两行,知不知道(a)下一步做什么 (b)刚发生了什么?** 是 → 发。

## 支持的平台(已扩到 9+ 个,版本 v0.2.0)

| 平台 | 安装方式 | 路径 |
|---|---|---|
| **Antigravity (agy)** | `agy plugin install https://github.com/ayghri/i-have-adhd` | `.agents/plugins/` |
| **Claude Code** | `claude plugin marketplace add ayghri/i-have-adhd`<br>`claude plugin install i-have-adhd@i-have-adhd` | `.claude-plugin/` |
| **Codex (OpenAI)** | Codex plugin | `.codex-plugin/` |
| **Cursor** | npx skills add | `.cursor/skills/i-have-adhd/` |
| **Gemini CLI** | extension (`gemini-extension.json`) | 仓库根 |
| **Kimi** | plugin (`kimi.plugin.json`) | 仓库根 |
| **Qwen Code** | extension (`qwen-extension.json`) | 仓库根 |
| **OpenCode** | server plugin + command + always-on (`opencode.json`) | `.opencode/` |
| **Pi (pi-native)** | extension (`extensions/feat/pi-native-extension`) + **`AdhdConfig` 配置** (alwaysOn / hideStatus) | `extensions/` |

→ **一个 skill,9+ 个 AI coding agent 平台通吃**(v0.2.0 新增 Pi 的 `alwaysOn` / `hideStatus` 配置)

## Always-on mode (3 种方式)

### 1) Claude Code hook

```bash
touch ~/.claude/.i-have-adhd-always
```

→ `SessionStart` hook 自动加载,无需 `/i-have-adhd` 调用

### 2) Antigravity / Gemini

加到 `~/.gemini/GEMINI.md`:

```markdown
## Output style
The reader has ADHD. Shape every response so it can be acted on:
1. Lead with the answer or next action
2. Number multi-step work
... (10 rules 摘要)
```

### 3) Codex / Cursor / Kimi

各家 platform 自己的 "default skills" 配置

## 调用方式

```bash
# Claude Code
claude plugin install i-have-adhd@i-have-adhd
# 然后:
/i-have-adhd

# 关闭
"stop adhd mode" 或 "normal mode"
```

**Persistence**: 规则在整个 session 持续,不会因话题切换而失效

## "Tune it" — Fork + 自定义

```bash
claude plugin uninstall i-have-adhd            # drop upstream
claude plugin marketplace remove i-have-adhd   # upstream + fork 同名
claude plugin marketplace add <your-username>/i-have-adhd
claude plugin install i-have-adhd@i-have-adhd
# edit skills/i-have-adhd/SKILL.md
```

→ 适合团队 / 个人化(例如不同团队的"action"标准不一样)

## 类似项目对比

| 项目 | 类型 | 重点 | ADHD-friendly |
|---|---|---|---|
| **i-have-adhd** | Skill | 输出风格 | ✅ 核心定位 |
| [codex-security](codex-security.md) | Plugin | 安全扫描 | ❌ 安全 |
| [qoder-security](qoder-security.md) | 内嵌 | L1/L2/L3 安全 | ❌ 安全 |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | Skill | Kimi PPT 生成 | ⚪ 工具调用 |
| Claude Code Memory | 框架 | 上下文持久化 | ⚪ 互补(持久 ≠ 输出风格) |

## 适用场景

| 场景 | 推荐 |
|---|---|
| **个人 ADHD 用户** | ✅ 必装 |
| **团队 code review** | ✅ 减少 reviewer 疲劳 |
| **教学 / 演示** | ✅ 学生 / 听众 容易 follow |
| **复杂任务多步骤** | ✅ Numbered + Restate state |
| **debug 长 session** | ✅ "Step 3 of 5 done" 防丢失上下文 |
| **短问答** | 🟡 overkill,但 still 适用 |
| **异步文档生成** | ✅ 比纯文档更高密度 |
| **会议纪要 / changelog** | ✅ 强制 action-first |

## 程序汪解读:为什么这个 skill 值得装 (2026-09-01 微信版)

> 资料源: 「我是程序汪」公众号 2026-09-01「一个SKILL.md拿下2.3万Star:让Codex/ClaudeCode少说废话、先给答案」(作者小G,原发JavaGuide)

### 解决的 3 个真实痛点 (作者原话)

1. **第一屏先出现能执行的东西** — Agent 喜欢先证明自己懂了,"这是一个很好的问题"/"让我先分析一下" 把命令挤到屏幕外。`i-have-adhd` 强制第一行 = 答案或 next action
2. **多轮任务不用猜做到哪** — 单轮问答结束就结束,但 Coding Agent 连续工作十几轮。前面的"改过什么/测试过没"散在不同消息里。Skill 要求每轮重新声明状态:「Step 3 of 5 done: schema 更新」
3. **报错和完成状态都说具体** — "好像出了点问题" 改成 `auth.spec.ts:42: 预期 200, 实际 401。原因: 缺认证头。修复: 为请求添加 Authorization: Bearer ***`

### 该解释和确认的时候不会硬压缩 (被低估的一条)

短≠所有问题都三句话。**用户要求"详细解释"或"带我一步步理解"**,允许 Agent 正常展开。**大范围删除 / 强制推送 / 数据库迁移**这类破坏性操作,确认步骤不能省。**连续 3 轮修复没解决** → 停下,命名假设,问 1 个诊断问题,不盲改。

### 实际安装命令 (Codex / Claude Code)

**Codex:**

```bash
codex plugin marketplace add ayghri/i-have-adhd --ref main
codex plugin add i-have-adhd@i-have-adhd
codex plugin list                       # 验证安装

# 会话内启用
$i-have-adhd

# Codex 不自动开启,需显式调用;想全会话默认 → 配官方常驻规则
```

**Claude Code:**

```bash
claude plugin marketplace add ayghri/i-have-adhd
claude plugin install i-have-adhd@i-have-adhd

# 会话内启用
/i-have-adhd
# 当前会话没识别到新插件时:
/exit                                  # 重新加载

# 常驻 (默认所有会话都用)
touch ~/.claude/.i-have-adhd-always
# → `SessionStart` hook 自动加载规则,无需 /i-have-adhd

# 临时关闭
"stop adhd mode" 或 "normal mode"
# 恢复按需 → 删标记文件
rm ~/.claude/.i-have-adhd-always
```

### 作者的使用策略 (重要)

> "先保留按需启用。排错、执行修改和推进长任务时打开;需要讨论方案、讲源码或审文章时,再决定要不要保留更完整的解释。"
> "用上一段时间,确定自己确实喜欢这种回答方式,再设成默认也不迟。"

→ **反 install 教条** — 不要上来就 `touch ~/.claude/.i-have-adhd-always`,先按需用 1-2 周

### 文章小结 (作者立场)

- 优点: **prompt-level + 单文件 SKILL.md**,模型不变、读代码 / 改文件 / 执行命令的工具不变,**只调整回答顺序、步骤长度、进度表达、错误说明**
- 局限: 名字里的 `adhd` 容易让人误以为是诊断或治疗,实际只管 Agent 怎么组织回答
- 生态意义: **跨 9+ 平台通用**,对"哪个 Coding Agent 都让 Agent 答非所问"有共振价值

## 风险与限制

- **不是 productivity 工具** — 只是输出风格,不会让你"做事"
- **Action-first 可能略去 context** — 复杂解释时还是需要"explain fully"(SKILL.md 规则 1)
- **关闭词必须明确** — "stop adhd mode" / "normal mode",LLM 可能不听
- **Dependency on platform plugin system** — 如果平台不更新 plugin schema,可能失效
- **i18n** — README 有 6 种语言(英/中/葡/日/越/韩),但 SKILL.md 仅英文
- **v0.2.0 (2026-08 中)** — 整体迁移到 plugin mode,新增 Pi 的 `alwaysOn` / `hideStatus` config + OpenCode server plugin

## 关键设计理念

> "Adapted for how an LLM should respond, **not how a human should organize their day.**"
> — Credits 段

→ 灵感来自 *The Adult ADHD Tool Kit*,但**适配对象是 LLM 输出**,不是人类时间管理

## 关联资料

- 仓库: <https://github.com/ayghri/i-have-adhd>
- 安装: <https://github.com/ayghri/i-have-adhd/blob/main/INSTALL.md>
- SKILL.md: <https://github.com/ayghri/i-have-adhd/blob/main/skills/i-have-adhd/SKILL.md>
- 程序汪解读 (2026-09-01): <https://mp.weixin.qq.com/s/rSJQHy1EIIHbDFljySVA2A>
- Credits 灵感: *The Adult ADHD Tool Kit* (J. Russell Ramsay & Anthony L. Rostain)

## 跟 Hermes 的关系(bonus)

让我看看这个 skill 跟 Hermes agent 输出的关系 — Hermes 已经用:
- 极简、指令式回复 ✓ (匹配 #10 "no preamble")
- 短句优先 ✓ (匹配 #5 "specific time" + #1 "lead with action")
- 你 (liuyin) 飞书 message "不用 markdown" ✓ (匹配 #2 "numbered + plain text")

→ Hermes 实际上**已经在不自觉地用 i-have-adhd 风格**(因为你"喜欢极简")。这 skill 是给 LLM 的 prompt-level 标准化 — Hermes 是给 Hermes agent 的 system prompt-level 标准化。

**潜在玩法**: 让 Hermes 在 user opts in 后**自动加载 SKILL.md** 进 system prompt