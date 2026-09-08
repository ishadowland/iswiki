# Ponytail — 给 AI agent 注入"最懒高级工程师"人格的跨平台 skill 集

> 学习笔记 · 调研时间 2026-08-31
> 仓库: <https://github.com/DietrichGebert/ponytail> · 官网: <https://ponytail.dev> · 文档: <https://github.com/DietrichGebert/ponytail/blob/main/docs/agent-portability.md>
> License: **MIT** · 语言: JavaScript (Hermes 适配器是 Python) · ⭐ **117.9k** · 🍴 6.4k · topics: agent-skills, claude-code, cursor-rules, prompt-engineering, yagni
> 最新版: v4.9.0 (对应仓版本) · 创建: 2026-06-12 (2.5 个月) · 最后 push 2026-08-07

## 一句话定位

**Ponytail = 给 AI coding agent 注入"老员工 + YAGNI"人格的跨 13 平台 skill 集**,核心一句话: "He says nothing. He writes one line. It works." —— 不教 agent 怎么写代码,教它**先判断要不要写、写哪一行最少**。

## 三种使用方式

| 方式 | 命令 | 适用 |
|---|---|---|
| **插件装**(完整功能,带 commands + 强度切换) | Claude Code: `/plugin marketplace add DietrichGebert/ponytail` + `/plugin install ponytail@ponytail`<br>Hermes: `hermes plugins install DietrichGebert/ponytail --enable`<br>Codex/Copilot/Qoder/Devin/Grok 类似 | 想用 `/ponytail-review`、`/ponytail-audit`、`/ponytail-debt`、`/ponytail-gain` 这些**命令** |
| **项目规则**(指令级 fallback,无 commands) | 把 `AGENTS.md` 拷到项目根,或 `.cursor/rules/ponytail.mdc` / `.windsurf/rules/ponytail.md` 等 | Cursor / Windsurf / Cline / Copilot Chat / Zed / Junie / Jules / Amp / Kiro —— 这些**只读项目指令**,不能装插件 |
| **按需 skill 触发** | Claude/Codex: `@ponytail-review` / `@ponytail-audit`<br>Hermes: `ponytail:ponytail-review` | 只在某个时刻要"懒检查"或"全仓审计",平时不污染 context |

**强度档(完整插件模式)**:`/ponytail lite|full|ultra|off`,默认 `full`。env `PONYTAIL_DEFAULT_MODE` 全局默认。

## 核心组件 / 模块 / 架构

### 一句话:1 个核心 instruction body + 13 个薄适配器

```
┌─────────────────────────────────────────────────────────┐
│  CORE(单源真理,所有适配器都指回这里)                      │
│                                                         │
│  AGENTS.md         32 行,instruction-only 紧凑版         │
│  skills/ponytail/SKILL.md    完整版(含强度档过滤逻辑)   │
│  skills/ponytail-{review,audit,debt,gain,help}/SKILL.md  5 个按需 skill │
│  hooks/ponytail-{mode-tracker,activate,instructions,subagent,statusline}.js │
│  commands/       命令文件(每个 host 不同)               │
│                                                         │
└──────────────────┬──────────────────────────────────────┘
                   │
       ┌───────────┼────────────────────────────────────┐
       ▼           ▼            ▼            ▼            ▼
   13 个 host 适配器(各 1~几个文件,薄):

   Claude Code   .claude-plugin/plugin.json + commands/ + hooks/
   Codex         .codex-plugin/plugin.json + hooks/
   Copilot CLI   .github/plugin/ + AGENTS.md
   Gemini CLI    gemini-extension.json + AGENTS.md
   OpenCode      .opencode/plugins/ponytail.mjs + .opencode/command/
   Hermes        plugin.yaml + __init__.py + skills/         ← 我们最关心
   Pi            pi-extension/index.js
   Qoder         .qoder-plugin/plugin.json + hooks/qoder-hooks.json
   Devin CLI     .devin-plugin/plugin.json
   Grok Build    root plugin.json + .grok-plugin/marketplace.json
   OpenClaw      .openclaw/skills/ (自动从 skills/ 生成)
   Cursor/Windsurf/Cline/Copilot/Zed/Junie/Jules/Amp  → 直接拷贝 AGENTS.md 或 rules/
```

**关键工程约束(写在 `docs/agent-portability.md` 第 35 行):**

> "Keep adapters thin. When a host supports skills or hooks, point it at the existing `skills/` and `hooks/` files. When a host only supports project instructions, keep its copied rule text aligned with `AGENTS.md`."

→ 这是**单源真理 + 适配器模式**的教科书应用。绝不在 13 个地方各自维护一份规则文本。

### Core instruction 详解(AGENTS.md 全 32 行)

```markdown
# 7 步决策梯子(在写代码之前,停在第一个能停住的阶梯):
1. 这东西根本需要存在吗?(YAGNI)
2. 代码库里已经有了吗?复用,别重写。
3. 标准库做这个吗?用。
4. 原生平台特性覆盖吗?用。<input type="date"> 而不是 date picker 库。
5. 已装的依赖能解决吗?用,绝不为"几行能做的事"加新依赖。
6. 能一行吗?一行。
7. 才写最少能跑的代码。

# Bug fix = 修根因,不是修症状:
报告给的是症状,grep 这个函数的所有 caller,在共享函数里加一个 guard。
一个 caller 加 guard 比 N 个 caller 各加一个 diff 小,而且只改报告里那条
路径会让兄弟 caller 还坏着。

# 严格规则:
- 绝不写没被明确要求的抽象。
- 绝不加能避免的新依赖。
- 绝不要"以后用"的脚手架,以后要的话以后自己加。
- 删除 > 添加。boring > clever。
- 最短可工作 diff 赢——但前提是先理解问题。

# 绝不偷懒于(底线):
- 信任边界输入校验
- 防数据丢失的错误处理
- 安全、可访问性、明确被请求的行为
- 非平凡逻辑至少留 1 个可运行检查(assert-based self-check 或 1 个小测试文件;
  不用框架、不用 fixture)。一行 trivial 代码不需要测试。
```

### 强度档 `lite / full / ultra` —— 在 SKILL.md 里靠表格 + 列表前缀过滤

Hermes 适配器 `__init__.py:_filter_skill_body_for_mode` 干了这件事(78-87 行):

```python
# 在 SKILL.md 的 markdown 里用 '| **lite** ...' / '- lite: ...' 这样的标记
# 标记某行属于哪一档;按当前 mode 过滤掉不属于自己的行。
table_label = re.match(r"^\|\s*\*\*(.+?)\*\*\s*\|", line)
if table_label:
    label_mode = _normalize_runtime_mode(table_label.group(1))
    if label_mode and label_mode != effective:
        continue  # 跳过这行

example_label = re.match(r"^-\s*([^:]+):\s*", line)
if example_label:
    label_mode = _normalize_runtime_mode(example_label.group(1))
    if label_mode and label_mode != effective:
        continue  # 跳过这行
```

→ **一篇文章写多档强度,运行时按档裁行** —— 不用维护 3 个文件,省维护成本,还保证三档绝对一致。

### 5 个按需 Skill(都是 40-60 行,极简)

| Skill | 触发 | 输出形态 |
|---|---|---|
| **ponytail-review** | review 当前 diff | `L<line>: <tag> <what>. <replacement>.` 一行一条 |
| **ponytail-audit** | 全仓审计 | 同上,按"能删多少行"排序 |
| **ponytail-debt** | 收集 `ponytail:` 注释成 ledger | grep → 表格 + "rot risk" 标记 |
| **ponytail-gain** | 显示实测节省的 scoreboard | 固定 ASCII 进度条,禁止捏造 per-repo 数字 |
| **ponytail-help** | 命令参考 | 一页 cheat sheet |

review/audit 共用 5 个 tag:`delete:` / `stdlib:` / `native:` / `yagni:` / `shrink:`

### Defer 标记 + Debt Ledger(防"以后再说"腐烂)

每个主动简化都要留 `# ponytail: <ceiling>, <upgrade path>` 注释,然后 `ponytail-debt` 用 grep 收集成账本。任何**没写升级触发条件**的标记会被打 `no-trigger` 警告 → "这才是腐烂的高风险"。

→ 这等于**给"技术债"装了一个轻量级 issue tracker**,而且是嵌在代码注释里的版本,接近时即提醒。

## Hermes Agent 适配(可借鉴的代码范本)

`__init__.py` 217 行,是 Hermes plugin SDK 的标准用法。核心要点:

### `register(ctx)` 注册 4 类资源

```python
def register(ctx: Any) -> None:
    # 1) 把 skills/ 下所有 SKILL.md 注册成命名 skill
    for child in sorted(SKILLS_DIR.iterdir()):
        if child.is_dir() and (child / "SKILL.md").exists():
            ctx.register_skill(child.name, skill_md)

    # 2) 注册 hook:pre_llm_call 在每次 LLM 调用前注入模式化 prompt
    ctx.register_hook("pre_llm_call", _pre_llm_call)

    # 3) 注册 hook:pre_gateway_dispatch 把 /ponytail-* gateway 命令改写为 agent prompt
    ctx.register_hook("pre_gateway_dispatch", rewrite_gateway_command)

    # 4) 注册命令:/ponytail 是模式切换,其余 5 个是把 skill prompt 注入对话
    ctx.register_command("ponytail", _handle_mode_command, ...)
    for command in SKILL_COMMANDS:
        ctx.register_command(command, _make_skill_command_handler(ctx, command), ...)
```

### pre_llm_call 的返回格式 = `{"context": "<注入文本>"}`

```python
def _pre_llm_call(session_id: str = "", **_: Any) -> dict[str, str] | None:
    mode = _current_mode or _default_mode()
    context = build_injected_context(mode)
    return {"context": context} if context else None
```

→ **pre_llm_call 的返回值就是"在原 prompt 前/后追加的内容",return None = 不注入**。

### `_slash_access_denied` 复用 gateway 的访问控制

```python
def _slash_access_denied(event, gateway, command):
    """让 gateway 自己决定这个用户能不能调 /ponytail-*"""
    checker = getattr(gateway, "_check_slash_access", None)
    source = getattr(event, "source", None)
    if checker is None or source is None:
        return False  # 没接 gateway 就放行
    try:
        return checker(source, command) is not None
    except Exception:
        return True   # 异常保守:拒绝
```

→ 共享场景(gateway 多用户)的关键安全设计:**plugin 不自己判断权限,而是问 gateway**。失败保守拒绝。

### `__init__.py` 是工程级 SDK 范本值得借鉴的点

1. **`_current_mode = None` 用全局变量存 session 状态**——因为 hook 是单进程注册,但 session 在进程内可以多次创建。要 session-隔离得用 `ctx` 传进来的 session_id,这里目前是简化版。
2. **fallback 永远要写**:`build_injected_context` 哪怕文件读不到也返回一段合理文本(第 90-102 行 `_fallback_instructions`),不让 agent 拿到空 context 行为失控。
3. **跨平台 config**:`_config_dir()` 按 `XDG_CONFIG_HOME` / `%APPDATA%` / `~/.config` 三种规范分别处理。
4. **type hint 用 `str | None`** —— Python 3.10+ idiom,符合 Hermes 当前最低版本。

## Benchmark 工程方法论(整份笔记的精华)

**README §Numbers 写了一段话,值得单独摘出:**

> "The honest measurement is a real agent doing real work: a headless Claude Code session editing tiangolo's full-stack-fastapi-template (a real FastAPI + React repo), scored on the `git diff` it leaves behind. Twelve feature tickets, the same agent with and without the skill, n=4, Haiku 4.5."

→ **真正的工程基准 = 在真实开源仓上跑真实 agent session,拿 git diff 算 LOC/成本/时间**。不是玩具题目。

### 双层 benchmark + 自我修正

| 阶段 | 方法 | 结果 | 问题 |
|---|---|---|---|
| **Single-shot**(2026-06-13) | promptfoo 5 tasks × 3 models × 10 runs,算 fenced code LOC | 80-94% less code | issue #126 指控 "baseline 包含了 prose + options,差距是 conversational artifact" |
| **Agentic**(2026-06-18) | headless Claude Code + full-stack-fastapi-template + 12 feature tickets + n=4 + git diff 算 LOC | -54% LOC / -22% tokens / -20% cost / -27% time / 100% safe | 仍是中等规模仓 |

**自我修正部分(`benchmarks/README.md` 第 64-71 行):**

> "Read this number honestly (updated 2026-06-18). The gap above is single-shot, against a bare model that answers with several options plus commentary, so it counts prose, not just code, and overstates the win. [#126](https://github.com/DietrichGebert/ponytail/issues/126) was right about that. The agentic benchmark re-runs the comparison as a *real Claude Code session on a real public repo*: ponytail cuts 60-94% on features with an over-build trap, is a wash on already-minimal code, never writes more, and stays 100% safe while the bare 'one-liner' prompt drops a guard."

→ 这是**工程诚信的范例**:社区指出问题后,作者没嘴硬,而是承认并重新跑了更公平的 agentic benchmark,新版数字反而对 ponytail 更不利(60-94% 而不是 80-94%),换来"defensible"的结论。

### 安全 tier 单独验证

benchmarks/results/2026-06-17-agentic-safety.md 单独跑了 adversarial tier:

> bare "write one-liners" prompt drops one guard → 95% safe
> baseline / caveman / ponytail: 100% safe

→ **lazy ≠ negligent** 的设计哲学在 benchmark 里得到验证。"少写代码"和"少安全性"是两个独立维度,ponytail 只砍前者。

### Benchmark 不只算 LOC:有 correctness gate

`benchmarks/correctness.js` 提取 fenced code 块并**真跑**(email/debounce/CSV 用 Python/Node spawn;React countdown/FastAPI rate-limit 走结构 regex 验)。

```javascript
// benchmarks/loc.js: always passes, just records line count
// benchmarks/correctness.js: gates — fails if code doesn't run/work
```

→ **两个独立 metric 文件分离**:`loc.js` 永远 pass 只记录,`correctness.js` 真测,互不污染。

### Cost 复测(独立审计)

> "Cost (USD, 5 tasks; 30 runs, 2026-06-17)" — 5 task × 3 模型 × 30 reps,比 LOC 的 10 reps 多 3 倍样本,**专门为审计成本**。

### 接受独立 benchmark(`README.md` 第 73-87 行)

| 来源 | 方法 | 结论 |
|---|---|---|
| [KuldeepB19](安装插件,24 tasks × 5 runs = 480 builds,Opus 4.8) | 跑代码验证 | ~44% less code,无正确性/安全回归,5/24 task 精简了非必要的输入校验 |
| [RicardoCostaGit](Cursor SDK,多轮 agentic,git worktree 隔离) | rule 切换 | 大 completion-forced 任务过程成本反而高;但 blocked/snowball-prone 任务省 |

→ **两个独立 benchmark 都指向同一个分裂**:ponytail 确实少写代码,**是否省钱取决于 workload**——在"易过度构建/易卡住"的任务上显著省,在"agent 必须一次完成大改"的任务上反而更多 token。这种**不隐藏负面发现**的姿态值得所有 benchmark 学习。

## 安装与最小使用

### Claude Code(用户最多)

```
/plugin marketplace add DietrichGebert/ponytail
/plugin install ponytail@ponytail
```
(必须分两条 prompt 发送才能生效)

### Hermes(我们的环境)

```bash
hermes plugins install DietrichGebert/ponytail --enable
```
装完重启 Hermes,自动注册:`ponytail` skill + 6 个命令(`/ponytail`、`/ponytail-review`、`/ponytail-audit`、`/ponytail-debt`、`/ponytail-gain`、`/ponytail-help`)。

### Pi / OpenCode / Codex / Copilot / Qoder / Devin / Grok / OpenClaw

```bash
# Pi
pi install git:github.com/DietrichGebert/ponytail

# OpenCode(加进 opencode.json)
# { "plugin": ["@dietrichgebert/ponytail"] }

# Codex
codex plugin marketplace add DietrichGebert/ponytail
codex plugin add ponytail@ponytail

# Copilot CLI / Qoder / Devin / Grok / OpenClaw 各自有 marketplace add + install 两步
```

### 零装方式(任何读 AGENTS.md 的 agent)

```bash
# 直接把仓 clone 到项目里或 ~/.config/<agent>/
git clone https://github.com/DietrichGebert/ponytail.git
```

→ Agent 是 Cursor/Windsurf/Cline/Copilot Chat/Zed/Junie/Jules/Amp 任何一个,**只要它读 `AGENTS.md`**,ponytail 立刻能跑(只是没 commands,只能用 always-on 规则)。

## 跟我们的关系

| 场景 | 价值 |
|---|---|
| **Hermes 自己的 plugin 范本** | `__init__.py` 是我看过的**最干净的 Hermes 插件写法** —— 注册 skill/hook/command 三件套的最小完整实现。可以直接当 `template-plugin` 来复制。 |
| **iswiki 写笔记的方法论** | 7 步决策梯子可作"写笔记前"流程:**这篇笔记真的需要吗?现有笔记覆盖了吗?简短版够吗?最短能说清吗?** 拿来当 iswiki skill 的反膨胀检查。 |
| **跨工具适配器模式** | "1 个核心 + 13 个薄适配器"是**复用到所有跨平台 skill 的工程模板**。我们自己做的 hermes skill / openclaw skill / pi extension 都该照这个组织。 |
| **Defer 标记 + Debt Ledger** | 在 `fireside`、`mac-permission-debug` 等项目里也可以引入 `# ponytail: <ceiling>, <upgrade path>` 这种注释规范,把"偷懒的地方"显式登记。 |
| **诚实 benchmark 文化** | #126 issue 后的 agentic 复跑 + 接受独立 benchmark 的负面发现 → **做工程评测时的标准姿态**:被批评就重做,接受负面结论,不抹数字。 |
| **强度档过滤的 markdown 技巧** | `**lite**` / `**full**` 表格标签 + runtime regex 过滤行 → **一篇文章维护 3 档强度,保证 3 档绝对一致**。比维护 3 个文件强得多。 |
| **人格化命名** | "Ponytail"(马尾辫)→ 老员工 → 51% 题。"LazySenior" "YagniPal" 这些名字就拉胯。"让用户觉得这是个真人"在 LLM skill 里就是护城河。 |
| **可疑点** | 117.9k ⭐ 但只有 2.5 个月 —— **值得怀疑的增长曲线**。trend-shift 链接在 README,自己判断是否 follow 效应(传染式 star / 推特 viral / Discord pump)。benchmark 是真做的,但 star 数与工程成熟度的比例需要时间检验。 |

## 风险点 / 注意事项

| 风险 | 说明 |
|---|---|
| **过度套用可能错过该有的复杂度** | 真正的架构决策、性能调优、可扩展性设计 —— 都不是"懒"的领域。如果在"必须做"的任务上 force `lite` 模式,反而拖延项目。 |
| **agentic benchmark 仍有局限** | 仓只是 tiangolo/template 那种 size,不代表 100 万行 monorepo 或 嵌入式/实时系统场景。ponytail 自己在 README 末尾 §Scale 说 "code you never wrote scales infinitely" 是 self-promotion。 |
| **强度档过滤用 markdown regex 不优雅** | 表格行 + 列表行两种 prefix 模式硬编码,加新格式就要改 `_filter_skill_body_for_mode`。结构化 YAML 比 markdown + regex 更稳。 |
| **可能和现有 skill 冲突** | 如果已经用了类似 "minimal-change" / "no-abstraction" 的 skill,会和 ponytail 重复 instructions → context 浪费 + 行为不一致。 |
| **117k ⭐ + 2.5 个月** | 警惕 viral / 自推型增长,工程严谨 ≠ 营销数据 |

## 版本节奏 / 关键 commit

- 创建: 2026-06-12,创始人 Dietrich Gebert
- GPL/AGPL/非商业协议: **无,纯 MIT**
- 多语种 README: en / es / ko (国际化覆盖)
- v4.9.0 (对应 `package.json`),仍在迭代
- 6 个核心 skill: ponytail / ponytail-review / ponytail-audit / ponytail-debt / ponytail-gain / ponytail-help
- 13 个 host 适配器:Claude Code / Codex / Copilot / Gemini / OpenCode / Hermes / Pi / Qoder / Devin / Grok / OpenClaw / Cursor / Windsurf / Cline / Zed / Junie / Jules / Amp / Kiro / Swival / CodeWhale / Antigravity
- 测试覆盖:`tests/` 13 个测试文件,`npm test` 跑 `tests/*.test.js + pi-extension + ponytail-mcp` 三套

## 参考链接

| 资源 | URL |
|---|---|
| GitHub 仓 | <https://github.com/DietrichGebert/ponytail> |
| 官网 | <https://ponytail.dev> |
| 跨工具适配表 | <https://github.com/DietrichGebert/ponytail/blob/main/docs/agent-portability.md> |
| Agentic Benchmark | <https://github.com/DietrichGebert/ponytail/blob/main/benchmarks/results/2026-06-18-agentic.md> |
| Benchmark 复跑说明 | <https://github.com/DietrichGebert/ponytail/issues/126> |
| 独立 benchmark 1 | <https://kuldeepb19.github.io/ponytail-benchmark/> |
| 独立 benchmark 2 | <https://github.com/RicardoCostaGit/ponytail-benchmark-from-cursor> |
| Hermes 适配源代码 | <https://github.com/DietrichGebert/ponytail/blob/main/__init__.py> |
| 核心 SKILL.md | <https://github.com/DietrichGebert/ponytail/blob/main/skills/ponytail/SKILL.md> |
| 同源/正交 skill (caveman) | <https://github.com/JuliusBrussee/caveman> |
