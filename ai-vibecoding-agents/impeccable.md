# Impeccable — 给 coding agent 的设计词汇表

> 学习笔记 · 调研时间 2026-11-02
> GitHub: https://github.com/pbakaus/impeccable · 官网: https://impeccable.style
> 文档: https://impeccable.style/docs · License: Apache-2.0
> 语言: Rust(主)/ JavaScript / TypeScript · ⭐ 99,751 · Fork 5,900 · 贡献者 58
> 最新提交 2026-11-01 · 最新 release `skill-v4.8.0` / `engine-v0.1.18`(2026-10-26)

---

## 0. 配图速览

| 场景 | 截图 |
|---|---|
| 不用 Impeccable —— 典型 AI slop | ![](assets/impeccable/01-without-impeccable.webp) |
| 用 Impeccable —— 同一 brief 的艺术指导版 | ![](assets/impeccable/02-with-impeccable.webp) |

---

## 1. 一句话定位

**Impeccable 是一套给 AI coding agent 用的「设计词汇表」**:把"设计品味"拆成 24 个可调用的命令词 + 62 条确定性反模式检测规则,装进 Claude Code / Cursor / Codex / Hermes 等 20 种 agent harness,让 agent 产出的界面从"一眼 AI 味"变成能过专业设计评审的东西。

它的核心洞察是:**问题不在模型能力,在模型没有词汇**。同一个模型同一个 brief,加了 Impeccable 和没加,输出完全是两个东西 —— 不是模型变强了,是拿到了词。

---

## 2. 核心数据

| 字段 | 值 |
|---|---|
| Stars / Fork | 99,751 / 5,900(约 11 个月,2025-11-16 创建) |
| 主语言 | Rust(11.1 MB),JS 3.1 MB,TS 257 KB |
| Rust 源文件 | 430 个,17 个 crate |
| 引擎版本 | `engine-v0.1.18`(`ENGINE_VERSION` 文件锁定) |
| Skill 版本 | `skill-v4.8.0` |
| 检测规则 | **62 条**,分 `slop`(AI 味)/ `quality`(真实质量缺陷)两类 |
| 命令 | 24 个(README 说 24,SKILL.md 表格列 23 + `craft` 废弃别名) |
| Harness 支持 | 20 种:Claude Code / Cursor / Codex CLI / Copilot / Devin / Replit / Gemini CLI / Grok Build / OpenCode / Antigravity / Kiro / Trae / Rovo Dev / Qoder / Mistral Vibe / Pi / **Hermes Agent** / DeepSeek Harness / Veto / Trae China |
| 依赖 | **运行时零依赖** —— 二进制自带引擎,不需要 Node,不需要 API key |

---

## 3. 核心架构:Rust 引擎 + 多 harness 分发

Impeccable 的工程结构很值得抄 —— 它是 **"一份源,多处生成"** 的典型。

```
                    ┌──────────────────────────────┐
                    │  skill/SKILL.src.md          │  ← 唯一真源
                    │  skill/reference/*.md (50+)  │
                    │  skill/agents/*.md           │
                    └──────────────┬───────────────┘
                                   │ 构建期生成
        ┌──────────┬───────────┬────┴────┬──────────┬──────────┐
        ▼          ▼           ▼         ▼          ▼          ▼
   .claude/    .cursor/     .codex/  .agents/  .hermes/   .grok/ ...
   (Claude)    (Cursor)    (Codex)  (通用)    (Hermes)   (Grok)
```

每个 harness 目录下是**已提交的生成产物**,不是构建时才有的。`git log` 里每天都有 `Sync generated provider output` 提交 —— 这是它的发布流水线。

### 3.1 Cargo workspace(17 个 crate)

```
crates/
  cli          impeccable 二进制:动词路由、退出码
  common       Io handle(stdout/stderr/stdin/env/cwd) + HTTP/1.1 server core
  context      context / doctor / staleness / signals / pin / concept-seed
  hook         设计 hook(hook / hook-before-edit / hook-admin)
  live         live 模式:server、wrap、accept、手工编辑、Svelte/Vue
  skills       install / update / check / link(旧 npm CLI 动词)
  comp         comp-fidelity 纯库(raster、png、metrics、fonts)
  comp-verbs   build-phase、comp-diff、comp-spec、font-match
  detect       impeccable detect:文件遍历、配置、忽略、输出、regex 引擎
  html         静态 HTML 引擎:parser、cascade、静态 DOM、规则适配
  browser      URL 引擎:Chrome 发现、CDP、snapshot、视觉 pass
  foundation   JS 语义辅助、色彩、findings、**规则注册表**、inline ignores
  core         **规则逻辑**:每个 check_* / scan_* 与其启发式
  wasm         wasm-bindgen 导出(页内 bundle + 扩展 offscreen core)
  bundle       页内 JS + bundler:wasm-pack 调用
  xtask        cargo xtask bundle —— workspace 的构建入口
```

关键分层是 `foundation` vs `core`:**foundation 是"规则被写成的形状"(纯数据类型、注册表、DOM trait),core 是"规则本身"(check_* 函数)**。`crates/core` 会把 foundation 的模块 re-export 到自己的路径下,所以消费方永远只用一个 crate。

发布 profile 是极限压缩:`opt-level = 3` + `lto = "fat"` + `codegen-units = 1` + `strip = true` + `panic = "abort"`。

### 3.2 三个引擎,一套规则

同一套 62 条规则跑在三个不同的地方,这是 Impeccable 最聪明的工程决策:

```
                    ┌─────────────────────────┐
                    │   crates/core 规则逻辑    │
                    │   (check_* / scan_*)     │
                    └────┬────────┬───────┬───┘
                         │        │       │
              ┌──────────┘        │       └──────────┐
              ▼                   ▼                   ▼
      ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
      │ detect (text)│   │  html (静态) │   │ browser (CDP) │
      │ 源码正则扫描  │   │ 解析成静态DOM│   │ 真实渲染页面   │
      └──────────────┘   └──────────────┘   └──────────────┘
                                                          │
                                    ┌─────────────────────┘
                                    ▼
                             ┌──────────────┐
                             │  wasm (Rust) │  ← 同一套逻辑编译成 wasm
                             └──────┬───────┘
                                    ▼
                      页内 bundle / Chrome 扩展 overlay
```

**browser 引擎走 wasm 这条路**特别值得注意:`cargo xtask bundle` 把 `crates/core` 编译成 WebAssembly,再把 `.wasm` 以 base64 内嵌进页内 JS。页内 JS 只实现 `Dom` probe、JSON 编解码和 overlay 绘制,**里面没有一行规则逻辑**。所以 Chrome 扩展里跑的检测,和 CLI 里跑的检测,是**同一份 Rust 代码**。

构建产物是可复现的(`cargo xtask bundle --check` 会在 CI 里校验 tracked 资产是否过期)。

### 3.3 三种运行方式

```bash
# 1. 在 agent 里 —— 设计 hook(最常用)
npx impeccable install   # 装 skill + 问你要不要装 hook

# 2. CI / 终端 —— CLI,不需要 agent
npx impeccable detect src/
npx impeccable detect https://example.com     # 用本机 Chrome/Edge 扫真实页面
npx impeccable detect --json .                # 机器可读
npx impeccable detect --github src/           # GitHub Actions annotation
npx impeccable detect --list-rules            # 全部规则 + id + 说明

# 3. 浏览器 —— Chrome 扩展,任意页面叠 finding
```

退出码有明确语义:**`2` = 有 finding,`1` = 目标扫不了,`0` = 干净**。CI 里 `exit 2` 直接失败。

---

## 4. 62 条规则:AI 味的完整taxonomy

规则注册表在 `crates/foundation/src/registry.rs`,`crates/detect/src/list_rules.rs` 负责输出。分两类:**`slop`**(AI 生成痕迹)和 **`quality`**(真实缺陷)。部分规则标 `advisory`(建议级)。

### 4.1 slop 类 —— AI 生成痕迹

这类规则是 Impeccable 真正的差异化资产。它把"AI 味"拆成了可机器检测的具体形态:

| 规则 id | 抓什么 |
|---|---|
| `side-tab` | 卡片单侧 4px 彩色边框 —— **"最具辨识度的 AI UI 标志"** |
| `border-accent-on-rounded` | 圆角卡片上的粗彩色边框(圆角和边框打架) |
| `overused-font` | Inter / Roboto / Fraunces / Geist / Plus Jakarta Sans / Space Grotesk |
| `flat-type-hierarchy` | 主标题与正文每级字号比 < 1.25×,层级扁平 |
| `gradient-text` | 渐变文字(尤其标题和数字) |
| `ai-color-palette` | 紫/紫罗兰渐变;深底上的青色平涂 |
| `cream-palette` | 奶油/米色页面底色 —— "**反射式选中的'品味'默认色**" |
| `nested-cards` | 卡片套卡片 |
| `monotonous-spacing` | 所有地方同一个间距值,无节奏 |
| `bounce-easing` *(advisory)* | bounce / elastic 缓动 |
| `pulsing-dot` | 装饰性脉冲状态点 |
| `blinking-cursor` *(advisory)* | hero 区装饰性闪烁光标 |
| `shape-assembled-illustration` *(advisory)* | 用基本图形堆出来的"占位剪贴画" |
| `dark-glow` | 彩色辉光阴影(零偏移色晕) |
| `radial-halo` | 深色页上的饱和径向渐变光晕 |
| `radial-spotlight-glow` | 装饰性"聚光灯"径向渐变 |
| `marquee` | 自动滚动跑马灯 |
| `icon-tile-stack` | 标题上方的圆角小方块图标 —— "**万能 AI 特性卡模板**" |
| `italic-serif-display` | 超大斜体衬线 hero 标题(Fraunces/Playfair/Newsreader-italic) |
| `hero-eyebrow-chip` | hero 标题上方的小号大写字距标签 / 药丸 chip |
| `kicker-above-heading` | 标题上方独立的 kicker 标签 —— "**直接禁止**" |
| `numbered-section-labels` *(advisory)* | 章节标题旁的小序号 |
| `em-dash-overuse` *(advisory)* | 破折号饱和(≥8 个且密度接近每 500 字符 1 个) |
| `marketing-buzzword` | streamline / empower / supercharge / world-class / next-generation… |
| `aphoristic-cadence` | "X. No Y." 式反诘句重复 ≥3 次; manufactured-contrast 警句 |
| `oversized-h1` | 整句标题用 display 尺寸 |
| `extreme-negative-tracking` | 字距压得字形失真 |
| `gpt-thin-border-wide-shadow` *(advisory)* | 发丝边框 + 大范围弥散阴影的卡片行 |
| `repeating-stripes-gradient` *(advisory)* | 重复渐变条纹装饰 |
| `codex-grid-background` *(advisory)* | 发丝 linear-gradient 网格底纹 |
| `theater-slop-phrase` *(advisory)* | "theater" 这类话术 |

### 4.2 quality 类 —— 真实缺陷

这部分和普通 lint 工具重叠,但实现细节有值得学的地方:

- `low-contrast` — WCAG AA(正文 4.5:1,大字号 3:1)。**接近阈值时降级为 advisory**,不硬报。
- `tiny-text` — 正文 < 12px;`undersized-ui-text` — 功能性 UI 文本 < 11px(footer 里也守 11px,只有非交互法律小字放宽到 10px)
- `skipped-heading` — h1 后直接 h3
- `line-length` — 渲染出来的行宽 > ~80 字符
- `cramped-padding` — 文字离容器边框太近(两种形态:元素自带文字 / 包裹层没有内缩)
- `body-text-viewport-edge` — 正文贴着视口边缘(< 16px,≤480px 视口则 < 12px)
- `tight-leading` — 行高 < 1.3×
- `heading-rhythm` — 标题上方间距应大于下方(否则"每节都像在给上一节配字幕")
- `justified-text` — 窄栏两端对齐产生"垂直白河"(CJK / 泰语 / 阿拉伯语按字符网格对齐,**不报**)
- `all-caps-body` — 元素自身文本 ≥ 80 字符才算长句;按钮/导航/kicker 约定不算
- `wide-tracking` — 正文字距 > 0.05em
- `content-hidden-at-rest` — **"失败 reveal"签名**:文字停在 opacity 0,内容发货了但永远不显示
- `script-error` — 加载期未捕获异常
- `text-occlusion` / `text-overflow` / `clipped-overflow-container` / `edge-flush-cards` / `first-viewport-column-overflow`
- `straggler` *(advisory)* — 段落最后一行只剩一个词(建议 `text-wrap: pretty`)
- `unbalanced-heading` *(advisory)* — 标题换行后末行远短于上行(建议 `text-wrap: balance`)
- `design-system-font` / `design-system-color` / `design-system-radius` / `design-system-font-size` — **对比 DESIGN.md 的 token 漂移**
- `broken-image` — `<img src="">` 等占位图

其中 `design-system-*` 四条直接读 `DESIGN.md` 的 frontmatter 做校验 —— 这就是 `document` 命令产出的东西有了用处。

---

## 5. 24 个命令词:给 agent 的设计词汇表

这是 Impeccable 名字里 "vocabulary" 的实体 —— 一套**有明确语义的设计动词**,替代"做得再炫一点"这种模糊 prose。

| 类别 | 命令 |
|---|---|
| **Steer 引导** | `bolder` 放大保守设计 · `quieter` 压低张扬设计 · `distill` 去掉不必要的东西 · `colorize` 给灰界面加色 · `typeset` 修字体/层级/字号 · `layout` 修间距与节奏 · `animate` 加过渡与反馈 · `delight` 加个性 · `overdrive` 上 shader / 弹簧物理 / 滚动驱动特效 |
| **Review 评审** | `critique` 打分 UX 评审 · `audit` 技术质量报告 |
| **Finish 收尾** | `polish` 交付前最后一遍 · `harden` 错误/i18n/溢出/边界情况 · `clarify` 重写不清楚的文案 · `adapt` 适配屏幕与设备 · `optimize` 加载与渲染性能 · `onboard` 首次流程与空状态 |
| **Iterate live** | `live` 在浏览器里选元素循环变体 · `generate` 不手选直接生成变体 |
| **Plan & set up** | `shape` 先规划 UX 再写码 · `init` 写 `PRODUCT.md` · `document` 写 `DESIGN.md` · `extract` 抽重复模式进设计系统 |

另有 `craft`(普通新建请求的废弃别名)和 `craft-floor.md` —— 承载"**扫描器永远抓不到的手感**"(绝对禁止项 + 反射性动作),在**任何 UI 编辑前必须加载**。

### 5.1 上下文文件机制

```
/impeccable init       → 读代码,只问推不出来的(产品是谁、约束),写 PRODUCT.md
/impeccable document   → 抓现有视觉系统,写 DESIGN.md
```

之后每条命令都读这两个文件。这是它和"一次性 prompt"的分界线 —— **状态被持久化了**,下一轮 agent 不用重新猜这个产品是什么。

### 5.2 Mode 机制:按"访客的成功形态"选调性

不是按产品选,是按**这个页面**选:

| Mode | 访客在做什么 | 设计取向 |
|---|---|---|
| **Persuade** | 决定并行动(落地页/营销/定价) | 设计就是产品,全力表达 |
| **Operate** | 完成任务(后台/编辑器/设置) | 可扫读性 > 表达,品牌活在精确细节里 |
| **Read** | 理解(文档/文章/指南) | 先为理解组织结构,再让阅读值得 |
| **Experience** | 置身作品之中(作品集/画廊) | 作品领路,界面退后 |

"一个工具的落地页仍然是 Persuade;一个时尚品牌的文档仍然是 Read" —— 这种粒度是很多设计系统文档写不清的。

### 5.3 critique 的双盲评审:最值得抄的设计

`critique` 命令的 "Hard Invariants" 写得很硬:

- **Assessment A(设计评审)和 Assessment B(检测器证据)都必须跑**,而且必须**作为两个隔离的 sub-agent** 并行跑。inline 跑 = **降级运行**,报告第一行必须打横幅 `⚠️ DEGRADED: single-context (<原因>)`。
- **A 必须先于 B 的检测结果进入父上下文**。理由写得很清楚:检测器输出虽然是确定性的,但**它会锚定判断**。先看到"62 条规则报了 10 个问题",你的评审就变成复述而不是独立判断。
- 没跑检测器的 critique 是失败的,除非 `impeccable detect` 真的缺失/崩溃,或者平台是 native。
- **问题是回复的最后一样东西**。报告写完再问;问完之后再写的话,读起来就像 critique 从没跑过。
- 一次运行既没有针对性提问、也没有字面 `Questions skipped: <原因>` 行 = 不完整运行。

> 这是把"避免 LLM 锚定"写成了硬约束,而不是提示词里的一句建议。**A 先于 B 的时序约束,是这类双盲评审设计的通用范式。**

---

## 6. 设计 hook:把检测塞进 agent 回路

这是 Impeccable 商业价值最高的部分 —— 因为 README 自己承认:"**没有 hook 的话,检测器只有在你记得运行它的时候才跑**"。

### 6.1 两级分层

```
agent 写完一个 UI 文件
        │
        ▼
  ┌─────────────────────────────────────────┐
  │ PostToolUse hook(每次编辑)              │
  │ 只跑"即时层"规则:                      │
  │   机械、无歧义、值得打断编辑的问题        │
  │   (broken image / overflow / contrast /   │
  │    gradient text / glow / design-system)  │
  └────────────────┬────────────────────────┘
                   │ findings 作为 system reminder 推回上下文
                   ▼
  ┌─────────────────────────────────────────┐
  │ Stop hook(回合结束时的深扫)              │
  │ 跑全量规则,扫本 session 碰过的每个 UI 文件│
  │ 与 PostToolUse 已报的去重,只报剩下的       │
  │ 干净 → 静默结束                          │
  └─────────────────────────────────────────┘
```

这个分层解决了一个真实矛盾:**每次编辑都跑全量 62 条会变成噪音,agent 会学会忽略**。即时层只报"你刚犯的机械性错误",深扫层在回合末统一报品味类问题。

### 6.2 各 harness 的落点

| Harness | 机制 |
|---|---|
| Claude Code / Codex | 原生 `PostToolUse` + `Stop` 事件 |
| Cursor | `postToolUse` on Write,返回 `additional_context`(**没有 Stop 深扫** —— Cursor 的 stop hook 只能回一句用户消息) |
| GitHub Copilot | 保留全量规则每次编辑(它的 stop 事件不回流给模型) |
| Grok Build | PostToolUse 标记文件,Stop 时 `additionalContext` 汇总 |
| **Hermes Agent** | `impeccable-design-hook` 插件 |

### 6.3 Hermes Agent 插件(★ 本机相关)

仓库里有 `.hermes/plugins/impeccable-design-hook/`,这是一个 **Python 插件**,把 Hermes 的 hook 事件翻译成引擎认识的 Claude 形状事件:

```python
# skill/hermes-plugin/__init__.py
_TOOL_NAMES = {"write_file": "Write", "patch": "Edit"}
_EDIT_TIMEOUT_S = 5
_STOP_TIMEOUT_S = 30

def on_transform_tool_result(tool_name="", args=None, result=None, session_id=None, **_):
    """把每次编辑的 findings 加进成功的 write_file / patch 结果"""
    for path in _edited_paths(result, args, cwd):
        event = {"hook_event_name": "PostToolUse", "cwd": cwd,
                 "tool_name": _TOOL_NAMES[tool_name],
                 "tool_input": {"file_path": path}}
        texts.append(_additional_context(_run_hook(launcher, cwd, event, _EDIT_TIMEOUT_S)))
```

四个设计点:

1. **Hermes 没有 command-hook manifest**,所以插件用 `transform_tool_result` + `pre_verify` 两个已有 hook 点,把事件喂给引擎的 `hook` 动词。引擎自己管其余一切(UI 文件过滤、`hook.enabled`、两级去重)。
2. **信任边界**:`_find_launcher()` 从编辑文件所在目录**向上**找最近的 `.hermes/skills/impeccable/scripts/impeccable`,但只在 Hermes 信任的 project 里用。注释写得很直白:*"An untrusted clone's launcher never runs: it is repository code."*
3. **fail-open**:任何异常、超时、找不到 launcher,都静默放过 —— "a broken hook must never cost the user a write"。
4. **结果里带 JSON**:findings 作为 `impeccable` 字段塞进 write_file 的 JSON 结果,而不是拼在文本后面。因为 Hermes 要读回结果 JSON 记录这次编辑给 verify gate 用,**文本追加在 JSON 后面会把这次写入从 `pre_verify` 视野里藏掉**。

启用方式:

```bash
npx impeccable install
hermes plugins enable impeccable-design-hook   # 一次性
```

---

## 7. 实测:我自己跑了一遍

不能只读 README。下面是本机实跑 `npx impeccable detect` 的结果。

### 7.1 测试样本

我手写了一个"典型 AI slop"页面(`/tmp/imp_test/demo.html`),故意塞了:

```html
<div style="border-left:4px solid #8b5cf6; border-radius:12px; padding:4px; background:#faf6f0;">
  <h1 style="font-family:Inter;font-size:56px;">Build faster with our AI platform</h1>
  <p style="color:#999;font-size:11px;line-height:1.1;">
    Streamline your workflow — supercharge your team. Enterprise-grade,
    next-generation solution. Not a feature. A platform.</p>
  <span style="letter-spacing:0.2em;text-transform:uppercase;font-size:10px;">Introducing</span>
  <h3>Features</h3>
  <img src="" alt="x">
  <div style="background:radial-gradient(circle, #a855f7, transparent)"></div>
</div>
```

### 7.2 实测输出

```
/private/tmp/imp_test/demo.html
  [side-tab] border-left: 4px + border-radius: 12px
  [low-contrast] 2.6:1 (need 4.5:1) — text #999999 on #faf6f0
  [broken-image] <img src="">
  [tight-leading] line-height 1.10x (need >=1.3)
  [tiny-text] 11px body text
  [undersized-ui-text] 10px functional text "Introducing" (below 11px floor)
  [overused-font] Primary font: inter
  [skipped-heading] <h1> "Build faster with our AI platform" followed by <h3> "Features" (missing h2)
  [ai-color-palette] Purple/violet accent colors detected
  [marketing-buzzword] 4 buzzword phrases: "AI platform Streamline your workflow —"

10 anti-patterns found.
```

**十个独立问题,全部命中,零漏报零误报。** 几个值得注意的细节:

- `low-contrast` 给了**具体比值 2.6:1**,不是"对比度不够"这种废话。
- `skipped-heading` 把两个标题的文本都引了出来,能直接定位。
- `marketing-buzzword` 报的是**数量**(4 处)+ 原文片段,不是命中一个就停。
- `undersized-ui-text` 单独报了 `letter-spacing` 大写标签 —— 这说明它能区分"装饰性字母间距微标签仍是功能性文本"这个设计判断。

### 7.3 JSON 模式

```json
{
  "antipattern": "side-tab",
  "name": "Side-tab accent border",
  "description": "Thick colored border on one side of a card — the most recognizable tell of AI-generated UIs...",
  "severity": "warning",
  "category": "slop",
  "file": "/private/tmp/imp_test/demo.html",
  "line": 0,
  "snippet": "border-left: 4px + border-radius: 12px"
}
```

字段设计对 CI 友好:`antipattern` / `category` / `severity` 三个维度可直接用于分组和门禁分级。

### 7.4 规则目录

```
$ npx impeccable detect --list-rules
slop
  side-tab
    Side-tab accent border
    Thick colored border on one side of a card — the most recognizable tell...
  ...
quality
  low-contrast
    Low contrast text
    ...
62 rules.
```

`--list-rules` 走 stdout、退出 0、**不做任何扫描**。`--json` 输出 `{id,name,category,severity,scopes,description}` 数组;`--quiet` 只输出 rule id 一行一个。配置里的 `ignoreRules` **不影响目录输出** —— 目录列出的是项目已关掉的规则(方便排查"为什么没报")。

### 7.5 那些没报的规则,和为什么

我这个样本里 **没有** 报出来的 slop 规则,恰好暴露了设计意图:

| 规则 | 为什么不报 |
|---|---|
| `italic-serif-display` | 我用的是 Inter 无衬线,不是斜体衬线 |
| `cream-palette` | 底色 `#faf6f0` 虽是暖奶油色,但**没有其他 slop 规则命中**时它不单独报 —— 它要靠上下文 |
| `radial-halo` | 径向渐变在 div 上,但没到"深色页面上的饱和光晕"的条件 |
| `hero-eyebrow-chip` | 我的大写标签在段落**下面**,不在 hero 标题**上面** |

这说明规则之间有**上下文依赖**,不是纯正则关键词匹配。`ai-color-palette` 的描述写得很准确:*"A gradient in one of those hues is the tell on its own; flat neon ink on a dark ground is charged once a second tell hue joins it."*(单靠紫色渐变就够定罪;平涂霓虹色则需要第二个特征色配合。)

---

## 8. 工程细节:值得抄的几处

### 8.1 Oracle 测试:字节级行为锁定

```
tests/oracle/
  golden/          # 期望输出(stdout / stderr / exit code / 写文件)
  vectors/calls/   # 冻结的函数级调用向量
  lib.mjs          # JS_VERBS 映射
  run.mjs          # 回放器
```

`docs/CLI-CONTRACT.md` 有 2166 行,**逐字节规定**每个动词的参数、环境变量、stdout/stderr、退出码、写入的文件、网络请求。这是"给另一个实现做规格书"的写法 —— 意味着 CLI 换语言重写(JS → Rust)不会破坏行为。

```
IMPECCABLE_BIN=target/release/impeccable node tests/oracle/run.mjs   # 行为门禁
```

### 8.2 RulePack:不改引擎加规则

下游 crate 想加自己的规则,不用 fork 引擎:

```rust
pub trait RulePack: Send + Sync + std::fmt::Debug {
    fn registry(&self) -> &'static [Antipattern];
    fn check_text(&self, content: &str, file_path: &str, ext: &str) -> Vec<Finding> { ... }
    fn check_element_dom(&self, dom: &dyn Dom, el: ElId) -> Vec<BrowserFinding> { ... }
    fn check_page_dom(&self, dom: &dyn Dom) -> Vec<ElFinding> { ... }
}
```

每个 hook 都有默认实现(返回空),所以 pack 只实现自己关心的引擎。id 强制命名空间前缀(`myproject/my-rule`)防止撞内置 id。**pack 的 findings 走和内置 findings 完全一样的 waiver 和过滤路径** —— 这是接口设计的关键:扩展点不能是二等公民。

`crates/bundle` 还把这套打包能力暴露给下游:链接 `impeccable-core` + `impeccable-wasm` + 自己的 pack,就能产出同样格式的 wasm bundle,**不用从本仓库拷文件**。

### 8.3 忽略机制的三层粒度

```
项目级:  .impeccable/config.json          → detector.ignoreRules / ignoreFiles / ignoreValues
开发者级: .impeccable/config.local.json    → gitignore,存个人例外
行内:    <!-- impeccable-disable overused-font: exported brand doc -->
```

CLI 也直接管:

```bash
impeccable hooks ignore-value overused-font Inter --reason "Brand font"
impeccable hooks ignore-file "src/legacy/Card.tsx"
impeccable hooks ignore-rule overused-font --all-values
```

`ignore-value` 支持按文件限定:`--file <glob>` 可以重复。这比全局 ignore 精确得多。README 提到 `impeccable:manual-edit-validate` 脚本会在你的权限下跑 —— 文档里明确提醒**先 review 再用**。

### 8.4 环境变量契约

`docs/RUNTIME-ENV.md` 规定了引擎读的所有环境变量。几个有意思的:

| 变量 | 作用 |
|---|---|
| `IMPECCABLE_SKILL_DIR` | skill 目录位置(内联 native 参考、更新检查、pin 的 command metadata) |
| `IMPECCABLE_PROVIDER_ID` | 构建时的 harness id,决定 hook manifest 路径和 `$`/`/` 命令前缀 |
| `IMPECCABLE_SELF` | 打印命令里怎么称呼这个二进制(Windows 下要输出 `& '<path>' <verb>` 的 PowerShell 字面量) |
| `IMPECCABLE_SEED_SALT` | 参考计算用的盐 —— **默认每用户随机 128 bit**,让提交的参考不能被反向算出 key |

### 8.5 Live 模式

`/impeccable live` 打开正在跑的 dev server,叠一个 overlay,选中元素 → 选方向 → 热替换变体 → 接受后写回源码。支持 Vite / Next / SvelteKit / Astro / Nuxt / 纯 HTML。

安全边界写得很清楚:*"Live mode edits a local checkout only; don't inject it into a deployed site or weaken a production CSP to make it work."* 应用文案修改会调用你 `package.json` 里的 `impeccable:manual-edit-validate` 脚本 —— **用你的权限跑**,所以陌生仓库里先看这个脚本。

---

## 9. 我的评价

### 9.1 真正做得好的

**① "问题不在模型,在模型没有词汇"这个定位是准的。** 绝大多数 AI UI 工具的思路是"让模型再努力一点"或者"再加个 review agent"。Impeccable 的思路是**给模型装一套领域术语和标准动作** —— `bolder` / `quieter` / `distill` 这些词本身就是设计总监的思维动作。这比"please make it look better"精确一个数量级。

**② 62 条规则里有一部分是真正的知识资产。** `side-tab`(单侧粗边框)、`icon-tile-stack`(标题上方圆角图标块)、`kicker-above-heading`、`cream-palette` —— 这些不是通用 lint 规则,是**具体到能编码的审美判断**。能写出 `cream-palette` 描述里那句 "reached for by reflex"(反射式选中的默认色)的人,是真的在反复看 AI 生成的页面。

**③ 规则的描述本身写得好。** 它们不是规则描述,是**带立场的评审意见**。比如 `hard-offset-shadow`:"可以属于刻意的 neobrutalist 方向,检查它是否符合预期设计;这是评审提示,不是 AI 作者身份的证据,也不是要求自动移除。" —— 明确标注"这可能是有意的",并给出豁免写法(`data-impeccable-ignore="hard-offset-shadow"`)。

**④ `undersized-ui-text` 堵了一个真实的逃生口。** 原文:*"Being ON the DESIGN.md size ramp does not exempt a value here: adding 8px to the ramp launders the token but not the legibility problem, and that is exactly the escape hatch this rule closes."*(加到 token 阶梯里只是洗白 token,没解决问题 —— 这条规则堵的就是这个口子。)这种把"我知道你可能怎么绕过"写进规则里的诚实,罕见。

**⑤ 状态持久化。** `PRODUCT.md` + `DESIGN.md` 让整个系统从"一次性 prompt"变成"有记忆的同事"。

**⑥ 双盲 critique 的时序约束。** "A 必须先于 B 进入父上下文" 是把 LLM 锚定问题当成工程约束处理,而不是提示词建议。

### 9.2 局限与风险

**① 62 条规则必然有误报,而且是"审美型误报"。** 上面实测已经看到:`cream-palette` 这类规则一旦命中就是"你在用奶油底色"这种判断,它无法区分**刻意的品牌选择**和**无脑默认**。Impeccable 的应对是分层(有些是 advisory)+ 精细化的 ignore 机制,但这是把成本转嫁给了用户。真实使用中,忽略清单会持续膨胀。

**② 它在跟自己的检测规则较劲。** `PRODUCT.md` 里写:*"The site must pass its own anti-pattern tests with flying colors. If we ship anything we'd flag in an audit, we've lost."* —— 这是很高的标准,但也意味着**每次加新规则,官网都得改**。仓库里每天的 `Sync generated provider output` 就是这个代价的体现。

**③ hook 的性能成本真实存在。** 每次编辑跑一次检测(5s 超时)+ 回合末深扫(30s 超时)。对大型 React 项目,每次 `write_file` 多几秒是不可忽略的。分两级是缓解,但不是消除。

**④ "62 条规则"是静态的,而审美是动态的。** 今天的 AI slop 是紫色渐变和圆角图标块;明年的 slop 是完全不同的东西。规则集需要持续更新,而审美规则集没有自动化测试来验证"新规则抓的是不是真的 slop"。

**⑤ 强绑 Claude 形状的 hook 事件。** Hermes 插件需要把 `transform_tool_result` / `pre_verify` 翻译成 `hook_event_name: "PostToolUse"` / `"Stop"`。这个翻译层是脆的 —— 引擎升级改了事件形状,所有下游 harness 插件都要跟着改。

**⑥ 需要读文档才能用好。** 24 个命令 + 4 种 mode + 三层 ignore + 多 harness 差异,学习曲线不低。`craft-floor.md` 说"任何 UI 编辑前必须加载" —— 这意味着**每次编辑都要额外读一个文件**,token 成本和注意力成本都不小。

### 9.3 适合谁 / 不适合谁

**适合:**
- 团队里有多人在用不同 AI 工具(Claude Code / Cursor / Codex / Copilot 混用),需要一个**共同的、跨工具的设计基线**。
- 已经有成熟前端工程,想把 AI 生成的 UI 纳入设计评审流程(CI 里 `detect --github` 直接出 annotation)。
- 对"AI 味"这件事有明确标准、需要一条能自动执行的检查线的团队。

**不适合:**
- 个人快速原型 —— 装 hook 的开销大于收益,直接手写 prompt 更快。
- 视觉主导的品牌站 —— 62 条规则有相当一部分是"中性 UI"的标准(可读性、对比度、层级),对艺术指导型设计会持续误报(比如 `italic-serif-display` 明确说"编辑/杂志调性可能合理,看上下文")。
- 已经有成熟设计系统的团队 —— `design-system-*` 那四条规则的价值有限,但仍然要装 skill、跑 hook。
- 强依赖原生平台(iOS/Android)—— 原生只跑 Assessment A,检测器那部分完全用不上。

### 9.4 可以直接抄的设计(不一定要用它)

| 值得抄 | 怎么抄 |
|---|---|
| **A/B 双盲评审 + 时序约束** | 任何"让 agent 自评 + 规则校验"的工作流都适用。关键是把"A 先于 B"写成硬约束,以及降级时必须打横幅 |
| **确定性规则做机械层,LLM 做判断层** | 62 条规则不用 LLM,省 token、可 CI、可复现;LLM 只做 taste。分层职责清晰 |
| **同一套规则编译到多个运行时** | Rust → wasm → 页内 bundle,规则逻辑零重复 |
| **扩展点是一等公民** | RulePack 的 findings 走和内置一样的 waiver 路径 |
| **oracle 字节级契约** | CLI/工具类项目直接照抄 `tests/oracle/golden/` 这套 |
| **ignore 的三层粒度 + 理由必填** | `--reason "Agent: literal ball-bounce animation, bounce easing is the subject"` —— 强制写理由,防止忽略清单无声膨胀 |
| **"先跑 A 再跑 B"的 skill 编排** | 参考 `skill/reference/*.md` 的 `<!-- rule:xxx -->` 注释和 `Hard Invariants` 写法 |

---

## 10. 快速上手

```bash
# 安装(会自动检测你装了哪些 harness)
npx impeccable install

# 在 agent 里
/impeccable init              # 写 PRODUCT.md,只问推不出来的
/impeccable document          # 抓现有视觉系统 → DESIGN.md
/impeccable critique the pricing cards

# 不用 agent,直接扫
npx impeccable detect src/
npx impeccable detect http://localhost:5173    # 需要本机 Chrome/Edge
npx impeccable detect --github src/           # CI annotation
npx impeccable detect --list-rules            # 全部 62 条

# Hermes Agent 额外一步
hermes plugins enable impeccable-design-hook
```

---

## 11. 相关 iswiki 文档

- [anthropicAiCodeReview](anthropicAiCodeReview.md) — Anthropic 七层防线的 AI 代码审核流程(同类思路:**用分层自动防线替代"相信模型自觉"**)
- [awesome-design-md](awesome-design-md.md) — DESIGN.md 规范合集(Impeccable 的 `document` 命令就是产出这个)
- [mattpocock-skills](mattpocock-skills.md) — 同为多 harness skill 分发的对照样本
- [patentDisclosureSkill](patentDisclosureSkill.md) — 用"须点名"硬门禁 + 机读前缀约束 agent 行为的另一种做法
- [ipAsLogoSkill](ipAsLogoSkill.md) — 把设计语言写成 SKILL 级硬约束(Impeccable 的 62 条规则是同一思路的规模化版本)

---

## 12. 参考链接

- 仓库: https://github.com/pbakaus/impeccable
- 官网 / 文档: https://impeccable.style · https://impeccable.style/docs
- 规则说明: https://impeccable.style/docs/detector
- hook 配置: https://impeccable.style/docs/hooks
- 案例研究: https://impeccable.style/cases/neo-mirai
- Chrome 扩展: https://chromewebstore.google.com/detail/impeccable/bdkgmiklpdmaojlpflclinlofgjfpabf
- 引擎架构: `docs/ENGINE.md`(271 行)
- CLI 契约: `docs/CLI-CONTRACT.md`(2166 行)
- 运行时环境: `docs/RUNTIME-ENV.md`
- 规则注册表: `crates/foundation/src/registry.rs`
- Hermes 插件: `skill/hermes-plugin/__init__.py`
