# modern-web-guidance — Chrome 团队的「现代 Web 平台」skill

> 学习笔记 · 调研时间 2026-11-16
> npm: <https://www.npmjs.com/package/modern-web-guidance> · 仓库: <https://github.com/GoogleChrome/modern-web-guidance>
> 源码仓: <https://github.com/GoogleChrome/modern-web-guidance-src> · 文档: <https://developer.chrome.com/docs/modern-web-guidance>
> 1.0 发布公告: <https://developer.chrome.com/blog/modern-web-guidance-v1>（Philip Walton · 2026-11-10）
> License: Apache-2.0 · Node ≥ 22 · ⭐ 21,706 · 122 个 npm 版本（0.0.55 → 1.0.1）

## 一句话定位

**把「现代 Web 平台怎么写」做成可检索的知识库，塞进 coding agent** —— 让它别再写 `<div>` + 几十行 JS 做模态框，而用 `<dialog>`；别再手搓 focus trap，用 `inert`。

由 **Google Chrome 团队出品，Microsoft Edge / Mozilla Firefox / MDN 团队共同维护**（2026-11 起从 Chrome 单方变成跨浏览器项目）。

## 一、它解决什么问题

官方原话（1.0 公告）：

> "AI models are very good at figuring out how to make something work **with JavaScript**, but in many cases there are **HTML or CSS features that can do the same thing with much less code**. And since they're handled by the browser, they usually perform better and come with accessibility affordances."

**根因是 LLM 训练数据过时** —— 模型见过海量老代码，所以：
- 要个 modal → 给 `<div>` + 手写 focus trap（而 `<dialog closedby="any">` 早就有了）
- 要个 tooltip → 上 Popper.js（而不是 Popover API + anchor positioning）
- 要个 scrollbar 样式 → 写 `::-webkit-scrollbar`（Firefox 完全无效）

官方给的量化说法：**前沿模型在我们的现代 Web 检查项上仍会失败约一半**（unguided ~51% → guided 91%）。

## 二、⭐ AI 到底错在哪：官方「Top 10」逐条拆解

> 💡 这是本篇最有信息量的部分 —— 官方自己承认模型在哪翻车，比任何第三方评测都具体。
> 来源：<https://developer.chrome.com/blog/top-10-things-ai-gets-wrong-in-web-dev>

### 无障碍（3 条，模型错得最多的）

**① 键盘焦点与 `inert` 管理**
- 新视图打开后**不移动焦点**，返回时**不还原焦点**到触发元素
- 自定义模态用**手写 JS tab trap + `aria-modal="true"`**，而不是用 `<dialog>` 或给背景加 `inert`
- 把工具栏/方向网格的每一项都暴露成独立 tab stop，而不用 **roving tabindex**
- 自定义 `:focus-visible` 轮廓**对比度不足 3:1**

**② `prefers-reduced-motion` 支持**
- 在 root 上**无条件**设 `scroll-behavior: smooth`
- scroll-driven 动画（view transitions / 滚动驱动）**不做 reduced motion 检查**
- 用 `* { transition-duration: 0.01ms }` 一刀切 → **把状态变化提示等必要过渡也一起干掉了**
- reduced motion 下覆盖 `::view-transition-*`，而应该只把 `@view-transition` 规则 gate 住

**③ 表单校验 / format hint / autofill 状态**
- 用 JS blur 校验**重新实现 `:user-invalid`** → 未交互的必填项一 tab 过去就报错
- **`aria-invalid` 与可见错误不同步**（blur 时过早设 true，或只改 CSS 不改 ARIA）
- 靠**消失的 placeholder** 提示格式（应改用持久 hint + `aria-describedby`）
- format hint 放在 `<input>` **下方** → 被移动端键盘和 autofill 气泡遮住
- `:autofill` 高亮**只改 border-color** → 应配一个不引起布局偏移的非颜色线索（如 inset box-shadow）

### 体验（3 条）

**④ 滑动 / 触摸手势**
- 用 `pointermove`/`touchmove` 手写 swipe-to-dismiss，而不用 **CSS Scroll Snap**
- 漏掉 **`overscroll-behavior-x: none`** → 过滑动会触发浏览器前进/后退
- 用 JS 回调在主线程驱动滑动进度，而不用 **scroll-driven animations**
- scroll-based swipe 面板**没做键盘焦点支持**

**⑤ 对话框 / popover / top-layer 过渡**
- 自定义 `position: fixed` 覆盖层 + 手写 click-outside，而不用 **`popover`**
- 用切换 class + `requestAnimationFrame` + `transitionend` 手写进出场，而不用 **纯 CSS `@starting-style` + `transition-behavior`**
- 靠 `<html>` 上 `overflow: hidden` 锁滚动，而不用 `<dialog>` 自带的 overscroll 包含
- 加 `popstate` 监听来关 Android 返回手势打开的模态，而不用 **`<dialog>` 原生返回键关闭**

**⑥ 暗色模式 / 主题自适应**
- **漏掉 `<meta name="color-scheme" content="light dark">`** → 暗色用户看到白屏闪烁
- 自定义暗色却不设 `color-scheme` → **原生滚动条和表单控件卡在亮色**
- 没用 CSS **`light-dark()`** 函数做主题自适应 token
- 只给「亮/暗」二元开关存 localStorage 显式覆盖，**没有「跟随系统」选项**

### 性能（2 条）

**⑦ 运行时响应性（INP）**
- 用自定义 `setTimeout()` 队列做后台任务，而不用 **`scheduler.postTask()`** / `scheduler.yield()`
- 密集数据网格**不设 `content-visibility: auto` + `contain-intrinsic-size`** → 交互后触发全页重排
- 隐藏 SPA 视图用 **`display: none`（销毁渲染缓存）** 而不用 `content-visibility: hidden`（配 `inert`）
- 用 **scroll 事件监听**做滚动提示（强制连续布局计算），而不用 **CSS scroll-state queries**

**⑧ 布局偏移与视觉闪烁**
- **`<video>` 漏掉 `width`/`height`** → 默认 300×150，metadata 加载后跳版
- web font 配系统 fallback 但**没用 `font-size-adjust`** → 字体替换时可见重排
- hero/全屏用**静态 `vh`** 而不用 `dvh`/`svh` → 移动端工具栏伸缩时内容跳动
- 用 `opacity: 0` 防闪烁片段 + A/B 测试的**多秒 setTimeout**（拖慢 LCP 且元素仍可点击）→ 应该用 `blocking="render"`
- 跨文档 view transition **在首屏关键标记解析前就触发** → 应该用 `rel="expect"` + `blocking="render"`

### 安全（2 条）

**⑨ DOM XSS 防御与 HTML 净化**
⭐ **最刺眼的一条**：
> "across all the tasks in our full eval suite, models **did not add a Content Security Policy (CSP) or cross-origin isolation header without explicit prompting**."

即使 prompt 明确要求安全，unguided 模型**仍有一半以上安全检查项失败**：
- 手写 `DOMParser` 白名单净化器，而不用 **DOMPurify**
- 每次页面加载都 eager bundle DOMPurify，而不用**原生 `setHTML()`**（支持时）
- 注册**宽松的 `input => input` 透传 Trusted Types policy**，反而架空了 sink 强制
- 静态页面配 Trusted Types 但 CSP 用宽松 `script-src 'self'`，而不用 **SHA-256 hash 锁内联脚本**
- nonce-based CSP **漏掉 `'strict-dynamic'` 和 `'report-sample'`**

**⑩ Passkey 登录 / 重新认证 / 凭据生命周期**

## 三、核心组件与架构

### 3.1 工作机制（官方 How It Works）

```
1. Activation   agent 因任务相关性激活 modern-web-guidance skill
                ↓
2. Local Semantic Search
                agent 跑 `modern-web-guidance search "<query>"`
                离线嵌入模型 + BM25，零网络调用、零 API key
                ↓
3. Guide Fetch  agent 跑 `modern-web-guidance retrieve <id>`
                把代码模式、坑、fallback 精确插进 context window
```

⭐ **关键设计：skill 本体只有 ~9.8 KB（一份 SKILL.md），209 个指南放在独立的 CLI 里按需取** —— 不是把 1.9 MB 塞进上下文。

### 3.2 三条设计原则（官方自述）

| 原则 | 做法 |
|---|---|
| **渐进增强 + 精细 fallback** | 区分「纯增量增强」（如 speculative preloading，老浏览器可静默忽略）和「关键行为」（如 dialog 控制、网络 beacon）—— 后者写**经过斟酌的低开销 fallback** |
| **负责的 fallback** | 优先**轻量、场景定制的自写 fallback（<50 LOC）**或条件加载的 polyfill，而非重型第三方 bundle |
| **Baseline 感知** | 用 **Baseline 项目的实时兼容性数据**，让 agent 按你的项目实际浏览器支持度动态适配 |

还有一条**很有分寸的设计**：
> **Origin Trial 与易变特性默认 gate 住** —— 实验性 API 和「近 3 个月内发布或仍在稳定的单引擎特性」**可以被 search 到，但在 retrieve 上锁**，除非开发者显式同意。

### 3.3 项目级配置 `.mwgrc`

```jsonc
{
  "allowOriginTrials": true,      // 解锁实验性 Origin Trial API 指南
  "allowVolatileFeatures": true   // 解锁易变单引擎特性指南
}
```
放在项目根目录（或 `~/.mwgrc` 作用户级兜底），**可 commit 共享给团队**。

### 3.4 两个 skill pack

| Pack | Token | 内容 |
|---|---|---|
| `modern-web-guidance` | ~205 | 现代浏览器 API、布局、性能的通用指导 |
| `chrome-extensions` | ~175 | Manifest V3、background worker、扩展 API、Chrome Web Store 发布 |

## 四、怎么用（三层，逐层实测过）

### 4.1 第一层：不装，直接用 CLI（我实测通过）

```bash
npx modern-web-guidance@latest search "animate a dialog modal backdrop"
npx modern-web-guidance@latest list
npx modern-web-guidance@latest retrieve "animate-to-from-top-layer"
npx modern-web-guidance@latest legacy-scan .
```

**实测输出**（search 命中 `animate-to-from-top-layer` 排第一，与官方 README 示例一致）：
```json
[{"id":"animate-to-from-top-layer","description":"Animate elements such as dialogs, popovers, and tooltips as they're entering/exiting the top layer."},
 {"id":"light-dismiss-a-dialog",...}, {"id":"prevent-page-scroll-under-modal-dialog",...},
 {"id":"dialog",...}, {"id":"navigation-drawer",...}, ...]
```

`retrieve` 的内容形态（**实跑截取**）—— 含反模式警告 + 浏览器支持矩阵 + fallback：
```
# Break Up Long Tasks
... use `scheduler.yield()`, which pauses an already-running task ...
**DO NOT** replace `scheduler.postTask()` or `TaskController` with `scheduler.yield()`
alone when scheduling work at different priorities; see `schedule-tasks-by-priority`.
...
### Fallback strategies
Browser support for Scheduler API: Limited availability.
Supported by: Chrome 129 (Sep 2024), Edge 129 (Sep 2024), and Firefox 142 (Aug 2025).
Unsupported in: Safari.
```

### 4.2 第二层：装成 skill（推荐）

```bash
npx modern-web-guidance@latest install
```

⭐ **安装器识别 79 个 agent，其中明确包含 "Hermes Agent"**（我实跑看到的安装摘要）：

```
◇  79 agents
●  Installing to: CodeBuddy, Hermes Agent, MiniMax Code, OpenCode, Qwen Code, Trae CN
✓ Installed 1 skill
   ~/.agents/skills/modern-web-guidance
   universal: OpenCode, Amp, Cline, Codex, Cursor +15 more
```

**落盘结构**（我实装后看到的）：
```
.agents/skills/modern-web-guidance/
├── SKILL.md          9.8 KB
├── guides/           1.9 MB / 210 个 .md（17 个子目录）
└── skills-lock.json  记录 source + commit + computedHash
```

**6 种其他安装路径**（官方 README 列出）：

| Agent | 命令 |
|---|---|
| Vercel Skills CLI | `npx skills add GoogleChrome/modern-web-guidance` |
| GitHub CLI | `gh skill install GoogleChrome/modern-web-guidance` |
| Claude Code Plugin | `/plugin marketplace add GoogleChrome/modern-web-guidance` → `/plugin install modern-web-guidance@googlechrome` |
| GitHub Copilot CLI | 同上（`@googlechrome`） |
| Google Antigravity | `agy plugin install https://github.com/GoogleChrome/modern-web-guidance` |
| Grok Build CLI | `grok plugin install https://github.com/GoogleChrome/modern-web-guidance --trust` |

更新：`npx modern-web-guidance@latest update`；卸载：`uninstall`。

### 4.3 第三层：`legacy-scan` 现代化扫描（1.0 新增）

```bash
npx modern-web-guidance@latest legacy-scan src --json
```

**我实跑的输出**（故意在样本里放了 `::-webkit-scrollbar`、`<div class="modal">`、`loading="eager"` 三种 legacy pattern）：

```json
{
  "totalFindings": 2,
  "guides": [{
    "guideId": "customize-scrollbar-color-and-thickness",
    "rules": [{
      "verifierRubric": {
        "keepWhen": ["The CSS rule uses vendor pseudo-elements (::-webkit-scrollbar ...) ..."],
        "dropWhen": ["The stylesheet already defines standard scrollbar-width or scrollbar-color properties.",
                     "... or the rule is inside an @supports not (scrollbar-color: auto) fallback block."]
      },
      "findings": [
        {"file":"legacy.html","line":4,"message":"CSS rule uses vendor ::-webkit-scrollbar pseudo-elements ..."},
        {"file":"legacy.html","line":5,"message":"..."}
      ]
    }]
  }],
  "activeRuleCount": 52,
  "activeGuideCount": 38,
  "note": "Checked 38 guides (52 deterministic rules; ~20% of the guidance corpus).
           Finding 2 items here only reflects deterministic legacy patterns;
           use 'search <topic>' for the rest of the catalog."
}
```

⭐ **三个关键事实**：
1. **只找到 2 处** —— 我故意放的 `<div class="modal">` 和 `loading="eager"` **都没报**
2. **只覆盖 38/209 ≈ 18%** 的指南（官方 JSON 自己承认 "~20% of the guidance corpus"）
3. **带 keep/drop rubric** —— 能区分「真 legacy」和「已在 `@supports` fallback 块里的合规写法」（但规则复杂，不读 rubric 看不出门道）

**结论：它是烟雾报警器，不是全面检查。** 官方也明说 1.0 只是 "static analysis to check for a **limited set** of patterns"，未来会加入 agentic audits。

### 4.4 官方给的现成 prompt

官方文档直接给了可抄的 prompt 模板：

```bash
# 构建新体验
"Create an accordion-style stats component that smoothly animates on open and close."
"Build a tab bar with a sliding highlight that tracks active items using CSS Anchor Positioning."
"Design a dashboard card that uses container queries to adapt its layout to its own width."

# 改造遗留代码
"Update legacy modal window implementations to use the <dialog> element and animate them using modern CSS features."
"Migrate legacy tooltips to use the Popover API and CSS Anchor Positioning."

# 安全
"Implement a passkey-based login flow using the latest WebAuthn features."
"Implement a starter Content Security Policy (CSP) without breaking my app."

# 性能
"My app has lots of long tasks, and its INP is affected. Help me fix it."
```

## 五、业界评价

### 5.1 官方 evals（最强证据，但是自己测自己）

| 日期 | Agent + 模型 | 任务/检查 | Unguided → Guided |
|---|---|---|---|
| Nov 8 | antigravity_cli (gemini-4-argon) | 214 / 1673 | 58% → **94%**（+36pp） |
| Nov 8 | codex_cli (gpt-6.1-sol) | 215 / 1795 | 54% → **82%**（+28pp） |
| Nov 8 | claude_code (opus-5-5) | 215 / 1801 | 57% → **88%**（+31pp） |
| Nov 6 | codex_cli | 212 / 1773 | 53% → 86%（+33pp） |
| Nov 6 | claude_code | 212 / 1773 | 56% → 90%（+34pp） |
| Nov 6 | antigravity_cli | 212 / 1722 | 60% → 96%（+36pp） |

**方法论（值得抄）**：
```
[专家撰写的指南 + demo]
        ↓
[目标生成] → 真实 webapp 上的任务、黄金解、Playwright grader
        ↓
[校准闭环] → Grader 跑黄金解（必须 100% 通过）
              Grader 跑未修改基线（必须 100% 失败）
        ↓
[E2E agent evals] → 有/无引导两种模式对比
```

⭐ **两个关键指标定义**：
- **opportunity** = 100% − unguided 通过率（模型本来就会的 → **剪掉**，因为是冗余内容）
- **uplift** = guided − unguided（模型挣扎的 → **精修**指南）

⭐ **prompt 不点名 API** —— 测 agent 能否自己发现该查哪条指南。这个设计比「告诉它用 X API」公平得多。

**公开 eval dashboard**：<https://googlechrome.github.io/modern-web-guidance-src/>

### 5.2 第三方独立评测

**✅ 500x Engineer（Codex 实测，11-12）**
自写 10 项内置浏览器特性清单：

| Run | 特性检查 10 项 | 点击穿透 10 项 | legacy-scan 发现 | app.js 有效行数 |
|---|---|---|---|---|
| plain-1 | **2** | 10 | 1 | 156 |
| plain-2 | **2** | 10 | 1 | 165 |
| guided-1 | **9** | 10 | 0 | 202 |
| guided-2 | **9** | 10 | 0 | **271** |

⭐ **最值得注意的反直觉结论：引导后 JS 反而更长** —— 原生特性 + 兼容 fallback 同时出现。作者自己说样本很小（1 prompt / 1 model / 每组 2 次）。

**✅ VarOps**：引用第三方 1,072 次任务运行 —— Claude Code **52% → 92%**、Codex **50% → 86%**、Antigravity **56% → 95%**，整体 **53% → 92%**；**无障碍检查 58% → 93%**（dashboard 自称「不是完整 WCAG 审计」）。结论：**「这周就在一个前端仓上装」**。

**✅ bitdoze（Astro 博客实跑，11-12）**：legacy-scan 找到 5 处，逐条核对 keep/drop rubric，**2 处需要再看**（1 处已部分处理、1 处是死代码）。⭐ 关键洞察：**「现代」的标准属性优先、vendor 兜底第二，不是删掉 vendor 代码** —— 因为 `scrollbar-color` 到 Baseline 是 2025-12（Safari 26.2），直接删 WebKit 规则会回归老 Safari。

**✅ The Search Post（读完 203 个指南）**：速度、表单、无障碍覆盖强，**SEO 几乎为零** —— 没有一条讲 title / canonical / 结构化数据 / 爬虫。结论：**「它让 agent 写更好的前端代码，不是更好的 SEO」**。

**✅ 官方生产案例**（Chrome 文档页列出）

| 公司 | 成果 |
|---|---|
| Policybazaar / Pensionbazaar | 新页面周转与 UI bug 减少 90%+，**手工 Core Web Vitals 审计工作量减少 92%** |
| MetaMask | 三行 advisory PR review bot 覆盖 ~480 个 PR，驱动 **43 处无障碍与语义 HTML 修复**，中位周转 15 分钟 |
| WeTV | CI/CD 自动诊断并修复 **90% 复现的 CLS 回归**，性能调试**快 87%** |
| note inc. | 现代 Web 指南遵循度 **61% → 94%**，LCP 优先级提升 **28%** |

### 5.3 ⚠️ 负面与质疑

**⚠️ 搜索召回不稳定 —— Ivan Kristianto 实测（11-05）**
搜 "filter list as you type" **拿不到自己的 `break-up-long-tasks` 指南**（返回的全是 forms / html / accessibility / validation / menus / autofill + 两个 WebMCP）。结果：16 个页面 INP 中位数 **baseline 2,715ms vs guidance 2,729ms —— 完全打平**，16 个页面全部落在 INP 的 poor band。

> ⭐ **但我今天用 1.0.1 复现，这条已经修好了** —— 搜 `break up long tasks` 现在**排第一**（他当时用 0.0.197 版本）。**所以这是旧版本缺陷已修复，不是当前问题。**
> ⚠️ 不过"filter list as you type"仍召回 form 类指南 —— 说明**语义搜索对「用户意图式描述」仍有边界**，纯 feature 名比业务描述更可靠。

**⚠️ 无障碍界权威 Adrian Roselli 的质疑**（5 月 preview 版）：输出**不符合 WCAG**、动画在 Firefox 失效，且「无法保证 agent 能遵循指南」。⚠️ 这是 preview 版，**v1.0 未见复测**。官方 v1.0 声明 user-facing guides 都过了「每天靠辅助技术工作的无障碍专家」的评审。

**⚠️ 遥测默认开启 —— Gloss 实测（11-15）**
> "The README says search makes 'no network calls'. **By default the same package posts every search query, the guide IDs it matched and your agent's name to a Google logging endpoint.**"

⚠️ 告知只在 `install` 命令时打印，而 README 列了 **8 条绕过它的安装路径**（走市场/插件安装的用户可能看不到）。
**退出方式**：`export DISABLE_TELEMETRY=1`。
官方说法：收集安装数、调用方 agent 名、指南检索 ID、**CLI 搜索查询词**；**不收集原始 user prompt**。代码在 `src/cli/modern-web.ts`。

**⚠️ 代码变长 / token 变多**（500x Engineer 与 VarOps 都提到）—— 引导后 token 更多、跑得更慢。

**⚠️ legacy-scan 覆盖只有 ~18%**（见 §4.3）。

**⚠️ 版本号极其碎** —— 122 个 npm 版本，0.0.x 阶段基本**每天发 1–3 次**（如 2026-05-14 一天发 12 个）。**升级节奏极快**，要 pin 版本。

## 六、⚠️ 我核实到的几处数据出入

不同来源的数字口径不一致，引用时要小心：

| 口径 | 数字 | 来源 |
|---|---|---|
| README 声称 | **262** modern web features | 仓库 README |
| `list` CLI 实测 | **209** 条（唯一 id 209） | 我实跑 1.0.1 |
| guides 目录实际文件 | **210** 个 .md（17 个子目录） | 我实装后数 |
| 1.0.0 时期各方报道 | 203 / 208 条 | The Search Post / Gloss / Medium |
| 官方文档页 | "200+ expert-vetted guides" | developer.chrome.com |
| 官方文档页另一处 | **91%** pass rate（unguided ~51%） | developer.chrome.com |

⭐ **结论：262 是「涵盖的 Web 特性数」，203/208/209 是「指南条目数」，两者不是一回事** —— 一条指南常覆盖多个特性（如 `break-up-long-tasks` 同时涉及 `scheduler.yield` / `scheduler.postTask` / `TaskController` / INP）。

**指南规模**（我实装后统计）：
- 单文件：最小 1,870 B / **中位 7,630 B（≈1,900 token）** / 最大 51,700 B（`accessibility.md`）
- 总计 1.9 MB

**分类分布**（210 个文件）：
| 目录 | 数量 | 目录 | 数量 |
|---|---:|---|---:|
| ui-behaviors | 40 | ui-atoms | 13 |
| performance | 26 | html | 8 |
| ui-components | 22 | js | 6 |
| visual-design | 22 | built-in-ai | 5 |
| forms | 19 | accessibility | 4 |
| css | 18 | webmcp | 3 |
| security | 17 | user-experience | 3 |
| | | pwa / privacy / wasm | 2 / 1 / 1 |

## 七、跟我们的关系

### 7.1 ⭐ 它和 `web-frontend-ui/` 分类正好对口

本仓 `web-frontend-ui/` 已有 19 篇（`threeui` / `artemis-art-direction` / `mediaPipeTasksVision` / `animeJs` / `odometer` / `weatherNext` …）。这些笔记记录的是**具体库怎么用**；Modern Web Guidance 补的是**跨库的底层约定** —— 「写 modal 就用 `<dialog>`、写 scrollbar 就用 `scrollbar-color`、写暗色就设 `color-scheme`」。

**最直接的价值场景**：本仓任何一个前端笔记要写示例代码时，都该先过一遍 `search` —— 否则示例本身就示范了 legacy pattern，那笔记就是在传播坏习惯。

### 7.2 ⭐ 它是「agent 写前端代码」的质量门

用户日常用 agent 写前端（`web-frontend-ui/` 那些项目）。装上之后相当于给 agent 加了一层**浏览器工程师审过的规范** —— 而且是**随 Web 平台演进而更新**的（这是静态规范文档做不到的）。

⭐ **配套建议**：官方明确推荐 **Modern Web Guidance + Chrome DevTools for agents** 组合：
> "Modern Web Guidance gives your agent the **up-front expertise** needed to write code... Chrome DevTools for agents gives your agent **runtime visibility** so it can verify, debug, and optimize."

三组官方给的协作范式：
| 场景 | MWG 负责 | DevTools for agents 负责 |
|---|---|---|
| 性能 | 教 agent 怎么打断长任务 | 跑 performance trace，看实际阻塞多少 ms |
| 动画 | 教 agent 怎么正确动效 | 录屏检查动画实际效果 + `prefers-reduced-motion` |
| 缓存 | 教 agent 怎么缓存视图 | memory 调试查泄漏 |

### 7.3 三条落地建议

| 优先级 | 动作 | 说明 |
|---|---|---|
| ⭐⭐ | **先只装 CLI 不装 skill** | `npx modern-web-guidance@latest search/retrieve` 零侵入，验证几条指南的质量后再决定是否装 skill |
| ⭐⭐ | **装 skill 前先写清浏览器支持目标** | 官方/VarOps 都强调：没有明确目标，fallback 建议就无处落地 —— 这也是「代码变长」的根源。建议写进 agent 指令文件："only features available in all major browsers for at least a year" |
| ⭐ | **装 skill 时设 `DISABLE_TELEMETRY=1`** | 默认发搜索词到 Google；不装 skill、只跑 CLI 的话可以不设 |

⚠️ **Hermes 侧的一个具体坑**（我实装时遇到）：安装器把 Hermes 标为 `skipped (project directory not found)` —— 它在**当前工作目录**下找 Hermes 项目目录，而不是装到 `~/.hermes/profiles/general/skills/`。要装到 Hermes，得在 Hermes profile 目录下跑，或手动拷 `.agents/skills/modern-web-guidance/` → `~/.hermes/profiles/general/skills/`。

### 7.4 ⚠️ 它不能替代什么

- **不能替代 SEO 检查**（实测：203 个指南里 0 条讲 title/canonical/结构化数据）
- **不能替代运行时验证**（官方自己说要配 DevTools for agents）
- **legacy-scan 不能替代全面审计**（只覆盖 ~18%）
- **不能替代 WCAG 审计**（dashboard 自称「not a full WCAG audit」；无障碍权威对 preview 版的质疑 v1.0 未见复测）

## 参考链接

**一手（官方）**
- npm: <https://www.npmjs.com/package/modern-web-guidance>
- 仓库（发布目标）: <https://github.com/GoogleChrome/modern-web-guidance> ⭐21,706
- 源码仓（提 PR 去这里）: <https://github.com/GoogleChrome/modern-web-guidance-src> ⭐8,287
- 官方文档: <https://developer.chrome.com/docs/modern-web-guidance>
- 1.0 发布公告: <https://developer.chrome.com/blog/modern-web-guidance-v1>
- ⭐ Top 10 things AI gets wrong: <https://developer.chrome.com/blog/top-10-things-ai-gets-wrong-in-web-dev>
- Eval Dashboard: <https://googlechrome.github.io/modern-web-guidance-src/>
- Baseline 兼容性数据: <https://web-platform-dx.github.io/web-features-explorer/>

**第三方评测**
- 500x Engineer（Codex 实测）: <https://www.500xengineer.com/blog/modern-web-guidance-test>
- VarOps: <https://varops.com/how-to-test-chromes-modern-web-guidance-skill-on-coding-agents-before-paying-for-the-extra-tokens/>
- The Search Post（SEO 视角）: <https://thesearchpost.com/modern-web-guidance>
- bitdoze（legacy-scan 实跑）: <https://www.bitdoze.com/modern-web-guidance-legacy-scan>
- Ivan Kristianto（⚠️ 负面实测 + 机制分析）: <https://www.ivankristianto.com/testing-modern-web-guidance/> · <https://www.ivankristianto.com/chrome-modern-web-guidance/>
- Gloss（⚠️ 遥测分析）: <https://gloss.run/post/chromes-modern-web-guidance-sends-agent-searches-to-google>
- Search Engine Journal（引 Roselli 的质疑）: <https://www.searchenginejournal.com/google-releases-modern-web-guidance-1-0-for-ai-coding-agents/596495/>

**相关笔记**
- [impeccable](impeccable.md) — 同为「给 coding agent 的硬约束」类工具（设计词汇表 + 反模式检测规则），可对照两者的 eval 方法论
- [awesome-agent-skills](awesome-agent-skills.md) — skill 生态横切面
- [mattpocock-skills](mattpocock-skills.md) · [homeRepoPattern](homeRepoPattern.md) — agent skill 的组织与分发模式

> ⚠️ **本机可达性说明**（2026-11-16 实测）：上列 16 条外链中 **14 条 curl 直返 200**；
> `npmjs.com/package/...` 与 `bitdoze.com/...` 两条返回 **403 Cloudflare 人机验证**（浏览器同样卡在验证页）——
> **非死链**：npm 包的元数据已通过 `registry.npmjs.org` 一手 API 核实（1.0.1 / Apache-2.0 / 122 版本）；
> bitdoze 那篇的正文（含 legacy-scan 的完整 JSON 输出）已从搜索索引取得。读者在常规浏览器环境应可正常打开。
