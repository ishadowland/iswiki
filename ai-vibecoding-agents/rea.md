# REA (morluto/rea) — 一个 MCP 逆向工程项目:让 agent 从「你觉得这功能不错」到「二进制级证据」

> 学习笔记 · 调研时间 2026-10-08
> 仓库: <https://github.com/morluto/rea> · 官网: <https://morluto.github.io/rea/> · npm: `rea-agents`
> 作者: morluto(独立开发者,X `@morluto`,bio 仅一个词「MTS」)
> License: MIT · TypeScript · ⭐ **20,918** · 2,247 forks · 79 open issues
> 建仓 2026-04-14 · npm 首版 2026-07-12 · 最新 **v6.0.0(2026-10-08)**
> 本机实测: `rea doctor --json` 跑通,Node 24.13.0 / macOS 13.6 判定 healthy

⚠️ **用户口述「14.5k star」与实际不符,实际是 20,918⭐**。下面所有数据以 GitHub API + 本机 clone + 实跑为准。

## 一句话定位

**一个 MCP server + CLI,把 Hopper / Ghidra / IDA 三个反编译引擎和十余种目标格式,封装成 106+ 个带证据链的 MCP 工具**,让 coding agent 能回答「这个 App 里那个功能是怎么实现的」并给出可验证证据,而不是猜。

它的独特之处不在「能反编译」,而在**强制每条结论都要挂证据 ID,并显式记录 unknowns(未知项)**。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **MCP(主推)** | `npx rea-agents setup` 注册到 agent | 让 Claude Code / Codex / Cursor / Gemini CLI 等直接调用 106+ 工具 |
| **CLI(一次性)** | `npx -y rea-agents@latest <cmd>` | 单次分析、脚本化、CI;**无需 MCP 注册即可用大部分静态能力** |
| **skill-only** | 从 skills.sh 装 `reverse-engineer-anything` skill | 只拿工作流指令,不装引擎 —— 但**单独装 skill 不注册 MCP,工具不会凭空出现** |

CLI 的价值被低估:skill 里明确写了「No MCP registration or native engine is required. Read the returned Evidence, graph, limitations, and unknowns with the same care as an MCP result」—— **CLI 和 MCP 返回同构的 Evidence 结构**,这对无 MCP 环境(如本机 Hermes 部分 profile)很关键。

## 核心架构

```
┌─ Agent (Claude Code / Codex / Cursor / Gemini CLI)
│   提问:「Notes app 的搜索是怎么做的?给我证据」
│
├─ skill: reverse-engineer-anything (v33)
│   不是「怎么用工具」的说明书,而是「怎么提问/怎么下结论」的方法论约束
│
├─ MCP server (rea-agents) ── 或 ── CLI (rea <cmd>)
│   ├── 106+ MCP 工具(inspect/trace/compare/verify/list/...)
│   ├── Evidence 记录层(每个结论挂 Evidence ID)
│   ├── Unknowns 台账(record_unknown / list_unknowns / verify_unknown_resolution)
│   └── provider 绑定(open_binary → Hopper|Ghidra|IDA,失败不自动切换)
│
└─ 分析引擎 / 工具(mix)
    ├── Hopper / Ghidra / IDA      (原生二进制深度分析)
    ├── JADX (headless)            (Android APK)
    ├── Binwalk / Unblob           (固件)
    ├── mitmproxy (Linux)          (网络抓包)
    ├── pwntools / GDB / pwndbg    (崩溃记录 / ELF)
    └── Chrome 系浏览器            (网页分析)
```

**`bridge/` 目录是关键的工程选择**:每个外部引擎都有一个 bridge(`hopper_bridge.py`、`pwndbg/`、`mitmproxy/`、`ghidra/`),把各引擎的异构接口统一成同一种调用契约。**这是它比单个引擎 MCP 强的地方** —— 不是造新引擎,而是**做适配层**。

**第三方依赖走 git submodule(不是 npm 依赖)**:

```
third_party/jadx-headless-mcp   → github.com/1013503897/jadx-headless-mcp
third_party/binwalk             → github.com/ReFirmLabs/binwalk
third_party/unblob              → github.com/onekey-sec/unblob
third_party/ghidra-nativeaot    → github.com/Washi1337/ghidra-nativeaot
third_party/wakaru              → github.com/pionxzh/wakaru
```

→ **clone 后要 `--recursive`,否则这些目录是空的**。这是最容易踩的坑。

## 106 个工具的分类结构(从 src 一手统计)

| 前缀 | 数量 | 代表工具 |
|---|---|---|
| `inspect_*` | 27 | `inspect_binary_layout` / `inspect_managed_members` / `inspect_web_page` / `inspect_android_class` |
| `list_*` | 14 | `list_functions` / `list_strings` / `list_classes` / `list_browser_targets` |
| `trace_*` | 12 | `trace_feature` / `trace_call_path` / `trace_application_feature` / `trace_crash` |
| `compare_*` | 12 | `compare_functions` / `compare_artifacts` / `compare_web_captures` |
| `capture_*` | 11 | `capture_process_scenario` / `capture_electron_scenario` / `capture_web_screenshot` |
| `verify_*` | 5 | `verify_reconstruction` / `verify_unknown_resolution` / `verify_reconstruction_obligations` |
| `analyze_*` | 4 | `analyze_function` / `analyze_javascript_application` |
| `open_/close_` | 6 | `open_binary` / `close_binary` / `open_database` |
| 其他 | 15 | `decompile_function` / `disassemble_function` / `read_bytes` / `search_*` / `export_evidence_bundle` |

**CLI 有独立的一套命名**(`src/cliCommandNames.ts` 里 `CLI_COMMANDS` 冻结对象,96 个主命令 + 1 别名),并显式维护 `CLI_COMMAND_TOOL_ALIASES` 映射(`analyze`/`inspect` → `binary_overview`,`function` → `analyze_function` …)。

**这个文件里还藏着一个信息** —— `MCP_TOOLS_WITHOUT_DEDICATED_CLI` 列了 **55 个只有 MCP 没有 CLI 的工具**,其中 `procedure_assembly` / `procedure_callees` / `get_call_graph` / `batch_decompile` 这类**底层操作密集**。

**→ 实用推论:需要精细控制反编译引擎时,用 MCP;只做「问一个问题」式分析,CLI 足够。** CLI 是 MCP 的子集 + 一层命令别名。

## 最值得学的设计:Evidence + Unknowns(这是它真正的差异化)

翻遍 106 个工具名,有一组格格不入:

```
list_unknowns      record_unknown      update_unknown
verify_unknown_resolution      verify_reconstruction
verify_reconstruction_obligations        get_evidence_bundle
```

**它把「我查了什么」和「我还没查清什么」都做成了可查询的工具。** skill 里对应的硬性要求(原文):

> Every conclusion must distinguish observations, inferences, and unknowns. Cite Evidence IDs, preserve limitations and incomplete coverage, and never imply …

**逐层递进的工作流**(skill 明文规定):先把请求变成「问题清单 + 每个问题需要什么证据」,再逐个查,查完检查「返回的证据是否还留下具体缺口」,有缺口就补查,最后用与结论类型相称的证据做佐证(静态结论要静态证据,运行时结论要运行时证据)。

**这套东西在 2026 年是稀缺的。** 对照我们每天在做的事:agent 说「已完成」「已修复」「应该没问题」时,**没有任何机制要求它挂证据 ID,也没有任何机制记录它的 unknowns**。我在 `iswiki` 的多篇笔记里都踩过同一个坑 ——「用户口述的数与远端 API 不一致,以远端为准」这条铁律,本质就是**强制 claim 挂一手证据**,和 REA 是同一个思路。

**另一个硬约束**:`process_lineage` 的观察被明确限定为「historical snapshots, not live process inventories, and do not claim that no short-lived descendant existed」—— **即使工具能观测到,它仍然拒绝声称「不存在 X」**。这种「能力边界写在契约里」的做法,比在文档里写免责声明强得多。

## 版本节奏(这是它最激进的地方)

| 指标 | 数值 |
|---|---|
| 31 个 release(2026-07-12 起) | 平均 **~2 天一个版本** |
| 版本号跨度 | 1.6.0 → 1.7.0 → 2.0 → 2.7 → 3.0 → 3.1 → 3.2.1 → 4.0 → 4.1 → **6.0.0** |
| 一个月内跳 6 个大版本 | 9-28 → 10-08:2.0 → 6.0 |

**最近 10 天:4.0.0(10-05) → 4.0.1 → 4.1.0(10-06) → 5.0.0(10-07) → 6.0.0(10-08)**,其中 4.0/5.0/6.0 都是大版本。

⚠️ **这对使用方式是硬约束**:skill 里明确警告

> a skill installed from repository main may describe capabilities absent from an older npm release

**即「skill 描述的功能在旧 npm 包上可能不存在」** —— 结论:**skill 和 npm 包必须同步更新**,混用会拿到一份描述了不存在能力的指令。README 也要求每次更新后重跑 setup 刷新注册。

## 本机实测:环境诊断结果

`rea doctor --json` 真实输出(2026-10-08,本机 macOS 13.6 / Node 24.13.0):

| 检查项 | 状态 | 分类 | 详情 |
|---|---|---|---|
| `node` | ✅ | healthy | 24.13.0 |
| `host` | ✅ | healthy | 13.6 |
| `hopper` | ❌ | missing_analysis_engine | 需 `rea setup` 安装或设 `HOPPER_LAUNCHER_PATH` |
| `ghidra` | ❌ | missing_analysis_engine | `GHIDRA_INSTALL_DIR is not set` |
| `ida-registration` | ❌ | missing_analysis_engine | IDA MCP 未配置 |
| `skill:identity` | ❌ | config_drift | 已安装的 REA skill identity 缺失 |
| `registration:claude_code` | ❌ | config_drift | `/Users/liuyin/.claude.json` |
| `registration:cursor` | ❌ | config_drift | `/Users/liuyin/.cursor/mcp.json` |
| `registration:gemini_cli` | ❌ | config_drift | `/Users/liuyin/.gemini/settings.json` |
| `registration:opencode` | ❌ | config_drift | `/Users/liuyin/.config/opencode/opencode.json` |
| `registration:vscode` | ❌ | config_drift | `~/Library/Application Support/Code/...` |

**结论:本机 Node 环境完全满足,三个反编译引擎一个都没有,所有 agent 注册都是空。**

**好消息**:`analyze-javascript-application` 和 .NET 静态检查**不需要任何原生引擎**,只要 Node + npm。Java 20 已在(Android 路径可用)。也就是说**本机能立刻用起来的部分:JS/Electron 应用分析、.NET 程序集、包/资源清单**。

## 三种技术路线

| 路线 | 场景 | 需要什么 |
|---|---|---|
| **原生二进制** | macOS app / .so / .exe / dylib 反编译 | Hopper(**可付费**,商业软件)或 Ghidra(免费)或 IDA(付费) |
| **JS / Electron / .NET 静态** | 模块、imports、source map、IPC、CIL | **只要 Node** —— 零引擎依赖 |
| **运行时观测** | 进程行为、浏览器场景、网络抓包 | pwntools(ELF)/ mitmproxy(Linux) / Chrome 系浏览器 |

**最大的采用障碍:原生分析必须有 Hopper 或 Ghidra 或 IDA 三者之一。** Hopper 是商业付费软件(Ghidra/IDA 也有各自授权),这个前置条件会挡住大部分个人用户。**但 JS/Electron 这条路是零门槛的,而它恰好覆盖了大量真实需求**(打包后的 Electron 应用是近年逆向的主要对象)。

## 实战建议

**优先从零门槛路径开始**

```bash
# 不需要 Hopper/Ghidra/IDA,只要 Node
npx -y rea-agents@latest analyze-javascript-application /abs/path/to/app --json

# 环境自检(只读)
npx -y rea-agents@latest doctor --json
npx -y rea-agents@latest capabilities
npx -y rea-agents@latest providers
```

**clone 源码必须递归**

```bash
git clone --recursive https://github.com/morluto/rea.git
# 忘了 --recursive → third_party/ 全是空目录,Android/固件/JS 反混淆能力直接缺失
```

**skill 与 npm 包必须同步**

```bash
rea update                                    # npm 装的 CLI
npx rea-agents@latest setup                   # npx 用的,刷新 agent 注册 + skill
# 之后重启 agent
```

**别在每次调查前跑 setup**。skill 明确说:「If REA tools are available and their registration is not known to be stale, proceed directly to the target. Do not run diagnostics or setup before every investigation.」—— 这条本身也是对 agent 行为的约束,值得学。

**它的三个 showcase 是理解它能力的最佳材料**(都在官网 showcase 页):

| Showcase | 做了什么 | 验证强度 |
|---|---|---|
| **DX-Ball** | 从 sound 调用追到 position-to-pan helper,反编译,还原成 C | **通过 3,205 个原 x86 测试用例 + 复现全部 63 字节编译产物** |
| **TH04** | PC-98 子弹角度计算的 16 位逆向,还原 C++ | 与历史编译器输出逐字节对比 |
| **Notion** | Electron 剪贴板 bridge 追踪:renderer → preload → IPC → main | 追踪完整链路 |

**DX-Ball 那个「3,205 用例 + 63 字节全复现」是它最硬的一击** —— 不是「看起来对了」,而是**可执行的等价性证明**。这正是我们前面刚在 `mythicalManMonthVibeCoding` 里讨论的:AI 时代「已完成」不再可信,必须有可观测的真伪验证。REA 用 showcase 展示了它对这条要求的实践方式。

## 风险点

| 风险 | 说明 |
|---|---|
| **版本节奏失控** | ~2 天一版,一个月内 2.0→6.0。skill 与 npm 包不同步会拿到「描述了不存在功能的指令」 |
| **原生分析有商业前置** | Hopper/Ghidra/IDA 至少要一个,IPA 签名绕过、动态调试等深度功能另计 |
| **submodule 依赖 5 个外部仓** | clone 漏 `--recursive` 就静默缺能力;这 5 个仓本身的更新也会影响 REA |
| **本机 79 open issues** | 社区活跃但问题积压;README 自己都写「REA changes quickly, and new releases include frequent bug fixes」 |
| **技能描述 ≠ 实际能力** | skill 从 main 分支装,描述可能超前于 npm 包 —— 这个坑上面说了 |
| **法律边界** | README 有明确 Disclaimer:「You are responsible for obtaining any required authorization」—— 分析商业 App / 绕过授权均在法律灰区,商用前务必自行评估 |
| **20,918⭐ vs 4 月建仓** | 建仓仅 6 个月涨到 2 万星,增长曲线极陡。**热度过高时更要看 issue 区有没有系统性抱怨**,不能只看 star |

## 跟我们的关系

**1. 与 `ReArk` 是同类不同层 —— 而且高度互补**

iswiki 里已有 `developer-productivity/ReArk.md`(HarmonyOS + Android 桌面逆向与 AI 辅助分析工作台,本机 `.hermes` 相关工具链)。对比:

| | ReArk | REA |
|---|---|---|
| 定位 | **分析工作台**(看界面、静态分析、真机投屏) | **MCP 工具层**(喂给 agent 用的证据接口) |
| 目标 | Android 桌面应用 | 跨平台(原生/JS/Electron/.NET/固件/网页) |
| 输出 | 报告 / 投屏视图 | **Evidence ID + unknowns 台账** |

**→ ReArk 是「工作站」,REA 是「给 agent 的工具箱」。** 如果我们要做一个「agent 自动逆向」流程,REA 的证据模型(unknowns 台账)正是 ReArk 缺的 —— 后者输出报告,前者输出**可被 agent 持续追问的结构化状态**。

**2. `Evidence + unknowns` 模型可以直接移植到我们的 skill 体系**

这是本篇最大的一条可落地项。我们现有 skill(如 `hermes-gateway-ops`、`CnDemSkill`)都靠自然语言约定「必须核一手」,**但没有强制机制**。REA 的做法可以借鉴:

- 结论分三档:`observation`(工具直接返回) / `inference`(推断) / `unknown`(没查到)
- unknowns 必须**可查询、可更新、可验证是否已解决**(`list_unknowns` / `record_unknown` / `verify_unknown_resolution`)
- 「能力边界写进契约」:即使能观测到,也明确声明「不声称 X 不存在」

这三条能显著降低 agent「自信地编」的频率。

**3. 与 `img2threejs` / `remix-reference-video-prompt` 的对照**

这两篇笔记都是「AI 看图/看 prompt 生成代码」,**而 REA 补上了它们的缺失环节:输入是已发布的二进制/包,不是图片或文字**。`img2threejs` 的产物是可继续编辑的 TS;REA 的 DX-Ball showcase 走的是**反推 → 还原成 C → 逐字节验证** —— 后者对「还原度」的要求严格得多。

**4. 本机可立即尝试的最小实验**

Node 24 + Java 20 都在,JS/Electron 与 .NET 静态分析**零引擎依赖**。如果要试,拿一个解包后的 Electron 应用目录跑:

```bash
npx -y rea-agents@latest analyze-javascript-application /path/to/app --json
```

**这条不碰 Hopper/Ghidra,零授权风险**(分析自己解包的文件)。

**5. 但先说清楚:这不是「装个 MCP 就变强」的东西**

REA 的价值在于**它把「证据」做成了工具契约**。如果我们只是把它装上然后让 agent 自由调用,大概率得到的是又一轮「agent 说它分析了」。**要用出价值,必须同时接受它的约束** —— 每个结论挂 Evidence ID、显式记录 unknowns、按结论类型配证据类型。

## 参考链接

- 仓库: <https://github.com/morluto/rea>
- 官网 /  Guides  /  Showcases: <https://morluto.github.io/rea/>
- npm: <https://www.npmjs.com/package/rea-agents>(首版 2026-07-12,现 6.0.0)
- skill: <https://skills.sh/morluto/rea/reverse-engineer-anything>
- skill 源码(值得直接读): <https://github.com/morluto/rea/tree/main/skill-src/reverse-engineer-anything>
- MCP 工具契约(Evidence / progress / 能力边界): <https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md>
- CLI 命令冻结表: <https://github.com/morluto/rea/blob/main/src/cliCommandNames.ts>
- 架构图: <https://github.com/morluto/rea/blob/main/docs/architecture.mermaid>
- 安全策略: <https://github.com/morluto/rea/blob/main/SECURITY.md>
- iswiki 关联笔记:`developer-productivity/ReArk.md`(Android 逆向工作台)、`ai-vibecoding-agents/img2threejs.md`(AI 生成 Three.js 代码)、`ai-vibecoding-agents/mythicalManMonthVibeCoding.md`(AI 时代「已完成」不再可信 —— DX-Ball 的逐字节验证正是那条要求的实践)