# ThreeUI — Meng To 出品的 Three.js 3D UI / Shader / Hero 组件目录

> 学习笔记 · 调研时间 2026-09-02
> 仓库: https://github.com/MengTo/threeui · 官网: https://threeui.com · 文档: https://threeui.com/installation
> License: MIT（应用 + Community 组件 + 官方图）；字体 SIL OFL 1.1；Three.js runtime MIT
> 语言: TypeScript / TSX + HTML · ⭐ 4.9k · Fork 484（截至 2026-09-02）
> npm: `@designcodeio/threeui@1.2.0`（2026-09-01 发布，含 trusted publishing + provenance）
> 作者: Meng To（DesignCode 创始人），自动化同步靠 `github-actions[bot]`

## 一句话定位

ThreeUI 是 Meng To 团队把 **Three.js 3D 视觉效果**（Shader、Hero、背景、UI 元素、Landing Page、交互模板）封装成可浏览、可复制、可改的可视化组件目录；GitHub 上的 **Community 仓库只开源「社区版」**（去 Pro / 去 Beta，约 164 个可浏览结果），其余 Pro / Beta 内容需要订阅 + CLI 鉴权下载。

## 三种使用方式

| 方式 | 入口 | 适用场景 | 鉴权 / 限制 |
| --- | --- | --- | --- |
| **1. 浏览器 Browse + 复制源码** | https://threeui.com/browse（449 项结构化数据 + 浏览页） | 看效果、复制粘贴单组件 | 公开免费 |
| **2. npm React 包（Community 子集）** | `npm install @designcodeio/threeui`（v1.2.0，2026-09-01） | 把它当 React 组件库直接 import | 仅 Community 子集，无 Pro 实现 |
| **3. Pro CLI（OAuth + PKCE）** | `npx @designcodeio/threeui-cli add <component>` | Pro 订阅用户拿完整 Pro 源码，绑定账号 entitlement，每请求服务端校验 | 必须订阅 + 登录 |

**对照官网 vs 开源仓：** 官网目录 = 449 项全集（含 Pro / Beta），GitHub `threeui` 仓 = 50 父组件 / 111 路由 / 141 free variant + 23 singleton = **164** Community 浏览结果。社区仓通过自动化 workflow 每次主仓推送后过滤 Pro / Beta 再发布，且每次发布走 trusted publishing + provenance。

## 核心组件 / 模块 / 架构

```
┌────────────────────────────────────────────────────────────────────┐
│   threeui.com （官网 · 全部 449 项 · Pro / Beta / Community）       │
│      React + Vite + TS · 5 种 palette (mono/sepia/azure/moss/mauve)│
│      主题持久化: localStorage (threeui-theme / -palette-*)         │
└────────────────────────────┬───────────────────────────────────────┘
                             │ 自动化同步（私有 main-threeui 快照）
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│   github.com/MengTo/threeui  （Community 公开仓 · 164 项）          │
│                                                                    │
│   ├── src/                       Vite 应用源码（应用壳、shell、路由）│
│   ├── packages/cli/             Pro 鉴权 CLI（OAuth + PKCE）       │
│   ├── public/                   同步报告 + source-code.json        │
│   │   ├── community-sync-report.json   variant/control parity 审计│
│   │   └── source-code.json             Community 源码包          │
│   ├── scripts/                  同步 + 边界审计 + 包构建脚本       │
│   ├── assets/                   ThreeUI 官方图片资源                │
│   └── src/data/shaders.tsx      Community-only catalog 渲染入口   │
│                                                                    │
│   npm @designcodeio/threeui@1.2.0（Community 子集 · MIT）           │
│     → lib-dist/index.js + components/* 子路径 + assets/*          │
└────────────────────────────────────────────────────────────────────┘
```

### 仓库目录结构（开源仓实际文件）

| 路径 | 作用 |
| --- | --- |
| `.github/workflows/` | 自动化同步 + npm trusted publishing |
| `packages/cli/` | Pro 鉴权 CLI（OAuth + PKCE，refresh token 仅 owner） |
| `src/` | Vite 应用 + React 组件源代码 |
| `scripts/` | `sync-community-from-main.mjs`、`audit-public.mjs`、`generate-library-entry.mjs`、`package-install-smoke.mjs`、`copy-library-assets.mjs` |
| `public/source-code.json` | Community 组件源码（Code Tab 渲染用） |
| `public/community-sync-report.json` | 同步 parity 审计报告 |
| `src/data/shaders.tsx` | Community-only catalog 渲染入口 |
| `ASSET-LICENSES.md` / `FONT-LICENSES.md` / `THIRD_PARTY_NOTICES.md` | 第三方资源许可 |

### 449 项浏览结果按主题分布（官网结构化数据）

| 主题 | 数量（节选） |
| --- | --- |
| Landing Pages | 40+（Kage / Cadence / Kairo / RenderLab / Halvorsen / Anteroom …） |
| Hero Sections | 40+（Orrery / Cortexa / Cathode 4 子项 / Tidecrest / Sylva 4 子项 …） |
| Backgrounds | 60+（CRT 4 / Betawise Globe 5 / Tidecrest Terrain 4 / Nocturne 4 …） |
| 3D UI Elements | 40+（Hourglass Loader 4 / Halftone Keyboard 4 / Brand Orbs 17 …） |
| Motion Design | 16（React Orbits / Cathode Session / Emberline Signal …） |
| Text Animation / CSS | 含 Neon Sign、Article Headings、Performance Gauges 等 |

### 关键技术栈

- **React 18–19**（peer dep `>= 18 < 20`） + **TypeScript** + **Vite**
- **three.js peer dep `>= 0.149 < 1`**；`package.json` 内置 `three@0.128.0`（`three128` alias） + `three@0.165.0`（`three165` alias）作为已知 OK 锁定点
- **Trusted publishing + provenance**（npm `publishConfig.access=public, provenance=true`）
- **运行时校验**：typescheck → public boundary audit → vite build → build audit → lib build → tsc emit → asset copy，全套走 `npm run build`

## 安装与最小使用

### 方式 A：把官网仓库当学习案例本地跑

```bash
git clone https://github.com/MengTo/threeui.git
cd threeui
npm install
npm run dev        # Vite dev server
```

跑测试 + 类型 + 构建 + 公开边界审计 + 冒烟测试（发布前会跑全这一套）：

```bash
npm run build      # test + build:site + build:lib
```

### 方式 B：在自己的 React 项目里用 npm 包

```bash
npm install @designcodeio/threeui
```

```tsx
import { AtTheHorizon } from "@designcodeio/threeui";
import "@designcodeio/threeui/style.css";

export function Hero() {
  return <AtTheHorizon />;
}
```

最小导入图（只 import 单组件子路径）：

```tsx
import { AtTheHorizon } from "@designcodeio/threeui/components/AtTheHorizon";
```

**坑点：** 某些组件（渲完整 HTML 文档那种）依赖同源路径下的运行时文件（`assets/`）。要么把 `node_modules/@designcodeio/threeui/lib-dist/assets/` 拷到自己 public，要么给组件传 `sourceUrl` / `assetBaseUrl` prop 覆盖。

### 方式 C：Pro CLI（订阅用户）

```bash
npx @designcodeio/threeui-cli add cross-beam     # 加 Pro 组件到项目
npx @designcodeio/threeui-cli --help             # login/logout/destination/dev
```

CLI 行为：OAuth + PKCE 登录、refresh token 只 owner 可读、每次服务端请求校验 entitlement、不会覆盖未 commit 的项目文件（除非 `--force`）。

## 跟我们的关系（用户工作相关 — 必填段）

ThreeUI **跟用户当前工作几乎不直接相关**，但有几个间接场景值得标记：

| 场景 | 是否推荐 | 备注 |
| --- | --- | --- |
| **Hermes / mmx / 飞书 / MiniMax 等纯后端 / Agent 类项目** | ❌ 不相关 | 这是 Three.js 前端视觉层，跟我们的工具链不交叉 |
| **未来想做产品官网 / Landing Page（含 3D 动效）** | ⭕ 备选 | 如果哪天用户接产品官网 / SaaS Landing，ThreeUI 是高质量参考实现；尤其是 50 个 Community 父组件的源码可研究 |
| **Three.js 学习** | ⭕ 备选 | 仓库含完整应用壳 + Shader 实现，是 Three.js 高级案例库；但跟"私活"距离远 |
| **AI Coding Agent 喂 prompt 改组件** | ⭕ 思路可借 | 「组件 + 源码 + Prompt + Variant + 配置 = Agent-Native UI」这个组合形态，是 Hermes Agent 自身的 skill / 模块设计可借鉴的方向（**不要把 skill 复制成 UI 库**，但「让 AI 在高质量基础上改」这种理念跟现在 prompt + skill 的协作模式一致） |
| **macOS / Hermes desktop UI 加动效** | ❌ 不相关 | Electron 桌面端不需要 WebGL Shader；硬上只会徒增 bundle 体积 |

**结论：** 现在不需要装、不需要 clone、不需要学。**只在未来接到「产品官网」或「需要研究 Three.js 视觉层怎么封装」需求时再回头查本笔记**。本笔记以学习价值为主，**没有马上要落地的集成任务**。

## 实战建议 / 风险点

### ✅ 用前先看

- **React only（>= 18 < 20）**，Vue 项目用不了 npm 包，只能 fork 源码改
- **three.js peer dep `>= 0.149 < 1`**，项目锁了老版本就装不上
- **某些组件需同源 assets**，自己部署时记得拷 `lib-dist/assets/`
- **Pro 组件不发布到 npm**，需要订阅 + CLI 鉴权（OAuth + PKCE）；**「Community 版本」≠「免费用全部 Pro 效果」**，这是最容易踩的认知坑
- **449 项 ≠ 164 项**：官网目录是全集，GitHub Community 是子集，差异在 Pro / Beta 部分
- **依赖内嵌两版 three**：项目主动保留 `three@0.128.0` 和 `three@0.165.0` 别名（`three128` / `three165`），如果上游升 three，注意兼容窗口

### ⚠️ License 拆得细

| 资源 | License |
| --- | --- |
| 应用代码 + Community 组件代码 + ThreeUI 官方图 | **MIT** |
| 内嵌开源字体 | SIL OFL 1.1 |
| Three.js runtime | MIT |
| 官网远程缩略图 / 预览图 | **不重新分发**（只从 threeui.com 加载，不进 npm） |

→ 自部署时缩略图 / 预览图得自己抓或换源，**别假设 npm 包里有**。

### ⚠️ 商业 / 资助模型

ThreeUI 不是典型 OSS，靠赞助 + Pro 订阅活：

| Plan | 位置 |
| --- | --- |
| Ecosystem Sponsor $500/月 | GitHub README 顶部 banner |
| Featured Sponsor $1,500/月 | 加 ThreeUI 文档侧栏 banner |
| Ultimate Sponsor $3,000/月 | 上述 + 1 个 fixed-scope 集成项目 |

流量基线：~9 万 views / day（2026-08-26 自报数，**只是流量参考不是曝光承诺**）。这个数字说明：Meng To 把流量当生意，**项目主导权不会轻易变更**；**不用担心一夜之间被商业化绑架**。

### ⚠️ 版本节奏（npm）

```
0.3.0 → 2026-08-21  首次发布
1.0.0 → 2026-08-23  GA
1.1.0 → 2026-08-25
1.2.0 → 2026-09-01  ← latest
```

发布节奏 ≈ 1 周 1 个 minor；`automation/community-sync` workflow 推 PR → 人工 review → merge → trusted publishing。同步是 fail-closed，**no-op sync 不会发新版**。

## 配套生态 / Studio / CLI 辅助

- **`@designcodeio/threeui-cli`**（开源在 `packages/cli/`）：Pro 鉴权 + 加组件命令；OAuth + PKCE + 端侧 entitlement 校验
- **官网自动化同步**：私有 `main-threeui` 仓每次 push → 公开仓 PR → 审核 → merge → npm trusted publishing（带 provenance）
- **审计脚本**：`audit-public.mjs`（发布前边界审计）/ `audit-build.mjs`（构建产物审计）/ `package-install-smoke.mjs`（匿名装包冒烟）
- **不入仓的资源**：官网 449 项的缩略图 / 预览视频只放 `threeui.com` CDN，不打包进 npm

## 调研方法备注

- 远端 `npm view @designcodeio/threeui` 时间戳 = 2026-09-01 04:18 UTC（**比 README star 数（4.9k, 484 forks）更新**）
- 公众号「前端Hardy」发布时间 2026-09-02 07:30；公众号文章与 GitHub README 在组件数量（**公众号文里写 164 项 ↔ README 也是 164 项**）完全对得上，**公众号内容可信度高**
- 官网首页 structured-data `numberOfItems = 449`（含 Pro + Beta），与 GitHub README 「Community 50 父组件 / 111 路由 / 141 variant / 23 singleton = 164」一致

## 参考链接

- 官网：https://threeui.com
- 官网 browse（449 项）：https://threeui.com/browse
- 安装文档：https://threeui.com/installation
- MCP 文档：https://threeui.com/mcp
- 定价：https://threeui.com/pricing
- 赞助：https://threeui.com/sponsorship
- GitHub 仓：https://github.com/MengTo/threeui
- 仓库 README（raw）：https://raw.githubusercontent.com/MengTo/threeui/main/README.md
- npm 包：https://www.npmjs.com/package/@designcodeio/threeui
- 公众号文章（前端Hardy）：https://mp.weixin.qq.com/s/yezL84pQ2Ww4tUEn7opm8A
- 作者：Meng To · https://designcode.io