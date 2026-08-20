# kage — Kyoto 夜间寺庙交互式 Three.js 体验

> 学习笔记 · 调研时间 2026-08-20
> 仓库: <https://github.com/MengTo/kage>
> 在线体验: <https://mengto.github.io/kage/>
> 作者: MengTo (Twitter: <https://x.com/MengTo/status/2086023649526452265>)
> ⭐ 1,250 · 230 forks · 1 issue · 23.7 MB repo · HTML · Created 2026-08-08 (10 天前)
> License: **未声明** (third-party Three.js 是 MIT)

## 一句话定位

**"5 章 Kyoto 山寺夜游,Three.js 实时渲染 + cinematic generated imagery 合成"** —— MengTo 写的一个**单文件 HTML** 交互式 editorial art book。一个 HTML 文件 = 整个站点,scroll 驱动相机穿越虚构京都山寺(门 / 灯笼 / 月 / 雾 / 雨 / 落叶 / 鸟居 / 楼梯 / 神道),配 4 张 GPT Image 2 生成的场景图 + 10 张 alpha-preserving WebP 前景元素。

## 跟 iswiki 现有工具的关系

| 工具 | 关系 |
|---|---|
| [mattpocock-skills](mattpocock-skills.md) | 🟢 同为 "single-file" 美学 (本仓库是 HTML + Three.js 单文件)|
| [i-have-adhd](i-have-adhd.md) | ⚪ 输出风格,无关 |
| [codex-security](codex-security.md) | ⚪ 安全 |
| [mapcn](mapcn.md) | ⚪ 地图组件 |
| [StadiView](StadiView.md) | 🟢 都是 Three.js / 3D 可视化 |

## 5 章节 + 实时 3D 路径

| 章节 | 内容 | Three.js 元素 |
|---|---|---|
| **1. Approach** (Hero) | 抵达,远处寺庙轮廓 | 远景寺庙 silhouette + 雾 + 鸟居 + 朱红月 |
| **2. Sanmon** (山门) | 进入山门 | 寺院正面 + 灯笼 + 灯笼光暖光 |
| **3. Lantern Court** (灯笼庭) | 灯笼庭院 | 灯笼群 + 灯笼光池 + 漂浮萤火 |
| **4. Moonwater** (水月) | 月光水边 | 水面反射 + 月 + 落叶 + 雨 |
| **5. Afterlight** (余光) | 余韵 | 暖色褪去 + 雾 + 镜头淡出 |

**镜头驱动**: 单条 continuous 相机路径,scroll 控制位置

## 文件结构 (1 个 HTML 文件 + assets)

```
kage/                              # 23.7 MB
├── index.html                     # 244 KB - 完整站点(包含所有 CSS + JS + 场景构建)
├── PROMPT.md                      # 2.6 KB - AI 重建 prompt (可 fork/remix 用)
├── README.md                      # 3.9 KB
├── .gitignore + .nojekyll         # GitHub Pages 配置
├── assets/
│   └── kage-preview.webp          # 101 KB - preview image
└── secret-pathways-assets/        # vendor 资源
    ├── fonts.css                  # 99 KB - 字体定义
    ├── three.min.js               # 608 KB - Three.js r149 (vendored MIT)
    ├── generated/                 # 4 张 cinematic 场景图 (~180 KB each)
    │   ├── kage-approach.webp     # 176 KB
    │   ├── kage-lantern-court.webp
    │   ├── kage-moonwater.webp
    │   └── kage-sanmon-preview.webp
    └── foreground/png/            # 10 张 alpha-preserving WebP cutouts
        ├── basalt-stones.webp     # 164 KB
        ├── garden-bush.webp
        ├── hill.webp
        ├── maple-leaves.webp
        ├── pine-tree.webp
        └── ... (5 more)
```

## 4 个核心特性

### 1. 实时 Three.js 场景(过程化生成)

`index.html` 在运行时构造:
- 🏯 寺庙 / 鸟居 / 楼梯 / 灯笼 / 月 / 地形 / 树 / 雾 / 雨 / 落叶 / 萤火
- 🎨 Restrained bloom + 颗粒 + 暗角 + 深度雾
- 🌡️ 暖色 shoji 光 + 冷色月光 + 朱红月
- 🎨 调色板:近黑 + 蓝炭 + 暖琥珀 + 骨白 + 朱红

### 2. 编辑性排版 (Editorial Typography)

- **Hero**:超大左对齐英文标题
- **垂直日语 display type**(large vertical Japanese)
- **小技术 label** + chapter 编号 + 细分割线
- **Generous negative space**

### 3. Scroll-driven camera path

- **单条 continuous camera path**(1 个相机跑完整旅程)
- **每个 section 感觉像新合成 shot**(不是硬切)
- **Eased interpolation**(慢、精确、subtle parallax)

### 4. Cinematic layered collage

- **Generated scenes**(4 张 WebP 场景图)+ **alpha-preserving WebP cutouts**(10 张前景) + **live 3D** = collage-like 深度
- **Foreground layers**:section 激活时全不透明,期间 fixed,handoff 时 fade + blur
- **Play icon**:居中在图片框内,不在 caption 区

## 5 大交互设计

| 特性 | 实现 |
|---|---|
| **Chapter navigation** | 全场景导航 |
| **Responsive mobile** | ~390×844 适配 |
| **Reduced-motion** | 保留完整阅读体验 |
| **Custom cursor** | 仅 fine pointer devices |
| **Working anchor nav** | 锚点链接 |

## 4 大原则 (README 明确)

1. **Use Three.js as fixed full-viewport environmental layer**(不是 product landing page)
2. **Drive one continuous camera path from page scroll**
3. **Layer editorial typography + generated scenes + alpha-preserving WebP foreground**
4. **No build step, no framework, no analytics, no remote fonts**

## 设计哲学 (README 引述)

> "Kage is an original, independent design study inspired by Japanese temple architecture and night gardens. **It is not affiliated with a specific temple, cultural institution, or tourism organization.**"

> "The cinematic scene plates and foreground artwork were generated for this project using **GPT Image 2**, then art-directed and composed with the live Three.js scene."

> "**No license is currently granted** for reuse or redistribution of the original Kage code or artwork."

→ **半开放**:代码可读,可学习,PROMPT.md 可 fork-remix,**但 commercial reuse 需联系作者**。

## 本地运行 (静态服务)

```bash
cd kage
python3 -m http.server 4173 --bind 127.0.0.1
# Visit http://127.0.0.1:4173/
```

**零依赖**:无 build step、无 env、无 analytics、无运行时网络

## 与 MengTo 其他作品的关系 (同设计语言)

| 项目 | 主题 | 链接 |
|---|---|---|
| **Kage** | Kyoto 山寺夜游 | <https://mengto.github.io/kage/> |
| **Complete Shelf** | 7 本可交互 hardcovers | <https://mengto.github.io/complete-shelf/> |
| **Sketchbook** | Singapore 翻页 sketchbook + magnifier | <https://mengto.com> |
| **Agent Skills** | Reusable skill library(被 Kage 引用) | <https://github.com/MengTo/Skills> |

→ **MengTo 的 "single-file experiment" 哲学**: 1 个 HTML = 1 个完整作品。

## 与 PROMPT.md 的关系 (重要!)

`PROMPT.md` (2.6 KB) **是一个"AI 重建 prompt"**:
- 描述场景结构
- 描述 layout 系统
- 描述 motion language
- 描述 quality constraints
- **可以让任何 AI agent 重建/重新诠释这个体验**

→ Kage 是 **"可重新诠释的体验"(reinterpretable experience)**,**不是唯一艺术品**。

## 技术栈细节

| 层 | 选型 |
|---|---|
| 渲染 | **Three.js r149** (vendored, no npm) |
| 文件 | **1 个 HTML** + assets(无 build) |
| 服务 | 任意 (`python -m http.server` 就够) |
| 网络 | **完全静态**(无 CDN、无 fonts、无 analytics) |
| Generated imagery | **GPT Image 2** (4 张 cinematic scenes) |
| Foreground cutouts | **alpha-preserving WebP** (10 张) |
| Custom cursor | JS only |
| Reduced-motion | JS query `@media (prefers-reduced-motion)` |

## 性能 / 体积

| 维度 | 数据 |
|---|---|
| index.html | 244 KB |
| Three.js | 608 KB |
| Generated scenes (4) | ~650 KB total |
| Foreground (10) | ~1.5 MB total |
| fonts.css | 99 KB |
| **Total repo** | **23.7 MB** (含 LFS / untracked) |
| **Initial load** | 估计 ~2-3 MB(gzip 后) |

→ **单页面一次性加载,无 lazy / no streaming**。**fashion 单文件艺术作品**,不追求 100/100 Lighthouse。

## vs 现代 Web 模式

| 维度 | Kage | 现代 "best practice" |
|---|---|---|
| 渲染 | Three.js r149 (1 年前 stable) | Latest r170 |
| Bundler | 无 | Vite/Turbopack |
| TypeScript | 无 | TS everywhere |
| Testing | 无 | Playwright/Vitest |
| Performance budget | 无 | LCP < 2.5s |
| Image format | WebP | AVIF/WebP responsive |
| Build step | 无 | Modern minify |

→ **Kage 反潮流** —— 它**故意不用**现代 web 工具链,**为了一个 editorial 艺术效果**。

## 适用 / 不适用

| ✅ 适合学习 | ❌ 不适合生产 |
|---|---|
| Three.js 场景构造 | 企业级 web app |
| Scroll-driven camera | SEO 要求 |
| Editorial typography | 多页面 |
| Single-file art | 团队协作 |
| Procedural generation | 性能关键场景 |
| AI-generated imagery + 3D composition | 移动网络差 |

## 风险与限制

- **未声明 license** —商业用途需询问作者
- **vendored Three.js r149** — 老版本(2023),可能有 newer GL features 缺失
- **No build optimization** — 文件大,无 tree-shaking
- **No accessibility audit** — README 说 reduced-motion + 语义 markup,但没 WCAG 检查
- **No cross-browser testing** — README 提 desktop + mobile,~390×844
- **Single-page hot reload 困难** — 必须重启 `python -m http.server`
- **GPT Image 2 生成 scenes** — 受 OpenAI ToS 约束 (无法独立 redistribute)

## 设计灵感来源

- **京都清水寺 / 鹿苑 / 高山寺 / 银阁寺** (作者研究)
- **茶道 / 怀石料理** 视觉美学
- **Apple Pro Display XDR product page** (单页 editorial art book 模式)
- **Stripe Sessions** (editorial typography)
- **The Browser Company** (1 file = full app)

## 跟 Hermes / iswiki 的关联

- **iswiki 索引化**:本仓库的"代码可读 + 不开源 reuse"哲学跟 iswiki "research notes"哲学相容
- **Kage 是 MengTo 风格**: 跟 [mattpocock-skills](mattpocock-skills.md) 的 "small, easy to adapt, composable" 哲学类似,但 MengTo 是美学派,mattpocock 是工程派

## 类似 Three.js 单文件项目对比

| 项目 | 作者 | 主题 | LOC | ⭐ |
|---|---|---|---|---|
| **Kage** | MengTo | Kyoto 山寺夜游 | 1 HTML + Three.js | 1.25k |
| [Three.js examples](https://threejs.org/examples/) | Three.js team | 通用 demo 集 | 各异 | - |
| [Shadertoy](https://www.shadertoy.com/) | community | WebGL shader | GLSL only | - |
| [100 Stunning WebGL Demos](https://100.stunningwebswebgl.com) | various | showcase | | - |

## 关联资料

- 仓库: <https://github.com/MengTo/kage>
- 在线体验: <https://mengto.github.io/kage/>
- PROMPT.md: <https://github.com/MengTo/kage/blob/main/PROMPT.md>
- 作者 Twitter: <https://x.com/MengTo/status/2086023649526452265>
- 作者其他作品:
  - <https://mengto.github.io/complete-shelf/>
  - <https://mengto.com>
  - <https://github.com/MengTo/Skills>
- 本地运行: `python3 -m http.server 4173`