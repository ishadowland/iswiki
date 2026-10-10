# Anime.js — 一个动画引擎覆盖 DOM / SVG / JS 对象 / Three.js

> 学习笔记 · 调研时间 2026-10-10 · 来源文章 2026-09-17
> 仓库: https://github.com/juliangarnier/anime · 官网: https://animejs.com · 文档: https://animejs.com/documentation
> License: MIT · 主语言: JavaScript(ESM-first) · ⭐ 73.4k · 5k forks · 907 commits · v4.5.0
> 39 tags · 19 branches · 102 open issues · 21 open PRs · 最近 commit 2 个月前
> **npm 下载量**(2026-09-09 → 2026-10-08): **4,999,623 次/月 ≈ 500 万 DL/月** · 全年 ~3,650 万
> 调研来源: 公众号「前端之神」《Github 70k Star 爆火动画库!几行代码实现复杂3D动画!》(已用远端 README / package.json / GitHub 主页 / npm registry / HN Show 核验,数据校正见 §9,多源报告见 [assets/animeJs/sources-report.md](assets/animeJs/sources-report.md))
> **类别**: web-frontend-ui · 动画引擎 · GSAP 替代 · Three.js 适配

## 0.5 配图速览

本笔记无样例图(animejs 官方未在仓库 `assets/` 暴露高质量静态配图,且 iswiki CONTRIBUTING §4 禁止自造图)。**研究档案副产物**:[assets/animeJs/sources-report.md](assets/animeJs/sources-report.md)(5 源 + 失败项说明,7.3KB),支撑 §2 核心数据表的「npm 下载量」字段与 §9 数据校正段的 HN 973 分独立验证。

## TL;DR

Anime.js 是 juliangarnier/anime 维护的 JavaScript 动画引擎,v4(ESM-first + 完整子模块化)用一个统一 `animate()` API 同时驱动 CSS 属性、SVG、JS 对象、Three.js 物体。包体积小（UMD bundle 走 CDN 约 17KB,源文估算）、零运行时依赖、MIT 商用免费,主打"中小项目够用、不想引入 GSAP 那套付费/学习成本"的场景。**对 sanfine.art 的实际意义**:首页动效、卡片入场、商品 hover、作品集滚动驱动这类需求,Anime.js 比 GSAP 更轻、上手成本更低;若 3D 区块要复用 Three.js,直接 `animejs/adapters/three` 子路径即可,无需另起一套。

## 1. 一句话定位

一个用一套 `animate(targets, props)` API 覆盖 **CSS / SVG / DOM 属性 / JS 对象 / Three.js 物体** 的动画引擎,核心目标是"少代码、可读、易组合"。

## 2. 核心数据

| 维度 | 值 | 信源 |
|---|---|---|
| 仓库 | juliangarnier/anime | GitHub 主页 |
| Stars | **73.4k**(本 session 实测 2026-10-10) | GitHub 主页 |
| Forks | 5k | GitHub 主页 |
| 最新版本 | v4.5.0(2026-06 发布,4 个月前) | package.json |
| License | MIT | package.json |
| 主入口(ESM) | `dist/modules/index.js` | package.json `exports["."]` |
| 主入口(UMD/CDN) | `dist/bundles/anime.umd.min.js` | package.json `jsdelivr` / `unpkg` |
| 包体积 | 约 17KB(压缩后 UMD bundle,源文估算,无官方声明) | 源文 + CDN 推断 |
| 运行依赖 | **零** | package.json 无 `dependencies` |
| 选填 peer | `three >=0.150.0`(走 `animejs/adapters/three`) | package.json peerDependencies |
| 子路径模块 | 21 个独立子路径:`animation / timeline / animatable / draggable / scope / engine / events / layout / easings(含 linear/steps/irregular/cubic-bezier/spring 5 个子模块) / utils / svg / text / waapi / adapters(含 three)` | package.json `exports` |
| 类型 | `"module"`(ESM-first) + 同时提供 CJS | package.json `type` |
| Commits / Branches / Tags | 907 / 19 / 39 | GitHub 主页 |
| Open issues / PRs | 102 / 21 | GitHub 主页 |
| 最近代码提交 | 2 个月前(README 更新) | GitHub 主页 |
| README 自描述 | "fast, multipurpose and lightweight JavaScript animation library with a simple, yet powerful API" | 仓库 README |

## 3. 它要解决的具体问题

源文列的 4 类痛点(我做了对照翻译,去掉"难用"这种主观词):

| 传统方案 | 真实痛点 | Anime.js 的解法 |
|---|---|---|
| **CSS 动画** | 多元素错开 + 多段衔接时,时间轴难以维护;时长/延迟/缓动曲线写死后改起来散在各处;SVG 路径、形变、沿路径动效需要 `@keyframes` + path `stroke-dasharray` 手动调 | 一个 `animate()` 调用覆盖 CSS 属性 + SVG 属性 + DOM 属性;`stagger()` 一行批量错开;`timeline()` 串多段 |
| **原生 requestAnimationFrame** | 时间、缓动、错开都自己写;多动画同步要手写调度;SVG 工具没有 | 引擎内置时间系统、缓动函数库(eases / steps / cubic-bezier / spring / irregular)、SVG 子模块 |
| **GSAP** | 功能完整但包大;SVG Morph/DrawSVG 等插件**仍在付费墙**;API 体系复杂,新手学习曲线陡 | 17KB 左右(UMD);MIT 全免费;核心 API 就 3 个:`animate / timeline / stagger` |
| **Framer Motion** | React 专属(45KB),非 React 项目用不上 | 框架无关,原生 JS / Vue / Svelte / Astro 都能直接 import |

源文对比表(我做了去营销改写):

```
对比项      Anime.js              GSAP                 Framer Motion         CSS Animation
体积        17KB 无依赖            40KB+ 含插件          45KB(React 专属)      零
商用授权    MIT 全免费              核心免费 / 插件付费    MIT                   无限制
SVG 能力    原生形变/路径           核心免费 / 多数付费    基础                  复杂
多目标交错  内置 stagger           支持(写法繁琐)       支持                  手写循环
时间轴      轻量灵活                功能最强              组件化                无原生
3D/Three    原生适配(子模块)       需额外封装              不支持                不支持
上手难度    低                      偏高                  React 友好            简单但复杂难
适用场景    官网/H5/可视化/SVG图标  大型交互/商业项目    React 组件动效         简单 hover/过渡
```

> 校准:GSAP 商用行源文写"商用付费"略过时 —— 2024 年起 GSAP 核心包彻底 MIT,但 **MorphSVG / ScrollSmoother / SplitText / DrawSVG 等仍是 Club GreenSock 付费插件**;记笔记时按"核心免费 / 高阶插件付费"表述更准确。

## 4. 核心设计约束 / 技术原理

### 4.1 架构层次(从源码 package.json `exports` 反推)

```
animejs@4.5.0
├── core (./dist/modules/index.js, ESM-first)
│   ├── animation      ← 单段动画驱动器
│   ├── timeline       ← 多段编排
│   ├── animatable     ← 可动画 JS 对象(无 DOM)
│   ├── stagger        ← 批量错开函数
│   ├── scope          ← 局部作用域(避免全局污染)
│   ├── engine         ← 时间引擎(raf / delta / fps)
│   ├── events         ← 动画生命周期回调
│   └── draggable      ← 拖拽交互
│
├── adapters/          ← 跨框架 target 适配器
│   └── three          ← Three.js Object3D 适配(选填 peer)
│
├── easings/           ← 缓动函数库
│   ├── eases          ← 命名缓动(inOutQuint 等)
│   ├── linear / steps
│   ├── cubic-bezier   ← 自定义 cubic-bezier()
│   ├── spring         ← 弹簧物理
│   └── irregular      ← 不规则多段
│
├── svg                ← SVG 属性 / 路径 / 形变
├── text               ← splitText(文字拆分后逐字动画)
├── waapi              ← Web Animations API 桥(浏览器原生加速)
├── layout             ← FLIP 布局动画
└── utils              ← 内部工具
```

**关键设计原则**:**ESM tree-shakable**。每个功能是独立子路径,构建工具(rollup/vite/webpack)会自动按需摇树,只把用到的子模块打进 bundle。这是 v3(CSM 不分块全量打包)→ v4(模块化)最重要的架构升级。

### 4.2 统一的 `animate(targets, props)` API

```js
// targets 可以是 5 种类型,API 完全一致
animate('.box',        { x: 200, rotate: 360, scale: 1.2 })        // CSS selector
animate(domNode,       { x: 200 })                                  // DOM 节点
animate(svgEl,         { strokeDashoffset: [anime.setDashoffset, 0] }) // SVG 属性
animate({ count: 0 },  { count: 100, onUpdate: () => ... })          // JS 对象
animate(threeMesh,      { x: 200, rotateY: 360 })                    // Three.js Object3D
```

**这一条统一性就是它的核心竞争力**:同样语法、同样 `stagger()`、同样 `timeline()`,换 target 类型就行。v3 时代目标是 CSS + DOM + JS 对象,v4 通过 `adapters/three` 扩展到 Three.js,后续可能扩 R3F / PixiJS。

### 4.3 Stagger 系统 — 批量错开的"一行 API"

源文示例:

```js
animate('.list li', {
  opacity: [0, 1],       // 数组语法 = 关键帧 [from, to]
  translateY: [30, 0],
  delay: stagger(100),   // 每个元素延后 100ms
  duration: 600
})
```

进阶用法(README 演示):

```js
stagger(65, { from: 'center' })   // 从中心向外扩散
stagger(100, { grid: [10, 10], from: [0, 5] })  // 二维网格
```

**工程意义**:不用循环写 `delay: i * 100`,引擎内部按 DOM 顺序或网格坐标算偏移;长列表(20+ 项)性能比手写循环更好,引擎是 batch 处理的。

### 4.4 Timeline — 多段动画编排

源文示例:

```js
const tl = timeline({ autoplay: false })  // autoplay: false = 先构造后播放
tl.add({ targets: '.box', x: 150 })        // 顺序追加
  .add({ targets: '.box', rotate: 180 }, '-=300')  // 偏移定位(从上一段结束前 300ms 开始)
  .add({ targets: '.box', opacity: 0 })

tl.play()      // 播放
tl.pause()     // 暂停
tl.reverse()   // 倒放
```

**偏移语法**: `-=300` = 上一段结束前 300ms;`+=200` = 上一段结束后 200ms;`'<100'` = 整个时间轴的 100ms 位置。**这与 GSAP position parameter 一脉相承**,熟悉 GSAP 的迁移成本几乎为零。

### 4.5 SVG 原生能力(源文重点吹,但实际要看子模块)

`animejs/svg` 子模块直接覆盖:

| 操作 | API |
|---|---|
| 路径描边 | `strokeDashoffset: [anime.setDashoffset, 0]` |
| 沿路径运动 | `motionPath: 'M10,50 L90,50'` |
| 图形形变 | SVG `<path d>` 字符串插值 |
| 路径 morph | `morphTo: targets` |

**校准**:源文说"SVG 原生能力强,不用再装插件",对 v4 是对的(v3 时期还要装 animejs 的 svg 模块)。但 GSAP 同类能力(MorphSVG / DrawSVG)**2024 年起部分仍要 Club 付费插件**,所以"vs GSAP 不用装付费插件"这条 Anime.js 仍有优势。

### 4.6 性能路径(源文说"自动适配硬件加速",需校准)

源文表述:**"兼容 Web Animations API,底层自动适配浏览器性能,支持硬件加速,低配置手机也更容易保持 60 帧"**。

**实际真相**(从 package.json `exports` 看):
- WAAPI 在 Anime.js 里是**独立的 `animejs/waapi` 子路径**,**不是自动底层**
- 想用 WAAPI 必须显式 import,默认还是走引擎的 raf 循环
- 硬件加速主要靠 CSS `transform` / `opacity` 属性(浏览器自动 GPU 合成),与 WAAPI 是两回事

**这算源文的一处小吹**:把"显式可选的子模块"说成"自动适配",技术表述不严谨。

## 5. 与同类对比

按本仓已有笔记和调研范围,放三个对照:

### 5.1 vs GSAP(本仓 `stadiView` / `shinjukuIndoorThreejsDemo` 已用 GSAP)

| 维度 | Anime.js v4 | GSAP |
|---|---|---|
| 包体积 | 约 17KB UMD | 40KB+ 核心 + 插件 |
| License | MIT(全免费) | 核心 MIT / 高阶插件付费 |
| 上手成本 | 低(3 个核心 API) | 中高(position parameter 学习曲线) |
| ScrollTrigger | 内置(自己包) | 一流(GSAP 官方,生态最丰富) |
| Three.js 适配 | 内置(`adapters/three` 子路径) | 需自己包或第三方 |
| SplitText | 内置(`animejs/text`) | Club 付费 |
| SVG morph | 内置(`animejs/svg`) | Club 付费 |
| 社区体量 | 73.4k stars | 24k star 远低于 Anime.js(我核了 GSAP 的 star,Anime.js 在动画库分类里**实际比 GSAP 更高**) |

> 校正:**源文说 GSAP "商用付费"**,2024 年起 GSAP 核心彻底免费,只是 MorphSVG / ScrollSmoother / SplitText / DrawSVG / GSDevTools 等高阶插件仍 Club GreenSock 付费。**Anime.js 全免费这条仍然成立**,但"GSAP 完全付费"这个说法过时了。

### 5.2 vs Framer Motion

| 维度 | Anime.js | Framer Motion |
|---|---|---|
| 框架 | 无关(原生 JS/Vue/Svelte/Astro 都能用) | React 专属 |
| 包体积 | 约 17KB | 45KB |
| 物理弹簧 | 内置(`easings/spring`) | 内置(spring 物理引擎更强) |
| 布局动画 | 内置(`animejs/layout`,FLIP 思路) | 内置(`layout` prop) |
| 手势 | 内置(`draggable`) | 内置(`drag` + `pan` + `tap`) |
| 学习曲线 | 低 | 中(需要理解 Motion 包装组件) |

**适用场景分界**:项目是 React 主导 + 重视手势和组件级动效 → Framer Motion;项目是多框架 + DOM/SVG/Three 都要动 → Anime.js。

### 5.3 vs CSS Animation(本应是默认选项)

| 维度 | Anime.js | CSS Animation |
|---|---|---|
| 浏览器兼容 | 现代浏览器(IE 不支持) | 全兼容 |
| 动态改属性 | 运行时任意改 | 写死后难改 |
| 多段编排 | timeline 一行 | 拼接 keyframes 难管 |
| 路径动效 | 内置 | 手写 path `stroke-dasharray` |
| 性能 | raf 循环 + 可选 WAAPI | 浏览器原生合成(GPU) |
| 包体积 | +17KB | 零 |

**结论**:简单 hover/过渡用 CSS,一旦要"批量错开 + 多段拼接 + 动态属性 + SVG 路径",Anime.js 性价比更高。

## 6. 安装 / 兼容性

### 6.1 三种安装方式

```html
<!-- 1. CDN(UMD) -->
<script src="https://cdn.jsdelivr.net/npm/animejs@4/lib/anime.min.js"></script>
```

```bash
# 2. npm
npm i animejs
```

```js
// 3. 框架 import(走 ESM 子路径)
import { animate, timeline, stagger } from 'animejs'

// 按需子路径
import { animate } from 'animejs/animation'
import { stagger } from 'animejs'           // stagger 是 core
import { svg } from 'animejs/svg'           // svg 子模块
import { waapi } from 'animejs/waapi'       // WAAPI 桥
import { animate } from 'animejs/adapters/three'  // Three.js 适配
```

### 6.2 Three.js 适配要求

```js
// 必须显式装 three
npm i three
// peer 要求 three >= 0.150.0(实测 dev 依赖 0.184.0)
```

### 6.3 浏览器兼容

- v4 全面使用 ES2017+ 语法(可选链 / async / Proxy),**IE 不支持**
- WAAPI 子模块要求支持 Web Animations API 的浏览器(Chrome / Firefox / Edge 全支持,IE 11 不支持)
- **不要为了兼容老旧浏览器强行上 Anime.js v4**,GSAP 兼容性更稳

### 6.4 与本仓其它笔记的关联

| 笔记 | 与 Anime.js 的接触点 |
|---|---|
| [stadiView](stadiView.md) | 用 GSAP + Three.js 做座位飞入动效。Anime.js `adapters/three` 子模块可以做类似效果,代码量可能更短;若重写,可用 Anime.js 替代 GSAP |
| [shinjukuIndoorThreejsDemo](shinjukuIndoorThreejsDemo.md) | 用 GSAP + Three.js 做流光行人效果。同样适用 Anime.js `adapters/three` |
| [humanAtlas](humanAtlas.md) | React + Three.js + BodyParts3D 模型爆炸效果。Framer Motion 更合适(React 专属),Anime.js 也行(需手动桥接 React lifecycle) |
| [scDatav](scDatav.md) | Three.js + React 19 数据可视化。同上,Framer Motion > Anime.js |
| [odometer](odometer.md) | HubSpot 翻牌数字库(< 3KB)。**极端轻量场景不需要换 Anime.js**,Anime.js 是动画引擎不是数字组件 |
| [mapcn](mapcn.md) / [mediaPipeTasksVision](mediaPipeTasksVision.md) / [kage](kage.md) | UI/3D 类,可能用到 scroll-driven 动效,Anime.js 内置 timeline 可覆盖 |

## 7. 实际使用 12 步工作流(sanfine.art 落地参考)

按本仓 `ipAsLogoSkill` / `semantica` 的工作流风格拆解:

```
[阶段 1: 环境决策]
  1. 框架判断     →  React/Next 为主?Framer Motion 更合适
                   →  Vue/Astro/原生 JS/Three.js?Anime.js 更合适
  2. 包决定        →  npm i animejs(优先 ESM import)
                    →  CDN UMD(纯静态站 < 17KB,可接受)
  3. 子模块清单    →  需要 SVG 动效? → 加 import svg
                    →  需要 Three.js? → npm i three + adapters/three
                    →  需要物理弹簧? → 加 import spring

[阶段 2: 动效设计]
  4. 列清单       →  首页 hero 入场 / 卡片 stagger / 数字滚动 / hover 微交互
                   →  按 6.4 关联表对照已有笔记
  5. 选 API       →  单元素 / 一次性 → animate()
                    →  列表批量入场 → animate(targets, { delay: stagger() })
                    →  多段编排    → timeline().add().add().play()
                    →  滚动驱动    → onScroll 钩子 + engine.time

[阶段 3: 落地实现]
  6. 入口处决定    →  'use client'(Next App Router)/ onMounted(Vue)/ DOMContentLoaded(原生)
  7. 性能预算      →  ≤ 50 个动画并行(超过考虑 stagger 分批)
                    →  transform / opacity 优先(GPU 合成)
                    →  长列表用 virtualScroll + 局部 stagger
  8. Scope        →  import { scope } from 'animejs'
                    →  scope.add(self => { animate(...) }).revert()
                    →  路由切换时 revert,避免内存泄漏
  9. SSR 兜底     →  Next: 'use client' 包裹
                    →  Astro: client:load 标记
                    →  Vue: onMounted 内调用

[阶段 4: 测试 + 优化]
  10. 兼容性      →  Safari 4+
                   →  移动端 ≤ 360px viewport 测试(Anime.js 适配良好但要实测)
                   →  prefers-reduced-motion 检查 → reduce 时禁用非必要动效
  11. 性能监控     →  Chrome DevTools Performance 面板看 raf 占用
                   →  engine.fps 检测降帧时降级
  12. 打包验证      →  rollup-plugin-visualizer 看 animejs 是否进 chunk
                   →  走子路径 import,确保 tree-shaking 生效
```

## 8. 跟我们的关系(sanfine.art 视角)

### 8.1 可借鉴到 sanfine.art 的点

1. **首页 hero 入场** —— 标题 / 副标题 / CTA 按钮三个元素 `stagger(100, { from: 'center' })`,可读性高,比 GSAP 短
3. **作品集卡片入场** —— 滚动到视口时 `delay: stagger(60)` 批量进场
4. **数字滚动(销售/版数/藏家数)** —— `animate({ count: 0 }, { count: 1200, onUpdate: ... })`,代码量比 odometer 还少(但 odometer 翻牌式更细腻,看设计需求)
5. **SVG logo 描边动效** —— `anime.setDashoffset` 一行,登录页/品牌页可用
6. **Three.js 3D 区块动效** —— 如果未来加 3D 作品预览,`adapters/three` 子模块天然适配,无需再装 GSAP + 第三方桥接

### 8.2 别学的点

1. **不要为了"用 Anime.js"放弃 CSS** —— 简单 hover / 过渡 / `@keyframes` 已经能搞定的事,别 +17KB
2. **不要在 React 项目里强用 Anime.js** —— Framer Motion 是 React 生态更深的解,组件级动效更自然
3. **不要在 SSR 主导的项目里默认导入** —— Next App Router / Astro 必须 `'use client'` 或 `client:load` 标记,否则 SSR 报错
4. **不要为了"三个核心 API"放弃排错空间** —— 简单 API 的代价是底层报错信息不够友好,debug 时记得开 `engine.debug` 或看 GitHub Issues

### 8.3 已知坑

- **WAAPI 不是默认底层**:源文"自动适配"表述不严谨,WAAPI 是显式子路径 `animejs/waapi`,需要手动 import
- **17KB 不是 git 仓库可见数字**:源文给的是 UMD bundle 估算,无 README / dist 文档佐证;实际打包后 gzip 后可能 ~6-8KB(UMD 17KB 是 minified 未 gzip)
- **三框架 React 适配弱**:Anime.js 没有官方 React adapter,需要自己包 hook / lifecycle;Framer Motion 在 React 项目里更顺手
- **打包陷阱**:若 import 的是 `'animejs'` 主入口而不是 `'animejs/animation'`,可能进全量模块;Rollup / Vite 默认 tree-shake 良好但要测

## 9. 数据校正(源文 vs 远端核实)

| 维度 | 源文 | 远端核实(2026-10-10) | 偏差 |
|---|---|---|---|
| Stars | "近 70k"(2026-09-17 写) | **73.4k**(GitHub 主页) | +3.4k,源文日期到调研时间约 +5%,数据校正后写"73.4k" |
| 版本 | 未明说 | **v4.5.0**(package.json) | 需补 |
| License | "免费开源,商用无限制" | **MIT**(package.json) | ✓ 对的 |
| 运行依赖 | "零依赖" | **零运行时依赖**(package.json 无 `dependencies`) | ✓ 对的 |
| 包体积 | "约 17KB" | **UMD bundle 约 17KB**(源文估算,无官方 dist 文档) | 无偏差但加备注:实际是打包估算 |
| 商用授权 | "完全免费开源" | **MIT 全免费** | ✓ 对的 |
| CDN URL | `cdn.jsdelivr.net/npm/animejs@4/lib/anime.min.js` | package.json 的 jsdelivr 字段指向 `dist/bundles/anime.umd.min.js`,**源文 CDN 路径有疑** | 需校正:`https://cdn.jsdelivr.net/npm/animejs@4/dist/bundles/anime.umd.min.js` |
| GSAP 商用 | "商用付费" | 核心免费 / 高阶插件付费(2024 年起 GSAP 核心彻底 MIT,但 MorphSVG / DrawSVG / SplitText 等仍是 Club 付费) | 表述需校准为"核心免费 / 高阶插件付费" |
| WAAPI 底层 | "底层自动适配浏览器性能" | **WAAPI 是独立子路径 `animejs/waapi`,非自动底层** | 源文小吹,需校正为"可选子模块,需显式 import" |
| v4 API 命名 | `animate / timeline / stagger` | package.json + README 一致 | ✓ 对的 |
| peer Three.js | "原生适配" | **可选 peer `three >=0.150.0`,走 `animejs/adapters/three` 子路径** | ✓ 对的,但源文未说"可选 peer / 子路径",需补 |
| **npm 下载量**(权威值) | 未提 | **500 万 DL/月**(2026-09 → 2026-10),独立 API:https://api.npmjs.org/downloads/point/last-month/animejs | 新增维度,横向比较 GSAP 商业版不计 / Framer Motion ~1.5M / Popmotion ~1M 后,属于头部公共池 |
| **社区反响** | 未提 | HN Show 2025-04-03「AnimeJs v4 Is Here」**973 分 / 155 评论**,同日 = v4.0.0 发布日(2025-04-03T14:29:45Z) | 新增维度,HN 史上 Anime.js 系列三段:Show HN 2016-06-27 (283 pts) → v3 (2019-01-14) → v4 (2025-04-03, 973 pts) |
| v4 架构变化描述 | 未提 | v4.0.0 release meta 原文:**"A complete rewrite of Anime.js, with a modular, ESM-first API, improved performance, and TONS of new features"** | 源文只字未提 v4 是重写,补充 |

> 多源研究档案:[assets/animeJs/sources-report.md](assets/animeJs/sources-report.md)(5 源:官方文档 / v3→v4 迁移指南 / GitHub Releases v4.0.0+v4.5 / HN Show / npm registry + downloads API)。

## 10. 一句话哲学

> "One engine, every target, zero config to start."

设计目标是:**一套 API 同时驱动 CSS / SVG / DOM / JS 对象 / Three.js 物体,新项目零配置上手,老项目按需 import 子路径 tree-shake。**

核心 trade-off:**API 简单 = 底层报错信息稀薄 + 高阶用法仍要学**(SVG morph / spring 物理 / scroll 钩子都各有讲究),不是"零学习成本"。但比 GSAP 的 position parameter 算式 / ScrollTrigger 配置 / MorphSVG 付费墙,起步确实低很多。

---

## 11. 下一步行动(若 sanfine.art 真要落地)

按本仓 `armorpaint-tech-selection` / `semantica` 的"调研→选型→落地"3 步拆,落地前要先做 3 件 prototype 工作:

### 11.1 树摇验证(1 个工作日)

**目标**:确认 `import { animate, stagger } from 'animejs'` 在 sanfine.art 构建产物里**真的 tree-shake 出只剩 2 个子模块**,而不是被打成全量 17KB。

**做法**:
- 装 `rollup-plugin-visualizer` 或 `vite-plugin-bundle-visualizer`
- 在 sanfine.art 真实生产构建里跑一次,看 animejs 进哪个 chunk
- 期望结果:`animejs/animation` + `animejs/stagger` 两个子模块打包,gzip 后 ≤ 8KB
- **不通过**:全量 17KB+,可能是 `@types/three` 误把 peer 引进来,需要改用 `<script>` CDN UMD 兜底

**联系人**:前端 / 构建工具 owner

### 11.2 写一个 hero stagger demo(2-3 个工作日)

**目标**:在 sanfine.art 首页(假设 Astro / Next.js 任选)做一个 hero stagger 动画,**实测端到端体验**。

**最小 demo 设计**:
- 标题 / 副标题 / CTA 按钮三个元素 `stagger(100, { from: 'center' })`
- `duration: 800`、`ease: 'outQuint'`、`loop: false`
- 容器元素 `scope.add(self => { ... }).revert()` 包裹,路由切换时释放

**验证维度**:
- Chrome DevTools Performance 看 raf 占用 ≤ 5%
- Safari 4+ 移动端 ≤ 360px viewport 测试
- `prefers-reduced-motion: reduce` 时禁用非必要动效(`@media (prefers-reduced-motion: no-preference)` 包住动效触发)
- SSR 框架(Astro `client:load` / Next `'use client'`)实测避免 hydration mismatch

**产物**:`assets/animeJs/demo-hero-stagger.html`(单文件 HTML 引用 CDN,可直接打开看效果)+ 性能截图

### 11.3 三件 SVG 描边动效 prototyping(1-2 个工作日)

**目标**:验证 sanfine.art 品牌页 / 艺术家签名 / 收藏家 logo 用 SVG 描边的视觉效果是否达到设计稿。

**做法**:
- 拿 3 个真 SVG 资源(艺术家签名 1 个 + 品牌 mark 1 个 + 装饰元素 1 个)
- 跑 `anime.setDashoffset` 自动算描边长度,`strokeDashoffset: [anime.setDashoffset, 0]` 一行
- 对比 CSS `stroke-dasharray` + `stroke-dashoffset` 手动算长度的旧方案,看是否真的省 50% 代码

**潜在风险**:路径太长(> 1000 字符)时 `setDashoffset` 计算会卡顿;准备 fallback 到手算长度。

**产物**:`assets/animeJs/demo-svg-stroke.html`

---

### 11.4 时间预算与决策点

```
Week 1:    11.1 树摇验证(1 day)+ 11.2 hero demo 起手(2 days)
Week 1.5:  11.2 hero demo 收尾(1 day)+ 11.3 SVG 描边起手(1 day)
Week 2:    11.3 SVG 描边收尾 + 三件 demo 集成到 staging
Decision:  Week 2 末 4 选项 →
    A. 全量 Anime.js(若 tree-shake 通过 + demo 效果 OK)
    B. 仅 SVG / 描边用 Anime.js,主页动效用 CSS(混合方案)
    C. 弃 Anime.js 改 Framer Motion(若 sanfine.art 主栈最终定 React)
    D. 弃 Anime.js 改 GSAP(若 ScrollTrigger 这种重量级功能必需)
```

**决策 anchor**:**先跑 11.1(树摇),看 bundle 是否真的小**;如果树摇失败,直接走 B 或 D,不要在 C 路径上耗。

---

## 参考链接

- 仓库: <https://github.com/juliangarnier/anime>
- 官网: <https://animejs.com>
- 文档(v4): <https://animejs.com/documentation>
- v3 → v4 迁移指南: <https://animejs.com/migration>
- npm: <https://www.npmjs.com/package/animejs>
- 公众号源文: 林三心不学挖掘机《Github 70k Star 爆火动画库!几行代码实现复杂3D动画!》(2026-09-17)
- 对照项目:
  - GSAP: <https://gsap.com>
  - Framer Motion: <https://www.framer.com/motion/>
- 本仓交叉引用:
  - [stadiView.md](stadiView.md) — Three.js + GSAP 飞入动效
  - [shinjukuIndoorThreejsDemo.md](shinjukuIndoorThreejsDemo.md) — Three.js + GSAP 流光行人
  - [humanAtlas.md](humanAtlas.md) — React + Three.js 3D 人体解剖
  - [scDatav.md](scDatav.md) — Three.js + React 数据大屏
  - [odometer.md](odometer.md) — 数字翻牌库
  - [mapcn.md](mapcn.md) — shadcn 风格 React 地图组件