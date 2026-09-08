# mapcn — shadcn 风格的 React 地图组件库(MapLibre GL + Tailwind v4)

> 学习笔记 · 调研时间 2026-08-13(详细更新版,基于 GitHub + 官方文档 + 源码)
> 官网: https://www.mapcn.dev/ · GitHub: https://github.com/AnmolSaini16/mapcn · 文档: https://mapcn.dev/docs
> License: **MIT**(代码)· CARTO basemaps **商业需 Enterprise license** · Language: TypeScript (strict) · React 19 · Next.js 16 · ⭐ **11.4k** · 🍴 657
> 创建: 2025-12-28(很年轻,~7.5 个月)· 最近 push: 2026-07-25(略冷)· 0.1.0 · `shadcn` registry compliant

## 一句话定位

**shadcn 风格的"可拷贝"地图组件库**——基于 MapLibre GL JS v5,自研 `src/registry/map.tsx` **64 KB 单文件**集成 Map + Marker + Popup + Tooltip + Label + Route + Arc + GeoJSON + Cluster + Controls + Blank mode,8 个 production-ready blocks(analytics-map / choropleth / delivery-tracker / uptime-monitor / heatmap / logistics-network / store-locator / analytics-card),通过 `npx shadcn add https://www.mapcn.dev/r/map.json` 一行注入。

## 三种使用方式

| 方式 | 命令 / 步骤 | 适用 |
|---|---|---|
| **整包 add**(推荐) | `npx shadcn@latest add https://www.mapcn.dev/r/map.json` | 一次性拿 map.tsx + 所有子组件到 `src/registry/map.tsx`,目标 `components/ui/map.tsx` |
| **单 block add** | `npx shadcn@latest add https://www.mapcn.dev/r/analytics-map.json` | 只要某个 block(如 uptime-monitor),自动拉依赖 |
| **手动 clone 子模块** | 从 repo `src/registry/` 拷单文件到自己项目 | 想魔改底层 |

注入内容:
- `map.tsx` → `components/ui/map.tsx`
- CSS overrides for MapLibre popups / attribution → 自动追加到 `globals.css`
- 依赖:`maplibre-gl` + `lucide-react`(+ `@types/geojson` 到 devDeps)

## Tech Stack(精确版本)

| 层 | 选型 | 版本 |
|---|---|---|
| Framework | **Next.js (App Router)** | 16.2.7 |
| UI Runtime | **React** | 19.2.3 |
| Map Engine | **MapLibre GL JS** | 5.15.0 |
| Styling | **Tailwind CSS v4** + `@tailwindcss/postcss` + `tw-animate-css` | 4.x |
| Components | **shadcn/ui** + Radix UI | 3.6.2 / 1.6.0 |
| Schema | class-variance-authority + clsx + tailwind-merge | 0.7.1 / 2.1.1 / 2.6.0 |
| Icons | lucide-react | 0.562.0 |
| Charts(被 analytics blocks 用) | recharts | 2.15.4 |
| Command palette | cmdk | 1.1.1 |
| Theme toggle | next-themes | 0.4.6 |
| Highlight(文档站) | shiki(dual light/dark) | 3.20.0 |
| Fonts | Geist Sans + Geist Mono | - |
| Analytics | @vercel/analytics | 1.6.1 |
| Build | shadcn CLI(`registry:build`) | - |
| Type | TypeScript 5 (strict) | - |

## 仓库结构(`src/`)

```
src/
├── app/
│   ├── layout.tsx                    # Root layout (fonts, metadata, providers)
│   ├── (main)/                       # 主布局(header + content)
│   │   ├── (home)/                   # 落地页
│   │   ├── docs/                     # /docs/* 文档站
│   │   └── blocks/                   # /blocks/* block 全屏 demo
│   └── (view)/                       # 独立 block viewer
├── components/                       # 文档站共享组件
│   ├── ui/                           # shadcn/ui primitives
│   ├── code-copy-button.tsx
│   ├── command-search.tsx            # ⌘K 命令搜索 (cmdk)
│   ├── footer.tsx · header.tsx · logo.tsx
│   ├── theme-provider.tsx · theme-toggle.tsx
│   └── ...
├── registry/                         # 核心:库本身
│   ├── map.tsx                       # 主组件库(64 KB 单文件!)
│   └── blocks/                       # 8 个 block
│       ├── analytics-map/            # 4 文件
│       ├── choropleth/               # 3 文件
│       ├── analytics-card/           # 2 文件
│       ├── delivery-tracker/         # 2 文件
│       ├── uptime-monitor/           # 4 文件
│       ├── heatmap/                  # 1 文件
│       ├── logistics-network/        # 4 文件
│       └── store-locator/            # 4 文件
├── hooks/
│   └── use-mobile.ts                 # 媒体查询 hook
├── lib/                              # 工具 + 配置
│   ├── utils.ts                      # cn()
│   ├── blocks.ts                     # registry → file tree 转换
│   ├── site-navigation.ts            # 文档站导航
│   ├── use-world-data.ts             # choropleth 用的世界地图数据
│   ├── get-block-file-source.ts      # 读 block 源码
│   ├── llm-content.ts / llm-prompts.ts  # LLM 友好的内容
│   ├── highlight.ts · events.ts
└── styles/
    └── globals.css                   # 主题 token(oklch)+ 动画 + 基线
```

## 核心 API(全部来自 `src/registry/map.tsx`)

### 主组件

| 组件 | 作用 |
|---|---|
| `<Map>` | 主容器,接受 `MapLibreGL.MapOptions` + theme props,提供 MapContext |
| `<MapMarker>` | 标记点,可挂 Popup / Tooltip / Label |
| `<MarkerContent>` | 标记内容(自定义 HTML) |
| `<MarkerPopup>` / `<MarkerTooltip>` / `<MarkerLabel>` | 标记上的 popup / tooltip / 文字标签 |
| `<MapPopup>` | 独立 popup(不挂在 marker 上) |
| `<MapControls>` | zoom / compass / geolocate / fullscreen 控件 |
| `<MapRoute>` | 折线路由(GeoJSON LineString) |
| `<MapArc>` | 大圆弧线(两点球面插值) |
| `<MapGeoJSON>` | GeoJSON 数据层 |
| `<MapClusterLayer>` | 集群点 |
| `useMap()` | hook 访问当前 `MapLibreGL.Map` 实例 + `isLoaded` + `resolvedTheme` |

### 关键 prop / 模式

- **`<Map blank>`** — 启用 **blank mode**:用透明背景 style,只画自己的 layers(choropleth / world arcs / dot maps 适用),主题色背景透过
- **`<Map theme="light|dark">`** — 强制主题;不传时自动检测
- **CARTO basemap defaults**:
  - `light`: `https://basemaps.cartocdn.com/gl/positron-gl-style/style.json`
  - `dark`: `https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json`

### 内部辅助函数(展示架构)

```typescript
// 1. useStableValue — 防止 inline style 对象触发 map style 全量重载
function useStableValue<T>(value: T): T {
  const key = useMemo(() => JSON.stringify(value) ?? "", [value]);
  return useMemo(() => value, [key]);
}

// 2. mergeHoverPaint — hover state 合并 paint 表达式
function mergeHoverPaint<T extends Record<string, unknown>>(
  paint: T, hoverPaint: T | undefined
): T { /* ... */ }

// 3. useResolvedTheme — MutationObserver 监听 class/data-theme
//    + matchMedia 监听 prefers-color-scheme
//    优先级: themeProp > 文档 class > data-theme > 系统偏好
function useResolvedTheme(themeProp?: "light" | "dark"): Theme { /* ... */ }

// 4. getDocumentTheme / getSystemTheme — 两种 theme 来源
```

### Theme system 三层

1. **prop**(最高优)— `<Map theme="dark">` 强制
2. **document class / data-theme** — `next-themes` 默认 toggle `<html class="dark">`,也支持 `data-theme` 属性
3. **system pref** — `window.matchMedia("(prefers-color-scheme: dark)")` 兜底

→ 三层都用 `MutationObserver` + `matchMedia change` event 实时响应,切换主题无 reload。

## 8 个 Registry Blocks

shadcn registry compliant,每个 block 自带独立 page component + data + (可选) 子组件。

| Block | 文件数 | 用途 | 关键文件 |
|---|---|---|---|
| **analytics-map** | 4 | 全球事件仪表板(world map + breakdown cards + device stats) | `page.tsx` + `data.ts` + `overview-card.tsx` |
| **choropleth** | 3 | 世界地图按国家着色 metric + hover tooltip + legend | `page.tsx` + `data.ts` + `use-world-data.ts` |
| **analytics-card** | 2 | 紧凑 analytics 卡片(标题 metric + 世界地图背景) | `page.tsx` + `data.ts` |
| **delivery-tracker** | 2 | 实时订单跟踪(routes + courier 位置 + 订单详情) | `page.tsx` + `data.ts` |
| **uptime-monitor** | 4 | status-page 风格边缘节点地图(live health / latency / uptime) | `page.tsx` + `data.ts` + `edge-node-marker.tsx` + |
| **heatmap** | 1 | 球面投影地震密度图(zoom-dependent styling) | `page.tsx` |
| **logistics-network** | 4 | 国内物流网络图 + 侧边统计 sidebar | `page.tsx` + `data.ts` + `filter-sidebar.tsx` + |
| **store-locator** | 4 | 可搜索的门店列表 + 同步地图标记 | `page.tsx` + `data.ts` + `store-list.tsx` + |

每个 block 包含的 `meta.iframeHeight` 让文档站能 iframe 嵌入固定高度 demo。

## 文档站结构(`/docs`)

| 路径 | 内容 |
|---|---|
| `/docs` | Getting Started |
| `/docs/installation` | 安装步骤 |
| `/docs/basic-map` | Map 组件 |
| `/docs/controls` | MapControls |
| `/docs/markers` | Markers 系列 |
| `/docs/popups` | Popups |
| `/docs/routes` | Routes |
| `/docs/arcs` | 大圆弧 |
| `/docs/geojson` | GeoJSON 层 |
| `/docs/clusters` | 集群 |
| `/docs/advanced-usage` | 高级用法 |
| `/llms.txt` | LLM-friendly 内容索引 |
| `/blocks` | 全部 block 全屏 demo |
| `/blocks/<block-name>` | 单 block 视图 |

另外:`app/llms.txt/` 目录有专门给 LLM 看的精简内容,方便 AI 编程助手一次性消化整库。

## 关键设计决策(从源码读出)

| 决策 | 为什么 |
|---|---|
| **64 KB 单文件 `map.tsx`** | "拷贝即用"哲学 — 用户拿到一个文件就拿到整个地图 API,不用追 import tree;子组件互相依赖也在同文件内可见 |
| **shadcn registry 协议** | 不是 npm 包,是 registry item — 用户拥有源码、能直接改、vendor lock-in 零;和 shadcn/ui 一致的 UX |
| **CARTO 默认 basemap** | 开箱即用,免费(非商业),商业授权清晰;MapTiler / OSM / Stadia 都可替换,只需改 style URL |
| **Theme token 用 oklch** | 现代色彩空间,light/dark 切换更平滑;Tailwind v4 原生支持 |
| **shadcn style: "new-york"** | shadcn 的新默认风格(相比 "default" 更紧凑) |
| **RSC-first** | 文档站默认 React Server Component,只在需要 Web API 时加 `"use client"`(map.tsx 是 client) |
| **minimal 视觉** | monochrome grayscale + 留白 + 字号层级,无装饰边框/阴影;Geist 字体 |
| **块独立 file 树** | 每 block 自包含 `page.tsx` + `data.ts` + 独立子组件,装一个 block 不会拖一堆 deps |

## Installation 详细

### 1) 整库 add(最常用)

```bash
npx shadcn@latest add https://www.mapcn.dev/r/map.json
```

落地:
- `map.tsx` → `components/ui/map.tsx`
- CSS overrides 注入 `globals.css`(MapLibre popup / attribution 主题)
- 自动加 `maplibre-gl` + `lucide-react` 到 deps,`@types/geojson` 到 devDeps

### 2) 单 block add

```bash
npx shadcn@latest add https://www.mapcn.dev/r/uptime-monitor.json
```

自动带 block 的 `registryDependencies`(map + 子 hooks)。

### 3) 手动 copy

从 repo `src/registry/blocks/<name>/` 复制 page + data + components,自己装 `map.tsx`。

## 性能要点

- **`useStableValue`** 是关键:inline 对象(`paint`、`layout` 等)传给 MapLibre 会触发整张 style 重载。`useStableValue` 用 `JSON.stringify` 作 key,等同引用就不重新计算 → 避免 re-render 风暴
- **`mergeHoverPaint`** 用 MapLibre `case` 表达式合并 hover/base paint,比 "hover 时换 style" 性能高
- **CARTO basemap 是矢量 tile** — 首次加载后 pan/zoom 平滑,不重 fetch
- **`blank` mode** 跳过 basemap,纯 layer 渲染 — choropleth / heatmap 场景首屏更快

## License / 合规注意

- **代码:MIT** — 自由用、改、商业化
- **CARTO basemaps**:
  - **非商业**:免费(CARTO grantees)
  - **商业**:需 CARTO Enterprise license(联系 sales)
  - **替代**:换 OSM raster tile、MapTiler、Stadia Maps 等任意 MapLibre 兼容 tile provider
- **OpenStreetMap 数据** — 即使换 basemap,OSM 数据要 attribution(在地图角落保留 © OpenStreetMap contributors)

→ 商业产品上线前要决定 basemap 来源,不要默认依赖 CARTO。

## 替代方案对比(详细)

| 选项 | 优势 | 劣势 | 适合 |
|---|---|---|---|
| **mapcn** | shadcn 集成 + 拷贝即用 + 主题感知 + 8 个 block 模板 | 极年轻(8 月)· 0.1.0 · API 可能 break | shadcn 项目 + 想要 0 决策成本 |
| react-leaflet | 老牌稳 + OSM 自带 + 文档厚 | 不"shadcn",不是矢量 tile,样式自由度低 | 简单地图 + OSM 够用 + 求稳 |
| Mapbox GL JS | 工业级 + 商业支持 + 矢量性能 | 商业 license + 收费按加载 | 商业级产品 + 有预算 |
| MapLibre GL JS(裸) | 同 Mapbox 性能,免 license | 自己写 wrapper / state / controls | 想完全控制 + 有时间 |
| deck.gl | 大数据可视化强 | 学习曲线陡 | 数据科学可视化 |
| vis.gl / carto-react | 大型 BI 平台级别 | 重 | 企业 BI dashboard |

**判断标准**:
- shadcn + Tailwind 项目 → mapcn
- 要商业 license + 工业级 → Mapbox
- 求稳不折腾 → react-leaflet
- 想要完全自由 → 裸 MapLibre

## 风险与注意

- **8 个月龄 + 0.1.0** — API 还会大改,跟随时 pin 版本
- **`pushed_at: 2026-07-25`** — 距今 3 周没 push,可能维护节奏放缓(关注 issue 响应)
- **23 open issues** — 活跃但不爆炸
- **依赖 CARTO basemap** — 商业要钱;且首屏依赖外网
- **shadcn 强绑定** — 不在 shadcn 生态的项目体验打折(registry / CSS variables / cn() 等都假设有)
- **Next.js 16 + React 19** — 都是最新版,旧项目升级成本高
- **注册方式而非 npm** — 没有 semver 锁,升级靠手动 `npx shadcn add` 再覆盖
- **map.tsx 64 KB 单文件** — 真要魔改核心,debug 略痛苦(vs 拆 npm 包)

## 跟我们的关系

| 项目 | 相关度 | 备注 |
|---|---|---|
| **Sanfineart**(艺术电商) | 🟡 **强相关** | 门店地图 / 画廊活动地图 / 艺术展览地理分布,store-locator block 几乎开箱即用 |
| **Fireside**(Sprint 1 dashboard) | 🟢 暂不需要,技术储备 | 未来加"用户地理分布"模块可拿来用 analytics-map / choropleth |
| **curator**(art-news-briefing) | 🟡 可选 | 同 Sanfineart,exhibition 地图 |
| **品行者 / PINOKRS** | 🟢 低 | 后端管理,B 端,用户没有"地理"维度 |
| **国内户储业务** | ⚪ 不相关 | 业务跟地图无关 |
| **huashu-nuwa skill** | 🟢 借鉴 | mapcn 的"单文件可拷贝 + registry 协议"模式,跟我们"小颗粒度 skill 模块化"思路相通 |

## 使用建议

1. **不要现在就用** — 等 1.0.0 再说(还在 0.1.x 震荡期)
2. **作为技术储备关注** — 等稳定后,Sanfineart 第一时间接入
3. **如果要用,只装 map 单组件 + 需要的 block** — 别整库 add,避免 64 KB 全量
4. **CARTO basemap 商业化前换成 MapTiler 或自托管** — 省 license 钱
5. **贡献上游** — 23 open issues,可能值得投时间回报

## 参考链接

- 官网: https://www.mapcn.dev/
- GitHub: https://github.com/AnmolSaini16/mapcn
- 文档: https://mapcn.dev/docs
- shadcn registry 协议: https://ui.shadcn.com/docs/registry
- MapLibre GL: https://maplibre.org/
- Tailwind v4: https://tailwindcss.com/
- CARTO basemap ToS: https://carto.com/legal/bmap
- shadcn/ui: https://ui.shadcn.com/
- star-history: https://star-history.com/#AnmolSaini16/mapcn

调研来源:GitHub repo `AnmolSaini16/mapcn`(API + 源码 + AGENTS.md + registry.json + components.json + package.json),2026-08-13 实时拉取