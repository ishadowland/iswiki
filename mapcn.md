# mapcn — 地图组件库 (MapLibre + shadcn/ui)

> 学习笔记 · 调研时间 2026-08-04
> 官网: https://www.mapcn.dev/ · GitHub: https://github.com/AnmolSaini16/mapcn
> License: MIT · Language: TypeScript / React 19 · Next.js 16 · ⭐ 11.2k

## 一句话定位

**shadcn 风格的可拷贝地图组件库**——基于 MapLibre GL JS，单文件 `map.tsx` 2226 行涵盖 Map + Marker + Popup + Route + Arc + GeoJSON + Cluster，**npx shadcn add** 一行装好。

## 跟 Fireside / Sanfineart 的相关点

| 项目 | 相关度 | 应用场景 |
|---|---|---|
| **Fireside** | 🟢 文档/状态页 用 | 暂时不需要，技术储备 |
| **Sanfineart** | 🟡 **强相关** | 门店/画廊/活动地图（与 360° 商品 + 室内 3D 互补） |
| **curator** (art-news-briefing) | 🟡 可选 | 艺术展览地理分布 |

## Tech Stack

| 层 | 选型 | 版本 |
|---|---|---|
| Framework | Next.js (App Router) | 16.2.7 |
| UI Runtime | React | 19.2.3 |
| Map Engine | **MapLibre GL JS** | 5.15 |
| Components | shadcn/ui + Radix UI | 3.6 / 1.6 |
| Styling | Tailwind CSS (oklch) | 4 |
| Icons | lucide-react | 0.562 |
| Charts | recharts | 2.15 |
| Themes | next-themes | 0.4 |
| Highlight | shiki | 3.20 |

## 核心 API（单文件 `src/registry/map.tsx` 2226 行）

```tsx
<Map />                    // 主 map, 支持 blank/data-only mode
<MapMarker />              // 标记
<MarkerContent />          // 自定义内容
<MarkerPopup />            // marker 上 popup
<MarkerTooltip />          // marker 上 tooltip
<MarkerLabel />            // marker 文字 label
<MapPopup />               // 独立 popup
<MapControls />            // zoom / geolocate / fullscreen
<MapRoute />               // 线 routes
<MapArc />                 // 曲线 arcs
<MapGeoJSON />             // GeoJSON 数据层
<MapClusterLayer />        // 集群
useMap()                    // hook 访问 map 实例
```

**Key features**:
- **Theme-aware** (light/dark 自动检测 via `next-themes`)
- **Blank mode** (`<Map blank>` — data viz without basemap)
- **CARTO basemaps** (free CARTO grantees / commercial)
- **CSS overrides** for MapLibre popups / attribution
- **Stable value** (useStableValue 防止 inline object 触发 style reload)

## 8 个展示 Blocks (registry:block)

| Block | 用途 | 文件 |
|---|---|---|
| `analytics-map` | 仪表板 + map | `page.tsx` + `data.ts` + 2 sub-components |
| `choropleth` | 国家热力图 (world data) | `page.tsx` + `use-world-data.ts` |
| `analytics-card` | 单卡片 widget | `page.tsx` + `data.ts` |
| `delivery-tracker` | 物流配送跟踪 | `page.tsx` + `data.ts` |
| `uptime-monitor` | 边缘节点监控 | `page.tsx` + 2 components |
| `heatmap` | 地理热图 | `page.tsx` |
| `logistics-network` | 网络图 (节点 + 过滤) | `page.tsx` + 2 components |
| `store-locator` | 门店定位 | `page.tsx` + 2 components |

每个 block 都是 self-contained page component。

## Installation (shadcn registry)

```bash
npx shadcn@latest add https://www.mapcn.dev/r/map.json
```

- `map.tsx` 装到 `src/registry/map.tsx`（目标 `components/ui/map.tsx`）
- 注入 CSS overrides
- 加 deps: `maplibre-gl` + `lucide-react`
- 加 devDeps: `@types/geojson`

## 风险 / 注意事项

- **新项目** (8 个月) — 仍在早期
- **No releases yet** — 版本可能 breaking
- 依赖 **CARTO basemaps** — 商业使用需 CARTO Enterprise license
- **OpenStreetMap** 数据 — 必须 attribution
- shadcn registry 依赖 — shadcn/ui 大版本变化可能 break

## 替代方案对比

| 选项 | 优势 | 劣势 |
|---|---|---|
| **mapcn** | shadcn 集成, blocks 现成, themed | 新项目, 无 release, 新 React 19 |
| react-leaflet | 老牌, 稳, OSM 自带 | 没那么 "shoji" |
| Mapbox GL JS | 工业级, 商业支持 | 商业 license, 贵 |
| MapLibre GL JS (裸) | 同 mapcn, 但要自己写 wrapper | 重复造轮子 |

## 建议

**Sanfineart 用 mapcn**（shadcn 集成省事），Fireside 暂不用。

## 参考

- 官网: https://www.mapcn.dev/
- GitHub: https://github.com/AnmolSaini16/mapcn
- MapLibre GL docs: https://maplibre.org/
- CARTO basemaps: https://github.com/CartoDB/basemap-styles
