# ShinjukuIndoorThreejsDemo — 国交省新宿駅屋内地图数据的 Three.js 3D 可视化 demo

> 学习笔记 · 调研时间 2026-09-03
> 仓库: https://github.com/satoshi7190/Shinjuku-indoor-threejs-demo · 在线 Demo: https://satoshi7190.github.io/Shinjuku-indoor-threejs-demo/ · 技术原文: https://qiita.com/satoshi7190/items/23d192372877af75b283
> 数据源: https://www.geospatial.jp/ckan/dataset/mlit-indoor-shinjuku-r2 （国土交通省「新宿駅周辺屋内地図データ」R2）
> License: **未声明**（仓库 + package.json 都没写 license 字段，spdx_id=null） · 语言: JavaScript · ⭐ 127 · 最近 push 2025-03-16

## 一句话定位

把日本国土交通省公开的「新宿駅」室内 GIS 数据（GeoJSON 格式）丢进 Three.js 做 3D 分层楼栋渲染 + 流光步行者网络动画的纯前端 demo，整套 Vite + GitHub Pages 静态部署。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| 线上 Demo | https://satoshi7190.github.io/Shinjuku-indoor-threejs-demo/ | 不装环境直接看效果（首次加载 fg.geojson 3.5 MB 略慢）|
| 本地开发 | `npm install && npm run dev`（Vite dev server）| 改 Three.js 场景 / 调试 GUI 控件 |
| 本地预览构建产物 | `npm run build && npm run preview` | 模拟 Pages 上 dist/ 的实际行为 |

无 CLI / 无 API / 无 SDK——它就是一份参考实现，不是产品。

## 核心组件 / 模块 / 架构

### 数据层（GeoJSON 切片）

仓库 `src/public/` 下三个目录，对应三类语义：

| 目录 | 文件形态 | 内容 |
|---|---|---|
| `ShinjukuTerminal/` | `ShinjukuTerminal_<floor>_<layer>.geojson` ×32 | 单层楼（-3 / -2 / -1 / 0 / 1 / 2 / 3 / 4）的三类要素：Space（房间多边形）、Floor（楼板）、Fixture（设备/设施）；个别楼层带 `out` 后缀代表站外延伸部分 |
| `nw/` | `Shinjuku_link.geojson` + `Shinjuku_node.geojson` | 步行者网络：link（带 start_id / end_id / direction）+ node（带 node_id / ordinal=楼层） |
| `fg.geojson` | 单文件 3.5 MB | 基础地图信息 道路数据（紫色 Line，铺在 0 层）|

坐标系：平面直角坐标 EPSG:6677，原点相对 `center = [-12035.29, -34261.85]` 做归零。

### 渲染层（src/main.js，~480 行单文件）

```
                ┌─ Space（房间，depth=5）  ─┐
   GeoJSON ───▶│─ Floor（楼板，depth=0.5）─┼─▶ ExtrudeGeometry ─▶ EdgesGeometry ─▶ LineSegments
                └─ Fixture（设施，depth=5）─┘                                 │
                                                                              ▼
                                                THREE.Group(group-3 ~ group4)
                                                                              │
                                            verticalOffset=30 分层堆叠 ◀────────┘

   nw/link.geojson + node.geojson ─▶ MeshLine（three.meshline）─▶ 自写 GLSL Shader
                                                              └─ uTime 动画 = 流光效果
```

关键设计点：

| 模块 | 做法 |
|---|---|
| **相机控制拆双** | `MapControls` 负责旋转 + 平移，`TrackballControls` 只负责缩放（`noPan / noRotate` 全锁），并把 `mapControls.target` 同步给 zoom target——非常巧妙的「一个看视角、一个管距离」分离 |
| **图层组** | 8 个 `THREE.Group`，命名 `group-3 ~ group4`，对应 B3 到 4F；lil-gui 里用 checkbox 切可见性 |
| **楼层定位** | 从文件名正则 `ShinjukuTerminal_([-B\d]+)(out)?_<Type>` 抽层号，`out` 后缀的当作同层处理 |
| **MeshLine 动画** | 用 `onBeforeCompile` 注入 `uTime / uDistance / uDirection` 三个 uniform，方向 1 / 2 配两种颜色 + 不同流向，做上下行分色流光线 |
| **资源加载** | `THREE.FileLoader().setResponseType('json')` 全程不走打包，直接相对路径 `./public/...` |

### 部署层（GitHub Pages）

`.github/workflows/static.yml` 用官方 `actions/deploy-pages@v4`，**直接上传 `dist/`** 到 Pages（不走 `npm ci && npm run build`，构建靠开发者本地跑）。意味着 dist/ 目录必须手工维护——这是它最「野生」的地方。

## 安装与最小使用

```bash
git clone https://github.com/satoshi7190/Shinjuku-indoor-threejs-demo
cd Shinjuku-indoor-threejs-demo
npm install
npm run dev    # http://localhost:5173
```

构建产物（dist/）作者已 commit 进仓库，所以可以直接拷 dist/ 跑静态服务：

```bash
cd dist && python3 -m http.server 8000
# http://localhost:8000/
```

最小可改示例——把流光颜色从青色换成橙色：

```javascript
// src/main.js, linkMaterial 处
mainColor = vec3(0.0, 1.0, 1.0);   // 上行：青
// ↓ 改
mainColor = vec3(1.0, 0.5, 0.0);   // 上行：橙
```

## 数据规模 & 性能基线

| 项 | 实测 |
|---|---|
| fg.geojson | 3,703,316 B（≈3.5 MB） |
| 全部 ShinjukuTerminal/*.geojson | 32 个文件，单文件最大 100,935 B（0 层 Space）|
| Three.js 版本 | ^0.151.3（2023 上半年版本，老但稳定）|
| three.meshline | ^1.4.0（社区维护，已多年未更）|
| Vite | ^4.2.0 |
| 构建产物 dist/index-*.js | 697,467 B（≈681 KB，未压）|

首屏加载 ≈ 4 MB 数据 + 681 KB JS，移动端首屏要 3-5 秒。代码本身不分帧/懒加载 GeoJSON——是单次全塞进场景。

## 跟我们的关系（用户工作相关 — 必填段）

| 项目/场景 | 能不能用上 |
|---|---|
| **城市数字孪生 / 园区可视化的脚手架** | ✅ 直接 fork 当模板，把 ShinjukuTerminal/*.geojson 换成自家物业或园区的数据即可。注意替换时**楼层号约定**（B 开头表示地下）和 **`center` 偏移归零**两件事——这两个抽不出来就要爆 |
| **地铁站/商场室内导航的可视化前段** | ✅ 步行者网络（link + node）的流光动画就是个迷你 demo，可作为 PoC 起点；想做成生产产品需要补最短路径算法 + 节点定位点击交互 |
| **国内 GIS 数据（高德室内图 / 百度室内图 / Mapbox 矢量楼栋）** | ⚠️ 坐标系不同——国交省是 EPSG:6677（平面直角），国内常用 GCJ-02 / WGS-84 / 各类自定义。**不能直接套**，得在 createExtrudedGeometry 之前做坐标转换 |
| **生产级 3D 楼栋编辑器** | ❌ 这是 demo 不是 editor。多人协作、要素编辑、属性面板、版本回滚全没有；想做编辑器看 `PascalEditor.md`（React Three Fiber + WebGPU + MCP 那条线）|
| **纯 Three.js / R3F 学习** | ✅ 是个干净的「单文件 Three.js + Vite + lil-gui」骨架，单 main.js 480 行能一次读完，适合当练手材料 |
| **想做「建筑信息 + 流线」仪表盘** | ✅ 步行者网络流光是核心看点，可拓展成「实时人流热力」、「设施使用率」等展示 |

可复用的两个核心片段：

1. **MapControls + TrackballControls 拆分**：想给非技术用户看 3D 时，「只让他缩放、不让他转晕」是个真实需求。这套双控写法值得偷。
2. **MeshLine + onBeforeCompile 注入流光**：Three.js 社区做管线动画的事实标配之一，比起手搓 ShaderMaterial 简单太多。

## 实战建议 / 风险点

| 风险 | 说明 |
|---|---|
| **License 缺失** | 仓库没声明 license（README/package.json/spdx 都没写）。**不能默认 MIT**。如果要二次发布（含 fork 后部属），建议先 issue 问清楚或注明「上游未授权」|
| **`three.meshline` 已停止维护** | 最后一次发布 2017 年，依赖的还是老版 Three.js 顶点结构。当前能跑是 Three.js 0.151 兼容；升 Three.js 到 r150+ 后 vertex array 改了，可能会挂 |
| **dist/ 入库** | 681 KB 的构建产物 + 3.5 MB GeoJSON 都在 git 里，单 clone ≈ 4 MB。fork 后建议改成 .gitignore + CI 自动 build |
| **`dependencies: { npm: ^3.0.1 }`** | package.json 里这一行大概率是手抖打错的（npm 是包管理器，不会当 runtime dep）。不影响功能但 lerna/dependabot 会报警 |
| **坐标系单一（EPSG:6677）** | `center` 硬编码偏移。如果数据源换投影（比如换 Tokyo 站或大阪站），得改 main.js 顶部的 center 数组 |
| **没分帧加载** | 全部 GeoJSON `loader.load` 一把塞，楼层多/数据大时会卡顿。生产化要做 LOD / 分块加载 |
| **无单元测试 / 无 lint** | `package.json` 没 eslint / prettier / vitest 配置。改代码全靠肉眼 |
| **Pages 部署依赖手工 dist** | `.github/workflows/static.yml` 只 `upload-pages-artifact` dist/，**不跑 build**。协作时要注意：改了 src/ 必须本地 build 后提交 dist/ |

## 版本节奏 / Release 历史

无 release / 无 tag，作者走「commit 即发布」路线。

| 时间 | 事件 |
|---|---|
| 2023-11-04 | 仓库创建（首次 commit）|
| 2023-12-24 | Qiita 技术文章首发 |
| 2025-01-26 | Qiita 文章更新（最近一次）|
| 2025-03-16 | 最近一次 push |

## 配套生态 / 相关文章

- **作者系列**：本仓库作者 `satoshi7190` 在 Qiita 还写过其他 Three.js + GIS 文章，可在 https://qiita.com/satoshi7190 翻
- **国交省数据**：https://www.geospatial.jp/ckan/dataset/mlit-indoor-shinjuku-r2 同期还放了大阪 / 名古屋 / 博多等其它枢纽站的室内地图数据（同样是 GeoJSON 切片），同套代码改 GeoJSON 路径就能跑
- **相关 iswiki 笔记**：
  - `ThreeUI.md` — Three.js 3D UI 组件目录（不同定位，但同栈）
  - `StadiView.md` — 3D 体育场馆可视化（同用 Three.js + 自写 shader 的思路）
  - `PascalEditor.md` — 生产级 3D 建筑编辑器（想做产品而不是 demo 看这条）

## 参考链接

- GitHub 仓库: https://github.com/satoshi7190/Shinjuku-indoor-threejs-demo
- 在线 Demo: https://satoshi7190.github.io/Shinjuku-indoor-threejs-demo/
- Qiita 技术原文: https://qiita.com/satoshi7190/items/23d192372877af75b283
- 数据源（国交省 R2）: https://www.geospatial.jp/ckan/dataset/mlit-indoor-shinjuku-r2
- 微信文章（用户提供）: https://mp.weixin.qq.com/s/wZwH6VAK5ZnmfK19Y0XWLg
- 主依赖:
  - Three.js https://threejs.org/
  - three.meshline https://github.com/spite/THREE.MeshLine
  - Vite https://vitejs.dev/
  - lil-gui https://github.com/georgealways/lil-gui