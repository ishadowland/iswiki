# PascalEditor — 3D 建筑 / 数字孪生编辑器（React Three Fiber + WebGPU + MCP）

> 学习笔记 · 调研时间 2026-08-13
> 仓库: https://github.com/pascalorg/editor · 官网: https://editor.pascal.app · 文档: https://editor.pascal.app/docs
> License: **MIT** · Language: TypeScript (96%) · React 19 + Next.js 16 · ⭐ **21.3k** · 🍴 2.7k
> 创建: 2025-10-16（很新）,最后更新 2026-08-13 · 包: `@pascal-app/core` `@pascal-app/viewer` `@pascal-app/editor` `@pascal-app/nodes` `@pascal-app/cli` `@pascal-app/mcp`

## 一句话定位

**开源 3D 建筑 / BIM / 数字孪生编辑器**——基于 React Three Fiber + WebGPU,Turborepo monorepo 拆 7 个包,自带 MCP server,Agent 能直接通过 MCP 操作场景(state CRUD + 工具 + 资源 + prompt)。GitHub 上 21k ⭐ 增长极快(2025-10 才创建,8 个月冲到 21k)。

## 三种使用方式

| 方式 | 入口命令 | 适用场景 |
|---|---|---|
| 一键 CLI(无需 clone) | `npx @pascal-app/cli editor` | 个人快速试用,MCP service 后台常驻,数据落 `~/.pascal/data/pascal.db` |
| npm 包嵌入自己的 Next.js | `npm i @pascal-app/core @pascal-app/viewer @pascal-app/editor @pascal-app/nodes` | 想拿 viewer/editor 包做二次开发或嵌入自家产品 |
| Clone monorepo 本地开发 | `bun install && bun dev` → http://localhost:3002 | 改 core/viewer 内部、做新 node kind、写 plugin |

要求 Node 22.13+(CLI 模式),开发模式 Node ≥20.9.0 + Bun。

## 核心架构(Turborepo monorepo,7 个包)

```
editor/
├── apps/
│   └── editor/          # Next.js 16 standalone host
├── packages/
│   ├── core/            # 场景图 + node schemas + Zustand stores + 事件总线 + 系统逻辑(纯逻辑,禁 import Three.js)
│   ├── viewer/          # 3D 渲染 runtime(React Three Fiber + WebGPU)+ 共享渲染系统 + presentation state
│   ├── editor/          # 编辑工具 + panels + 选择管理 + 直接操作 UI
│   ├── nodes/           # 内置 node kind 注册 plugin(schema + 3D/2D 渲染 + 摆放工具 + inspector)
│   ├── cli/             # 版本化的 standalone editor runtime + 持久化本地数据
│   ├── mcp/             # MCP server + 场景存储适配器(给 AI Agent 用)
│   └── ui/              # 共享 UI 组件
```

**3 层强隔离**(AGENTS.md 写得很死):
- `core` 只能管 domain 数据 + 纯逻辑,**禁 import Three.js / viewer / editor / UI / 工具 / 视图概念**
- `viewer` 管 3D canvas + 渲染 + 真正的 presentation state,**不知道 useEditor / 工具 / phase / paint mode / floorplan state**
- `apps/editor` 管编辑体验(工具 / useEditor / panels / floorplan / paint / 快捷键 / 命令面板 / 光标徽章 / 编辑器专属 overlay),通过 props + children 注入到 `<Viewer>`

→ 这种"渲染"和"编辑"彻底分离,意味着 viewer 包可以独立拿去展示(只读),editor 包再加交互。

## 核心概念:BIM 节点树

```
Site
└── Building
    └── Level
        ├── Wall  ──→ Item(门 / 窗)
        ├── Slab(楼板)
        ├── Ceiling ──→ Item(灯)
        ├── Roof
        ├── Zone
        ├── Scan(3D 参考)
        └── Guide(2D 参考)
```

**节点存储是扁平字典** (`Record<id, Node>`),不是嵌套树。父子关系靠 `parentId` + `children` 数组维护。

每个节点继承 `BaseNode`:

```typescript
BaseNode {
  id: string              // 自动生成带类型前缀, e.g. "wall_abc123"
  type: string            // 类型判别
  parentId: string | null
  visible: boolean
  camera?: Camera         // 可选保存的相机位置
  metadata?: JSON         // 任意元数据 (e.g. { isTransient: true })
}
```

## 3 个 Zustand Store 分层

| Store | 包 | 职责 | 持久化 |
|---|---|---|---|
| `useScene` | `@pascal-app/core` | 场景数据:nodes / root IDs / dirty nodes / CRUD | IndexedDB + Zundo 50 步 undo/redo |
| `useViewer` | `@pascal-app/viewer` | viewer 状态:当前选择(building/level/zone IDs)+ level 显示模式(stacked/exploded/solo)+ 相机模式 | viewer 内存 |
| `useEditor` | `apps/editor` | editor 状态:active tool / structure layer 可见性 / panel 状态 / 编辑器偏好 | editor 内存 |

**在 React 组件外访问**(callback / system):

```typescript
const node = useScene.getState().nodes[id]
useViewer.getState().setSelection({ levelId: 'level_123' })
```

## 核心系统(放 `@pascal-app/core`)

| System | 职责 |
|---|---|
| `WallSystem` | 墙几何生成 + 斜接 + CSG 切出门窗洞(`three-bvh-csg`) |
| `SlabSystem` | 从多边形生成楼板 |
| `CeilingSystem` | 天花板几何 |
| `RoofSystem` | 屋顶几何 |
| `ItemSystem` | 物品摆放到墙 / 天花板 / 楼板(基于 slab elevation) |

viewer 包还有:`LevelSystem`(stacked/exploded/solo 显示模式)、`ScanSystem`(3D 参考扫描)、`GuideSystem`(2D 参考图)。

## Dirty Nodes 处理模式(增量更新)

```typescript
useFrame(() => {
  for (const id of dirtyNodes) {
    const obj = sceneRegistry.nodes.get(id)
    const node = useScene.getState().nodes[id]
    updateGeometry(obj, node)
    dirtyNodes.delete(id)
  }
})
```

`createNode / updateNode / deleteNode` 会自动把节点 mark 为 dirty,系统每帧只对 dirty 节点重算几何。手改可以:`useScene.getState().dirtyNodes.add(wallId)`。

## MCP 集成(给 AI Agent 用的接口)

`@pascal-app/mcp` 是 **Model Context Protocol server**,把场景操作暴露成 MCP tools / resources / prompts:

- CLI 模式下 `pascal mcp connect` 把 MCP service 起在后台
- 配置 Agent(Claude Code / Cursor / Codex 等)launch `pascal mcp connect`,Agent 就能直接读场景、调工具、改 state
- 数据落 `~/.pascal/data/pascal.db`

→ 这是一个亮点:**BIM 编辑器 + Agent 原生集成**,Agent 不是"截图 + 看"而是"调 MCP 改真场景"。同类工具(StadiView、mapcn)都没这层。

## 插件体系

不用改 core 源码就能加新 node kind:

- **manifest**:`Plugin` shape(同内置 node 用同一套 API)
- **plugin 内容**:node kind(schema + 3D/2D 渲染 + 摆放工具 + inspector 参数面板) + left-rail panels
- **生命周期**:发现 / 加载 / 卸载都统一
- **Worked example**:`pascalorg/plugin-trees`——独立 repo,程序化生成树 / 花 / 草 + presets panel。可以 clone 当起点。

## 安装与最小使用

### 1) 一键 CLI(推荐先试这个)

```bash
npx @pascal-app/cli editor
# 后台跑 editor + authenticated MCP service
# 自动选 collision-free loopback port
# 数据 ~/.pascal/data/pascal.db
# Agent 配: pascal mcp connect
```

### 2) npm 包嵌入自己的 React/Next.js

```bash
npm install @pascal-app/core @pascal-app/viewer @pascal-app/editor @pascal-app/nodes
```

```typescript
import { loadPlugin } from '@pascal-app/core'
import { builtinPlugin } from '@pascal-app/nodes'

await loadPlugin(builtinPlugin)
// 然后挂 <Viewer />
```

### 3) Clone monorepo 本地开发

```bash
git clone https://github.com/pascalorg/editor
cd editor
bun install
bun dev
# http://localhost:3002
```

> 重要:`bun dev` 必须从根目录跑,会触发 core / viewer 的 watch + Next.js editor dev server,改 `packages/core/src/` 或 `packages/viewer/src/` 能 hot reload。

## 技术栈

| 层 | 选型 |
|---|---|
| 渲染 | Three.js + **WebGPU renderer** |
| 3D 框架 | React Three Fiber + Drei |
| 应用框架 | Next.js 16 + React 19 |
| 状态 | Zustand(3 store 分层)+ Zundo(undo/redo) |
| Schema | Zod |
| 几何布尔 | three-bvh-csg |
| Monorepo | Turborepo |
| 包管理 | Bun |
| 类型 | TypeScript 96% |

## 编辑器架构(在 viewer 之上加的层)

- **Tools**:SelectTool / WallTool / ZoneTool / ItemTool / SlabTool
- **Selection Manager**:Site → Building → Level → Zone → Items,每层自己的 hover/click 策略
- **Editor 专属系统**:ZoneSystem(根据 level mode 控 zone 可见性)、自定义相机控制(节点 focus)
- **数据流**:用户操作 → Tool Handler → `useScene.createNode/updateNode` → store 标记 dirty → React re-render → `useRegistry` 注册 3D 对象 → 系统每帧处理 dirty 节点 → 更新几何

## 关键文件导航

| 路径 | 说明 |
|---|---|
| `packages/core/src/schema/` | Node type 定义(Zod schemas) |
| `packages/core/src/store/use-scene.ts` | 场景状态 store |
| `packages/core/src/hooks/scene-registry/` | 3D 对象 registry |
| `packages/core/src/systems/` | 几何生成系统 |
| `packages/viewer/src/components/renderers/` | Node 渲染器 |
| `packages/viewer/src/components/viewer/` | 主 Viewer 组件 |
| `apps/editor/components/tools/` | 编辑器工具 |
| `apps/editor/store/` | 编辑器专属状态 |

## 跟我们的关系

- **数字孪生 / BIM 调研** — StadiView 是纯展示 demo;PascalEditor 是真编辑器。直接对标工具:Unity、Unreal Editor、BIM 360、Planner 5D,但开源 + Web + MCP 集成是稀缺点。
- **品行者 / PINOKRS 业务** — 若要做"门店 3D 数字孪生 / 工厂 BIM / 设备 3D 建模后端",这个值得深挖(尤其 MCP → Agent 改场景的链路)
- **MCP 集成范式** — 看它怎么把"CRUD + 工具 + 资源 + prompt"封装成 MCP server,这种模式可以套到别的领域编辑器(地图 / 数据库建模 / 流程图)
- **架构隔离参考** — core / viewer / editor 三层强隔离 + AGENTS.md 把"不能 import 什么"写成铁律 → 对自家多模块项目有借鉴价值

## 风险与注意

- **2025-10 才创建**,8 个月 21k ⭐ 增长曲线,但还非常年轻,API 可能有 breaking change(v1 之前)
- **WebGPU** 是渲染默认,但不是所有浏览器都支持(Chrome 113+ / Edge 113+,Safari 18+,Firefox 实验);老浏览器会降级到 WebGL?
- **依赖度高**:Bun 锁住开发体验(虽然 production 可走 npm/turbo build),团队迁移成本
- **3.7k forks** 但 AGENTS.md 自己说"不要 backwards-compat shim / dead code / speculative abstraction" → 激进重构,跟随时要勤 bump version

## 参考链接

- GitHub: https://github.com/pascalorg/editor
- 在线编辑器: https://editor.pascal.app
- 开发者文档: https://editor.pascal.app/docs
- 插件 worked example: https://github.com/pascalorg/plugin-trees
- Discord: https://discord.gg/XRKsDcpqgS
- X / Twitter: https://x.com/pascal_app
- npm: https://www.npmjs.com/package/@pascal-app/core 等
- Trendshift: https://trendshift.io/repositories/23831

调研来源:GitHub repo `pascalorg/editor` API + raw README.md + AGENTS.md(2026-08-13)