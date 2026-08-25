# Artemis (redradman) — Three.js 复刻 NASA 载人登月任务

> 学习笔记 · 调研时间 2026-08-25
> 仓库: <https://github.com/redradman/artemis>
> 介绍文章: <https://mp.weixin.qq.com/s/XA3EZ2TXlyJtbGfpf0RY_Q> ("三木前端笔记" 公众号, 2026-06-28)
> 作者: Reza Radman (@redradman)
> ⭐ 44 · 11 forks · TypeScript · MIT License · 128 MB
> Created 2026-04-22 · 0 open issues · Homepage: <https://artemis.radman.dev/>

## 一句话定位

**"Three.js 在浏览器里复刻了 NASA 载人登月任务"** —— 用 14 个阶段 + 16 个可点击飞行器组件 + 3 种视觉主题(Blueprint / Space / Cinematic),把 Artemis II 从 **T+0:00:00 SLS 点火**到 **T+217:46:00 溅落太平洋**的完整飞行剖面搬进浏览器。**数据密度比一般 Three.js demo 高很多** —— 每个 T+ 时间精确到秒,飞行器参数**引用 NASA 原始文件页码**。

## 跟 iswiki 现有工具对比

| 工具 | 关系 |
|---|---|
| [kage](kage.md) | 🟡 同样 Three.js demo,但 kage 偏 Poetic art,这个偏 data-driven scientific |
| [wfu](wfu.md) | ⚪ 完全不同领域 |
| [pasoflow](pasoflow.md) | ⚪ 不同领域 |

## 6 大核心数据点

### 14 个飞行阶段(T+ 精确到秒)

| Phase | T+ | 描述 | 数据来源 |
|---|---|---|---|
| LIFTOFF | 00:00:00 | 四台 RS-25 + 双固体助推器,**880 万磅推力** | p.40, 48, 50, 97 |
| MAX-Q | 00:01:11 | 43,795 ft, 1,041 mph | p.40, 47 |
| SRB SEP | 00:02:08 | 148,384 ft, 3,006 mph (Mach 4.3) | p.40, 48, 50 |
| LAS JETT | 00:03:28 | 286,146 ft, 4,487 mph | p.97–98 |
| MECO | 00:08:06 | 511,884 ft, 17,599 mph (Mach 23), 燃尽 537k 加仑液氢 + 196k 加仑液氧 | (推测 p.97) |
| TLI | 25:37:00 | 第 2 飞行日,欧洲服务舱主发动机点火 (Trans-Lunar Injection) | (推测) |
| LUNAR FLYBY | 121:23:20 | 第 5 飞行日,**4,700 英里月球背面**, 超越 Apollo 13 | (推测) |
| ENTRY | 217:33:00 | 25,000 mph 大气层,**186 块 Avcoat 烧蚀材料**, 5,000°F | (推测) |
| SPLASHDOWN | 217:46:00 | **11 伞系统 (3+2+3+3)**, **36,000 平方英尺** 总面积, 圣地亚哥海域 | (推测) |

→ **每个 phase 都有 `sources: ['artemis-ii-reference-guide p.X', ...]`** 字段 — **真源页码**!

### 16 个可点击飞行器组件

| Component | Kicker | 关键参数 |
|---|---|---|
| Launch Abort System (LAS) | Lockheed Martin | **400,000 lb peak thrust**, 2 秒加速到 400-500 mph |
| Heat Shield | - | 186 块 Avcoat, Apollo 改进版 |
| Solid Rocket Booster (×2) | Northrop Grumman | 每个 **330 万磅推力** |
| Core Stage LH2 Tank | Boeing | 537,000 加仑, −423°F |
| ICPS Upper Stage | Boeing/ULA | RL10C-2 engine (24,750 lb thrust) |

→ 组件也有 `anchor / focus / focusRadius` (Vector3) — **精准定位 3D 场景**

### 3 种视觉主题

| Theme | 风格 | 用途 |
|---|---|---|
| **Blueprint** | 线框工程图 | 默认启动,**看分离结构** |
| **Space** | 深空环境照明 | 真实飞行视角 |
| **Cinematic** | 戏剧性打光 | 视觉冲击 |

→ 切换通过 Zustand store 的 `renderMode` 字段,**React Three Fiber 材质系统响应状态实时重渲染**

## 完整目录结构 (128 MB)

```
artemis/
├── src/scenes/ArtemisII/                # 主场景
│   ├── data/                            # 静态数据
│   │   ├── phases.ts                    # 14 个飞行阶段 (含 NASA 源页码)
│   │   ├── components.ts                 # 16 个飞行器组件 (含 3D 坐标)
│   │   └── mission.ts                    # 任务级 metadata
│   ├── effects/                          # 11 个视觉效果组件
│   │   ├── BloomHalo.tsx                # 发光晕
│   │   ├── CapsulePendulum.tsx          # 摆动效果
│   │   ├── CelestialBodies.tsx          # 天体
│   │   ├── CinematicShell.tsx           # 电影外壳
│   │   ├── EntryPlasma.tsx              # 大气再入等离子体
│   │   ├── HybridDetails.tsx            # 混合细节
│   │   ├── MissionEffects.tsx           # 任务效果聚合
│   │   ├── Parachutes.tsx               # 降落伞 (3+2+3+3 系统)
│   │   ├── ParticleJet.tsx              # 粒子喷射
│   │   ├── RcsPuffs.tsx                 # RCS 推力器烟雾
│   │   └── SepMotorPuffs.tsx            # 分离发动机烟雾
│   ├── geometry/                          # 几何
│   │   ├── Wire.tsx                       # 线框渲染器
│   │   └── buildWire.ts                   # 线框构建工具
│   ├── parts/                            # 7 个模块化零件
│   │   ├── CoreStage.tsx
│   │   ├── CrewModule.tsx
│   │   ├── ICPS.tsx
│   │   ├── LaunchAbortSystem.tsx
│   │   ├── ServiceModule.tsx
│   │   ├── SolidRocketBooster.tsx
│   │   └── (1 more)
│   ├── lib/
│   │   └── stateAt.ts                    # **time → state mapper** (核心)
│   ├── materials.ts                      # 3 主题材质
│   └── index.tsx                         # 场景入口
├── src/store/                            # Zustand missionStore
├── src/components/                       # UI 组件
├── src/hooks/                             # React hooks
├── src/lib/                               # 通用工具
├── src/assets/                            # 静态资源
├── src/styles/                            # 全局样式
├── docs/
│   ├── sources/                          # **NASA 原始 PDF** (Reference Guide + Timeline)
│   │   ├── artemis-ii-reference-guide.pdf
│   │   └── artemis-ii-timeline.pdf
│   └── media/                             # GIF + PNG 截图
├── public/og-artemis-ii.png               # OG image
├── Dockerfile                             # Railway 部署
├── railway.json                           # Railway config
├── package.json (pnpm)
├── vite.config.ts                         # Vite build
├── tsconfig.*                              # TS configs
└── README.md (1234 bytes)
```

## 5 大技术实现要点

### 1. **Time-driven scene state** (核心)
```ts
// src/scenes/ArtemisII/lib/stateAt.ts
// 把归一化时间 (0-1) 映射到飞行器姿态/推进/质量状态
export function stateAt(t: number) {
  // ...lerp positions, throttle, mass based on phases
}
```

### 2. **Zustand central store**
```ts
// missionStore.ts — 集中管理
{
  currentT: 0..1,        // 归一化时间
  playing: boolean,      // 播放状态
  activeComponent: id,  // 当前打开的组件
  renderMode: 'blueprint'|'space'|'cinematic',
  autoRotate: boolean,
}
```

### 3. **Panel-aware auto-pause**
- 打开组件面板 → 自动暂停
- 关闭面板 → 自动继续
- 状态机在 store 里,**不散落到组件层**

### 4. **Multi-theme material system**
- Blueprint: 线框风格
- Space: 深空光照
- Cinematic: 戏剧化打光
- 同一个 `materials.ts` 提供 3 套,**`renderMode` 切换时实时重渲染**

### 5. **Data-driven from NASA original docs**
- 数据写在 `data/phases.ts` 和 `data/components.ts`
- 每个数据点都有 **`['artemis-ii-reference-guide p.40', ...]`** 字段
- 可以凭数据点追溯到原始 PDF 页码

## 启动命令

```bash
git clone https://github.com/redradman/artemis.git
cd artemis
nvm use    # 读取 .nvmrc 中的 Node 版本
pnpm install
pnpm dev   # 访问 http://localhost:5173
```

生产构建: `pnpm build && pnpm start`

## 8 大工程亮点

1. **Data density 极高** — 14 phases × T+秒级精度
2. **NASA 源页码注释** — 每个数据点可追溯
3. **7 个模块化 parts** — 独立 `<ComponentName>.tsx` 文件
4. **11 个 effects** — BloomHalo / EntryPlasma / Parachutes / etc
5. **3 主题 wireframe 风格** — 默认 Blueprint 看分离结构
6. **Time → state mapping** 干净 (lib/stateAt.ts)
7. **Zustand 中央状态** — 不散落到组件层
8. **完全客户端** — 无后端,Docker 部署 Railway

## 5 大可借鉴 Three.js 模式

1. **Time-driven scene state** — 归一化时间 (0-1) 驱动所有 visual params
2. **Zustand 单 store** — 复杂 UI state 不散落
3. **Multi-theme material system** — `materials.ts` 三套,响应 store
4. **Modular parts directory** — 每个 flight component = 1 file
5. **Auto-pause on interaction** — 用户看组件时暂停动画,关闭继续

## 数据驱动开发完整流程

```
NASA 原始 PDF (Reference Guide + Timeline)
    ↓ 提取
data/phases.ts (14 phases) + data/components.ts (16 components)
    ↓ 渲染
parts/* + effects/* + materials.ts
    ↓ 时间驱动
lib/stateAt.ts (time → state)
    ↓ Zustand 协调
store/missionStore.ts (currentT, renderMode, ...)
    ↓ UI
components/* (timeline + panels + buttons)
```

## 适用场景

| ✅ 适合 | ❌ 不适合 |
|---|---|
| **科学可视化**(mission / flight / physics sim) | 商业产品 3D demo |
| **教育内容**(interactive textbook) | 高频实时游戏 |
| **数据密度高的 3D 教学**(museum, archive) | 简单 marketing 网站 |
| **Three.js 学习** (state management 范本) | 移动端 heavy 3D (canvas 性能) |

## 限制

- **依赖具体 NASA 数据** — 换任务/换飞行器需重写 `data/`
- **128 MB repo size** — `pnpm-lock.yaml` 109 KB + docs/PDF 比较大
- **TypeScript + pnpm** — 学习曲线
- **React Three Fiber** — 不是纯 Three.js,要理解 R3F 的 declarative model
- **无服务器** — 客户端 only (适合 static deploy)

## 类似 / 对比项目

| 项目 | 关系 |
|---|---|
| **Three.js examples** | 通用,但没有这种 data-density 教学 |
| **NASA Eyes** (eyes.nasa.gov) | 官方,WebGL 但技术栈不同 |
| **MapLibre / Kepler.gl** | 同样数据驱动 3D, 不同领域 |
| **CesiumJS** | 地球/航天可视化专用 |

## 关联资料

- 仓库: <https://github.com/redradman/artemis>
- 主页: <https://artemis.radman.dev/>
- 文章: <https://mp.weixin.qq.com/s/XA3EZ2TXlyJtbGfpf0RY_Q> ("三木前端笔记")
- 作者: <https://x.com/redradman>
- License: MIT
- Stack: TypeScript + Vite + React Three Fiber + Zustand
- 部署: Railway (Docker)
- 文档: `docs/sources/` 包含 **NASA 原始 PDF** (Reference Guide + Timeline)

## 🎯 TL;DR

== **核心 insight**(3 个学习点):

| # | 模式 | 用在哪里 |
|---|---|---|
| 1 | **Data density + NASA 源页码注释** | 任何科学 / 工程 / 教育 3D |
| 2 | **Zustand central store + auto-pause on interaction** | 任何 interactive 3D / 2D viewer |
| 3 | **Multi-theme material system** (Blueprint/Space/Cinematic) | 任何"演示型 3D app" |

== **给 Three.js 开发者的 3 个直接参考**:
- **状态管理**:Zustand 集中(不散落到 component 层)
- **时间轴驱动**:`lib/stateAt.ts` 把归一化时间映射到 visual params
- **数据组织**:`data/*.ts` 静态 + `parts/ + effects/` 模块化渲染

== **跟 [kage](kage.md) 对比**:
- **kage**: 5 章 art / 24 frames / 单一 visual style (Phaser pixel)
- **artemis**: 14 phases / 实时交互 / **3 主题切换** (Blueprint/Space/Cinematic)
- **kage 偏 poetic, artemis 偏 scientific**

→ **两个项目可作为 Three.js 两种哲学的对照样本**:
- kage = **craft + 美术**
- artemis = **data + 工程**