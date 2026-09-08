# VGPU — Vercel Labs 的 WebGPU 库(25KB,TypeScript,Agent-Ready)

> 学习笔记 · 调研时间 2026-08-31
> GitHub: <https://github.com/vercel-labs/vgpu>
> 官网: <https://vgpu.sh>
> 示例: <https://vgpu.sh/examples>
> 调研文章: 微信公众号 (2026-08-31)

---

## 1. 一句话定位

**vgpu = "WebGPU 库,设计给 AI agent 用"** — Vercel Labs 出品,**TypeScript**,**Typed WGSL imports**(`.wgsl` 文件像 TS 模块一样 import/export),一个 `Gpu` context 跨 browser / headless Node / CI 三个 runtime,完整 fullscreen effect **gzip 后 25KB**,专为 LLM agent 设计的 CLI + docs。

## 2. 核心数据

| 字段 | 值 |
|---|---|
| **GitHub stars** | **1119** ⭐ (3.5 个月前发布) |
| **Forks** | 49 |
| **Size** | **108 MB** (大! 因为 examples 目录有大型 assets) |
| **Language** | TypeScript (99.8%) |
| **License** | **MIT** |
| **Homepage** | <https://vgpu.sh> |
| **Created** | 2026-05-05 (4 months ago) |
| **Updated** | 2026-08-31 (active) |
| **Node** | >=22 <23 |
| **Pkg manager** | pnpm 9.15.4 |

## 3. 8 大核心特性 (来自 README)

1. **Typed WGSL imports** — `.wgsl` 文件像 TS 模块一样 import/export,反射自动保持 binding names / types / layouts 正确,**无需手写声明**
2. **One `Gpu` context** — `init()` 返回单个 handle,所有 entry point (`draw`/`effect`/`frame`/`surface`/`target`/`set`) 都把 gpu 作为 first arg,**无隐藏全局状态**
3. **Small by design** — 未用 declarations 在 minify 前被剪,**完整 fullscreen effect gzip 后 25 KB**,CI 强制 budget
4. **Multi-runtime by default** — 同一 public API 跨 browser / headless Node (`vgpu/node`, Dawn-backed) / deterministic mock (`vgpu/mock`, 给 tests + CI)
5. **Explicit frames** — `frame(gpu, (f) => f.pass(target, effect))` — passes / clears / draws 都是 explicit calls,无 implicit scene-graph state
6. **Agent-ready** — Docs + examples + shader validation 都能从 CLI 跑 (`npx vgpu docs` / `npx vgpu examples` / `npx vgpu check`),[vgpu.sh](https://vgpu.sh) 发布 `agents.md` 和 `llms.txt` 给 LLM consumption
7. **Bundle budgets enforced** — `pnpm bundle-check` 跑 gzip size gates,client hard gate + tooling soft gate
8. **CI with real GPU** — `.github/dawn/Dockerfile` 跑 Dawn 在 Linux GPU 上做真实验

## 4. 8 大 packages (workspace)

```
vgpu-workspace/
├── packages/
│   ├── vgpu/              # Main entry, public surface
│   ├── vgpu-api/          # Effect/Frame/TG/etc core API types
│   ├── core/              # Gpu context, adapters base
│   ├── render/            # Render targets, surfaces, frames
│   ├── wgsl/              # Typed WGSL imports + bundler integration (webpack/vite)
│   ├── wgsl-std/          # WGSL standard library bindings
│   ├── adapter-node/      # Dawn-backed Node.js headless renderer
│   └── adapter-mock/      # Deterministic mock for tests
└── apps/
    ├── docs/              # vgpu.sh docs site
    └── agent-evals/       # Agent-driven evaluation suite (EVAL TASKS!)
```

## 5. Quick Start (5 行代码)

```ts
import { clock, init, effect, frameLoop, surface } from "vgpu";
import waveShader from "./wave.wgsl";

const gpu = await init();
const canvasSurface = surface(gpu, canvas, { dpr: [1, 2] });
const wave = effect(gpu, waveShader, { set: { speed: 2 } });

const time = clock(gpu);
frameLoop(gpu, (frame) => {
  wave.set({ time: time.time });
  frame.pass(canvasSurface, wave);
});
```

`init()` 获取 adapter + device → 单一 `Gpu` handle → 每个 entry point 接受它 → `surface` 包 canvas → `effect` 编译 shader → `set()` 按 WGSL 名字写 uniforms。

## 6. 4 大运行场景 (从官网截图)

| Scenario | Description |
|---|---|
| **WEB** | Interactive · Canvas (浏览器交互) |
| **IMAGE** | PNG · 8192 × 4608 (静态高分辨率渲染) |
| **VIDEO** | MP4 · 60 FPS (录屏渲染) |
| **CI** | Headless · Artifact (CI 截图对比) |

**关键**: **同一 shader 跨 4 场景** — 这就是 "Render everywhere" 的真正含义。

## 7. 4 个 Live Examples (从官网)

| Example | 描述 |
|---|---|
| **Black Hole** | Raymarched gravitational lensing — null geodesics 弯曲星光 + Keplerian accretion disk + Doppler beaming + HDR bloom chain |
| **Transmission** | 玻璃立方体折射 + Snell refraction + 色散 + Fresnel-weighted environment reflection |
| **Next.js Flare** | Next.js logo shader — rim-lit N + 48-step ray walk + volumetric scattering + Gaussian blur chain |
| **Depth Estimation** | ONNX Runtime Web + WebGPU — 从 photo 或 webcam 估 depth,zero-copy vgpu buffer wrap |

## 8. CLI 设计 (Agent-first)

```bash
npx vgpu docs      # read API (ls, cat, grep, find, path, symbols)
npx vgpu examples  # pull a reference
npx vgpu check     # validate WGSL
npx vgpu doctor    # repair the runtime
```

**核心哲学**: **CLI 是 agent 的 API** — 每个 tool 都是 LLM-friendly (text output, structured)。

## 9. Agent Evals (应用层评估)

`apps/agent-evals/` 跑 **agent-driven evaluation**:
- Agent 拿到 task (e.g. "用 vgpu 写一个 black-hole shader")
- Agent 在 sandbox 里跑
- 自动 evaluate shader 渲染结果
- Pass/fail

3 个内置 eval tasks:
- `n1-hero-shader` — 基础 hero shader 测试
- `s2-gradient` — gradient rendering
- `view-image-smoke` — image rendering smoke test

**这是 OpenAI evals 风格的 agent benchmarking**,直接集成在 repo 里。

## 10. Bundle Budget System

```json
"client" (default)         — browser-facing entries. Hard gate: 1 byte over = fail.
"tooling"                  — loaders / Node runtime / CLI / tarballs.
                              Soft gate: over budget warns, only fails past 5% growth.
```

```bash
pnpm bundle-check             # check budgets
pnpm bundle-check --update    # re-baseline (next 512B multiple)
```

→ **CI 强制 size 不超 25KB gzipped**, author 不能 偷偷加 dependency。

## 11. 6 大技术亮点

1. **WGSL-to-TS binding reflection** — `.wgsl` 文件 import 像 TS module,自动生成 TypeScript types
2. **Single `Gpu` context, no globals** — 跟 Three.js / Babylon.js 的全局 state 哲学相反,纯函数式
3. **Explicit frame()** — 没有隐式 scene graph,每次 frame 显式 pass + clear + draw
4. **Multi-adapter pattern** — `vgpu/node` (Dawn) / `vgpu/mock` (tests) 共享同一 API
5. **Pruned dead code at minify** — Shader 内未引用的 declarations 自动删除
6. **CLI as agent API** — 所有 docs/examples/check 都能从 terminal 跑,text output

## 12. 跟 Three.js / Babylon.js 对比

| 维度 | Three.js | Babylon.js | **vgpu** |
|---|---|---|---|
| API 范式 | OOP / class | OOP / class | **Functional (Gpu context)** |
| WebGL/WebGPU | WebGL (WebGPU 试验) | WebGL + WebGPU | **WebGPU only** |
| Bundle size | ~600 KB | ~2 MB | **25 KB gzipped** |
| Shader language | GLSL (WebGL), WGSL | GLSL / WGSL | **Typed WGSL + TS bindings** |
| Multi-runtime | Browser only | Browser | **Browser + Node + Mock** |
| Agent integration | None | None | **First-class (CLI + llms.txt + evals)** |
| 适用场景 | Complex 3D scenes | Games | **Shaders + GPU compute + AI viz** |
| 学习曲线 | Medium | Medium-High | **Low (functional, small API)** |

## 13. 跟 vgpu 对比 substation-blueprint (我的项目)

| 维度 | substation-blueprint | **vgpu** |
|---|---|---|
| 库 | Three.js r149 vendored | **WebGPU (直接)** |
| Bundle | 244 KB | **25 KB gzipped** |
| 主题切换 | 3 themes (manual) | **不需要(材质即代码)** |
| 资产 | 0 procedural | **WGSL 程序生成 + 14 张手绘** |
| 工具集 | OrbitControls + Raycaster | **`Gpu` + `frame()` + `set()`** |
| 单 HTML? | ✅ | ❌ (pnpm workspace) |
| Agent 集成 | 无 | **CLI + llms.txt + evals** |

**substation-blueprint 是 "visualization experience",vgpu 是 "raw compute + shader toolkit"**。vgpu 适合做:
- 后端 server-side shader rendering (用 `vgpu/node` + Dawn)
- 浏览器 AI 模型推理 (ONNX Runtime Web on WebGPU)
- 数据可视化 (实时 GPU compute on tensors)
- Agent 驱动的 shader 生成 (用 CLI 自动生成 + test)

## 14. 适用 substation-blueprint / 我自己的场景

1. **如果想要 server-side render**: 用 `vgpu/node` + Dawn,可以替代我手动 spawn browser screenshot
2. **如果想要 shader 集成**: `vgpu` 的 WGSL TS bindings 比 Three.js 的 `ShaderMaterial` 更类型安全
3. **如果做 agent-driven content**: vgpu 的 CLI + evals 是学习榜样 (我的 OpenOPC 也可以加 evals)
4. **小尺寸优势**: 25 KB gzip 适合嵌入到 data dashboard / ML tools
5. **如果想做 AI viz**: ONNX Runtime + vgpu = 端到端 AI inference + rendering

## 15. 9 大工程亮点 (Deep dive)

1. **Typed WGSL** — 不是字符串拼接,而是 `.wgsl` 文件的 reflection
2. **25 KB gzipped hard limit** — CI 强制,`pnpm bundle-check` 自动验证
3. **Multi-adapter (Node/Mock/Browser)** — 同一份代码,3 个 runtime
4. **CLI-as-Agent-API** — docs/examples/check/doctor 都是 LLM-friendly output
5. **Agent Evals in-repo** — 不是 README demo,而是 `apps/agent-evals/` 跑 sandbox eval
6. **Dawn CI** — `.github/dawn/Dockerfile` 跑 Dawn on Linux GPU 做真实验
7. **`agents.md` + `llms.txt`** — 直接给 LLM 消费的 docs
8. **Bundle budgets tiered** — client hard gate + tooling soft gate + 5% growth threshold
9. **Hermes analogy** — 跟 hermes-agent 的 "per-conversation prompt caching is sacred" 哲学相似,vgpu 的 "25KB bundle is sacred"

## 16. 相关 iswiki 项目

- **[redradman/artemis](artemis-redradman.md)** (44 ⭐) — 同范式 Three.js wireframe
- **[kage](kage.md)** (1407 ⭐) — 同范式 Three.js + scroll-driven
- **[vercel-labs/vgpu](vgpu.md)** (1119 ⭐) — 本文 (WebGPU library)
- **[openclaw-awd-arena](openclaw-awd-arena.md)** (319 ⭐) — 同 agent-first 哲学

## 17. TL;DR

**vgpu = Vercel Labs 出的 WebGPU 库,专为 AI agent 设计**。1119 ⭐,TypeScript,Typed WGSL imports,multi-runtime (browser/Node/mock),25KB gzipped hard limit,CLI-first API design,内置 agent evals。

**3 大最佳应用**:
- **WebGPU shader 编程** — 比 Three.js ShaderMaterial 更类型安全,比 Babylon.js 轻 80x
- **Server-side shader rendering** — Node + Dawn 跑 headless,无 browser overhead
- **Agent-driven content generation** — CLI + llms.txt + 内置 evals

**最值得学的 1 点**: **"25KB bundle is sacred"** — 跟 Hermes 的 "per-conversation prompt caching is sacred" 类似,vgpu 用 CI 强制 bundle size,保证 API surface 不臃肿。**substation-blueprint 应该学这种 "self-imposed hard limits"** — 比如 enforce "no asset > 2MB" 或 "single HTML < 300KB" 之类。

# 写文档
