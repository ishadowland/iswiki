# ArmorPaint — 开源 PBR 纹理绘制工具技术选型参考

> 学习笔记 · 调研时间 2026-09-13
> 原文: 微信公众号「智能时代蛮子」— *GitHub 推荐:9 年写出的开源 PBR 神器 ArmorPaint 凭什么让 Substance 用户叛逃*
> URL: <https://mp.weixin.qq.com/s/_idKh-ixPG-4LEjgbHe5pQ>
> 仓库: <https://github.com/armory3d/armorpaint>
> Stars: **4.9K** · 贡献者: 35 · 代码: 31.4 万行 · 项目年龄: 9 年 · License: zlib

> ⚠️ **关于本文**:**原文质量较差**(营销话术多、术语混乱、技术细节堆砌但不分类),本文做了**大量删减 + 重组 + 重写**,目标是给初级前端 / PM 一份**清晰的技术选型参考**。

---

## 0. 一句话定位(PM 友好)

**ArmorPaint** 是一款**开源的 3D 纹理绘制工具**(PBR 材质绘制),由 Lubos Lenco 单人主导 9 年打造,挑战 Adobe **Substance Painter**(订阅制商业软件)的市场地位。

== **如果你是 PM,只需要知道三件事**:
1. 它能**替代 Substance Painter**(给 3D 模型画贴图、画材质)
2. **买断制**(¥280 一次性),不订阅
3. 工具链**全平台 + 单文件部署(< 10 MB)+ 支持本地 AI 推理**

---

## 1. 来龙去脉(故事背景)

### 1.1 项目起源

- **创始人**: Lubos Lenco (GitHub: `luboslenco`)
- **公司**: Armory 3D 开源组织(类似 Blender Foundation,但更小众)
- **起点 (2014)**: Lubos 在做 Armory3D 游戏引擎时,**自己也需要给 3D 模型画 PBR 贴图**,但用 Blender 觉得工作流碎、用 Substance 又贵又绑平台
- **结论**:**自己写一个**(dogfooding 模式:不是为了卖,是为了自用)

### 1.2 9 年时间线

| 年份 | 里程碑 |
|---|---|
| 2014 | Lubos 启动 Armory3D 游戏引擎项目 |
| 2017 | **Armorpaint 仓库建立**(第一个 commit 2017-12-14) |
| 2018-2022 | 单人维护,缓慢迭代 PBR 绘制核心 |
| 2023 | 加入**节点图编辑器** + **自研 path-tracer** |
| 2024 | 加入**本地 AI 模型推理**(FLUX.2 / Real-ESRGAN) |
| 2026 | **v0.11.x**(现在),4.9K ★,月均 100+ commit,Substance 订阅化后的接替者 |

### 1.3 为什么是现在值得关注?

- **Adobe 把 Substance 改成纯订阅**(2023 起),独立美术 / 中小工作室负担加重
- **本地 AI 模型推理成熟**(2024 后,GGUF + llama.cpp 生态爆发)
- ArmorPaint 同时打中两个痛点:**订阅逃逸 + AI 本地化**

---

## 2. 技术背景(给前端开发能理解的版本)

### 2.1 PBR 纹理绘制是个啥?

**PBR** = Physically Based Rendering(基于物理的渲染)
**纹理绘制** = 给 3D 模型「刷油漆」,在表面画材质、画磨损、画贴花

| 概念 | 类比 |
|---|---|
| **3D 模型** | 一个空白的塑料玩具 |
| **PBR 贴图** | 给玩具画的「涂装」(颜色 + 粗糙度 + 金属感 + 法线)|
| **绘制工具** | 数字版「喷漆工具箱」 |

== **类比给前端**:PBR 纹理绘制 ≈ **3D 版的 Photoshop 绘图**

### 2.2 ArmorPaint 的技术栈(简化版)

== **不要被原文的术语堆砌吓到**,核心结构就 4 层:

```
┌─────────────────────────────────────────┐
│ 第 4 层:ArmorPaint 应用                  │ ← 你看到的 UI
├─────────────────────────────────────────┤
│ 第 3 层:Kong 节点图编译器                │ ← 节点拖拽 → 编译成 shader
├─────────────────────────────────────────┤
│ 第 2 层:Iron 3D 引擎 + minic 脚本        │ ← 自研引擎 + C 子集脚本
├─────────────────────────────────────────┤
│ 第 1 层:5 套 GPU 后端(Vulkan/D3D12/     │ ← 同一份 IR → 不同 GPU API
│         Metal/OpenGL/WebGPU)             │
└─────────────────────────────────────────┘
```

### 2.3 关键技术概念(前端能懂的版本)

| 概念 | 是什么 | 前端类比 |
|---|---|---|
| **节点图** | 拖拽节点连线,描述「材质怎么算」 | 类似 **ComfyUI / RAG 流程编排** |
| **Path tracer** | 离线渲染,精确模拟光线 | 类似 **SSR**(但 3D 版)|
| **PBR shader** | 顶点/片元着色器,GPU 上跑 | 类似 **WebGL fragment shader** |
| **GGUF** | 本地 AI 模型格式 | 类似 **ONNX** 但更轻 |
| **WASM** | 浏览器编译目标 | 你知道的 |

### 2.4 5 套 GPU 后端是咋回事?

== **同一份节点图** → 编译成**不同 GPU 的着色器**:
- **Vulkan**: Linux/Steam Deck/新硬件
- **D3D12**: Windows
- **Metal**: macOS/iOS
- **OpenGL**: 兼容性后备
- **WebGPU**: 浏览器

== **类比给前端**:类似 **Babel/SWC 把同一份 TS 编译成 ES5/ES2020** — 同一份源码,不同目标平台。

### 2.5「主程序 < 10 MB」是怎么做到的?

- **自己写 3D 引擎**(Iron)
- **自己写窗口系统**
- **自己写 UI 框架**(Zui)
- **自己写 shader 编译器**(Kong)
- **自己写嵌入式 C 脚本**(minic)
- **自己写 C 数学库**(armorcore)
- → **零运行时依赖,单 exe 部署**

== **类比给前端**:类似 **Svelte 把 runtime 编进 bundle**(而非运行时引入)— 所有依赖都「内化」。

---

## 3. 适用场景(PM 视角)

### 3.1 ✅ 适合谁?

| 角色 | 用途 | 为什么适合 |
|---|---|---|
| **独立 3D 美术** | 个人项目 / 自由职业 | 不用订阅,可买断;本地 AI 辅助 |
| **中小工作室**(5-20 人)| 独立游戏 / 影视道具 | 团队订阅成本高,买断 + 开源省 |
| **Linux/macOS 用户** | 跨平台需求 | Substance Linux 支持弱,Mari 不支持 |
| **游戏开发者** | 配合 Armory3D 引擎 | 同组织产品,深度集成 |
| **3D 打印 / 数字孪生** | 模型材质精细化 | PBR 渲染逼真度高 |
| **教育机构 / 个人学习** | 教学用 | 免费版可用(zlib 源码)|

### 3.2 ❌ 不适合谁?

| 角色 | 用途 | 为什么不适合 |
|---|---|---|
| **大型 3A 工作室** | 数十人美术流水线 | Substance 生态成熟、Adobe 集成深 |
| **Windows-only 用户** | 已经在 Substance 生态 | 迁移成本高 |
| **不画 PBR 材质的用户** | 只需要建模 / 雕刻 | 应该用 Blender / ZBrush |
| **需要节点图高级功能** | 复杂 procedural 材质 | Substance Designer 更专业 |

### 3.3 关键场景案例

```
典型工作流:
1. 美术在 Blender/Maya 建模
2. 导出 .fbx / .obj 到 ArmorPaint
3. 用节点图绘制材质(基础色 + 粗糙度 + 法线)
4. 调用本地 AI(FLUX.2 生成纹理草图,Real-ESRGAN 提升分辨率)
5. 烘焙 → 输出贴图
6. 导入游戏引擎(Unity / Unreal / Godot / Armory3D)
```

---

## 4. 技术架构(给前端开发详细版)

### 4.1 完整架构图(从应用到底层)

```
[ ArmorPaint 应用 ] (10 MB 单 exe)
├── UI 框架 Zui (IMGUI 风格)
├── 节点编辑器 (画布 + 节点 + 连线)
├── 工具栏 / 笔刷引擎
├── 历史/撤销 (数组快照实现)
│
[ Kong shader 编译器 ] (节点图 → shader)
├── 节点图 IR
├── 类型推断 / 优化
├── 代码生成(5 套后端)
│   ├── Vulkan SPIR-V
│   ├── D3D12 DXIL
│   ├── Metal MSL
│   ├── GLSL
│   └── WebGPU WGSL
│
[ Iron 3D 引擎 ] (自研,跟 Armory3D 共用)
├── 场景图 / 网格加载 (.fbx/.obj/.gltf)
├── 资源管理 (armorpack 二进制格式)
├── 资产 I/O (zip + json)
│
[ minic 脚本引擎 ] (嵌入式 C 子集)
├── 解析器
├── 类型系统(struct 布局通过 offsetof 透传)
├── 字节码编译
│
[ armorcore C 库 ] (数学 + IO)
├── 向量 / 矩阵 / 四元数
├── 文件 I/O / 内存管理
│
[ 5 套 GPU 后端 ] (同一份 IR → 不同 GPU API)
│
[ 本地 AI 模型 ] (子进程按需拉取)
├── FLUX.2 (8GB+, HF 拉取)
├── Real-ESRGAN (超分辨率)
├── Hunyuan3D (3D 生成)
└── 推理在用户显卡,不上云
```

### 4.2 5 个值得前端借鉴的工程模式

#### ① 节点图 + 多后端单趟编译(Kong 编译器)

```typescript
// 前端类比:类似 webpack/rollup/vite 的多 target 编译
// 同一份节点图配置 → 不同 GPU 的 shader 代码

const nodeGraph = {
  nodes: [
    { type: 'TextureSample', inputs: ['uv', 'tex'] },
    { type: 'Multiply', inputs: ['a', 'b'] },
    { type: 'Output', inputs: ['rgb'] }
  ],
  edges: [
    { from: 'node1.out', to: 'node2.a' },
    { from: 'node1.rgb', to: 'node2.b' },
    { from: 'node2.out', to: 'node3.rgb' }
  ]
};

// 编译成 5 种 GPU 代码
kong.compile(nodeGraph, { target: 'vulkan' });   // SPIR-V
kong.compile(nodeGraph, { target: 'd3d12' });    // DXIL
kong.compile(nodeGraph, { target: 'metal' });    // MSL
kong.compile(nodeGraph, { target: 'webgpu' });   // WGSL
```

#### ②「主程序 < 10 MB + 重模型走子进程」桌面 AI 集成模式

```
应用启动(< 10 MB)
├── 检查本地 AI 模型缓存
├── 需要 FLUX.2? → spawn 子进程
│   └── 子进程:从 HuggingFace 下载 → 加载到显存 → 推理
├── 需要 Real-ESRGAN? → spawn 子进程
│   └── ...
└── 主程序永远轻,GPU 显存按需加载
```

== **类比给前端**:类似 **Code Splitting / 懒加载** — 首屏小,功能按需加载。

#### ③ 嵌入式 C 脚本 + struct 布局透传(minic)

== **核心创新**:用 `offsetof(struct)` 跨语言共享内存布局,**避免序列化**。

```c
// C 端
struct Material {
    vec3 albedo;
    float roughness;
    vec3 normal;
};
Material m = {{0.5, 0.5, 0.5}, 0.8, {0, 0, 1}};
// 把 m 直接交给 minic 脚本,无需 JSON 序列化
```

== **类比给前端**:类似 **SharedArrayBuffer**(多线程/多语言共享内存,无拷贝)。

#### ④ IMGUI + 节点画布纯数据模型

== **撤销/重做 = 数组快照**(无版本号对比,直接恢复):

```typescript
const undoStack: SceneState[] = [];
const redoStack: SceneState[] = [];

function applyAction(action: Action) {
  undoStack.push(clone(currentState));
  redoStack.length = 0;
  currentState = action.apply(currentState);
}

function undo() {
  if (undoStack.length > 0) {
    redoStack.push(currentState);
    currentState = undoStack.pop()!;
  }
}
```

== **简单粗暴但有效**,对比 Redux 时间旅行更轻量。

#### ⑤ TCC(Tiny C Compiler) 嵌入仓里

== **把 TCC 编译器的 C 源码拖进自己的代码仓库**,意味着:
- **任何平台都能「裸机编译」**(不需要系统装 C 编译器)
- WASM / iOS 这类**难装工具链的目标**特别有用
- 但增加了 ~80MB 仓库体积

== **类比给前端**:类似 **Babel 把所有插件都打进 bundle**(虽然大,但不依赖外部)

---

## 5. 跟其他方案对比(PM/技术选型必看)

### 5.1 PBR 纹理绘制工具 5 大主流方案

| 方案 | 价格 | 跨平台 | 节点材质 | 实时 path-tracer | 本地 AI | 开源 | 体积 |
|---|---|---|---|---|---|---|---|
| **ArmorPaint** | **¥280 买断** | ✅ 全平台 | ✅ Kong | ✅ | ✅ FLUX.2 等 | ✅ zlib | **< 10 MB** |
| **Substance Painter** | **$239/年订阅** | Win/macOS | ❌ | ❌ | ❌ | ❌ | 数 GB |
| **Mari** | 商业授权(贵)| Linux 为主 | ❌ | 弱 | ❌ | ❌ | 数 GB |
| **3D-Coat** | 部分免费 | Windows 优先 | ❌ | ❌ | ❌ | 部分 | 数 GB |
| **Blender Texture Paint** | 免费内置 | 全平台 | 弱 | 弱(CPU)| 弱 | ✅ GPL | Blender ~200 MB |

### 5.2 详细对比分析

#### vs Substance Painter(主要对手)

| 维度 | ArmorPaint | Substance Painter |
|---|---|---|
| **价格** | ¥280 买断,**一次性** | $239/年,**订阅** |
| **10 年成本** | ¥280 | **¥17,000+**(持续订阅) |
| **生态** | 小众,**独立美术圈** | 成熟,**大厂标准** |
| **PBR 质量** | 商业级(可对标) | 商业级(略好) |
| **AI 集成** | **本地**(8GB+ 模型) | 云端(Adobe Firefly) |
| **跨平台** | Win/macOS/**Linux**/Android/iOS/WASM | 仅 Win/macOS |
| **二进制体积** | **< 10 MB** | 数 GB |
| **离线可用** | ✅ | ❌ 需登录 |
| **数据安全** | 本地,**不上云** | 提交到 Adobe 服务器 |

== **ArmorPaint 优势**:**订阅逃逸 + Linux 支持 + 本地 AI**
== **Substance 优势**:**生态成熟 + 性能优化更好 + 团队协作强**

#### vs Blender Texture Paint(免费对手)

| 维度 | ArmorPaint | Blender |
|---|---|---|
| **定位** | 专门画贴图 | 一体化 DCC(建模+雕刻+绘制) |
| **节点材质** | ✅ Kong(强)| 弱(主要是 shader graph,不是 PBR 绘制专用)|
| **Path tracer** | ✅ 自研,实时 | CPU only,慢 |
| **生态** | Armory3D 工具链 | Blender Foundation(巨大) |
| **学习成本** | 中(独立工具) | 高(整个 Blender) |
| **代价** | ¥280 | 免费(但体积大)|

== **ArmorPaint 优势**:**专注 + 轻量 + 专业**
== **Blender 优势**:**免费 + 一体化 + 生态大**

#### vs 3D-Coat

| 维度 | ArmorPaint | 3D-Coat |
|---|---|---|
| **Voxel 雕刻** | ❌(独立模块未完成) | ✅ 核心功能 |
| **PBR 绘制** | ✅ | ✅ |
| **跨平台** | 全 | 弱(Windows 优先) |
| **价格** | ¥280 | $399 买断 |
| **体积** | < 10 MB | 数 GB |

== **ArmorPaint 优势**:**更轻 + 更跨平台**
== **3D-Coat 优势**:**雕刻能力更强**

### 5.3 关键决策表

| 你的情况 | 推荐方案 |
|---|---|
| 独立美术,做独立游戏 | **ArmorPaint** ✅ |
| 团队 10+ 人,商业项目 | **Substance Painter** ✅ |
| 免费 + 一体化需求 | **Blender** ✅ |
| 需要雕刻 | **3D-Coat** ✅ |
| Linux 主力 | **ArmorPaint** ✅ |
| macOS 订阅不敏感 | **Substance Painter** ✅ |
| 预算 ¥0 | **Blender / ArmorPaint 免费试用** ✅ |

---

## 6. 限制与风险(选型前必看)

### 6.1 5 大硬限制

| 限制 | 详情 |
|---|---|
| **🚨 单一作者** | Lubos 96% 贡献率,他出意外项目就停滞 |
| **🚨 文档薄弱** | 无 API 文档 / 无架构 ADR / 无 CHANGELOG |
| **🚨 构建复杂** | 自研工具链(Kha/Kromx/Iron/amake)+ 多平台多 GPU 后端 |
| **🚨 Sculpting 未完成** | 雕刻模块长期 in development,核心承诺未交付 |
| **🚨 商业模式脆弱** | 依赖独立用户付费意愿,Adobe 一改买断制就会冲击 |

### 6.2 适用边界

| 场景 | 是否可用 | 备注 |
|---|---|---|
| 独立美术买断 | ✅ 强烈推荐 | 性价比最高 |
| 中小工作室(5-20 人)| ✅ 推荐 | 长期成本低 |
| 大厂生产线 | ⚠️ 谨慎 | 生态不成熟,招聘难 |
| 关键路径(主力)| ⚠️ 谨慎 | 单点失败风险 |
| 教学 | ✅ 推荐 | 价格友好 |
| 模型雕刻 | ❌ 不行 | 用 ZBrush / 3D-Coat |

### 6.3 跟前端项目的类比限制

== **类比前端项目**:
- **单一作者** = 「只有一个 core contributor,一旦离职项目死」
- **文档薄弱** = 「没有 JSDoc / Storybook / 文档站点」
- **构建复杂** = 「自研 webpack 插件,踩坑没人能帮你」
- **Sculpting 未完成** = 「路线图上的核心 feature 一直没交付」

== **结论**:**适合早期采用者 + 独立开发者**,**不适合关键业务主线**。

---

## 7. 行动建议(PM 视角)

### 7.1 选型 checklist

- [ ] **你的团队规模?** 1 人 / 10 人 / 100 人?
- [ ] **预算模式?** 买断 ¥280 / 订阅 ¥1700+/年 / 免费?
- [ ] **平台需求?** Win / macOS / Linux / 浏览器?
- [ ] **是否需要 AI 集成?** 本地 / 云端 / 不需要?
- [ ] **是否在意数据隐私?** 本地处理 / 可上传云?
- [ ] **生态依赖?** 需要跟 Substance 团队协作吗?
- [ ] **长期可持续?** 商业软件公司可能并购吗?

### 7.2 实施建议

| 阶段 | 动作 |
|---|---|
| **第 1 周** | 下载试用版,zlib 源码,看能否编译 |
| **第 2 周** | 导入现有项目模型,测试工作流 |
| **第 3 周** | 评估 AI 模型推理效果(本地硬件是否够) |
| **第 4 周** | 团队小范围推广(1-2 人)|
| **第 5 周** | 评估 ROI,决定是否买断 / 切换 |

### 7.3 风险缓解

| 风险 | 缓解策略 |
|---|---|
| Lubos 单点失败 | **不要把所有模型放 ArmorPaint**,保持 .fbx/.obj 中性格式 |
| 文档薄弱 | 加入 **DeepWiki**(社区 wiki 已收录) |
| 构建困难 | 优先用**官方二进制**(¥280),不要自编译 |
| AI 模型大 | 用 SSD + 充足磁盘,模型可清理 |

---

## 8. 技术选型总结(给 PM 的 1 句话)

> **ArmorPaint = Substance 订阅逃逸 + Linux 友好 + 本地 AI**,**适合独立美术 + 中小工作室**,**不适合大厂主线生产**。
>
> **2026 年的差异化价值**:**跨平台 + 节点图 + 本地 AI + 单 exe**(10MB) 三角交集上的稀缺定位。
>
> **核心风险**:**单一作者 + 文档薄弱**,**不要把所有工作流都押在一个人的项目上**。

---

## 9. 关键 takeaway(给前端 / PM 的 5 句话)

1. **ArmorPaint = 开源 PBR 纹理绘制工具**,**Substance Painter 替代品**,**买断制**(¥280 一次性)
2. **技术架构核心**:**Kong 节点图编译器 + 5 套 GPU 后端 + 本地 AI 推理**
3. **应用场景**:**3D 模型材质绘制**,**适合独立美术 + 中小工作室**
4. **核心风险**:**单一作者 96% 贡献率**,**文档薄弱**
5. **借鉴价值**:**节点图多后端编译 + 主程序轻量化 + 子进程拉重模型** = 桌面 AI 工具的「轻壳重模」标准模式

---

## 10. 引用与参考

- **原文**: <https://mp.weixin.qq.com/s/_idKh-ixPG-4LEjgbHe5pQ>
- **GitHub**: <https://github.com/armory3d/armorpaint>
- **Armory 3D 组织**: <https://github.com/armory3d>(35+ 仓库)
- **官网**: <https://armorpaint.org>
- **DeepWiki**: deepwiki.com/armory3d/armorpaint(社区 wiki,25 页)
- **官方文档**: docs.armorpaint.org
- **下载**: <https://armorpaint.org/download/>(¥280 买断 / zlib 源码免费)

## 11. 跨 iswiki 引用

- **[artemis-art-direction](../3d-web-visualization/)** — 同样探索 AI + 3D 流程,但在 web 端
- **[img2threejs](../3d-web-visualization/)** — AI 图转 Three.js 代码,3D-as-code 思路相似
- **[nova3d](../3d-web-visualization/)** — 3D-as-code (Blender Python),同属「3D 代码生成」潮流
- **[kylinV10DisableIPv6](../ops-cybersec-dba/)** — 国产工具替代思路(国产 ARM 替代 CentOS)| 
|---|---|

## 12. 给初级前端的学习建议

== 如果你想**理解 ArmorPaint 的代码**,从这 3 个仓开始:

1. **`armorcore`** (C 库) — 学习自底向上的 C 数学库(读 ~2000 行)
2. **`kong`** (shader 编译器) — 学习节点图 IR(类似学习 Babel AST)
3. **`armorpaint/Sources`** — 看 UI 层如何用 IR + 状态机实现

== **如果你想借鉴到自己的项目**:

1. **节点图 + 多后端** → 用现成的 **Rete.js** / **Litegraph.js**(浏览器端节点编辑器)
2. **轻壳 + 重模型按需** → 参考 **ComfyUI** / **LM Studio** 架构
3. **撤销/重做** → 数组快照就够了,**别过度设计**

== **关键 takeaway**:**ArmorPaint 不是「用 3D 的人才能看」的项目** — 它是个**教科书级的「自研技术栈 + 极简主义 + 单作者 9 年坚持」案例**,**学它的工程纪律比学它的代码更有价值**。