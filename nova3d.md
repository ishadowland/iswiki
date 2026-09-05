# Nova3D — RareSense 的"程序化构造"3D 生成器 (693 ⭐)

> 学习笔记 · 调研时间 2026-09-05
> GitHub: <https://github.com/RareSense/Nova3D>
> 官网: <https://nova3d.xyz>
> 在线 App: <https://app.nova3d.xyz>
> 论文: <https://arxiv.org/abs/2607.22738>
> 调研文章: 「AI 生成 3D 模型,最怕的不是生成不出来,而是生成出来根本不好改」

---

## 1. 一句话定位

**Nova3D = "3D as Code" — AI 生成 3D 时不直接生成网格,而是先写 Blender Python 构造程序** — 每个部件独立命名 + 完整层级 + 材质单独调整 + 支持关节 + 可动结构,最终输出**结构化 GLB**(可继续在 Blender / 引擎里编辑)。

==**核心哲学**:**程序是 source of truth,网格只是编译产物**。

## 2. 核心数据

| 字段 | 值 |
|---|---|
| **GitHub stars** | **693** ⭐ |
| **Forks** | 66 |
| **License** | **MIT**(client + integrations,生成后端闭源) |
| **Size** | 160 MB |
| **Language** | **Dart**(Flutter web client)+ Python (MCP) + Blender add-on |
| **Created** | 2026-05-06 |
| **Updated** | 2026-09-05 (active,今天) |
| **Topics** | `3d-generation, blender, cad, claude, flutter, gemini, generative-ai, glb, llms, openai` |
| **Sister product** | FormaNova(珠宝 CAD 专用) |

## 3. 跟"图片转3D"传统方法的本质区别

| 维度 | Meshy / Tripo / TRELLIS / Rodin | **Nova3D** |
|---|---|---|
| **产物** | **fused mesh blob**(融合网格) | **Blender Python 程序 → 结构化 GLB** |
| **可编辑** | ❌ 二进制融合 | ✅ 每个部件独立命名 |
| **部件边界** | ❌ 无 | ✅ watertight 单独部件 |
| **层级** | ❌ 扁平 | ✅ 完整 assembly hierarchy(depth-7+ 链条) |
| **材质** | 烤进 vertex color | ✅ 真正 PBR materials |
| **关节 / 可动** | ❌ 无 | ✅ 关节 + 装配关系保留 |
| **编辑单部件** | 重生成整个 mesh | ✅ 只重生成该 part |
| **生成后** | 渲染可看,workflow 阻塞 | ✅ 进入游戏 / 配置器 / 机器人 / AR |

==**关键洞察**:**大部分"AI 生成 3D"项目在产出渲染好看的图时就停了;Nova3D 解决了"生成完之后能改吗"这个更深层的问题**。

## 4. 核心架构 — 4 层

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Layer 0: 用户输入                                                                                     │
│  Text prompt / Reference image                                                                   │
└──────────────────┬──────────────────────────────────────────────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: LLM 生成构造程序(Hosted, 闭源)                                                            │
│  - Provider-agnostic:OpenRouter / OpenAI / Anthropic / Gemini 可切换                            │
│  - 输出:Blender Python 构造代码(不是网格)                                                          │
│  - 每个部件独立命名 + 层级 + 材质 + 关节定义                                                          │
└──────────────────┬──────────────────────────────────────────────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Headless Blender 执行 + 验证 + 自修复(Hosted)                                          │
│  - 执行 Python 程序                                                                                  │
│  - 验证几何(连接 / 法线 / 拓扑)                                                                   │
│  - 自修复 → 重生成                                                                                  │
└──────────────────┬──────────────────────────────────────────────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Layer 3: 输出                                                                                          │
│  - 结构化 GLB(命名部件 + 完整 hierarchy + 关节 + 4K PBR 贴图)                       │
│  - code_artifact(原始 Python 程序)                                                              │
│  - conversation_url(浏览器 viewer)                                                                  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 5. 4 大核心概念

### 5.1 Script-Native, Not Mesh-Native

==**Nova3D 是 prompt-to-code / image-to-code,不是 image-to-mesh**==

- 传统 image-to-3D diffusion → 单一 fused mesh(无命名、无层级、无可编辑)
- Nova3D:LLM 写 Blender API 代码 → 逻辑层级 + surgical edits + PBR materials

### 5.2 Named, Watertight Parts(部件独立)

```
每部件:
├── 唯一 ID/名称 (e.g. "washing_machine_drum")
├── watertight mesh(不与邻居融合)
├── 独立材质(PBR,可在 Blender 单独调整)
├── 可独立选择/重生成/重贴图/绑定
└── 父级 hierarchy(depth-7 链条)
```

### 5.3 Assembly Hierarchy + Joint Pivots

==**深度可达 7+ 的层级链 + 每个 articulation point 有 pivot**:==

```
Robot arm (示例)
├── base
│   └── joint_1 (pivot at base center)
│       └── arm_lower
│           └── joint_2 (pivot at elbow)
│               └── arm_upper
│                   └── joint_3 (pivot at wrist)
│                       └── hand
│                           ├── finger_1
│                           ├── finger_2
│                           └── thumb
```

==**关键**:rotating any pivot moves its whole subtree(子部件跟着移动)— 跟 mesh blob 完全不一样。

### 5.4 Modifiable After Generation(4 个工具)

| Tool | 作用 |
|---|---|
| `regenerate_part` | **只重生成**一个命名部件,不动其他 |
| `add_part` | 添加新部件到现有 asset |
| `articulate_model` | 加关节 / 铰链 / 旋转结构 |
| `get_generation_status` | 查询运行中 workflow |

==**Workflow**:
```
generate_3d(prompt)              → GLB + code_artifact
regenerate_part(code, "handle", "把杯子手柄改成木质")  → 更新版 asset
add_part(code, "...")            → 加部件
articulate_model(code, ...)      → 加关节
```

## 6. 与同类项目的对比(README 里的)

### 6.1 vs 视觉扩散生成器

| | TRELLIS | Hunyuan3D | **Nova3D** |
|---|---|---|---|
| 产物 | mesh blob | mesh blob | **结构化 GLB + Python code** |
| 编辑 | 难 | 难 | ✅ 单部件独立 |
| 部件边界 | ❌ | ❌ | ✅ 独立 named parts |
| 层级 | 扁平 | 扁平 | ✅ depth-7+ hierarchy |
| 关节 | ❌ | ❌ | ✅ 真实关节定义 |
| 视觉保真 | 高 | 高 | **同样高 + 可编辑优势** |

### 6.2 vs PartPacker / Tripo Segmentation

| | NVIDIA PartPacker | Tripo Segmentation | **Nova3D** |
|---|---|---|---|
| 部件命名 | 部分(无命名) | 需要输入名字 | **自动命名** |
| 编辑 | 需手动分割 | 需手动分割 | ✅ 部件天生独立 |
| 边界稳定性 | 模糊 | 模糊 | ✅ 干净 watertight 边界 |
| 二次编辑 | 难 | 难 | ✅ 编辑 locality(改手柄不动杯) |

==**Nova3D = "Built as parts, not segmented after the fact"** —— 其他工具是先做整 mesh 再分割,Nova3D 从一开始就是部件。

## 7. 仓库结构

```
Nova3D/
├── app/                        # Flutter/Dart web client
│   ├── lib/                    # Dart source
│   ├── web/                    # Web assets
│   ├── assets/gifs/nova3d/     # drill_machine / escalator / oven 等
│   ├── mcp-client-api-mapping.md
│   ├── sketch_to_3d_v2_frontend_integration.md
│   └── pubspec.yaml
├── blender-plugin/             # Blender add-on
│   ├── nova3d_blender/         # Plugin source
│   ├── docs/
│   └── build.sh
├── mcp/                        # Nova3D MCP server (⭐ 关键)
│   ├── nova3d_mcp/             # Python MCP server source
│   ├── llms.txt                # AI-readable docs
│   ├── server.json             # MCP server manifest
│   ├── pyproject.toml
│   └── README.md
├── docs/media/                 # Demo GIFs + comparison images
├── .github/
├── README.md
└── LICENSE (MIT)
```

==**关键**:**MCP server 是开放入口** — 任何 AI 客户端可以通过 MCP 调用 Nova3D。

## 8. MCP 工具集(AI 客户端调用)

```python
# 10 个 MCP tools
nova3d_setup()           # 客户端未配 token 时返回 setup 指引
nova3d_login()           # 浏览器登录(走 preferred flow)
nova3d_status()          # 检查 credits + readiness
nova3d_logout()          # 清除本地 MCP session
generate_3d(prompt)      # 主入口:生成结构化 GLB
regenerate_part(...)     # 重生成单个 named part
add_part(...)           # 加部件
articulate_model(...)    # 加关节 / 铰链
get_generation_status(...)  # 查 workflow 进度
```

### 8.1 5 大客户端支持

| Client | Install |
|---|---|
| **Claude Code** | `claude mcp add nova3d -- uvx nova3d-mcp` |
| **Codex** | `codex mcp add nova3d -- uvx nova3d-mcp` |
| **Cursor** | `.cursor/mcp.json` 配置 |
| **VS Code** | `.vscode/mcp.json` 或 `code --add-mcp` |
| **Visual Studio** | `.mcp.json` 或 VS MCP UI |

==**agent-agnostic 哲学** — 任何 MCP 兼容客户端都能用。

## 9. 与 CSG/OpenSCAD / 传统 CAD 的对比

| | OpenSCAD / CSG | **Nova3D** |
|---|---|---|
| 几何范围 | 限于 CSG(布尔运算) | ✅ **Blender 全部 modifier suite** |
| 有机形状 | 弱(不能雕塑) | ✅ subdivision + sculpting + booleans |
| 层级 | 弱 | ✅ 完整 assembly hierarchy |
| 材质 | 弱 | ✅ 真正 PBR materials |
| 动画 | 弱 | ✅ 关节 + rigging |
| 编辑粒度 | 单 primitive | ✅ 命名部件独立编辑 |

==**Nova3D 是 CSG/OpenSCAD 的严格超集** + 还能做有机形状。

## 10. 8 大 demo 案例(从 README / 官网)

| 案例 | 类别 | 特点 |
|---|---|---|
| **Drill machine** | 工业设备 | 多部件独立 + 关节 |
| **Escalator** | 大型机械 | 复杂运动结构 |
| **Oven** | 家电 | 控制面板 + 内部结构 |
| **Engagement ring** | 珠宝 | 精确尺寸(6.82 × 8.75 × 4.40 mm)|
| **Robot arm** | 机器人 | depth-7 关节链 |
| **Tracked crane** | 工程车 | 铰链 + 多关节 |
| **Building** | 建筑 | assembly hierarchy + 标注 |
| **Washing machine** | 家电 | 滚筒 / 门 / 控制面板 / 软管(README 头) |

## 11. 4 大核心设计哲学

1. **"Code-native, not mesh-native"**
   - 程序是 source of truth,网格只是编译产物
2. **"Model-agnostic"**
   - 切换 LLM provider 不影响 pipeline
3. **"Precision + Organic Flow"**
   - CSG 的精确 + Blender modifier suite 的有机形状
4. **"Editable After Generation"**
   - 单部件独立编辑是核心卖点,不是 nice-to-have

## 12. 与 img2threejs / substation-blueprint 的对比

| 维度 | **Nova3D** | img2threejs | substation-blueprint |
|---|---|---|---|
| **产物** | Blender Python + 结构化 GLB | Three.js 代码 | single HTML + Three.js |
| **代码生成方式** | Hosted LLM(闭源后端)| 本地 SKILL(开源) | 人工手写 + OPC CEO |
| **部件编辑** | ✅ 单部件重生成 | ✅ 8 阶段 + 视觉门 | ❌ 一次性,后续人工 |
| **关节 / 可动** | ✅ 真实 | ❌ (rig 派生) | ❌ drone 演示 |
| **可视化目标** | 游戏 / CAD / 机器人 | 通用 Three.js 场景 | substation 可视化 |
| **Stars** | 693 | 15k | (本仓库) |

## 13. 5 大可借鉴元素

1. **"Program is source of truth, mesh is compiled output"**
   - 把"代码生成 + 编译"范式应用到 3D → 代码可 Git 追踪,可修改,可版本化

2. **"Editable After Generation" 是核心,不是 nice-to-have**
   - 反传统 image-to-3D 只追求"看起来像"的范式

3. **MCP-as-distribution** — `uvx nova3d-mcp` 一行接入所有 AI 客户端
4. **Provider-agnostic** — OpenAI / Gemini / Anthropic / OpenRouter 可切换,不被绑死
5. **Strict superset positioning** — 不是"另一种 3D 工具",而是 CSG + mesh generation 的超集

## 14. 适用 substation-blueprint 的可借鉴性

substation-blueprint 是「**只读3D 可视化**」(静态展示 + 主题切换),如果要加 **AI 生成** 能力:

### 14.1 短期建议
1. **加 Nova3D 集成**:作为外部 generator,生成后 substation-blueprint 显示
2. **集成 MCP**:通过 MCP 调用 Nova3D,把生成的 GLB 导入 Three.js 场景

### 14.2 中期可借鉴元素
1. **"Program is source of truth"** → substation-blueprint 的 scene.js 已经是程序(只是手工写),可以用 LLM 辅助生成
2. **"Named parts"** → 当前 substation-blueprint 没明确组件命名,可以加(component layer)
3. **"Edit locality"** → 用户点击单个部件,可以 AI 重生成该部件

### 14.3 长期方向
1. **"Build as parts, not edit whole"** → 跟当前 theme 切换不同,substation-blueprint 可以加「部件级别重生成」
2. **Provider-agnostic LLM** → 跟 Nova3D 一样不绑死 provider

## 15. 跟 OPC fork 的关系

我 fork 的 OpenOPC 是「多 Agent 业务协作」,**Nova3D 的架构哲学可借鉴到 OPC**:

| Nova3D 元素 | 借鉴到 OPC |
|---|---|
| `code_artifact` 作为 session state | OPC task `artifact_id` 持久化 |
| `regenerate_part` 单部件重生成 | OPC task 单步重做,不用重跑整个 task |
| `articulate_model` 加关节 | OPC 加新 agent 进现有任务 |
| `get_generation_status` 查 workflow | OPC 看 task 进度 |

## 16. 适用场景(README 明示)

✅ **适合**:
- **产品官网 3D 展示**(configurator)
- **可点击拆解的设备结构**
- **游戏道具原型**
- **教学演示**
- **需要继续绑定动画 + 交互的创意可视化**
- **珠宝 CAD**(FormaNova 姊妹产品)
- **机器人 / 数字孪生**(关节 + 装配关系)

❌ **不适合**:
- **一次性渲染**(传统3D 工具已够)
- **隐藏区域需要真实几何**(单图源限制)

## 17. 相关 iswiki 项目

- **[img2threejs](img2threejs.md)** (15k ⭐) — AI 图转 Three.js 代码(类似思路)
- **[kage](kage.md)** (1407 ⭐) — Three.js + 手绘 WebP
- **[artemis-redradman](artemis-redradman.md)** (44 ⭐) — Three.js + 数据密度
- **[reverse-skill](reverse-skill.md)** (33.7k ⭐) — 安全任务路由包
- **[Nova3D](nova3d.md)** (693 ⭐) — 本文:3D as code

## 18. TL;DR

**Nova3D = RareSense 的 "3D as Code" 生成器,693 ⭐,MIT**。

==**核心哲学**:**不直接生成 mesh,而是先写 Blender Python 构造程序** → 每个部件独立命名 + 完整 hierarchy + 关节 + 可动结构 → 编译为结构化 GLB。

==**4 大创新点**:
1. **部件级编辑**(`regenerate_part` 只重生成单部件)
2. **真实关节**(不是动 rigging)
3. **PBR 材质**(不是 vertex color)
4. **MCP 一行接入**(任何 AI 客户端)

==**最值得学的 1 点**:**"Program is source of truth, mesh is compiled output"** —— 这是 AI 生成 3D 的范式转换,**代码可编辑、可 Git、可版本化,网格只是视图**。
