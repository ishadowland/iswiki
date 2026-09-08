# Tripo (VAST) — AI 3D 生成从「能看」到「能进引擎」的转折点

> 学习笔记 · 调研时间 2026-09-05
> 公司: VAST（也称 Tripo AI）· 官网: https://www.tripo3d.ai/ · 平台/API 入口: https://platform.tripo3d.ai/
> GitHub org: https://github.com/VAST-AI-Research
> 旗舰模型: Tripo P2.0（基座大模型，闭源 API）· 开源侧: TripoSR / TripoSG / TripoSF / TripoSplat（MIT）
> License: API 服务 + Python SDK（`tripo3d`）MIT + 主要研究仓 MIT + `tripo-cli` MIT
> 商业模型: 闭源 API + 计费 token（账户余额查询可用 `tripo3d.TripoClient().get_balance()`）
> 调研来源: 游戏茶馆《游戏制作的体力活时代，正在被 AI 3D 终结》(2026-09-04) https://mp.weixin.qq.com/s/Hn4qkL-J4azdeT-s6yI9rg
> 横向交叉: TripoSR paper (arXiv 2403.02151) / TripoSF paper (arXiv 2503.21732) / PyPI `tripo3d` API JSON / GitHub API

## 一句话定位

VAST（Tripo AI）是国内 AI 3D 大模型公司，主打「原生四边面拓扑 + 按面数预算直出 + 语义分件」的 3D 生成基座；Tripo P2.0 是其首个原生四边面 AI 3D 基座模型，让模型从「生成即可看」跨到「进引擎可绑定可拆分」，已落地网易《蛋仔派对》《燕云十六声》等管线。

## 三种使用方式

| 方式 | 入口 | 适用场景 | 鉴权 |
|---|---|---|---|
| Web 控制台 | https://platform.tripo3d.ai/ | 体验、试玩、单次生成 | 账号登录 |
| 官方 CLI | `npm i -g tripo-cli`（`tripo`）或 `tripo-cli`（v0.3.1，2026-08-29） | 终端里 prompt/image → GLB/FBX；CI 自动化 | `TRIPO_API_KEY` 环境变量 |
| 官方 SDK | `pip install tripo3d`（v0.4.2，2026-07-01） | Python 异步客户端：text/image/multiview → 3D 模型、自动 rigging/retarget、mesh segmentation、smart lowpoly、格式转换 | API Key（`tsk_…`）或环境变量 `TRIPO_API_KEY` |
| 桌面 / 节点 | Blender 插件（`tripo-3d-for-blender`）、ComfyUI 节点（`ComfyUI-Tripo`）、MCP server（`tripo-mcp`，alpha，仅 Blender 集成） | 在 DCC 工作流内嵌调用 | 各工具自带 key 注入 |
| 开源本地推理 | TripoSR / TripoSG / TripoSF / TripoSplat（PyTorch 仓，MIT） | 研究 / 自托管 / 不想付费；能力弱于云端 P2.0 | 无 |

> 注意：Tripo CLI 仓的真实归属是 `vast-enterprise/Tripo-API-CLI`（Vast.ai 是另一家 GPU 云公司，别名撞车，不要混）。

## 核心组件 / 模块 / 架构

```
VAST (Tripo AI) — 一家做 AI 3D 大模型的公司
├── 闭源商业 API（Tripo Platform, platform.tripo3d.ai）
│   ├── 基座大模型
│   │   ├── Tripo V3 / P2.0 —— 原生四边面拓扑 + 语义分件（云端推理，按 token 计费）
│   │   └── 早期 TripoSR（已在 2024-03 开源为 image → mesh 单图模型）
│   ├── 能力层
│   │   ├── text-to-3D / image-to-3D / multiview-to-3D
│   │   ├── text-to-image / 多参考图 / 模板（图生图）
│   │   ├── 多视角图生成与编辑
│   │   ├── one-shot 动画：自动 rigging + retarget
│   │   ├── 外部模型导入：GLB / OBJ / FBX / STL
│   │   ├── mesh 编辑：segmentation / completion / smart lowpoly
│   │   ├── 模型风格化 / 转换 / 重新拓扑
│   │   └── 异步任务系统（task_id + wait_for_task）
│   └── 接入层
│       ├── Web 控制台（platform.tripo3d.ai）
│       ├── Python SDK（tripo3d, MIT, PyPI）
│       ├── Node CLI（tripo-cli, MIT, npm）
│       ├── Blender 插件（tripo-3d-for-blender, MIT）
│       ├── ComfyUI 节点（ComfyUI-Tripo, MIT）
│       └── MCP server（tripo-mcp, MIT, alpha）
└── 开源研究线（VAST-AI-Research，MIT，全部可商用）
    ├── TripoSR —— image → mesh，单图重建，0.5s/A100（arXiv 2403.02151）
    ├── TripoSG —— rectified flow 形状合成（SIGGRAPH 风格）
    ├── TripoSF (SparseFlex) —— 1024³ 高分辨率 + 任意拓扑（arXiv 2503.21732）
    ├── TripoSplat —— image → 3D Gaussians（最多 262,144 点）
    └── tripo-mcp —— 官方 MCP，Claude/Cursor → Blender
```

**架构图（位置定位）**：

```
┌──── 你的工作流 ─────────────────────────────┐
│  Blender / ComfyUI / MCP / Python / 终端     │
└────────────────┬────────────────────────────┘
                 │ HTTPS（Tripo V3 API）
                 ▼
        ┌──── platform.tripo3d.ai ────┐
        │  Tripo P2.0（闭源基座）       │  ← 计费（按 token / 任务）
        │  + 任务编排 + 模型后处理        │
        └────────────────┬─────────────┘
                         │ 输出 GLB / FBX / OBJ
                         ▼
                ┌──── 你的引擎 ────┐
                │ UE / Unity / Web │
                └──────────────────┘
```

## 安装与最小使用

### 1. Python SDK（最常用）

```bash
pip install tripo3d          # v0.4.2（2026-07-01）
export TRIPO_API_KEY=tsk_xxx # 从 platform.tripo3d.ai 申请
```

```python
import asyncio
from tripo3d import TripoClient, TaskStatus

async def main():
    async with TripoClient() as client:
        # ① 一句话出 3D
        task_id = await client.text_to_model(
            prompt="a cute cyber cat",
            negative_prompt="low quality, blurry",
        )
        task = await client.wait_for_task(task_id, verbose=True)

        if task.status == TaskStatus.SUCCESS:
            files = await client.download_task_models(task, "./out")
            for kind, path in files.items():
                if path:
                    print(f"{kind} -> {path}")

        # ② 余额
        bal = await client.get_balance()
        print(f"balance={bal.balance} frozen={bal.frozen}")

asyncio.run(main())
```

### 2. CLI（终端 / CI 友好）

```bash
npm i -g tripo-cli
export TRIPO_API_KEY=tsk_xxx
tripo text "a steampunk robot" --format glb -o robot.glb
tripo image ./sketch.png --format fbx -o sketch.fbx
```

### 3. MCP（让 Claude / Cursor 直接产出 3D + 落到 Blender）

```json
// Claude Desktop / Cursor 的 mcp.json
{
  "mcpServers": {
    "tripo-mcp": {
      "command": "uvx",
      "args": ["tripo-mcp"]
    }
  }
}
```

> 注意：`tripo-mcp` 当前仅与 Tripo Blender Addon 打通（README 写明 alpha），聊到「做一只蜘蛛，逐部件加动画逻辑」这种 Agent 写代码 + 调模型的链路就是它。

### 4. 开源侧：本地跑 TripoSR（弱于 P2.0，但免费 + MIT）

```bash
git clone https://github.com/VAST-AI-Research/TripoSR.git
cd TripoSR
pip install -r requirements.txt        # 需 PyTorch + CUDA，单图 ~6GB VRAM
python run.py examples/chair.png --output-dir output/   # ~0.5s/A100 出 mesh
python gradio_app.py                                    # 本地 Gradio UI
```

## 版本 / 节奏

| 包 / 仓 | 最新版 | 发布日 | 备注 |
|---|---|---|---|
| `tripo3d` (PyPI) | 0.4.2 | 2026-07-01 | 0.4.0/0.4.1/0.4.2 集中在 2026-04-29 至 07-01；自 2025-03 起约每 2–4 周一版 |
| `tripo-cli` (npm) | 0.3.1 | 2026-08-29 | 起步晚（2026-07-22 首发 0.1.0），迭代节奏 ~1 月 |
| `tripo-mcp` | alpha | 2025-04-14（last push 2026-08-31） | 仅 Blender 集成，仍标 alpha |
| `TripoSR` 仓 | — | last push 2026-06-04 | 6.9k ⭐，MIT，主要维护停顿；仍是 image → mesh 入门首选 |
| `TripoSG` 仓 | — | last push 2025-04-18 | 1.8k ⭐，MIT（shape generation） |
| `TripoSplat` 仓 | — | last push 2026-08-13 | 1.3k ⭐，MIT，~2k LOC 易读 |
| `TripoSF` 仓 | — | last push 2025-04-07 | 765 ⭐，MIT，1024³ 高分辨率 |
| `ComfyUI-Tripo` | — | last push 2026-07-08 | 350 ⭐；2026-06-30 加 Mesh Segmentation v2.0 |
| `tripo-3d-for-blender` | — | last push 2025-11-06 | 63 ⭐ |
| Tripo P2.0（闭源） | — | 2026-09-01 发布会 | 全球首个原生四边面 AI 3D 基座模型 |

## 跟我们的关系（用户工作相关 — 必填段）

| 用户场景 | 可复用点 | 风险 / 注意 |
|---|---|---|
| 给小朋友做「看图变 3D 小玩具」网页 | 用 `tripo3d` 做 image_to_model + `task.pbr_model_url` 直接出 PBR GLB，前端 Three.js 看 | API 按 token 收费；不要拿 demo 跑无限循环，先调 `get_balance()` 设上限 |
| ComfyUI 工作流里塞 3D 生成 | 直接装 `ComfyUI-Tripo`（支持 Mesh Segmentation v2.0、URL 导入、动画、retopology） | key 用 `TRIPO_API_KEY` 环境变量或节点字段都行，别写进 git |
| 沙雕玩法（feed 随便一张图 → 3D） | `tripo-cli` 跑一次性任务最干净：image → glb/fbx → 直接给 UE/Unity/Blender | 输出文件可能几十 MB，传网盘/S3 设好 expiry |
| 给现成 GLB 加动画 + 让 Claude 拆部件写脚本 | `tripo-mcp`（alpha，但场景就是这个） | 仅 Blender 集成；README 明确「alpha」，别当生产依赖 |
| 想完全本地 / 离线 / 免费 | 跑 `TripoSR`（单图 → mesh）或 `TripoSplat`（image → Gaussians） | 质量明显弱于云端 P2.0，且需要 NVIDIA 卡 + ~6GB VRAM 起 |
| 关注 3D 数据合规 | 输出的 GLB/FBX 版权归用户，但要看你 prompt 是否侵权（参考 img2video / Sora 同类问题） | 商业 / 二次分发前自行把控 prompt 来源 |

> 一句话结论：**别拿它当"AI 玩具"玩**，P2.0 的真卖点是「分件 + 四边面 + 按面数预算」三件套同时成立——这才是它能进网易《蛋仔》月活过亿的工程环境的原因；做 UGC / 关卡编辑器时直接 `mesh_segmentation` 拿过来用最值。

## 关键人物 / 投资 / 落地（来自原文，已与远端数据交叉）

- 公司：VAST（也称 Tripo AI），国内 AI 3D 大模型公司。
- 融资：2026-09-01 宣布 B + B+ 轮合计约 30 亿，经纬创投领投；近半年累计约 50 亿。
- 游戏股东：A3 轮 四三九九 / 贪玩 / 巨人网络；B + B+ 完美世界 / 三七互娱 / 延趣游戏（原文措辞已用，不展开）。
- 已落地产品（原文）：
  - 网易《蛋仔派对》蛋仔工坊：2025-09 上线 AI 生模型；2026-07-30 上线 3D 模型拆分功能（VAST 提供）；移动端月活过亿。
  - 网易《燕云十六声》：2025 初「万物太极」一句话生成道具（基于 Tripo API）。
  - 全球多家头部游戏大厂：场景资产快速搭建、关卡原型验证、多方案比选，「综合提效 >50%」（VAST 自述，需自行核数）。
- 首席科学家：曹炎培（演示 P2.0 + 大模型写机械蜘蛛部件动画逻辑）。

## 风险点 / 注意事项

| 风险 | 说明 |
|---|---|
| **Cloudflare 拦截** | `tripo3d.ai` 与 `platform.tripo3d.ai/docs` 在抓取测试时均触发 Cloudflare 验证；API 鉴权机制 `tsk_…` key 不能在前端 / 公开仓暴露。 |
| **GitHub org 别名** | `vast-enterprise` 这个 org 名下既挂着 VAST 的 CLI，也挂着 trimesh / LAVIS / overleaf / ComfyUI-ControlNet-Aux 等无关 fork；搜「Tripo」务必用 `VAST-AI-Research`，别误抓。`vast-ai` 是另一家 GPU 云公司，不要混。 |
| **闭源核心** | P2.0 只走 API，本地不可跑；只有 TripoSR / SG / SF / Splat 这几个研究仓是开源的。 |
| **能力差异** | 开源 TripoSR 出的是「mesh」，结构 / 拓扑不一定能直接进 UE/Unity 走完绑定；P2.0 的「原生四边面 + 语义分件」是闭源侧卖点，云端才拿到。 |
| **API 价格 / token 风险** | 异步任务，没有显式硬上限；接循环 / Agent 必须显式调用 `get_balance()` 或加本地预算。 |
| **隐私** | 提示词 / 上传图会上传到 VAST 平台；含人物 / 商标 / 自有 IP 的图，先审。 |
| **MCP 仅 alpha** | `tripo-mcp` README 自标 alpha，且只对接 Blender Addon；想接 UE/Unity/Three.js 走自建 Python 客户端。 |

## 实战建议

1. **先用 `tripo-cli` 跑通**，再上 Python SDK —— CLI 一次一文件、好排查，SDK 适合嵌进 Agent 循环。
2. **Agent 场景必走三件套**：干净拓扑（四边面）+ 可控面数（按预算）+ 清晰分件（`mesh_segmentation`）—— 这是 P2.0 的差异点；用 `tripo-mcp` / `ComfyUI-Tripo` 验证了再上量。
3. **要本地免费**：用 TripoSR 当 baseline；能跑通就把它当「最差 fallback」，线上再切到 P2.0 做对比。
4. **资方 / 股东信息是「口径」非「事实」**：B/B+ 30 亿 + 半年 50 亿来自公司公告 + 媒体（游戏茶馆），不是有审计的财报，写对外材料时引用需注明出处。
5. **「月活过亿 / 提效 >50%」都是 VAST 单方说法**，对外文档引用要注明「据 VAST 自述」。

## 参考链接

| 类型 | 链接 |
|---|---|
| 调研原文 | https://mp.weixin.qq.com/s/Hn4qkL-J4azdeT-s6yI9rg |
| 公司官网 | https://www.tripo3d.ai/ |
| 平台 / API 控制台 | https://platform.tripo3d.ai/ |
| 平台文档入口（SPA） | https://platform.tripo3d.ai/docs |
| 研究 org GitHub | https://github.com/VAST-AI-Research |
| 商业 CLI 仓 | https://github.com/vast-enterprise/Tripo-API-CLI |
| Python SDK 仓 | https://github.com/VAST-AI-Research/tripo-python-sdk |
| Python SDK 包（PyPI） | https://pypi.org/project/tripo3d/ |
| CLI 包（npm） | https://www.npmjs.com/package/tripo-cli |
| TripoSR 仓 | https://github.com/VAST-AI-Research/TripoSR |
| TripoSR 论文 | https://arxiv.org/abs/2403.02151 |
| TripoSG 仓 | https://github.com/VAST-AI-Research/TripoSG |
| TripoSF 仓 | https://github.com/VAST-AI-Research/TripoSF |
| TripoSF 论文 | https://arxiv.org/abs/2503.21732 |
| TripoSplat 仓 | https://github.com/VAST-AI-Research/TripoSplat |
| MCP server | https://github.com/VAST-AI-Research/tripo-mcp |
| Blender 插件 | https://github.com/VAST-AI-Research/tripo-3d-for-blender |
| ComfyUI 节点 | https://github.com/VAST-AI-Research/ComfyUI-Tripo |
| Hugging Face 模型 hub | https://huggingface.co/VAST-AI |