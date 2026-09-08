# WeatherNext — DeepMind 全球天气预报 AI 模型家族

> 学习笔记 · 调研时间 2026-09-05
> 仓库: https://github.com/google-deepmind/weathernext · 模型主页: https://deepmind.google/science/weathernext/
> 产品入口: https://deepmind.google/science/weathernext/ · Google Developers 文档: https://developers.google.com/weathernext/guides/models
> License: **Apache-2.0**（代码 + Colab）/ **CC BY 4.0**（其他材料） · 语言: Python (JAX) · ⭐ 7,626 · 最新 release v0.3.0（2026-08-06）

## 一句话定位

DeepMind 公开的全球天气预报 AI 模型家族 —— 同一仓库承载 GraphCast (2023, Nature 封面) / GenCast / WeatherNext 2 / WeatherNext 3 (2026) / WeatherNext Cyclones (FNV3) 五代，从 GNN 到 diffusion 再到 hourly ensemble，把传统 NWP 的数值预报推进到「秒级推理 + 0.25° 网格 + 15 天预报」。

## 用户口述 vs 远端核验（重要纠偏）

| 项 | 用户口述 | 远端核验 | 结论 |
|---|---|---|---|
| 仓内容 | "WeatherNext 3 开源" | 仓 README 标题是 **WeatherNext 2**，WN3 模型 2026-09 上线但**仓里仍只有 WN2 + Cyclones 的推理代码 + 权重**（v0.3.0, 2026-08-06） | 用户给的链接都对，但**实际开源到 WN2 + Cyclones**，WN3 主要作为 Google 产品内服务（Search/Maps/Gemini） |
| 模型代数 | "第三代" | GraphCast (2023) → GenCast (2024) → WN2 (2025) → **WN3 (2026-09)**，仓库 README 还显式收录了"Older Models" GraphCast 和 GenCast | 用户口述"第三代"从 WN3 视角看准确（WN1/2/3），但仓里还**包含前两代** |
| 预测时长 | "15 天" | WN2/3 文档：15 天 / 0.25° 网格 / hourly (WN3 才有) | ✅ 对 |
| 网格精度 | "0.25°" | WN2_<2025 / WN Cyclones_<2025 / WN Cyclones_<2024 / WN Cyclones_<2023 都是 0.25° | ✅ 对 |
| License | 用户未提 | **Apache-2.0**（代码 + Colab）+ **CC BY 4.0**（其他材料） | 宽松，**不是 PolyForm 等限制型** |

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **A. 直接消费预报数据**（零代码） | Google Cloud (Earth Engine / BigQuery / Vertex AI) / DeepMind WeatherLab / OpenMeteo | 业务方接预报数据，无须自己跑模型 |
| **B. 跑开源模型推理**（研究 / 二次开发） | `pip install git+https://github.com/google-deepmind/weathernext.git@v0.3.0` + Colab notebook | 做天气研究、对比 baseline、做 ablation |
| **C. 接入 Google 产品**（B 端） | Google Search / Maps / Gemini 内置 | 终端用户通过 Google 产品消费预报 |

> 入口文档（Google Developers）：https://developers.google.com/weathernext/guides/models

## 模型家族谱系

```
WeatherNext (google-deepmind/weathernext)  单一仓库承载全家族
│
├── WeatherNext 3  (2026-09)        ← 当前最强，hourly + ensemble + 直接消费卫星数据
│     ├─ Search / Maps / Gemini 内置
│     └─ 已用于 National Hurricane Center 预测 Hurricane Melissa
│
├── WeatherNext 2  (2025, v0.3.0)   ← 仓里最新的"代码 + 权重"开源版本
│     ├─ WeatherNext2_<2025 (4 个 ensemble 成员)  ← Operational, 0.25°, 微调 HRES
│     └─ WeatherNext Cyclones (FNV3, 0.25°)
│           ├─ <2025>   Operational（2025 大西洋飓风季实跑）
│           ├─ <2024>
│           ├─ <2023>
│           ├─ Mini_<2024>   1° 分辨率, 轻量版, 单卡可跑
│           └─ Mini_<2023>
│
└── Older Models  (仓里仍维护)
      ├─ WeatherNext Graph   = GraphCast (2023 Nature 封面, GNN 确定性预报)
      └─ WeatherNext Gen     = GenCast  (2024, diffusion-based ensemble)
```

**架构演进：**
- **GraphCast (2023)** — Graph Neural Network，多层 mesh graph，**确定性**预报
- **GenCast (2024)** — Diffusion model，**概率性** ensemble 预报
- **WeatherNext 2 (2025)** — FGN (Functional Generative Network) 架构，4-member ensemble，0.25°
- **WeatherNext 3 (2026)** — 首个 **hourly** 全球模型，直接吃卫星数据，ensemble

## 核心组件 / 模块 / 架构

### 1. 仓库目录结构（v0.3.0）

```
weathernext/
├── docs/
│   ├── weathernext2/wn2_demo.ipynb         ← Colab 入口，强烈推荐先跑这个
│   ├── weathernext1_graph/README.md         ← GraphCast 文档
│   └── weathernext1_gen/README.md           ← GenCast 文档
├── utils/                                   ← 共享库（autoregressive rollout,
│                                              input normalization, graph building,
│                                              loss, JAX-compatible xarray）
├── WeatherNext2_<2025_model{1,2,3,4}.npz   ← WN2 4 个 ensemble 权重
├── WeatherNextCyclones_<2025_model{1,2,3,4}.npz
├── WeatherNextCyclones_<2024>...
├── WeatherNextCyclones_<2023>...
├── WeatherNextCyclones_Mini_<2024>.npz     ← 1°, 轻量, 单卡可跑
└── WeatherNextCyclones_Mini_<2023>.npz
```

### 2. 预训练权重数据源

| 数据 | 来源 | 用途 |
|---|---|---|
| ERA5 | ECMWF reanalysis | 主要训练数据 |
| HRES initial conditions | ECMWF IFS HRES | WN2 微调 + Operational 初始化 |
| WeatherBench2 | Zarr mirror | 访问 ERA5 / HRES 的推荐入口 |
| 卫星数据 | （WN3 直接消费） | WN3 独有 |
| 权重文件托管 | Google Cloud Storage `dm_graphcast` bucket | `gsutil cp` 下载 |

### 3. 训练 / 推理算力需求

| 模型 | 推荐硬件 | 备注 |
|---|---|---|
| WN Cyclones Mini (1°) | 单 P100 / 单 TPU v5e-1 | Colab 免费档够跑 |
| WN2 / WN Cyclones (0.25°) | H100 / TPU v5p | 显存吃紧 |
| Attention 实现 | TPU 优化；GPU 需切换 attention impl（Colab notebook 里演示） |

## 安装与最小使用

### 步骤 1：装包（**官方强推 pin 到 release tag**）

```bash
pip install git+https://github.com/google-deepmind/weathernext.git@v0.3.0
```

> README 原话："There are no guarantees of API stability and future updates may introduce breaking changes without notice. We recommend pinning to a specific release."

### 步骤 2：跑 Colab notebook（**最快上手路径**）

打开 Colab notebook 默认就是 `WeatherNext Cyclones Mini` + `v5e-1` runtime（免费）：

```text
https://colab.research.google.com/github/google-deepmind/weathernext/blob/master/docs/weathernext2/wn2_demo.ipynb
```

notebook 内教你 7 件事：
1. 自动从 GCS bucket 拉权重
2. 加载 initial state（HRES initial conditions）
3. 初始化 WN2 (FGN) 架构
4. 自回归 rollout 生成预报
5. 可视化（温度 / 风速 / 位势高度）
6. 在输出上跑 cyclone tracker → 拿到轨迹
7. 算训练 loss + 反向传播（**包括训练入口**，不只是推理）

### 步骤 3：直接消费预报数据（不走模型）

| 入口 | URL |
|---|---|
| Google Cloud (含 Earth Engine / BigQuery / Vertex AI) | https://developers.google.com/weathernext/guides/access-forecast |
| WeatherLab（含 cyclone tracks） | https://deepmind.google.com/science/weatherlab |
| OpenMeteo（含 API + interactive builder） | https://open-meteo.com/en/docs/google-weathernext-api |

### 最小代码示意（伪）

```python
# 安装: pip install git+https://github.com/google-deepmind/weathernext.git@v0.3.0
# 下载权重: gsutil cp gs://dm_graphcast/WeatherNextCyclones_Mini_<2024>.npz .
# 完整可跑代码请直接打开 Colab notebook
import weathernext

model = weathernext.from_pretrained("WeatherNextCyclones_Mini_<2024>")
forecast = model.rollout(initial_state_hres, steps=15)   # 15 天
```

## 关键论文 / 技术报告

| 主题 | 出处 | 链接 |
|---|---|---|
| WeatherNext Cyclones 论文 | Nature, 2026 | https://www.nature.com/articles/s41586-026-10953-2 |
| FGN / WN2 技术报告 | arXiv:2506.10772 | https://arxiv.org/abs/2506.10772 |
| WeatherNext 2 公告 | Google blog | https://blog.google/innovation-and-ai/models-and-research/google-deepmind/weathernext-2/ |
| WeatherNext Cyclones 公告 | DeepMind blog | https://deepmind.google/blog/weathernext-ai-model-achieves-breakthrough-in-forecasting-cyclones/ |
| GraphCast 公告（2023 Nature 封面） | DeepMind blog | https://deepmind.google/blog/graphcast-ai-model-for-faster-and-more-accurate-global-weather-forecasting/ |
| GenCast 公告 | DeepMind blog | https://deepmind.google/blog/gencast-predicts-weather-and-the-risks-of-extreme-conditions-with-sota-accuracy/ |
| 模型主页 | DeepMind | https://deepmind.google/science/weathernext/ |

## Release 节奏

| Tag | 日期 | 说明 |
|---|---|---|
| v0.1 | 2023-10-31 | 初代 GraphCast 仓库 |
| v0.1.1 | 2024-10-09 | |
| v0.2 | 2026-03-30 | |
| **v0.3.0** | **2026-08-06** | 当前 latest；仓最近 push 2026-09-04，README 仍以 WN2 为主 |

> 注：WN3 是 2026-09 在产品层上线（Search/Maps/Gemini/Hurricane Center 实战），**仓内的代码 + 权重目前仍是 WN2 + Cyclones**，这是用户口述里唯一需要注意的偏差。

## 实战案例：WN3 助 NHC 预测 Hurricane Melissa

WN3 在 2025 年大西洋飓风季为美国国家飓风中心 (NHC) 提供飓风轨迹预报，**对 Hurricane Melissa 的历史性登陆 Jamaica** 的预测准确度显著优于传统 NWP。NHC 后处理版本名为 **GDMI**（Google DeepMind Internal）。

详见 DeepMind 故事页：https://deepmind.google/science/weathernext/

## 风险点 / 注意事项

1. **API 不稳定**：README 明说"research code as-is, no API stability guarantee"，**生产集成必须 pin tag**，否则升级会被 break。
2. **算力门槛**：0.25° 模型要 H100 / TPU v5p，**单卡 P100 跑不动**，Mini 版才行。
3. **数据合规**：训练用 ERA5 + HRES 受 ECMWF 单独条款约束，**用之前先确认合规**（README 显式提醒）。
4. **不是官方气象产品**：DISCLAIMER："not an officially supported Google product" + "not endorsed by any government meteorological agency" — **不能替代官方警报**。
5. **WN3 的代码 + 权重未在仓内**：用户调研时如果想本地跑 WN3，目前只能用 WN2 + Cyclones；WN3 仅可通过 Google Cloud / WeatherLab / OpenMeteo 消费数据，或通过 Search/Maps/Gemini 间接体验。

## 跟我们的关系

| 我们有的东西 | 怎么用 WeatherNext |
|---|---|
| **Fireside / 私活项目** | 若做天气相关小程序（户外 / 农业 / 物流场景），**不要自己跑模型**，接 OpenMeteo 的 WN2 API（免费档）即可，5 行代码拉到 15 天预报 |
| **iswiki 自身** | 这是 iswiki 第一次收录气象领域 AI 模型，建议后续若关注 AI for Science，再补一份 GraphCast / GenCast 的独立笔记（现在 README 显式说仓里仍维护这两代的代码 + 文档） |
| **作为 AI 落地参考案例** | WN3 → NHC 实战是少数**前沿 AI 模型直接进入政府关键基础设施**的案例，跟我们讨论"AI 落地避坑"时引用价值高 |
| **GPU / TPU 资源** | VPS 无算力（见 memory），本机 Mac mini 跑不动 H100 级推理，**只做数据消费 + Colab free tier demo** |
| **调研方法学** | 这个项目的 "Older Models 仍维护在主仓" 模式值得借鉴 —— 我们自己的"AI Agent 工具栈"调研笔记也应该用一个总仓承载多个代际的笔记，而不是每个版本开新仓 |

## 参考链接

- GitHub: https://github.com/google-deepmind/weathernext
- 模型主页: https://deepmind.google/science/weathernext/
- Google Developers 文档: https://developers.google.com/weathernext/guides/models
- WeatherLab: https://deepmind.google.com/science/weatherlab
- OpenMeteo API: https://open-meteo.com/en/docs/google-weathernext-api
- Colab Demo: https://colab.research.google.com/github/google-deepmind/weathernext/blob/master/docs/weathernext2/wn2_demo.ipynb
- 权重存储: https://console.cloud.google.com/storage/browser/dm_graphcast
- WeatherBench2 数据: https://weatherbench2.readthedocs.io/en/latest/data-guide.html
- Product Hunt: https://www.producthunt.com/products/weathernext-3（社区反馈，被 Cloudflare 挡了，未抓到）
- Nature 论文 (Cyclones): https://www.nature.com/articles/s41586-026-10953-2
- arXiv FGN 技术报告: https://arxiv.org/abs/2506.10772
- GraphCast 公告: https://deepmind.google/blog/graphcast-ai-model-for-faster-and-more-accurate-global-weather-forecasting/
- GenCast 公告: https://deepmind.google/blog/gencast-predicts-weather-and-the-risks-of-extreme-conditions-with-sota-accuracy/
