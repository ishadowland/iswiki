# OpenClaw × Ultralytics YOLO — 「让 agent 盯着流水线」的四步法与五级递进，以及落地时必须改的 6 处

> 学习笔记 · 调研时间 2026-10-18
> 触发来源: 微信公众号《让 OpenClaw 指挥 YOLO，7×24 小时盯着流水线》(机器学习AI算法工程) https://mp.weixin.qq.com/s/qzfxrqYrHUY_tRewmzX1Lw (发布 2026-09-29)
> 上游: OpenClaw https://docs.openclaw.ai · Ultralytics https://docs.ultralytics.com
> License: **Ultralytics 主仓 AGPL-3.0**(实测 GitHub API) · OpenClaw 本机 CLI 2026.3.28 · Ultralytics 8.4.181 (2026-10-17) · ultralytics/ultralytics ⭐ 62,594

---

## 一句话定位

把 YOLO 缺陷检测封装成 agent skill，用定时任务编排「检测 → 报表 → 预警 → 趋势 → 归档」五级自动化 —— **真正值钱的是那个"先算延迟预算再决定 agent 放哪"的判断，和五级递进的搭法**；代码接口层则要整个重写。

---

## 一、核心方法论：先算延迟预算，再决定 agent 该不该在这条链路上

原文开篇就把一个绝大多数教程会糊过去的问题摆在了台面上，这是全文最有价值的一句：

> OpenClaw 调用大模型推理需要 1-3 秒，YOLO 检测需要 0.1-0.5 秒，总延迟 5 秒以上，对高速流水线来说是致命的。
> **解决方案：不追求实时，先做离线自动化。**

**这是一条通用的 agent 落位原则，不是 YOLO 专属的**：先量出「LLM 单次往返 + 业务函数执行 + I/O」的端到端下界，再看这条链路的时延预算装不装得下。装不下就换落位方式，而不是去优化 prompt 让它快一点 —— 快不掉的。

由此推出原文的场景适配矩阵（我按这个原则重新排了一遍）：

| 场景 | 时延预算 | agent 该不该在这条链路上 | 正确的分工 |
|---|---|---|---|
| 单件实时拦截（<100ms） | 装不下 5s | ❌ 别放 | 纯代码判定，agent 最多事后复盘 |
| 高速产线在线检测 | 装不下 | ❌ 别放 | 同上 |
| 夜班全量离线质检 → 日报 | 分钟级 | ✅ 合适 | 判定在代码，agent 编排 + 解释 + 推送 |
| 定时巡检抽检 | 秒~分钟级 | ✅ 合适 | 同上 |
| 告警通知链路 | 无硬预算 | ✅ 合适 | **判定在代码，agent 只做通知与解释** |
| 月度趋势挖掘 / 设备评分 | 分钟~小时级 | ✅ 最合适 | agent 做跨文件聚合与自然语言结论 |
| 缺陷图归档 + 自然语言检索 | 无硬预算 | ✅ 合适 | agent 做索引与检索入口 |

**一句话提炼**：**agent 的位置 = 时延预算宽裕 + 需要跨数据源做判断与解释的那一段**。中间的「判定」永远留给代码 —— 因为让 LLM 去数缺陷个数，就是在用一个不可复现的组件替换一个确定性的组件。

---

## 二、四步法骨架

原文的整体搭法是对的，值得原样记住这个顺序 —— 关键在于**「先把模型搞出来」被放在第一步，而不是先搭 agent**。绝大多数「AI + 传统算法」的教程都反着写，先讲怎么接 agent，再含糊地说「你需要一个模型」，读者接完发现无从下手。

```
第一步  训练一个能用的 YOLO 缺陷检测模型
        └ 数据集目录 → data.yaml → 训练 → best.pt
        └ 已有模型则跳过（原文明确允许）

第二步  把 YOLO 封装成 agent skill
        └ skill 目录 + 3 个检测工具（单张 / 批量 / 报表）
        └ 依赖声明 + 模型路径 + 阈值配置集中一处

第三步  配置自动化任务  ← 核心步骤
        └ 自然语言描述 → agent 生成声明式配置 → 人工审查
        └ 5 类任务（见第三节）

第四步  接消息推送渠道
        └ 企微应用创建 → 插件配置 → 重启 → 发测试消息验证闭环
```

**为什么这个顺序重要**：第一步是**可独立验证**的（模型准不准，跑张图就知道），第二三步是**编排层**。如果反着来，agent 接好了但模型是糊的，你在 agent 层调 prompt 调一整天也调不出准确率。先把不确定性最大的那一环单独收敛，是任何「传统算法 + LLM」组合的第一步。

原文还明说「如果你已经有训练好的 YOLO 模型，直接跳到第二步」—— 这是个好的接口设计：**第一步和后面三步解耦**。

---

## 三、五级递进：不是 5 个孤立技巧，是一条从数据到决策到知识的完整阶梯

原文给了 5 个自动化任务，多数人会当成 5 个可以跳着选的例子。但它们其实构成一条**有依赖关系的递进链** —— 后一级用到前一级的产物：

```
① 每日缺陷统计报表        定时批处理   ──► 产出：CSV（明细）+ 缺陷率 + 类别分布
        │                              「有了今天的数据，但看不到变化」
        ▼
② 实时缺陷预警            事件驱动     ──► 产出：告警 + 带置信度的明细 + 风险等级
        │                              「有了异常，但没人定优先级」
        ▼
③ 月度质量趋势分析        跨月聚合     ──► 产出：趋势图 + 关键发现（如「2 号线划痕持续上升 +15%」）
        │                              「看到了趋势，但不知道该动谁」
        ▼
④ 设备健康度评分          规则化决策   ──► 产出：0-100 分 + 低分设备 + 维保建议
        │                              「有分数了，但数据散落各处查不动」
        ▼
⑤ 数据归档与检索          知识管理     ──► 产出：按类归档 + 「找 3 月所有划痕」自然语言可查
```

**这条阶梯的通用价值**：任何「把某个检测/统计能力接进自动化」的题目，都值得先问一句「我的用户接下来要回答什么问题」，然后按 **看今天 → 看异常 → 看趋势 → 定优先级 → 翻历史** 这个顺序逐级加。原文五个场景恰好把这条链走完了，可以当 checklist 用。

### 每一级的具体配置思路

**① 每日缺陷统计报表** — 定时批处理 + 延迟推送

- 自然语言配置（原文示例）：
  > 「每天凌晨 2 点，检测 `/data/products/` 目录下所有图片，统计缺陷类型，早上 8 点把报表发我企业微信」
- 配置形态：`cron: "0 2 * * *"` → `detect_batch` → `generate_report` → `at_time: "08:00"` 推送
- **值得学的设计**：**检测时间和推送时间分离**（02:00 算、08:00 发）。夜班跑完报表，人早上上班才看到。这是个很小但很体贴的分层。
- 产出形态：不良率 % + 缺陷分布 + **带行动指向的解读**（「划痕：623 次（重点查 2 号线）」—— 不只是罗列数字，而是标出最该查的那一项）

**② 实时缺陷预警** — 事件驱动 + 条件分支

- 自然语言配置：
  > 「监听 `/data/uav/` 目录，有新文件就用 YOLO 检测，发现缺陷立即发企业微信预警」
- 配置形态：`watch: {directory, pattern: "*.jpg", debounce: 5s}` → `detect_single` → **条件判断** `total_detections > 0` 才推送
- **`debounce: 5s` 是关键设计**：文件监听必须做防抖。相机 / 无人机连拍会写出连续多个文件，不防抖就是告警风暴。这条与我们的 ToDesk wakeup 风暴是同一类问题。
- 产出形态：照片名 + 位置 + 时间 + **分类明细带置信度区间** + **风险等级** + 处置建议（「立即停机检查！」）
- 预警消息里带 `priority: "high"` 字段 —— 告警分级，而不是所有异常同一个待遇

**③ 月度质量趋势分析** — 跨文件数据挖掘

- 自然语言配置：「帮我统计过去 3 个月的缺陷数据，生成趋势图表」
- 配置形态：`cron: "0 9 1 * *"` → `list_files(pattern: "daily_report_*.csv", date_range: "-3 months")` → `trend_analysis` → `create_chart(line)` → 带附件推送
- **依赖关系体现得很清楚**：这一步的输入正是 ① 每天产出的 CSV。所以 ① 必须先跑通并保证**输出格式稳定**，否则 ③ 无法聚合。
- 关注的指标：`defect_rate`（整体不良率）、`class_distribution`（类别分布）、`line_performance`（产线维度）
- 产出形态：**带方向的对比**（「划痕 +15%↑ / 凹坑 -8%↓ / 整体稳定在 1.2%」）+ **归因猜测**（「2 号线持续上升」）。原文示例里 OpenClaw 直接给了归因 —— ⚠️ 这种归因是模型猜的，不是算出来的，生产环境要标注为「待验证假设」。

**④ 设备健康度评分** — 把检测结果接进决策规则

- 自然语言配置：「给每台设备打分，低于 60 分的推送维保建议」
- 配置形态：`cron: "0 18 * * *"` → 收集缺陷 → `device_scoring` → **条件** `min_score < 60` 才推送
- **评分规则写成声明式**（原文）：
  ```
  基础分：100 分
  划痕：-2 分/个    凹坑：-3 分/个
  污渍：-1 分/个    裂纹：-5 分/个
  ```
  **这条值得单独学**：规则以**数据形式**写在配置里，而不是硬编码在业务代码里。好处是 —— 非工程师（设备工程师 / 车间主任）能直接调权重；规则变更留 git diff；agent 读配置就能解释「为什么这台设备 45 分」。
  裂纹权重最高（-5），符合真实场景里裂纹比污渍严重的直觉。
- 产出形态：**分数 + 扣分明细拆解**（100 - 35（划痕 35×2）- 15（凹坑 5×3）- 5（污渍 5×1）= 45）+ 处置建议
- **明细拆解比单看分数重要得多** —— 收到「45 分」没人知道该修哪，收到了「划痕 35 处」就直接指向操作。

**⑤ 自动化数据归档与检索** — 从「统计」升级到「知识管理」

- 自然语言配置：
  > 「把所有缺陷图片按类型归档，以后我说"找 3 月所有划痕"就能查到」
- 配置形态：`cron: "0 3 * * *"` → 检测分类 → `archive_by_class`，命名规则 `{class}_{timestamp}_{index}.jpg`
- **命名规则模板化**是这一级的核心 —— 有了稳定命名，自然语言检索才有可能。
- 产出形态：「找到 1,237 张划痕图片，已打包发送」
- 这是五级里**最容易被忽略但复用价值最高**的一级：前四级的产出是一张报表，用完即弃；这一级把数据变成可累积、可回溯的资产。

---

## 四、低代码配置法：自然语言 → 声明式配置 → 人工审查

原文强调「全程低代码，大部分配置只需对着 OpenClaw 说句话」。这条路径的**方法论骨架**是：

```
① 用自然语言描述意图（含：触发时机 + 数据源 + 判定条件 + 动作 + 推送渠道）
        ↓
② agent 把它翻译成结构化的声明式配置文件（原文叫 tasks/*.yaml）
        ↓
③ 人工审查这份生成物 —— 重点看 cron 表达式、阈值、推送目标有没有被误解
        ↓
④ 落盘成配置，之后进版本管理
```

**这条路线的真正价值不是省了写 YAML 的力气，而是把「意图」显式化了。** 第 ③ 步的审查动作会逼你确认三件事：

- **触发时机**对不对（`0 2 * * *` 是 2 点还是 20 点？时区是哪个？）
- **判定条件**被 agent 理解成什么了（我说「发现缺陷」，它写成 `total > 0` 还是 `confidence > 0.5`？）
- **推送目标**是哪个渠道、哪个群

这三点恰恰是自然语言最容易被「礼貌地误解」的地方。原文的五个例子都给了 agent 回显的生成配置原文 —— **这个回显动作本身才是最值钱的部分**，它把「我以为我配置对了」变成了「我看到配置长什么样」。

⚠️ 但要清楚这条路的边界：翻译层是 LLM，配置语法是你自己选的 DSL。**如果 DSL 本身是幻觉的（见第七节），这一步就会自信地生成一份完全无效的配置。** 所以低代码的前提是那个 DSL 真实存在。

---

## 五、沉淀物设计：三种产物，各有职责

原文的代码部分（无论接口细节如何对不上）体现了一个值得抄的产物设计 —— **检测结果被拆成三层，各自服务不同的读者**：

| 产物 | 内容 | 读者 | 用途 |
|---|---|---|---|
| 逐框明细（CSV / JSON） | 每张图每个框：类别 / 置信度 / 像素坐标 | 算法工程师 | 调阈值、复算、追责 |
| 统计摘要（summary.json） | 图片数 / 缺陷数 / 不良率 / 类别计数 | 车间 / 管理层 | 看日报、决定优先级 |
| 可视化附件（PNG 趋势图 / 标注框图） | 趋势线 / 检出框 | 排查人员 | 定位问题 |

原文的 CSV 用 `encoding='utf-8-sig'` —— 一个小但正确的细节（Excel 打开中文列名不乱码）。

判定结果的编码方式也值得注意：原文把 `confidence` 保留到小数点后 3 位、把 bbox 坐标 `round(..., 2)`，即**原始数值保留、展示时才截断**。这个「明细层不丢精度」的约定，比任何具体实现都重要。

---

## 六、跟我们的关系

**这台机器跑不了训练，但能跑通链路。** 实测本机（Macmini8,1，Intel i7-8809G，4 核）：`torch` 未安装、无 `nvcc` / `nvidia-smi`、Intel 集显上 MPS 后端等于没有（实际退回 CPU）。而已确认的环境事实是：VPS 纯调度编排、无本地算力。所以分工只能是 —— **训练临时租 GPU（只把几十 MB 的 `best.pt` 带回来）/ 推理放产线工控机 / 这台 Mac 只做小批量抽检与链路验证**。

### 可直接搬的三件事

**1. 三段式职责切分。** 判定在代码、编排与解释在 agent、通知走 channel。这个切法跟我们 `press-fit-guard`（Modbus 从站仿真 + SQLite WAL 落库）、`s7-monitor`（PLC 采集 + 越限报警）是一脉相承的取向 —— **不要让 LLM 去数缺陷个数，也不要让它去读 Modbus 寄存器**。原文 ⑤ 的「LLM 猜的归因」那段要当反面教材记：模型可以给假设，不能给结论。

**2. 五级递进当 checklist 用。** 我们最有价值的落点不是 ①②，而是 ③ 和 ⑤：
- ③ 定时跑完出趋势 + **带方向对比**，对上 `s7-monitor` 的「边沿即时 + 持续降频落库」模式 —— 落库产生的数据，正好喂给趋势分析
- ⑤ 归档 + 自然语言检索 —— 巡检照片、报警截图、故障波形按类型归档，以后一句「找上个月所有过热报警」就能查

**3. 声明式规则 + 明细拆解。** ④ 的「评分规则写成配置而非代码」可以直接搬到 `press-fit-guard` 的位移-压力包络线阈值 —— 让设备工程师自己调包络参数，而不是每次改 Python。以及「扣分明细拆解」这个输出形式：报「45 分」没人知道修什么，报「划痕 35 处」直接指向操作。

### 双通道兜底

告警链路不该只有一条腿。本机 OpenClaw 侧：Feishu default（configured, enabled）+ `openclaw-weixin`（configured, enabled）；企微插件 `wecom-openclaw-plugin` 2026.3.26 **已加载但 channel 未配凭证**（`config get wecom` 报 `Config path not found`）。Hermes 侧三个 gateway 在飞书上跑着。两条腿任一可用即可。

### 不建议照搬

「每天凌晨 2 点扫 10 万张图」对我们是伪需求 —— 我们没有产线。真正能落地的是**巡检照片定时抽检**：定时报一批图 → 检测 → 有异常才推人 → 顺手留 CSV 追溯。

---

## 七、落地时必须改的 6 处（一手核验）

原文的**方法论可以照抄，接口层必须整个重写**。以下每条都经 OpenClaw 2026.3.28 / ultralytics 8.4.181 实测：

| # | 原文写法 | 实测 |
|---|---|---|
| 1 | skill 目录含 `skill.json` + `prompt.md` + `tools/*.py`；`openclaw skills install .` | **OpenClaw 没有 `skill.json` 这个概念。** Skill = 一个目录 + `SKILL.md`（YAML frontmatter + markdown 正文），依赖声明在 frontmatter 的 `metadata.openclaw` 块（`requires.env` / `requires.bins` / `primaryEnv` / `install[]`）。且 `openclaw skills install` **只接受 ClawHub slug**，help 里只有 `--force` / `--version`，**没有本地路径参数** —— 本地 skill 靠丢进 `<workspace>/skills/<name>/SKILL.md` 被发现（优先级第 1） |
| 2 | `tools/detect_single.py` 自动注册成可调用的 `yolo-defect-detect.detect_batch` | **不会。** `SKILL.md` 是「教 agent 怎么用现有工具」的指令文件，旁边的 `.py` 只会经 shell/exec 调用，不会变成 tool。真正的可执行 tool 只能来自**插件**（JS/TS plugin） |
| 3 | `tasks/*.yaml` 的 `- step / tool / params / ${steps.x.output}` DSL | **没有这个 DSL。** 调度只有 5 种：`at` / `every` / `cron` / `on-exit` / `stream`。`cron add` 全部 34 个 flag 里没有任何 workflow / step / params 概念，`${steps.x.output}` 无对应物 |
| 4 | `watch: {directory, pattern, debounce}` 文件监听 | **没有这个配置。** 本机 2026.3.28 的 `cron add` 连 `--stream-command` 都没有（官方文档里有），所以 ② 的实时监听只能退化到 `--every 1m` 轮询，或自写 `fs.watch` / fswatch 脚本挂 `--on-exit`（本机也未装 fswatch） |
| 5 | `openclaw plugins install @openclaw/wecom-bot` + `config set wecom.corpId/agentId/secret` + `openclaw wecom send` | **三重错误。** ① npm 上 `@openclaw/wecom-bot` **404**；② 真名 `@wecom/wecom-openclaw-plugin`（腾讯企微团队官方，GitHub 475★）；③ 配置 key 全不同 —— Bot 模式是 `channels.wecom.botId` / `.secret` / `.enabled`，自建应用模式才是 `channels.wecom.agent.corpId` / `.corpSecret` / `.agentId` / `.token` / `.encodingAESKey`。`openclaw wecom` **子命令不存在** |
| 6 | `YOLOv8` + `ultralytics>=8.0.0` + `pip install -i https://pypi.douban.com/simple/` | 版本全面过时。PyPI 最新 **8.4.181（2026-10-17）**；官方文档现推 **YOLO26**（唯一覆盖全部 7 个任务），YOLO11 为成熟替代，YOLO27 还在 waitlist。⚠️ 豆瓣 PyPI 镜像本次实测 **curl 超时连不上** |

**另有一条文档与版本不一致（原文不会提，但会让你白折腾）**：官方文档 Automation 章节通篇写 `openclaw automations add` / `list`，但本机 2026.3.28 实测 `openclaw automations` 和 `openclaw lobster` 都返回 **`unknown command`** —— 文档口径领先于本机版本，只有 `openclaw cron` 可用。写教程不要照抄文档里的命令名。

### 真实接口对照（把原文的四步法改成能跑的）

**① 训练** —— `data.yaml` 那段原文是**对的**，实测源码 `ultralytics/data/utils.py` 的 `check_det_dataset` 确认：`names` 与 `nc` 至少要有一个，两者都给时**长度必须一致**（否则 `SyntaxError`）；`train`/`val` 指向的目录找不到图片抛 `FileNotFoundError`。标注为 `class_id cx cy w h`，全部归一化到 0~1。

```bash
conda create -n yolo-defect python=3.10 -y && conda activate yolo-defect
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install -U ultralytics          # 8.4.181，务必 pin 版本（一周三发）
```

```yaml
# defect_dataset/data.yaml
path: /path/to/defect_dataset
train: images/train
val: images/val
nc: 4                              # 与 names 长度必须一致
names: [scratch, dent, stain, crack]
```

```python
from ultralytics import YOLO
model = YOLO('yolo26n.pt')
model.train(data='defect_dataset/data.yaml', epochs=100, imgsz=640,
            batch=16, name='defect_v1', device=0, patience=20)
# runs/detect/defect_v1/weights/best.pt
```

**② skill** —— 换成 `SKILL.md`（关键是把判定规则写进去，而不是让模型自己看结果）：

```markdown
---
name: yolo-defect
description: 用 YOLO 检测产品表面缺陷（划痕/凹坑/污渍/裂纹），产出 CSV + 摘要 JSON。
version: 1.0.0
metadata:
  openclaw:
    emoji: "🔍"
    requires:
      bins: [python3]
      config: [models/defect_v1/weights/best.pt]
---
# YOLO 缺陷检测
## 何时用
用户提到「缺陷 / 不良 / 划痕 / 质检 / 检测这批图」时。
## 怎么做
单张：python3 tools/detect_single.py <image> --conf 0.25
批量：python3 tools/detect_batch.py <dir> --conf 0.25 --out reports/
## 判定规则（由代码判定，不要让模型自己数）
- total_detections > 0 → 不良
- confidence < 0.25 → 记「待人工复核」，不计入不良率
- crack 任一命中 → 立即告警，不等批次结束
## 汇报格式（固定）
总检测数 / 不良率 / 各类别计数 / 待复核数
```

**③ 编排** —— 换成 `cron`（无 YAML DSL）：

```bash
openclaw cron add \
  --name "每日缺陷统计报表" \
  --cron "0 2 * * *" --tz Asia/Shanghai --exact \
  --message "用 yolo-defect skill：批量检测 /data/products/，生成 CSV + summary.json，整理成中文日报（总检测数/不良率/各类别计数/待复核数）后推送企业微信。" \
  --announce --channel wecom --timeout-seconds 1800
```

⚠️ 两个 cron 坑：整点通配表达式（`0 * * * *`）会被**自动 stagger 最多 5 分钟**，要精确加 `--exact` 或 `--stagger 30s`；`--tz` 只对 `--at` / `--cron` 有效，与 `--every` / `--on-exit` 同用会报错，无 `--tz` 时按 Gateway 主机时区解释。**原文「02:00 检测、08:00 推送」的分时设计用 `--cron` 要配两个 job**，不能写在同一个配置里。

**④ 企微推送** —— 换成真实配置路径：

```bash
npx -y @wecom/wecom-openclaw-cli install          # 官方一键，顺带走完 bot 配置
# 或手动
openclaw plugins install @wecom/wecom-openclaw-plugin
openclaw config set channels.wecom.botId  <BOT_ID>
openclaw config set channels.wecom.secret <BOT_SECRET>
openclaw config set channels.wecom.enabled true
openclaw gateway restart
```

Bot 模式（WebSocket 长轮询，只要 botId + secret）比自建应用模式（HTTP 回调，要 corpId/corpSecret/agentId + token + encodingAESKey）简单得多，除非要用企业应用能力否则选前者。要用插件的企微业务能力（文档 / 智能表格 / 日历）再放行：

```bash
openclaw config set tools.alsoAllow '["wecom-openclaw-plugin"]'   # 已有内容要合并，别覆盖
openclaw gateway restart
```

**判定脚本三个原文没提的工程坑**：

1. **模型要模块级加载一次**。原文 `detect_batch.py` 循环调 `detect_single`，等于每张图重建模型 + 重新 warmup。
2. **良率要按「图片」去重，不是按「缺陷个数」**。原文 `defect_rate = total_detections / total_images` —— 一张图 5 个划痕就算 5 个不良，良率虚高。
3. **趋势归因要标为假设**。原文 ③ 里 OpenClaw 直接说「划痕问题在 2 号线持续上升」—— 这是模型看数字猜的，生产环境必须标注「待验证」。

---

## 八、两个真问题

### Ultralytics 一周三发

实测近 5 个版本：8.4.177（10-13）→ 8.4.178（10-16）→ 8.4.179（10-17）→ 8.4.180（10-17）→ 8.4.181（10-17），内容从 RKNN toolkit 约束到 YOLO26-pose 标签分配再到 `.yml` 数据集发现回归修复。**生产必须 pin 版本**，不要 `pip install -U` 后裸跑。

### ⚠️ AGPL-3.0 是这套方案最大的变量

实测 `ultralytics/ultralytics` 主仓 license 为 **AGPL-3.0**（GitHub API `spdx_id`）。边界大致如下（**非法律意见**）：

| 场景 | 义务 |
|---|---|
| 公司内部自用，不对外提供网络服务 | 不触发「对外提供」条款，闭源可用 |
| 作为 SaaS / Web 服务对外提供 | 属「网络交互」，需按 AGPL 开源整体 |
| 打进要分发的客户端 / 边缘设备软件 | 强传染，必须整体开源 |

Ultralytics 官方卖 Enterprise License 做闭源商用。**这套要对外交付或做成服务，得先过法务。**

另：Ultralytics 默认开启匿名遥测（使用统计不出本机），内网合规场景建议显式关闭。

---

## 参考链接

- 原文（触发来源）: https://mp.weixin.qq.com/s/qzfxrqYrHUY_tRewmzX1Lw
- OpenClaw 文档: https://docs.openclaw.ai
  - Skill format（SKILL.md + frontmatter 全字段表）: https://docs.openclaw.ai/clawhub/skill-format
  - Skills（加载优先级 / 安全 / token 影响）: https://docs.openclaw.ai/tools/skills
  - Automation schedules（5 种调度 + stagger 坑）: https://docs.openclaw.ai/automation/cron-jobs/schedules
  - Lobster（pipeline 是 JSON 不是 YAML DSL）: https://docs.openclaw.ai/tools/lobster
  - WeCom channel: https://docs.openclaw.ai/channels/wecom
- Ultralytics:
  - 文档: https://docs.ultralytics.com · Quickstart https://docs.ultralytics.com/quickstart/
  - Models（YOLO26 / YOLO11 / YOLO27 waitlist）: https://docs.ultralytics.com/models/
  - 仓库: https://github.com/ultralytics/ultralytics （AGPL-3.0，⭐ 62,594）
- 企业微信插件: https://github.com/WecomTeam/wecom-openclaw-plugin （⭐ 475）
- 相关笔记: [s7-monitor](../ops-cybersec-dba/s7-monitor.md) · [press-fit-guard](../developer-productivity/press-fit-guard.md) · [openclaw-awd-arena](openclaw-awd-arena.md)
