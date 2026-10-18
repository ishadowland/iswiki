# OpenClaw × Ultralytics YOLO — 「让 agent 7×24 盯着流水线」的架构骨架，以及公众号教程里 6 处跑不通的地方

> 学习笔记 · 调研时间 2026-10-18
> 触发来源: 微信公众号《让 OpenClaw 指挥 YOLO，7×24 小时盯着流水线》(机器学习AI算法工程) https://mp.weixin.qq.com/s/qzfxrqYrHUY_tRewmzX1Lw (发布 2026-09-29)
> 上游: OpenClaw https://docs.openclaw.ai · https://github.com/openclaw · Ultralytics https://docs.ultralytics.com
> License: **Ultralytics 主仓 AGPL-3.0**(实测 GitHub API `license.spdx_id`) · OpenClaw 本机 CLI 2026.3.28 · Ultralytics 8.4.181 (2026-10-17) · ultralytics/ultralytics ⭐ 62,594

---

## 一句话定位

把 YOLO 缺陷检测封装成 agent skill，用定时任务编排「检测 → 报表 → 预警」的离线自动化流水线 —— 骨架对，但公众号给的**接口、配置 key、调度语法三处全是幻觉**，照抄跑不起来。

---

## 一手核验：原文 6 处不能照抄

原文整体架构直觉是对的（**不追求实时，先做离线自动化**这个判断很清醒），但它写的 skill 格式、插件名、配置 key、任务 DSL **与 OpenClaw 2026.3.28 实际实现全都不匹配**。逐条实测如下。

| # | 原文写法 | 实测（OpenClaw 2026.3.28 + ultralytics 8.4.181） |
|---|---|---|
| 1 | skill 目录含 `skill.json` + `prompt.md` + `tools/*.py`，`openclaw skills install .` | **OpenClaw 没有 `skill.json` 这个概念。** Skill = 一个目录 + 一份 `SKILL.md`（YAML frontmatter + markdown 正文）。运行时依赖声明在 frontmatter 的 `metadata.openclaw` 块里（`requires.env` / `requires.bins` / `primaryEnv` / `install[]`）。⚠️ 且 `openclaw skills install` **只接受 ClawHub slug**，help 里只有 `--force` / `--version`，**没有本地路径参数** —— 本地 skill 靠丢进 `<workspace>/skills/<name>/SKILL.md` 被自动发现 |
| 2 | `tools/detect_single.py` 会被自动注册成 agent 可调用的 `yolo-defect-detect.detect_batch` | **不会。** `SKILL.md` 是「教 agent 怎么用现有工具」的指令文件，`.py` 放在旁边不会被变成 tool。真正的可执行 tool 只能来自**插件**（JS/TS plugin）。想暴露成 tool 要么用 Lobster 调 CLI，要么写 plugin |
| 3 | `tasks/daily_defect_report.yaml` 里的 `- step: detect / tool: ... / params: ... / ${steps.detect.output}` DSL | **OpenClaw 没有 tasks/*.yaml workflow DSL。** 调度只有 5 种：`at` / `every` / `cron` / `on-exit` / `stream`。`cron add` 的 34 个 flag 里没有任何 workflow/step/params 概念，`${steps.x.output}` 无对应物 |
| 4 | `watch: {directory, pattern, debounce}` 文件监听 | **没有这个配置。** 本机 2026.3.28 的 `cron add` 连 `--stream-command` 都没有（只有文档里写有），所以真要做监听只能退化到 `--every 1m` 轮询，或自己写 fswatch/fs.watch 脚本挂 `--on-exit` |
| 5 | `openclaw plugins install @openclaw/wecom-bot` + `openclaw config set wecom.corpId/agentId/secret` + `openclaw wecom send` | **三重错误。** ① npm 上 `@openclaw/wecom-bot` **404**（实测）；② 真实包名是 `@wecom/wecom-openclaw-plugin`（腾讯企业微信团队官方维护，GitHub 475★）；③ 配置 key 全部不同 —— Bot 模式是 `channels.wecom.botId` / `channels.wecom.secret` / `channels.wecom.enabled`，自建应用模式才是 `channels.wecom.agent.corpId` / `corpSecret` / `agentId` / `token` / `encodingAESKey`。`openclaw wecom` 这个 CLI 子命令**不存在**（实测回落到顶层 help） |
| 6 | `YOLOv8` + `ultralytics>=8.0.0` + `pip install -i https://pypi.douban.com/simple/` | 版本全面过时。PyPI 最新 **8.4.181（2026-10-17）**；官方文档现推 **YOLO26**（唯一覆盖全部 7 个任务），YOLO11 为成熟替代，YOLO27 还在 waitlist。⚠️ 豆瓣 PyPI 镜像本次实测 **curl 超时连不上**，别写进教程 |

**另一处文档/版本不一致（值得单独记）**：官方文档 Automation 章节通篇写 `openclaw automations add` / `openclaw automations list`，但本机 2026.3.28 实测 `openclaw automations` 和 `openclaw lobster` 都返回 **`unknown command`** —— 新版文档口径领先于本机版本，只有 `openclaw cron` 可用。写教程时不要照抄文档里的命令名。

### 一处原文**对**的地方

`data.yaml` 那段是对的，实测源码确认（`ultralytics/data/utils.py` `check_det_dataset`）：`names` 与 `nc` **至少要有一个**，两者都给时**长度必须一致**，否则抛 `SyntaxError`；`train`/`val` 指向的目录找不到图片抛 `FileNotFoundError`。原文同时给了 `nc: 4` + 4 个 names，是合法写法。

---

## 骨架：把 agent 放在哪里才对

原文最值得抄的是**架构判断**，不是代码。

```
❌ 原文想象的结构（三个都是幻觉）
OpenClaw ──skill.json──> tools/*.py 自动注册为 tool
        └──tasks/*.yaml workflow DSL──> ${steps.x.output}

✅ OpenClaw 2026.3.28 的真实结构
OpenClaw
├── Skills（<workspace>/skills/<name>/SKILL.md）
│   └── markdown 指令：教 agent「什么时候、怎么调」现有工具
│       附带的 .py 只会被 shell/exec 调用，不会变成 tool
├── Automations（openclaw cron add --cron / --every / --on-exit）
│   └── 触发 → 唤醒 agent（--message 给它一句任务）
│       → agent 读 SKILL.md → exec 跑检测脚本 → 汇总 → --announce 推送到 channel
├── Lobster（stock plugin，本机 disabled）
│   └── 多步 pipeline 当**一次** tool call，带 approval 断点 + resume token
│       pipeline 是 JSON，不是 YAML DSL
└── Channels（wecom / feishu / weixin…）—— 推送落地
```

**延迟论证成立且应当保留**：agent 调 LLM 单次往返 1-3s，YOLO 推理 0.1-0.5s，端到端 5s+ —— 这在高速产线上是致命的。所以：

| 场景 | 适不适合放 agent |
|---|---|
| 单件实时拦截（<100ms 预算） | ❌ 别放，agent 的 LLM 往返就是硬下限 |
| 批量离线质检（夜班跑全量图，出日报） | ✅ 合适，agent 负责编排 + 解释 + 推送，不负责判定 |
| 巡检照片抽检（每小时一次） | ✅ 合适，延迟无所谓 |
| 告警链路（发现问题 → 推企微） | ✅ 合适，但**判定必须在代码里，agent 只做通知与解释** |

---

## 最小可运行示例（OpenClaw 2026.3.28 实测口径）

### 1. 训练 YOLO（脱离 agent，纯 Python）

```bash
conda create -n yolo-defect python=3.10 -y && conda activate yolo-defect

# PyTorch 先装（版本随 CUDA 变；CPU 版去掉 --index-url）
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install -U ultralytics          # 8.4.181，实测可用；不要用已超时的豆瓣镜像
```

```
defect_dataset/
├── images/{train,val}/*.jpg
└── labels/{train,val}/*.txt     # 一一对应，YOLO 归一化格式
```

```yaml
# defect_dataset/data.yaml
path: /path/to/defect_dataset
train: images/train
val: images/val
nc: 4                              # 与 names 长度必须一致，否则 SyntaxError
names: [scratch, dent, stain, crack]
```

标注每行 `class_id cx cy w h`，**全部归一化到 0~1**：

```
0 0.512 0.423 0.234 0.156
1 0.678 0.345 0.089 0.123
```

```python
from ultralytics import YOLO

model = YOLO('yolo26n.pt')          # 新项目从 YOLO26 起步（自动下载权重）
model.train(
    data='defect_dataset/data.yaml',
    epochs=100, imgsz=640, batch=16,
    name='defect_v1', device=0,     # 无 GPU 写 'cpu'
    patience=20,
)
# 最佳权重：runs/detect/defect_v1/weights/best.pt

# 验证
best = YOLO('runs/detect/defect_v1/weights/best.pt')
best('test.jpg', conf=0.25)
best('/data/products/*.jpg', conf=0.25, save=True)   # 结果落在 runs/detect/predict/
```

CLI 等价（Ultralytics 自带 `yolo` 命令）：

```bash
yolo predict model=yolo26n.pt source=0 show=True    # source=0 是摄像头
yolo detect train data=defect_dataset/data.yaml epochs=100 imgsz=640
```

### 2. Skill（真实格式，不是 skill.json）

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
单张检测：
    python3 tools/detect_single.py <image_path> --conf 0.25

批量检测（输出 CSV + summary.json）：
    python3 tools/detect_batch.py <image_dir> --conf 0.25 --out reports/

## 判定规则（由代码判定，不要让模型自己数）
- `total_detections > 0` → 视为不良
- `confidence < 0.25` → 记为「待人工复核」，不计入不良率
- 裂纹（crack）任一命中 → 立即告警，不等批次结束

## 汇报格式
固定输出：总检测数 / 不良率 / 各类别计数 / 待复核数。
```

放在 `~/.openclaw/workspace/skills/yolo-defect/SKILL.md` 即被加载（**skills 加载优先级第 1：workspace skills**）。改完刷新：

```bash
openclaw skills check                       # 哪个 ready 哪个缺依赖
openclaw skills info yolo-defect
```

⚠️ frontmatter 声明要和代码实际用的东西一致。ClawHub 的安全分析会核对「代码里引用的环境变量 vs frontmatter 声明」，不匹配会被标 metadata mismatch。可选变量用 `envVars` + `required: false`，**不要**塞进 `requires.env`（那语义是「没它就跑不了」）。

### 3. 自动化（`cron`，不是 tasks/*.yaml）

```bash
# 每天 02:00 跑全量检测，08:00 前把日报推到企业微信
openclaw cron add \
  --name "每日缺陷统计报表" \
  --cron "0 2 * * *" --tz Asia/Shanghai \
  --exact \
  --message "用 yolo-defect skill：批量检测 /data/products/，生成 CSV + summary.json，整理成中文日报（总检测数/不良率/各类别计数/待复核数）后推送到企业微信。" \
  --announce --channel wecom \
  --timeout-seconds 1800

openclaw cron list
openclaw cron runs        # 历史
openclaw cron disable <id> / enable <id> / rm <id>
```

⚠️ 两个 cron 坑（实测自官方文档）：

- **顶小时表达式会被自动 stagger 最多 5 分钟**（`0 2 * * *` 里的整点是 `0 N * * *` 通配小时，这里不触发；但 `0 * * * *` 会）。要精确就加 `--exact` 或 `--stagger 30s`。
- **`--tz` 只对 `--at` / `--cron` 有效**，跟 `--every` / `--on-exit` 一起用会报错。无 `--tz` 时按 Gateway 主机时区解释。

### 4. 缺陷判定脚本（真正该由代码干的活）

```python
# tools/detect_batch.py —— 注意这里刻意不 import 任何 agent SDK
import json, sys
from pathlib import Path
import pandas as pd
from ultralytics import YOLO

WEIGHTS = Path(__file__).resolve().parents[1] / "models/defect_v1/weights/best.pt"
CONF, IOU = 0.25, 0.45
REVIEW_BELOW = 0.40          # 低于此置信度不算不良，记待复核

model = YOLO(str(WEIGHTS))
rows = []
for img in sorted(Path(sys.argv[1]).glob("*.jpg")):
    for r in model(str(img), conf=CONF, iou=IOU):
        for box in r.boxes:
            x1, y1, x2, y2 = box.xyxy[0].tolist()
            conf = float(box.conf[0])
            cls = int(box.cls[0])
            rows.append({
                "image": img.name, "class": r.names[cls], "confidence": round(conf, 3),
                "x1": round(x1, 2), "y1": round(y1, 2), "x2": round(x2, 2), "y2": round(y2, 2),
                "verdict": "review" if conf < REVIEW_BELOW else "defect",
            })

df = pd.DataFrame(rows)
out = Path(sys.argv[2] if len(sys.argv) > 2 else "reports"); out.mkdir(parents=True, exist_ok=True)
df.to_csv(out / "daily_report.csv", index=False, encoding="utf-8-sig")

n_img = len(list(Path(sys.argv[1]).glob("*.jpg")))
hard = df[df["verdict"] == "defect"]
summary = {
    "总检测图片数": n_img,
    "不良件数": int(hard["image"].nunique()),
    "不良率": round(hard["image"].nunique() / n_img * 100, 2) if n_img else 0.0,
    "待复核件数": int(df[df["verdict"] == "review"]["image"].nunique()),
    "各类别计数": hard["class"].value_counts().to_dict(),
    "裂纹命中": bool((hard["class"] == "crack").any()),   # 硬告警开关
}
(out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))
```

三个工程点，公众号原文都没提：

1. **模型每次调用都重新 `YOLO(...)`** —— 批量场景应该模块级加载一次，否则每张图付一次权重加载 + warmup。原文 `detect_batch.py` 循环调 `detect_single`，等于每图重建模型。
2. **良率要按「图片」去重，不是按「缺陷个数」**。原文 `defect_rate = total_detections / total_images` —— 一张图上有 5 个划痕就算 5 个不良，良率直接虚高。
3. **`csv` 用 `utf-8-sig`**，否则 Excel 打开中文列名乱码。

### 5. 企业微信推送（真实配置路径）

```bash
# 官方一键装（顺带把 bot 配置交互走完）
npx -y @wecom/wecom-openclaw-cli install
npx -y @wecom/wecom-openclaw-cli install --force     # 失败时

# 或手动
openclaw plugins install @wecom/wecom-openclaw-plugin

# Bot 模式（智能机器人，WebSocket 长轮询，最省事）
openclaw config set channels.wecom.botId  <BOT_ID>
openclaw config set channels.wecom.secret <BOT_SECRET>
openclaw config set channels.wecom.enabled true
openclaw gateway restart
```

| 配置路径 | 说明 | 默认 |
|---|---|---|
| `channels.wecom.connectionMode` | `websocket` / `webhook` | `websocket` |
| `channels.wecom.websocketUrl` | 长轮询端点 | `wss://openws.work.weixin.qq.com` |
| `channels.wecom.name` | 账号显示名 | `企业微信` |
| `channels.wecom.sendThinkingMessage` | 发「思考中」占位 | `true` |
| `channels.wecom.agent.corpId` | 自建应用 CorpID | — |
| `channels.wecom.agent.corpSecret` | 自建应用密钥 | — |
| `channels.wecom.agent.agentId` | 自建应用 AgentId | — |
| `channels.wecom.agent.token` | 回调 token（webhook 模式） | — |
| `channels.wecom.agent.encodingAESKey` | 43 字符 Base64（webhook 模式） | — |

两种模式选一套：Bot 模式走 WebSocket，只要 botId + secret；自建应用（Agent 模式）走 HTTP 回调，消息是 XML，要配公网可访问的回调地址 + token + AESKey。**Bot 模式简单得多，除非你非要用企业应用能力。**

要用插件提供的企微业务能力（文档 / 智能表格 / 日历），还得放行插件：

```bash
openclaw config set tools.alsoAllow '["wecom-openclaw-plugin"]'
openclaw gateway restart
```

⚠️ `tools.alsoAllow` 已是数组时要**合并**而不是覆盖。

---

## 版本节奏与许可证（两个真问题）

### Ultralytics 8.4.x 发布极快

实测近 5 个版本：

| 版本 | 发布时间 | 改动 |
|---|---|---|
| 8.4.177 | 2026-10-13 | — |
| 8.4.178 | 2026-10-16 | — |
| 8.4.179 | 2026-10-17 | cap rknn-toolkit2 < 2.5 + RKNN imgsz=64 smoke |
| 8.4.180 | 2026-10-17 | YOLO26-pose 的 OKS-aware 标签分配 |
| 8.4.181 | 2026-10-17 | 修 `.yml` 数据集发现回归 + 大小写不敏感 source 列表 |

**一周三发**。生产环境必须 pin 版本，不要 `pip install -U ultralytics` 后裸跑。

### ⚠️ AGPL-3.0：把 YOLO 塞进商业质检的最大变量

实测 `ultralytics/ultralytics` 主仓 license 是 **AGPL-3.0**（GitHub API `spdx_id`）。边界大致如下（**不是法律意见，具体场景找法务**）：

| 场景 | 义务 |
|---|---|
| 公司内部自用，不对外提供网络服务 | 不触发 AGPL 的「对外提供」条款，闭源可用 |
| 作为 SaaS / Web 服务对外提供 | 属「网络交互」，需按 AGPL 开源整体 |
| 打进要分发的客户端 / 边缘设备软件 | 强传染，必须整体开源 |

Ultralytics 官方卖 Enterprise License 做闭源商用。如果这套要**对外交付或做成服务**，这条必须先过法务，不要等上线前才发现。

另外 Ultralytics 默认开启匿名遥测（用户数据不出本机，只发使用统计），内网合规场景建议显式关掉。

---

## 跟我们的关系

**这台机器跑不了训练，但能跑推理。** 实测本机（Macmini8,1，Intel i7-8809G，4 核）：

- `torch` 未安装
- 无 `nvcc` / `nvidia-smi`
- Intel 集显 —— 即便装上 PyTorch，MPS 后端在 Intel Mac 上基本等于没有，实际会退回 CPU

CPU 上 `yolo26n` @ imgsz=640 单图大致秒级，**夜班全量跑几万张图不现实**。而按已确认的环境事实，我们的 VPS 是纯调度/编排、无本地算力。所以分工只能是：

- **训练**：临时租 GPU（AutoDL / 恒源云 / RunPod），训完只把 `best.pt` 拿回来（几十 MB）
- **推理**：放产线边缘小主机 / 工控机，不是这台 Mac mini
- **这台 Mac**：只适合做「小批量抽检 + 跑通链路验证」

### 本机 OpenClaw 现状（实测 2026-10-18）

| 项 | 状态 |
|---|---|
| CLI 版本 | 2026.3.28 (f9b1079) |
| workspace | `~/.openclaw/workspace` |
| 已有 skill（4 个，全是本地 markdown 型） | `changting-waf` / `nuwa-skill` / `openmtp-cli` / `waf-validator-skills` |
| 已加载 channel | Feishu default（configured, enabled）、`openclaw-weixin`（configured, enabled） |
| 企微插件 | 插件**已加载**（`global:wecom-openclaw-plugin` 2026.3.26），但 `channels list` 里**没有 wecom**，`openclaw config get wecom` 报 `Config path not found` → **插件在、channel 没配凭证** |
| Lobster | `stock:lobster/index.js`，状态 **disabled** |
| gateway | 18789，本机 loopback，当前 `pairing required`（CLI 未配对，cron 类命令全部连不上） |

**已有 4 个 skill 全是本地 `SKILL.md` 型，零 `skill.json`** —— 这本身就是对「OpenClaw 没有 skill.json 格式」的一手佐证。

### 可直接搬的三件事

1. **三段式职责切分**：判定在代码、编排和解释在 agent、通知走 channel。这个切法跟我们 `press-fit-guard`（Modbus 从站 + SQLite WAL 落库）那种「硬逻辑自己扛，agent 只做上界」的取向一致 —— 不要让 LLM 去数缺陷个数。
2. **Skill 封装 + cron 编排 + 报表落库**这个骨架可以直接套到 `s7-monitor` / `press-fit-guard` 的告警链路上，做「夜班跑完出日报，异常才推人」。
3. **双通道兜底**：企微（已装插件，缺凭证）+ 飞书（本机 Hermes 已在飞书上跑三个 gateway）。告警链路不该只有一条腿。

### 不建议照搬的

公众号那套「每天凌晨 2 点扫 10 万张图」在我们这儿是伪需求 —— 我们没有产线。真正能落地的是**巡检照片抽检**：定时报一批图 → 检测 → 有裂纹/异常才推送 → 顺手留一份 CSV 追溯。这正好对上 `s7-monitor` 的「边沿即时 + 持续降频落库」模式。

---

## 参考链接

- 原文（触发来源）: https://mp.weixin.qq.com/s/qzfxrqYrHUY_tRewmzX1Lw
- OpenClaw 文档: https://docs.openclaw.ai
  - Skill format（SKILL.md + frontmatter 字段全表）: https://docs.openclaw.ai/clawhub/skill-format
  - Skills（加载优先级 / 安全 / token 影响）: https://docs.openclaw.ai/tools/skills
  - Automation schedules（5 种调度 + stagger 坑）: https://docs.openclaw.ai/automation/cron-jobs/schedules
  - Lobster（pipeline 是 JSON 不是 YAML DSL）: https://docs.openclaw.ai/tools/lobster
  - WeCom channel: https://docs.openclaw.ai/channels/wecom
- Ultralytics:
  - 文档: https://docs.ultralytics.com · Quickstart https://docs.ultralytics.com/quickstart/
  - Models（YOLO26 / YOLO11 / YOLO27 waitlist）: https://docs.ultralytics.com/models/
  - 仓库: https://github.com/ultralytics/ultralytics （AGPL-3.0，⭐ 62,594）
- 企业微信插件: https://github.com/WecomTeam/wecom-openclaw-plugin （⭐ 475）
