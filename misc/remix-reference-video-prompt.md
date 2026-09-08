# remix-reference-video-prompt — 爆款视频复刻 Skill

> 学习笔记 · 调研时间 2026-08-14
> 仓库: <https://github.com/penposs/remix-reference-video-prompt>
> 视频模型: MiniMax H3 (开源, 5914 ⭐, MiniMax-AI 出品)
> 来源: B 站 / RunningHub / 相工云 教程
> License: 无显式声明 · ⭐ 92 · 11 forks · 1 commit · Python 100%

## 一句话定位

**一个 SKILL.md 文件级别的 prompt skill** —— 教 AI agent 按"参考视频"自动拆解镜头、运镜、转场节奏,然后让 MiniMax H3 (或 Seedance / 其他视频模型) 按结构**生成可直接复用的视频提示词**,**保留爆款节奏、只换视觉内容**(人物/服装/背景/产品)。

## 跟"普通文生视频"对比

| 维度 | 普通文生视频 | remix-reference-video-prompt |
|---|---|---|
| 输入 | 文字描述 | **参考视频 + 用户素材 + 目标描述** |
| 输出 | 单段视频 | **分镜拆解 + 改写后提示词** |
| 复刻爆款 | ❌ 完全自由生成 | ✅ 保留时间轴 + 运镜 + 转场,只换视觉 |
| 视频模型 | 任意 | 主要适配 **MiniMax H3**(也支持通用 / Seedance) |
| 校验 | ❌ | ✅ 2 个 Python 脚本,验证时间轴 + 字数 |

## 5 个工作模式

| Mode | 何时用 |
|---|---|
| `deconstruct_only` | "拆解这个参考视频",**不**生成提示词 |
| `deconstruct_and_prompt` | "参考这个写提示词" / "照这个做一个" |
| `selective_remix` | "保留 A,改 B"(逐层选策略) |
| `visual_remix_locked` | "**镜头不变、只换视觉**"(爆款换皮,最常用) |
| `free_rebuild` | "参考节奏,允许重新设计" (默认全锁,必须用户明确允许) |

**核心锁定维度** (visual_remix_locked 默认):
- `timeline` (时长/分段/卡点) → preserve
- `camera` (景别/角度/运镜) → preserve
- `composition` (构图) → preserve
- `actions` (动作) → preserve
- `transitions` (转场) → preserve
- `audio_timing` (音乐卡点) → preserve

**允许替换维度** (默认 replace):
- `visuals` (人物/妆发/服装/场景/光线/色彩)
- `product_brand` (产品/包装/品牌)
- `props` (道具外观,运动保留)
- `text` (字幕文案)

## 5 步上手

### Step 1: 装 Skill

```powershell
# Codex 全局
git clone https://github.com/penposs/remix-reference-video-prompt.git "$env:USERPROFILE\.codex\skills\remix-reference-video-prompt"

# Codex 项目级
git clone https://github.com/penposs/remix-reference-video-prompt.git ".agents\skills\remix-reference-video-prompt"

# Claude Code 项目级
git clone https://github.com/penposs/remix-reference-video-prompt.git ".claude\skills\remix-reference-video-prompt"
```

### Step 2: 给 prompt

```text
用 remix-reference-video-prompt 拆解这条参考视频，
保留镜头、运镜、动作顺序和转场，只把人物、服装、背景与产品
换成我提供的素材，最后输出 Seedance 可直接使用的提示词。
```

### Step 3: 提供素材

- **参考视频** (URL / 本地文件)
- **人物图 / 产品图 / 场景图** (用于视觉替换)
- **品牌素材** (logo / 配色 / 文案)
- **目标描述** (用途 / 受众 / 时长 / 画幅 / 目标模型)

### Step 4: 选模式

默认按用户原话推断:
- "分析 / 拆解 / 研究" → `deconstruct_only`
- "参考 / 照这个" → `deconstruct_and_prompt`
- "保留 A 改 B" → `selective_remix`
- "镜头不变只换视觉" → `visual_remix_locked`

### Step 5: 校验 (可选)

```powershell
# 校验拆解 JSON 结构
python scripts/validate_deconstruction.py --input deconstruction.json

# 校验改写后提示词 (含时间轴)
python scripts/validate_remix.py `
  --source "<原提示词>" `
  --output "<最终提示词>" `
  --contract remix-contract.json
```

## 输出格式 (Markdown 镜头表)

| 时间 | 镜头与构图 | 主体动作 | 场景与视觉 | 转场/字幕/声音 | 功能 | 策略 |
|---|---|---|---|---|---|---|
| 0-2s | 固定正面中景,人物居中 | 拿起产品、开盖 | 白色影棚,硬光 | 开瓶声,硬切 | 建立产品 | 运镜保留,视觉替换 |
| 2-5s | 正面特写,产品居中 | 倒水、冒泡 | 桌面,暖光 | 倒水声 | 展示细节 | 替换 |
| ... |

+ 精简结构总结(不重复逐格)

## 输出格式 (JSON 结构)

```json
{
  "schema_version": 1,
  "source": { "type": "video", "path_or_url": "ref.mp4", "evidence": "video" },
  "goal": "保留镜头节奏,重做人物和产品广告",
  "duration_seconds": 15,
  "shots": [
    {
      "shot_id": "S01",
      "start_seconds": 0,
      "end_seconds": 2,
      "camera": "fixed-front-medium-shot",
      "composition": "subject-center",
      "action": "拿起产品,开盖",
      "transition_effects": ["hard-cut"],
      "audio": "开瓶声",
      "narrative_function": "establish-product",
      "policy": "preserve"
    }
  ]
}
```

## 4 种层级策略 (Layer Contract)

| 策略 | 含义 |
|---|---|
| `preserve` | 内容、顺序、功能全部保留 |
| `adapt` | 保留功能/节奏,允许按新素材调整表现 |
| `replace` | 用用户新内容重新设计 |
| `omit` | 明确删除 |

**12 个可控制层级**:
1. `timeline` - 时长/分段/镜头顺序/卡点
2. `camera` - 景别/角度/机位/镜头运动
3. `composition` - 主体位置/画面重心/前后景
4. `actions` - 动作顺序/方向/轨迹/速度/停顿
5. `transitions` - 硬切/遮挡/蒙版/匹配剪辑/变形/定格
6. `text` - 字幕内容/位置/动画
7. `audio_timing` - 音乐卡点/音效触发
8. `audio_style` - 音乐类型/音色/环境声
9. `visuals` - 人物/妆发/服装/场景/光线/色彩/材质
10. `props` - 道具外观/数量/位置/轨迹
11. `product_brand` - 产品/包装/标签/品牌
12. `narrative` - 信息顺序/冲突/卖点/情绪曲线

## 证据边界(关键设计)

> "实际读取并查看视频后,才可以说'根据参考视频拆解'。
> 只有提示词、脚本或字幕时,标记为 `prompt_only`,**不得声称看过视频**。
> 图片必须逐张查看,不根据文件名推断。"

→ **Skill 主动防 hallucinate** — 输入类型决定 evidence type:
- `video` (真看过视频)
- `prompt_only` (只有文本)
- `transcript_only` (只有字幕)
- `mixed` (混合证据)

## 冲突优先级 (5 层)

1. **用户当前明确要求** (最高)
2. **实际观察到的视频内容**
3. **原始提示词 / 脚本 / 字幕**
4. **人物图 / 产品图 / 其他素材**
5. **保守假设** (最低)

## 拆解分段原则 (deconstruction-schema.md)

按以下任一变化新建镜头/连续段:
- 明显切镜或转场
- 机位/景别/角度/运镜改变
- 主体/主要动作/动作目的改变
- 场景/时间/服装/产品展示阶段改变
- 字幕/音效/叙事功能明显切换

> **不要为了凑数量拆镜**。连续长镜头按动作阶段分段,但要标记同一镜头。

## 提示词生成规则 (7 条)

1. 先落实用户保留策略,再写最终画面
2. 用户指定模型时,**适配该模型表达习惯**(MiniMax H3 / Seedance 等)
3. **每段直接写最终主体/场景/动作/镜头/转场/字幕/声音**,不解释"从什么改成什么"
4. **保留项必须写入提示词**;替换项用真实素材特征
5. 只保留必要的全局一致性约束(同人物不变形/文字准确/固定机位)
6. 默认长度 ≤ 1600 字符
7. 用户只要结果时,**仅输出可直接复制的视频提示词**

## 提示词禁止句式

禁止在成品提示词中写:
- "把原人物替换为..."
- "原场景改成..."
- "如果与参考视频冲突..."
- 长篇解释拆解 / 映射 / 改写过程

→ **结果只输出可直接用的最终提示词**,不暴露工作过程

## 校验脚本

### validate_deconstruction.py

校验 JSON 结构:
- `evidence_types` ∈ {video, prompt_only, transcript_only, mixed}
- `policy_values` ∈ {preserve, adapt, replace, omit}
- `confidence_values` ∈ {high, medium, low}
- 必含 9 个 shot 字段

### validate_remix.py

校验提示词:
- 时间轴格式 `\d+ - \d+ 秒`
- 不含 meta 句式 ("原人物替换为...", "如果与参考视频冲突..." 等)
- 校验必留短语、结构字段、字数

## 文件结构

```
remix-reference-video-prompt/
├── README.md          ← 安装 + 使用
├── SKILL.md           ← 完整 skill 规约 (核心)
├── agents/            ← agent 配置 (?)
├── references/
│   ├── deconstruction-schema.md   ← 分段 + JSON schema
│   └── layer-contract.md          ← 4 策略 + 12 层级 + 预设
└── scripts/
    ├── validate_deconstruction.py
    └── validate_remix.py
```

## MiniMax H3 视频模型 (底层引擎)

| 维度 | 数据 |
|---|---|
| **项目** | MiniMax-AI/MiniMax-H3 (GitHub) |
| **⭐** | 5914 |
| **License** | Apache 2.0 |
| **特点** | 8B 参数,通用视频生成模型 |
| **输入** | 文本 prompt / 起始帧 / 末尾帧 / 多参考帧 |
| **输出** | 视频 (默认 6s, 720p) |
| **运行** | ComfyUI / Diffusers / 自家 API |
| **加速** | 多个 turbo / distilled 变体(4 步 / 8 步蒸馏) |

## 完整部署方案 (来自 B 站文章)

| 方案 | 资源 | 适用 |
|---|---|---|
| **MiniMax H3 智能视频工厂** | <https://app-ed9db76285994072aeaa6c7784f2ad76.apps.vibex.cn/> | 一键在线用,免部署 |
| **RunningHub 文生视频** | <https://www.runninghub.ai/zh-cn/post/2084115885563965441/> | ComfyUI 云端,智能 prompt |
| **RunningHub 首尾帧** | <https://www.runninghub.ai/zh-cn/post/2084165728835596290/> | 图生视频,首尾帧控制 |
| **RunningHub FL2VA 多参** | <https://www.runninghub.ai/post/2084145051723599874/> | 多参考图生视频 |
| **相工云免费镜像** | <https://www.xiangongyun.com/image/detail/385d0c30-4a3c-4a0a-9a14-7e588a4d1363> | 国内云端加速,注册送算力 |
| **夸克网盘 ComfyUI 整合包** | <https://pan.quark.cn/s/01e31c72400d> | 8GB 可用,加速版提速 30% |
| **夸克网盘 模型+工作流** | <https://pan.quark.cn/s/182450cd5b92> | 模型 + 加速工作流 |

## 适用场景

| ✅ 适合 | ❌ 不适合 |
|---|---|
| 复制爆款节奏换皮 | 完全原创视频 |
| 电商产品广告同款化 | 需要真人/实拍场景 |
| 自媒体批量生产"参考型"视频 | 剧情 / 故事片 (需复杂叙事) |
| 跨平台账号矩阵 (同节奏多主体) | 长视频 (> 30s, MiniMax H3 默认 6s) |
| 文生视频高质量内容 | 视频精修 / 多轮迭代 |

## 风险与限制

- **单一 commit** — 风险:作者中途放弃或失联
- **License 未声明** — 商业使用前需问作者
- **MiniMax H3 时长限制** — 默认 6s,需拼接实现长视频
- **拆解粒度依赖视频质量** — 低清 / 抖动镜头会丢失结构
- **校验脚本不验证 prompt 质量** — 只验证结构和禁词
- **不支持音频生成** — MiniMax H3 默认视频静音,需配音另接
- **国产生态深度绑定** — 主要部署在 RunningHub / 相工云,海外部署复杂

## 跟其他 iswiki 工具的关系

| 工具 | 关系 |
|---|---|
| [i-have-adhd](i-have-adhd.md) | 🟡 都是 prompt skill,但 i-have-adhd 是输出风格,这个是工作流 |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | 🟡 都是 SKILL.md 级别的 prompt,生态类似 |
| [codex-security](codex-security.md) | ⚪ 安全 |
| [mapcn](mapcn.md) | ⚪ 地图 |
| [odometer](odometer.md) | ⚪ 数字动画 |

## 关联资料

- 仓库: <https://github.com/penposs/remix-reference-video-prompt>
- 视频模型: <https://github.com/MiniMax-AI/MiniMax-H3> (5914 ⭐)
- B 站视频教程: <https://b23.tv/MojOPRH>
- MiniMax H3 智能视频工厂: <https://app-ed9db76285994072aeaa6c7784f2ad76.apps.vibex.cn/>
- RunningHub: <https://www.runninghub.ai/>
- 相工云: <https://www.xiangongyun.com/>
- 夸克网盘 ComfyUI 整合包: <https://pan.quark.cn/s/01e31c72400d>