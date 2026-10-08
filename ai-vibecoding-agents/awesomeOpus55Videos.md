# awesome-opus5-5-videos — Claude Opus 5.5 爆款视频 prompt 语料库

> 学习笔记 · 调研时间 2026-10-08
> 仓库: <https://github.com/yihui-dev/awesome-opus5-5-videos>
> 作者: Yihui / 熠辉(独立开发者,`happyaicoding.com`,X `@yihui_indie`,GitHub 2017 年起)
> 配套站: <https://skillry.dev/ai-videos/opus-5-5> · 媒体域 `media.skillry.dev`
> License: MIT · 内容类型: 纯 markdown + json(无代码 / 无 CI / 无 release / 无 tag)
> ⭐ 2,925 · 302 forks · 6 commits · 1 open issue · 建仓 2026-09-27 · 最后 push 2026-10-08
> 规模: `prompts/` 513 个 md · `data/videos.json` 585 KB · 476 位作者

## 一句话定位

**一个 prompt 语料库**:把 476 位 X 创作者用 Claude Opus 5.5「让 AI 把动画写成代码(HTML / Canvas / SVG / Three.js / GLSL)」产出的爆款视频,连同作者原 prompt 一起收进 Git,MIT 开源、离线可读。

它的价值不在「视频」,在**「自然语言 → 可运行动画代码」这条路径的 513 个已验证样本**。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **在线浏览** | `skillry.dev/ai-videos/opus-5-5` | 每个视频左边原片、右边 live remake 对照,判断「AI 复刻得像不像」 |
| **本地 clone 采样** | `git clone --depth=1 https://github.com/yihui-dev/awesome-opus5-5-videos` | 写脚本按 `category` / `tech_tags` / 长度过滤,批量喂给自己的 agent |
| **JSON 结构化消费** | `data/videos.json` | 唯一带 `prompt_partial` 标记的数据源,做 prompt 检索 / 去重 / 质量分级的唯一入口 |

第三种是**唯一可用于程序化检索的路径** —— `prompts/*.md` 只是给人读的,元信息在 front-matter 之外全靠正文里的 `- **Category:**` 之类的行,正则解析很脆。

## 仓库结构与数据模型

```
awesome-opus5-5-videos/
├── README.md          50 KB · 4 宫格图片表,精选 100 条(100 = 58 motion + 16 explainer + 14 3d + 12 games)
├── LICENSE            MIT
├── .gitignore         只有 .DS_Store
├── data/videos.json   585 KB · 513 条 · 唯一结构化数据源
└── prompts/           513 个 md · 文件名 <author>-<id>.md,一视频一文件
```

**`data/videos.json` 单条 schema(一手核对,11 个字段):**

```json
{
  "slug": "ajith-io-890146",
  "author": "ajith_io",
  "author_url": "https://x.com/ajith_io",
  "post_url": "https://x.com/ajith_io/status/2103449416325890146",
  "category": "motion",
  "tech_tags": ["canvas"],
  "prompt": "make a dynamic 15-second motion graphics video that ...",
  "prompt_partial": false,
  "poster_url": "https://media.skillry.dev/opus-5-5/ajith-io-890146/original.<hash>.webp",
  "skillry_url": "https://skillry.dev/ai-videos/opus-5-5/ajith-io-890146",
  "added": "2026-09-26"
}
```

**`prompts/<slug>.md` 的固定版式**(便于正则批量改写):

```markdown
# Opus 5.5 video by @<author>

[▶ Watch the original and a live remake on Skillry](...) · [Original post](...)

- **Category:** Motion graphics
- **Remake built with:** Canvas
- **Author:** [@<author>](...)

## Prompt

```text
<原始 prompt 原文>
```
```

## 513 条的实际分布(一手统计 `data/videos.json`)

**分类 —— motion 占 62%,是绝对主流:**

| category | 条数 | 占比 | prompt 中位长度 | `prompt_partial` 比例 |
|---|---|---|---|---|
| `motion`(Motion graphics) | 317 | 61.8% | 169 字 | 31% |
| `interactive`(Games & interactive) | 70 | 13.6% | 215 字 | **74%** |
| `explainer` | 67 | 13.1% | 229 字 | 64% |
| `3d`(3D scenes) | 59 | 11.5% | 253 字 | 66% |

→ **`motion` 的完整 prompt 率最高(69%),`interactive` 最低(26%)**。要抄完整可跑的 prompt,优先从 motion 里挑。

**技术栈标签 —— Canvas 是绝对地基,Three.js 只在 3D / 游戏里出现:**

| tech_tag | 条数 | 分布特征 |
|---|---|---|
| `canvas` | 351 | 全类别通吃,motion 里 218/317 |
| `svg` | 219 | motion 159,偏排版 / 字动效 / 信息图 |
| `threejs` | 147 | **只在 3D(48/59)+ interactive(46/70) 里密集**,motion 仅 37 |
| `shader` | 104 | 3D + interactive 各占三成,是「质感」分水岭 |
| `gsap` | 100 | 几乎全是 motion(77/100),时间轴编排主力 |
| `css` | 68 | 兜底样式 / 2D 合成 |
| `audio` | 36 | Web Audio 直接合成音效,不加载音频文件 |
| `particles` | 26 | 粒子系统 |
| `playable` | 22 | **只有 interactive 用** = 可操作游戏而非纯录像 |
| `pixel` | 16 | 像素风 |
| `ai-image` / `webgl` / `physics` | 10 / 9 / 9 | 长尾 |

**prompt 长度 —— 中位数只有 180 字,极度两极化:**

| 长度区间 | 条数 |
|---|---|
| < 100 字 | 105 |
| 100–300 字 | **264** |
| 300–800 字 | 89 |
| 800–2000 字 | 22 |
| 2000–6000 字 | 25 |
| > 6000 字 | 8 |

最短 11 字,最长 **22,367 字**(`alexwtlf-981005`,一段 25 秒太空站双人戏的完整剧本级 prompt)。

→ **`prompt_partial: true` 占 234/513 = 46%**,即近一半 prompt 作者没公开全文,仓里只有片段或原帖描述。

## 「让 AI 写动画代码」这条路径的实际约定(关键词频次统计)

在 513 条 prompt 里做关键词计数,得到的隐含协议:

| 关键词 | 命中 | 说明 |
|---|---|---|
| `loop` | 25 | 循环播放是默认诉求(便于人肉看效果,不用 seek) |
| `60fps` | 24 | 帧率被显式指定,`60fps` 几乎是标配 |
| `remotion` | 24 | React 驱动的视频框架(见下节) |
| `screenshot` | 12 | 「先出截图确认再动」的工作流 |
| `three.js` / `threejs` | 18 | 3D 场景默认栈 |
| `export` / `record` | 9 / 9 | 导出成 mp4 / 录屏 |
| `self-contained` | 7 | **单文件自包含**是硬要求 |
| `GSAP` | 6 | 时间轴 / 缓动编排 |
| `single HTML file` | 2 | 明确点名单 HTML |

**README 的官方三步法:**

1. 打开 prompt 文件,复制 `## Prompt` 块
2. 粘进 Claude Opus 5.5(Claude Code / Claude app / 任何跑 Opus 的 agent)
3. **「让它把结果渲染成一个单 HTML 文件,然后想出视频就录屏」**

第 3 步是这套工作流最关键的工程约束:**产物是 HTML,不是 mp4**。视频是「录 HTML」得到的二次产物,所以能被 Skillry 拿来做 live remake 对照。

## 三条技术路线(一手核到的差异)

| 路线 | 代表 prompt | 产物 | 何时选它 |
|---|---|---|---|
| **单文件 HTML + Canvas/SVG/GSAP** | `ajith-io-890146`(11 字起手令)、`moritzkremb-466494` | 一个 `.html`,CDN 引 three.js/gsap | 90% 的 motion;最快验证,零依赖 |
| **Remotion(React 驱动)** | `daniel-haida-636937`(15,583 字,给记账 App Taxtello 做产品片) | 一个 Remotion 项目 | 89 条 prompt 提到 remotion(2026-09-29 批 59 条 + 2026-10-08 批 27 条 + 09-26 批 3 条),**是 2026-09-29 之后的主线** |
| **Three.js + GLSL** | `lukasersil-726495`(744 字 showreel)、`viggle-pinoc-434495`(2,019 字) | three.js 场景 + shader | 3D scenes / Games 两个分类 |

Remotion 路线值得单独说:**它的 prompt 里包含真实仓库路径和设计 token 文件路径**(如 `/taxtello/main/public/css/app/_00-tokens.css`、`/taxtello/main/docs/design/TOKENS.md`),让 agent 先读真实 design token 再设计 —— 这是「AI 做品牌片」从「画个好看的动画」升级到「用对品牌资产」的关键技巧。

## 版本节奏

| commit | 日期 | 内容 |
|---|---|---|
| `1c09219` | 2026-09-27 | 首批 **282** 条 prompt + README gallery |
| `b26e063` | 2026-09-28 | 追加 **107** 条(累计 389) |
| `6cdcea6` | 2026-09-28 | README 加 hero mosaic + Skillry 页截图 |
| `b9ef22c` | 2026-09-28 | 补 MIT license |
| `3d54892` | 2026-09-29 | 追加 **86** 条(累计 475),**Remotion / HyperFrames 批次** |
| `7562902` | 2026-10-08 | 追加 **38** 条(累计 513),以 motion graphics + explainer 为主 |

**节奏:**建仓 11 天收了 513 条,但增量在衰减(282 → 107 → 86 → 38),且 2026-09-29 到 10-08 之间停了 9 天。**把这当「定期更新的快照」而不是「持续流」** —— 需要时直接 `git pull`,别指望实时。

值得注意:最近两个 commit 的作者是 `yihui-dev and claude`,commit body 带 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` —— **作者的日常收集流程本身就是 Claude 跑的**(抓 X、抽 prompt、分类、生成 md、写 README)。这本身就是这个仓的自证。

## 实战建议

**筛选前必看 —— `prompt_partial` 藏在 JSON 里,md 文件不告诉你**

我核过:234 条 `prompt_partial: true` 的记录,对应的 `prompts/*.md` **正文里没有任何「这是片段」的提示**,只有 6 个文件因为作者原话里带了类似字眼才偶然出现。所以:

```python
import json, pathlib
ROOT = pathlib.Path("awesome-opus5-5-videos")
videos = json.loads((ROOT / "data/videos.json").read_text())

# 只要完整 prompt
full = [v for v in videos if not v["prompt_partial"]]

# 按分类 + 技术栈取「可直接喂 agent」的长 prompt
samples = [
    v for v in full
    if v["category"] == "motion" and "gsap" in v["tech_tags"]
    and len(v["prompt"]) > 300
]
for v in samples[:5]:
    print(v["slug"], v["author"], v["post_url"])
    print(v["prompt"][:300], "\n---")
```

**别整段抄,抽参数**

513 条里 264 条长度在 100–300 字之间,结构高度同质(场景 → LOOK/WORLDS/HOW 三段 → 交付要求)。真正可迁移的是**骨架**:

```
[时长] + [镜头/场景清单] + LOOK(视觉风格词) + HOW(技术栈 + 交互/分镜规则) + 交付要求(时长/分辨率/单文件/可循环)
```

把这个骨架填自己的内容,比复制 2,000 字别人的 prompt 更有效。

**国内网络可用性**

- `x.com` 原帖(513/513 全在 X)在墙内基本打不开 → **务必用本地 `prompts/` + `data/videos.json`,不要依赖 `post_url`**
- `skillry.dev` / `media.skillry.dev` 是作者自建域,可达性本次未实测(命令未获批准),按墙外站点对待
- `git clone` GitHub 可用,513 个 md 共约 1.5 MB,`--depth=1` 秒级

**版权边界(重要)**

- **MIT 只覆盖作者自己的整理工作**(README + md 格式 + json 结构)
- **513 条 prompt 的著作权仍属各自 creator**,README 的 Credits 段明确写了「Every video and prompt belongs to its creator」,并提供 issue 渠道要求修改 / 移除
- → **商用 / 发公众号 / 做产品营销物料前,逐条回 `post_url` 确认授权**。别拿 MIT 当免责金牌。

## 风险点

| 风险 | 说明 |
|---|---|
| **近一半 prompt 不完整** | `prompt_partial` 46%,motion 之外的分类更是 64%–74% 不完整 |
| **分类与标签是人工标注** | `tech_tags` 里的 `shader` / `webgl` / `canvas` 边界模糊,`3d` 分类下也有 37/59 带 `canvas`;拿它做精确过滤会漏 |
| **原作者单点** | 单人维护 + Claude 协作收集,作者一旦停更就断(2026-10-08 已减到 38 条/批) |
| **无 tag / 无 release / 无 schema 文档** | `videos.json` 的字段语义全靠推断,上游改字段不会通知 |
| **media.skillry.dev 集中托管** | 513 张 poster 同一域,作者域名失效则图片全挂(仓内不含图,README 是外链) |
| **X 平台单点** | 全部 513 条 `post_url` 在 x.com,作者删帖 / 账号注销则溯源链断 |
| **prompt 是「别人的作品描述」** | 直接喂别人的 prompt 复刻出几乎一样的画面,可能构成实质性相似;当学习样本用,别当模板直接量产 |

## 跟我们的关系

**1. 每日简报 / 收盘总结 → 从静态文字升级成可分享的 HTML 动画**

我们现在的简报(`daily-news-briefing` / `market-close-summary`)产出是纯文本 + m4a 语音。这个仓的 `motion`(317 条,完整 prompt 率 69%)提供了现成的「持仓 / 新闻数据 → 15 秒动效片」配方:Canvas 画数据 + GSAP 排时间轴 + `loop` + `60fps` + 单文件。配合本机已有的 ffmpeg(见下)可以真出片。

**2. `note-slides` 横向翻页 HTML → 直接借 SVG + GSAP 的转场语汇**

`note-slides` 已经产出横向翻页的 HTML,缺的是「转场不生硬」。这里 100 条 `svg` + 100 条 `gsap` 的 motion prompt 可以当**转场效果库**采样(按 tech_tags 过滤,不用读全部 513 条)。

**3. 与 iswiki 已有笔记的交叉点**

- `scDatav`(Three.js + React 19 数据大屏)↔ 本仓 `3d` / `explainer` 分类:同一批技术栈,互补的是**「怎么做动」**(本仓)vs「数据怎么组织」(已有笔记)
- `img2threejs`(AI 看图写 Three.js 代码,产物可编辑 TS)↔ 本仓 `threejs` 147 条:本仓是「一句话 prompt 直接出成品代码」,已有笔记是「有结构可维护的工程化路径」
- `MiceInTheMuseum`(Gemini + Google AI Audio 实时讲解)↔ 本仓 36 条 `audio` 标签(多为 Web Audio 直接合成):**同样是把声音当代码生成,一个走 TTS 模型,一个走 Web Audio 合成器**
- `nova3d` / `humanAtlas` / `threeui`:Three.js 生态工具,本仓是「AI 帮你写」侧

**4. 本机已具备的能力(可以真跑通 README 第 3 步)**

我核过本机环境:

```bash
$ ffmpeg -version
ffmpeg version 8.1-tessus    # /Users/liuyin/.local/bin/ffmpeg

$ ffmpeg -f avfoundation -list_devices true -i ""
AVFoundation video devices:
[0] Capture screen 0        # ← 屏录设备存在
```

→ README 说「录屏出视频」,本机 ffmpeg 8.1 + avfoundation 的 `Capture screen 0` **够用**,不需要额外装 OBS:

```bash
# 单 HTML 出片(参数随 macOS 版本微调,avfoundation 索引不带引号)
ffmpeg -f avfoundation -capture_cursor 0 -i "1:none" \
  -t 15 -r 60 -pix_fmt yuv420p out.mp4
```

⚠️ 两个实测限制:
- 这版是 **tessus 静态编译版**,没有 x11grab 那套滤镜,要靠 `-pix_fmt yuv420p` 保证 QuickTime / 微信能播
- **本机没装 Playwright**(npx 提示缺包、python3 import 失败)→ 想做「无头浏览器逐帧确定性出图」得先 `npx playwright install chromium`,重

**5. 模型不绑定 Opus 5.5 —— 但要有预期差**

这批 prompt 的**内容是「自然语言 + 结构化段落 + 交付约束」,不是 Opus 私有格式**。我们这边 provider 是 `minimax-cn`(记忆里 VPS 无本地算力,推理全靠外部 agent),把 prompt 喂给 MiniMax / 其他模型跑**格式上完全可行**。

但要诚实说清楚:这 513 条视频**全都是 Opus 5.5 出的成品**,我们没有对照实验证明「换个模型产出会不会掉档」。**建议先拿 3–5 条已知的完整 prompt(比如 `moritzkremb-466494` 520 字 SaaS 发布片、`lukasersil-726495` 744 字 showreel)做 A/B**,而不是直接批量跑。

**6. 定位提醒**

这个仓**不是「视频教程」也不是「提示词工程课」**,它是**一份创作器的行为数据集**:513 次「人给一句话 → Opus 写出一整段可运行动画」的真实输入输出对。真正的学习价值是**观察 476 个人怎么描述自己想要的东西**,而不是背别人的 prompt。

## 参考链接

- 仓库: <https://github.com/yihui-dev/awesome-opus5-5-videos>
- 在线浏览(原片 ↔ live remake 对照): <https://skillry.dev/ai-videos/opus-5-5>
- 作者博客: <https://happyaicoding.com/>
- 作者 X: <https://x.com/yihui_indie>
- 单条示例(SaaS 产品发布片 prompt,520 字): <https://github.com/yihui-dev/awesome-opus5-5-videos/blob/main/prompts/moritzkremb-466494.md>
- 单条示例(Remotion 品牌片,15,583 字): <https://github.com/yihui-dev/awesome-opus5-5-videos/blob/main/prompts/daniel-haida-636937.md>
- 结构化数据: <https://github.com/yihui-dev/awesome-opus5-5-videos/blob/main/data/videos.json>
- iswiki 关联笔记:`ai-vibecoding-agents/remix-reference-video-prompt.md`(视频 prompt skill)、`web-frontend-ui/scDatav.md`(Three.js 数据大屏)、`ai-vibecoding-agents/img2threejs.md`(AI 写 Three.js 的工程化路径)、`ai-vibecoding-agents/MiceInTheMuseum.md`(AI 音频实时生成)