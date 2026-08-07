# open-kimi-ppt-skill — AI Agent 用的 Kimi PPT 逆向 skill

> 学习笔记 · 调研时间 2026-08-07
> 仓库: https://github.com/Binaryify/open-kimi-ppt-skill · npm: `open-kimi-ppt-skill`
> License: MIT · 语言: Python / Node.js · ⭐ 1.5k · v1.3.0

## 一句话定位
**逆向 Moonshot Kimi Slides 做的非官方 PPT 创作 skill**——让 AI Coding Agent（Codex / Claude Code / Cursor / WorkBuddy）能生成"可继续编辑"的 PPTD 项目 + "嵌字体带淡入淡出"的 PPTX，附本地浏览器编辑器。

> [!IMPORTANT]
> 非 Kimi/Moonshot 官方项目，**只供学习与研究**。依赖的前端资源 / 通信协议可能随 Kimi 更新而失效。

## 核心概念：PPTD
PPTD = **PPTX + Document**，是一种 YAML 写的演示文稿 DSL，是 OOXML 之上的简化抽象层：
- 保留主题、页面布局、元素位置等核心信息
- 去除 Master 等复杂嵌套
- 每页自包含、所见即所得
- 比直接拼 OOXML / pptxgenjs **稳**
- 比整页渲图 **好改**

### 一个 PPTD 项目目录
```text
deck/
  deck.pptd     # 清单文件（YAML）
  pages/        # 每页一个 .page 文件
  media/        # 本地媒体资源
  deck.pptx     # 默认同步生成的 PPTX
```

## 跟同类方案的对比

| | open-kimi-ppt | pptxgenjs 类 | 整页图片 PPT | HTML PPT |
|---|---|---|---|---|
| 交付物 | **PPTD + PPTX** | 多为仅 PPTX | 多为仅 PPTX | 单文件 HTML |
| Agent 友好度 | YAML 逐页、清晰 | 坐标/API 细节多、易翻车 | 依赖出图模型 | HTML/CSS 约束强 |
| PowerPoint 可编辑 | ✅ 文本形状图片都能改 | 可编辑但难精修 | 整页位图、难改 | 非原生 |
| 视觉质量 | 真实版式 + 多模态质检 | 依赖手调布局 | 统一偏海报 | 动效强 |
| 二次编辑 | **浏览器可视化 + 自动保存** | 改代码重导出 | 重新出图 | 改 HTML |

## 安装

### 前置
- Node.js 18+（必须，否则停止并提示用户安装）
- npm / npx（自带）
- python3（PPTX 导出 / 图片 QA 需要）
- Chrome / Chromium / Edge（图片 QA 可选；默认 WASM 导出不需要）

### 一行命令
```bash
npx open-kimi-ppt-skill@latest install -y
```
默认装到共享目录 `~/.agents/skills/open-kimi-ppt`，多数 Agent 装一次即可发现。

### 安装到指定 Agent
```bash
# Codex / Claude Code / Cursor
npx open-kimi-ppt-skill install --target ~/.codex/skills --target ~/.claude/skills

# WorkBuddy（不识别共享目录）
npx open-kimi-ppt-skill install --target ~/.workbuddy/skills

# 全部
npx open-kimi-ppt-skill install --all
```

支持的安装目录：`~/.agents/skills`、`~/.codex/skills`、`~/.claude/skills`、`~/.cursor/skills`、`~/.workbuddy/skills`

### 更新
再跑一次 `install -y`（带相同 `--target` / `--all`）即可，**只换 skill 文件，不动已生成的 PPTD/PPTX**。

## 使用

### 让 Agent 生成 PPT
```text
使用 open-kimi-ppt 做一个介绍小米 yu7 的 PPT
要求图片做背景，素材从网上找，8 页左右
```

**默认产出两份**（除非明确说只要 PPTD）：
1. 完整 PPTD 项目（可继续编辑）
2. 嵌字体、带淡入淡出翻页的 PPTX

**风格建议（让效果更稳）**：
- ✅ 写明风格：「深色产品发布风」「苹果 liquid glass」
- ✅ 点名 preset：「用 `pine-green-strategy`」
- ✅ 附参考模板 / 截图
- ❌ 只给主题不给风格 → Agent 自由发挥、容易波动

### 元素动画（可选）
提示词加「**要求带元素入场动画**」即可，按页编排合适的入场效果（fade/fly/zoom）。默认**不**加。

### 在线编辑
```bash
npx open-kimi-ppt-skill serve        # 启动本地编辑器 http://127.0.0.1:55173/
npx open-kimi-ppt-skill serve --open # 自动开浏览器
npx open-kimi-ppt-skill serve --port 56000
```
- 只在 `127.0.0.1` 起服务，**不监听局域网**
- 浏览器选完整 PPTD 项目目录（含 `.pptd` 清单 + `pages/` + `media/`）即可打开
- Chrome 系浏览器支持 File System Access API，可写目录
- 其他浏览器回退为只读上传

## 工作流（SKILL.md 5 步法）

| Step | 内容 |
|---|---|
| **step0** | 验证 Node 18+ / npm / python3 / Chromium |
| **step1** | 读上下文（用户上传、URL、PPTD 格式文档） |
| **step2** | 理解需求：目的（创作/编辑/复刻）+ 设计方向（自由/preset/模板/风格迁移）+ 输入类型（主题/全文/大纲）+ 页数 |
| **step3** | 生成 PPTD，按"设计方向"走不同分支 |
| **step4** | 验证：结构校验 → **多模态图片 QA**（导出页面图 → 拼接总览图 → 逐页排查遮挡/出界/对比度/溢出）→ 修复复检 → 全过才出 PPTX |
| **step5** | 同步生成 PPTX → 验证 fade transition → 交付（项目目录 / .pptd / pages / media / .pptx） |

### PPTX 导出
```bash
# 默认：本地 patched WASM（离线）
python3 ~/.agents/skills/open-kimi-ppt/scripts/export_pptx.py \
  /abs/path/deck.pptd \
  --output /abs/path/deck.pptx

# 可选：本地 neo-ppt 浏览器 UI（也离线）
python3 ~/.agents/skills/open-kimi-ppt/scripts/export_pptx.py \
  /abs/path/deck.pptd \
  --output /abs/path/deck.pptx --browser
```
- 默认 slide transition: `fade`（每页淡入淡出）
- 嵌字体：浏览器路径可用；WASM 路径优先可靠性
- 覆盖：`--transition none` / `--force`（覆盖已有文件）

### 图片 QA（视觉质检）
```bash
python3 ~/.agents/skills/open-kimi-ppt/scripts/export_images.py \
  /abs/path/deck.pptd \
  --output /abs/path/deck.pptx/.qa-images
```
- 加载 deck 到**本地** neo-ppt 编辑器（不走 kimi.com）
- 导出每页图 → 拼成总览图 → 输出 JSON mapping（`P1`...`Pn` → `.page` 文件）
- 模型读总览图逐页检查：清晰/不压脸/不超界/对比够/排版齐/不溢出/不遮挡
- 多次循环修复直至全部通过，**才出 PPTX**

## 预设主题（~30 套，分 6 类）

只在用户**点名**时才用（自选设计不会自动套）：

| 类别 | 适合场景 | 主题示例 |
|---|---|---|
| 咨询策略 | 战略咨询、尽调、转型、高管汇报 | `apricot-white-brief`、`indigo-due-diligence`、`marine-blue-research`、`moss-green-transformation`、`pine-green-strategy`、`red-black-growth` |
| 商务财务 | 投研、年报、备忘录、财务分析 | `black-gold-ledger` 等 |
| 工作汇报 | 内部汇报、周报月报 | - |
| 品牌推广 | 营销、产品发布 | - |
| 学术教育 | 学术答辩、课程 | - |
| 策略/商务/工作/推广/学术 | 子分类 | - |

完整列表见 `theme.md`（仓库自带预览图）。

## 安全边界
- ✅ CLI 只 `127.0.0.1`，不监听局域网
- ✅ 浏览器只在用户授权后读 PPTD 目录
- ✅ 保存回调只允许改 `.pptd` / `.page`，拒绝绝对路径 / `..` 越界
- ✅ 默认导出走本地 neo-ppt 镜像 + patched WASM，**不**依赖 kimi.com
- ✅ 不提供/注入 Kimi 登录令牌、不访问私有文稿
- ⚠️ 远程图片 / 字体若被文稿引用仍会从原服务器加载

## Windows 特殊行为
走浏览器路径时（视觉质检 / `--browser` PPTX）会自动启动**常驻调试浏览器**：
- 优先本机 Chrome → 回退 Edge
- 以 `--remote-debugging-port=9337` + 独立 profile（`%TEMP%\okp-cdp-profile`）启动
- 窗口定位屏幕外、导出后保持运行、复用同一实例
- 想完全自控：自行启动带 debug port 的浏览器，设 `AGENT_BROWSER_CDP=<port>` 即被优先使用

macOS / Linux 无此行为。

## 关键版本演进
- **v1.3.0 (2026-08-07)** — 完全本地化（neo-ppt 镜像 + patched WASM），不依赖 kimi.com；图片 QA / 浏览器导出走本地编辑器
- **v1.2.0 (2026-08-06)** — npm 包名统一为 `open-kimi-ppt-skill`（旧 `open-kimi-ppt-skills` 弃用）
- **v1.1.3 (2026-08-06)** — install 交互多选目录；Windows 调试浏览器常驻；修复 `.crdownload` 重命名导致的导出中断

## 跟我们的关系
- **OpenClaw skill 兼容** — 直接 `npx skills add Binaryify/open-kimi-ppt-skill` 装到 SKILL.md 体系
- **跟我们 iswiki 体系互补** — Strix 是"主动找漏洞"，open-kimi-ppt 是"自动产出文档"（对外汇报、安全报告、培训材料）
- **使用场景**：
  - 周报/月报自动化（写完大纲 → Agent 出 PPTD → 浏览器调样式 → PPTX 提交）
  - 安全事件复盘报告（图片作背景 + 时间线 + 修复清单）
  - 等保 / 渗透测试交付物（专业咨询风主题）
  - 培训 / 课件制作（学术教育主题）
- **风险**：
  - 默认 WASM 导出**不走** kimi.com，**但**远程图片/字体可能从原站加载（看 PPTD 内容）
  - 浏览器编辑器在 Windows 常驻浏览器进程，注意资源占用
  - 多模态 QA 依赖模型支持视觉，没视觉的模型只能做结构 review

## 实战建议
1. **先小后大**：用小米 YU7 / DJI Pocket 4 等成熟 demo prompt 验证安装 + 模型兼容性
2. **风格优先**：永远带 preset 名或参考图，比"自由发挥"稳定 10 倍
3. **多模态 QA 必跑**：模型支持图像时跑 export_images.py，不通过就别出 PPTX
4. **PPTX 后处理**：导出后用 PowerPoint / WPS 打开实测，淡入淡出切换和字体嵌入确认 OK
5. **混合工作流**：本地 WASM 出 PPTX + 浏览器编辑器调样式，比纯命令行灵活

## 参考链接
- 仓库: https://github.com/Binaryify/open-kimi-ppt-skill
- npm: https://www.npmjs.com/package/open-kimi-ppt-skill
- 主题列表: https://github.com/Binaryify/open-kimi-ppt-skill/blob/main/theme.md
- PPTD 格式定义: https://github.com/Binaryify/open-kimi-ppt-skill/blob/main/skills/open-kimi-ppt/reference/pptd.md
- 设计系统: https://github.com/Binaryify/open-kimi-ppt-skill/tree/main/skills/open-kimi-ppt/reference/design_system
- 作者: https://github.com/Binaryify（Vue.js 知名 maintainer）