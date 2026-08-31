# iswiki

> random tec articals by ishady@ishadowland
> copyleft feel free to commit

个人技术调研笔记库。所有 `<Topic>.md` 文件一律 root level,
按主题命名,不分子目录。

## 索引

### 🛠️ CLI / 工具

- [OpenKimiPPTSkill](OpenKimiPPTSkill.md) — Open Kimi PPT skill,
  Kimi 模型接入 PPT 生成的 Skill 体系
- [Strix](Strix.md) — 用自主 AI Agent 集群做渗透测试（49.4k ⭐）
- [codex-security](codex-security.md) — OpenAI 的 AI 安全扫描
  CLI（9.7k ⭐，GPT-5 驱动 + 验证漏洞）
- [qoder-security](qoder-security.md) — 阿里 Qoder 的 AI 安全能力
  （L1/L2/L3 三层渐进扫描 + 一键修复）
- [i-have-adhd](i-have-adhd.md) — 跨 8 个 AI 编程平台的
  ADHD-friendly 输出风格 skill（20k ⭐）
- [remix-reference-video-prompt](remix-reference-video-prompt.md) —
  爆款视频复刻 skill（拆解参考视频 + MiniMax H3 生成）
- [mattpocock-skills](mattpocock-skills.md) — Matt Pocock 的
  "Real Engineers" skills 集合（25 skills，218k ⭐）
- [paseo](paseo.md) — 多 agent 编排器（Claude Code + Codex + Copilot +
  OpenCode + Pi, desktop + mobile, 14.6k ⭐）
- [teamai-cli](teamai-cli.md) — 腾讯团队级 AI agent harness
  （Git-native skill/rule 同步 + 知识库 + 可借鉴到 fireside）
- [wake](wake.md) — Mac 上所有 Coding Agent 会话的统一档案馆
  （Rust + GPUI 原生，13+ agent 适配，全文搜索 + 一键恢复）
- [openopc](openopc.md) — 港大 HKUDS 的"AI-Native Company"框架
- [openclaw-awd-arena](openclaw-awd-arena.md) — Docker 编排的 LLM agent AWD 攻防对抗 (319 ⭐, Hermes backend)
  （Self-Built/Run/Grown，Phaser Office UI，1.45k ⭐）
- [LobeHub](LobeHub.md) — 首席 Agent 运营官，多 Agent 编排平台
  （81.6k ⭐，IM Gateway + 自部署，含飞书/微信/QQ adapter）
- [Ponytail](Ponytail.md) — 给 AI agent 注入"最懒高级工程师"人格的跨 13 平台 skill 集
  （117.9k ⭐，MIT，YAGNI 7 步梯子 + 三档强度 + 诚实 agentic benchmark + Hermes 原生适配）

### 🛠️ 运维 / 排错思路

- [OpsTroubleshootingDiskGhost](OpsTroubleshootingDiskGhost.md) —
  df 说满、du 说没满 ——「幽灵空间」账本思维
- [OpsTroubleshootingOOMCgroup](OpsTroubleshootingOOMCgroup.md) —
  free 还有 8G，OOM 却杀了数据库 —— cgroup 账本思维

### 🌐 Web / 3D

- [mapcn](mapcn.md) — shadcn 风格的 MapLibre 地图组件库（11.4k ⭐）
- [StadiView](StadiView.md) — 3D 足球场可视化
- [PascalEditor](PascalEditor.md) — 开源 3D 建筑 / 数字孪生编辑器，React Three Fiber + WebGPU + 原生 MCP 集成（21.3k ⭐）
- [odometer](odometer.md) — HubSpot 的平滑数字过渡 JS/CSS 库
  （7.3k ⭐，archived 2019，< 3kb）
- [kage](kage.md) — MengTo 的 Kyoto 夜间寺庙交互式 Three.js
  体验（1.25k ⭐，5 章 + cinematic generated imagery）
- [vgpu](vgpu.md) — Vercel Labs 的 WebGPU 库（1.1k ⭐，25KB gzip，
  Typed WGSL，Browser/Node/CI 跨 runtime，Agent-ready + 内置 evals）
- [artemis-redradman](artemis-redradman.md) — Three.js 复刻 NASA
  Artemis II（14 阶段 + 16 组件 + 3 主题，数据密度极高）
- [artemis-art-direction](artemis-art-direction.md) — Artemis
  美术风格深度分析（pure black + warm cream + amber + wireframe 范式）
- [Netdata](Netdata.md) — AI-powered 全栈可观测性平台（80.4k ⭐，per-second + 自带 ML 异常 + NIDL 自动 dashboard；前端 NCUL1 闭源 CDN 交付）

### 🐧 Linux / 运维故障排查
- [linux-permission-debug](linux-permission-debug.md) — chmod 777 翻车:
  6 层访问链(身份/路径/挂载/SELinux/NFS/容器 namespace)的
  完整定位思路 + read-only 排查命令

### 🖥️ macOS / 本地 AI

- [Logue](Logue.md) — macOS 26+ 上完全本地（MLX）的 AI 会议笔记
  + 写作助手（145 ⭐，1.0.1）
- [MediaPipeTasksVision](MediaPipeTasksVision.md) — Google
  MediaPipe Tasks Vision 调研（浏览器/Node 端视觉 AI）

### 💼 软件开发项目案例

- [ProgramWangPrivateProjects](ProgramWangPrivateProjects.md) —
  程序汪的私活案例笔记

### 🔒 安全

- [wafKnowledgeBase](wafKnowledgeBase.md) — WAF 知识库
- [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md) —
  817 个结构化网络安全技能库（30.5k ⭐，Apache 2.0，可迁 Hermes/opencode）
- [overseas-youtube-security-channels](overseas-youtube-security-channels.md) —
  8 个海外网络安全 YouTube 频道调研（NetworkChuck / IppSec / TCM 等）

### 🏗️ 项目复盘

- [fireside-sprint1](fireside-sprint1.md) — Fireside Sprint 1 完整
  复盘：REST + WebSocket + 刷新令牌 + Dashboard + 10 reviewer issues
- [tier-1-housekeeping](tier-1-housekeeping.md) — Fireside Sprint 1.6
  Tier 1 housekeeping: 2 ADRs + dashboard display_name modal + RFC
  §2.3 reconciliation

## 风格

- 每个 `.md` 是 1 个独立主题
- 开头用 `# Topic — 短描述`,然后是 `> 学习笔记 · 调研时间`
- meta 行用 `> 仓库: <url> · License: <X> · ...`
- 自由 sections,中文为主
- commit 风格: `docs: add <X> research notes` 或 `docs: update <X>`

## 维护

- 主要维护: ishashy (isher)
- 更新方式: 你发我研究材料 / 主题 / URL,我写并 commit
- 重大改动直接 push main

## 来源

任何渠道 — 邮件、消息、URL、文件、想法都可以。

