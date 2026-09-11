# iswiki — 技术调研笔记

> 学习笔记库 · 长期积累的项目 / 工具 / 运维 / 安全 / 3D / AI 调研
> 按主题分类,每个目录有自己的 README.md 索引
> **共 48 个文档,4 个顶层分类 + 1 个 misc 专题目录**

---

## 🗂 文档树

```
iswiki/
├── README.md
├── ai-vibecoding-agents/         🤖 AI coding agent / 编排 / skill(15)
├── developer-productivity/       ⚡ 开发者生产力 / 个人项目(1)
├── ops-cybersec-dba/             🛠️ Ops / Cybersec / DBA / 监控(15)
├── web-frontend-ui/              🌐 Web 前端 / UI 库 / 3D / WebGPU(16)
└── misc/
    └── OS-gaming-console/        🎮 掌机 / 自定义 firmware(1)
```

---

## 🤖 [ai-vibecoding-agents/](ai-vibecoding-agents/) — AI coding agent / 编排 / skill

| 文档 | 一句话 |
|---|---|
| [fireside-sprint1](ai-vibecoding-agents/fireside-sprint1.md) | Fireside 异步圆桌会议平台的 Sprint 1 闭环笔记(REST 建房 → WebSocket 广播 → EndRoom)。 |
| [i-have-adhd](ai-vibecoding-agents/i-have-adhd.md) | 让 AI coding agent 用 action-first / numbered / no-preamble 风格输出,适合 ADHD 读者。 |
| [img2threejs](ai-vibecoding-agents/img2threejs.md) | AI 看图后按 8 阶段写 Three.js 代码,产物是可继续编辑的 TS,不是网格。 |
| [lobeHub](ai-vibecoding-agents/lobeHub.md) | 把零散 LLM Agent 统一纳管的"首席 Agent 运营官"产品(招聘/排班/IM 网关)。 |
| [logue](ai-vibecoding-agents/logue.md) | macOS 端完全本地(Apple Silicon MLX)的 AI 会议笔记 + 写作助手。 |
| [mattpocock-skills](ai-vibecoding-agents/mattpocock-skills.md) | Matt Pocock 从 `.agents/` 开源的 Real Engineering skills,2×2 分类。 |
| [OpenKimiPPTSkill](ai-vibecoding-agents/OpenKimiPPTSkill.md) | 逆向 Moonshot Kimi Slides 的非官方 PPT 创作 skill,生成可继续编辑的 PPTD 项目。 |
| [openclaw-awd-arena](ai-vibecoding-agents/openclaw-awd-arena.md) | Docker 编排的 LLM Agent 攻防对抗平台,容器隔离网络里多 agent 互打 + 实时计分大屏。 |
| [openopc](ai-vibecoding-agents/openopc.md) | HKUDS 开源的"个人 AI 原生公司"模拟器,Phaser 像素办公室可视化 AI 员工。 |
| [paseo](ai-vibecoding-agents/paseo.md) | 跨平台多 agent 编排器,统一管理 Claude Code / Codex / Copilot / OpenCode / Pi。 |
| [ponytail](ai-vibecoding-agents/ponytail.md) | 给 AI coding agent 注入"老员工 + YAGNI"人格的跨 13 平台 skill 集。 |
| [remix-reference-video-prompt](ai-vibecoding-agents/remix-reference-video-prompt.md) | SKILL.md 级 prompt skill,按参考视频拆解运镜 + 生成结构化视频提示词。 |
| [reverse-skill](ai-vibecoding-agents/reverse-skill.md) | AI Agent 的安全/逆向/渗透任务路由,857 文件 / 55 skill 模块 / R0-R39 路由。 |
| [teamai-cli](ai-vibecoding-agents/teamai-cli.md) | 腾讯开源的 Git-native 团队 AI 工具 CLI,push/MR/pull 同步 skill 给各 agent。 |
| [wake](ai-vibecoding-agents/wake.md) | Mac 上 Rust+GPUI 写的 multi-agent 会话档案馆,统一浏览本地历史。 |

---

## 🛠️ [ops-cybersec-dba/](ops-cybersec-dba/) — Ops / Cybersec / DBA / 监控

| 文档 | 一句话 |
|---|---|
| [anthropic-cybersecurity-skills](ops-cybersec-dba/anthropic-cybersecurity-skills.md) | 817 个结构化网络安全技能 + 6 框架映射,让 AI agent 像资深安全分析师工作。 |
| [codex-security](ops-cybersec-dba/codex-security.md) | OpenAI 开源的 `@openai/codex-security`,自动验证漏洞,不报误报。 |
| [disable-ipv6-multi-kernel](ops-cybersec-dba/disable-ipv6-multi-kernel.md) | 多内核 Linux 引导菜单批量加 `ipv6.disable=1` 的完整 SOP。 |
| [kylinV10DisableIPv6](ops-cybersec-dba/kylinV10DisableIPv6.md) | 麒麟 V10 ARM 版通过 GRUB 内核参数彻底关闭 IPv6 的 5 步操作流程。 |
| [linux-permission-debug](ops-cybersec-dba/linux-permission-debug.md) | `chmod 777` 成功但服务仍 Permission denied 的 6 层访问链调试。 |
| [netdata](ops-cybersec-dba/netdata.md) | 开箱即用的 per-second 实时监控平台,自带 ML 异常检测 + 告警。 |
| [opsTroubleshootingDiskGhost](ops-cybersec-dba/opsTroubleshootingDiskGhost.md) | df 说满、du 说没满 ——「幽灵空间」排查(fd 还指向的 inode)。 |
| [opsTroubleshootingOOMCgroup](ops-cybersec-dba/opsTroubleshootingOOMCgroup.md) | free 还有 8G 但 OOM 杀进程 —— cgroup 账本思维排查。 |
| [overseas-youtube-security-channels](ops-cybersec-dba/overseas-youtube-security-channels.md) | 8 个海外网络安全 YouTube 频道,覆盖入门到高级研究的完整自学路径。 |
| [performanceTriage](ops-cybersec-dba/performanceTriage.md) | 性能告警 70% 是假象,基于"快照 vs 趋势 / 用户态 vs 内核态"的四维定位骨架。 |
| [qoder-security](ops-cybersec-dba/qoder-security.md) | 阿里 Qoder 平台内嵌的 AI 安全工程师,IDE/CLI 原生三阶段扫描(L1/L2/L3)。 |
| [recovery-sop](ops-cybersec-dba/recovery-sop.md) | 误删 MySQL/文件/RAID/PVC 等场景的通用恢复 SOP。 |
| [strix](ops-cybersec-dba/strix.md) | 开源 AI 渗透测试 Agent 集群,动态挖漏洞 + PoC 验证,不是静态扫描器。 |
| [tier-1-housekeeping](ops-cybersec-dba/tier-1-housekeeping.md) | Fireside Sprint 1.6 Tier 1 housekeeping,只收 outstanding 小修,不做大块。 |
| [wafKnowledgeBase](ops-cybersec-dba/wafKnowledgeBase.md) | WAF 拦截的攻击行为分类知识库(SQL 注入 / XSS / 命令注入 等)。 |

---

## 🌐 [web-frontend-ui/](web-frontend-ui/) — Web 前端 / UI 库 / 3D / WebGPU

| 文档 | 一句话 |
|---|---|
| [agoraFlat](web-frontend-ui/agoraFlat.md) | 声网开源的 Web/Desktop/Android 全端在线互动教室。 |
| [artemis-art-direction](web-frontend-ui/artemis-art-direction.md) | Artemis 的视觉风格 = Blueprint × 太空电影 × 琥珀橙焦点色的工程解读。 |
| [artemis-redradman](web-frontend-ui/artemis-redradman.md) | Three.js 在浏览器里复刻 NASA Artemis II 载人登月任务(14 阶段 / 16 飞行器组件)。 |
| [kage](web-frontend-ui/kage.md) | Meng To 的 244 KB 单 HTML 文件 Three.js 京都夜行寺(scroll-driven 镜头推进)。 |
| [mapcn](web-frontend-ui/mapcn.md) | shadcn 风格的 React 地图组件库(MapLibre GL + Tailwind v4),一行注入。 |
| [mediaPipeTasksVision](web-frontend-ui/mediaPipeTasksVision.md) | Google MediaPipe 端侧视觉任务 SDK,15 个开箱即用 Web API,WASM + GPU。 |
| [nova3d](web-frontend-ui/nova3d.md) | AI 不直接生成网格而写 Blender Python 构造程序,输出结构化 GLB。 |
| [odometer](web-frontend-ui/odometer.md) | HubSpot 的 JS/CSS 数字动画库,< 3kb,翻牌式数字滚动过渡。 |
| [pascalEditor](web-frontend-ui/pascalEditor.md) | R3F + WebGPU 的开源 3D 建筑/BIM/数字孪生编辑器,自带 MCP server。 |
| [humanAtlas](web-frontend-ui/humanAtlas.md) | React + Three.js + BodyParts3D 4.0 的 3D 人体解剖浏览器,2234 mesh + 3432 概念 + 爆炸图。 |
| [shinjukuIndoorThreejsDemo](web-frontend-ui/shinjukuIndoorThreejsDemo.md) | 日本国土交通省新宿站室内 GIS 数据丢进 Three.js 做 3D 分层楼栋 + 流光行人。 |
| [stadiView](web-frontend-ui/stadiView.md) | 纯过程化生成的 3D 足球场座位预览 demo,Three.js + GSAP 飞进任一座位。 |
| [threeui](web-frontend-ui/threeui.md) | Meng To 出品的 Three.js 3D UI / Shader / Hero 组件目录(Community 版 164 个)。 |
| [tripo](web-frontend-ui/tripo.md) | VAST 的 AI 3D 大模型公司,主打原生四边面拓扑 + 按面数预算直出。 |
| [vgpu](web-frontend-ui/vgpu.md) | Vercel Labs 的 WebGPU 库(TypeScript, 25KB),设计给 AI agent 用。 |
| [weatherNext](web-frontend-ui/weatherNext.md) | DeepMind 全球天气预报 AI 模型家族(GraphCast / GenCast / WeatherNext 五代)。 |

---

## ⚡ [developer-productivity/](developer-productivity/) — 开发者生产力 / 个人项目

| 文档 | 一句话 |
|---|---|
| [programWangPrivateProjects](developer-productivity/programWangPrivateProjects.md) | 程序汪公众号私活案例集,按文章为单位 append(技术栈 / 商业模式分析)。 |

---

## 📌 [misc/](misc/) — Misc / 专项主题

#### 🎮 [misc/OS-gaming-console/](misc/OS-gaming-console/) — 掌机 / 自定义 firmware

| 文档 | 一句话 |
|---|---|
| [leaf-deploy](misc/OS-gaming-console/leaf-deploy.md) | Miniloong Pocket 1 掌机的自定义 firmware 部署编排器 + UMRK workspace 中央命令面。 |

---

## 📊 统计

| 分类 | 文档数 |
|---|---|
| 🤖 ai-vibecoding-agents | 15 |
| 🛠️ ops-cybersec-dba | 15 |
| 🌐 web-frontend-ui | 16 |
| ⚡ developer-productivity | 1 |
| 📌 misc/OS-gaming-console | 1 |
| **总计** | **48** |

(48 个被分类的 doc + 1 个根 README.md)

---

## 🔗 相关项目

- **iswiki 主仓**: <https://github.com/ishadowland/iswiki>
- **liuyin**(作者): <https://github.com/ishadowland>