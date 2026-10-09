# iswiki — 技术调研笔记

> 学习笔记库 · 长期积累的项目 / 工具 / 运维 / 安全 / 3D / AI 调研
> 按主题分类,每个目录有自己的 README.md 索引
> **共 74 个文档,4 个顶层分类 + 1 个 misc 专题目录**

---

## 🗂 文档树

```
iswiki/
├── README.md
├── ai-vibecoding-agents/         🤖 AI coding agent / 编排 / skill(27)
├── developer-productivity/       ⚡ 开发者生产力 / 个人项目(7)
├── ops-cybersec-dba/             🛠️ Ops / Cybersec / DBA / 监控(19)
├── web-frontend-ui/              🌐 Web 前端 / UI 库 / 3D / WebGPU(17)
└── misc/
    └── OS-gaming-console/        🎮 掌机 / 自定义 firmware(2)
```

---

## 🤖 [ai-vibecoding-agents/](ai-vibecoding-agents/) — AI coding agent / 编排 / skill

| 文档 | 一句话 |
|---|---|
| [fireside-sprint1](ai-vibecoding-agents/fireside-sprint1.md) | Fireside 异步圆桌会议平台的 Sprint 1 闭环笔记(REST 建房 → WebSocket 广播 → EndRoom)。 |
| [i-have-adhd](ai-vibecoding-agents/i-have-adhd.md) | 让 AI coding agent 用 action-first / numbered / no-preamble 风格输出,适合 ADHD 读者。 |
| [img2threejs](ai-vibecoding-agents/img2threejs.md) | AI 看图后按 8 阶段写 Three.js 代码,产物是可继续编辑的 TS,不是网格。 |
| [ipAsLogoSkill](ai-vibecoding-agents/ipAsLogoSkill.md) | 把"极简圆润 IP logo"设计语言写成 17KB SKILL 级硬约束,装到 Codex/Coze/Doubao/YouMind/Manus/Gemini Apps/Replit Agent 7 家,3 方向 × 2 变体 = 6 张候选(3 LL + 3 LR,三色封顶,永不降级 SVG)。5,867★ / MIT。 |
| [MiceInTheMuseum](ai-vibecoding-agents/MiceInTheMuseum.md) | Google Arts & Culture 的 Gemini 多模态 + Google AI Audio 实时音频导览实验(2024-11 上线),架构可平移到儿童讲解 / 景点导览。 |
| [mythicalManMonthVibeCoding](ai-vibecoding-agents/mythicalManMonthVibeCoding.md) | 《人月神话》在 vibe coding 时代还剩什么:解读 + 4 处商榷,指出文章漏掉第二系统效应与进度追踪幻觉,并把 Brooks 定律重新锚定到 agent 编排。 |
| [bagidea-office](ai-vibecoding-agents/bagidea-office.md) | Claude Code 当引擎、脑子可换的桌面像素小人办公室:20 模型混搭 / agent 自发开会 / 自提案 plugin / 真·桌面壁纸模式 / WorkerW 监督 / 三层预算 / 5 套团队模板。228⭐,3 个月增长。 |
| [3dgs-substation-digital-twin](ai-vibecoding-agents/3dgs-substation-digital-twin.md) | 3DGS 在变电站数字孪生的深度分析(去除营销,技术原理 + 5 大真实优势 + 7 大不足 + 6 大工程挑战 + 成本估算)。 |
- [armorpaint-tech-selection](armorpaint-tech-selection.md) — ArmorPaint 开源 PBR 纹理绘制工具(给初级前端 + PM 的技术选型参考,12 节,含 9 年时间线 / 5 大方案对比 / 6 大限制 / 借鉴到自己的项目)
| [lobeHub](ai-vibecoding-agents/lobeHub.md) | 把零散 LLM Agent 统一纳管的"首席 Agent 运营官"产品(招聘/排班/IM 网关)。 |
| [logue](ai-vibecoding-agents/logue.md) | macOS 端完全本地(Apple Silicon MLX)的 AI 会议笔记 + 写作助手。 |
| [mattpocock-skills](ai-vibecoding-agents/mattpocock-skills.md) | Matt Pocock 从 `.agents/` 开源的 Real Engineering skills,2×2 分类。 |
| [OpenKimiPPTSkill](ai-vibecoding-agents/OpenKimiPPTSkill.md) | 逆向 Moonshot Kimi Slides 的非官方 PPT 创作 skill,生成可继续编辑的 PPTD 项目。 |
| [openclaw-awd-arena](ai-vibecoding-agents/openclaw-awd-arena.md) | Docker 编排的 LLM Agent 攻防对抗平台,容器隔离网络里多 agent 互打 + 实时计分大屏。 |
| [openopc](ai-vibecoding-agents/openopc.md) | HKUDS 开源的"个人 AI 原生公司"模拟器,Phaser 像素办公室可视化 AI 员工。 |
| [openviking](ai-vibecoding-agents/openviking.md) | ⭐39,514 火山引擎的 Agent 上下文数据库:`viking://` 虚拟文件系统 + L0/L1/L2 三层渐进加载 + 会话提交抽长期记忆。⚠️ AGPL-3.0 主仓(CLI/examples Apache 2.0、Hermes 插件 MIT);v0.5.0 破坏性变更(peer 改用 git origin、WM 默认关闭);**Hermes 是官方 Built-in 集成**,LoCoMo 记忆 33.38% → 82.86%。 |
| [paperclip](ai-vibecoding-agents/paperclip.md) | 92,766⭐ 的 agent 公司级控制平面:org chart + 原子任务 checkout + 预算硬停 + 审批门 + 审计日志,**内置 Hermes adapter**(`hermes_local` / `hermes_gateway`)。 |
| [paseo](ai-vibecoding-agents/paseo.md) | 跨平台多 agent 编排器,统一管理 Claude Code / Codex / Copilot / OpenCode / Pi。 |
| [ponytail](ai-vibecoding-agents/ponytail.md) | 给 AI coding agent 注入"老员工 + YAGNI"人格的跨 13 平台 skill 集。 |
| [rea](ai-vibecoding-agents/rea.md) | 20,918⭐ 的逆向 MCP:106+ 工具封装 Hopper/Ghidra/IDA,强制每条结论挂 Evidence ID 并记录 unknowns。 |
| [remix-reference-video-prompt](ai-vibecoding-agents/remix-reference-video-prompt.md) | SKILL.md 级 prompt skill,按参考视频拆解运镜 + 生成结构化视频提示词。 |
| [reverse-skill](ai-vibecoding-agents/reverse-skill.md) | AI Agent 的安全/逆向/渗透任务路由,857 文件 / 55 skill 模块 / R0-R39 路由。 |
| [semantica](ai-vibecoding-agents/semantica.md) | ⭐13,856 的图原生 AI 可解释基础设施:决策变一等可查询对象 + W3C PROV-O 溯源 + Rete/Datalog/SPARQL 确定性推理,面向金融医疗法律合规。⚠️ 实测推翻 README 4 处(advanced_analytics 裸装即崩 / trace 只对下游有效 / 语义检索喂关键词无结果 / 规则门禁缺字段返假阴性),且 bus factor = 1。 |
| [teamai-cli](ai-vibecoding-agents/teamai-cli.md) | 腾讯开源的 Git-native 团队 AI 工具 CLI,push/MR/pull 同步 skill 给各 agent。 |
| [awesome-agent-skills](ai-vibecoding-agents/awesome-agent-skills.md) | VoltAgent 维护的 1497+ agent skill 官方合集索引,70+ 真实工程团队出品,适配 8 个 AI 编程工具。 |
| [awesomeOpus55Videos](ai-vibecoding-agents/awesomeOpus55Videos.md) | 476 位创作者用 Claude Opus 5.5「让 AI 把动画写成代码」产出的 513 条爆款视频 + prompt 语料库,MIT;一手统计 motion 占 62% / Canvas 是地基 / prompt 中位仅 180 字 / 近一半标记为残缺。 |
| [CnDemSkill](ai-vibecoding-agents/CnDemSkill.md) | 「说个地名就下载中国 30 米 DEM」的 WorkBuddy skill 拆解 + 一手核验:GLO-30 免 Key 桶实测、TIFF 头逐标签解析,并推翻原文 2 处技术错误(multi-polygon bug 真实根因是 `_full` 端点选错、GCJ-02 纠偏存疑)。 |
| [wake](ai-vibecoding-agents/wake.md) | Mac 上 Rust+GPUI 写的 multi-agent 会话档案馆,统一浏览本地历史。 |

---

## 🛠️ [ops-cybersec-dba/](ops-cybersec-dba/) — Ops / Cybersec / DBA / 监控(19)

| 文档 | 一句话 |
|---|---|
| [anthropic-cybersecurity-skills](ops-cybersec-dba/anthropic-cybersecurity-skills.md) | 817 个结构化网络安全技能 + 6 框架映射,让 AI agent 像资深安全分析师工作。 |
| [codex-security](ops-cybersec-dba/codex-security.md) | OpenAI 开源的 `@openai/codex-security`,自动验证漏洞,不报误报。 |
| [disable-ipv6-multi-kernel](ops-cybersec-dba/disable-ipv6-multi-kernel.md) | 多内核 Linux 引导菜单批量加 `ipv6.disable=1` 的完整 SOP。 |
| [kylinV10DisableIPv6](ops-cybersec-dba/kylinV10DisableIPv6.md) | 麒麟 V10 ARM 版通过 GRUB 内核参数彻底关闭 IPv6 的 5 步操作流程。 |
| [linux-permission-debug](ops-cybersec-dba/linux-permission-debug.md) | `chmod 777` 成功但服务仍 Permission denied 的 6 层访问链调试。 |
| [frpc-desktop](ops-cybersec-dba/frpc-desktop.md) | FRP 内网穿透跨平台桌面客户端(Electron + Vue 3),可视化配 frpc 代理,6,875⭐ 头部项目。 |
| [bash-reference-manual](ops-cybersec-dba/bash-reference-manual.md) | Bash Reference Manual 完整学习(10 章 + 4 附录,含 8 大展开 / 13 类重定向 / 80+ 内建命令 / 12 大陷阱 / 5 大最佳实践)。 |
| [netdata](ops-cybersec-dba/netdata.md) | 开箱即用的 per-second 实时监控平台,自带 ML 异常检测 + 告警。 |
| [opsTroubleshootingDiskGhost](ops-cybersec-dba/opsTroubleshootingDiskGhost.md) | df 说满、du 说没满 ——「幽灵空间」排查(fd 还指向的 inode)。 |
| [opsTroubleshootingOOMCgroup](ops-cybersec-dba/opsTroubleshootingOOMCgroup.md) | free 还有 8G 但 OOM 杀进程 —— cgroup 账本思维排查。 |
| [opsTroubleshootingStealTime](ops-cybersec-dba/opsTroubleshootingStealTime.md) | 云上 CPU 30% 却卡:steal time 排查三板斧 + 工单取证话术。 |
| [opsTroubleshootingTCPPortExhaustion](ops-cybersec-dba/opsTroubleshootingTCPPortExhaustion.md) | 调大 ulimit 反而雪崩:出站 TCP 端口耗尽 `EADDRNOTAVAIL` 三层修复 + 自查清单。 |
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
| [scDatav](web-frontend-ui/scDatav.md) | Three.js + React 19 数据大屏:一张四川地图做出地形纹理/热力起伏/蓝色电力风/GLB 拆解 4 种风格,Apache-2.0 可商用。 |
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
| [ReArk](developer-productivity/ReArk.md) | HarmonyOS + Android 桌面逆向与 AI 辅助分析工作台(静态分析 + 真机投屏 + LLM Agent 三合一)。 |
| [remote-obd-deep-analysis](developer-productivity/remote-obd-deep-analysis.md) | 远程 OBD USB 诊断方案的深度技术分析(12 节,含 USB over IP 协议 / XTCP 打洞 / HEX-V2 VCDS 协议栈 / 车载恶劣环境生存策略)。 |
| [remote-obd-usb-over-ip](developer-productivity/remote-obd-usb-over-ip.md) | 车载 OBD 远程 USB 透传(N1 + VirtualHere + FRP/XTCP),27 节文章 + 6 大实际坑 + 8 大可迁移场景。 |
| [sdrangel](developer-productivity/sdrangel.md) | SDRangel 开源软件无线电「全家桶」工作台(87 插件 / 10 硬件 / Rx+Tx, NOAA / AIS / FT8 / LoRa, 4059⭐) |
| [press-fit-guard](developer-productivity/press-fit-guard.md) | 新能源三电压装上位机:全行程位移-压力包络线判定替代只看峰值,Modbus 从站仿真 + SQLite WAL 追溯(⚠️ 仓库空仓,内容来自公众号文章) |
| [hermes-feishu-gateway-bug](developer-productivity/hermes-feishu-gateway-bug.md) | Hermes feishu gateway 入站缺 `message_id` 时静默丢弃整条消息(仅 DEBUG 日志)。含已装 fallback patch 的 6 处一手复核,以及 cron 监控被 `grep -c` + `set -e` 静默打挂 12 天的第二层 bug。 |

---

## 📌 [misc/](misc/) — Misc / 专项主题

#### 🎮 [misc/OS-gaming-console/](misc/OS-gaming-console/) — 掌机 / 自定义 firmware

| 文档 | 一句话 |
|---|---|
| [Mindustry](misc/OS-gaming-console/Mindustry.md) | 一人开发 9 年的 GPL-3.0 开源工厂塔防:四渠道分层定价(itch 自愿付费 / Play+F-Droid 免费 / iOS $1.99 / Steam $9.99),零广告零内购零 DLC,约 130 万份 / $630 万。 |
| [leaf-deploy](misc/OS-gaming-console/leaf-deploy.md) | Miniloong Pocket 1 掌机的自定义固件,SD 卡安装 / OTA 升级 / recovery 回退(基于 v0.11.0)。 |

---

## 📊 统计

| 分类 | 文档数 |
|---|---|
| 🤖 ai-vibecoding-agents | 24 |
| 🛠️ ops-cybersec-dba | 19 |
| 🌐 web-frontend-ui | 17 |
| ⚡ developer-productivity | 7 |
| 📌 misc/OS-gaming-console | 2 |
| **总计** | **69** |

(69 个被分类的 doc + 1 个根 README.md + 1 个 CONTRIBUTING.md)

---

## 🔗 相关项目

- **iswiki 主仓**: <https://github.com/ishadowland/iswiki>
- **liuyin**(作者): <https://github.com/ishadowland>