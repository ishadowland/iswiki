# 🤖 AI Vibecoding Agents / 编排

> AI coding agent 工具 / 编排框架 / skill 集 / 多 agent 协作平台 / AI 视频 prompt / macOS AI 工具

## 索引

| 文档 | 描述 |
|------|------|
| [3dgs-substation-digital-twin](3dgs-substation-digital-twin.md) | 3DGS 在变电站数字孪生的深度分析(去除营销,技术原理 + 5 大真实优势 + 7 大不足 + 6 大工程挑战 + 成本估算)。 |
| [awesome-agent-skills](awesome-agent-skills.md) | VoltAgent 维护的 1497+ agent skill 官方合集索引,70+ 真实工程团队出品,适配 8 个 AI 编程工具。 |
| [awesomeOpus55Videos](awesomeOpus55Videos.md) | 476 位 X 创作者用 Claude Opus 5.5「让 AI 把动画写成代码」产出的 513 条爆款视频 + 原始 prompt 语料库,MIT 开源;一手统计出 motion 占 62% / Canvas 是地基 / prompt 中位仅 180 字 / **近一半 `prompt_partial` 标记为残缺**。 |
| [CnDemSkill](CnDemSkill.md) | 「说个地名就下载中国 30 米 DEM」的 WorkBuddy skill 拆解 + 一手核验:GLO-30 免 Key 桶实测、TIFF 头逐标签解析,并推翻原文 2 处技术错误(multi-polygon bug 真实根因是 `_full` 端点选错、GCJ-02 纠偏存疑)。 |
| [bagidea-office](bagidea-office.md) | Claude Code 当引擎、脑子可换的桌面像素小人办公室:20 模型混搭 / agent 自发开会 / 自提案 plugin / 真·桌面壁纸模式 / WorkerW 监督 / 三层预算 / 5 套团队模板。228⭐,3 个月增长。 |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | 逆向 Moonshot Kimi Slides 的非官方 PPT 创作 skill,生成可继续编辑的 PPTD 项目。 |
| [fireside-sprint1](fireside-sprint1.md) | Fireside 异步圆桌会议平台的 Sprint 1 闭环笔记(REST 建房 → WebSocket 广播 → EndRoom)。 |
| [i-have-adhd](i-have-adhd.md) | 让 AI coding agent 用 action-first / numbered / no-preamble 风格输出,适合 ADHD 读者。 |
| [img2threejs](img2threejs.md) | AI 看图后按 8 阶段写 Three.js 代码,产物是可继续编辑的 TS,不是网格。 |
| [MiceInTheMuseum](MiceInTheMuseum.md) | Google Arts & Culture 的 Gemini 多模态 + Google AI Audio 实时音频导览实验(2024-11 上线),架构可平移到儿童讲解 / 景点导览。 |
| [mythicalManMonthVibeCoding](mythicalManMonthVibeCoding.md) | 解读「都2026年了《人月神话》还值得看吗」并商榷:文章无事实错误但漏了原书里对 AI 最危险的两条(第二系统效应 / 进度追踪幻觉),并把 Brooks 定律的 n(n-1)/2 重新锚定到 agent 编排(并行单元从人头换成 agent,公式仍成立)。 |
| [lobeHub](lobeHub.md) | 把零散 LLM Agent 统一纳管的"首席 Agent 运营官"产品(招聘/排班/IM 网关)。 |
| [logue](logue.md) | macOS 端完全本地(Apple Silicon MLX)的 AI 会议笔记 + 写作助手。 |
| [mattpocock-skills](mattpocock-skills.md) | Matt Pocock 从 `.agents/` 开源的 Real Engineering skills,2×2 分类。 |
| [openclaw-awd-arena](openclaw-awd-arena.md) | Docker 编排的 LLM Agent 攻防对抗平台,容器隔离网络里多 agent 互打 + 实时计分大屏。 |
| [openopc](openopc.md) | HKUDS 开源的"个人 AI 原生公司"模拟器,Phaser 像素办公室可视化 AI 员工。 |
| [openviking](openviking.md) | ⭐39,514 火山引擎的 Agent 上下文数据库:`viking://` 虚拟文件系统 + L0/L1/L2 三层渐进加载 + 会话提交抽长期记忆。⚠️ **AGPL-3.0**(CLI/examples Apache 2.0、Hermes 插件 MIT);v0.5.0 有破坏性变更(peer 改用 git origin 推导、WM 默认关闭);**Hermes 是官方标注 Built-in 的集成**(Partner Projects 点名),benchmark 里 Hermes 原生记忆 33.38% → 82.86%。 |
| [paperclip](paperclip.md) | 92,766⭐ 的 agent 公司级控制平面:org chart + 原子任务 checkout + 预算硬停 + 审批门 + 审计日志,内置 Hermes adapter(`hermes_local` / `hermes_gateway`)。 |
| [paseo](paseo.md) | 跨平台多 agent 编排器,统一管理 Claude Code / Codex / Copilot / OpenCode / Pi。 |
| [ponytail](ponytail.md) | 给 AI coding agent 注入"老员工 + YAGNI"人格的跨 13 平台 skill 集。 |
| [rea](rea.md) | 20,918⭐ 的逆向 MCP 项目:106+ 工具把 Hopper/Ghidra/IDA 封装成带证据链的接口。最大亮点是 **Evidence ID + unknowns 台账**(`record_unknown` / `verify_unknown_resolution`)——强制每条结论挂证据。⚠️ clone 必须 `--recursive`(5 个 submodule),原生分析需 Hopper/Ghidra/IDA 之一。 |
| [remix-reference-video-prompt](remix-reference-video-prompt.md) | SKILL.md 级 prompt skill,按参考视频拆解运镜 + 生成结构化视频提示词。 |
| [reverse-skill](reverse-skill.md) | AI Agent 的安全/逆向/渗透任务路由,857 文件 / 55 skill 模块 / R0-R39 路由。 |
| [semantica](semantica.md) | ⭐13,856 的图原生 AI 可解释基础设施:决策变一等可查询对象 + W3C PROV-O 溯源 + Rete/Datalog/SPARQL 确定性推理,面向金融医疗法律合规。⚠️ **实测推翻 README 4 处**(`advanced_analytics=True` 裸装即崩 / trace 只对下游有效 / 语义检索喂关键词无结果 / 规则门禁缺字段返假阴性),且 bus factor = 1。 |
| [teamai-cli](teamai-cli.md) | 腾讯开源的 Git-native 团队 AI 工具 CLI,push/MR/pull 同步 skill 给各 agent。 |
| [wake](wake.md) | Mac 上 Rust+GPUI 写的 multi-agent 会话档案馆,统一浏览本地历史。 |

**共 26 个文档**。