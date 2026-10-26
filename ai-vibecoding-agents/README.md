# 🤖 AI Vibecoding Agents / 编排

> AI coding agent 工具 / 编排框架 / skill 集 / 多 agent 协作平台 / AI 视频 prompt / macOS AI 工具

## 索引

| 文档 | 描述 |
|------|------|
| [3dgs-substation-digital-twin](3dgs-substation-digital-twin.md) | 3DGS 在变电站数字孪生的深度分析(去除营销,技术原理 + 5 大真实优势 + 7 大不足 + 6 大工程挑战 + 成本估算)。 |
| [anthropicAiCodeReview](anthropicAiCodeReview.md) | 马克的技术工作坊解读 Anthropic《How the Claude Code team does code review》:**Claude Code 90% 代码由 AI 写**(monorepo 每日变更 5 月 ~2,500 → 9 月 >30,000),审核从"人读代码"重构为**七层自动防线**(验证→AI review→安全→CI→按风险审批→合并队列/开关→回滚)。含 **AI review 三步**(发现/过滤/处理)+ **三个优化目标**(找真问题用真实历史 bug 评测集打分 / 减噪声用"作者反应四分类"+已知干净 PR 两种方法量化 / 让 review 收敛的**四条规则**)与效果(**一轮过审 65%→78%、≥5 轮 8.9%→1.5%、平均轮数 2.08→1.32、PR 翻倍而回滚降 40%+**)。**最可迁移:用"全新 context 的 agent"审 diff**(原 agent 自查会沿用原思路漏问题);**59% 反复标记的代码是第一轮就有的老代码**(git blame 实测,直接推出"后几轮只审新 diff")。⚠️ 原文补充视频未讲的 6 项(谁下令谁担责 / agent 批准不算人批 / 一次批准只覆盖一个 commit / CLAUDE.md+REVIEW.md / 多 agent 投票过滤 finding + Important·Nit·Pre-existing 标签 / 夜间扫存量代码)。数据均为 Anthropic 单点无对照组,且"零人工合并"作者自承尚缺 circuit breaker。 |
| [awesome-agent-skills](awesome-agent-skills.md) | VoltAgent 维护的 1497+ agent skill 官方合集索引,70+ 真实工程团队出品,适配 8 个 AI 编程工具。 |
| [awesome-design-md](awesome-design-md.md) | VoltAgent 维护的 74 份大厂设计系统 `DESIGN.md` 单文件合集(Google Stitch 2026-04-21 开源 spec); Stripe / Linear / Claude / Vercel 等的色板/字体/组件/Do's-and-Don'ts 写进 YAML+md,丢项目根目录 AI 写 UI 就有据可依。⚠️ 仓内**没有 preview.html**,实测子 README 自述"已迁到 getdesign.md",真预览在站上。120,017★ / MIT / 313 issues。 |
| [awesomeOpus55Videos](awesomeOpus55Videos.md) | 476 位 X 创作者用 Claude Opus 5.5「让 AI 把动画写成代码」产出的 513 条爆款视频 + 原始 prompt 语料库,MIT 开源;一手统计出 motion 占 62% / Canvas 是地基 / prompt 中位仅 180 字 / **近一半 `prompt_partial` 标记为残缺**。 |
| [CnDemSkill](CnDemSkill.md) | 「说个地名就下载中国 30 米 DEM」的 WorkBuddy skill 拆解 + 一手核验:GLO-30 免 Key 桶实测、TIFF 头逐标签解析,并推翻原文 2 处技术错误(multi-polygon bug 真实根因是 `_full` 端点选错、GCJ-02 纠偏存疑)。 |
| [bagidea-office](bagidea-office.md) | Claude Code 当引擎、脑子可换的桌面像素小人办公室:20 模型混搭 / agent 自发开会 / 自提案 plugin / 真·桌面壁纸模式 / WorkerW 监督 / 三层预算 / 5 套团队模板。228⭐,3 个月增长。 |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | 逆向 Moonshot Kimi Slides 的非官方 PPT 创作 skill,生成可继续编辑的 PPTD 项目。 |
| [fireside-sprint1](fireside-sprint1.md) | Fireside 异步圆桌会议平台的 Sprint 1 闭环笔记(REST 建房 → WebSocket 广播 → EndRoom)。 |
| [i-have-adhd](i-have-adhd.md) | 让 AI coding agent 用 action-first / numbered / no-preamble 风格输出,适合 ADHD 读者。 |
| [img2threejs](img2threejs.md) | AI 看图后按 8 阶段写 Three.js 代码,产物是可继续编辑的 TS,不是网格。 |
| [ipAsLogoSkill](ipAsLogoSkill.md) | 把"极简圆润 IP logo"设计语言写成 17KB SKILL 级硬约束,装到 Codex/Coze/Doubao/YouMind/Manus/Gemini Apps/Replit Agent 7 家,3 方向 × 2 变体 = 6 张候选(3 LL + 3 LR,三色封顶,永不降级 SVG)。5,867★ / MIT。 |
| [MiceInTheMuseum](MiceInTheMuseum.md) | Google Arts & Culture 的 Gemini 多模态 + Google AI Audio 实时音频导览实验(2024-11 上线),架构可平移到儿童讲解 / 景点导览。 |
| [mythicalManMonthVibeCoding](mythicalManMonthVibeCoding.md) | 解读「都2026年了《人月神话》还值得看吗」并商榷:文章无事实错误但漏了原书里对 AI 最危险的两条(第二系统效应 / 进度追踪幻觉),并把 Brooks 定律的 n(n-1)/2 重新锚定到 agent 编排(并行单元从人头换成 agent,公式仍成立)。 |
| [lobeHub](lobeHub.md) | 把零散 LLM Agent 统一纳管的"首席 Agent 运营官"产品(招聘/排班/IM 网关)。 |
| [logue](logue.md) | macOS 端完全本地(Apple Silicon MLX)的 AI 会议笔记 + 写作助手。 |
| [mattpocock-skills](mattpocock-skills.md) | Matt Pocock 从 `.agents/` 开源的 Real Engineering skills,2×2 分类。 |
| [mattpocock-skills-1-3](mattpocock-skills-1-3.md) | v1.3 把五步补成闭环七步:新增 `implement-spec`(task graph + frontier 并行,含 5 个实测坑)/ `pr`(Summary+Evidence+Merge Danger 三段式)/ `retro`(改环境不改代码)。一手核验 7 处,**视频漏报 `resolving-merge-conflicts` 被删 + `CONTEXT.md` 全线改名 `GLOSSARY.md` 两项破坏性变更**;`pr` 的视觉菜单实测抄自 Dex Horthy 的 `show-me`。294,790★ / MIT / v1.3.1。 |
| [openclaw-awd-arena](openclaw-awd-arena.md) | Docker 编排的 LLM Agent 攻防对抗平台,容器隔离网络里多 agent 互打 + 实时计分大屏。 |
| [openclaw-yolo-inspection](openclaw-yolo-inspection.md) | 把 YOLO 缺陷检测接进 agent 自动化的完整方法论:① **先算延迟预算再决定 agent 落在哪一段**(LLM 单次 1-3s + 推理 0.5s = 5s+,高速产线装不下就不放) ② 四步法(先训模型→再封 skill→再编排→最后接渠道,顺序不能反) ③ **五级递进阶梯**(日报→预警→趋势→评分→归档,后级依赖前级产物,当 checklist 用) ④ 低代码配置法(自然语言→声明式→人工审查三件事) ⑤ 声明式评分规则 + 扣分明细拆解两个可迁移模式。⚠️ 接口层 6 处必须重写:OpenClaw 没有 `skill.json`(是 `SKILL.md`)、`.py` 不自动注册成 tool、没有 `tasks/*.yaml` workflow DSL(只有 at/every/cron/on-exit/stream)、`@openclaw/wecom-bot` npm 404(真名 `@wecom/wecom-openclaw-plugin`)、配置 key 是 `channels.wecom.botId`、`openclaw wecom` 子命令不存在;另实测 `openclaw automations` / `openclaw lobster` 在本机 2026.3.28 是 unknown command。含良率去重 / 模型复用 / utf-8-sig / 归因要标假设四个坑 + AGPL-3.0 商用传染性。 |
| [openopc](openopc.md) | HKUDS 开源的"个人 AI 原生公司"模拟器,Phaser 像素办公室可视化 AI 员工。 |
| [openviking](openviking.md) | ⭐39,514 火山引擎的 Agent 上下文数据库:`viking://` 虚拟文件系统 + L0/L1/L2 三层渐进加载 + 会话提交抽长期记忆。⚠️ **AGPL-3.0**(CLI/examples Apache 2.0、Hermes 插件 MIT);v0.5.0 有破坏性变更(peer 改用 git origin 推导、WM 默认关闭);**Hermes 是官方标注 Built-in 的集成**(Partner Projects 点名),benchmark 里 Hermes 原生记忆 33.38% → 82.86%。 |
| [paperclip](paperclip.md) | 92,766⭐ 的 agent 公司级控制平面:org chart + 原子任务 checkout + 预算硬停 + 审批门 + 审计日志,内置 Hermes adapter(`hermes_local` / `hermes_gateway`)。 |
| [patentDisclosureSkill](patentDisclosureSkill.md) | ⭐11,836 的「中国专利.skill」:9 个子 skill 覆盖交底书 / 申请四件套 / 解读 / 专利地图 / 对照表 / 审查答复 / 政策简报,**根 SKILL.md 只做路由(86 行)**。三个可抄设计:「须点名」硬门禁 / prompt 目录=状态机(max_rounds=3)+ 42 个 YAML Schema gate / 机读前缀 + 退出码协议。⚠️ 无 tag、无 CI、5 个工具有意存 3 份副本(~190 KB 重复)、只覆盖 CNIPA。 |
| [pixelFanAiVerification](pixelFanAiVerification.md) | 像素范《AI 越来越会做,为什么会验收的人更重要?》**全文转写 + 弹幕/评论逐条深读**(v2 扩写)。理论底座是纳瓦尔 2026-02 转发的《Some Simple Economics of AGI》,核心概念 **可衡量性鸿沟**:生成成本趋零但验证成本不同步下降 → AI 替代的是「结果可衡量」的工作而非低技能工作 → 稀缺资源从生产转向验证 → 未来公司卖「错了赔钱」的担保。**10 章 / 35KB**:内容记录 → 弹幕 7 条逐条(「不同≠差距」把程度问题升级为性质问题)→ 评论 5 条逐条(「掰扯成本>动手成本」实证反对 + 「判断模型能力边界」新增技能层)→ 8 段时间轴 → **论证链重建**(最脆弱一环:整套论证依赖「AI 需要人定义偏好」前提,评论区无人回应)→ 13 条观点 + **三层技能树** → **主张 vs 反馈对照表** → 可迁移 → 方法论 + **样本局限自陈**(弹幕仅 7 条/论文未核原文/UP 主是培训从业者有选择偏差)。 |
| [paseo](paseo.md) | 跨平台多 agent 编排器,统一管理 Claude Code / Codex / Copilot / OpenCode / Pi。 |
| [ponytail](ponytail.md) | 给 AI coding agent 注入"老员工 + YAGNI"人格的跨 13 平台 skill 集。 |
| [redisAIAgentStack](redisAIAgentStack.md) | Redis 8 把 Vector Set + 向量检索 + Agent Memory + 语义缓存收进一个内核。**一手核验推翻公众号原文 3 处**(`SemanticSessionManager` 包路径不存在 / `SemanticCache.Builder` 无 `redisUrl()` 必传 client+vectorizer / `check(q,1)` 应为 `checkTopK`)+ 2 处版本(Java artifactId 实为 `redisvl` 0.13.1、`langchain4j-redis` 已停更迁 `langchain4j-community-redis`)。⚠️ **8.0 起 tri-license RSALv2/SSPLv1/AGPLv3**;Iris 是托管服务,本地 Docker 拿不到。 |
| [rea](rea.md) | 20,918⭐ 的逆向 MCP 项目:106+ 工具把 Hopper/Ghidra/IDA 封装成带证据链的接口。最大亮点是 **Evidence ID + unknowns 台账**(`record_unknown` / `verify_unknown_resolution`)——强制每条结论挂证据。⚠️ clone 必须 `--recursive`(5 个 submodule),原生分析需 Hopper/Ghidra/IDA 之一。 |
| [reaVideoReview](reaVideoReview.md) | Gary Chen《REA 到底在紅什麼？》13 分钟视频的一手字幕拆解(372 段官方 zh-TW 字幕全提取)+ 22 条评论交叉核验。视频侧视角,补 [rea](rea.md) 缺的三块:爆红原因(工具存在≠人用得起)、真实使用手感、边界认知。最硬的一段是 0:51「门槛不在工具在编译丢信息」;可迁移方法论是 8:22「参考物消灭猜测空间」。⚠️ 一手核验 5 处:视频省略 Hopper/Ghidra 授权门槛 / 作者自承不确定备忘录复刻是否真成功 / 8:14 最强对照实验未给来源 / 全片未提法律边界 / 未提 skill 与 npm 版本不同步的坑。 |
| [remix-reference-video-prompt](remix-reference-video-prompt.md) | SKILL.md 级 prompt skill,按参考视频拆解运镜 + 生成结构化视频提示词。 |
| [reverse-skill](reverse-skill.md) | AI Agent 的安全/逆向/渗透任务路由,857 文件 / 55 skill 模块 / R0-R39 路由。 |
| [semantica](semantica.md) | ⭐13,856 的图原生 AI 可解释基础设施:决策变一等可查询对象 + W3C PROV-O 溯源 + Rete/Datalog/SPARQL 确定性推理,面向金融医疗法律合规。⚠️ **实测推翻 README 4 处**(`advanced_analytics=True` 裸装即崩 / trace 只对下游有效 / 语义检索喂关键词无结果 / 规则门禁缺字段返假阴性),且 bus factor = 1。 |
| [teamai-cli](teamai-cli.md) | 腾讯开源的 Git-native 团队 AI 工具 CLI,push/MR/pull 同步 skill 给各 agent。 |
| [wake](wake.md) | Mac 上 Rust+GPUI 写的 multi-agent 会话档案馆,统一浏览本地历史。 |

| [multiAccountUnifiedAuth](multiAccountUnifiedAuth.md) | 公众号《我是程序汪》2026-10-20《多账号统一登录(实现方案)》的全文沉淀。作者 jruing / dustyblog.cn;核心动作是把 `users` 与 `user_auth` 拆为两张表,使新增第三方登录的成本降到零。含核心数据表 SQL 块 + 4 阶段叙述 + 方法论备注。 |

**共 36 个文档**(本次新增 1 篇 multiAccountUnifiedAuth)。
