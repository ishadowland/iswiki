# AwesomeAgentSkills — 1497+ 个 Agent 技能官方仓库速查

> 学习笔记 · 调研时间 2026-09-11
> 仓库: https://github.com/VoltAgent/awesome-agent-skills · 站点: https://officialskills.sh
> License: MIT · ⭐ 数未公开在 README · skills 数 1497+(README badge,含子项目和子链)
> **注意**:这个仓不是 skill 仓本身,而是**索引 + 列表**,每个 skill 跳到对应官方仓

## 一句话定位

VoltAgent 维护的 **agent skill 官方合集索引**,收录 1497+ 个由 **70+ 家真实工程团队**(Anthropic / Google / Vercel / Stripe / Microsoft / NVIDIA / OpenAI / Cloudflare / MongoDB / Notion / Supabase 等)出品、社区验证的 agent skill,**不收录 AI 批量生成的凑数内容**,兼容 8 个 AI 编程工具。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **浏览挑选** | https://github.com/VoltAgent/awesome-agent-skills(README 全文)| 找灵感 / 选 skill |
| **官方目录站** | https://officialskills.sh | 按 vendor / 分类筛 skill,带详情页 |
| **本地一键装**(单 skill)| 各 skill 仓的 `npx skills add <vendor>/<skill>` 或对应工具的目录 | 装到当前工程 |

## Skill 适配 8 个 AI 编程工具(路径速查)

| 工具 | 项目内路径 | 全局路径 | 备注 |
|---|---|---|---|
| **Antigravity** | `.agents/skills/` | `~/.gemini/config/skills/` | Google 出品 |
| **Claude Code** | `.claude/skills/` | `~/.claude/skills/` | Anthropic |
| **Codex** | `.agents/skills/` | `~/.agents/skills/` | OpenAI |
| **Cursor** | `.cursor/skills/` | `~/.cursor/skills/` | |
| **Gemini CLI** | `.gemini/skills/` | `~/.gemini/skills/` | |
| **GitHub Copilot** | `.github/skills/` | `~/.copilot/skills/` | |
| **OpenCode** | `.opencode/skills/` | `~/.config/opencode/skills/` | |
| **Windsurf** | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` | |

> 各家**项目内路径**会冲突 — Antigravity 和 Codex 都是 `.agents/skills/`,GitHub Copilot 跟 Windsurf 不同。

## 按能力/场景分类(核心价值段)

1497 个 skill 全列会爆。这份表**按场景分类,每类列代表 skill 和出处 vendor**,方便按需查。

### 1. 文档处理 / 办公

| Skill | 出处 | 干什么 |
|---|---|---|
| `docx` `pdf` `xlsx` `pptx` | Anthropic | Office 四件套读写 |
| `Nutrient DWS API`(PDF/DOCX/XLSX/PPTX/OCR)| PSPDFKit | 文档转换 + 20+ 语言 OCR + PII redact |
| `xlsx` `spreadsheet` | OpenAI | Excel 公式 / 可视化 |
| `doc-coauthoring` `internal-comms` | Anthropic | 协作文档 / 内部通讯模板 |

**典型场景**:让 agent 帮人写周报、改 PPT、从 PDF 抽合同字段。

### 2. 前端 / 设计 / UI

| Skill | 出处 | 干什么 |
|---|---|---|
| `frontend-design` `frontend-skill` | Anthropic / OpenAI | 生产级前端代码 |
| `canvas-design` `theme-factory` `web-artifacts-builder` | Anthropic | claude.ai artifact 设计 |
| `frontend-design-review` `frontend-ui-dark-ts` | Microsoft | 前端代码评审 + 暗色主题 |
| `figma-*`(7 个)| OpenAI | Figma MCP 设计↔代码 |
| `react-flow-node-ts` `zustand-store-ts` | Microsoft | React Flow 节点 + 状态管理 |
| `gsap` | GSAP | 动画库最佳实践 |
| `add-stroke-effect` `brainstorming` `writing-plans` | obra/superpowers | 设计/计划方法论 |
| `addosmani/web-quality` | Google Chrome / Addy Osmani | Web 质量检查 |

### 3. 后端 / 云服务 / 部署

| Skill | 出处 | 干什么 |
|---|---|---|
| **Azure SDK 矩阵**(~100 个,.NET/Java/Python/Rust/TS)| Microsoft | Cosmos / EventHub / ServiceBus / Identity / KeyVault / Storage 等全套 |
| `vercel-deploy` `nextjs-*` | OpenAI / Vercel | Vercel 部署 + Next.js |
| `cloudflare-deploy` | OpenAI / Cloudflare | Cloudflare Workers / Pages |
| `netlify-deploy` `render-deploy` | OpenAI | Netlify / Render 部署 |
| `terraform-*` | HashiCorp | IaC |
| `core-aws` `aws-serverless` `dynamo-db` | MiniMax | AWS 全套 |
| `mongodb-*` | MongoDB | 文档数据库 |
| `supabase-*` | Supabase | BaaS(Auth / DB / Storage / Edge Functions)|
| `neon-*` | Neon | Serverless Postgres |
| `redis-*` | Redis | 缓存 / 队列 |
| `clickhouse-*` | ClickHouse | OLAP 列存 |
| `duckdb` | DuckDB | 本地 OLAP |
| `apollo-graphql` | Apollo | GraphQL |

**典型场景**:让 agent 帮你写 SQL、建 Redis 缓存、部署到 Vercel、写 Terraform。

### 4. AI / ML 模型

| Skill | 出处 | 干什么 |
|---|---|---|
| `huggingface-*` | Hugging Face | HF 模型 / dataset / pipeline |
| `replicate-*` | Replicate | Replicate 模型市场 |
| `fal-*`(15 个:3D / audio / generate / image-edit / lip-sync / restore / train / tryon / upscale / vision / workflow)| fal.ai | 多模态 AI 推理 |
| `sora` `speech` `imagegen` `transcribe` | OpenAI | OpenAI API(Sora 视频 / TTS / 图 / STT)|
| `venice.ai-*` | Venice.ai | 隐私优先 LLM |
| **NVIDIA 套件**(~16 个:NeMo / Megatron / TensorRT-LLM / DALI / RAG / Nemotron 等)| NVIDIA | GPU 训练 / 推理 / RAG |
| `Mastra-*` | Mastra | TS AI agent framework |

### 5. 鉴权 / 安全

| Skill | 出处 | 干什么 |
|---|---|---|
| `stripe-*` | Stripe | 支付集成 |
| `auth0-*` | Auth0 | OAuth/OIDC |
| `better-auth-*` | Better Auth | 现代 TS 鉴权 |
| `entra-agent-id` `azure-identity-*` | Microsoft | Entra ID / Agent ID |
| **Trail of Bits 安全套件** | Trail of Bits | 静态分析 / fuzz / crypto / SBOM |
| `security-threat-model` `security-best-practices` `security-ownership-map` | OpenAI | 威胁建模 / 安全审查 / 责任人映射 |
| `qoder-security` | 阿里 Qoder | AI 安全工程师 |

### 6. 数据 / 搜索 / 爬虫

| Skill | 出处 | 干什么 |
|---|---|---|
| `firecrawl-*` | Firecrawl | 网页 → 结构化数据 |
| `crawl-html` / `crawl-markdown` / `crawl-screenshot` | Crawlbase | 爬虫 + 截图 |
| `serpapi-web-search` | SerpApi | 130+ 搜索引擎 |
| `brave-search` | Brave | 隐私搜索 |
| `playwright` `playwright-interactive` | OpenAI / Microsoft | 真实浏览器交互 |
| `multi-source-search` | sandbase | 多源研究 + 离线验证 |
| `qdrant` | Qdrant | 向量数据库(7 语言 SDK)|

### 7. 通信 / 协作 / 生产力

| Skill | 出处 | 干什么 |
|---|---|---|
| `notion-*`(5 个)| Notion / OpenAI | 知识库 / 会议 / 研究 / 任务 |
| `linear` | OpenAI / Linear | 项目管理 |
| `sentry` | OpenAI / Sentry | 错误监控 |
| `slack-gif-creator` | Anthropic | Slack 限大小 GIF |
| `resend` `courier` `mailtrap` | Resend / Courier / Mailtrap | 邮件 |
| `whatsapp-*`(3 个)| gokapso | WhatsApp 集成 / 自动化 / 监控 |
| `notebooklm-skill` | PleasePrompto | NotebookLM 集成 |
| `claude-memory-skill` | hanfang | 分层文件系统记忆 |
| `founder-skills` | ognjengt | 创业者工作流 |

### 8. 营销 / SEO / 增长

| Skill | 出处 | 干什么 |
|---|---|---|
| `ai-marketing-claude-code-skills`(17 框架)| BrianRWagner | 冷外联 / 落地页审计 / 社交卡 |
| `claude-seo` | AgriciDaniel | 通用 SEO 审计 |
| `goose-skills`(125 个 GTM)| gooseworks | 广告 / 内容 / lead gen / SEO |
| `aaron-marketing-skills`(69 个)| aaron-he-zhu | SEO/GEO + 5 基准审计门 |
| `digital-marketing-pro`(150 个)| indranilbanerjee | EU AI Act C2PA 合规 |
| `humanizer` `unslop` `humanizer-ru` `sepia` | blader / MohamedAbdullah / Vladimir-Human / Nanako0129 | 去 AI 味 |
| `creative-director-skill` | smixs | 创意总监,20+ 方法论 |
| `x-twitter-scraper` `tweetclaw` | Xquik-dev | X/Twitter 抓取 + 自动发帖 |

### 9. 产品 / PM

| Skill | 出处 | 干什么 |
|---|---|---|
| `product-manager-skills`(30+ 框架)| Dean Peters | PM agent + SaaS metrics |
| `product-management-skills` | Paweł Huryn | PM 方法论 |
| `gtm-cofounder`(18 个)| AIDevGTM | 独立开发者 GTM |
| `cfo-skill` | EveryInc | CFO 财务管理(Charlie Munger 风)|
| `resume-skills`(20 个)| Paramchoudhary | 简历优化 / ATS / 面试 |
| `career-ops`(14 个)| santifer | AI 求职 pipeline |
| `tax-classification`(371 个,134 国)| openaccountants | 全球税务分类 |

### 10. 框架 / 工程方法论

| Skill | 出处 | 干什么 |
|---|---|---|
| `superpowers` 套件(`brainstorming` `writing-plans` `executing-plans` `dispatching-parallel-agents` `using-superpowers`)| obra | Claude Code 必装方法论 |
| `voltagent-best-practices` `voltagent-core-reference` | VoltAgent | VoltAgent TS 框架 |
| `mcp-builder` `skill-creator` | Microsoft / Anthropic | MCP server / skill 创建指南 |
| `cloud-solution-architect` | Microsoft | Azure 架构设计 |
| `continual-learning` | Microsoft | Azure AI 持续学习 |

### 11. 3D / 媒体 / 多模态生成

| Skill | 出处 | 干什么 |
|---|---|---|
| `fal-3d` / `fal-vision` / `fal-audio` / `fal-video-edit` | fal.ai | 3D / 视觉 / 音视频 |
| `remotion` | Remotion | React 写视频 |
| `remotion-render` | Remotion | Remotion 渲染 |
| `develop-web-game` | OpenAI | 用 Playwright 时间步进写 web 游戏 |

### 12. 数据库 / SQL / 测试

| Skill | 出处 | 干什么 |
|---|---|---|
| `playwright` / `cypress` | OpenAI / Cypress | E2E 测试 |
| `azure-resource-manager-playwright-dotnet` | Microsoft | 大规模 Playwright |
| `gh-fix-ci` | OpenAI | GitHub Actions CI 修复 |
| `testmu-*` | TestMu AI | LambdaTest 测试云 |

### 13. 其他垂直

| Skill | 出处 | 干什么 |
|---|---|---|
| `binance` | Binance | 加密交易 |
| `coinbase` | Coinbase | 加密 |
| `datadog-labs` | Datadog | 可观测 |
| `tinybird` | Tinybird | 实时分析 |
| `react-native-*` `expo-*` `callstack-*` | React Native / Expo / CallStack | RN / Expo 移动 |
| `flutter-*` `firebase-*` | Flutter / Firebase | Flutter |
| `wordpress-*`(13 个)| WordPress 官方 | WP 路由 / Block / Plugin / REST |
| `redhat-*` | Red Hat | RHEL / OpenShift |
| `google-workspace-cli` | Google | Workspace CLI |
| `google-cloud-*` | Google Cloud | GCP |

## 装一个 skill 的标准流程(以 Claude Code 为例)

```bash
# 1. 浏览列表 -> 选 skill
# README 找到 vendor/skill, 比如 openai/linear

# 2. 通过 vendor 仓安装(各 vendor 自带 README 教)
# 大多数 vendor 提供 npx scripts:
npx skills add openai/linear   # 假设 vendor 暴露了 CLI

# 或手动放到对应目录:
mkdir -p .claude/skills/linear
# 把 vendor 仓的 SKILL.md 放进去

# 3. 在 Claude Code / Cursor / Codex 里描述需求
# agent 会自动发现匹配的 skill 并加载
```

## ⚠️ 安全提示(README 显式声明)

> "Skills in this list are curated, not audited." — 收录 ≠ 审计过。

| 风险 | 推荐工具 |
|---|---|
| Prompt injection / tool poisoning / hidden payload | [Snyk agent-scan](https://github.com/snyk/agent-scan) |
| Skill 来源可信度 | [Agent Trust Hub](https://ai.gendigital.com/agent-trust-hub) |

**生产环境装 skill 前必读源码**。

## 质量标准(README 公开的社区约定)

| 维度 | 要求 |
|---|---|
| **Description** | 第三人称;说清 *做什么* 和 *何时用*;关键词具体(如"PostgreSQL 迁移"而不是"数据库")|
| **Progressive disclosure** | 顶层 metadata < 100 token;body < 500 行;大文档按需加载,不内联 |
| **No absolute paths** | 不写死 `/Users/alice/`,用相对路径或 `$HOME` / `$PROJECT_ROOT` |
| **Scoped tools** | 只声明需要的 tool,不要 `"tools": ["*"]` |

## 跟我们的关系

**适用场景画像:**

1. **Hermes Agent 自身的 skill 生态参考** — Hermes 已经用 skill 机制管理能力,这仓库是 skill 设计的最佳实践样本(质量标准、命名、文件结构)
2. **私活借用官方成熟 skill** — 帮人写前端(`frontend-design`)、部署 Vercel(`vercel-deploy`)、跑 Stripe(`stripe-*`)、写 Notion(`notion-*`)时,直接 clone 官方 skill 加载,不用自己造
3. **学习企业级 skill 的结构** — Microsoft 100+ 个 Azure SDK skill 是**企业级 SDK 文档 + agent skill 融合的范例**;Microsoft 一个 vendor 占全仓 ~25%,说明**Azure 的 agent 化路线已经成熟**
4. **避开 "AI-slop" 自创 skill** — README 显式拒收"3 小时前造的新 skill",印证社区经验:**复用 > 自造**

**不要做的事:**

1. ❌ 不要盲目 `npx skills add <unknown-vendor>/<skill>` — README 自带安全警告,生产装前过 Snyk agent-scan
2. ❌ 不要把 1497 个全装 — 路径冲突 + 噪音爆炸,只挑当前任务相关的
3. ❌ 不要在跨平台项目混用不同工具的路径 — `.agents/skills/` 在 Antigravity 和 Codex 都合法,但语义不同

**值得立刻装的 3 个 skill**(按通用度):`obra/superpowers`(方法论)、`openai/notion-*`(知识库)、`stripe/*`(支付接入)

## 数据校正

| 用户口述 | 远端 README | 说明 |
|---|---|---|
| "Anthropic / Google / Vercel / Stripe 这些顶尖工程团队" | 70+ vendor,Anthropic / Google / Vercel / Stripe 仅是其中 4 家 | README 实际涵盖 Microsoft / OpenAI / NVIDIA / Cloudflare / MongoDB / Notion 等更多 |
| "1497+ 个 skill" | 1252 个一级 skill + 子项目 + 链向官方仓的目录项 | badge 数字,真实目录展开后更多 |

## 参考链接

- GitHub 仓: https://github.com/VoltAgent/awesome-agent-skills
- 官方目录站: https://officialskills.sh
- Snyk skill 安全扫描: https://github.com/snyk/agent-scan
- Anthropic Claude Code skills 文档: https://docs.anthropic.com/en/docs/claude-code/skills
- 调研来源: https://mp.weixin.qq.com/s/6eEgiYRhTOOGjQp6rvvx3A 风格的中文 agent 综述 — 本笔记无对应来源,直接核 README
