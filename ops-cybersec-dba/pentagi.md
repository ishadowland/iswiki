# PentAGI — 开源自托管多智能体渗透测试平台

> 调研时间 2026-11-18 · 仓库: https://github.com/vxcontrol/pentagi
> License: **MIT + 附加 EULA**（双层，见 §五）· 语言: Go（后端）+ React/TypeScript（前端）
> ⭐ 34,520 · Fork 5,478 · Open Issues 76 · 创建 2025-01-06 · 最后推送 2026-11-13
> 最新 release: **v2.2.0（2026-10-05）** ⚠️ 仓库仍在持续推送，release 滞后约 6 周
> 开发方: VXControl（迪拜安全工程公司）· 官方文档站: https://pentagi.com

## 一句话定位

**自托管的多智能体渗透测试平台** —— 你用自然语言描述目标和目标，十几类专职 AI agent 自行制定计划、在隔离 Docker 沙箱里跑 nmap / Metasploit / sqlmap 等 20+ 专业工具、记住学到的东西，最后交一份报告。

同类项目已有 [strix](strix.md) 一篇；本文是 PentAGI 的独立档案，并在 §八 做横向对比。

---

## 一、它解决什么问题

传统漏扫工具（ Nessus、AWVS、扫描器）的共同问题：**规则是死的**。看到 `id=` 参数就报 SQLi，不管参数是不是动态拼的、目标有没有 WAF、报错是不是被静默吞掉。结果就是两大痛点：

1. **误报多** —— 大量需要人工逐条甄别
2. **漏报深** —— 业务逻辑、越权链、组合利用基本覆盖不到

PentAGI 的赌注是：**让 LLM 做"怎么试"的判断，把工具做"试什么"的执行**。这带来两个直接结果：

- **能规划攻击链** —— 第三方实测记录到完整链条：发现弱口令 → 拿它进管理后台 → 在设置页找到 API Key → 用 Key 进后端系统，全程无人工干预
- **能适应环境** —— 遇到 WAF 会换手法的可能性（但见 §七 的实测反例）

### 两种工作模式（官方 Discussion #217 明确）

| 模式 | 行为 | 官方建议场景 |
|---|---|---|
| **Autonomous** | 端到端自动，agent 自己拆子任务、可停可调 | 快速第一遍扫、批量自动化 |
| **Assistant** | 人机协同，每步需人确认 | **红队、对生产边缘服务做复杂分析** |

> 官方原话："Fully autonomous mode is not optimal in such scenarios, because the system may use more noticeable tools and techniques."（自主模式可能用到更扎眼的手段，红队场景不适用）

---

## 二、架构

### 容器拓扑（README 的 Container Architecture 图）

```
核心服务
  UI    React + TypeScript          ← Web 控制台
  API   Go + GraphQL + REST         ← Bearer Token 认证
  DB    PostgreSQL + pgvector       ← 向量存储 / 长期记忆
  MQ    异步任务队列
  Agent 多智能体系统                 ← 专职 agent 团队

知识图谱（可选）
  Graphiti → Neo4j                  ← 主机/服务/发现关系图

监控
  OpenTelemetry → Grafana / VictoriaMetrics / Jaeger / Loki

分析
  Langfuse → ClickHouse + Redis + MinIO    ← LLM 可观测性

安全工具
  Scraper 隔离浏览器 + 20+ 专业工具沙箱
```

**体量不小**：PostgreSQL + Neo4j + ClickHouse + Redis + MinIO + Langfuse + Grafana + VictoriaMetrics + Jaeger + Loki。跑一次全量 compose，容器数十几个。

### Agent 角色体系

从 README 的配置表可反推出完整角色清单：

| 角色 | 定位 | 工具调用上限 |
|---|---|---|
| `primary_agent` | 主导者 | 100 |
| `pentester` | 渗透执行 | 100 |
| `coder` | 写脚本/PoC | 100 |
| `installer` | 装工具 | 100 |
| `assistant` | 协助 | 100 |
| `adviser` | **顾问 / 导师（mentor）** | 20 |
| `planner` | 任务规划 | 20 |
| `reflector` | 收尾引导 | 20 |
| `searcher` / `enricher` / `memorist` / `generator` / `reporter` | 搜索 / 丰富 / 记忆 / 生成 / 报告 | 20 |

> 上限通过 `MAX_GENERAL_AGENT_TOOL_CALLS`（默认 100）和 `MAX_LIMITED_AGENT_TOOL_CALLS`（默认 20）配置。

### 小模型增强机制（Beta，但 Always Active）

这是 PentAGI 最有特色的设计：

- **Execution Monitoring** —— 监测 agent 执行模式，异常时**自动唤起 adviser（导师）**干预
- **Intelligent Task Planning** —— planner 先把目标拆成 3-7 个具体步骤再开工
- **Reflector** —— 接近工具调用上限时引导收尾

官方用 **Qwen3.5-27B-FP8** 实测的结论（README 明说是"测试得出"）：

| 指标 | 变化 |
|---|---|
| 结果质量 | **2x** 提升 |
| Token 消耗 | **2-3x** 增加 |
| 执行时间 | **2-3x** 延长 |

⭐ 官方的诚实之处在于没有吹"小模型也能打前沿模型"：他们明确说 *"supervision makes small models useful, not frontier-class"*（监督让小模型**可用**，不是达到前沿水平）。

**最优配置策略**：给 adviser 单独配更强的模型或更高的 reasoning 参数，其余 agent 用基础模型。

---

## 三、怎么用

### 系统要求

- Docker + Docker Compose（或 Podman）
- **最低 2 vCPU / 4GB RAM / 20GB 磁盘** ← 官方给的是最低线，真实生产建议翻倍
- 联网（拉镜像）

### 安装（官方推荐：交互式安装器）

```bash
mkdir -p pentagi && cd pentagi
wget -O installer.zip https://pentagi.com/downloads/linux/amd64/installer-latest.zip
unzip installer.zip
sudo ./installer          # 生产环境推荐 root 运行
```

平台覆盖：Linux amd64/arm64、Windows amd64、macOS amd64/arm64（M 系列）—— 官方站点直接提供预编译安装器。

⚠️ **macOS 官方自己挂警告**：*"If macOS flags a downloaded installer, use only the official PentAGI links..."* —— 即 macOS 可能把安装器误报为恶意软件。官方给了专门的 troubleshooting 章节。

**权限要求**：安装器需要操作 Docker API，默认用 `/var/run/docker.sock`，两条路：

```bash
# 生产：直接 root 跑安装器
sudo ./installer

# 开发：把用户加进 docker 组
sudo usermod -aG docker $USER && newgrp docker && docker ps
```

⚠️ 官方原话警告：*"Adding a user to the `docker` group grants root-equivalent privileges."* —— **docker 组等价 root**，生产环境优先 rootless Docker 或 sudo。

安装器会依次做：系统检查 → 写 `.env` → 配 LLM provider → 配搜索引擎 → **安全加固（生成凭据 + 配 SSL）** → docker-compose 启动。

⚠️ **镜像版本滞后于源码**（实测 Docker Hub `vxcontrol/pentagi`）：可见 tag 只有 `latest` / `2.2.0` / `2.2` / `2` / `nightly` / `2.1.0`，而 GitHub 最新 release 是 v2.2.0（2026-10-05）、仓库 11-13 仍在推送。**这意味着 `docker-compose.yml` 默认拉到的 `latest` 镜像比源码旧约 6 周**。要追最新功能需自行 build，或接受 release 节奏（该 README 自己也提示"更新到最新 build 可修复模型返回畸形 function-call 参数导致流程卡死的问题"—— 这类修复正是镜像滞后时拿不到的）。

### 首次登录

```
https://localhost:8443
默认账号：admin@pentagi.com / admin
```

⚠️ **默认口令是 `admin`** —— README 自己写明"首次登录后必须改密"。官方不开放自助注册，管理员可通过 REST API (`/api/v1/users/`) 管理用户，Swagger UI 在 `/api/v1/swagger/index.html`。

### `.env` 里的默认值（安全审计要点）

`.env.example` 里有一批**明文弱默认口令**，虽标注了 `# change this to improve security`，但生产部署必须逐个改：

```
PENTAGI_POSTGRES_PASSWORD=postgres
NEO4J_PASSWORD=devpassword
LANGFUSE_POSTGRES_PASSWORD=postgres
LANGFUSE_CLICKHOUSE_PASSWORD=clickhouse
LANGFUSE_S3_SECRET_ACCESS_KEY=secretkey
LANGFUSE_REDIS_AUTH=redispassword
LANGFUSE_NEXTAUTH_SECRET=secret
LANGFUSE_INIT_USER_PASSWORD=password
LOCAL_SCRAPER_PASSWORD=somepass
```

还有一个值得注意的：

```
DOCKER_NET_ADMIN=true # enable to use net_admin capability
```

`NET_ADMIN` 是容器逃逸面最大的 capability 之一，官方默认给 `true`。如果目标环境不需要（比如只是打 web 应用），关掉它能显著降低沙箱被突破后的损失。

### LLM Provider（10+ 家）

OpenAI / Anthropic / Gemini / **AWS Bedrock** / **Ollama** / **DeepSeek** / **GLM** / **Kimi** / **Qwen** / **MiniMax** / Mistral / xAI / 任意 OpenAI 兼容端点（含 Azure OpenAI）

聚合商：OpenRouter / DeepInfra / Atlas Cloud / OpenCode Go plan

⭐ **对国内用户特别友好**：DeepSeek / GLM / Kimi / Qwen / MiniMax 都是一等公民配置项，README 里有专门的"Optional: Chinese AI providers"段落和价格表。Qwen3.5-27B-FP8 还有一份完整的 vLLM 本地部署指南（`examples/guides/vllm-qwen35-27b-fp8.md`）。

### 搜索引擎（9 家）

Tavily / Firecrawl / Traversaal / Perplexity / DuckDuckGo / Google Custom Search / Sploitus Search / SearXNG + 内置浏览器分析 fallback 引擎

### API 自动化

```bash
curl -X POST https://your-pentagi-instance:8443/api/v1/graphql \
  -H "Authorization: Bearer <token>" -d '{"query":"..."}'

curl https://your-pentagi-instance:8443/api/v1/flows \
  -H "Authorization: Bearer <token>"

# GraphQL Playground
https://your-pentagi-instance:8443/api/v1/graphql/playground
```

### 可观测性（自建）

- `docker-compose-langfuse.yml` —— LLM 调用可观测
- `docker-compose-observability.yml` —— Grafana + VictoriaMetrics + Jaeger + Loki
- `docker-compose-graphiti.yml` —— Neo4j 知识图谱

---

## 四、能力边界（官方自己划的线）

README 有一节罕见的 **"Current Capability Boundaries"**，直接把三个坑说在前面：

1. ⚠️ **不是 CALDERA 式 BAS / 对手模拟产品** —— 没有预置 campaign、没有预置 attack plan
2. ⚠️ **BAS 风格的 agent 自主编写攻击脚本属于"概念性或未来工作"**，不是已实现的功能
3. ⚠️ **flow report UI 目前只支持** web 查看 / 复制 / Markdown 下载 / PDF 下载 —— **JSON flow-report 导出不作为受支持的输出格式**

另外后文的模型价格表里有个 `*` 标记，部分模型带星号表示**存在已知限制**。

---

## 五、许可证：MIT 之上叠了一层 EULA ⚠️

这是本篇最需要提醒的一点，**很容易只看 LICENSE 文件就误判**：

```
LICENSE      → MIT License (Copyright 2025 PentAGI Development Team)
EULA.md      → PentAGI End User License Agreement (12KB)
NOTICE       → 说明集成 VXControl Cloud SDK（AGPL-3.0 + 对本项目的特别例外）
```

EULA 明确写：*"The source code of PentAGI is provided under the MIT license... This EULA governs your use of the PentAGI software as a whole, including any pre-built Docker images and the web UI, and applies **in addition to** the MIT license."*

⚠️ **冲突时以 MIT 为准**（原文：*"In the event of any conflict between this EULA and the MIT license, the terms of the MIT license shall prevail with respect to the source code."*）—— 注意限定词 **"with respect to the source code"**，对预构建镜像和 Web UI 的约束仍在。

EULA 的关键约束：

| 条款 | 内容 |
|---|---|
| 授权范围 | **仅限合法渗透测试**；授权"non-exclusive, non-transferable, **revocable**"（可撤销） |
| 禁止 | 未经授权的网络访问；**关键基础设施 / 应急响应系统未经充分测试不得使用**；不得在生产环境部署而无 Thorough 安全评估 |
| 责任划分 | 你对 agent 的行为**完全负责**；开发方"不监督、不控制"agent 行为 |
| 赔偿 | **你需赔偿**开发方因你使用软件引发的所有索赔 |
| 责任上限 | 累计责任**不超过你为软件支付的金额**（OSS 用户即 ¥0） |
| 第三方服务 | 承认会接入 OpenAI / Anthropic / OpenRouter 及搜索商，**数据合规责任在你**（含 GDPR） |

⭐ 值得肯定的是 EULA 措辞相当克制——它**不伪称这个工具无害**，而是明确说"this product does not inherently possess tools used for executing cyber attacks. Instead, it facilitates the download of publicly available penetration testing tools"（它本身不含攻击工具，只是帮你下载 Kali 那套公开工具）。这个法律定位是站得住的。

⚠️ **但要注意**：可撤销 + 赔偿条款 + "不得在关键基础设施/生产环境使用"，这与很多企业采购开源安全工具的合规流程有摩擦。商用前建议过一遍法务。

---

## 六、真实使用成本（第三方实测）

PentAGI 的成本几乎完全取决于选哪个模型。README 有完整的价格表（如 `gpt-5.6-sol` $5/$30/$0.5 per M tokens）。

第三方实测数字（**注意这是个人博客，非受控基准**）：

| 实测者 | 场景 | 成本 | 结果 |
|---|---|---|---|
| paolagarcia.com | OWASP Juice Shop | **$1.39** | 38 分钟，15 个任务，11 个发现（3 高/4 中/4 低），**3 个带完整 request/response 证据的已验证 PoC** |
| karl.fail | 自家外网 IP | **€25–30** 每次 | 6 小时；15 次测试共 €250；**人工验证后 80-90% 结果真实可用**；还重测了一个曾花 €15,000 人工渗透的应用，**找到了人工渗透员漏掉的严重漏洞** |
| habr.com | 客户外网 ~200 主机 | 未披露金额 | **6h41m**；Strix 耗 145.1M token vs PentAGI 31.4M |

---

## 七、业界评价（正反都要看）

### ⚠️ 最有分量的一篇负面实测：habr.com（俄语，同行评审式）

对 PentAGI 和 Strix 做对比，用 GLM 5.3 模型跑客户外网约 200 台主机。**结论对本工具非常不利，必须原样记录**：

> **PentAGI 找到 296 个漏洞，其中 42 CRITICAL + 50 HIGH。这 92 个"高危"发现没有一个真正可利用。** 部分"已确认"的 PoC 里混入了别人的 CVE，证据是从报告模板里粘贴的。

同篇还记录：

- **真实的严重漏洞**（2 个 CRITICAL、OAuth 密钥泄露、可执行代码链）**是商业工具找到的**，不是 PentAGI
- **越界扫描** ⭐ —— PentAGI **自己发现了**上半个 CIDR 属于另一家无关组织，标记了 `CRITICAL SCOPE BOUNDARY`，**但仍然继续扫描了那个不属于自己的网段**；作者不得不**手动干预才停下来**
- 首次运行时 Kali 沙箱镜像没下载成功，流程卡在 sandbox 准备阶段
- 结论：*"在这项研究中没能取代渗透测试人员。scope 控制、误报甄别、真实风险评估仍然留在人手里。"*

⚠️ 越界那条尤其要注意 —— 它说明**ROE（Rules of Engagement）约束在这个实现里不足以阻止越界扫描**，这正是 §五 EULA 里"仅限授权测试"那句要靠用户自己兜底的地方。

### GitHub Discussion #217：官方认账内部安全团队的评估

有人在 Discussion #217 提交了一份内部安全团队评估，官方维护者逐条回应并**明确表示"评估大体公允"**：

| 评估项 | 官方回应 |
|---|---|
| 1. 覆盖标准化但深度有限：预编程逻辑打已知漏洞模式，**OWASP Top 10 无法端到端覆盖**，注入/认证/访问控制/业务逻辑都未被系统性评估 | 承认 |
| 2. 规模与速度优势：1-5 小时出首轮结果 | 承认 |
| 3. **误报率 10-30%**，需人工甄别 | 承认 |
| 4. **缺乏上下文与业务逻辑理解**：无法处理自定义业务逻辑缺陷、上下文相关漏洞、工作流滥用 | 承认 |
| 5. **缺乏利用验证**：发现未经端到端 exploit 验证，理论风险被当作真实风险上报 | 承认 |
| 6. **严重度错配**：部分发现未经充分验证却给了高严重度 | 承认 |

官方的定性回答（第 1 问）：

> *"We realistically view PentAGI as a powerful **augmentation layer** for human pentesters, red teamers, and AppSec engineers."*

官方推荐的工作流（第 4 问）：**PentAGI 做首轮自动探索与假设生成 → 人工验证 → 人工引导深入**。

还补了一句现实感的话：*"the quality of the result is directly related to **how much expertise and context the user brings into the process**."*（结果质量直接取决于用户投入了多少专业判断和上下文）

### 其他第三方视角

| 来源 | 结论 |
|---|---|
| **playciso.com** | "free, MIT-licensed"，但**开箱第一步是改默认登录**；建议真正落进安全流程时用 Assistant 模式而非全自动 |
| **medium.com**（亲测） | 攻击链规划能力是真的强（弱口令→管理后台→API Key→后端系统全自动）。但 WAF 挡请求、自定义登录逻辑搞晕它、**幻觉出一个不存在的漏洞**，最后作者得全程盯着审批。结论：省了 10 小时手工，但盯梢的 2 小时更值钱 |
| **franzramadhan.dev**（Homelab） | 隔离方案写得极有价值：**把隔离墙放在 VM 边界**，并**从 agent 自己 spawn 出的容器内部**验证墙是否生效。另一个硬结论：**Cloudflare Workers AI 太弱，tool-calling 不稳** —— 47+ 次 LLM 调用后仍是 0 个任务、0 次工具执行、0 个容器 |
| **saas.pet** | "最有能力的开源自主安全测试 agent"；**擅长已知漏洞类（SQLi/XSS/配置错误），不擅长新型攻击向量**；是**力量倍增器，不是人类专家的替代品** |
| **heatdrop.ai** | 标题即结论："The Open-Source Pentest Agent That **Admits What It Can't Do**" —— 把 §四 的能力边界当成优点来写 |

### 综合判断

PentAGI 的**工程完成度是同类开源项目里最高的**（Web UI、GraphQL、pgvector 记忆、Neo4j 图谱、Langfuse 可观测、K8s 友好、多模型支持全齐），而且**罕见的坦率**——官方主动划能力边界、在 Discussion 里认账误报率和缺乏利用验证、README 里主动写"这不是 BAS 产品"。

但**工程完整 ≠ 结果可靠**。habr 那篇的 296→0 是最硬的警告。PentAGI 的正确定位是 **"高速第一遍扫描 + 假设生成器"**，不是"渗透测试替代品"。

---

## 八、与同类工具横向对比

| | **PentAGI** | [Strix](strix.md) | Shannon | AIRecon |
|---|---|---|---|---|
| 主体 | VXControl | usestrix | KeygraphHQ | pikpikcu |
| ⭐ | 34,520 | 49,400 | 52,037 | 1,095 |
| License | MIT + EULA | Apache-2.0 | **AGPL-3.0** | MIT |
| 语言 | Go + React | Python 3.12+ | TypeScript | Python 3.12+ |
| 形态 | **Web 控制台 + Docker Compose** | CLI + Cloud + Skill | CLI (`npx`) | **TUI (Textual)** |
| 记忆 | PostgreSQL + pgvector + Neo4j 图谱 | notes 目录 | 工作区 | SQLite + JSON + FTS5 |
| 本地模型 | ✅ Ollama / vLLM | ✅ | 需自备 | ✅ **完全离线是卖点** |
| 商业版 | ✅ Enterprise | ✅ Cloud | ✅ Pro $50/开发者/月 | 无 |
| 独立第三方实测 | ✅ **有（含负面）** | ✅ 有 | ⚠️ 少 | ❌ 基本没有 |
| 核心卖点 | 全栈平台化 + 全模型支持 | 简单、Skill 化 | **"No exploit, no report"** | 零 API key + 本地知识库 |

---

## 九、跟我们的关系

我们做的是**工业控制 / 电力系统上位机 + AI coding agent 工具链**，pentagi 有三处可直接借用：

1. ⭐ **adviser 单独配强模型** —— 这条对我们尤其有用。我们用 MiniMax-M3 跑主力，如果遇到需要跨文档推理的任务（等保条款映射、漏洞归类），可以照搬"给 adviser 单独挂强模型、其余 agent 用便宜模型"的思路，而不是全链路换模型。

2. ⭐ **`DOCKER_NET_ADMIN` 默认 true 要改** —— 我们的 pentest/扫描类 agent 如果要容器化跑工具，**默认别给 NET_ADMIN**。pentagi 这行注释是现成的提醒。

3. ⭐ **越界扫描必须靠外部机制兜底** —— habr 那条实测说明 agent 层面的 ROE 声明拦不住越界。**scope 约束要落在网络层**（像 franzramadhan 那样在 VM/防火墙边界拦），不能只写在 prompt 里。

另外可以补进我们的 [blackBoxPentestPlaybook](blackBoxPentestPlaybook.md) 作为对照 —— 那篇是**人工黑盒方法论**，pentagi/strix 是**自动化多智能体**，两者互补：pentagi 适合做首轮广度覆盖，我们的手工 playbook 适合做深挖与差异化验证。

---

## 十、落地建议

**适合用它的场景**：
- 自有基础设施的周期性第一遍扫描（找已知漏洞类）
- CTF / 靶场练习
- 有明确书面授权的客户端项目，且**预期投入人工复核工时**
- 作为**红队前期**的假设生成器

**不适合**：
- 生产环境的唯一验证手段
- 关键基础设施 / 应急响应系统（EULA 明令禁止）
- 期待它做业务逻辑审计（官方和第三方都承认不行）
- 期待它自动收敛范围（habr 实测越界）

**如果上生产，按这个顺序做**：
1. 改 `admin@pentagi.com` 默认口令
2. 逐个替换 `.env` 里的 10 个弱默认口令
3. 关掉 `DOCKER_NET_ADMIN`（除非确实需要）
4. 装在**独立 VM** 里，网络层做 scope 白名单
5. **默认用 Assistant 模式**，不要一上来就全自动
6. 所有发现必须人工验证后再进工单 —— 官方自己说误报率 10-30%，habr 实测的 92 个高危无一可利用
7. 数据出境评估：接了 DeepSeek/Qwen 等国内模型时目标信息仍会出境，需过合规

---

## 参考链接

**官方**
- 仓库 https://github.com/vxcontrol/pentagi
- 官网 https://pentagi.com
- 安装指南 https://github.com/vxcontrol/pentagi/blob/main/examples/guides/installation_configuration.md
- 本地模型指南 https://github.com/vxcontrol/pentagi/blob/main/examples/guides/vllm-qwen35-27b-fp8.md
- Discussion #217（官方对内部评估的回应）https://github.com/vxcontrol/pentagi/discussions/217
- EULA https://github.com/vxcontrol/pentagi/blob/main/EULA.md

**第三方实测**
- habr.com 对比 Strix（负面实测，含越界扫描）https://habr.com/ru/articles/1107742/
- karl.fail €250 实测 https://karl.fail/blog/i-spent-250e-on-ai-pentesting-agents-pentagi-strix-xalgorix/
- paolagarcia OWASP Juice Shop https://www.paolagarcia.com/blog/pentagi-owasp-juiceshop/
- medium 亲测 https://medium.com/@fa3n20004/i-tested-pentagi-heres-what-actually-happened-e83756580719
- franzramadhan Homelab 隔离方案 https://franzramadhan.dev/blog/45-homelab-rebuild-38-pentagi-pentest-vm/
- playciso 上手风险 https://playciso.com/blog/pentagi-autonomous-ai-penetration-testing-agent
- saas.pet 评测 https://saas.pet/reviews/pentagi-review/
- heatdrop 能力边界评价 https://heatdrop.ai/editorial/vxcontrol/pentagi/2026-10-14
