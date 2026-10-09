# OpenViking — 火山引擎的 Agent 上下文数据库(viking:// 虚拟文件系统 + 三层渐进加载)

> 学习笔记 · 调研时间 2026-10-09
> 仓库: <https://github.com/volcengine/OpenViking> · 官网: <https://openviking.ai> · 文档: <https://docs.openviking.ai>
> License: **AGPL-3.0**(主仓;CLI/exexamples 为 Apache 2.0,**Hermes 插件保留 MIT**)
> 语言: Python + Rust · ⭐ 39,514 · 3,120 forks · 868 open issues
> 版本: v0.5.0(2026-10-09,调研当天刚发) · 建仓 2026-01-05 · 最后 push 2026-10-09

---

## 一句话定位

**把 Agent 的知识、记忆、技能统一塞进一个 `viking://` 虚拟文件系统**,让 Agent 像操作目录一样 `ls / tree / read / grep`,而不是面对一个看不见的向量池。

**它的核心主张:Agent 记忆不该是黑盒。** 文本进去、embedding 出来,你没法知道到底存了什么;OpenViking 把每一条记忆变成你能打开、能编辑、能合并的 Markdown 文件。

---

## 三层渐进加载(这是它省 token 的核心机制)

| 层 | 名称 | 内容 | 何时读 |
|---|---|---|---|
| **L0** | Abstract | 一句话摘要 | 快速判断相关性 |
| **L1** | Overview | 核心信息 + 使用场景 | 规划下一步 |
| **L2** | Details | 完整原始数据 | 确认需要时才读 |

目录树里的实际形态:

```
viking://resources/my_project/
├── .abstract.md           # L0:快速相关性检查
├── .overview.md           # L1:结构与要点
└── docs/
    ├── .abstract.md
    ├── .overview.md
    └── api/
        ├── auth.md         # L2:完整内容,按需加载
        └── endpoints.md
```

**这是它相对普通向量库的核心差异**:Agent 先扫摘要,判断值不值得展开,而不是每次都把整库塞进上下文。

---

## 三种上下文类型(统一在一个 URI 空间)

```
viking://
├── resources/              # 项目文档、代码仓、网页
│   └── my_project/{docs/,src/}
└── user/{user_id}/
    ├── memories/
    │   └── preferences/{writing_style, coding_habits}
    ├── resources/private_project/
    ├── skills/{search_code, analyze_data}
    └── peers/web-visitor-alice/
```

| 类型 | 装什么 |
|---|---|
| **resources** | 项目文档、仓库、网页——"世界是什么样" |
| **memories** | 用户偏好、任务经验——"你是谁 / 做过什么" |
| **skills** | 怎么干活——不只是抽出来的 fact,是完整可复用上下文 |

三者各有 `viking://` URI,可浏览可检索,**统一在同一个目录树里**。

---

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **托管服务** | Volcengine 托管,`api.vikingdb.cn-beijing.volces.com/openviking`,前 50 文件免费 | 快速试用,不想自己装 |
| **自托管 server** | `uv tool install openviking && openviking-server init` | 生产、私有化;支持多租户 + 资源 ACL |
| **CLI / SDK** | `ov` CLI + Python / Go / TypeScript SDK + HTTP API | 脚本化、CI、集成进自有 agent |

**检索的两种方式**(概念页明确区分):
- `find` — 在**指定 URI 作用域内**直接跑查询
- `search` — 从会话上下文出发规划检索

**`find` 的意义**:搜一个项目子树,而不是扫整个扁平向量池。背后的正式理论见 ICDE 论文的 **TrieHI** 索引(见「研究」段)。

---

## 核心架构(实读 docs/en/concepts/)

```
CLI / SDK / HTTP client
          ↓
      HTTP Server
          ↓
      Service Layer          ← FSService / SearchService / SessionService
          ↓                        ResourceService / PackService / DebugService
   Retrieval / Sessions / Resource-Skill import
          ↓
      VikingFS
     ↙         ↘
  AGFS        Vector index    ← 内容与索引分离
```

| 模块 | 职责 |
|---|---|
| **FSService** | ls / mkdir / rm / mv / tree / stat / read / **abstract** / **overview** / grep / glob |
| **SearchService** | search / find |
| **SessionService** | session / sessions / commit / delete |
| **ResourceService** | add_resource / add_skill / wait_processed |
| **PackService** | ovpack 导入导出 + 备份恢复 |
| **Retrieve** | IntentAnalyzer → HierarchicalRetriever → Rerank |
| **Memory** | ExtractLoop 按 MemoryType schema 抽取 → MemoryUpdater 以 patch 合并去重回写 |

**会话提交链路**:消息 → 归档边界 → 生成 L0/L1 → 按 MemoryType schema 抽记忆 → 写回 RAGFS/AGFS + 向量索引。

**记忆是 Markdown 文件**,可检查、可编辑、可合并——这是与传统记忆库最大的区别。

---

## 最小可运行示例

```bash
# 1) 自托管 server(需要 uv + Python 3.10+ + 一个带 embedding 和 VLM 的模型供应商)
uv tool install openviking --upgrade && openviking-server init
# init 写 ~/.openviking/ov.conf,支持 Volcengine / OpenAI / Codex OAuth / Kimi / GLM / 本地 Ollama
openviking-server          # 前台运行,保持这个终端开着

# 2) CLI 探索
ov status
ov add-resource https://github.com/volcengine/OpenViking
ov task status TASK_ID              # 换返回的 task_id,直到 status 是 completed
ov ls viking://resources/
ov tree viking://resources/volcengine -L 2
ov find "what is openviking"
ov grep "openviking" --uri viking://resources/volcengine/OpenViking/docs/en

# 3) 接入 agent(官方安装器)
curl -fsSL https://openviking.ai/install | bash
# 会问:自托管本地 / Volcengine Cloud / 自定义 URL;开认证要用 user key(不是 root key)
# 装完重启 agent。Claude Code 验证:会话里跑 /openviking-memory:ov
```

**VikingBot**(建在 OpenViking 上的 agent 框架):

```bash
pip install "openviking[bot]"
openviking-server --with-bot
ov chat
```

---

## 接入的 Agent 工具(12 个,含 Hermes)

| 工具 | 集成方式 |
|---|---|
| Claude / Codex / Cursor / TRAE | Hooks + MCP |
| **Hermes** | **Built-in** |
| OpenClaw | Context engine |
| OpenCode / DeerFlow / DSH / Doubao Work | Plugin + MCP / Connector |
| pi | Native extension |
| LangChain / LangGraph | Tools + store |
| 通用 | Agent Plugins 1.0 / MCP clients |

**`github.com/NousResearch/hermes-agent` 被列在 Partner Projects 里**,这是唯一一个被官方点名"Built-in"的集成。

---

## 🎯 与我们的关系:Hermes 已内置集成

**这条直接关系到用户自己的系统** —— 用户的 Hermes Agent 跑着飞书 gateway、有三个 gateway 实例(记忆里记着 curator + stock launchd 守护 / coder foreground)。OpenViking 的 Hermes 集成路径:

```bash
# 在目标 Hermes profile 里执行
hermes plugins install openviking --enable
hermes memory setup openviking
hermes
# 安装时接受依赖提示;setup 里选使用模式 + 选连接方式
```

**两种记忆模式**(插件 README 原文):

| 模式 | 行为 |
|---|---|
| **Personal Agent** | 召回公共记忆 + **当前发送者**的记忆(Telegram/Discord 等平台的 sender 绑定);不改动现有会话历史设置 |
| **Shared Agent** | 群/话题内共享会话历史,召回同一 OpenViking user 下**所有发送者**的记忆;改历史设置前会先确认 |

**插件许可证是 MIT**(`examples/hermes-plugin/LICENSE`,Copyright 2025 Nous Research)——这是 AGPL 主仓里一个明确的宽松例外。

**三个跟用户现状直接相关的注意点:**

1. **peer 命名规则变了**(v0.5.0 unreleased):现在从 **git origin URL** 推导 workspace peer(`github.com-volcengine-openviking` 这种),不再用工作目录。好处是同一 repo 的 clone / worktree / 子目录共享一个 peer,fork 各自独立。**非 git 目录不再有 peer**,记忆会落到 user 级空间。要恢复旧行为设 `peer.source: "cwd"` 或 `OPENVIKING_PEER_SOURCE=cwd`。
   → 用户有三个 Hermes gateway 实例 + 多个项目目录,**这条规则直接决定记忆归到哪个命名空间**,升级前要确认。
2. **Working Memory 默认关闭**(v0.5.0 行为变更):commit 仍归档原始消息并抽长期记忆,但**不再默认生成 WM/checkpoint 摘要**。老配置里没写 `WM=true` 的,即使曾经显式选过 true,现在也会变成 false。可用 per-commit 的 `enable_working_memory` 布尔单独开。
3. **Hermes 官方支持 OpenClaw / Codex / Claude Code 的对比基准** —— 见下方 benchmark。

---

## Benchmark(README 声称,v0.3.22 测的)

| Agent | 原生记忆 LoCoMo 准确率 | 接 OpenViking |
|---|---|---|
| OpenClaw | 24.20% | **82.08%** |
| **Hermes** | **33.38%** | **82.86%** |
| Claude Code | 57.21% | **80.32%** |

- **input token 下降 34.3–91.0%**,query 延迟下降 58.45–66.10%
- **tau2-bench**(agent 经验记忆):任务成功率零售 +6.87pp、航空 +11.87pp
- 测试模型:**豆包 2.0 Pro**(VLM)+ Doubao-embedding-vision-251215(embedding)
- 复现脚本在 `./benchmark`

**怎么看这个数字**:三家原生记忆差距巨大(24%–57%),说明"agent 记忆"目前没有及格线,谁接了都涨。**但测试用的是自家豆包模型**,换模型结果可能不同——这是火山自家 benchmark,不是第三方复现,引用时要说清口径。

---

## 实战建议 / 风险点

| 风险 | 说明 | 缓解 |
|---|---|---|
| ⚠️ **AGPL-3.0** | 主仓 AGPLv3,网络服务场景有传染性 | 自建内部服务通常无碍;**对外提供网络服务必须开源修改**。实在介意可只参考设计,或只用 examples/CLI(Apache 2.0)与 Hermes 插件(MIT) |
| ⚠️ **v0.5.0 破坏性变更** | peer 命名规则变更、WM 默认关闭、pi 工具改名、Watch API 迁移 | 升级前必读 Unreleased changelog,`ovpack` 先备份 |
| **降级不可逆** | 05-storage.md 明写:新记录格式老版本读不了,降级需恢复**写入前**的备份 | 换版本前先 `backup_ovpack` |
| **需要模型供应商** | 抽取记忆/生成 L0L1 都要 VLM + embedding | 本地 Ollama 可跑,但效果与成本另算 |
| **868 open issues** | 迭代极快(v0.5.0 当天发) | 锁版本,别追 latest |
| **国内生态友好** | 火山出品,飞书/微信/Discord 社区、BytePlus 出海计划 | 对用户在国内部署是加分项 |
| **托管版有配额** | 前 50 文件免费,之后按套餐 | 严肃用建议自托管 |

---

## 版本节奏

| 版本 | 日期 |
|---|---|
| **v0.5.0** | **2026-10-09**(调研当天) |
| v0.4.23 | 2026-10-02 |
| v0.4.22 | 2026-09-28 |
| v0.4.21 | 2026-09-20 |
| v0.4.20 | 2026-09-14 |
| v0.4.19 | 2026-09-08 |

多仓同步发版:`python-sdk@0.1.14`、`cli@0.4.23`、`sdk/go/v0.0.5`(2026-10-02)—— **Go SDK 还在 0.0.x,别上生产**。

**后端配置**(`storage.agfs.backend` / `storage.vectordb.backend`):
- 内容层:`local` / `memory` / `s3`
- 向量层:`local` / **`cuvs`** / `http` / `volcengine` / `vikingdb`

---

## 配套生态

- **OpenViking Studio** — 网页版直接试玩(<https://openviking.ai/studio>),也能自建
- **Desktop App(beta)** — macOS arm64/x64 + Windows x64,配置本地 agent 集成、检视 recall/capture 事件
- **VikingBot** — 建在其上的 agent 框架,官方 Docker 镜像默认启动
- **Railway 一键部署** — <https://railway.com/deploy/openviking>
- **社区** — 飞书群 / 微信群 / Discord / X(@openvikingai);13 语言的 README(en/中文/日本語)

---

## 研究(两篇已发表 + 一篇投稿,值得看)

| 论文 | 会议 | 与 OpenViking 的关系 |
|---|---|---|
| **VikingMem** — A Memory Base Management System for Stateful LLM-based Applications(arXiv:2605.29640) | **VLDB 2026** | 事件驱动的长期记忆抽取/更新/合并;OpenViking 开源了其中一部分 |
| **Directory-Aware Query and Maintenance in Vector Databases**(arXiv:2606.16903) | **ICDE 已录** | 给"目录结构即检索上下文"提供形式化基础,提出 **TrieHI** 索引,OpenViking 已集成 |
| VikingRAG(arXiv:2609.11390) | 投稿中 | 结构化文档上的 token 高效检索,机制已并入 |

**VikingMem 的作者里有 Maojia Sheng、Yifan Zhu 等,和 OpenViking 贡献者名单(qin-ctx / ZaynJarvis / t0saki / r266-tech / MaojiaSheng)高度重合** —— 是字节的研究团队 + 工程团队联合产出。

---

## 参考链接

- 仓库: <https://github.com/volcengine/OpenViking>
- 官网: <https://openviking.ai> · Studio: <https://openviking.ai/studio>
- 文档: <https://docs.openviking.ai>
- 中文文档: <https://github.com/volcengine/OpenViking/tree/main/docs/zh>
- Benchmark 报告: <https://blog.openviking.ai/post/openviking-benchmark-results/>
- 设计理念博客: <https://blog.openviking.ai/post/openviking-context-database/>
- Hermes 集成文档: <https://docs.openviking.ai/en/agent-integrations/05-hermes>
- Hermes 插件源码: <https://github.com/volcengine/OpenViking/tree/main/examples/hermes-plugin>
- 架构概念: <https://github.com/volcengine/OpenViking/tree/main/docs/en/concepts>
- Changelog(升级必读): <https://github.com/volcengine/OpenViking/blob/main/docs/en/about/02-changelog.md>
- 火山托管版: <https://www.volcengine.com/product/openviking-service>
- VLDB 2026 论文: <https://arxiv.org/abs/2605.29640>
- ICDE 论文: <https://arxiv.org/abs/2606.16903>