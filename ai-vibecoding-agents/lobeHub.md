# LobeHub — 首席 Agent 运营官 / 多 Agent 编排平台

> 学习笔记 · 调研时间 2026-08-13
> 仓库: https://github.com/lobehub/lobehub · 官网: https://lobehub.com · 文档: https://docs.lobehub.com
> License: **LobeHub Community License (Apache 2.0 + 附加条款)** · 语言: TypeScript (66M LOC 主体)
> ⭐ 81,641 · Fork 15,804 · Watch 303 · Issue 719 · Default branch: `canary`

## 一句话定位

把零散的 LLM Agent 当成"工作单元"统一纳管的产品平台 —— 招聘（Agent Builder）、排班（Schedule / Cron）、协作（Agent Group）、记忆（Personal Memory）、IM 网关（Feishu/微信/QQ/iMessage/Line），核心卖点是 **7×24 不需要你盯着**。

> 副标："Your Chief Agent Operator"。原型产品是早期 LobeChat（个人 Chat UI），2026 战略升级为"Agent Operator"。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **LobeHub Cloud（官方 SaaS）** | https://lobehub.com | 不自建，开箱即用，含 IM Gateway、企业版功能 |
| **Self-host（Docker / Vercel / 阿里云）** | `docker-compose/` 目录、`apps/desktop`、`apps/server` | 私有部署，数据不出域；Docker 一键起全栈 |
| **SDK / IM Adapter 二次开发** | `packages/sdk`、`packages/chat-adapter-feishu` 等 70+ 包 | 集成进自有产品，定制 Agent / 接入 IM 网关 |

## 核心组件 / 模块 / 架构

仓库是 monorepo（pnpm workspace），结构：

```
lobehub/lobehub (default branch: canary)
├── apps/                       # 三个独立可部署应用
│   ├── desktop/                # Electron 桌面客户端（Mac/Win/Linux）
│   ├── server/                 # 后端服务（Node + tRPC + 数据库）
│   └── cli/                    # 命令行工具
├── packages/                   # 70+ 内部包，按职能拆分
│   ├── agent-runtime/          # Agent 执行引擎（核心）
│   ├── agent-manager-runtime/  # Agent 管理（生命周期、调度）
│   ├── context-engine/         # 上下文工程（RAG / 知识库）
│   ├── conversation-flow/      # 多 Agent 会话流编排
│   ├── model-bank/             # 多模型供应商统一接口
│   ├── model-runtime/          # LLM 调用 + SSE 流式
│   ├── tool-runtime/           # 工具调用框架
│   ├── builtin-tool-*/         # 40+ 内置工具（web-browsing / memory / page-agent / claude-code ...）
│   ├── chat-adapter-feishu/    # 飞书 IM 适配器（@lobechat/chat-adapter-feishu v0.1.0）
│   ├── chat-adapter-wechat/    # 微信 IM 适配器
│   ├── chat-adapter-qq/        # QQ IM 适配器
│   ├── chat-adapter-imessage/  # iMessage（macOS-only）
│   ├── chat-adapter-line/      # Line 适配器
│   ├── sdk/                    # 公开 SDK（外部集成入口）
│   ├── heterogeneous-agents/   # 异构 Agent 协同
│   ├── memory-user-memory/     # 个人记忆（白盒、可编辑）
│   └── ssrf-safe-fetch/        # SSRF 防护 fetch（自研安全工具）
├── docker-compose/             # Docker 部署文件 + setup.sh
├── docs/                       # 文档（usage / self-hosting / development / wiki）
├── locales/                    # i18n（含 zh-CN）
└── plugins/                    # 第三方插件市场
```

**核心架构理念（来自 README）**：
- **Agents as the unit of work** —— Agent 不是工具，是"工作单元"
- **Operator / Create / Collaborate / Evolve** —— 四大支柱，对应"运营/创建/协作/进化"
- **White-Box Memory** —— 记忆是结构化、可编辑、可导出，反对黑盒
- **IM Gateway** —— Agent 部署到你已经在用的聊天软件（飞书 / 微信 / QQ / iMessage / Line）

## 安装与最小使用

### 1. Docker 自部署（最快路径）

```bash
git clone https://github.com/lobehub/lobehub.git
cd lobehub/docker-compose
bash setup.sh     # 生成 .env 配置
docker compose up -d
# 浏览器访问 http://localhost:3210
```

> 注：仓库 `default_branch` 是 `canary`（预览版），生产部署建议切到稳定 tag 如 `v2.2.13`。

### 2. 桌面端（apps/desktop）

```bash
# 自行 build，或从官网下载预编译包
# 内置 server，前端 + 后端 + LLM 调用全在一台机器
```

### 3. SDK / IM Adapter 集成

```bash
# 安装飞书 IM 适配器（已有公开包）
npm install @lobechat/chat-adapter-feishu
# 当前版本: 0.1.0（实验性，API 不稳定）
```

最小示例（构造飞书消息适配器）：

```ts
import { FeishuChatAdapter } from '@lobechat/chat-adapter-feishu';

const adapter = new FeishuChatAdapter({
  appId: process.env.FEISHU_APP_ID!,
  appSecret: process.env.FEISHU_APP_SECRET!,
  verificationToken: process.env.FEISHU_TOKEN!,
  encryptKey: process.env.FEISHU_ENCRYPT_KEY!,
});

// 在 server 端注册到 LobeHub agent-runtime
await adapter.start();
```

> ⚠️ 飞书 adapter 是 **私有 npm 包（@lobechat/ 命名空间，非公开 registry）**，自部署才能用；Cloud 版由官方托管。

## 版本节奏 / Release 历史

| 版本 | 日期 | 状态 |
|---|---|---|
| **v2.2.13**（latest stable） | 2026-08-01 | 正式 |
| v2.2.14-canary.84 | 2026-08-13 | canary |
| v2.2.14-canary.83 ~ .78 | 2026-08-12 ~ 08-13 | canary（高频） |
| v0.0.0-nightly.prXXXXX | 每天 10+ 个 | PR Build 预览 |

**节奏特征**：
- 稳定版约 **每 2 周一次**（v2.2.13 是最新）
- canary 几乎每天 5+ 个
- PR Build（Nightly）按 PR 触发，每个 PR 都出独立预览版
- default_branch = `canary`（生产 clone 需指定 tag）

## 跟我们的关系

LobeHub 的几个组件跟现有 Hermes / Feishu 体系有直接复用空间：

| 复用点 | 价值 |
|---|---|
| **`@lobechat/chat-adapter-feishu`** | 飞书消息 → Agent 编排已有现成 adapter，可对照自研 chat-adapter 看实现差异（事件签名校验、消息加密、长连接管理） |
| **`context-engine` + `memory-user-memory`** | 白盒记忆实现思路（结构化、可编辑、导出）正是 Hermes `chromamem` 演进方向 |
| **`ssrf-safe-fetch`** | 自研 SSRF 防护工具，正好是用户敏感"自建方案网络合规"那块缺的工具 |
| **`apps/cli`** | 命令行 Agent 编排客户端，可参考其 CLI 模式补齐 Hermes 在 cronjob / watcher 之外的人机交互通道 |
| **`builtin-tool-claude-code` / `builtin-tool-browser`** | "Agent 内嵌 CLI / 浏览器"模式，可对照自研 delegate_task 是否值得做类似封装 |

**注意 —— 不适合直接接的东西**：
- LobeHub Cloud（SaaS）数据走 LobeHub LLC，国内合规风险不可忽略
- IM 适配器（飞书 / 微信）官方版与国内 IM 平台 ToS 有微妙冲突，**自部署 + 自定义 adapter 更稳**
- Electron 桌面端封装了 server + LLM，运行模型大；本地 Mac 跑要算电费和内存账

## 风险点 / 合规

### License 风险（**最关键**）

| 项 | 内容 |
|---|---|
| 协议 | **LobeHub Community License（Apache 2.0 + 附加条款）** |
| 商业可用 | ✅ 可商用，作为前端/后端服务 + **不修改源码** |
| 修改源码商用 | ❌ 需联系 `hello@lobehub.com` 取商业授权 |
| 贡献者条款 | ⚠️ 贡献代码可被用于商业用途（含其云版本） |
| 衍生作品分发 | ⚠️ 同上，需商业授权 |

→ **自部署私有使用 OK**；**Fork 改源码再分发不 OK**；**接入生产 SaaS 服务自家用户 → 商业授权必谈**。

### 其它

- 仓库 `default_branch = canary`，clone 默认拉预览版，CI/生产务必切 tag
- IM 适配器当前 0.1.x 阶段，**API 不稳定**，不要绑定死版本
- 桌面端（Electron）拉起 LLM 对硬件要求高（>= 16GB RAM 推荐）
- canary 每天 5+ 个 release，**issue 增长也快**（719 open），小版本 bug 风险存在

## 参考链接

- 仓库：https://github.com/lobehub/lobehub
- 官网：https://lobehub.com
- 文档站：https://docs.lobehub.com
- 更新日志：https://github.com/lobehub/lobehub/tree/canary/changelog
- 博客：https://lobehub.com/blog
- Docker 部署：https://github.com/lobehub/lobehub/tree/canary/docker-compose
- License 全文：https://github.com/lobehub/lobehub/blob/canary/LICENSE
- 飞书 adapter 包：`@lobechat/chat-adapter-feishu`（私有 registry，自部署后可装）
- 协议原始讨论（Apache 2.0 基础）：http://www.apache.org/licenses/LICENSE-2.0

---

调研来源：https://github.com/lobehub/lobehub (2026-08-13) · README + GitHub API + LICENSE 全文