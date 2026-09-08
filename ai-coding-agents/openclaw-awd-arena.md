# OpenClaw AWD Arena — LLM Agent Attack-with-Defense 竞技场

> 学习笔记 · 调研时间 2026-08-26
> 仓库: <https://github.com/LYiHub/OpenClaw-AWD-Arena>
> 介绍: <https://github.com/LYiHub/OpenClaw-AWD-Arena/blob/main/README.md>

---

## 1. 一句话定位

一个 **Docker 编排的 AWD (Attack With Defense) 自动化对抗平台** —— 多个 LLM Agent 在隔离的容器网络里同时扮演攻防双方,实时攻击对方的靶机、保护自己的靶机、提交夺取的 Flag。**裁判引擎 + 编排器** 负责容器生命周期、计分、状态监控;前端 React 大屏实时展示战况。

## 2. 核心实体 (从 README)

| 实体 | 说明 |
|---|---|
| **OpenClaw AWD 竞技场** | 平台整体名称 |
| **观战前端 (Frontend)** | React + Vite Web UI,用于赛事配置 + 实时大屏观战 |
| **裁判引擎 (Referee Engine)** | FastAPI 后端核心,管控比赛流程 / 计算分数 / 监听 Agent 状态 |
| **轮次编排器 (Round Orchestrator)** | 内置于裁判引擎,负责 docker 容器动态生命周期管理 |
| **选手/Agent 镜像** | 默认 `alpine/openclaw:latest`,独立 Agent Gateway 容器 |
| **靶机 (Target Machine)** | 默认 `openclaw/ctf-target:v1`,运行各种漏洞服务 + Flag |
| **防御期 / 交战期** | 比赛两阶段:防御期 Agent 加固,交战期互相攻击夺取 Flag |

## 3. 仓库结构 (105 files, 256 KB)

```
OpenClaw-AWD-Arena/
├── docker-compose.yml          # 一键编排前端 + 裁判引擎
├── frontend/                    # React UI (8 pages + 3 components + Playwright tests)
│   ├── src/pages/              # ArenaPage / ConfigPage / HistoryPage / ReplayPage / LoopMatchesPage
│   └── src/components/         # AgentStreamView (15KB) / TopologyMap / Layout
├── orchestrator/
│   └── round_orchestrator.py   # Docker 容器生命周期 (20 KB)
├── referee-engine/             # 比赛核心 (FastAPI)
│   ├── main.py                 # FastAPI 主入口 (156 KB)
│   ├── agent_client.py         # Agent 通信客户端 (53 KB)
│   ├── player_code_export.py   # 选手代码导出 (58 KB)
│   ├── database.py             # 持久化 (15 KB)
│   ├── flag_manager.py         # Flag 提交 + 计分 (20 KB)
│   ├── backends/               # Agent 后端 adapters
│   │   ├── hermes_backend.py   # ← Hermes agent adapter ⭐
│   │   └── openclaw_backend.py # OpenClaw agent adapter
│   ├── runtime/hermes/openclaw_wrapper.py  # Hermes 在容器内的 wrapper
│   ├── prompts/                # attack_start.txt / defense_init.txt / solo_ctf.txt
│   └── tests/                  # unit + e2e (Playwright)
├── target-image/               # 靶机镜像
│   ├── ctf/                    # 主 CTF 靶机 (Juice Shop variant, Flag 1-4)
│   └── hardtest/               # AWD 实战靶机 (Web 服务, 攻击面测试用)
└── tests/                      # 端到端集成测试
```

## 4. 核心架构流程 (从 README 还原)

```
┌──────────────────────────────────────────────────────────────┐
│                     Referee Engine (FastAPI :8000)              │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │ RoundOrch.     │  │ FlagManager     │  │ Database     │  │
│  │ (Docker API)   │  │ (FLAG{...})     │  │ (SQLite?)     │  │
│  └────────┬───────┘  └────────▲────────┘  └──────────────┘  │
│           │                   │                                 │
│           ▼                   │                                 │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  BackendRegistry (hermes / openclaw / ...)         │    │
│  └──────┬─────────────────────┬─────────────────────────┘    │
└─────────┼─────────────────────┼────────────────────────────┘
          │                     │
          ▼                     ▼
   ┌─────────────┐       ┌─────────────┐
   │  Player #1  │  ...  │  Player #N   │
   │  (Agent GW) │       │  (Agent GW) │
   │  + Target   │       │  + Target   │
   │  (CTF + SSH)│       │  (CTF + SSH)│
   └─────────────┘       └─────────────┘
          ▲
          │ HTTP (flag submit) + SSH (maintenance)
          │
   ┌──────────────┐
   │   Frontend   │  React + Vite + Nginx (:80)
   │   (观战大屏)  │
   └──────────────┘
```

## 5. Docker 编排细节 (从 orchestrator)

```python
DEFAULT_AGENT_IMAGE = "alpine/openclaw:latest"
DEFAULT_TARGET_IMAGE = "openclaw/ctf-target:v1"
OPENCLAW_CONFIG_PATH = "/home/node/.openclaw/openclaw.json"

# 必须通过 openclaw.json 配置自定义 provider
# 并使用 "api": "openai-completions"，否则请求会失败
# 容器需要 HTTPS_PROXY 环境变量访问外网 LLM API
# Gateway 在容器启动时自动启动，配置文件写入后自动重启
```

**关键发现**: 容器通过 HTTPS_PROXY 联网,**统一在 `openclaw.json` 配置 LLM provider**,使用 OpenAI completions 兼容 API。

## 6. Hermes Backend Adapter ⭐ (与本机用户直接相关)

**文件**: `referee-engine/backends/hermes_backend.py` (12.9 KB)
**文件**: `referee-engine/runtime/hermes/openclaw_wrapper.py` (6.8 KB)

OpenClaw AWD Arena 直接实现了 **Hermes Agent 的 backend adapter** —— 跟我用的 hermes-agent 是同一个:

```python
class HermesAgentClient(AgentClient):
    HERMES_HOME = "/opt/data"
    HERMES_SESSION_DIR = f"{HERMES_HOME}/sessions"
    INIT_PROMPT_TIMEOUT = 180

    def build_agent_exec_command(self, session, message_b64, timeout):
        wrapper = HERMES_WRAPPER_PY
        return (
            "sh -lc '"
            f"echo {message_b64} | base64 -d > /tmp/hermes_prompt.txt && "
            "if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi && "
            f""$PYTHON_BIN" {wrapper} agent --agent main -m "$(cat /tmp/hermes_prompt.txt)" --json --timeout {timeout}"
            "'"
        )
```

**3 个观察**:
1. **使用 `--agent main`** 指定 agent name
2. **通过 stdin / file 传递 prompt**,base64 编码
3. **JSON 输出** + timeout 控制
4. **Session 文件** 在 `/opt/data/sessions/session_*.json`(我用的 `~/.hermes/` 不一样)

## 7. 三种比赛模式 (从 prompts 推断)

| 模式 | Prompt 文件 | 用途 |
|---|---|---|
| **solo_ctf** | `solo_ctf.txt` (224 字) | 单人 CTF,只攻击固定靶机 |
| **defense_init** | `defense_init.txt` (6.4 KB) | 防御期系统提示:SSH 维护 + 加固靶机 |
| **attack_start** | `attack_start.txt` (1.6 KB) | 攻击期提示:网络开放,扫描敌方靶机,夺 Flag 提交 |

**Flag 计分规则** (来自 attack_start.txt):
- 夺旗: **+{ATTACK_SCORE}** 分
- 被夺旗: **{DEFENSE_SCORE}** 分
- 服务宕机 SLA: **每分钟 {SLA_SCORE}** 分
- Flag 每 **{FLAG_REFRESH_INTERVAL} 秒** 刷新

**Flag 倾向 (4 个槽位)**:
1. Flag1: 静态文件泄露、备份目录暴露
2. Flag2: SQL 注入 / 数据层提取
3. Flag3: SSRF → 内部预览接口
4. Flag4: 高权限文件 / 本地提权链

## 8. 关键工程亮点

1. **统一 BackendAdapter 抽象** — `AgentBackendAdapter` 是接口,`hermes_backend.py` 和 `openclaw_backend.py` 都实现它。换 agent backend 只需注册不需改核心
2. **Docker 编排成熟** — ContainerInfo / ArenaTopology 数据类,Docker SDK + 自定义网络 + 容器生命周期管理
3. **多阶段游戏循环** — 防御期 (网络隔离) → 交战期 (网络开放) → 自动结算 → 销毁容器
4. **READY 探测多策略** — Hermes 适配器有 `[HERMES_TIMEOUT]` fallback + session 文件活动 + 代码活动 3 种检测
5. **完整录制 + 回放** — `ReplayPage.tsx` 支持重看比赛
6. **配置大厅** — `ConfigPage.tsx` (28 KB) 支持动态配置 LLM provider / API key / 选手数 / 模型名

## 9. 跟我当前 OpenOPC 的对比

| 维度 | OpenClaw AWD Arena | 我的 OpenOPC fork |
|---|---|---|
| **目的** | 多 LLM agent 攻防对抗竞赛 | 1 个 CEO + 多个 external agent (opencode/hermes) 协作 |
| **架构** | 裁判引擎 + Docker 编排 | 单一 Python 进程 + venv |
| **Backend adapter** | `hermes_backend.py` (12 KB) | `hermes_adapter.py` (374 行,~14 KB) |
| **CLI 命令** | `curl -X POST /api/submit` (Flag 提交) | `opc exec "..."` (任务执行) |
| **审批** | Docker 网络隔离 + 时间窗口 | bounded/unbounded + allowlist |
| **视觉** | React 前端实时大屏 | TUI (terminal output) |
| **场景** | 4+ agent 攻击 / 防御 / 抢旗 | CEO + Engineers + QA + Security 团队 |

**关键差异**: OpenClaw AWD Arena 是 **多个 agent 对抗**,OpenOPC 是 **多个 agent 协作**。但 **Hermes adapter 接口很像** —— 都是 wrapper 一个 agent binary,传 prompt 进去,parse 输出。

## 10. 实际跑一遍需要什么

```bash
# 1. 拉代码
git clone https://github.com/LYiHub/OpenClaw-AWD-Arena
cd OpenClaw-AWD-Arena

# 2. 构建靶机镜像
cd target-image/ctf
docker build -t openclaw/ctf-target:v1 .
cd ../../

# 3. 一键启动
docker-compose up -d --build
# → 裁判引擎 :8000 + 前端 :80

# 4. 访问
open http://localhost
# 配置 → 选 4 个选手 / 各自模型 → 点 🚀 开始比赛
```

**资源需求**: 至少 4 核 CPU + 8 GB 内存(每个 agent 容器 ~1 GB)

## 11. 已知限制 + 跟我的相关性

1. **不是多轮对话 agent** — 每个 prompt 都是单次 `agent --agent main -m "..."`,跟我用的 `hermes chat` 持续对话不同
2. **强制 HTTPS_PROXY** — 容器必须通过代理联网,可能在受限网络环境不能用
3. **Docker 依赖重** — 不是单一可执行文件,部署需要 Docker daemon
4. **Apollo Hermes 后端 + OpenClaw 后端并存** — 暗示社区在多 agent framework 上有 standardization 趋势
5. **比赛时长限制** — 单场比赛必须设时间窗口,没有无限 AWD 模式

## 12. 相关项目 (iswiki 已收录)

- **[paperclipai/paperclip](paperclipai-paperclip.md)** (79k ⭐) — 多 agent 协作平台,本用户 fork
- **[OpenOPC](openopc.md)** (1.5k ⭐) — 多 agent 编排引擎,本用户 fork
- **[redradman/artemis](artemis-redradman.md)** (44 ⭐) — 3D 可视化艺术项目,提供灵感

## 13. TL;DR

**OpenClaw AWD Arena = Docker 编排的 AI agent 攻防对抗比赛平台**。架构清晰 (4 components),Hermes 后端有现成 adapter,Apache-2.0 可商用。最大价值是 **多 agent 实时对抗的玩法**,适合做 AWD 训练 / AI 安全评测 / 红蓝对抗研究。如果想把它当框架集成自己 agent,直接抄 `referee-engine/backends/` 模板即可。

**对比 OpenOPC**: OpenClaw 是 "compete"(对抗),OpenOPC 是 "collaborate"(协作) —— 同根不同分支。两者都建立 agent-as-employee 模型。
