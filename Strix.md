# Strix — 开源 AI 渗透测试工具

> 学习笔记 · 调研时间 2026-08-07
> 仓库: https://github.com/usestrix/strix · 官网: https://strix.ai · 文档: https://docs.strix.ai
> License: Apache 2.0 · 语言: Python 3.12+ · ⭐ 49.4k

## 一句话定位
**自主 AI 渗透测试 Agent 集群**——像真人黑客一样动态执行代码、挖漏洞、用 PoC 验证，号称"不是又一份静态扫描器"。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| OSS CLI（自托管） | `strix -t ./code-or-url` | 本地开发循环、离线/隔离环境、要自定义模型 |
| Cloud API（托管） | `https://app.strix.ai/api/v1/scans` | 没有 Docker/LLM key、要团队 dashboard、要 PDF 报告 |
| Agent Skill | `npx skills add usestrix/strix` | 让 Claude Code / Cursor / Codex 直接跑渗透 |

两种跑法底层同一个引擎，输出同一种 SARIF 2.1.0，可以混用。

## 4 个 Agent Skills（`npx skills add usestrix/strix`）
- **strix-pentest** — 无头跑扫描 + 读结果（CLI/Cloud 两边都能用）
- **strix-cloud-api** — REST 调 app.strix.ai（不要本地 Docker/LLM）
- **strix-fix-findings** — 修复漏洞 + 重扫验证
- **strix-ci-setup** — 接 CI/CD 跑 PR 扫描

## 多 Agent 编排（Graph of Agents）
不是单一 LLM 循环，而是 **specialized agent 团队**：recon / exploitation / post-exploitation 各自一个，并行跑、共享发现、链式攻击（一个漏洞触发另一个）。

代码组织：
- `strix/agents/factory.py` — agent graph 工厂
- `strix/agents/prompts/` — 多套 prompt 模板

## 内置渗透工具箱（`strix/tools/`）

| 工具 | 作用 |
|---|---|
| `proxy/caido_api.py` | **Caido** HTTP 拦截代理（请求/响应改写） |
| `agent_browser/` | 自动化浏览器（XSS / CSRF / clickjacking / auth bypass） |
| `shell/` | 交互终端（exploit 开发、后渗透） |
| `apply_patch/` | 写 PoC + 补丁 |
| `load_skill/` | 动态加载技能包 |
| `web_search/` | OSINT / 漏洞情报搜索 |
| `thinking/` + `todo/` | 推理 + 任务分解 |
| `notes/` | 持久化笔记（跨 agent 共享上下文） |
| `report/` + `reporting/` | 报告生成 + 落盘 |

## 覆盖的漏洞类型（OWASP Top 10 + 更多）

- **访问控制**：IDOR、越权、auth bypass
- **注入**：SQLi / NoSQLi / OS 命令注入 / SSTI
- **服务端**：SSRF / XXE / 不安全反序列化 / RCE
- **客户端**：XSS（stored / reflected / DOM）/ 原型链污染 / CSRF
- **业务逻辑**：竞态条件、支付绕过、工作流绕过
- **认证 / 会话**：JWT 攻击、session fixation、credential stuffing
- **基础设施 / 云**：错配配置、暴露服务、云安全
- **API**：认证缺陷、mass assignment、限流绕过

## 安装与最小使用

### 前置
- Docker（必须 running，首次跑自动拉沙箱镜像）
- 一个 LLM key（OpenAI / Anthropic / Google / 本地 LiteLLM 都行）

### 三条命令跑起来
```bash
curl -sSL https://strix.ai/install | bash     # 装 CLI
export STRIX_LLM="openai/gpt-5.4"             # 任何 LiteLLM 模型 ID
export LLM_API_KEY="***"                    # 你的 key
strix -n -t ./your-app --max-budget 10        # 无头扫本地代码
```

### 推荐模型
- `openai/gpt-5.4`
- `anthropic/claude-sonnet-4-6`
- `vertex_ai/gemini-3-pro-preview`
- 也支持 ChatGPT Plus / Pro 订阅（`chatgpt/gpt-5.4` + `strix auth login chatgpt`）

## 扫描模式 & 时间预算

| 模式 | 耗时 | 用途 |
|---|---|---|
| `quick` | 分钟级 | PR diff scope、CI gate |
| `standard` | ~30 分钟 | 日常扫描 |
| `deep`（默认） | 小时级 | 深度评估 |

**关键 flag**：
- `-n / --non-interactive` — 默认 TUI 会阻塞；Agent 调用必须加
- `--max-budget USD` — 硬性 LLM 花费上限
- `--max-turns N` — 每个 agent 轮次上限（默认 500）
- `--mount` — 大 monorepo 用 bind-mount 而不是 copy
- `--instruction` — 传凭据 / 范围 / 重点（例：`"用 user:pass 测 IDOR"`）

## 输出（落到 `strix_runs/<run-name>/`）

| 文件 | 用途 |
|---|---|
| `penetration_test_report.md` | 高管能看的总报告，**先读这个** |
| `vulnerabilities/*.md` | 每个漏洞一个文件，含 PoC + 修复建议 |
| `vulnerabilities.json` / `.csv` | 结构化索引 |
| `findings.sarif` | **SARIF 2.1.0**，对接 GitHub Code Scanning / ASPM |
| `run.json` | 运行元数据 + LLM 花费 |

## CI/CD 集成（GitHub Actions 例子）

```yaml
- uses: actions/checkout@v6
  with: { fetch-depth: 0 }
- run: curl -sSL https://strix.ai/install | bash
- env:
    STRIX_LLM: ${{ secrets.STRIX_LLM }}
    LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
  run: strix -n -t ./ --scan-mode quick
```

- PR 模式自动 `--scope-mode diff --diff-base origin/main`（只看变更文件）
- checkout 必须 `fetch-depth: 0` 否则 diff 解析失败

## 本地 Web Dashboard（`strix view`）
每次扫描完开浏览器查看：
- **Overview** — 严重度分布
- **Vulnerabilities** — 每条带 PoC 复现步骤
- **Agent graph** — 实时看哪个 agent 在干嘛
- **Steering** — 扫描中途通过浏览器给 agent 下指令改向
- **History / Reports**

`127.0.0.1` + tokenized link，纯本地，不上传。

## 退出码（headless 模式）
- `0` — 没发现漏洞（**但只看扫描到的部分，不等于全面安全**）
- `1` — fatal error（缺环境变量 / Docker 没起）
- `2` — 有漏洞
- ⚠️ `0` 不代表扫完：预算或 turn 上限到了也会 `0`，要核对 `run.json` 的 `status` 和 `llm_usage.cost`

## 代码贡献结构

```
strix/
├── agents/        # agent graph + prompts
├── tools/         # proxy, browser, terminal, scanners
├── runtime/       # Docker 沙箱
├── report/        # findings + SARIF
├── skills/        # 内部知识包（跟消费者 skills/ 不同）
├── interface/     # CLI + TUI
├── llm/           # compaction + context budget
└── telemetry/
containers/        # 沙箱镜像
skills/            # 4 个 consumer skills
```

开发命令：`make dev-install` / `make check-all`（ruff + mypy + bandit）/ `make pre-commit`

## 跟我们（WAF/SecOps）的关系

- **互补关系**：Strix 是"主动找漏洞"，WAF（safeline-waf skill）是"被动拦攻击"。两者结合 = **shift-left + shift-right**。
- **Agent 视角**：4 个 consumer skills 直接装进 OpenClaw 就有 `strix-pentest` 命令可用（`npx skills add usestrix/strix`）
- **CI 集成**：可以接到品能者 / 品行者的 PR pipeline 自动跑
- **风险**：跑 PoC 是动态执行的，**只能扫自己有权测试的目标**（README 自带 `WARNING: Authorized use only`）

## 实战建议（给运维团队）

1. **先在内部 staging 跑**——确认 model 选择、budget 设置、PoC 输出格式
2. **CI gate 用 `quick` 模式**——只扫 PR diff，避免阻塞合并
3. **夜跑 `standard` 模式**——跑全量代码，第二天 review 报告
4. **SARIF 接 GitHub Code Scanning**——直接在 PR 评论区显示漏洞
5. **`max-budget` 一定要设**——防止 agent 死循环烧光 token

## 参考链接
- 仓库: https://github.com/usestrix/strix
- 官网: https://strix.ai
- 文档: https://docs.strix.ai
- LLM Providers: https://docs.strix.ai/llm-providers/overview
- Cloud API: https://docs.app.strix.ai
- LLM-friendly docs: https://docs.strix.ai/llms.txt
- DeepWiki: https://deepwiki.com/usestrix/strix
- Discord: https://discord.gg/strix-ai