# AIRecon — 零 API Key 的本地化自主渗透侦察 Agent

> 调研时间 2026-11-18 · 仓库: https://github.com/pikpikcu/airecon
> 文档站: https://pikpikcu.github.io/airecon/ · License: **MIT** · 语言: Python 3.12+
> ⭐ 1,095 · Fork 176 · Open Issues 6 · 创建 2026-03-05 · 最后推送 2026-11-12
> 作者: pikpikcu · 仓库体积 10.3 MB · 主语言 Python 4.07 MB

## 一句话定位

**跑在你自己机器上的自主安全侦察 agent** —— 一个 OpenAI 兼容网关（可以是本地 Ollama）+ 一个 Kali Linux Docker 沙箱 + 一个 Textual 终端 UI，**不需要任何 API key、不需要云**。

⭐ 它和 [PentAGI](pentagi.md) / [Strix](strix.md) 最根本的差别不在功能，而在**数据边界**：当网关指向本地模型时，**目标情报、工具输出、报告都不出本机**。

---

## 一、它解决什么问题

AIRecon 瞄准的是**渗透测试的前半段**：侦察（recon）。

传统 recon 痛点：

1. **工具很多但不串起来** —— subfinder 跑完不会自动喂给 httpx，httpx 跑完不会喂给 nuclei
2. **命令历史不沉淀** —— 下次换个目标，同一批踩过的坑再踩一遍
3. **云端 LLM 泄密** —— 用云模型做 recon，目标情报（子域名、内部主机名、API 路径）全部出境
4. **本地模型没工具链** —— 直接给 Ollama 灌一堆工具，它调不动

AIRecon 的答案是：**一个会自己编排工具链的 agent + 全部落盘的结构化记忆 + 完全本地可选的模型**。

### 与同类的核心差异

| | AIRecon | PentAGI | Strix |
|---|---|---|---|
| 界面 | **Textual TUI**（终端 UI） | Web 控制台 | CLI / Web |
| 部署 | **单机单进程 + 一个 Docker 沙箱** | 十几个容器的 compose | Docker |
| 模型 | **任意 OpenAI 兼容网关** | 10+ provider 原生 + Ollama | OpenAI/Anthropic |
| 完全离线 | ✅ **卖点** | ✅（Ollama/vLLM） | ✅ |
| 知识库 | ✅ **本地 1.09M 条安全记录 FTS5** | pgvector + Neo4j | 无内置知识库 |
| 依赖 | Python 3.12 + Docker + 网关 | Docker Compose 全家桶 | Docker |

---

## 二、Pipeline：四阶段状态机

```
RECON → ANALYSIS → EXPLOIT → REPORT
```

⭐ **阶段强制是"软"的** —— 官方原文：*"Phase enforcement is **soft** — the agent is guided but never blocked."*（agent 被引导，但不会被拦住）

这点和 PentAGI/Shannon 的「只报有 PoC 的」思路不同：AIRecon 允许 agent 自由跳转，用 checkpoint 兜底：

- 每 **5** 次迭代 → phase eval（阶段评估）
- 每 **10** 次迭代 → self-eval（自评）
- 每 **15** 次迭代 → context compression（上下文压缩）

---

## 三、反幻觉机制（这是 AIRecon 最值得抄的部分）

⭐ AIRecon 在"防止模型编造漏洞"上做了**多层工程约束**，而且**明确写清了每一层的实现**。这套设计对我们自己的 AI coding agent 工具链有直接参考价值。

### 第 1 层：幻觉模式字符串检测

agent loop 检查模型输出里是否出现这些"无工具输出的断言"：

```python
hallucination_signals = [
    "i have found",           # 声称有发现但没有工具输出
    "the scan shows",         # 声称扫描结果但没跑扫描
    "the results indicate",   # 声称结果但无工具证据
    "my analysis shows",      # 声称分析但没用 code_analysis 工具
    "it appears that",        # 投机性断言无证据
    "based on my knowledge",  # 用模型知识而非实时工具输出
    "without running",        # 明确承认没跑工具
]
```

### 第 2 层：工具调用校验

接受一次工具调用前，验证三件事：
1. 工具名在注册表里存在
2. 必填参数齐全
3. 参数类型符合 schema

### 第 3 层：证据强制（Evidence Requirement）

漏洞报告必须包含具体证据：
- HTTP 请求/响应对
- 截图或 PoC 脚本
- CVSS vector string

**无证据的报告被直接拒绝**：

```
[VALIDATION ERROR] Vulnerability report rejected: missing evidence.
Include HTTP response, PoC script, or screenshot.
```

### 第 4 层：字段级校验规则

| 字段 | 要求 |
|---|---|
| `poc_script_code` | > 50 字符，**必须包含真实目标 URL** |
| `poc_description` | **必须含 HTTP 状态码证据**（如 "HTTP 200"、"302 redirect"） |
| `technical_analysis` | > 80 字符 |
| 语言检查 | 用 "might" / "possibly" / "could be" 却无证据 → **拒收** |
| CVSS vector | 必须是合法的 CVSS 3.1 vector string |

### 第 5 层：置信度分级

```
≥ 0.65  → high confidence (confirmed)
0.4–0.65 → medium confidence (likely)
< 0.4    → low confidence (speculative)  → 标记为需人工复核
```

### 第 6 层：只学已验证的（Verified-only learning）

⭐ 这条解决了一个真实痛点：**长期运行后误报会污染记忆，让 agent 越来越差**。

- 开关：`intelligence_learn_only_verified`（默认**开**）
- 只有 `verified` / `replay_verified` 为真，或 `verified_confidence ≥ 0.65` 的发现才写入跨会话大脑

changelog 原文说明了动机：*"Previously every session vulnerability — verified or not — was persisted, so accumulated false positives would degrade the agent over time."*

### 第 7 层：工作区隔离（Workspace Isolation）

用 URL pattern 匹配（gf 语法）限定每个工作区可访问的目标，防止 agent 跑到工作区外面去。

> ⚠️ 与 PentAGI 的对比很说明问题：PentAGI 在 habr 实测中**越界扫描了不属于自己的 CIDR 网段**；AIRecon 把 scope 做成了独立模块 + 审计日志。这不代表 AIRecon 的 scope 实现一定更可靠（它没有独立第三方实测），但设计思路更对。

---

## 四、记忆与学习（官方明说：不做微调）

⭐ **官方原话**：*"AIRecon does **not** fine-tune the LLM. Its 'learning' is local, structured telemetry that guides tool choice and avoids repeating failed paths."*

### 落盘位置

| 路径 | 内容 |
|---|---|
| `~/.airecon/memory/airecon.db` | SQLite：会话、发现、模式、目标情报、工具使用、模型表现、技能使用、攻击链发现 |
| `~/.airecon/learning/global_learning.json` | 工具表现统计、策略模式、观察日志、蒸馏洞察 |
| `~/.airecon/memory/by_target/` | 每目标记忆：端点、漏洞、WAF 绕过、敏感参数、认证端点 |
| `workspace/<target>/payload_memory.json` | payload 记忆快照（失败过的 payload 不再重试） |

### 行为影响机制

- 会话启动时注入记忆上下文（目标情报、相似发现、已学模式、工具可靠性）
- **冷启动**：无历史时从静态 `tech_correlations` 数据集注入知识简报 —— 从第 1 轮就有"大脑"
- 每 `intelligence_memory_recall_interval`（默认 **4**）次迭代，按检测到的技术栈重新注入
- `intelligence_correlation_interval`（默认 **6**）次迭代跑一次相关性分析
- **自适应工具排序**：按历史成功/失败给工具排序、推荐策略；`intelligence_adaptive_min_observations`（默认 **2**）次观察后即开始会话内学习

---

## 五、工具链

### Kali 沙箱内的工具（按类别）

所有 shell 命令都在隔离的 `airecon-sandbox` Kali 容器里执行：

```
Agent Loop → execute 工具 → docker exec airecon-sandbox bash -c "<command>"
```

| 类别 | 工具 |
|---|---|
| 子域名发现 | subfinder, amass, assetfinder, dnsx, shuffledns, massdns, sublist3r, hakip2host |
| 端口扫描 | nmap, naabu, masscan, netcat |
| Web 爬取 | katana, gospider, gau, waybackurls, httpx, httprobe, meg, waymore |
| 指纹识别 | whatweb, wafw00f, wappalyzer, tlsx, retire, wpscan, joomscan |
| JS 分析 | jsleak, jsluice, gf, trufflehog, js-beautify, LinkFinder |
| 模糊测试 | ffuf, feroxbuster, dirsearch, arjun, x8, headi, dalfox, wfuzz |
| 漏洞扫描 | nuclei, nikto, wapiti, sqlmap, ghauri, nosqli, toxicache, csprecon, semgrep, trivy |
| 利用 | sqlmap, ghauri, dalfox, interactsh-client, testssl.sh |
| JWT & GraphQL | jwt_tool, jwt-cracker, inql, GraphQLmap |
| 密钥泄露 | gitleaks, trufflehog, bandit, git-dumper |
| 密码攻击 | hydra, medusa, hashcat, john |
| 云 & S3 | s3scanner, festin, shodan |
| 字典 | **完整 SecLists** (`/usr/share/seclists/`)、FuzzDB (`/home/pentester/wordlists/fuzzdb/`)、rockyou |
| 脚本 | python3, bash, curl, wget, jq, ripgrep, parallel, tmux |

### 自研工具（不靠 Kali 镜像的部分）

| 工具 | 说明 |
|---|---|
| **Caido 集成** | 原生。工具：`list` / `replay` / `automate` / `findings` / `scope` / `sitemap` / `intercept`；支持 HTTPQL 过滤表达式、`§FUZZ§` 标记 |
| **Fuzzing Engine** | 自研 fuzz 引擎 + `§FUZZ§` 标记注入 |
| **Schemathesis** | API Schema 模糊测试，含自动发现 |
| **Semgrep SAST** | 源码扫描 |
| **Browser Automation** | Playwright；支持浏览器认证（含 TOTP/2FA 登录流程） |
| **Correlation Engine** | 技术指纹 → 规则源 → 输出；喂给关联分析 |
| **Multi-Agent** | `spawn_agent` / `run_parallel_agents` / AgentGraph（DAG） |
| **SearXNG & Web Search** | 支持 dork 操作符 |

### Skills 系统

⚠️ **README 说 "57 built-in skill files"，但实测仓库 `airecon/proxy/skills/` 下有 141 个 `.md` 文件**（153 个 tree 条目，含目录）。README 这个数字**已过时**。

实测的 141 个 skill 分布在 9 个分类目录：

```
ctf/           ctf/pwn, ctf/reversing, ctf/crypto, ctf/forensics
frameworks/    django, dotnet, express, fastapi, flask, laravel, nextjs, ...
payloads/      payload 类
postexploit/   后渗透
protocols/     协议类
reconnaissance/ 侦察
technologies/  技术栈
tools/         工具用法
vulnerabilities/ 漏洞类
```

社区扩展：[airecon-skills](https://github.com/pikpikcu/airecon-skills) —— 再加 57 个 CLI 导向的 playbook（CTF / 漏洞赏金 / 渗透）。

### 本地安全知识库（airecon-dataset）

可选伴侣项目，把安全数据集索引进本地 SQLite FTS5：

| 数据集 | 记录数 | 内容 |
|---|---:|---|
| Pentest Agent (ChatML) | 322,433 | CVE 驱动的利用工作流（MITRE/NVD/ExploitDB） |
| CTF SaTML 2024 | 190,657 | 真实攻防 CTF 交互数据 |
| CTF Instruct | 141,182 | Pwn / web / crypto / forensics / 逆向 |
| Cybersecurity CVE | 124,732 | CVE 分析、CVSS、利用上下文 |
| Cybersecurity Fenrir | 83,918 | 攻防指令对 |
| Red Team Offensive | 78,430 | 横向移动、提权、规避 |
| SQL Injection Q&A | 50,632 | SQLi 检测/绕过/利用 |
| Cybersecurity Q&A | 53,199 | 广谱安全知识 |
| Nuclei Templates | 23,180 | nuclei YAML 模板生成 |
| StackExchange RE | 20,641 | 二进制分析、反汇编、调试、恶意软件 |
| NVD Security Instructions | 2,063 | 结构化 CVE 分析 |
| APT Privilege Escalation | 1,000 | Linux 提权 + APT 战术 |
| Bug Bounty & Pentest | 146 | payload、绕过方法、报告模板 |
| **合计** | **~1.09M** | |

⭐ 关键设计：**LLM 自主决定何时调用** `dataset_search`，系统不自动触发。系统提示词里 instruct agent 在尝试不熟悉技术前先查知识库。

```bash
git clone https://github.com/pikpikcu/airecon-dataset.git
cd airecon-dataset && python install.py
```

---

## 六、模型要求

⭐ **唯一的硬性要求：原生 tool/function calling**

> ⚠️ *"Native tool/function calling is **REQUIRED**. Without it the agent cannot run any tool (http_observe, execute, browser, Caido, …) and is **non-functional**."*

`openai_supports_native_tools: true` 必须保持。

### 推理能力自动探测（不硬编码模型名）

`llm_thinking_request_mode: auto`（默认）：
- 发 `reasoning_effort` 给 o-series / gpt-5 / gemini-thinking / grok-reasoning / QwQ / DeepSeek-R1
- 发 `chat_template_kwargs.enable_thinking` 给 Qwen3 / GLM / vLLM 托管模型
- 对普通模型（gpt-4o、gemini-flash）不发 —— 发了会被 400 拒绝

⭐ 后端返回 400「不支持该参数」时**自动剥离并记住**，不用维护模型名单。

`llm_reasoning_replay: auto` —— 决定是否把存储的 `reasoning_content` 回传给模型。DeepSeek API 和 `deepseek/` 前缀的网关模型默认回传（它们的 thinking 模式不带这个会拒绝 tool 请求），其他后端不回传（省 context）。

### 双 wire 协议

| `llm_provider` | 端点 | 说明 |
|---|---|---|
| `openai`（默认） | `/v1/chat/completions` | LiteLLM / vLLM / 托管网关 |
| `anthropic` | `/v1/messages` | 原生 Anthropic，保留 signed thinking 和 tool block |

原生 Anthropic 的默认认证方式是 `llm_anthropic_auth: x-api-key`；需要 Bearer 的网关要显式选 `bearer` 或 `both`。

### 质量分级（官方建议）

| 模型档位 | 表现 |
|---|---|
| 强推理 + tool calling（GPT-5/o 系、Claude Sonnet/Opus 4.x、Gemini 2.5、Qwen3 ≥32B、DeepSeek-R） | 可靠跑完整 recon 流程 |
| 中档（8B–14B 本地） | 简单任务可用，**预期更多 tool-call 错误和幻觉** |
| <8B 本地 | **不建议**做严肃测试 |

⭐ *"Quality scales with the model, not with AIRecon."*（质量取决于模型，不是取决于 AIRecon）

### 不用 `openai` SDK

代码直接用 `httpx` 说 `/v1/chat/completions` 协议，pyproject 里显式注释了原因：*"the heavyweight `openai` SDK is intentionally NOT a dependency"*。这减少了依赖面，也让任何兼容网关都能用。

---

## 七、安装

### 前置

- **Python 3.12+**
- **Docker 20.10+**
- 一个可达的 **OpenAI 兼容 LLM 网关**（`openai_base_url`）
- git、curl

### 一行安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/pikpikcu/airecon/refs/heads/main/scripts/install.sh | bash
```

脚本行为：自动检测 remote vs local 模式 → 缺 Poetry 就用官方安装器装（不污染系统包）→ 构建 wheel → 装到 `~/.local/bin`。

### 手动安装

```bash
git clone https://github.com/pikpikcu/airecon.git
cd airecon
./install.sh
export PATH="$HOME/.local/bin:$PATH"
airecon --version
```

### ⚠️ 实测发现的安装坑：install.sh 的 Python 选择逻辑

**这是本机实际复现出来的**，不是推测。

`scripts/install.sh` 第 200-201 行：

```bash
PYTHON_CMD="python3"
[ -f "/usr/bin/python3" ] && PYTHON_CMD="/usr/bin/python3"
```

**它无条件优先选 `/usr/bin/python3`**（macOS 自带的 3.9），而不是 PATH 里更新的版本。紧接着第 217 行做版本检查：

```bash
PY_OK=$($PYTHON_CMD -c "import sys; print('yes' if sys.version_info >= (3,12) else 'no')" 2>/dev/null || echo "no")
if [ "$PY_OK" != "yes" ]; then
    echo -e "${RED}[!] Python >= 3.12 required, found $PY_VERSION${NC}"
    exit 1
fi
```

**本机实测**：PATH 里有 Python 3.14.9（`~/.hermes/tools/python-3.14.9+20251021-darwin-arm64/bin/python3`），但 `/usr/bin/python3` 是 3.9.6 → 脚本会选到 3.9 → **直接报「Python >= 3.12 required, found 3.9」并退出**。

✅ **绕过方法**（任选）：
```bash
# 方法 A：让 /usr/bin/python3 指向 3.12+（需 sudo，会影响系统工具链，慎用）
# 方法 B：改脚本这两行，让它优先用 PATH 里的 python3
#   PYTHON_CMD="python3"
#   [ -f "/usr/bin/python3" ] && PYTHON_CMD="/usr/bin/python3"
#   ↓ 改为
#   PYTHON_CMD="$(command -v python3)"
#   if "$PYTHON_CMD" -c 'import sys; sys.exit(0 if sys.version_info>=(3,12) else 1)'; then :; else
#     for c in python3.12 python3.13 python3.14; do
#       command -v "$c" >/dev/null && PYTHON_CMD="$(command -v "$c")" && break
#     done
#   fi
# 方法 C：自建 3.12+ 环境后，先 export PATH 再跑 install.sh —— 但脚本仍会选 /usr/bin/python3
```

⚠️ **方法 C 无效**（脚本硬编码路径优先于 PATH）。实际可行的是方法 B（改脚本）或方法 A。

### 卸载

```bash
./scripts/uninstall.sh
```

### 运行

```bash
airecon start                          # 启动 TUI
airecon start --session <session_id>  # 恢复会话（重放之前的 chat + tool 调用）
```

### 配置要点

配置文件 `~/.airecon/config.yaml`，主要分组：

| 组 | 关键项 |
|---|---|
| LLM Backend | `openai_base_url`（**必须含 `/v1`**）、`openai_model`、`openai_api_key`、`openai_supports_native_tools`（**必须 true**） |
| LLM Tuning | `llm_enable_thinking`、`llm_thinking_mode`、`llm_thinking_request_mode`、`llm_reasoning_replay` |
| Scan Profile | 基线预设（你的其它 key 仍会覆盖它） |
| Scope Guard & Audit | 范围守卫与审计（运行时也可用 `/scope` 改） |
| Notifications | 扫描完成通知 |
| Intelligence & Memory | `intelligence_learn_only_verified`（默认开）、recall/correlation interval |
| Tool Health | 工具健康检查 |
| Safety / Docker / Recon | 安全与沙箱配置 |

### MCP 集成

配置 `~/.airecon/mcp.json`：

```json
{
  "mcpServers": {
    "hexstrike": {
      "command": "python3",
      "args": ["/path/hexstrike-ai/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"],
      "env": {"PYTHONUNBUFFERED": "1"},
      "enabled": true
    },
    "recon": {
      "transport": "sse",
      "url": "https://example.com/mcp",
      "enabled": true,
      "headers": {"Authorization": "Bearer xxxxx"}
    }
  }
}
```

工具名格式 `mcp_<server>`，动作：`list_tools` / `search_tools` / `call_tool`。

```json
{"name": "mcp_acme", "arguments": {"action": "list_tools"}}
```

TUI 里也支持 `/mcp add http://localhost:3001 auth:apikey:*** example_name`。

---

## 八、业界评价

⚠️ **必须先说清楚：AIRecon 的独立第三方实测严重不足。** 这与 PentAGI（6+ 篇独立实测，含一篇结论不利）和 Strix（有独立评测）形成鲜明对比。

### 现有的第三方材料

| 来源 | 性质 | 内容 |
|---|---|---|
| cybersecuritynews.com（2026-06-17） | **新闻稿转述** | 报道其完全离线运行（本地 Ollama + Kali Docker），强调无数据云端暴露 |
| letsdatascience.com | **新闻稿转述** | 同上，标注基于 GitHub README 与该新闻报道 |
| vyprsec.ai（portal） | **新闻稿转述** | 同上 |
| deepwiki.com | **AI 生成的项目解读** | 代码结构梳理，非实测 |
| pikpikcu.github.io/airecon | **官方文档站** | features / tools / configuration / changelog / stability 全套 |
| 各类仓库镜像（gsatyadev/airecon-ai-pentest 等） | **fork** | 无独立内容 |

⭐ **"完全离线"这个卖点目前主要由厂商自己的 README + 三家新闻稿转述支撑，没有第三方在隔离环境里跑通过的独立记录。** 这与 PentAGI 的情况正好相反。

### 官方的"稳定性"文档

项目有专门的 `docs/stability.md`（20KB），这在同类项目里少见 —— 值得肯定的是作者**主动写了已知问题**而不是藏起来。

### 自评的可信度信号

AIRecon 有几个**反营销**的细节，这些通常比任何评测都更能说明作者态度：

1. ⭐ **明说"不做微调"** —— *"AIRecon does not fine-tune the LLM. Its 'learning' is local, structured telemetry..."* 很多同类项目会含糊其辞或夸大"AI 自我进化"
2. ⭐ **明说阶段强制是软的** —— *"Phase enforcement is soft — the agent is guided but never blocked."*
3. ⭐ **明说 <8B 模型不建议用** —— 并给出 8-14B"预期更多 tool-call 错误和幻觉"的分档
4. ⭐ **明说协议支持 ≠ 质量保证** —— *"protocol support is not a guarantee of model quality"*
5. ⭐ **README 的 skill 数量（57）已过时（实际 141）** —— 不是隐瞒，是**忘了更新**，属于作者善意但粗心
6. ⭐ **changelog 里主动写"以前会积累误报导致 agent 变差，现在改成只学已验证的"** —— 主动承认历史缺陷并修复

### 版本号的两个坑

⚠️ **版本号体系不一致**：

| 来源 | 版本 |
|---|---|
| `pyproject.toml` | `1.7.1-beta` |
| `airecon/_version.py` fallback | `1.7.1-beta` |
| CHANGELOG 顶部 | `v1.7.1-beta`（2026-06-17） |
| **GitHub Releases** | **`0.1.7-beta`（2026-04-03）** 是最新 |
| **PyPI** | **不存在**（`pypi.org/pypi/airecon/json` → **404**） |

⭐ `_version.py` 的实际逻辑是优先从 `importlib.metadata.version("airecon")` 读安装版本，**只有读不到才 fallback 到 `1.7.1-beta`**。所以 PyPI 上没有包、Releases tag 也是 `0.1.x`，但装完 `airecon --version` 会显示 `1.7.1-beta` —— 这个版本号**只在源码安装路径下有意义**。

**分发渠道只有 GitHub 源码安装**（脚本自动装 Poetry、构建 wheel、`pip install` 本地 wheel），没有 PyPI 包。

⚠️ **GitHub Releases 停更约 7 个月**：实测全部 release 只有 `0.1.7-beta`（2026-04-03）、`v0.1.6-beta`（2026-03-17）、`v0.1.5-beta`（2026-03-05），tag 也只有这 3 个。但仓库 2026-11-12 仍在推送、CHANGELOG 已到 `v1.7.1-beta`（2026-06-17）。**结论：作者走的是"main 分支滚动开发"模式，不打正式 release。** 这对使用者意味着：

- 想追新只能 `git clone main` + `./install.sh`，没有"下载最新稳定版"的选项
- 无法通过 release 做版本锁定/回滚，需要自己记 commit SHA
- 也没有 release 附带的 changelog 摘要，得自己读 `CHANGELOG.txt`

---

## 九、跟我们的关系

我们做 AI coding agent 工具链，AIRecon 有**三处可以直接抄的设计**：

1. ⭐⭐ **反幻觉的六层结构（§三）** —— 这是全篇最有工程价值的地方。我们的 agent 也会遇到"模型声称做了但没做"的问题。AIRecon 的做法是**分层递进且每层都可独立验证**：
   - 字符串黑名单（廉价、覆盖常见句式）
   - 工具调用 schema 校验（结构性）
   - **证据强制**（无证据报告直接拒收）⭐ —— 这条最狠，也最容易抄
   - 字段级规则（长度、必含状态码、禁用意犹未尽的措辞）
   - 置信度分级
   - **只学已验证的** ⭐ —— 解决"误报污染长期记忆"

   我们只要挑 **「证据强制」+「只学已验证的」** 两条落进自己的 finding/report 流程，就能拿到最大收益。

2. ⭐ **语言措辞黑名单** —— `"might" / "possibly" / "could be"` 无证据即拒收。这条几乎零成本，可以直接用在我们自己的报告生成里。

3. ⭐ **工作区 scope 隔离（§三第 7 层）** —— 对比 PentAGI 的越界实测，我们的 AI agent 工具链**必须有硬性的目标范围约束**。AIRecon 的 `gf` 模式匹配 + 审计日志是可参考的实现形态。

另外 **[strix](strix.md)** 和 **[pentagi](pentagi.md)** 已经在了，这三个可以构成一张"AI 渗透工具版图"：

| | PentAGI | Strix | AIRecon |
|---|---|---|---|
| 成熟度 | ⭐ 34.5k / 13 个月 | ⭐ 49.4k | ⭐ 1.1k / 8 个月 |
| 工程完整度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| 独立第三方实测 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐（缺） |
| 离线/隐私 | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 知识库 | pgvector+Neo4j | 无 | ⭐⭐⭐⭐⭐ 1.09M 本地 |
| 部署复杂度 | 高（十余容器） | 中 | **低（单进程+1 沙箱）** |
| 误报控制 | 官方承认 10-30% | — | 七层反幻觉（设计最强，实测未知） |
| 许可 | MIT + EULA | Apache-2.0 | MIT |

---

## 十、落地建议

**适合**：
- 有强隔离要求的内网 / 涉密环境（本地模型 + 本地沙箱 = 数据不出网）
- 漏洞赏金的前期侦察（自动化程度高，人只看结果）
- 想学一套**反幻觉工程**的实现（§三 那七层）
- 轻量部署（比 PentAGI 的 compose 轻得多）

**不适合**：
- 期待它替代人工渗透（没有任何独立实测支持这个期待）
- 用 <8B 模型（官方明说不建议）
- 期待 JSON/结构化输出对接现有工单系统（文档没提）

**如果试，按这个顺序**：
1. 先修 install.sh 的 Python 选择（或直接改用 3.12+ 的 `/usr/bin/python3`），否则装不上
2. 准备一个 OpenAI 兼容网关 —— 最简是本地 Ollama，但**模型至少要 32B 级别**才有意义
3. `airecon start` 先跑自己域名或本地靶场
4. **`intelligence_learn_only_verified` 保持默认开** ⭐ —— 这是长期质量的关键
5. 装 `airecon-dataset`（1.09M 条）后再跑，agent 冷启动就有知识可用
6. 检查 `~/.airecon/memory/airecon.db` 和 `~/.airecon/learning/global_learning.json` —— 这些是它的全部"学习"，也是唯一需要备份的东西
7. 跑之前确认 Docker 沙箱的出网策略（沙箱能访问什么，它就能攻击什么）

---

## 参考链接

**官方**
- 仓库 https://github.com/pikpikcu/airecon
- 文档站 https://pikpikcu.github.io/airecon/
- Features https://pikpikcu.github.io/airecon/features/
- Tools Reference https://pikpikcu.github.io/airecon/tools/
- Configuration https://pikpikcu.github.io/airecon/configuration/
- Changelog https://pikpikcu.github.io/airecon/changelog/
- 社区技能库 https://github.com/pikpikcu/airecon-skills
- 本地知识库 https://github.com/pikpikcu/airecon-dataset

**第三方（均为转述，无独立实测）**
- cybersecuritynews.com https://cybersecuritynews.com/airecon-penetration-testing-tool/
- letsdatascience.com https://letsdatascience.com/news/airecon-runs-offline-penetration-testing-with-kali-sandbox-e01c7813
- DeepWiki https://deepwiki.com/pikpikcu/airecon

**相关笔记**
- [pentagi](pentagi.md) — 同类工具，工程完整度更高，有大量独立实测
- [strix](strix.md) — 同类工具，Skill 化程度最高
