# Agentic Attack Detections — 把「合法 AI Agent 改成攻击控制台」拆成可导入 SIEM 的检测规则

> 学习笔记 · 调研时间 2026-11-27
> 原文: 公众号《AI Agent 正在被改造成攻击控制台：80 余个框架的检测清单》（数字羲和，**2026-11-27 12:00:51 CST**，原始 `ct=1795752051`）
> 一手源: https://github.com/ThreatDefence/agentic-attack-detections · 厂商页 https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
> 被检测对象: [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)（MIT · 仓库审阅点 `7c34e2db` 2026-11-21）
> License: **MIT**（`LICENSE` 文件实测：*Copyright (c) 2026 ThreatDefence Pty Ltd and contributors*）· ⭐757 · fork 157 · 93 commit · 11 个 release（v2.7.0→v2.11.1，2026-11-22~11-24）
> 相关笔记: [aiPentestHarnessesComparison](aiPentestHarnessesComparison.md)（AI 渗透框架已被真实威胁方使用）· [strix](strix.md) · [pentagi](pentagi.md) · [airecon](airecon.md) · [llmCodeAuditMethodology](llmCodeAuditMethodology.md)

---

## 📌 Abstract（摘要）

**核心命题**：攻击链的战场已经从「文件是不是恶意的」转移到「配置是不是异常的」——攻击者不再投递木马，而是下载一个**合法开源的 AI Agent**，改几个配置项就把它变成攻击控制台。ThreatDefence 的 `agentic-attack-detections` 把这件事拆成了 **1,827 条规则 / 124 个 ATT&CK 技术**，覆盖 82 个 Agent 攻击框架。

**方法论骨架**：

| 层 | 目录 | 回答什么问题 | 实测规模（2026-11-27） |
|---|---|---|---|
| 框架层 | `frameworks/<name>/` | 这个具体框架的攻击特征长什么样 | 82 个目录（覆盖矩阵里 71 个） |
| 行为层 | `behaviors/` | **不管哪家框架**，只要「有 Agent 在干攻击的活」就能发现 | 9 hunt + 3 analytics + 10 Sigma |
| 通用入侵层 | `general/` | 攻击者不论用不用 Agent 都会做的动作 | 16 hunt + 3 analytics + 16 Sigma |
| 情报层 | `iocs/indicators.csv` + `feeds/` + `exposure/` | 已知 IOC / 暴露面快照 | 1,838 条指标、8,531 条暴露控制台 |
| 生成层 | `tools/*.py` + `generated/` | 从 CSV 生成全部产物，CI 校验 | 12 个 Python 脚本（7 个 `build_*.py` + `convert.py` / `validate.py` 等） |

⭐ **最硬的一条洞察（文章完全没写）**：**上游明确拒绝把「开了 `--yolo`」当作检测条件**。`behaviors/sentinel/hunting/01` 的注释原文写着 auto-approve flag「不是过滤器」——真实遥测里它在员工机器上很常见，甚至有 agent **不带任何 flag 就跑了 nmap**，所以这个 flag「既不能识别攻击者，也不能为同事开脱」。**攻击工具本身才是信号**。文章却把「命令行同时出现 Agent 启动参数 + `--yolo` + 扫描工具」的 join 查询当作项目做法贴出来——**这个 KQL 在仓库里不存在，且方向与上游设计相反**（详见 §五·事实错误 1）。

⭐ **对我们最直接可用的一条**：这套规则是针对 **Hermes Agent 本身**写的（`frameworks/hermes/` 有独立目录，4 条 KQL + 3 条 Sigma + 4 条 YARA），**而这台机器上跑着 5 个 Hermes profile**。我按上游规则实跑了一遍本机自查：**攻击特征 HIT = 0**，但**误报清单是 3 条硬命中**（godmode 越狱技能字符串 21~28 个文件、SOUL.md 文件事件、`/.hermes/` 进程命令行）——其中 godmode 误报**是设计如此**（上游 YARA 规则注释自己承认 "matches by design"）。

---

## 一、一句话定位

**把「合法 AI Agent 被改成攻击控制台」这件事，拆成可以一键导入 Sentinel / Defender XDR / Splunk / Elastic / Suricata / Zeek / YARA / WAF / STIX 2.1 的检测规则集**——猎的是「配置被改了」，不是「装了某个软件」。

---

## 二、三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **① 规则导入 SIEM** | Sentinel ARM 模板一键部署 / Splunk app `.tgz` / Elastic `.ndjson` / Sigma 转换 | 已有 Sentinel·Splunk·Elastic 的团队，规则全 disabled，需自己调阈值 |
| **② 自建狩猎管线** | `frameworks/*/sentinel/hunting/*.kql` + `behaviors/` + `general/` | 有 Defender XDR 高级搜寻或日志管道；KQL 直接贴进 Defender / Log Analytics |
| **③ 网络+磁盘侧拦截** | `suricata/*.rules`、`zeek/` 包（`zkg install`）、`yara/*.yar`、`waf/`（Cloudflare/AWS/Azure） | 边界侧封堵 + 主机侧扫盘 |
| **④ 情报订阅** | `feeds/stix2.1-bundle.json`（2,008 对象）、`feeds/by-framework/`、`iocs/indicators.csv` | 导入 TIP（MISP / OpenCTI，步骤见 `docs/threat-intelligence-platforms.md`） |

---

## 三、核心架构

```
agentic-attack-detections/
├── frameworks/<82 个>/          框架层：README + source-code-signals + coverage + hunting-order
│                                + sentinel/{hunting,analytics} + sigma/ + suricata/ + yara/ + zeek/
├── behaviors/                   行为层：跨框架通用（Agent 起攻击工具 / 服务器调模型 API / UA 家族爆发…）
│   ├── sentinel/{hunting(9),analytics(3)}  sigma(10)  suricata/  zeek/agentic-behaviors/
├── general/                     通用入侵层：与 Agent 无关的传统入侵动作（喷洒 / webshell / DCSync…）
│   └── sentinel/{hunting(16),analytics(3)}  sigma(16)
├── iocs/indicators.csv          1,838 条指标（唯一真源，所有 feed 由它生成）
├── feeds/                       stix2.1-bundle.json + by-framework/ + domains/ipv4/sha256/urls/user_agents
├── exposure/                    暴露面快照：consoles.csv 8,531 行 / registry-writes.csv 380 个开放 registry
├── generated/                   自动生成产物：sentinel_asim / defender_xdr / elastic_* / splunk / attack(Navigator)
├── tools/                       build_feeds / build_attack / build_splunk / build_elastic / build_sentinel / convert / validate
├── lab/                         本地沙盒：Splunk 10.6.2 + Kibana 9.5.5（Docker Compose，绑 127.0.0.1）
├── waf/                         Cloudflare / AWS WAF / Azure WAF 规则
└── docs/attack-coverage.md      ATT&CK 覆盖矩阵（自动生成，对齐 Enterprise 20.1）
```

**关键设计：一条规则必须写 ATT&CK 技术编号**——`tools/attack-enterprise.json` 里 pin 了 ATT&CK Enterprise 20.1，CI 会对「没写技术编号」或「写了该 release 里不存在的技术」的 PR 直接失败。实测 `1827 rules cover 124 techniques`。

**SID 段**：向 sidallocation.org 申请的 `3800000–3819999`，每框架 1000 段（Hermes = `3806001–3806499`），避免与其他规则集撞号。

### 实测规则密度（本地 clone 统计，2026-11-27）

| 格式 | 数量 | 备注 |
|---|---|---|
| Sigma 规则 | **349** 个 `.yml` | 其中 `frameworks/` 323 + `behaviors/` 10 + `general/` 16 |
| KQL hunt | **260** 个 `.kql` | 框架 235 + behaviors 9 + general 16 |
| Sentinel analytics | **78** 个 `.yaml` | 框架 72 + behaviors 3 + general 3 |
| Suricata | **897** 条 `alert` | 151 个 `.rules` 文件 |
| YARA | **210** 条 `rule` | 69 个 `.yar` |
| Zeek | 20 个 `.zeek` | `behaviors/zeek` 10 个脚本 + 包 |
| 指标 | **1,838** 行 CSV | 69 个 framework 标签 |
| 暴露控制台 | **8,531** 行 | 7,500 个不同地址 / 28 个框架 |

**跑通上游自己的校验器**（`python3 tools/validate.py`，实跑输出）：

```
sigma: 349 files parsed
sentinel: 260 hunts
kql: skipped (dotnet not installed)
elastic: 5 rules, 349 in the NDJSON import
splunk: 15 saved searches in frameworks/
splunk: 363 saved searches in deploy/
suricata: 897 rules
yara: compiled
zeek: skipped (zeek not installed)
osquery: json ok
feeds: up to date

all checks passed
```

> ⚠️ KQL 与 Zeek 两项在本机被 skip（缺 dotnet / zeek），**「all checks passed」不等于这两类规则被验证过**。

---

## 四、安装与最小使用

```bash
git clone --depth 1 https://github.com/ThreatDefence/agentic-attack-detections
cd agentic-attack-detections

# ① 校验全部产物（CI 跑的就是它）—— 需要 sigma-cli 等 Python 包
python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt
.venv/bin/python3 tools/validate.py

# ② 拿一个框架的规则跑 Suricata（仓库自带 pcap，输出写到 out/）
suricata -r frameworks/artex/tests/artex-sample.pcap \
         -S frameworks/artex/suricata/artex.rules -l out -k none
cat out/fast.log

# ③ 转换格式（Sigma → KQL/ES|QL/Splunk），产物落在 generated/
.venv/bin/python3 tools/convert.py
```

**安装踩坑（实测）**：`tools/requirements.txt` 里 `sigma-cli>=3.1` **在系统 Python 3.9 上装不上**（本机 `python3` 是 3.9.6，无对应 wheel）。用 Hermes 自带的 Python 3.14 建 venv 即可：

```bash
~/.hermes/tools/python-3.14.9+*/bin/python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt     # sigma-cli 3.1.0 装得上
```

**本地沙盒**（`lab/lab.sh`）：Splunk 10.6.2 + Kibana 9.5.5，端口只绑 `127.0.0.1`，需 ~8 GB 内存；Splunk 只发 amd64 镜像，Apple Silicon 上走模拟启动要几分钟。

---

## 五、文章事实核查（一手源逐条核对）

> 核对基准：仓库 `main` @ `12e37af`（2026-11-26 11:51 UTC），文章发布于 2026-11-27 12:00 CST。数字均为本机实测。

### 5.1 事实错误 / 失真

| # | 文章说法 | 一手源实测 | 判定 |
|---|---|---|---|
| 1 | 「项目的检测规则把 Agent 进程和攻击工具做了联合匹配」，并贴出 `join kind=inner`（Agent 工具进程 ⟗ 带 `--yolo` 的进程，按 DeviceId 连接）的 KQL | **仓库里没有这条查询。**`frameworks/hermes/sentinel/hunting/01` 用的是 `union isfuzzy=true` 的 4 个分支，yolo 判断是独立分支；唯一同时含 `join kind=inner` 与 yolo 的是 `behaviors/.../01-ai-agent-in-auto-approve-mode`，但该文件注释明写 flag「are not a filter… an agent ran nmap with no flag at all, so the flag neither finds an attacker nor clears a colleague」 | ❌ **拼接产物 + 与上游设计相反**。文章把 `hermes/01` 的工具列表和 `behaviors/01` 的 join 风格缝在了一起 |
| 2 | 「Suricata 规则 —— 46 条」（ARTEX） | README 覆盖表写 46，但 `frameworks/artex/suricata/` 实测 **50+38=88** 条 `alert`，仓库自动生成的 `docs/attack-coverage.md` 也写 **88** | ⚠️ 文章抄的是**已过期的 README 数字**；正确值 88 |
| 3 | 「指标文件 iocs/indicators.csv 收录 1838 条，每条带…复核日期」 | 行数 1,838 ✅ 对；但 **只有 176 行有 `review_by`**（地址类才需要复核日期），CSV 共 10 列（`type,value,confidence,context,actor,source,source_url,reported,review_by,framework`），文章漏了 `source` 与 `reported` | ⚠️ 前半对，后半夸大 |
| 4 | 「覆盖最全的一个框架：KQL 15 / Sentinel 3 / Sigma 16 / YARA 4 / 指标 247」 | 与 README 的 ARTEX 行完全一致 ✅；但 Hermes 行同样列了 Suricata=**7**，实测 `hermes.rules`(8) + `hermes-ip.rules`(26) = **34**（`attack-coverage.md` 也写 34） | ⚠️ README 的 Suricata 列整体滞后 |
| 5 | 「项目建立仅一周，已有 93 次提交」「750 余颗星」 | 93 commit ✅、757★ ✅、建于 2026-11-20 ✅ | ✅ |
| 6 | 「80 余个框架」 | `frameworks/` 下 **82 个目录** ✅；但 README 覆盖矩阵只有 **71 个框架行**，另 11 个是「控制台指纹级」小目录（只有 README + `source-code-signals.md` + 自动生成的 `*-ip.rules` / `*.intel`，**没有 KQL / Sigma 规则**） | ⚠️ 需拆开看 |
| 7 | 「常见端口 8878（Web 界面）、9119（仪表盘）」 | 仓库自己的 11-25 暴露快照里 Hermes 控制台 **2,226 条全部在 9119**，**8878 零条**；上游当前 `hermes web` 默认 **8080**、dashboard 默认 9119 且默认绑 `127.0.0.1`；在上游代码里搜 `"HermesWebUI"` **0 命中** | ⚠️ 8878 是 2026-07 Hunt.io 观测到的历史形态，不是现状 |
| 8 | 「ThreatDown 建议狩猎滥用特征而不是 Agent 软件包本身」「它不是攻击软件，正因如此攻击者才喜欢它」 | 两句都是上游原文（`frameworks/hermes/source-code-signals.md`） | ✅ 转述准确 |

### 5.2 普适性缺口（结论成立但边界被省略）

1. **全部规则是实验性的**：README 明写 *「No rule has been tested against a captured intrusion. Treat every rule as experimental until it has run on your own data.」* 文章只说「注意项目自己声明了实验性」，没说清**没有任何一条规则在真实入侵上验证过**。
2. **平台边界**：Sigma `file_event` 规则的 `logsource.product: linux` → **macOS / Windows 主机不适用**；Sigma `process_creation` 无 product 限制（跨平台），YARA / Suricata 跨平台。文章没提这条，直接影响落地选型。
3. **「暴露控制台」是某天的扫描快照**（2026-11-25），不是持续情报；`exposure/registry-writes.csv` 里 380 个开放 registry 上有被推送的探针镜像（`artex-rce`/`writecheck` 等）——**那是别人的资产被利用的证据，不是我们的暴露面**。
4. **README 的数字普遍滞后于代码**（指标 580 vs 1,838；Suricata 46 vs 88；暴露面 8,523/7,495 vs CSV 8,531/7,500）。11 天发了 11 个 release（v2.7.0→v2.11.1）——**以 `tools/` 生成物和 `docs/attack-coverage.md` 为准，别拿 README 数字当准**。

### 5.3 文章完全漏掉的一整块能力

WAF 规则（Cloudflare / AWS WAF / Azure WAF）· osquery pack · Splunk app · Elastic NDJSON 一键导入 · Zeek 包（`zkg install`）· STIX 2.1 bundle（2,008 对象）· `exposure/` 暴露面数据集 · `docs/attack-coverage.md` 的 1827 规则/124 技术矩阵 · `tools/` 生成链 + CI 校验 · `lab/` 本地 Splunk+Kibana 沙盒 · SID 段申请 · **`general/` 这一整层**（16 hunt + 16 Sigma 的非 Agent 入侵动作）。

---

## 六、Hermes 专项：六个检测点逐条对照上游

文章讲的「六个可以立刻查的检测点」全部来自 `frameworks/hermes/`。逐条核到上游一手源：

| # | 检测点 | 上游证据（文件:行） | 判定 |
|---|---|---|---|
| 1 | **审批被关闭** | `hermes_cli/_parser.py`（`--yolo`，本机实测 `~/.hermes/hermes-agent/hermes_cli/_parser.py:201`）；`config_defaults.py` 的 `"approvals": {"mode": "smart", ...}`；KQL `hermes/01` 分支 1 匹配 `--yolo` / `HERMES_YOLO_MODE` / `approvals.mode` | ✅ 三个开关都真实存在。⚠️ 上游**默认 `smart`**（辅助模型自动批低风险），不是「默认每次问」 |
| 2 | **越狱技能 godmode + `prefill.json`** | 上游 `optional-skills/security/godmode/`（`SKILL.md` + `scripts/{load_godmode,auto_jailbreak,parseltongue,godmode_race}.py`）；`config_defaults.py:1348` 有 `"prefill_messages_file": ""`；Sigma `file_event_lnx_hermes_attack_files.yml` 匹配 `/.hermes/skills/security/godmode/` 与 `/.hermes/prefill.json` | ✅ 三个手法（G0DM0D3 / Parseltongue / ULTRAPLINIAN）实测在仓里 |
| 3 | **人格文件被替换** | YARA `Hermes_Carbonato_GH0ST_Persona`（`"You are GH0ST"` + `/root/.hermes/loot/`）、`Hermes_Red_Team_Operator_Persona`（`"SOUL - Red Team Operator"`）；KQL 匹配 `SOUL.md` 的 FileCreated/FileModified | ✅ |
| 4 | **技能批量写入** | 上游记 Gambit 案例：121 个技能中 **78 个**与攻击相关，含「剥离自身安全过滤」和「提取后清库」 | ✅ |
| 5 | **控制面暴露** | Telegram gateway / WebUI 8878 / dashboard 9119（`hermes_cli/subcommands/dashboard.py:18` 默认 9119） | ⚠️ 见 §五·7：8878 是历史值 |
| 6 | **凭据集中收集** | GH0ST 人格要求把 API key 写入 `/root/.hermes/loot/`；Sigma 匹配 `/.hermes/loot/` | ✅ |

**四个真实案例（上游 `source-code-signals.md`）**：Unit 42（2026-07-30，珠海 knaithe/KnYuan，DeepSeek + godmode，460+ 目标，`python3 -m http.server 8888` 暴露密钥/目标/会话日志）· Hunt.io（2026-07-23，泰国财政部内网 yolo 无人值守跑 LinPEAS，`43.246.208.207` 留 `hermes-results`、Hades implant、VShell、Hermes WebUI 8878）· Gambit（2026-09-22，零售盗卡，1,951 prompt / 260 会话）· ThreatDown（2026-09-22，Carbonato 僵尸网络，Docker API 2375 → `nsenter` 逃逸 → cron/systemd/rc.local 持久化 → 挖矿 → Telegram 上报）。

> ⚠️ **这些案例里的 Hermes 版本是 2026 上半年**：上游审阅点是 `7c34e2db`（2026-11-21），我们本机是 `v0.23.1+447.g448e307`（2026-11-09）。文件路径引用（如 `config.py:133`）对不同 commit 会漂移。

---

## 七、跟我们的关系（本机实跑）

### 7.1 我们自己就在被这套规则瞄着

| 项 | 本机实测（2026-11-27） |
|---|---|
| Hermes 版本 | `v0.23.1+447.g448e307`（本地 commit `448e3072`，2026-11-09）· 上游审阅点 `7c34e2db`（2026-11-21） |
| profile 数 | 5（`default` / `general` / `curator` / `stock` / `gitncoding`） |
| `approvals.mode` | `curator: manual`、`stock: smart`、其余 3 个**未设 → 上游默认 `smart`**；**无 `off`** ✅ |
| 进程 | `python3 -m hermes_cli.main --profile default gateway run --quiet`；**12 个进程命令行含 `/.hermes/`** |
| `~/.hermes/SOUL.md` | 存在（根目录 + 4 个 profile 各一份，共 5 份），**不含**攻击人格 ✅ |
| `prefill.json` / `loot/` | **均不存在** ✅ |
| 端口 8878 / 9119 | **均未监听** ✅ |
| 攻击工具（nmap/nuclei/sqlmap/…） | 本机**未安装** ✅ |

### 7.2 误报清单（把上游规则搬到自有机队时必踩）

| 误报源 | 上游规则 | 本机实际情况 | 处置建议 |
|---|---|---|---|
| **godmode 越狱字符串** | YARA `Hermes_Godmode_Jailbreak_Installed`（`2 of $s*` 或 `prefill_messages_file`+`prefill.json`+1 个 `$s*`） | 实测命中 **21 个文件**（skills 目录内）/ 28 个（含 `.archive`、curator 备份、源码树、官网文档）——因为 Hermes **自带** `optional-skills/security/godmode`，且我们的 `red-teaming/llm-unrefusal` 里是同一套 `load_godmode.py`/`auto_jailbreak.py`/`parseltongue.py`/`godmode_race.py` | 上游规则注释自己写了 "matches by design"。**扫自机前必须把 `optional-skills/`、`*.archive/`、`red-teaming/llm-unrefusal/` 加白名单**，否则全量误报 |
| **SOUL.md 文件事件** | KQL `hermes/01` 分支 4：`FileName =~ "SOUL.md" and ActionType in (FileCreated, FileModified)` | 我们正常改 `SOUL.md` 就会触发 | 改用 YARA 内容匹配（`"SOUL - Red Team Operator"` / `"You are GH0ST"`）而不是文件事件 |
| **`/.hermes/` 进程命令行** | Sigma `selection_hermes` 正则含 `/\.hermes/`；KQL 分支 3 匹配 `InitiatingProcessCommandLine` | 12 个进程命中 | 需要同时命中 `selection_yolo` 才成立；但**任何提到 `~/.hermes` 路径的 wrapper/cron 都会被当「Agent 进程」** |

### 7.3 可直接复用的东西

1. **`hermes-selfcheck.sh`（见下）**——把上游 6 个检测点做成本机只读自查，**已在本机实跑，HIT = 0**。
2. **`frameworks/hermes/sigma/*.yml` 3 条 + `frameworks/hermes/yara/hermes.yar` 4 条**——可以直接进我们的 EDR/Sigma 管道（注意 `file_event` 那条是 linux-only，`process_creation` 与 YARA 跨平台）。
3. **`behaviors/`（跨框架）+ `general/`（非 Agent）**——这两层与 Hermes 无关，**适合做我们自己的通用狩猎基线**（密码喷洒节奏、UA 家族爆发、容器 registry 写测试、模型 API 出站）。
4. **`exposure/consoles.csv`**——8,531 条暴露控制台。**Hermes 2,226 条（全部 9119 仪表盘，0 蜜罐）** 是现成的情报：谁在公网跑着和 Hermes 一样的控制台。
5. **`docs/attack-coverage.md`**——1827 规则/124 技术的 ATT&CK 覆盖矩阵，可作为我们做「AI agent 类威胁」的 ATT&CK 基线。

### 7.4 附：本机自查脚本（已实跑）

```bash
#!/usr/bin/env bash
# hermes-selfcheck.sh —— 只读自查：对照 ThreatDefence/agentic-attack-detections 的
# frameworks/hermes 规则，检查本机 Hermes 是否带攻击者特征。
# 只读：不修改任何文件。用法: bash hermes-selfcheck.sh [HERMES_HOME]
#
# ⚠️ ps|grep 自匹配陷阱：grep 自己的命令行里含有模式串，会把自己算成命中。
#    本脚本用 "串拆分" 技巧（'--y''olo'）让模式不出现在 grep 的 argv 里，
#    并额外排除自身 PID 与脚本名。
set -uo pipefail

HERMES_HOME="${1:-$HOME/.hermes}"
RG="${RG:-rg}"
hits=0
SELF_PID=$$

hit()  { printf '  [HIT]  %s\n' "$1"; hits=$((hits+1)); }
ok()   { printf '  [ ok ]  %s\n' "$1"; }
info() { printf '  [ -- ]  %s\n' "$1"; }
sec()  { printf '\n== %s ==\n' "$1"; }

# 列出进程命令行，排除自身与 grep 自身
procs() {
  ps -Ao pid=,command= 2>/dev/null | awk -v self="$SELF_PID" -v me="$(basename "$0")" \
    '$1 != self && index($0, me) == 0 && $0 !~ /grep -/ {print $0}'
}

printf 'HERMES_HOME=%s\n' "$HERMES_HOME"

# --- 1. 审批被关闭 ---------------------------------------------------------
sec '1. approvals off'
cfgs=$(ls -d "$HERMES_HOME"/config.yaml "$HERMES_HOME"/profiles/*/config.yaml 2>/dev/null)
for c in $cfgs; do
  m=$(awk '/^approvals:/{f=1;next} f&&/^[^ ]/{f=0} f&&/mode:/{print $2;exit}' "$c" 2>/dev/null)
  case "$m" in
    off) hit "$c -> approvals.mode: off（危险命令无需人工确认）" ;;
    "")  ok  "$c -> 无 mode 键（上游默认 smart）" ;;
    *)   info "$c -> approvals.mode: $m" ;;
  esac
done
YOLO_PAT='--y''olo|HERMES_YOLO''_MODE'
if procs | grep -qE -e "$YOLO_PAT"; then
  hit '有进程带 --yolo / HERMES_YOLO_MODE'
else
  ok '没有进程带 --yolo / HERMES_YOLO_MODE'
fi

# --- 2. godmode 越狱技能 / prefill.json ----------------------------------
sec '2. godmode jailbreak skill'
for d in "$HERMES_HOME"/skills/security/godmode "$HERMES_HOME"/profiles/*/skills/security/godmode; do
  [ -d "$d" ] && hit "godmode 技能目录: $d"
done
for p in "$HERMES_HOME"/prefill.json "$HERMES_HOME"/profiles/*/prefill.json; do
  [ -f "$p" ] && hit "prefill 预填消息文件: $p"
done
for c in $cfgs; do
  grep -q "prefill_messages_file: *['\"]\?[^'\"[:space:]]" "$c" 2>/dev/null && hit "$c 设置了 prefill_messages_file"
done
scan_roots=()
for d in "$HERMES_HOME"/skills "$HERMES_HOME"/profiles/*/skills "$HERMES_HOME"/hermes-agent/optional-skills; do
  [ -d "$d" ] && scan_roots+=("$d")
done
if [ ${#scan_roots[@]} -gt 0 ]; then
  n=$("$RG" -l --no-messages -e 'G0DM0D3' -e 'Parseltongue' -e 'ULTRAPLINIAN' -e 'load_godmode' "${scan_roots[@]}" 2>/dev/null | wc -l | tr -d ' ')
  info "含越狱字符串的文件数（G0DM0D3/Parseltongue/ULTRAPLINIAN/load_godmode）: $n  <- 上游 YARA 会命中；源码树/自带技能属预期，不是入侵证据"
fi

# --- 3. 人格文件被替换 ----------------------------------------------------
sec '3. SOUL.md persona'
for f in "$HERMES_HOME"/SOUL.md "$HERMES_HOME"/profiles/*/SOUL.md; do
  [ -f "$f" ] || continue
  if grep -qiE 'SOUL - Red Team Operator|You are GH0ST' "$f" 2>/dev/null; then
    hit "$f 含攻击人格（Red Team Operator / GH0ST）"
  else
    ok "$f 未见攻击人格"
  fi
done

# --- 4. 技能数量 ----------------------------------------------------------
sec '4. skill 数量（上游案例: 121 个技能中 78 个与攻击相关）'
for d in "$HERMES_HOME"/skills "$HERMES_HOME"/profiles/*/skills; do
  [ -d "$d" ] || continue
  n=$(find "$d" -mindepth 1 -maxdepth 3 -name SKILL.md 2>/dev/null | wc -l | tr -d ' ')
  printf '  [ -- ]  %s -> %s 个 SKILL.md\n' "$d" "$n"
done

# --- 5. 控制面暴露 --------------------------------------------------------
sec '5. 控制面端口 8878 / 9119'
for port in 8878 9119; do
  if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q .; then
      hit "端口 $port 正在监听"
    else
      ok "端口 $port 未监听"
    fi
  else
    info "无 lsof，跳过端口 $port 检查"
  fi
done
DASH_PAT='hermes dash''board'
if procs | grep -q -e "$DASH_PAT"; then
  hit 'hermes dashboard 进程在跑'
else
  ok 'hermes dashboard 进程不在'
fi

# --- 6. loot 凭据目录 -----------------------------------------------------
sec '6. loot 凭据目录'
found=0
for d in "$HERMES_HOME"/loot "$HERMES_HOME"/profiles/*/loot; do
  [ -d "$d" ] && { hit "loot 目录: $d"; found=1; }
done
[ "$found" = "0" ] && ok '没有 loot 目录'

printf '\n== 结论 ==\n'
if [ "$hits" -gt 0 ]; then
  printf 'HIT 数 = %d —— 逐条人工确认后按处置流程走\n' "$hits"
else
  printf 'HIT 数 = 0 —— 未见攻击者特征\n'
fi
```

**本机实跑输出**：

```
HERMES_HOME=/Users/test/.hermes

== 1. approvals off ==
  [ ok ]  /Users/test/.hermes/config.yaml -> 无 mode 键（上游默认 smart）
  [ -- ]  /Users/test/.hermes/profiles/curator/config.yaml -> approvals.mode: manual
  [ ok ]  /Users/test/.hermes/profiles/general/config.yaml -> 无 mode 键（上游默认 smart）
  [ ok ]  /Users/test/.hermes/profiles/gitncoding/config.yaml -> 无 mode 键（上游默认 smart）
  [ -- ]  /Users/test/.hermes/profiles/stock/config.yaml -> approvals.mode: smart
  [ ok ]  没有进程带 --yolo / HERMES_YOLO_MODE

== 2. godmode jailbreak skill ==
  [ -- ]  含越狱字符串的文件数（G0DM0D3/Parseltongue/ULTRAPLINIAN/load_godmode）: 21  <- 上游 YARA 会命中；源码树/自带技能属预期，不是入侵证据

== 3. SOUL.md persona ==
  [ ok ]  /Users/test/.hermes/SOUL.md 未见攻击人格
  [ ok ]  /Users/test/.hermes/profiles/{curator,general,gitncoding,stock}/SOUL.md 未见攻击人格

== 4. skill 数量（上游案例: 121 个技能中 78 个与攻击相关） ==
  [ -- ]  ~/.hermes/skills -> 46 个 SKILL.md
  [ -- ]  ~/.hermes/profiles/curator/skills -> 111 个
  [ -- ]  ~/.hermes/profiles/general/skills -> 164 个
  [ -- ]  ~/.hermes/profiles/gitncoding/skills -> 48 个
  [ -- ]  ~/.hermes/profiles/stock/skills -> 173 个

== 5. 控制面端口 8878 / 9119 ==
  [ ok ]  端口 8878 未监听
  [ ok ]  端口 9119 未监听
  [ ok ]  hermes dashboard 进程不在

== 6. loot 凭据目录 ==
  [ ok ]  没有 loot 目录

== 结论 ==
HIT 数 = 0 —— 未见攻击者特征
```

> ⚠️ **脚本自坑（实跑踩到）**：`ps | grep -- '--yolo'` 会把 **grep 自己**算成命中（模式串出现在 grep 的 argv 里）。修法有两种，本脚本同时用了：`grep -qE -e "$PAT"`（模式作为独立参数仍会出现在 argv → 用 `'--y''olo'` **串拆分**让字面量不出现）+ `awk` 过滤自身 PID 与 `grep -` 行。
> ⚠️ 另一坑：`grep -rlE 'G0DM0D3|…' ~/.hermes` 在本机要 **2 分 09 秒**（扫了 cache/sessions/日志）；换成 `rg` 且只扫 skills 目录 → **0.2 秒**。

---

## 八、风险与局限

1. **零真实验证**：上游所有规则都没在真实入侵样本上跑过；README 自己要求「先在自己数据上基线」。
2. **误报面大**：godmode / SOUL.md / `/.hermes/` 三处在本机就会误报（§七·7.2）。
3. **平台偏向 Linux**：`file_event` 类 Sigma 只覆盖 linux；macOS 端点要靠 EDR 原生事件或自建脚本。
4. **数字漂移快**：11 天 11 个 release，README 数字普遍过期，引用必须标「实测日期 + commit」。
5. **暴露面数据的性质**：`exposure/` 是「某天互联网扫描快照」，且含大量蜜罐与他人资产，**不能当作我们的暴露面**。
6. **许可**：MIT，可自由改；改完记得跑 `tools/validate.py`（CI 会卡住没有 ATT&CK 编号的规则）。

---

## 九、参考链接

- 仓库（检测规则本体）: https://github.com/ThreatDefence/agentic-attack-detections
- 厂商说明页: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- 被检测对象: https://github.com/NousResearch/hermes-agent · godmode 技能: https://github.com/NousResearch/hermes-agent/tree/main/optional-skills/security/godmode
- 四个一手案例报告: Unit 42 https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/ · Hunt.io https://hunt.io/blog/thailand-ministry-finance-targeted-with-hermes-ai-agent · ThreatDown（Carbonato）https://www.threatdown.com/blog/carbonato/ · Gambit https://gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company
- 规则说明文档: `docs/attack-coverage.md` · `docs/adding-a-framework.md` · `docs/threat-intelligence-platforms.md`
- ATT&CK Navigator layers: `generated/attack/`（每框架一层 + 汇总层）
