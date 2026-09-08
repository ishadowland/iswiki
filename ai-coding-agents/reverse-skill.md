# reverse-skill — zhaoxuya520 的安全任务技能路由包 (33.7k ⭐)

> 学习笔记 · 调研时间 2026-09-01
> GitHub: <https://github.com/zhaoxuya520/reverse-skill>
> README: <https://github.com/zhaoxuya520/reverse-skill/blob/main/README.md>
> AI 入口: <https://github.com/zhaoxuya520/reverse-skill/blob/main/README_AI.md>
> 配套网站: <https://reverse.apivix.com/>

---

## 1. 一句话定位

**reverse-skill = AI Agent 的「安全/逆向/渗透」任务路由系统** — 给 Claude Code / Kiro / Cursor / Cline / Codex 等 AI 客户端用的**标准技能包**,**857 个文件 / 55 个 skill 模块 / R0-R39 路由规则 / 跨平台**(Windows PowerShell + Linux/macOS/Kali Bash)。

当 AI 遇到 APK / ELF / 前端 JS 加密 / CTF 题 / 渗透目标 / 报告生成,**自动路由到对应 skill,检查工具链,执行可复现 workflow**,而不是猜命令。

## 2. 核心数据

| 字段 | 值 |
|---|---|
| **GitHub stars** | **33,674** ⭐ (3.5 个月涨到 33k,增长极其快) |
| **Forks** | 4,554 |
| **License** | **MIT** |
| **Size** | 4.2 MB / **857 files** |
| **Language** | PowerShell (主) + Python + Bash + Markdown |
| **Created** | 2026-05-13 |
| **Updated** | 2026-09-01 (持续维护,3 天前 commit) |
| **Open issues** | 20 |
| **Watchers** | 33,674 (跟 stars 同,关注度极高) |
| **默认分支** | main |
| **Topics** | (空 — 但描述关键词: AI-powered routing / On-demand toolchain bootstrapping / Self-evolving knowledge base) |

## 3. 10 大顶层目录(857 文件分布)

```
reverse-skill/
├── skills/                       # ⭐ 核心(495 文件 / 5.6 MB)
│   ├── MASTER-ROUTING.md         # 快路径执行契约
│   ├── routing.md                # 3 轴路由矩阵(advisory)
│   ├── INDEX.md                  # 自动生成的 skill 索引
│   ├── config/routing.json       # ⭐ 路由 SSoT(单一事实源)
│   ├── 50 个 skill 子目录/       # 55 个 skill 模块
│   ├── ops/                      # 操作契约(scope/role/evidence)
│   ├── scripts/                  # PowerShell 脚本
│   ├── references/               # 社区 skill / agent 工作流参考
│   ├── tests/                    # 路由回归测试 (163 个 bilingual cases)
│   └── field-journal/            # 脱敏回写
├── CTF-Sandbox-Orchestrator/    # CTF 比赛编排(44 文件)
├── burp-mcp-full/               # Burp Suite MCP 集成(25 文件)
├── docs/                          # 平台部署文档
├── kali/                          # Kali Linux 专用
├── examples/                      # 示例
├── reports/                       # 报告模板
├── scripts/                       # 顶层脚本
├── .github/workflows/             # CI(auto-merge / ci / macos-bash-compat)
├── RULES.md                       # ⭐ 行为链 SSoT(23900 字符)
├── README.md / README_AI.md       # ⭐ AI 启动入口
├── AGENTS.md / CHANGELOG.md
└── LICENSE
```

## 4. 核心架构 — 3 层

```
┌──────────────────────────────────────────────────────────────────┐
│ Layer 0: AI 客户端入口(平台无关)                                    │
│  Claude Code / Kiro / Cursor / Cline / Codex CLI / Aider / etc  │
└──────────────────┬───────────────────────────────────────────────┘
                   │ 读 README_AI.md / RULES.md
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│ Layer 1: 路由层(SSoT = skills/config/routing.json)              │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐     │
│  │ master-route.  │  │ MASTER-ROUTING │  │  routing.md     │     │
│  │ ps1 / .sh      │  │  .md 优先级表  │  │  (3 轴矩阵)     │     │
│  │ (主入口)       │  │  (advisory)    │  │  (advisory)     │     │
│  └───────┬────────┘  └────────────────┘  └─────────────────┘     │
│          │                                                      │
│          ↓                                                     │
│  ┌─────────────────────────────────────────────────────┐       │
│  │ R0-R39 路由规则(must / mustAll / exclude 语义)        │       │
│  │ R1=APK R2=Mobile R6=IDA R11=Pentest R37=SAML ...     │       │
│  │ 输出 PRIMARY skill 路径                                │       │
│  └─────────────────────────────────────────────────────┘       │
└──────────────────┬───────────────────────────────────────────────┘
                   │ PRIMARY = "skills/<module>/SKILL.md"
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│ Layer 2: Ops 契约层(硬门槛,任何 ACT 之前必走)                    │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐  │
│  │ case-init       │  │ scope-contract   │  │ role-map       │  │
│  │ 创建 work/case/ │  │ auth.status 必须 │  │ lead/cie/cpe/  │  │
│  │ case 名/时间戳  │  │ = granted 才能   │  │ cre/cae/cbe/   │  │
│  │                 │  │ ACT(对目标动手)  │  │ cce/llm/doc    │  │
│  └─────────────────┘  └──────────────────┘  └────────────────┘  │
│  ┌─────────────────────────────────────────────────────┐       │
│  │ evidence-finding-path 证据链                          │       │
│  │ E-{nnn} 证据 → F-{nnn} Finding → P-{nnn} Path       │       │
│  └─────────────────────────────────────────────────────┘       │
└──────────────────┬───────────────────────────────────────────────┘
                   │ PRIMARY skill + scope ready_for_act=true
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│ Layer 3: Skill 执行层(55 个 skill 模块)                          │
│  ┌─────────────────────────────────────────────────────┐       │
│  │ skills/<PRIMARY>/SKILL.md(详细工作流)              │       │
│  │  + scripts/(封装好的 PowerShell 脚本)              │       │
│  │  + references/(背景知识)                          │       │
│  └─────────────────────────────────────────────────────┘       │
│  → 工具检测: tool-index.md (gitignored,首次需 refresh)         │
│  → 缺工具: bootstrap-reverse.(ps1|sh)(仅 manifest 能力)        │
└──────────────────────────────────────────────────────────────────┘
```

## 5. RULES.md — 行为链 SSoT(最强约束)

RULES.md 是**仓库最高约束**(23900 字符),要求 AI:

```text
1. NOW:  读完立即执行(不要只回 "ok got it" / "请告诉我任务" / 等待确认)
2. NOW:  运行平台原生 router → PRIMARY(SSoT = skills/config/routing.json)
3. NEXT: 运行 case-init 直到 scope.md 满足 auth.status=granted + 合法 network_profile
4. ACT:  打开 PRIMARY 的 SKILL.md → 执行 ACTION REQUIRED
5. 工具只从 tool-index.md 取,缺则 bootstrap
6. 追加 timeline + workitems,结论走 Evidence→Finding→Path
7. 客户端集成边界:Claude Code/Cursor/Codex 等客户端是适配层,不是核心依赖
```

**关键哲学**:**AI 不是被告知"请告诉我任务",而是必须"立即执行"**(针对 LLM 的「等确认」excuse 现象做了 rebuttal 表)。

## 6. 路由层 — R0-R39 + JSON SSoT

### 6.1 单一事实源(routing.json)

```json
{
  "schemaVersion": "1.0",
  "fallbackId": "R0",
  "scoring": "每条关键字规则命中后计入候选集;
              按 priority 数组顺序取『命中分数最高』的为 PRIMARY;
              分数并列时 priority 靠前者胜出;未命中回退 R0",
  "routes": {
    "R1": { "label": "APK reverse", "skill": "apk-reverse/SKILL.md",
            "keywords": [{"must": "\bapk\b|smali|jadx|apktool|..."}] },
    "R2": { "label": "Mobile reverse", "skill": "mobile-reverse/SKILL.md",
            "keywords": [{"must": "\bipa\b|ios.?reverse|..."},
                         {"must": "越狱", "exclude": "模型|提示词|llm|prompt|jailbreak|..."}] },
    ...
  }
}
```

### 6.2 路由语法语义

- **must** — 必须命中(正则表达式)
- **mustAll** — 必须同时全部命中(数组 AND)
- **exclude** — 必须排除(避免误判)
  - 例:「越狱」裸词分给 iOS,排除 LLM 上下文「jailbreak」
- **fallbackId** — 未命中时回退 R0

### 6.3 优先级表(40 条路由简表)

| ID | 条件 | PRIMARY skill |
|----|------|---------------|
| R1 | APK / smali / jadx / apktool | `apk-reverse/` |
| R2 | IPA / iOS / Objection / MobSF | `mobile-reverse/` |
| R3 | JS 签名 / 前端加密 / jshook / CDP | `js-reverse/` |
| R4 | DSL VM / fireye / 自定义 opcode VM | `reverse-engineering/dsl-vm-reverse/` |
| R5 | .NET / dnSpy / de4dot / ConfuserEx | `dotnet-reverse/` |
| R6 | IDA / 反编译 / 反汇编 | `ida-reverse/` |
| R7 | radare2 / r2 | `radare2/` |
| R8 | 固件 / binwalk / IoT / EMBA | `firmware-pentest/` |
| R9 | 恶意样本 / YARA / 沙箱 | `malware-analysis/` |
| R10 | 红队 / 完整渗透 / 横向移动 | `attack-chain/` |
| R11 | nmap / nuclei / sqlmap / ffuf / 渗透 | `pentest-tools/` |
| R12 | API 安全 / GraphQL / BOLA / OAuth | `api-security/` |
| R17 | Pwn / ROP / 堆栈利用 | `pwn-chain/` |
| R18 | EDR 免杀 / syscall | `edr-bypass-re/` |
| R24 | Windows AD / Kerberos / AD CS | `windows-ad/` |
| R30 | 浏览器扩展逆向 | `browser-extension-reverse/` |
| R31 | macOS / Mach-O | `macos-reverse/` |
| R33 | Go / Rust 二进制 | `go-rust-reverse/` |
| R37 | SAML / OIDC / SSO | `identity-federation/` |
| ... | (共 R0-R39) | ... |

## 7. Ops 契约层 — 4 大硬约束

### 7.1 scope-contract.md(任务启动硬门槛)

任何安全/逆向/渗透任务在 **ACT 之前**必须在 `work/<case>/` 落地 `scope.md`:

```yaml
auth:
  status: granted | pending | denied    # MUST = granted
  basis: written_contract | bug_bounty_scope | ctf_public | own_system | lab_only
  evidence_of_auth: <ticket / path / CTF public / owner-operated>

in_scope:
  assets: []                             # 主机/域/APK 路径/URL
  surfaces: []                           # web / mobile / binary / network / api
  activities: []                        # recon / reverse / exploit_validate / report

network_profile:
  mode: offline | lab_only | authorized_target_only | unrestricted_lab

signoff:
  ready_for_act: false                  # 必须 true 才能 ACT
```

**硬门**:`-Force` / `--force` **不能绕过** auth / scope / network_profile / ready_for_act。

### 7.2 role-map.md(角色→skill 映射)

不真起多 Agent(无 Z3r0 API 依赖),**单人会话内通过角色前缀模拟**:

```
[lead] 规划 + 阶段门控
[cie]  情报收集(资产发现) → pentest-tools (recon)
[cpe]  渗透验证(扫描/利用) → pentest-tools
[cre]  逆向分析(二进制/固件/移动/前端) → ida-reverse / apk-reverse / ...
[cae]  代码审计 → code-audit + supply-chain-security
[cbe]  蓝队/取证 → threat-hunting / digital-forensics
[cce]  密码学 → reverse-engineering 模式文档
[llm]  AI 安全(Prompt/Agent) → llm-security
[doc]  文档官(报告/writeup/图) → docs-generator + diagram-generator
```

### 7.3 evidence-finding-path.md(证据链)

```
E-{nnn}  Evidence (不可变观察)   ←  command | screenshot | file | log | memory | network | manual
                                sha256 hash, repro_command, raw_excerpt
    ↓ 引用
F-{nnn}  Finding   (安全/逆向结论)  ←  severity, evidence_ids, location, repro_steps, remediation
    ↓ 引用
P-{nnn}  Path      (攻击路径/调用链/解题路径)
                                path_type: attack | callflow | solve
                                每步可关联 Evidence + Finding
```

**约束**:`evidence_ids` 非空,`status=validated` 时 confidence 不得为 low。

### 7.4 master-route 路径(执行契约)

```
1. 先路由后动手
2. 输出 PRIMARY 路径 + 一句话依据
3. case-init / scope.md(auth 未 granted 禁止 ACT)
4. 指定 lead + specialist 角色
5. 立即打开 PRIMARY 的 SKILL.md → ACTION REQUIRED
6. 工具路径只认 tool-index.md;缺则 bootstrap
7. 过程追加 timeline / workitems;结论走 Evidence→Finding→Path
8. 未命中 → 读 routing.md 全表或提议新 skill
```

## 8. 跨平台支持 — Windows + Linux + macOS + Kali

**设计哲学**:PowerShell + Bash **同 routing 契约** — 平台只改变执行入口,不改变 semantics。

|平台 | Router 入口 | Case-init | Bootstrap | Refresh-tool-index |
|-----|-------------|-----------|-----------|---------------------|
| **Windows** | `master-route.ps1` | `case-init.ps1` | `bootstrap-reverse.ps1` | `refresh-tool-index.ps1` |
| **Linux / macOS** | `master-route.sh` | `case-init.sh` | `bootstrap-reverse.sh` | `refresh-tool-index.sh` |
| **Kali** | `master-route.sh` (复用) | `case-init.sh` (复用) | `kali/scripts/bootstrap-reverse.sh` | `kali/scripts/refresh-tool-index.sh` |

== **关键**:**Linux/macOS 不需要 PowerShell**,核心路由/case 流程用 Bash 跑 — 大大降低非 Windows 用户门槛。

## 9. CTF-Sandbox-Orchestrator 子模块(44 文件)

CTF 比赛自动化编排器,**42 个独立 skill**:

```
CTF-Sandbox-Orchestrator/
├── README.md
├── competition-ad-certificate-abuse/    # AD 证书滥用
├── competition-agent-cloud/             # 代理云
├── competition-android-hooking/         # Android Hook
├── competition-browser-persistence/     # 浏览器持久化
├── competition-bundle-sourcemap-recovery/ # webpack sourcemap
├── competition-cloud-metadata-path/      # 云元数据
├── competition-container-runtime/        # 容器运行时
├── competition-crypto-mobile/            # 移动加密
├── competition-custom-protocol-replay/   # 自定义协议重放
└── ... (42 个)
```

每个 competition 目录有 **3 个标准文件**:
- `SKILL.md` — 技能描述
- `agents/openai.yaml` — OpenAI agent 配置
- `references/<topic>.md` — 背景知识

== **设计模式**:**每个场景独立 skill,标准 3 文件结构** — 完美示范 skill 包的扩展性。

## 10. 工具链 — 自动检测 + bootstrap

### 10.1 tool-index.md(运行时工具清单)

- **gitignored**(每台机器不同)
- 首次运行通过 `refresh-tool-index.{ps1|sh}` 生成
- 列出已安装工具 + 实际路径 + 版本
- master-route 只认这个清单,**不猜路径**

### 10.2 bootstrap(按需自举)

**仅 manifest 能力**(不下载具体工具,提供安装指引):

- `bootstrap-reverse.ps1`(Windows)
- `bootstrap-reverse.sh`(Linux/macOS)
- `kali/scripts/bootstrap-reverse.sh`(Kali)

== **关键设计**: bootstrap 只给**能力声明**,不主动下载 — 防止 supply chain attack(所有版本必须有 pin)。

### 10.3 供应链 pin gate

`verify-routing-coherence.ps1` 校验:**任何 auto-install 能力必须有**:
- `pinnedVersion` / `pinnedCommit` / `pinPolicy` / asset hash

== **Pinned 实例**:frida-tools 14.10.4, pwntools 4.15.0, agent-browser 0.31.1, nuclei v3.9.0, SecLists/ProxyCat @commit。

## 11. 4 大核心设计哲学

1. **SSoT(单一事实源)**
   - `routing.json` = 路由 SSoT,`RULES.md` = 行为链 SSoT,`tool-index.md` = 工具 SSoT
   - 改路由只改 JSON;改行为链只改 RULES.md
   - 任何「散落在 markdown / ps1 里的硬编码路由表」都是 anti-pattern

2. **Platform-neutral + adapter**
   - 核心 routing / tests / manifests / case workflows 不依赖任何 AI 客户端
   - Claude Code / Codex / Cursor / OpenCode 通过**适配层**接入,核心配置零修改

3. **「Don't acknowledge, EXECUTE」**
   - RULES.md 顶部强调:读完立即执行,不回 "understood / got it"
   - 有专门的 `agent-obedience-engineering.md` 反驳 excuse 表(LLM Security 子模块)

4. **硬门 vs 软门**
   - 硬门:`auth.status=granted` + `ready_for_act=true` + `network_profile` 合法 → 才能 ACT
   - `-Force` / `--force` **不能绕过**
   - 软门:`routing.md` advisory,允许 JSON SSoT 覆盖

## 12. 5 大 CI 工作流

```
.github/workflows/
├── auto-merge-journal.yml        # 自动合并 journal PR(7503 b)
├── ci.yml                       # 主 CI(14017 b)
└── macos-bash-compat.yml        # macOS Bash 兼容(2456 b)
```

== **CI 关注点**:
- 路由回归测试(`test-routing.ps1`)
- 一致性校验(`verify-routing-coherence.ps1`)
- Supply-chain pin gate
- 客户端边界(不得写 client-global config)
- PS 5.1 UTF-8 BOM(避免非 ASCII 字符串乱码)

## 13. CHANGELOG 风格(Keep a Changelog)

[Unreleased] / [1.0.1] - 2026-08-08 / 等版本,严格区分 **Added / Fixed / Changed / Removed**,**重大变更逐条记录**(例:IDA open lock files, MCP keep-alive, coherence clamp identity-preserving)。

== **关键**: 这是工程化做法,跟「普通 commit message」完全不同 — 跟 hermes-agent / OpenOPC 的 AGENTS.md 哲学一致。

## 14. 跟我已有项目的可借鉴性

### 14.1 跟 OpenOPC 对比

| 维度 | reverse-skill | **OpenOPC (我 fork)** |
|---|---|---|
| **目标** | 单 Agent 跑安全任务 | 多 Agent 跑业务任务 |
| **Agent 编排** | 单会话内角色前缀 | Hermes adapter + external agents |
| **路由** | JSON SSoT + 40 路由规则 | 内部 LLM 决策 |
| **Ops 契约** | scope / role / evidence / path | approval_allowlist |
| **跨平台** | PS + Bash + Kali | Linux only(Python venv) |
| **Skill 数** | 55 | 6 adapters |
| **Bootstrap** | 工具自举 + pin gate | MCP stdio watchdog(易 park) |

### 14.2 跟 hermes-agent skill 系统对比

| 维度 | reverse-skill | **hermes-agent** |
|---|---|---|
| **Skill 格式** | `<name>/SKILL.md` + YAML frontmatter | `<name>/SKILL.md` + YAML frontmatter |
| **Skill 发现** | INDEX.md (动态生成) | `skills_list` tool |
| **加载时机** | master-route 按 PRIMARY 加载 | 按 `--skills SKILLS` 参数预加载 |
| **跨平台** | PS + Bash | Python only |
| **MCP 集成** | 通过 MCP(如 anything-analyzer) | 通过 MCP stdio watchdog |
| **Routing 自动化** | JSON 关键词 + scoring | LLM 自己决定 |

### 14.3 5 大可借鉴元素

1. **routing.json + 关键词 must/exclude 语义**
   - OpenOPC 可以加 routing 层,按 query 类型分到不同 agent
2. **SSoT 原则**(RULES.md / routing.json / tool-index.md 各一个 SSoT)
   - hermes-agent config.yaml + skills 多源,容易矛盾;可以学 single-source
3. **「Don't acknowledge, EXECUTE」哲学**
   - 反 LLM 「等确认」行为,适合自动化 agent
4. **Platform-neutral + adapter pattern**
   - 核心能力跟具体客户端解耦,我 fork 的 OpenOPC 也应该这么做
5. **Evidence → Finding → Path 证据链**
   - 我写 iswiki 调研时,可以学这个结构(Evidence 引用 / Finding 分类 / Path 推导)

## 15. 完整 WP 视角(如果我要 fork)

| WP | 内容 | 估时 |
|---|---|---|
| **WP-R1** | 把 reverse-skill clone 到本机 + 运行 master-route.ps1 | 0.5d |
| **WP-R2** | 跑一次 case-init (无授权目标,验证流程) | 0.5d |
| **WP-R3** | 跑一次 R6(IDA reverse)skill,分析一个真实 ELF | 1d |
| **WP-R4** | 适配 hermes-agent:把 reverse-skill 作为可选 skill 包 | 2d |
| **WP-R5** | 加到 OpenOPC external agent 列表 | 1d |

## 16. 适用 substation-blueprint 的可借鉴元素

substation-blueprint 是 **Three.js 3D 可视化**,跟安全/逆向无关。但 reverse-skill 的 **架构模式**完全可学:

1. **SSoT 架构** — substation-blueprint 当前 14 个 WebP 资产散在 `secret-pathways-assets/` 目录,如果加 asset-registry SSoT 是不是更好?
2. **JSON 路由 + 关键词语义** — substation-blueprint 可以加 `config/scene-modes.json`,按 URL `?mode=` 路由到不同 demo
3. **CHANGELOG 风格** — substation-blueprint 改用 Keep a Changelog
4. **Platform-neutral** — single HTML + vendored three.min.js 已经做对了
5. **「Don't acknowledge, EXECUTE」** — 写一个 RULES.md 给未来 AI agents 用(给 kage / vgpu / openopc 同样的入口)

## 17. 相关 iswiki 项目

- **[mattpocock-skills](mattpocock-skills.md)** — TypeScript AI agent skill 集
- **[openopc](openopc.md)** — AI-Native Company 多 Agent 编排(含 hermes_adapter)
- **[openclaw-awd-arena](openclaw-awd-arena.md)** — 多 Agent 对抗训练(含 hermes_backend)
- **[zhaoxuya520/reverse-skill](reverse-skill.md)** — 安全/逆向/渗透技能路由包(本文, 33.7k ⭐)

## 18. TL;DR

**reverse-skill = zhaoxuya520 的 AI 安全任务路由包**,3.5 个月涨到 33,674 ⭐,857 文件 / 55 skill / R0-R39 路由 / 跨平台 PS+Bash+Kali。

==**3 大核心**:
1. **routing.json SSoT** — 40 路由规则,must/mustAll/exclude 语义
2. **Ops 契约硬门** — scope.md(auth+network_profile) → role-map → evidence-finding-path
3. **跨平台不改变 routing semantics** — PowerShell / Bash 同 contract,客户端是适配层

==**3 大借鉴**:
1. **routing.json + JSON 单一事实源**(我 fork 的 OpenOPC 应该学)
2. **「Don't acknowledge, EXECUTE」** 哲学
3. **Platform-neutral + adapter pattern**

==**最值得学的 1 点**:**「RULES.md 是行为链 SSoT,tool-index.md 是工具 SSoT,routing.json 是路由 SSoT」** — 任何复杂 skill 包都应该有这种「每个关注点一个 SSoT」的设计纪律。
