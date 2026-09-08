# Anthropic Cybersecurity Skills — 817 攻防安全技能库

> 学习笔记 · 调研时间 2026-08-22
> 仓库: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills>
> 介绍文章: <https://mp.weixin.qq.com/s/8wTPixeLFZdGnOBc07NmLw>(公众号 "繁星AI随笔" 2026-08-18)
> ⭐ 30,569 · 3,636 forks · Apache 2.0 · 13.7 MB · Python · Created 2026-02-25
> ⚠️ **独立社区项目**(作者: Mahipal Jangra / mukul975),**与 Anthropic PBC 无关联**

## 一句话定位

**817 个结构化网络安全技能 + 6 大框架映射 + 26+ 平台兼容 + agentskills.io 开放标准** —— 把安全分析流程**结构化**,让 AI agent 能像资深安全分析师一样**威胁狩猎 / 数字取证 / 渗透测试 / 应急响应 / 云安全 / 红队**。**`npx skills add mukul975/Anthropic-Cybersecurity-Skills`** 一行安装。

## 跟 iswiki 现有工具的关系

| 工具 | 关系 |
|---|---|
| [mattpocock-skills](mattpocock-skills.md) | 🟢 **同源** — 都是 agentskills.io 标准,25+ 技能 |
| [i-have-adhd](i-have-adhd.md) | 🟡 都是 SKILL.md 风格,被相同生态加载 |
| [codex-security](codex-security.md) | 🟢 都是 cybersecurity + 适合 agent 集成 |
| [qoder-security](qoder-security.md) | 🟡 同样面向 AI 编码工具的安全 |
| [paseo](paseo.md) | 🟡 Paseo 是 multi-agent orchestrator,本仓库是单 agent 技能 |

## 6 大映射框架

| 框架 | 用途 | 关键覆盖 |
|---|---|---|
| **MITRE ATT&CK** | 攻击战术 / 技术 | 14 tactics, 200+ techniques (T1005 / T1074 等) |
| **NIST CSF 2.0** | 网络安全框架 | RS.AN / DE.AE / RS.MA 等 function IDs |
| **MITRE ATLAS** | AI 攻击矩阵 | ML supply chain / prompt injection |
| **D3FEND** | 防御技术 | 已知防御 / 检测技术 |
| **NIST AI RMF** | AI 风险管理 | Govern / Map / Measure / Manage |
| **MITRE F3 (Fight Fraud)** | 反欺诈 | 2026-04-09 发布(填补 ATT&CK 金融欺诈空白) |

## 6 大框架 vs 817 技能 mapping

每个 SKILL.md frontmatter 显式标注:
```yaml
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, autopsy, disk-analysis, ...]
nist_csf: [RS.AN-03, DE.AE-02, RS.MA-01]
mitre_attack: [T1005, T1074.001, T1083]
```

→ **机器可读 + 双向 query** = agent 能按 ATT&CK ID 反查 skill

## 29 个安全领域

| 域 | 技能数 | 关键能力 |
|---|---|---|
| **Cloud Security** | 66 | AWS/Azure/GCP 加固 · CSPM · 云攻击模拟 · 云取证 |
| **Threat Hunting** | 58 | 假设驱动 hunting · LOTL 检测 · EVTX hunting |
| **Threat Intelligence** | (待补) | APT group 分析 · campaign attribution |
| **Digital Forensics** | (待补) | DFIR · 磁盘镜像 · 恶意软件分析 |
| **Penetration Testing** | (待补) | Red team · C2 · 漏洞利用 |
| **Incident Response** | (待补) | IR playbooks · 应急恢复 |
| ... (24 more) | | |

## 安装 (3 步)

```bash
# 1) npx skills add (recommended)
npx skills add mukul975/Anthropic-Cybersecurity-Skills

# 2) Or clone
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
cd Anthropic-Cybersecurity-Skills

# 3) 立即生效 (任何支持 agentskills.io 标准的平台)
# Claude Code / Cursor / OpenAI Codex CLI / GitHub Copilot / Gemini CLI /
# Windsurf / Cline / Aider / Continue / Roo Code / Amazon Q Developer /
# Tabnine / Sourcegraph Cody / JetBrains AI / Devin / Replit Agent /
# SWE-agent / OpenHands / LangChain / CrewAI / AutoGen / Semantic Kernel /
# Haystack / Vercel AI SDK / **Any MCP-compatible agent**
```

## agentskills.io 开放标准 (3 阶段渐进式披露)

```
Discovery (启动):
  Agent 启动时,只加载技能的 name + description
  → 节省 context (不加载完整 SKILL.md)

Activation (激活):
  当任务与技能 description 匹配时,加载完整 SKILL.md
  → 进入 context window

Execution (执行):
  Agent 按指令执行,可按需调用 scripts/ 加载 references/
  → 真实工具调用
```

## 完整 SKILL.md 结构 (符合 agentskills.io 标准)

```text
my-skill/
├── SKILL.md       # Required: metadata + instructions
├── scripts/       # Optional: executable code (Python)
├── references/    # Optional: documentation / data files
├── assets/        # Optional: templates, resources
└── ... # Any additional files
```

### SKILL.md frontmatter example (取自 `analyzing-disk-image-with-autopsy`)

```yaml
---
name: analyzing-disk-image-with-autopsy
description: Perform comprehensive forensic analysis of raw (dd), E01, or AFF disk images with Autopsy and The Sleuth Kit, recovering deleted files, examining metadata and embedded artifacts, keyword searching, and building investigation timelines with visual reports. Use for structured analysis of a forensic disk image or when stakeholders need visual reports from evidence.
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- autopsy
- disk-analysis
- sleuth-kit
- file-recovery
- artifact-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
mitre_attack:
- T1005
- T1074.001
- T1070.004
- T1083
---
```

## 实际可迁移性分析 (用户问题核心)

### 🎯 迁移到 Hermes (NousResearch/hermes-agent)

**✅ 可以,直接可用** — README badge 显式声明:
> `[![Hermes Agent](https://img.shields.io/badge/Hermes_Agent-compatible-blueviolet)](https://github.com/NousResearch/hermes-agent)`

**Why**: 
- 符合 **agentskills.io 开放标准** (Hermes 支持)
- Hermes `optional-skills/security/` 目录已存在 (有 1password / oss-forensics / sherlock / web-pentest)
- 安装方法:
  ```bash
  # 方式 1: npx skills (通用)
  npx skills add mukul975/Anthropic-Cybersecurity-Skills
  
  # 方式 2: 手动 (跟现有 skills 同级)
  cd ~/.hermes/hermes-agent/optional-skills/security/
  git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
  mv Anthropic-Cybersecurity-Skills anthropic-cybersecurity-skills
  ```

**问题**:
- 817 个 skill 文件 = 大量 discovery metadata
- Hermes 当前 skills 都是**单 SKILL.md**,817 个嵌套目录可能不匹配 Hermes 的 flat load 行为
- 需要在 Hermes skill loader 加 **agentskills.io standard support** (progressive disclosure)

**建议**: 写一个 **wrapper skill**(单 SKILL.md) — 内部 引用 Anthropic Cybersecurity Skills 的 index.json,按需调阅

### 🎯 迁移到 opencode (anomalyco/opencode)

**✅ 可以** — opencode 是 200k ⭐ 的 sst/opencode fork(实际上是 anomalyco/opencode):
- 200,119 ⭐ · MIT · "The open source coding agent"
- opencode 内置**MCP client** + plugin system
- 符合 **agentskills.io 标准**
- 安装:
  ```bash
  npx skills add mukul975/Anthropic-Cybersecurity-Skills
  # 或
  opencode plugin add https://github.com/mukul975/Anthropic-Cybersecurity-Skills
  ```

**优势**:
- opencode 设计就是 coding-focused,正好对接 817 个 security skills
- 提供 `npx skills` CLI,install UX 一致

### 🎯 迁移到 zcode (Zed / Z.ai GLM)

**两种可能**:

**1) Zed (Zed Industries editor) — zed-industries/zed (89k ⭐)**:
- Zed 是 Rust 写的 code editor
- **有 extensions API** 但**没有 agent runtime**(不是 agent)
- 不适合作为 skill host(它是 IDE)
- 适合:**IDE 内调用 LLM** 时,manually load Anthropic Cybersecurity Skills 作为 reference

**2) Z.ai ZCode (智谱)**:
- **没有找到 zcode-ai/zcode repo**
- bruce-drawio 提"zcode" 是个**老 plugins 名**,与本项目无关
- FrostLeafKEE/wanx-draw-skill 提"ZCode skill" 是**画图 skill**,不是 agent
- 智谱有 **GLM-Code (智谱代码)**,但不是 zcode

**结论**: "zcode" likely = **Zed editor**,不适合作为 agent skill host。Z.ai GLM 通过 **MCP / OpenAI 兼容 API** 接 Hermes / opencode 即可,**不需要 direct integration**。

## 5 大适移原则 (你问"能否迁移")

| 原则 | Hermes | opencode | zcode (Zed) |
|---|---|---|---|
| **agentskills.io 标准支持** | ✅ 显式兼容 badge | ✅ 内置 npx skills | ❌ 不是 agent |
| **Single-file install** | ✅ 已有 skills 目录 | ✅ plugin add | ❌ 无 system |
| **MCP protocol** | ✅ 任意 MCP agent | ✅ 内置 | ⚠️ 仅作 client |
| **Directory structure match** | ⚠️ 817 嵌套目录,需 wrapper | ✅ 设计为多 skill | ❌ 不适用 |
| **实时 loading (progressive)** | ⚠️ Hermes flat load 需改 | ✅ 内置 | ❌ 不适用 |

## ⚠️ 注意:合法 + 道德使用

> **项目包含攻击性 / 双重用途技术**(红队 C2 / 钓鱼模拟 / 漏洞利用)

**只可对**:
- 你**自己拥有**的系统
- 你**获得明确书面许可**的系统
- 授权渗透测试 / 安全研究 / 防御 / 教育

**不可对**:
- 未授权系统
- 商业间谍
- 任何违法活动

> "You are solely responsible for how you use the library." — README 明确声明

## 局限 (原文引用)

- **"production-grade" 不等于 "production-ready"**: 817 个 skill 社区贡献,有些打磨细致,有些**只是粗略操作步骤**,**生产前必须逐个验证**
- **没认证** — 没 WCAG / SOC2 等
- **质量参差** — 需要 reviewer
- **License 重要但贡献者未一一验证** — 双重 license 风险

## 跟 Hermes 现有 security skills 对比

| 现有 skill | 范围 | vs Anthropic Cybersecurity Skills |
|---|---|---|
| **1password** | Secret 管理 | Anthropic Cybersecurity Skills 不覆盖 secret 管理 |
| **godmode** | Red team (单一) | **817 vs 1** — 范围大 |
| **oss-forensics** | 开源取证 | Anthropic Cybersecurity Skills 覆盖更广 |
| **sherlock** | OSINT / username | 互补(不重复) |
| **unbroker** | 漏洞利用 (单一) | **817 vs 1** |
| **web-pentest** | Web 渗透 (单 skill) | **817 vs 1** |

→ **Anthropic Cybersecurity Skills 几乎 = Hermes security/ 的全集 + 812 个新 skills**

## 6 步推荐迁移 plan (到 Hermes)

```bash
# 1) 备份现有 security skills
cp -r ~/.hermes/hermes-agent/optional-skills/security/ \
      ~/hermes-security-backup/

# 2) Clone Anthropic Cybersecurity Skills
cd ~/.hermes/hermes-agent/optional-skills/security/
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git \
            anthropic-cybersecurity-skills
cd anthropic-cybersecurity-skills

# 3) 写 wrapper SKILL.md
cat > SKILL.md << 'EOF'
---
name: anthropic-cybersecurity-skills
description: 817 cybersecurity skills for AI agents (cyber threat hunting, DFIR, pentest, cloud security, malware analysis, red team, OSINT, MITRE ATT&CK mapping).
version: 1.1.0
author: mukul975 (community project)
license: Apache-2.0
platforms: [linux, macos]
metadata:
  hermes:
    tags: [security, cybersecurity, mitre-attack, dfir, pentest, red-team, agentskills-io]
    related_skills: [godmode, oss-forensics, sherlock, unbroker, web-pentest]
    fallback_for_toolsets: []
  upstream:
    repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
    registry: https://agentskills.io
    version: 1.1.0
---

# Anthropic Cybersecurity Skills (817 skills wrapper)

This is a Hermes-side wrapper for the upstream Anthropic Cybersecurity Skills
library (817 skills, MITRE ATT&CK mapped, Apache 2.0).

## When to use

- Threat hunting (LOTL detection, EVTX, hypothesis-driven)
- Digital forensics (Autopsy, Volatility, disk image analysis)
- Penetration testing (red team, exploitation, C2)
- Cloud security (AWS/Azure/GCP hardening)
- Malware analysis (static + dynamic)
- Threat intelligence (APT group attribution)
- Incident response (playbooks, IR procedures)

## Important

**Authorized use only.** Contains offensive / dual-use techniques.
You are solely responsible for lawful use per README.

## How it works (agentskills.io standard)

This wrapper delegates to the upstream `mukul975/Anthropic-Cybersecurity-Skills`
repository which provides 817 skills via `npx skills add` and `git clone`.
Each individual skill follows the agentskills.io progressive disclosure:
- Discovery: name + description only at startup
- Activation: full SKILL.md on task match
- Execution: scripts/ + references/ on demand
EOF

# 4) Hermes reload (restart)
hermes skills list

# 5) Verify
# Should see "anthropic-cybersecurity-skills" in the list

# 6) Test
# In a Hermes session: "use anthropic-cybersecurity-skills to analyze..."
```

## 适用 / 不适用

| ✅ 适合 | ❌ 不适合 |
|---|---|
| 红队 / 蓝队 / DFIR / IR / ThreatIntel | 单纯代码 review |
| 安全研究 / pentest 培训 | Production SOC analyst (需要 vendor tool) |
| AI agent 自动化安全任务 | 需 SIEM / SOAR 集成的大型企业 |
| 教育 (学生练) | 涉密 (部分内容可能 restricted) |
| 渗透测试 / 漏洞赏金 | 黑客 / 违法 |

## 风险与限制

- **Apache 2.0 ✓** — 商业可用
- **License 风险:每个 skill 可能含第三方 snippet** — 需 review
- **No SLA** — 社区项目
- **质量参差** — 817 个 skill,有些**只粗略**
- **不能直接用于 production** — 需 reviewer 验证
- **安全双重用途** — 攻击性技术存在,可能**违反某些公司 policy**
- **依赖外部 tool**(如 Volatility / Autopsy / SharpDPAPI) — 不是 standalone
- **没 Semantic version 锁定** — 跟 npx skills 每次都拉 latest
- **47 open issues** — 社区项目维护

## 8 大相关项目 / 工具

- **agentskills.io** — 技能标准
- **awesome-agent-skills** — VoltAgent/awesome-agent-skills (1,000+ skills 索引)
- **awesome-ai-security** — ottosulin/awesome-ai-security
- **awesome-codex-cli** — RoggeOhta/awesome-codex-cli
- **SkillsLLM** — skillsllm.com (skills marketplace)
- **Openflows** — openflows.org (signal analysis)
- **NeverSight/skills_feed** — automated skills index
- **Casky.ai** — 作者 playground,AI cybersecurity 训练

## 4 大科研活动

- **GARS-2026** — Global Agentic AI Readiness Survey (作者 60 题目调研)
- **SRH Berlin 监督** — 学术合作
- **结果 CC-BY 4.0** — 开源
- 50 Casky Tokens 激励

## 类似 / 对比项目

| 项目 | 类似 | 区别 |
|---|---|---|
| **Strix** | AI 渗透测试 | Strix 主动攻击,Anthropic Cybersecurity Skills 包含攻防双向 |
| **Claude Code Security Guidance** | Claude 内置 | Anthropic Cybersecurity Skills 是外部增强库 |
| **OSCP / SANS** | 攻防教育 | Anthropic Cybersecurity Skills 是 AI 化的 OSCP 知识 |
| **MITRE ATT&CK Navigator** | 框架可视化 | Anthropic Cybersecurity Skills 包含执行细节 |
| **WADComs / HackTricks** | 命令集合 | Anthropic Cybersecurity Skills 包含**完整工作流** (prerequisites + verification) |

## 跟 Matt Pocock Skills 对比

| 维度 | Matt Pocock (25 skills) | Anthropic Cybersecurity (817 skills) |
|---|---|---|
| 范围 | 通用软件工程 (TDD / planning) | 单一领域 (cybersecurity) |
| 哲学 | 小的 + 可组合 | "production-grade" 但实际参差 |
| 框架映射 | 无 | 6 框架(ATT&CK / NIST / ATLAS / D3FEND / AI RMF / F3) |
| 适用 | 任何 coding agent | cybersecurity + 红蓝队 |
| 评级 | 高(单一作者 + 10K+ ⭐) | 中(社区 + 30K+ ⭐) |

## 关联资料

- 仓库: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills>
- 作者: Mahipal Jangra (mukul975)
- 介绍文章: <https://mp.weixin.qq.com/s/8wTPixeLFZdGnOBc07NmLw> (繁星AI随笔)
- 调查: <https://mahipal.engineer/survey> (GARS-2026)
- 标准: <https://agentskills.io/home>
- 文档: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/README.md>
- 索引: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/index.json>
- 框架 mapping: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/ATTACK_COVERAGE.md>
- 许可证: Apache 2.0 (商业可用)

## 🎯 TL;DR (你问的"能否迁移")

| 目标 | 结论 | 难度 |
|---|---|---|
| **Hermes** | ✅ **YES** — README 显式 compat + Hermes 有 `security/` 目录 | ⭐(wrapper SKILL.md) |
| **opencode** | ✅ **YES** — 内置 `npx skills` + MCP,设计给多 skill | ⭐(`npx skills add` 一次) |
| **zcode (Zed)** | ❌ **NO** — Zed 是 IDE,不是 agent runtime | ⭐⭐⭐(需要把 Zed 改造成 agent) |
| **zcode (Z.ai GLM)** | ✅ **YES** (via MCP / OpenAI 兼容 API) — GLM 通过 Hermes/opencode 集成 | ⭐(跟 Hermes/opencode 一样) |

**推荐**: **先在 Hermes 装 wrapper**,**再装 opencode** (如果 Hermes 不够)。两者都是直接 `npx skills add` 搞定。Zed (zcode) 跳过 — 它不是 agent。