# Qoder Security — 阿里 Qoder 的 AI 安全能力

> 学习笔记 · 调研时间 2026-08-12
> 官网: <https://qoder.com/security> · 文档: <https://qoder.com/docs/security>
> 公司: BRIGHT ZENITH PRIVATE LIMITED (阿里系) · 1,000,000+ 用户
> License: 商业 ML (Qoder 平台内嵌) · IDE: Qoder IDE / Qoder CLI
> 发布: v1.16.0 (2026-07-20) · Qoder 1.0.0 (2026-08-06)

## 一句话定位

**Qoder Security 是 Qoder 平台内嵌的 AI 安全工程师** —— 不是独立 CLI/SDK,而是 IDE/CLI **原生三阶段扫描**(L1 / L2 / L3),覆盖"代码生成 → 对话 → 提交"全生命周期,主打"**对话即安全**"和"**LLM 语义检测超越规则**"。

## vs Codex Security (OpenAI)

| 维度 | **Qoder Security** (阿里) | **Codex Security** (OpenAI) |
|---|---|---|
| **形式** | Qoder IDE/CLI 内嵌插件 | npm CLI + TypeScript SDK |
| **开源** | ❌ 商业(闭源) | ✅ Apache 2.0 npm |
| **扫描层次** | **3 层渐进**(L1/L2/L3) | 2 模式(Standard / Deep) |
| **触发点** | 本轮生成 / 对话 / 提交 | 一次性 `scan .` |
| **模型** | 阿里 Qwen-Coder (deepseek/qwen 私有) | OpenAI / OpenRouter / Fireworks / Bedrock |
| **代码安全左移** | ✅(原生成即扫) | ❌(写完才扫) |
| **LLM 语义检测** | ✅ 核心 | ✅ |
| **三层防线** | L1 模式匹配→L2 语义→L3 数据流追踪 | 多 worker 并行 |
| **自修复** | ✅ 一键 | ✅ |
| **GPT-5 驱动** | ❌ Qwen 驱动 | ✅ |
| **GitHub stars** | N/A (商业) | 9.7k |
| **试点** | Qoder 1.0+ 用户(100万+) | 独立,npm install |
| **修复时间** | **小时级** | 不显式(由 LLM 决定) |
| **误报率 vs 传统** | **-80%** | 微信文章"自动验证"报道 |
| **检出率 vs 传统** | **+60%** | 微信文章"自动验证"报道 |

## 3 层渐进式扫描

| Level | 名称 | 作用 | 触发时机 |
|---|---|---|---|
| **L1** | **静态检查** | 高危模式匹配 + 危险函数检测 + **即时发现 + 自动修复** | 本轮任务生成代码 |
| **L2** | **轻量扫描** | 语义理解 + 注入 / RCE / 敏感信息泄露识别 | 增量代码 |
| **L3** | **轻量扫描** | 跨文件 + 跨函数**数据流追踪** + 隐藏关联漏洞 | 增量代码(深度) |

**关键设计**:
- L1 跑**当前轮生成**代码(快,模式匹配)
- L2 跑**增量代码**(语义理解)
- L3 跑**跨文件数据流**(全工程视角)
- 数值: **+60% 检出率,** **-80% 误报率** vs 传统方案

## 核心定位(从官方文案)

> "AI 让代码产出成倍增长,**传统安全工具 '发现得太晚、噪音太大、结果看不懂' 的短板被进一步放大**。
> 这一版本,Qoder 把代码安全审查**嵌入开发流程**,支持 L1 / L2 / L3 三层渐进式扫描,
> 让每一次代码生成、每一次对话、每一次提交都自带安全把关,并支持一键快捷修复,
> 让每行代码提交即安全。"

→ **AI 编码时代的 native 安全** vs **传统 SAST 工具**

## 关键特性

| 特性 | 描述 |
|---|---|
| **原生内置** | 装 Qoder IDE 自动有,不需外挂 |
| **安全左移** | 在代码生成**那一刻**就扫,不是写完才扫 |
| **LLM 语义检测** | 不是规则 grep,是 LLM 理解代码语义 |
| **三层防线** | L1(LSP 通用)+ L2(SLICEC)+ L3(数据流) |
| **一键修复** | 验证后自动修,无需 1 提交 1 改 |
| **>.md 报告** | 修复位置 + 修复方案直接可贴 |
| **持续进化** | 阿里 Qwen-Coder 持续在该能力上迭代 |

## 集成方式

不像 Codex Security 是 `npm install` + `npx scan`:

```bash
# 1. 装 Qoder IDE (or Qoder CLI)
brew install qoder   # 或 macOS download
# 或
curl -fsSL https://qoder.com/install.sh | sh

# 2. 登录阿里云账号(或 BYOK 用自有 key)
# Qoder IDE 内置登录

# 3. 写代码(Quest 模式或手工写)
# Qoder Security 自动在 3 个节点触发:
#   - 每一轮任务生成结束 (L1)
#   - 每次对话 commit (L2)
#   - 每次 pushed commit (L3)
```

## 类似工具对比

| 工具 | 厂商 | 形式 | 扫描方式 | 自修复 | 开源 |
|---|---|---|---|---|---|
| **Qoder Security** | 阿里 (BRIGHT ZENITH) | Qoder IDE 内嵌 | L1/L2/L3 渐进 | ✅ 一键 | ❌ |
| **Codex Security** | OpenAI | npm CLI + TS SDK | Standard / Deep | ✅ | ✅ Apache 2.0 |
| **Claude Code Security Guidance** | Anthropic | Claude Code 内嵌 | commit 时扫描 | ❌ | ❌ |
| **Strix** | 开源 (usestrix) | CLI + Cloud | 主动 Agent 渗透 | ❌ | ✅ MIT/Apache |

## 跟 Codex Security 深度对比

**1. 集成哲学不同**:
- **Codex Security**: "扫描器" — 你写完代码跑 `codex-security scan .`
- **Qoder Security**: "嵌入式审计员" — 写代码时自动帮你审

**2. 模型选择不同**:
- **Codex Security**: 多 provider (OpenAI / OpenRouter / Fireworks / Bedrock)
- **Qoder Security**: 阿里 Qwen-Coder 私有模型(不能换)

**3. 触发点不同**:
- **Codex Security**: CI / commit hook / 手动 scan
- **Qoder Security**: L1 立刻(轮生成)、L2 提交时、L3 push 后

**4. 覆盖度不同**:
- **Codex Security**: 整体 + 增量都可以,依赖用户选 mode
- **Qoder Security**: 三层渐进,**用户不需要做选择**

**5. License**:
- **Codex Security**: Apache 2.0 npm,可独立部署
- **Qoder Security**: Qoder 平台内嵌,不开源

**6. 数据流分析**:
- **Codex Security**: 多 worker 并行扫描
- **Qoder Security**: L3 跨文件跨函数数据流追踪(单文件视角看不到的)

**7. 自我修复**:
- 都提供自动修复,差异是触发方式

## 选哪个

| 场景 | 推荐 |
|---|---|
| **独立 CI/CD / 简单集成** | Codex Security (npm 即可) |
| **已经在用 Qoder IDE** | Qoder Security (原生) |
| **想要 AI 写代码时实时查** | Qoder Security (L1 立即) |
| **开源 / 自部署 / 多模型** | Codex Security |
| **CI 集成 / 不绑 IDE** | Codex Security |
| **阿里生态 / 中国开发者** | Qoder Security |
| **要自训练模型** | Qoder Security (Qwen-Coder 路径) |
| **跨境 / 国际团队** | Codex Security |

## 风险与限制

- **不开源** — Qoder Security 业务代码不公开
- **阿里生态绑定** — Qoder 跟 Cursor / Claude Code 不互通
- **模型单一** — Qoder Security 只能用 Qwen-Coder
- **商业付费** — 1.0 后订阅制(Qoder 社区版 BYOK)
- **新项目** — v1.16.0 1 个月前发布,仍在迭代
- **误报没彻底解决** — 60% 检出率 + 80% 误报率,"提升"不是"消灭"

## 跟其他 iswiki 工具的关系

| 工具 | 用途 | 跟 Qoder Security 关系 |
|---|---|---|
| [codex-security](codex-security.md) | OpenAI 同类工具 | 🔴 **直接竞品** |
| [Strix](Strix.md) | 主动 AI 渗透 | 🟡 Qoder Security 被动审查,Strix 主动攻击 |
| [fireside-sprint1](fireside-sprint1.md) | Fireside 项目 | 🟢 可用 Qoder Security 扫 |
| [tier-1-housekeeping](tier-1-housekeeping.md) | Fireside housekeeping | 🟢 Qoder Security 可作 commits hook |
| [Logue](Logue.md) | macOS 本地 AI | ⚪ 不相关 |
| [mapcn](mapcn.md) | 地图组件 | ⚪ 不相关 |

## 文档资源

- Qoder 官网: <https://qoder.com>
- Qoder Security: <https://qoder.com/security>
- v1.16.0 更新日志: <https://qoder.com/zh/changelog>
- Qoder 1.0 博客: <https://qoder.com/zh/blog>
- 案例: <https://qoder.com/zh/blog/case/qoder-security-user-practice>
- 下载: Qoder IDE (macOS / Windows / Linux) / Qoder CLI

## 关联

- `codex-security.md` — OpenAI 同类工具,含详细对比
- `Strix.md` — 主动 AI 渗透测试
- `fireside-sprint1.md` — Fireside 项目,可跑这些扫描
