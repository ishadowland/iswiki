# Codex Security — OpenAI 的 AI 安全扫描 CLI

> 学习笔记 · 调研时间 2026-08-12
> 来源: <https://mp.weixin.qq.com/s/oSYF8qFCcDifIiV9bJ2akg> (GitHubDaily 公众号, 小 G 撰)
> 仓库: <https://github.com/openai/codex-security> · 文档: <https://learn.chatgpt.com/docs/security/cli>
> License: Apache-2.0 · Language: TypeScript / Node.js 22.13+ / Python 3.10+ · ⭐ 9.7k

## 一句话定位

**OpenAI 把自家安全插件开源**——`@openai/codex-security` npm 包,既是一套 CLI 工具,也是 TypeScript SDK,定位是"**自动验证漏洞**"而不是"扫描器报几百条误报"。前身是 2025-10 发布的 Aardvark,2026-03 改名 Codex Security,上月底(2026-07)以 npm 包开源。

## 跟"传统扫描器"对比

| 维度 | 传统 SAST (Snyk / Semgrep) | Codex Security |
|---|---|---|
| 输出 | 一次几百条告警 | 验证后才报告 |
| 误报 | 高 | 自动复现 + 排误 |
| 修复建议 | 静态 (link to CVE) | 含问题位置 + 修复代码 + 修复方案 |
| 模型 | 规则引擎 | GPT-5 驱动 + 多 worker |
| 集成 | 单独 CI | Agent 工具外挂 (Claude Code / Cursor / Codex) |

## 3 步上手

```bash
# 1) 装包
npm install @openai/codex-security

# 2) 授权 (ChatGPT 登录 / OpenAI API Key / OpenRouter / Fireworks / Bedrock)
npx @openai/codex-security login

# 3) 在项目根目录扫描
npx @openai/codex-security scan .
```

## 核心命令

```bash
# 基础扫描
npx @openai/codex-security scan .

# 指定模型 + 强度
npx @openai/codex-security scan . --model gpt-5.6-terra --effort high

# 自定义扫描 / 后扫描 prompt
npx @openai/codex-security scan . \
  --scan-prompt-file scan.md \
  --post-scan-prompt-file follow-up.md

# Deep 模式 (多 worker 并行 + sub-agents)
npx @openai/codex-security scan . \
  --mode deep \
  --workers 2 \
  --subagents 0 \
  --stop-after-no-new 3 \
  --max-discovery-runs 10
```

## 多模型支持

| Provider | 接入方式 | 示例 |
|---|---|---|
| **OpenAI** (default) | ChatGPT 登录 或 `OPENAI_API_KEY` | `--model gpt-5.6` |
| **OpenRouter** | `OPENROUTER_API_KEY` | `--model anthropic/claude-sonnet-4.5` |
| **Fireworks** | `FIREWORKS_API_KEY` | `--model accounts/fireworks/models/qwen3-235b-a22b` |
| **Amazon Bedrock** | `AWS_BEARER_TOKEN_BEDROCK` + `AWS_REGION` | `--model openai.gpt-5.6-luna` |

## TypeScript SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
const result = await security.run(".");
await security.run(".", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  maxDiscoveryRuns: 10,
});
console.log(result.reportPath);
await security.close();
```

## 两种扫描模式

| Mode | 用途 | Worker 数 | Token 消耗 |
|---|---|---|---|
| **Standard** | 日常 CI / commit hook | 1 | 少 |
| **Deep** | 大版本上线前 / 完整审计 | 可配 (multi-worker) | 多 |

> 微信文章原话: "Deep 模式还可以让多个 worker 并行深挖,因此我觉得比较适合大版本上线前做一次整体扫描。"

## 关键功能

- **自动验证**(不像传统扫描器甩 100 条告警后再人工排误) — 找到疑似漏洞后会继续验证推演,确认才能进报告
- **修复位置 + 修复方案 + 写进报告** — 直接给"哪里改 + 怎么改"
- **`scans compare BEFORE_ID AFTER_ID`** — 修复前 vs 修复后 diff,自动标 (new / persisting / reopened / resolved / unknown)
- **`findings list [repository]`** — 跨 scan 累计未修复项
- **CI 友好** — 只需 `OPENAI_API_KEY` 环境变量,无需登录
- **Agent 工具外挂** — Claude Code / Cursor / Codex 都能装上用
- **可重入** — 扫描历史存 workbench state dir,跨 scan 关联 (root cause matching)

## 集成场景

### 1) Claude Code + Codex Security

先用 Claude Code 装上,通过 OAuth 授权或 OpenRouter API Key:

```
# 在 Codex 桌面端:
搜索 "Codex Security" 插件安装

# 在 Claude Code:
让 Claude Code 帮我们装
接着 OpenAI 授权登录 / OpenRouter API Key
```

### 2) CI 流水线

```yaml
# GitHub Actions 示例
- name: Security scan
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: |
    npm install -g @openai/codex-security
    npx @openai/codex-security scan . --mode deep --workers 2
```

### 3) Vibe Coding 上线前

微信文章原话: "如果我们手上正好有个 Vibe Coding 出来的产品挂在公网上,可以先拿 Codex Security 跑一遍。"

## 容器化批量扫描

支持 `docker/` 目录 + `compose.yaml` + `compose.apparmor.yaml` (AppArmor hardening)。官方 multi-arch 镜像 (2 周前发布):

```bash
docker pull openai/codex-security
# 用 compose.yaml 跑非交互、可恢复的批量扫描
```

适用场景:仓库固定到 immutable Git revision,做大规模批量审计。

## 类似工具对比

| 工具 | 厂商 | 形式 | 接入 |
|---|---|---|---|
| **Codex Security** | OpenAI | npm CLI + TS SDK | OpenAI / OpenRouter / Fireworks / Bedrock | see also [qoder-security](qoder-security.md) |
| **Claude Code Security Guidance** | Anthropic | Claude Code 内置 | 写完代码 / 结束任务 / commit 时检查 |
| **Qoder Security** | 阿里 | Qoder 插件 | Qoder IDE |
| **Strix** | 开源 (usestrix) | CLI + Cloud | 49.4k ⭐, 自主 Agent 集群 |

## 风险与限制

- **Deep 模式耗时长 + Token** — 微信公众号原话: "耗时会较长而且会消耗大量的 Token"
- **Trusted Access for Cyber** — 某些 cybersecurity requests / protected findings 需要 OpenAI 信任访问 ([chatgpt.com/cyber](https://chatgpt.com/cyber))
- **Verbose 日志含敏感数据** — README 警告: "Verbose diagnostics may contain sensitive data. Review local logs before sharing them."
- **CI 注入风险** — `--scan-prompt-file` 可来自外部,小心 prompt injection
- **新项目** — 2 周前 published Docker 镜像,仍在迭代

## 配置文件

- `~/.codex-security/state/` — 扫描历史、credentials、findings
- `CODEX_SECURITY_STATE_DIR` — 可自定义状态目录
- `~/.codex-security/credentials/keyring` — 用系统 keyring (managed device)

## 相关

- **官方**: <https://github.com/openai/codex-security>
- **npm**: <https://www.npmjs.com/package/@openai/codex-security>
- **文档**: <https://learn.chatgpt.com/docs/security/cli>
- **Trust Access**: <https://chatgpt.com/cyber>
- **原文章**: <https://mp.weixin.qq.com/s/oSYF8qFCcDifIiV9bJ2akg> (GitHubDaily)
- **同类研究**: [Strix](Strix.md) — 自主 AI 渗透测试 Agent 集群

## 跟其他 iswiki 工具的关系

| 工具 | 用途 | 跟 Codex Security 重合 |
|---|---|---|
| [Strix](Strix.md) | 主动渗透测试 + 找漏洞 | 🟡 都有"找漏洞",但 Strix 主动攻击,Codex Security 被动审查 |
| [mapcn](mapcn.md) | 地图组件 | 不相关 |
| [fireside-sprint1](fireside-sprint1.md) | Fireside 项目复盘 | 🟢 Fireside 是 web app,可以用 Codex Security 扫 |
| [OpenKimiPPTSkill](OpenKimiPPTSkill.md) | Kimi PPT skill | 不相关 |
| [StadiView](StadiView.md) | 3D 足球场 | 不相关 |
| [wafKnowledgeBase](wafKnowledgeBase.md) | WAF 知识库 | 🟡 互补 — Codex Security 找漏洞,WAF 拦截 |
| [tier-1-housekeeping](tier-1-housekeeping.md) | Fireside Sprint 1.6 | 适合跑 Codex Security 验证 |
