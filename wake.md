# Wake — Mac 上 Coding Agent 会话的统一档案馆

> 学习笔记 · 调研时间 2026-08-24
> 仓库: <https://github.com/iAmCorey/Wake>
> 作者: Corey (iAmCorey)
> ⭐ 549 · 31 forks · Rust · MIT License · 917 KB
> Created 2026-08-18 (1 周前!) · v0.2.0 (2026-08-20)

## 一句话定位

**"把散落在 `~/.claude`、`~/.codex` 等十多个本地目录里的 coding agent 历史会话全部收进一个原生 macOS 应用,统一浏览 / 全文搜索 / 一键恢复"** —— Rust + GPUI 写的**纯本地 / 只读 / 零网络**的 multi-agent 会话档案馆。

## 6 大核心特性 (README)

1. **Unified browsing** — 按 Agent / project 分组,**实时文件监听**增量更新
2. **Full-text search** (⌘K) — **SQLite FTS5 trigram 索引**,**CJK + 代码子串** (e.g. `useEffect(`) 都精准,直接跳转到对应消息
3. **Transcript view** — user/assistant 气泡,工具调用折叠簇,thinking 摘要,**tree-sitter 代码高亮** (30+ 语言)
4. **One-click resume** — `claude --resume` / `codex resume` 等,在 Terminal/iTerm,**自动回到原项目目录**
5. **Manage** — 收藏 / 置顶 / 导出 Markdown / 删到废纸篓 (系统 Trash + tombstone)
6. **Rust + GPUI** 原生应用,800MB 数据建索引 **~5s**,实时监听增量更新

## 13 大支持的 Coding Agent

| Agent | 数据源 | Model | Via |
|---|---|---|---|
| **Claude Code** | `~/.claude/projects/**/*.jsonl` | ✅ | — |
| **Codex CLI** | `~/.codex/sessions` + `state_5.sqlite` (read-only) | ✅ | ✅ |
| **Copilot CLI** | `~/.copilot/session-store.db` | — | — |
| **Cursor (CLI transcripts)** | `~/.cursor/projects/**/agent-transcripts` | — | — |
| **OpenCode** | `~/.local/share/opencode/opencode.db` | ✅ | — |
| **OpenCode 2** (beta) | same DB, new `session_v2` tables | ✅ | — |
| **Kiro** | `~/.kiro/sessions/cli` | ✅ | — |
| **Gemini CLI** | `~/.gemini/tmp/**/chats` | — | — |
| **Pi** | `~/.pi/agent/sessions/**/*.jsonl` | ✅ | — |
| **Oh My Pi** | `~/.omp/agent/sessions/**/*.jsonl` | ✅ | — |
| **Grok Build** | `~/.grok/sessions/**/updates.jsonl` | ✅ | — |
| **Kimi Code** | `~/.kimi-code/sessions/**/wire.jsonl` | — | — |
| **Antigravity CLI** | `~/.gemini/antigravity-cli/conversation_summaries.db` (metadata only) | — | — |
| **DeepSeek Harness (`dsh`)** | `~/.dsh/sessions/**/session.jsonl[.zstd]` (zstd 透明解压) | ✅ | — |

**不支持** (理由):
- **Cursor IDE chats / Windsurf / Trae** — 本地数据加密
- **Amp / Factory (Droid) / Warp** — 会话在云端
- **Reasonix** — 本机零会话,未实测

## 4 大隐私承诺

> "Agent data directories are opened **read-only**; Wake never writes to another tool's files or databases"

| 承诺 | 实现 |
|---|---|
| **Read-only** | Wake 不写其他 tool 的 files / databases (包括 Codex 的 SQLite) |
| **No credentials** | `auth.json` 等绝不被读 |
| **Zero network** | Wake 不构造/不调用 HTTP client(GPUI 依赖树带,但 Wake 不用) |
| **Rebuildable** | 索引在 `~/Library/Application Support/wake/wake.db`,**可随时重建** |

## 4 大性能数据 (作者机器 ~310 sessions / ~800 MB)

| 操作 | 时间 |
|---|---|
| Full index (冷启动) | **~5s** |
| Incremental (mtime) | **instant** |
| Search (热) | **< 1ms** |
| 实时文件监听 | 增量更新 |

## 完整架构 (2 crates / 5 阶段数据流)

```
crates/
├── wake-core                       # 纯数据层 (无 UI 依赖)
│   ├── adapters/                   #   13 个 AgentAdapter trait 实现
│   │   ├── claude.rs               #   Claude Code
│   │   ├── codex.rs                #   Codex CLI
│   │   ├── copilot.rs              #   Copilot CLI
│   │   ├── cursor.rs               #   Cursor CLI
│   │   ├── opencode.rs             #   OpenCode + OpenCode 2
│   │   ├── kiro.rs                 #   Kiro
│   │   ├── gemini.rs               #   Gemini CLI
│   │   ├── pi.rs                   #   Pi
│   │   ├── omp.rs                  #   Oh My Pi
│   │   ├── grok.rs                 #   Grok Build
│   │   ├── kimi.rs                 #   Kimi Code
│   │   ├── antigravity.rs          #   Antigravity CLI (metadata only)
│   │   ├── dsh.rs                  #   DeepSeek Harness (zstd 透明解压)
│   │   └── parse_utils.rs          #   共用 parsing helper
│   ├── scanner.rs                  #   single-pass scan + FTS
│   ├── watcher.rs                  #   notify-based file watch
│   ├── db.rs                       #   rusqlite (WAL mode)
│   ├── models.rs                   #   数据模型
│   ├── services/                   #   terminal resume / export / trash
│   └── bin/scan.rs                 #   CLI smoke test
└── wake                            # GPUI app (UI 层)
    ├── theme.rs                    #   颜色 token (强制)
    ├── workbench.rs                #   三栏结构
    └── detail.rs                   #   对话正文渲染
```

## 设计系统 (3 栏 / Liquid Glass)

```
┌─────────────┬─────────────────┬──────────────────┐
│ 资料库侧栏   │   会话流         │     阅读区         │
│ (224px)     │   (336px)        │   (剩余)          │
│             │                 │                   │
│ ▢ All       │ [Agent] 日期    │ ┌──────────────┐  │
│ ▢ Stars     │ [Agent] 日期    │ │ 会话身份       │  │
│ ▢ Agents   │ [Agent] 日期    │ │ user: ...     │  │
│   ▸ Claude │ [Agent] 日期    │ │ tool: ...     │  │
│   ▸ Codex  │ [Agent] 日期    │ │ asst: ...     │  │
│ ▢ Projects │                 │ └──────────────┘  │
│             │                 │                   │
│ ⌘K         │                 │                   │
└─────────────┴─────────────────┴──────────────────┘
```

**Design 原则** (DESIGN.md):
- "在几秒内重新找到并继续一段对话"
- 现代 macOS **Liquid Glass** 层级
- 不用边框,用色差表达层级
- 阴影只用于 搜索面板 / 菜单 / 确认框
- 系统蓝只用于主操作 / 选择 / 焦点
- Agent 品牌色作为**功能性识别色**(Claude 橙 #D97757 / Codex 绿 #12A06B)

## 颜色 token 全部在 `theme.rs`

| Token | 浅色 | 深色 | 用途 |
|---|---|---|---|
| `title_bar` | `#EDEDEA` | `#1B1B1A` | 侧栏顶部拖拽区 |
| `sidebar` | `#EDEDEA` | `#1B1B1A` | 资料库侧栏 |
| `list` | `#F7F7F5` | `#20201F` | 会话流 |
| `background` | `#F1F1EF` | `#242422` | 阅读区外层 |
| `popover` | `#FDFDFC` | `#2C2C2A` | 阅读卡 / 对话框 |
| `foreground` | `#1D1D1F` | `#F0EFED` | 正文 |
| `muted_foreground` | `#686761` | `#A9A8A2` | 元信息 |
| `primary` | `#0A84FF` | `#4C8DFF` | 主操作 / 焦点 |
| `danger` | `#E5484D` | `#FF6B60` | 删除 |
| `success` | `#2F9E63` | `#56C789` | 刷新 |

→ **禁止其他文件出现颜色字面量**(代码规则)

## 6 大开发命令

```bash
cargo run -p wake                  # dev mode
scripts/test.sh                    # 完整测试
scripts/test.sh --smoke            # 加真实数据扫描 baseline
cargo test -p wake-core            # 数据层测试
cargo run -p wake-core --bin scan  # smoke test
cargo run -p wake-core --bin scan -- --search "useEffect("   # search smoke
WAKE_THEME=dark cargo run -p wake  # 强制深色
git config core.hooksPath scripts/hooks  # pre-commit tests
python3 scripts/demo-home.py       # 生成假数据 for 截图
```

## 5 大 安装 + 使用

```bash
# 1) 装 Rust toolchain
rustup install stable

# 2) 克隆 + build
git clone https://github.com/iAmCorey/Wake
cd Wake
scripts/make-app.sh                # build dist/Wake.app (icon + Info.plist, ad-hoc signed)

# 3) 打开
open dist/Wake.app

# 4) 第一次打开:右键 → 打开 (绕过 Gatekeeper)
# 或:
xattr -d com.apple.quarantine Wake.app
```

## 9 大产品原则 (PRODUCT.md)

1. **本地优先,只读别家数据,一切可重建**
2. **找回一段对话的速度是唯一北极星**
3. **原生质感优先于个性表达**(Operate 工具,克制)
4. **中文内容(会话正文)的排版与混排质量是一等公民;UI 语言为英文**
5. **开源可读**:代码与设计决策都要经得起外人看
6. 跟随系统深浅色
7. 文字对比按 HIG
8. 不依赖纯色区分状态
9. accessibility inclusion

## 命名 / 设计哲学

**Wake** = 船迹(agent 驶过的痕迹)+ 唤醒(恢复会话)
> 2026-08-14 从 **Vibex** 改名 (作者考虑)
> "在几秒内重新找到并继续一段对话" — 北极星
> UI 是**工具**,不是艺术品

## 4 大技术亮点

### 1. SQLite FTS5 trigram 索引

```sql
CREATE VIRTUAL TABLE messages_fts USING fts5(
  content, role,
  tokenize = 'trigram'
);
```

**为什么 trigram**: standard FTS5 对 CJK 支持差(单字). Trigram 按 3 字符 tokenize,既支持 `useEffect(` 短代码子串,**也支持中文** (每个 CJK 字=1 token).

### 2. mtime-based 增量扫描

```rust
// scanner.rs
for path in walkdir(dir).with_modified_since(last_run) {
    parse_and_index(path);
}
```

→ **首次冷启动 5s,后续 instant**(只扫新文件)

### 3. notify-based file watcher

```rust
// watcher.rs
let mut watcher = notify::recommended_watcher(|res| {
    incremental_update(res.path);
});
```

→ **实时增量更新**(用户开新会话,Wake 立即索引)

### 4. Adapter trait 模式

```rust
trait AgentAdapter {
    fn data_dir(&self) -> &Path;
    fn parse_session(&self, path: &Path) -> Result<Session>;
    fn extract_model(&self, session: &Session) -> Option<Model>;
    fn extract_origin(&self, session: &Session) -> Option<Origin>;
}
```

→ **新加 agent = 实现 1 个 trait** = 整个 UI 免费

## 7 大产品功能 (vs 竞品)

| 功能 | Wake | 单 agent (e.g. Anthropic Console) | 云端 (e.g. ChatGPT) |
|---|---|---|---|
| 多 agent 聚合 | ✅ 13+ | ❌ 单 | ❌ 单一 chat |
| 全文搜索 | ✅ FTS5 trigram | ⚠️ 各家各异 | ✅ |
| 跨项目 / agent 搜索 | ✅ | ❌ | ❌ |
| 一键恢复会话 | ✅ `claude --resume` | ⚠️ | ❌ |
| 本地隐私 | ✅ **零网络** | ✅ | ❌ |
| 离线 | ✅ | ✅ | ❌ |
| 删除废纸篓 | ✅ + tombstone | ❌ | ❌ |
| 导出 Markdown | ✅ | ⚠️ | ⚠️ |
| Mac 原生 | ✅ GPUI | ⚠️ Web | ⚠️ Web |

## 5 大 risk / 限制

- **macOS 14+ only** — 不跨平台
- **GPUI 0.2** — 早期框架,bundle size / 稳定性
- **ad-hoc signed** — Gatekeeper 需右键绕过
- **No cross-agent session ID** — 同一对话从 Claude 转到 Codex,Wake 视为两个 session
- **Antigravity / Cursor IDE 加密** — 仅元数据

## 跟 iswiki 现有工具对比

| 工具 | 关系 |
|---|---|
| [mattpocock-skills](mattpocock-skills.md) | ⚪ 不同领域 (skills 集合) |
| [paseo](paseo.md) | 🟡 都是 multi-agent 工具 |
| [i-have-adhd](i-have-adhd.md) | ⚪ 输出风格 |
| [codex-security](codex-security.md) | 🟢 支持 Codex (Wake 之一) |
| [qoder-security](qoder-security.md) | ⚪ 不相关 |
| [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md) | ⚪ 不相关 |
| [Logue](Logue.md) | ⚪ 不相关 |

## 关联资料

- 仓库: <https://github.com/iAmCorey/Wake>
- Releases: <https://github.com/iAmCorey/Wake/releases>
- DESIGN.md: 设计 token 规范
- PRODUCT.md: 产品决策
- CI: <https://github.com/iAmCorey/Wake/actions/workflows/ci.yml>
- License: MIT
- Brand icons: [lobe-icons](https://github.com/lobehub/lobe-icons) (MIT)

## 🎯 TL;DR — 写给谁用

| ✅ 适合 | ❌ 不适合 |
|---|---|
| **重度 multi-agent 用户**(Claude + Codex + ...)| 单一 agent 死忠 |
| **Mac 14+** 用户 | Linux / Windows 用户 |
| **本地隐私敏感**(医疗 / 金融 / 律师) | 需要云同步 |
| **300+ 历史会话** 找不到 | 99% 时间只用一个 agent |
| **想 search 跨 agent 跨项目** | 单 agent 自带 search 够用 |
| **厌倦每家各自的 search UI** | 一周只开一两次 agent |
| **需要把对话导出 Markdown** | 不需要持久化 |
| 喜欢 **Mac 原生质感** (Things / Bear 级) | 喜欢 web 跨平台 |

## 给 Hermes / iswiki 用户的特别建议

如果你跟我一样多 AI agent 混用 — **Wake 是必装**。
1 周维护,1 周已经 549 ⭐, 4 open issues (v0.2.0 刚出),v0.1.0 → v0.2.0 加了:
- 搜索 ⌘K 命中直达详情页对应消息
- OpenCode 2 beta 支持
- dsh (DeepSeek Harness) zstd 透明解压

→ **v0.3.0 估计会加 more adapters + AI summary 集成**