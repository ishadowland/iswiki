# My Wiki — 本地优先、证据闭环的 Markdown 知识库 + Agent Skill

> 学习笔记 · 调研时间 2026-10-15
> 仓库: <https://github.com/NimaChu/my-wiki> · npm 包: `my-wiki-skill`@0.7.1 · 默认远程服务: <https://my-wiki.cloud>（实测 HTTP 200 存活）
> OKF 标准: <https://github.com/GoogleCloudPlatform/open-knowledge-format>（v0.2 · Apache-2.0 · 959★）
> License: **MIT**（作者 Chu, Zijun，独立研究者） · 语言: JavaScript(Node ESM) + TypeScript/React 19 前端
> ⭐ **123** · 2 forks · 1 open issue · **contributors = 1** · 建仓 2026-07-02 · 最后 push 2026-10-08
> 版本 **0.7.1**（2026-09-11 发布） · GitHub Releases **停在 v0.2.2**（2026-07-15，已废弃通道）

---

## 一句话定位

**把本地散落的网页 / PDF / 扫描件 / Office 文档，用 Agent 蒸馏成「原子 Concept + 原始 Reference」双向可追溯的知识库，并自带一个可安装到 Codex / Claude Code / Hermes 的轻量 Skill 适配层。**

它的核心主张跟大多数「AI 笔记工具」相反：**不是给每份文档生成一段摘要**。一份 Reference 可以更新多个长期 Concept，一个 Concept 也可以综合多份 Reference；只有双向证据关系闭合、后续事项处理完成，Reference 的 `workflow_status` 才变成 `processed`。

---

## 三种使用方式

| 方式 | 入口 | 需要装什么 | 适用 |
|---|---|---|---|
| **1. 当 Agent 工作区打开** | clone 仓库 → `npm run setup` → `npm run wiki -- init <vault> --use` | Node 18+（无需全局 Skill） | 主要用法。Agent 读根目录 `AGENTS.md` 直接跑 CLI / Dashboard / 测试 |
| **2. 通过 Skill 从其他工作区调用** | `npx my-wiki-skill@latest --target hermes` | Skill 适配层（**不含**项目主体和知识库） | 在别的项目里说人话就能操作同一个 vault |
| **3. 打开知识宇宙网页** | `npm run wiki -- open-dashboard`（默认 `127.0.0.1:5173`） | 项目主体 + Dashboard 依赖 | 浏览知识宇宙 / 文档库 / Viki 问答 / 导入导出知识星系 |

**四层壳**：README 明确写「项目主体 ≠ Skill ≠ 知识库」，Skill 只做工作流路由与项目发现，**不复制应用代码、不保存知识库**。项目或 vault 缺失时，Agent 先征得用户确认再补齐。

---

## 核心架构

```text
my-wiki/
  AGENTS.md            Agent 打开项目时的入口（路由：知识操作/开发/安装/发布）
  scripts/             CLI + 知识维护主体（68 个 .mjs / 17,163 行）
    my-wiki.mjs            入口：remote 路由判定 → 转发 karpathy-wiki.mjs
    core/karpathy-wiki.mjs 22 个子命令的 dispatch 表
    core/wiki-lib.mjs       frontmatter 解析、Markdown 遍历（763 行，基础设施）
    core/dashboard-api.mjs  HTTP API（3,679 行，最大单文件）
    core/document-*.mjs     IR / 提取路由 / 质量门禁 / 页级渲染
    core/mineru-extractor.mjs / docling-extractor.mjs / agent-vision-repair.mjs
    core/viki-*.mjs         问答：retrieval / cli-boundary / api-agent / web-tools
    core/public-access.mjs / github-allowlist.mjs / remote-auth.mjs
    migrations/vault-schema-v2.mjs  ← 唯一对外暴露路径的迁移脚本（见风险点）
  assets/dashboard/    React 19 + Vite 7 前端 + server.mjs（本地服务）
  deploy/apple-container/  Apple Container 公网沙箱（8787 端口）
  my-wiki-skill/       可选适配层：SKILL.md + 10 个 references/ + 3 个 scripts/
  tests/               46 个测试文件
```

**技术栈要点**：

| 项 | 值 |
|---|---|
| 运行时 | Node 18+（**`package.json` 里没有 `engines` 字段**，README 只靠 badge 声明） |
| 后端依赖 | 15 个：MCP SDK 1.30、minisearch 7.2、unified/remark/mdast 全家桶、`jose`(JWT)、`jszip`、`ipaddr.js`、`yaml` |
| 前端依赖 | React 19.2 / Vite 7.3 / **@milkdown/crepe 7.21**（编辑器）/ katex 0.18 / pdfjs-dist 4.2 / tesseract.js 6 / mammoth / read-excel-file / @napi-rs/canvas |
| Dashboard 体积 | `main.tsx` 126KB + `Viki.tsx` 84KB + `styles.css` 90KB；构建产物最大 chunk **MarkdownLiveEditor 1.36MB**（gzip 433KB） |
| CI | `.github/workflows/cross-platform.yml`：ubuntu / macos / windows 三平台，**只测 Node 20** |
| 前端代码量 | `scripts/` + `assets/dashboard/src/` + `tests/` 合计 **1.77 MB** |

---

## 知识模型：Reference → Concept（这是全项目的设计核心）

术语强制用 **OKF v0.2 原生词**，仓库里明确警告不要从 `wiki/` `raw/` 这些历史变量名反推目录结构。

| OKF 概念 | My Wiki 术语 | 位置 | 生命周期字段 |
|---|---|---|---|
| 捕获的证据 | **Reference** | `references/sources/<source>.md`（扁平，不分分类子目录） | `status: draft/stable/deprecated` + **独立的** `workflow_status: inbox/needs-followup/processed/stale` |
| 保留的原件 | **original** | `references/originals/`（网页快照 / PDF / Office 原件） | — |
| 长期可复用知识 | **Concept** | `concepts/<atomic>.md` | OKF `status`，证据挂 `sources` 映射 + `[^source-id]` 脚注 |
| 知识分组 | **知识星系**（galaxy） | Concept frontmatter 的 `universes` 列表（**第一个是主星系**） | — |
| 图谱可视化 | 知识宇宙 / 星系 / **Concept 星球** / 参考证据层 | **不是额外数据库**，直接从 Concept↔Reference 关系生成 | — |

**最值得抄的一条设计**：`status` 和 `workflow_status` **刻意分成两个字段**。OKF 的 `status` 表达知识成熟度，`workflow_status` 表达队列状态，绝不复用。README 里专门点出「系统不会把『已经蒸馏』冒充为人工验证」——`verified` 只能由具名的人实际做过才写。

vault 结构：

```text
my-vault/
  index.md            OKF 知识入口（保留文件名）
  log.md              OKF 更新日志（保留文件名）
  concepts/           原子 Concept
  references/
    sources/          Reference Markdown（扁平）
    assets/<source>/  该来源专属图片 + image-index.json（禁止跨来源混放）
    originals/        原件
  templates/
  .my-wiki/           运行状态 / 缓存 / 回收站 / 提取报告（不属知识内容）
```

---

## 文档提取与证据门禁（本项目工程含量最高的部分，可直接抄）

**核心理念：My Wiki 自己定义证据契约，外部解析器只提供观测，不能自行宣布「资料可维护」。**

```text
保留快照 → 格式探测 / 引擎路由 → 提取器适配 → my-wiki.document-ir/v1
        → 中央证据门禁 → Markdown 渲染 + 本地图片 → Reference + 提取报告
```

| 引擎 | 定位 |
|---|---|
| **MinerU** | 中文技术 PDF / 扫描件 / 公式表格主解析器 |
| **Docling** | Office / OpenDocument / EPUB 首选，提供 block 级页码 + bounding box provenance；PDF 降级 |
| **agent-vision**（内置） | 借鉴 doc7 的页级视觉重建：把中央门禁标出的**风险页**渲染成图，丢给已登录的 OpenCode / Codex 多模态模型；**结果必须经确定性差分门禁判定"明显更好"才替换**，且不安装 doc7 |
| PDF.js / Tesseract | 无高保真引擎时的降级路径。**已实际运行但失败的 MinerU/Docling 结果不允许被低保真降级掩盖**（只有 `unavailable` 才换引擎） |

**确定性硬门禁（失败即锁 `needs-followup`，绝不伪装成功）**：

| 门禁 | 判据 |
|---|---|
| 公式 | 用**与 Dashboard 同一个 KaTeX 运行时**校验真实 Markdown math 节点；确定性的 parse 失败 / strict warning 记精确页码行号并阻塞 |
| 编码 | 最终 `## Capture` 正文里任何 **U+FFFD** 替换字符 = 确定性编码损失，按页记录并锁死 |
| 页覆盖 | 分页文档缺页码 provenance 直接阻塞 |
| 附件 | 本地图片引用缺失阻塞 |
| 内容 | 空输出 / 全局质量差阻塞 |
| 缺视觉证据 | 页面**有墨迹和对比度**但 MinerU 返回几乎无内容且无图片 → 记 `missing-visual-evidence:pages=...`，必须渲染该页图并更新 `image-index.json` 才算解决 |

**设计取向值得注意**：自动视觉分类（空白页 / 透印页）**只是建议性的**——只要正面有实质文本就必须保留并转人工复核。只有「人工确认的空白页」或「稀疏/重复文本交叉印证的候选」才可省略，且**页锚点必须保留**。宁可留噪音也不静默丢证据。

可调环境变量（CLI help 里全列了）：`MY_WIKI_PDF_ENGINE`、`MY_WIKI_VISUAL_REPAIR_MODE=off|auto|required`、`MY_WIKI_VISUAL_REPAIR_MAX_PAGES`、`MY_WIKI_MINERU_BATCH_THRESHOLD_PAGES`(默认 512) / `MY_WIKI_MINERU_BATCH_PAGES`(默认 64)。

---

## 最小可运行示例（本机实测通过）

```bash
git clone https://github.com/NimaChu/my-wiki.git
cd my-wiki
npm install                      # 15 个运行时依赖（实测 18s / 187 packages）
npm run setup                    # 注册项目到 ~/.my-wiki/project.json
npm run wiki -- init ~/Knowledge/personal --name personal --use

npm run wiki -- status           # vault 健康快照（JSON）
npm run wiki -- lint             # 证据闭环 lint
npm run wiki -- capture --title "标题" --url "https://example.com/"
npm run wiki -- search "关键词"
npm run wiki -- okf-audit        # OKF v0.2 兼容性审计
npm run wiki -- export-universe "星系名"     # → 单个 .mywiki 知识包
npm run wiki -- open-dashboard   # http://127.0.0.1:5173
```

装 Skill 到 Hermes（**只有 npm 版安装器支持**）：

```bash
npx my-wiki-skill@latest --target hermes     # → ~/.hermes/skills/my-wiki
# 国内网络：npx --registry=https://registry.npmmirror.com my-wiki-skill@latest
```

装好后让任何 SKILL.md 宿主跑这一句解析当前目标：

```bash
node <skill-dir>/scripts/my-wiki.mjs where
```

**远程模式**（另一台电脑，无需装项目主体/OCR/本地 vault）：

```bash
node <skill-dir>/scripts/my-wiki.mjs remote connect   # 浏览器 GitHub 白名单登录，默认 my-wiki.cloud
node <skill-dir>/scripts/my-wiki.mjs search "查询"
node <skill-dir>/scripts/my-wiki.mjs capture --file /path/book.pdf
```

---

## 🎯 跟我们的关系

**1. 它是少数几个把 Hermes 写进安装矩阵的开源项目。** `npm-dist/install.mjs` 探测 7 个 Skill 根目录，`~/.hermes/skills` 在列，`hermes-agent` 是显式 target 别名。本机实测 `node npm-dist/install.mjs --list` 输出：

```text
/Users/liuyin/.agents/skills
/Users/liuyin/.claude/skills
/Users/liuyin/.config/opencode/skills
/Users/liuyin/.openclaw/workspace/skills
/Users/liuyin/.hermes/skills        ← 我们
```

**2. 它的知识模型跟我们已在用的东西高度互补，不是替代。** iswiki 仓是「写完就 push 的调研笔记」；Hermes 有 `chromamem`（ChromaDB + bge-small-zh 向量记忆）。My Wiki 管的是**第三层**：需要证据核实的项目资料 → 蒸馏成可长期复用的 Concept。而 chromamem 管的还是「会话事实 / 用户偏好 / 环境事实」这类高频短文本。两者可以并存：My Wiki 的 vault 交给 RAG，chromamem 继续管短记忆。

**3. 值得直接抄的三条工程纪律**（跟它是什么项目无关）：

| 纪律 | 具体做法 |
|---|---|
| **状态字段分层** | 知识的「成熟度」和任务的「队列状态」永不共用一个字段（`status` vs `workflow_status`） |
| **失败不伪装成功** | U+FFFD / KaTeX 失败 / 缺页码 / 缺附件 = 硬阻塞；自动判断只作建议，人工确认才能豁免；已运行但失败的引擎不许被降级掩盖 |
| **流程状态由服务端重算** | Agent 返回后**无视它自称的任何状态**（"disregards any claimed status"），服务端自己重跑全部门禁再改状态 —— 防的就是 LLM 谎报「我修好了」 |

**4. 本机环境已具备条件**（调研时实测）：

| 依赖 | 本机状态 |
|---|---|
| Node | v24.13.0 ✅（CI 只测 Node 20，但 v24 实测跑通 init / status / lint / capture / search） |
| uv | ✅ `/Users/liuyin/.local/bin/uv` —— MinerU / Docling 安装的前置 |
| MinerU / Docling | ❌ 未装（中文 PDF 解析能力目前为空，会落到 PDF.js/Tesseract 降级路径） |
| opencode / openclaw | ✅ 已装 —— Dashboard 的 Viki 问答 + 页级视觉修复都复用它们 |
| 端口 5173 / 8787 | ✅ 均空闲 |
| ~/.my-wiki | ❌ 不存在，零污染 |

**5. 建议的落地姿势**：如果要试，**不要装 npm Skill**（会往 `~/.hermes/skills` 里塞第三方 Skill 目录），直接 clone 到一个独立目录当 Agent 工作区用。第一步只跑 `init` + `capture` 验证 PDF 门禁，别一上来就 `npm run setup:all`。

---

## 一手核验：README 说法 vs 实测（4 处出入）

| # | README 说法 | 实测 / 源码事实 |
|---|---|---|
| 1 | 安装器表格列 Hermes / Claude Code 等 6 家「自动探测或 `--target <x>`」 | **只有 npm 版安装器**（`npm-dist/install.mjs`）支持 6 家 + `--target`。**仓内 `my-wiki-skill/scripts/install.mjs` 只硬编码 codex 和 opencode 两个 target**（`--opencode-only` / `--codex-only`），README 的表格挂在「`npm run skill:install`」那段上，属文档错位 |
| 2 | npm badge 显示 `my-wiki-skill` 版本 | ✅ 一致（0.7.1）。但 **GitHub Releases 停在 v0.2.2（2026-07-15）**，版本真通道是 npm dist-tag，看 Releases 会严重误判 |
| 3 | Node.js 18+ | `package.json` **没有 `engines` 字段**，README 只靠 badge。CI 只跑 Node 20。v24 实测可用，但「18+」未经 CI 验证 |
| 4 | 「失败不会伪装成功 / 证据闭环」 | ✅ 属实，且实现比 README 说的更严。但**唯一 open issue #10 正是一处 HIGH 级路径校验缺失**：`scripts/migrations/vault-schema-v2.mjs:7` 直接 `path.resolve(process.argv[2] \|\| MY_WIKI_VAULT)` 不做根目录校验，CWE-22，截至 2026-10-15 未修 |

**其他事实核对**：

- **无遥测**：全仓 grep 不到 sentry / posthog / analytics / tracking；出网只到 `api.deepseek.com`（可选 Viki provider）、`api.github.com`（OAuth）、`ima.qq.com`（腾讯 IMA 导入）、`mcp.exa.ai`（可选 MCP）。
- **许可证干净**：主仓 MIT；Dashboard 内置 3 只像素宠物（`claude--xiangking` / `codenono--dq02` / `qoderwork--my-wiki`，各带 LICENSE + NOTICE）保留各自授权。
- **`.gitignore` 已排除** `/knowledge-base/`、`/paper/`、`.mcp.json` —— 作者自己也不把 vault 放仓内。
- **安全边界写得很克制**：网页默认只绑 `127.0.0.1`；浏览器写操作要同源 session token；URL 抓取拒绝内网/私有地址（`ipaddr.js`）；上传流式 + 大小限制；ZIP 拒绝不安全路径；CLI 问答走**私有 stdio MCP 适配器 + 白名单快照**，禁掉原生 file/shell/browser 工具；陈旧保存返回 HTTP 409。

---

## 实战建议 / 风险点

| 风险 | 说明 | 建议 |
|---|---|---|
| **bus factor = 1** | `contributors = 1`（NimaChu，102 commits），无其他维护者，无 CODEOWNERS | 把它当**可读的架构参考**而非依赖项。要抄设计，别把关键流程压在它身上 |
| **采用度极低** | ⭐123 / 2 forks / npm 近 30 天下载 **94**、近 7 天 **13**；issue/PR 几乎不动，最后 push 2026-10-08 | 说明它主要是个人的重度自用项目，公开生态尚未形成 |
| **README 极度冗长** | 中文 337 行 / 英文 285 行，大段 bullet 罗列前端功能（原文把「图标视图排序」「预览 ETag 304」「回收站」都写成 bullet） | 读的时候只抓四块：`AGENTS.md` → `my-wiki-skill/SKILL.md` → `references/knowledge-model.md` → `references/evidence-rules.md`。这四份是真规范，README 是功能广告 |
| **前端极重** | Dashboard 依赖 380 packages / 1.77MB 源码，构建后 MarkdownLiveEditor 单 chunk 1.36MB；`styles.css` 89KB | 只用 CLI 不碰 Dashboard 的话，前端开销为零。建议先纯 CLI 用 |
| **依赖 PDF 高保真引擎才有价值** | MinerU / Docling 未装时全靠 PDF.js + Tesseract，中文技术 PDF 基本废 | 装 MinerU 前先估算：首次下载模型很重，Apple Container 沙箱明确用 CPU（拿不到 MPS/MLX），会很慢 |
| **Viki 依赖已登录的外部 CLI** | 走 OpenCode / Qoder / Codex / Claude 本地 CLI，或 DeepSeek API。**API Key 只存服务端** | 用户本机只有 opencode / openclaw，Codex 和 Claude CLI 没装 → Viki 只能用 opencode 通道 |
| **远程模式有隐含前提** | `my-wiki.cloud` 是作者的服务，登录仅限服务端 GitHub 白名单；设备凭据 90 天有效 | 敏感资料不要放远程。另外远程 API **尚不支持**完整蒸馏提交、星系增删、永久删除、服务端 Agent CLI 调度 —— 不要指望远程等于本地 |
| **单一大文件** | `dashboard-api.mjs` 3,679 行 | 想改行为要读很久；慎 fork |
| **路径校验缺口（open issue）** | `migrate-vault-v2` 直接 `path.resolve` 外部输入 | 别在有价值的 vault 上跑 `migrate-vault-v2`，先备份 |

---

## 版本节奏

| 版本 | 日期 | 关键内容 |
|---|---|---|
| 0.3.0 | 2026-07-24 | npm 包首发 |
| 0.6.0 | 2026-07-31 | — |
| 0.6.1 | 2026-08-28 | 可恢复的星系删除、大幅扩展 Viki |
| 0.7.0 | 2026-09-11 | GitHub 授权的远程 Skill 访问 |
| 0.7.1 | 2026-09-11 | 服务端 GitHub 白名单 + Skill 路由 |
| （main） | 2026-09-14 | 文档库 + Viki 会话 |
| （main） | 2026-09-15 | Viki 流式 + SVG 导出 |
| （main） | 2026-10-08 | Windows 远程 CLI 优雅退出（**最后 commit**） |

节奏判断：7 月三次连发（0.3 → 0.6），9 月两次（0.7.0/0.7.1），10 月只有 1 个修复 commit。**近一个月基本停在维护状态**，0.7.1 之后无版本号推进。

---

## 生态与配套

| 组件 | 说明 |
|---|---|
| **OKF v0.2** | Google [open-knowledge-format](https://github.com/GoogleCloudPlatform/open-knowledge-format)（959★ Apache-2.0，2026-08-21 最后 push）。`.mywiki` 知识包就是过了 OKF v0.2 审计的可移植包；包内直接是 `index.md` / `log.md` / `concepts/` / `references/` 布局 |
| **Obsidian** | 可作同一套 Markdown 的人工编辑器，**非依赖** |
| **Firecrawl MCP** | 增强动态网页抓取，完整托管爬取可能需 Firecrawl 认证 |
| **腾讯 IMA** | `sync-ima` / `fetch-ima`，用户确认授权后把资料迁成 Reference |
| **Apple Container 部署** | `deploy/apple-container/`，公网沙箱只发 `127.0.0.1:8787`，前面接 Cloudflare Tunnel |
| **Zenodo** | 有 `.zenodo.json`（MIT，Independent Researcher），说明作者走学术存档路线 |
| **`karpathy-wiki.mjs`** | CLI dispatch 的真身文件名 —— 作者自称这条线来自 Karpathy 式的 source-grounded 写法（资产模板里也有 `web-clipper-karpathy.md`） |

---

## 参考链接

- 仓库：<https://github.com/NimaChu/my-wiki>
- README（中文 337 行）：<https://github.com/NimaChu/my-wiki/blob/main/README.md>
- Agent 入口规范：<https://github.com/NimaChu/my-wiki/blob/main/AGENTS.md>
- Skill 主文件：<https://github.com/NimaChu/my-wiki/blob/main/my-wiki-skill/SKILL.md>
- 知识模型：<https://github.com/NimaChu/my-wiki/blob/main/my-wiki-skill/references/knowledge-model.md>
- 证据门禁规则：<https://github.com/NimaChu/my-wiki/blob/main/my-wiki-skill/references/evidence-rules.md>
- Dashboard Agent 行为：<https://github.com/NimaChu/my-wiki/blob/main/my-wiki-skill/references/dashboard-agent.md>
- 远程模式：<https://github.com/NimaChu/my-wiki/blob/main/my-wiki-skill/references/remote.md>
- 文档提取架构：<https://github.com/NimaChu/my-wiki/blob/main/docs/document-extraction.md>
- Viki 传输通道：<https://github.com/NimaChu/my-wiki/blob/main/docs/viki-transports.md>
- Dashboard 前端说明：<https://github.com/NimaChu/my-wiki/blob/main/assets/dashboard/README.md>
- Apple Container 部署：<https://github.com/NimaChu/my-wiki/blob/main/deploy/apple-container/README.md>
- npm 包：<https://www.npmjs.com/package/my-wiki-skill>
- open issue #10（路径校验）：<https://github.com/NimaChu/my-wiki/issues/10>
- OKF v0.2 规范：<https://github.com/GoogleCloudPlatform/open-knowledge-format>
