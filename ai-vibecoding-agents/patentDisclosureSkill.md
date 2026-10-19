# patent-disclosure-skill — 中国专利.skill：把「交底书 / 申请文件 / 解读 / 审查答复」全流程塞进 9 个子 skill 的 Agent 技能包

> 学习笔记 · 调研时间 2026-10-19
> 仓库: https://github.com/handsomestWei/patent-disclosure-skill · 主页: https://skillhub.cn/skills/patent-disclosure-skill
> License: **MIT** · 语言: Python（+ 14 个 js）· ⭐ **11,836** · Fork **1,251** · 版本 **5.1.0**（写在 SKILL.md frontmatter，无 tag/release）
> 创建 2026-04-07 · 最后 push 2026-10-18 · 16 open issues · 作者 handsomestWei 66 commits + 4 人各 1~3 commit

---

## 一句话定位

**中国专利全流程的 Agent 技能包**：把项目材料 / 公开号 / 审查意见分别路由到 9 个子 skill，产出交底书（发明 / 实用新型 / 外观）、申请文件四件套、通俗解读笔记、专利地图、权利要求对照表和政策简报——**根 `SKILL.md` 只做路由，一个字的业务正文都没有**。

---

## 核心架构：根文件是纯路由器，正文全在 `skills/*/`

这是本仓最值得学的设计决策：**`SKILL.md` 8.4 KB / 86 行，全部内容是「能力总览 + 路由判定表 + 通则 + 执行前核对」**，真正的业务逻辑散在 9 个子包里。

```
patent-disclosure-skill/
├── SKILL.md                    # 纯路由：9 条路由 + 须点名门禁 + 通则（86 行）
├── INSTALL.md                  # 14.8 KB 安装说明（Claude Code / Cursor / 分层依赖）
├── requirements.txt            # 主依赖只要 6 个包
├── skills/
│   ├── patent-disclosure/      # 交底书（发明/实用/外观）—— 仓库体积最大的包
│   ├── patent-application/     # 申请文件四件套      ⚪ 须点名
│   ├── patent-docket/          # 案卷会稿（交底+申请一趟）  ⚪ 须点名
│   ├── patent-reader/          # 通俗解读 + Obsidian 入库
│   ├── patent-search/          # CNIPA 著录检索
│   ├── patent-chart/           # 权利要求对照表       ⚪ 须点名
│   ├── patent-map/             # 专利地图（本机网页）   ⚪ 须点名
│   ├── patent-oa/              # 审查答复辅助          ⚪ 须点名
│   └── patent-exam-policy/     # 政策简报             ⚪ 须点名
├── docs/                       # 8 张效果截图（约 2.7 MB）
└── .github/workflows/          # 仅一个 update-star-history
```

**规模（2026-10-19 一手统计）**：

| 指标 | 值 |
|---|---|
| 仓库文件总数 | **489** |
| `.py` | 222（含 **59 个 `test_*.py`**） |
| `.md` | 155（prompt / reference / README 分层） |
| `.yaml` | **42**（几乎全是 JSON Schema） |
| `.js` | 14（含 vendor 的 mermaid + three.js） |
| Python 源码总量 | **2.06 MB ≈ 5.9 万行**（按 35 字节/行粗估） |

⚠️ 59 个测试文件对 489 文件的仓不是低比例——**它是有测试的 skill 包**，不是纯 prompt 堆。

---

## 三个真正值得抄的设计

### 1. 「须点名」门禁表：把「防止 agent 自由联想越界」写进 SKILL.md

根 SKILL.md 的**路由判定表**有一列叫「前置门禁」，明确标注 9 个能力里 **6 个「须点名」**（application / docket / chart / map / oa / exam-policy），并写死两条铁律：

> 「**须点名**」= 只有用户明确说出该行触发词才进入，**禁止**由写交底或读专利自动进入。
> 「技能进化 / `/patent-evolve`」同一入口 —— **无点名不改技能文件**。

这解决了 skill 类项目的一个通病：agent 干完 A 顺手把 B 也做了，用户失去控制。**把「不许自动进入」写成硬约束 + 每个包 SKILL.md 都复述一遍**（每个子包的「何时用」段都重复「须用户点名」），比写在总则里有效得多。

### 2. prompt 目录 = 显式状态机，schema gate 卡在成文之前

`patent-disclosure/prompts/` 里是 8 步流水线（intake → project_scan → 挖点 → 查新 → **Step 5.5 D1 锁定** → preview → builder → self_check），**每步对应一个 prompt 文件名，SKILL.md 用表格列出来**：

| 步骤 | 文件 |
|---|---|
| Step 5.5 | 同文件「D1 锁定与区别特征 Fk」：钉一篇最接近对比文件 + 逐特征表 + **三态门禁** |
| 迭代 | `iteration_context.md` / `merger.md` / `correction_handler.md` |

`patent-docket` 更进一步——它是**带轮次上限的状态机**：

```yaml
# references/phases.yaml 定义合法跳转
phase: bootstrap_disclosure → dispatch_disclosure → wait_disclosure
     → bootstrap_application → dispatch_application → wait_application
     → triage → ask_human → round_close → terminal_*
```

`config.yaml` 里 `max_rounds: 3`，「从零：首套交底 + 首套申请记为第 1 轮，之后每『分诊 → 派工 → 再出申请并核清单』加 1 轮，**第 3 轮结束后必须停**」。

**schema gate** 是另一道闸：所有结构化产物先落 YAML Schema（42 个 yaml），再用 Python 脚本校验，**退出码非 0 就停**：

```bash
# 缺材料 → 退出码 2，必须回到交底技能补齐
python skills/patent-application/tools/material_gate.py --case-dir outputs/{案件}
# 交底查新：退出码 3 = 部分结果，「禁止据此声称全部」
python skills/patent-disclosure/tools/crawl/cnipa_epub_search.py --type utility_model 卡扣
```

### 3. 机读前缀 + 退出码协议：让 LLM 不靠猜判断成败

所有脚本输出固定前缀，让 agent「**以退出码和机读前缀为准**」：

| 前缀 | 来源脚本 |
|---|---|
| `PROBE:` | 浏览器探测 |
| `EPUB_HITS_JSON:` / `EPUB_SEARCH_JSON:` / `EPUB_SEARCH_INCOMPLETE:` | CNIPA 检索 |
| `MERMAID:` / `DOCX:` / `MATH:` | 出图 / 出 Word / 公式 |
| `DOCKET_DIR:` / `DOCKET_YAML:` / `DOCKET_OK:` / `DOCKET_ERROR:` | 案卷 |
| `MAP_URL:` / `MAP_PORT:` / `MAP_VAULT:` / `MAP_MODEL:` | 专利地图 |
| `INTAKE_OK:1` | 对照表输入齐备 |

INSTALL.md 还专门写了一句防坑：**「stderr 有中文或 PowerShell `NativeCommandError` 不等于失败」，「不要用 `2>&1` 把 JSON 混进错误流」**。这是被 Windows 终端坑过才会写下的句子。

---

## 依赖分层：主依赖极薄，重型能力全部隔离

`requirements.txt` 只有 6 个包：

```text
python-docx>=1.1.0      # Word 出入
latex2mathml>=3.77.0    # LaTeX → MathML → OMML(Word 可编辑公式)
PyYAML>=6.0             # schema / formula paradigms
playwright>=1.40.0      # mermaid → PNG，且与 CNIPA 爬虫共用浏览器
mammoth>=1.6.0          # docx → md
python-pptx>=0.6.21     # pptx → md
```

其余全是**按需装、装在独立位置**：

| 能力 | 依赖 | 隔离方式 |
|---|---|---|
| mermaid 出图 | **系统 Chrome/Edge** + Playwright | 不必装 Node / npm / mmdc（mermaid.min.js 2.5 MB vendor 在仓里） |
| 公式 PNG | matplotlib（~100 MB） | **默认不装**，仅当 stderr 出现 `omml_text_fallback` 且用户回「是」 |
| CNIPA 爬虫 | `tools/crawl/requirements-cnipa.txt` | 独立；失败可降级 WebSearch |
| PDF 扫描 | `tools/requirements-pdf.txt`（pymupdf） | 有 PDF 才装 |
| CAD / STEP | **CadQuery，装进隔离 venv（Python 3.10–3.12）** | `cad_venv.py` / `bootstrap_cad_venv.py`；默认关闭，成文落盘后才反问是否开启 |
| OA 向量库 | `requirements-oa.txt` + 智谱 embedding-3 / DashScope / MiniMax / 本地 / OpenAI | 模型与案例库落 `{Documents}/patent-disclosure-skill/oa/` |
| 专利地图地形 | fastembed（不含 PyTorch） | `bge-small-zh-v1.5` **只装 Qdrant ONNX**；没装也能开图，退回 IPC 簇 |

**最值得注意的一条工程约束**：CadQuery 的版本要求 Python 3.10–3.12，脚本明确写「本机已是 3.11/3.12 不必再装 3.10」，且「CAD 出图**不使用** matplotlib」——**同一个项目里 matplotlib 只服务发明公式 PNG**。这种隔离粒度在 skill 里很少见。

---

## 9 个子 skill 一览

| 子 skill | 做什么 | 主产出 | 须点名 |
|---|---|---|---|
| `patent-disclosure` | 挖专利点 → 轻量查新 → 成文 → 迭代；首篇定稿后可做**保护型 1+N 围栏布局** | 交底书 md + docx + 查新定位稿 | — |
| `patent-application` | 交底 → 权要 / 说明书 / 摘要 / 黑白附图 | 四件套 + 旁路 `问题清单.md` | ⚪ |
| `patent-docket` | 案卷会稿：交底工程师 vs 代理师角色扮演，多轮记账 | `docket.yaml` + `TRACKER.md` | ⚪ |
| `patent-reader` | 公开号/PDF → 通俗笔记 + 图谱 + Obsidian 入库 | `claim_features.json` / `description_paragraphs.json` | — |
| `patent-search` | CNIPA 公布站高级检索；也能**扔一张产品图或一段权要倒推检索式** | `SEARCH-*.md` | — |
| `patent-map` | 已入库案例摊成**五种图**（语义地形 / 申请人四象限 / 同族引证网 / 功效矩阵 / 仪表盘） | 本机 URL（`127.0.0.1:0` 随机端口） | ⚪ |
| `patent-oa` | 审查意见拆条款问答 + 草稿；历史案脱敏入库后对照旧打法 | 意见陈述 md → 确认后 docx | ⚪ |
| `patent-chart` | 独权拆特征格，逐格填对比文件/产品/标准的证据与强弱 | **Excel 主交付**（按场景加专用页） | ⚪ |
| `patent-exam-policy` | 对照国知局近期口径出简报，指出哪些写法可能过时 | `outputs/exam-policy/` | ⚪ |

### 三个设计细节

**① 保护型 1+N 围栏（`prompts/fence/`）** —— 首篇交底定稿后的专利布局旁路，流程是 `decompose → design_around → matrix → plan → score → dispatch`，弱校验表对齐 **GB/T 42748《专利评估指引》**的法律 / 技术 / 经济价值度 + 一条自加的「围栏可行性」。评分表里写了一句很清醒的话：

> 海外同族 / 维持十年 / 质押 / 金奖交底阶段全是空的，**禁止打正分**。这不是资产评估报告，也不是国知局「高价值发明专利」统计口径。

**② 对照表按场景出不同页** —— xlsx 固定含总览 / 对照表 / 明细 / 图例，`invalidity` 加「路径备忘」、`fto` 加「风险清单」、`infringement` 加「证据缺口」、`oa` 加「驳回映射」。SKILL.md 反复强调**「不出法律意见」**。

**③ 专利地图是纯本机私有** —— three.js + 一个 10.5 KB 的 `terrain3d.js`，模型只装 ONNX 不装 PyTorch，索引和模型落 `{Documents}/patent-disclosure-skill/patent-map/`（`PATENT_MAP_HOME` 可改）。README 里有一句诚实的话：「空白点只表示**库里没读到**」。

---

## 实战：最小安装与验证

```bash
git clone https://github.com/handsomestWei/patent-disclosure-skill.git
cd patent-disclosure-skill
pip install -r requirements.txt

# 关键一步：探测系统浏览器能不能起（出图 + 查新共用）
python skills/patent-disclosure/tools/browser.py --probe
#  ok=true → 直接定稿出图 + 跑 CNIPA 检索
#  没有 Chrome/Edge 才需要：python -m playwright install chromium

# CNIPA 著录检索
pip install -r skills/patent-disclosure/tools/crawl/requirements-cnipa.txt
python skills/patent-search/tools/cnipa_search.py \
  --inventor "发明人姓名" --applicant "申请主体" --type all

# 案卷（须显式触发后才会到这里）
python skills/patent-docket/tools/init_docket.py --case-id 案件slug --mode from_zero
python skills/patent-docket/tools/validate_docket.py --yaml outputs/docket/案件slug/docket.yaml
```

**触发方式**：`/交底书` `/patent-disclosure`（默认发明）· `/申请底稿` `/patent-apply` · `/patent-docket` · `/读专利` `/patent-read` · `/patent-search` · `/patent-chart` · `/专利地图` `/patent-map` · `/oa` · `/政策简报` `/patent-brief`。frontmatter 还声明 `user-invocable: true` + `argument-hint`，斜杠命令可直接带参数。

---

## ⚠️ 坑点与风险（一手核验）

| # | 发现 | 说明 |
|---|---|---|
| 1 | **无 tag / 无 release** | `gh api .../tags` 和 `/releases` 均返回空。版本号 `5.1.0` 只写在根 SKILL.md frontmatter 里，**安装无版本锚点**，半年后无法判断装的是哪版 |
| 2 | **工具副本是有意为之** | `md_to_docx.py` **3 份**（47,138 / 45,633 / 45,899 字节）、`browser.py` **3 份**、`emit_chart.py` 2 份、`xlsx_minimal.py` 2 份、`highlights.py` 2 份，合计约 190 KB 重复代码。SKILL.md 通则明说「同一能力已有本包副本时，跑本包这一份」——**为「单独拷走某一子包」服务**。代价：fork 后改一处漏两处 = bug |
| 3 | **Windows 优先** | INSTALL.md 14.8 KB 里 PowerShell 命令、`C:\Users\...` 路径、中文乱码防护占了近半。macOS / Linux 路径虽给了，但整仓没有 CI，跨平台问题只能自己踩 |
| 4 | **无 CI** | `.github/workflows/` 只有一个 `update-star-history`。59 个测试文件**不会被自动跑** |
| 5 | **反爬依赖** | CNIPA 公布站抓取靠 Playwright 驱动真实浏览器过 WAF，每个包自带一份 `browser.py`。**存在被国知局风控拦截 / IP 限流的可能**，仓内也承认可降级为 WebSearch |
| 6 | **污染本机路径** | 模型与向量库默认落系统**文档目录** `{Documents}/patent-disclosure-skill/`（`PATENT_MAP_HOME` / `PATENT_OA_HOME` 可改），不是工作区。Windows 上就是 `C:\Users\<你>\Documents\`，容易在备份 / 同步里翻车 |
| 7 | **只覆盖中国专利** | 全部流程绑定 CNIPA（`epub.cnipa.gov.cn`）、国知局政策、IPC 分类表（`ipc_subclasses_2026.01.csv`）。**美 / 欧 / 日专利不在范围内** |
| 8 | **法律性质** | 仓库自己反复声明：对照表是**底稿**、不含法律意见；OA 草稿**须代理师复核签字**；围栏评分表**不是资产评估报告**。用它产出的东西对外递交前必须人工过 |
| 9 | **bus factor 偏低** | 66 commits 里 62 条来自作者一人，另 4 人共 6 commit。README 里的 star history 也说明维护者数量少 |
| 10 | **体积** | clone 下来约 2.7 MB 光 `docs/` 截图（8 张 jpg/png）+ 3.2 MB vendor JS + 2 MB Python。只想要提示词的话会白拉一堆 |

---

## 跟我们的关系

**直接可用**：这是一个标准 AgentSkills 布局的仓（根目录即技能根 + `SKILL.md`），可以原样 clone 进 `~/.hermes/skills/`，Hermes 的 skill 机制能直接吃。但有三点要注意：

1. **不要整仓塞进来**。5.9 万行 Python + 42 个 schema 全量加载毫无意义，而且它的 9 个子 skill 走的是「root 路由 + Read 子 SKILL.md」模式，Hermes 的 skill 索引会把它当成**一个** skill 描述，路由表根本不会生效。
2. **frontmatter 字段不通用**。根 SKILL.md 里的 `allowed-tools: Read, Write, Edit, Grep, Glob, WebSearch, Bash` 是 Claude Code 的约定，Hermes 会忽略；`description` 是中英双语的 200+ 字长串，塞进 Hermes 的 skill 索引会挤掉其他 skill 的触发空间。
3. **实用做法**：只挑 `skills/patent-search` 或 `skills/patent-disclosure` 单个包拷出来改造成 Hermes skill（去掉 `name/description` 之外的多余 frontmatter，触发词按我们的习惯重写）。

**真正的价值在方法论而非代码**。这个仓把「skill 该怎么组织」这件事演示得比大多数 skill 仓库清楚，值得直接抄的三点：

- **根 SKILL.md 只做路由**，正文下沉到子包，每行都写清「进哪个包 / 前置门禁 / 明确不要做什么」
- **「须点名」作为硬门禁**抑制 agent 自由联想越界——这跟我们遇到的问题是同一类（agent 干完 A 顺手把 B 也做了）
- **机读前缀 + 退出码协议 + schema gate**，让 LLM 判断成败不靠猜；Windows 终端那句「stderr 有中文不等于失败」是被坑过的血泪

**领域层面**：我们做的 3DGS 变电站数字孪生、ReArk 桌面逆向工作台、YOLO 缺陷检测这些方向，如果要对外做技术交付或谈合作，**都可能需要走一遍专利交底**。这个 skill 的交底包（挖点 → 查新 → 三态门禁 → 成文 → docx）正好是这条路径的现成 SOP，可以当作**「我们的项目怎么把技术贡献变成可交付物」的模板**读，不必真装。

**可单独拆用的资产**（就算不用整个 skill 也有价值）：

- `skills/patent-map/data/ipc_subclasses_2026.01.csv`（88 KB，**2026 年 1 月版 IPC 分类表**）——纯数据，可当分类查询表
- `skills/patent-search/tools/cnipa_search.py`（41.8 KB）+ `cnipa_parse.py`（21.8 KB）——**CNIPA 公布站检索 + 解析的完整实现**，反 WAF 方案齐全
- `skills/patent-reader/tools/extract/fetch_patent_pdf.py`（16.3 KB）——公开号 → PDF 抓取
- `skills/patent-reader/tools/vault/clue_vault.py`（**61.5 KB，仓内最大单文件**）——Obsidian 线索库

---

## 参考链接

- 仓库: https://github.com/handsomestWei/patent-disclosure-skill
- 安装说明: https://github.com/handsomestWei/patent-disclosure-skill/blob/main/INSTALL.md
- 技能入口（路由）: https://github.com/handsomestWei/patent-disclosure-skill/blob/main/SKILL.md
- SkillHub 主页: https://skillhub.cn/skills/patent-disclosure-skill
- AgentSkills 规范: https://agentskills.io
- 围栏评分表（GB/T 42748 对齐）: https://github.com/handsomestWei/patent-disclosure-skill/blob/main/skills/patent-disclosure/references/scorecards/gbt42748_fence.yaml
- CNIPA 公布公告站: http://epub.cnipa.gov.cn/
- Obsidian CLI: https://help.obsidian.md/cli
