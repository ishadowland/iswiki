# Semantica — 图原生 AI 可解释基础设施(AI 做了什么、依据什么、来源可追)

> 学习笔记 · 调研时间 2026-10-09
> 仓库: <https://github.com/semantica-agi/semantica> · 官网: <https://getsemantica.ai> · 文档: <https://docs.getsemantica.ai>
> License: MIT · 语言: Python (3.10–3.13) · ⭐ 13,856 · 1,592 forks · v0.7.0(2026-09-22)
> 组织: `semantica-agi`(3 个公开仓) · 建仓 2025-06-25 · 最后 push 2026-10-09 · 115 open issues

---

## 一句话定位

**在 LLM 和向量库底下垫一层"语义/上下文图"**:把企业散乱数据抽成知识图谱,让 agent 的每个决策都变成**一等公民对象**——可查询、可溯源、可回溯因果链、可导出监管格式。

**它的核心承诺不是"让 LLM 更聪明",而是"让 LLM 干的事能向监管方交差"。**

---

## ⚠️ 先纠正:用户给的 URL 是错的

用户提供的 `https://github.com/semantica` **不是这个项目**:

| 用户给的 | 实际情况 |
|---|---|
| `github.com/semantica` | 2013 年建的**空组织**,0 个公开仓,官网 semantica.co(连接超时) |
| 真正的项目 | **`github.com/semantica-agi/semantica`** — ⭐13,856 / MIT / 活跃维护 |

名字极像,极易混淆。真项目的组织名是 `semantica-agi`,官网 `getsemantica.ai`。

---

## 它到底解决什么问题

README 自己的判断很直白:

> Most AI agents run on embeddings, not meaning: similarity scores with no structure, no relationships, and no way to explain why a result came back.

向量库 + RAG 的结构性缺陷(README 对比表):

| 维度 | Vector DB + RAG | 普通 LLM Memory | Semantica |
|---|---|---|---|
| 召回方式 | 向量相似度 | token 窗口 | 图遍历 + 语义检索 |
| 决策历史 | 不存 | 不存 | **一等可查询对象** |
| 溯源 | 无 | 无 | **W3C PROV-O,链到源** |
| 推理 | 无 | 黑箱 | **前向链 / Rete / Datalog / SPARQL** |
| 冲突处理 | 静默覆盖 | 静默覆盖 | **检测、标记、解决** |
| 时间旅行 | 无 | 无 | **时点快照** |
| 合规导出 | 无 | 无 | **PROV-O / SHACL / OWL / RDF** |
| 实体归一 | 无 | 无 | 阻塞 + 语义去重 |
| 多 agent 上下文 | 各存各的 | 各存各的 | **单一共享智能层** |

---

## 关于"可解释"的边界(项目自己划得很清楚)

这是用户最关心的问题,README 和 docs/concepts.md 都用 **NOTE/Warning** 显式声明:

> **System-level explainability, not foundation-model explainability.**
> Semantica 不暴露、不重建 LLM **内部**发生了什么:模型的内部推理保持不透明,跟任何外部系统一样。
> Semantica 解释的是模型**外部**的东西:喂进去的上下文、产生的决策、它的溯源、相关关系、应用的策略、以及完整执行轨迹。

**翻译成人话**:它不解释"模型为什么这么想",它解释"**系统给模型看了什么、系统最后做了什么、依据哪条数据**"。

这正是合规场景需要的——监管方问的从来不是"你的 CoT 给我看看"(厂商也不会给),而是"**这条结论引用了哪些文档、哪张表、哪个版本、谁在什么时候批的**"。

---

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **Python SDK** | `from semantica.context import ContextGraph` | 嵌进自己的 agent 服务,决策/溯源/规则门禁 |
| **CLI** | `semantica doctor` / `semantica build` / 50+ 命令 | 本地验证、CI 里跑体检、脚本化数据管线 |
| **服务层** | REST API(100+ 端点)+ MCP Server(10+ tools) | 多 agent/多团队共享一层;Claude Code / Cursor / Codex 等编辑器插件 |

编辑器插件覆盖:Claude Code、Cursor、Codex、Windsurf、Cline、Continue、VS Code、OpenClaw、pi。
Agent 框架:Agno、CrewAI、LangChain 一等支持。

---

## 核心架构(实读 ARCHITECTURE.md + 目录树核对)

```
Sources → Ingest → Parse → Normalize → Split → Extract → Conflict → Dedup
   → Knowledge Graph → [ Ontology · Reasoning · Provenance · Decisions ] → Enriched KG
   → Vector Store + Polyglot Graph Store (RDF & LPG) → Export / Visualize / REST · MCP · CLI
```

**包结构**(`semantica/`,33 个子模块):

| 模块 | 职责 |
|---|---|
| `ingest` | 多源摄取:文件 / Web / DB / Databricks / Snowflake / SAP / Kafka / Git / 邮件 / MCP |
| `parse` `normalize` `split` | 文档解析、文本实体日期归一、**GraphRAG 原生 entity-aware 分块** |
| `semantic_extract` | NER / 关系抽取 / 事件检测 / 三元组 / 共指消解 |
| `conflicts` `deduplication` | 冲突事实检测 + 语义去重 + 实体归一 |
| `kg` | `GraphBuilder`、双时态事实、图分析(中心度/社区/链接预测) |
| `reasoning` | Rete 引擎、Datalog、SPARQL、**ExplanationGenerator** |
| `provenance` | **W3C PROV-O** 血缘,每个事实都有 |
| `ontology` | OWL 生成、SHACL 校验、SKOS 受控词表 |
| `context` | `ContextGraph` / `AgentContext` / `DecisionRecorder` / `CausalChainAnalyzer` / `PolicyEngine` |
| `graph_store` | LPG:Neo4j / FalkorDB / Apache AGE / Neptune |
| `vector_store` | FAISS / Qdrant / Weaviate / Milvus / Pinecone / PgVector + RRF 混合检索 |
| `explorer` `visualization` | Knowledge Explorer 浏览器工作台 |

---

## 最小可运行示例(**已实测跑通,含 README 的 4 个坑**)

```bash
pip install semantica        # Python 3.10–3.13,<3.14
semantica doctor             # 体检:看 graph store / vector store / embedding 后端是否就绪
```

```python
from semantica.context import ContextGraph

# ⚠️ 坑 1:README 写 advanced_analytics=True,裸装会直接失败退出
#    "Failed to initialize KG components: gensim is required for Node2Vec"
#    要么 pip install 'semantica[graph-embeddings]',要么保持默认 False
graph = ContextGraph()

d1 = graph.record_decision(
    category="vendor_selection",
    scenario="Choose cloud provider for HIPAA workload",
    reasoning="AWS offers BAA, mature HIPAA tooling, existing team expertise",
    outcome="selected_aws", confidence=0.93,
)
d2 = graph.record_decision(
    category="dosage_adjustment",
    scenario="INR monitoring plan for P-4821",
    reasoning="Reduce warfarin dose per interaction severity",
    outcome="dose_reduced_30pct", confidence=0.87,
)

# relationship_type 只能是这三个(实测枚举)
graph.add_causal_relationship(d1, d2, relationship_type="CAUSED")

# ⚠️ 坑 2:trace 要查"果"(下游),不是"因"(上游)
#    d1 是因 → trace_decision_chain(d1) 返回 []
#    d2 是果 → 才拿到完整因果跳
chain = graph.trace_decision_chain(d2)   # -> hops/hop_count/confidence_decay
# ⚠️ 坑 3:find_similar_decisions 是语义检索,喂关键词没结果
#    find_similar_decisions("cloud vendor")            -> []
#    find_similar_decisions("<完整 scenario 原文>")     -> 命中
similar = graph.find_similar_decisions(d1.scenario if hasattr(d1,'scenario') else
                                       "Choose cloud provider for HIPAA workload", max_results=3)

impact  = graph.analyze_decision_impact(d1)          # 下游影响图(d1 作为因,能列出 d2)

# ⚠️ 坑 4:check_decision_rules 必须喂完整 payload,否则合规判定是假阴性
graph.check_decision_rules({"category": "vendor_selection"})
# -> {'compliant': False, 'violations': ['Confidence too low: 0', 'Invalid outcome: None',
#                                       'Missing required field: decision_maker'], ...}   ← 全是假报警
graph.check_decision_rules({
    "category": "vendor_selection", "outcome": "approved", "confidence": 0.93,
    "reasoning": "ok", "decision_maker": "compliance-officer",
})
# -> {'compliant': True, 'violations': [], ...}   ← 真实策略: min_confidence 0.7
#                                                        required_outcomes [approved,rejected,flagged]
#                                                        required_metadata [decision_maker]
#                                                        max_reasoning_length 10000
```

**导出监管格式:**

```python
from semantica.provenance import ProvenanceManager
from semantica.export import RDFExporter

prov = ProvenanceManager(storage_path="./audit.db")
prov.track_entity("patient_P4821", source="ehr/medication_orders_2024.json",
                  metadata={"extractor": "NamedEntityRecognizer"})

kg = graph.to_kg_dict()          # 官方适配器,产出 {"entities","relationships","statistics"}
RDFExporter().export(kg, "audit_trail.ttl", format="turtle")   # W3C PROV-O Turtle
```

`to_kg_dict()` 实测返回 key:`['entities', 'relationships', 'statistics']`。

---

## 实测核验记录(本机跑出来的真实结果)

**环境**:Python 3.10.7 / macOS / 裸装 `pip install semantica`(63 个包落地,pyproject 声明 122 个依赖)

| 项 | README 声称 | 实测 |
|---|---|---|
| `pip install semantica` 即可用 | ✅ | ✅ 成立 |
| `ContextGraph(advanced_analytics=True)` | Quick Start 首行 | ❌ **裸装失败退出**(gensim 缺失) |
| `trace_decision_chain(decision_id)` "full causal ancestry" | 完整祖先链 | ⚠️ 只对**下游(果)**有效,对因返回 `[]` |
| `find_similar_decisions("cloud vendor")` | precedent 检索 | ⚠️ 关键词无结果,需语义相近原文 |
| `check_decision_rules({...})` "policy gate" | 合规门禁 | ⚠️ 缺字段时 `compliant: False` 是**假阴性** |
| 推理 / KG 构建 / 溯源层无需 LLM | ✅ | ✅ 确认,全离线可跑 |
| `semantica doctor` | 5 秒验证 | ✅ 成立,输出 Python/库/后端/LLM key 全表 |

`semantica doctor` 裸装实际输出:Python ✓ 3.10.7、semantica ✓ 0.7.0、rich ✓、Graph store ✗(未装 neo4j)、Vector store ✗(未装 faiss)、Embeddings ✗ ×2、OpenAI/Anthropic/Groq ⚠(key 未设)。

**性能声称**(README 自己标注了口径,值得抄录):118,000 节点生产图上节点搜索 24ms → 0.004ms(6,000×)、embedding 缓存命中 10× 吞吐、语义去重 6.98×。README **主动声明**去重/候选生成数字是 CHANGELOG 里的历史测量值而非 `tests/` 断言,建议自己跑 `pytest tests/vector_store/test_performance_benchmarks.py -s` 复测。

---

## 合规场景落地路径(金融 / 医疗 / 法律)

**它的合规卖点 = 结构本身,审计是副产品:**

> Decision provenance and audit trails aren't the product. They fall out of that structure for free.

三条可复用路径:

| 场景 | 组合方式 |
|---|---|
| **医疗** | `record_decision(category="drug_interaction_check")` + `add_causal_relationship(CAUSED)` + `track_entity(source="ehr/...")` + RDF Turtle 导出 → 药品相互作用决策链可交监管 |
| **金融 / AML** | 规则引擎建在 KG 上,`check_decision_rules` 做放行/拦截门禁;README 的 More Recipes 有现成 AML rules engine 配方 |
| **法律 / 合同** | `FileIngestor().ingest_directory("./contracts/")` 批量入库,合同条款进图,引用关系可追到具体文件与抽取器 |

**为什么比"给 agent 加日志"强**:日志是流水文本,图是**结构化带血缘的关系**。监管问"这条结论怎么来的",图能答"因为 d1(选了 AWS,BAA 齐备,置信 0.93)导致 d2(剂量下调 30%)",日志只能让你自己读。

---

## 跟我们的关系

**定位:金融/医疗/法律自建方案的"可解释性"层参考实现。**

用户此前反复表达过对自建方案的"登录/用户管理/网络安全"有清醒质疑、不愿交数据给第三方 SaaS。Semantica 正好是这条路线的**可解释层**:

1. **可自托管 + MIT + 多后端** — Neo4j / Oxigraph / RDF4J / Neptune 可换,不锁定单一厂商,数据不出内网
2. **对"黑箱"给了工程答案** — 不是说"相信大模型",而是把系统级可追溯做成可导出的 PROV-O/RDF/SHACL 制品
3. **与用户现有栈的关系** — 官方明确"**不替换**你的 LLM / 向量库 / agent 框架",只是加一层决策记录 + 因果推理 + 溯源,可以只取用 `semantica.context` 这一个模块

**建议的最小引入路径**(真要落地,别一上来全装):

```bash
pip install semantica                        # 只用 context/reasoning/provenance 三模块,全离线
# 按需再补:pip install 'semantica[db-databricks,shacl,documents]'
```

**但要清醒的三点:**

1. **v0.7.0 还是 pre-1.0** — 建仓 2025-06,迭代很快(MINOR 月级),API 未冻结;`>=3.10,<3.14` 卡死了 Python 3.14+ 用户
2. **社区高度集中在单一作者** — KaifAhmad1 一人 2,066 次提交(总贡献第二 286),bus factor 是 1;1592 forks 但 115 open issues。MIT + 单人主导适合做参考实现,**不适合把审计链押在它上面**
3. **审计链本身要被审计** — 用它生成的 PROV-O 交给监管,监管会问"你的图本身对不对"。SHACL 约束校验和 entity resolution 的准确率需要**自己在业务数据上验证**,它给的是"可追",不是"保证对"

---

## 版本节奏

| 版本 | 日期 | 备注 |
|---|---|---|
| v0.7.0 | 2026-09-22 | 当前最新(PyPI 与 GitHub tag 一致) |
| v0.6.8 | 2026-09-05 | |
| v0.6.7 | 2026-08-28 | |
| v0.6.6 | 2026-08-20 | |
| v0.6.5 | 2026-08-11 | |
| v0.6.0 | 2026-07-21 | |
| v0.5.1 | 2026-06-29 | 性能数字出自此版本 |
| v0.5.0 | 2026-05-11 | |
| v0.4.0 | 2026-04-08 | |
| 0.0.1 (PyPI 首发) | 2025-11-21 | |

PyPI 累计 25 个 release。发布纪律:MAJOR 季度/按需,MINOR 月级或随时,PATCH 随时。

---

## 依赖矩阵(选装策略,重要)

**122 个依赖声明**,但裸装只落 63 个包 —— 因为重依赖全在 extras 里。**关键分组:**

| 用途 | extra | 装什么 |
|---|---|---|
| LLM provider(9 家) | `llm-all` / `llm-openai` 等 | openai / anthropic / google-genai / groq / ollama / litellm / deepseek… **用不到就别装** |
| 文档解析 | `documents` `parse-pdf` `parse-docling` | python-docx / openpyxl / lxml / beautifulsoup4 / pdfplumber |
| SHACL 校验 | `shacl` | pyshacl |
| 企业数据平台 | `db-databricks` `db-snowflake` `db-all` | databricks-sdk / snowflake-connector |
| 图后端 | `graph-neo4j` `graph-falkordb` `graph-apache-age` | 对应驱动 |
| 向量库 | `vector-*` | FAISS / Qdrant / Weaviate 等 |
| **图嵌入(坑 1 的解法)** | **`graph-embeddings`** | **gensim —— 缺它 `advanced_analytics=True` 直接崩** |
| 本地 embedding | `embeddings-local` | sentence-transformers / fastembed / onnxruntime |
| NLP | `nlp-spacy` `nlp-langdetect` | spacy / langdetect(不装则语言检测全返回默认值) |

**核心常驻依赖**:numpy>=2.0.2、pandas、scipy、scikit-learn、rdflib>=6.2.0、networkx、pydantic>=2.13.4、click、rich、structlog、loguru、pyarrow。

**LLM 是可选的** — `semantica.llms` 支持 9 家 provider,不用 LLM 也能跑图构建 / 推理 / 溯源(实测确认)。

---

## 实战建议 / 风险点

| 风险 | 说明 | 缓解 |
|---|---|---|
| **README 示例误导** | Quick Start 首行裸装即崩;4 处 API 语义未说明(见上文坑 1–4) | 按本文实测版抄代码,别照抄 README |
| **pre-1.0,API 会变** | 2025-06 建仓,11 个月 25 个 release | 锁版本 `semantica==0.7.0`,升级前跑回归 |
| **bus factor = 1** | 头号贡献者一人占 2,066 次提交 | 当参考实现 / 可解释层组件,别当审计系统唯一依赖 |
| **Python <3.14** | 上限卡死 | 3.14+ 环境只能跑源码或 fork |
| **合规≠正确** | PROV-O 只证明"记录完整",不证明"抽取准确" | entity resolution / 冲突检测必须在业务数据上验证召回率 |
| **凭据硬编码** | README 示例明写 `token`/`password`/`private_key` | 一律走环境变量或 secrets manager(README 自己有 Security Note) |
| **性能数字不可直接引用** | 部分来自 CHANGELOG 历史测量,非测试断言 | 自跑 benchmark 再写进自己方案 |

---

## 配套生态

- **Knowledge Explorer** — 交互式浏览器工作台,可视化图 / 本体 / 时间线
- **REST API** — 100+ 端点;**MCP Server** — 10+ tools
- **CLI** — 58 个命令注册(实测解析 `cli.py`,README 声称 50+),22 个命令组
- **编辑器插件** — Claude Code / Cursor / Codex / Windsurf / Cline / Continue / VS Code / OpenClaw / pi
- **Discord + X**(@BuildSemantica)+ 13 语言 README(readme-i18n,含中文版)
- **OpenSSF Scorecard** badge + Checkov 配置 + OSV Scanner(供应链安全有意识)

---

## 参考链接

- 仓库: <https://github.com/semantica-agi/semantica>
- 官网: <https://getsemantica.ai>
- 文档: <https://docs.getsemantica.ai>
- PyPI: <https://pypi.org/project/semantica/>
- 架构图: <https://github.com/semantica-agi/semantica/blob/main/ARCHITECTURE.md>
- 核心概念(可解释边界原文): <https://github.com/semantica-agi/semantica/blob/main/docs/concepts.md>
- 治理模型: <https://github.com/semantica-agi/semantica/blob/main/docs/governance.md>
- CHANGELOG(性能数字出处): <https://github.com/semantica-agi/semantica/blob/main/CHANGELOG.md>
- Cookbook: <https://github.com/semantica-agi/semantica/tree/main/cookbook>
- DeepWiki: <https://deepwiki.com/semantica-agi/semantica>
- 平台演示视频: <https://www.youtube.com/watch?v=QfnNZg4-dZA>