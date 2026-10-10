# Redis AI Stack — Redis 把向量 + 智能体记忆 + 语义缓存收进一个内核

> 学习笔记 · 调研时间 2026-10-10
> 触发来源: 微信公众号《Redis 宣布正式接入AI》 https://mp.weixin.qq.com/s/EKM40ww-giB-rMr8_pMPWA
> 主仓: https://github.com/redis/redis · 文档: https://redis.io/docs/latest/develop/ai/ · RedisVL: https://docs.redisvl.com/
> License: **Redis 8 起三重授权 RSALv2 / SSPLv1 / AGPLv3**(≤7.2 为 BSD-3)· 语言 C · ⭐ 76,677 · 最新稳定 8.10.2 (2026-09-17)

---

## 一句话定位

Redis 8 把 Vector Set + 向量检索引擎 + Agent Memory + 语义缓存做进内核，让「向量库 + 会话库 + 缓存」三件套收敛成一个组件。

---

## 一手核验：原文 3 处需要纠正的地方

公众号文章整体方向没错，但**代码与包名有 3 处对不上真实仓库**（已 clone `redis/redis-vl-java` 逐个核对类名与方法签名）：

| # | 原文写法 | 实际（redis-vl-java main 分支） |
|---|---|---|
| 1 | `com.redis.vl.extensions.session.SemanticSessionManager` | **包路径不存在**。实际在 `com.redis.vl.extensions.messagehistory`，类是 `SemanticMessageHistory` |
| 2 | `SemanticCache.builder()....redisUrl("redis://localhost:6379")` | Builder **没有 `redisUrl()` 方法**。必须传 `redisClient(UnifiedJedis)` + `vectorizer(BaseVectorizer)`，两者都必填，否则 `build()` 抛 `IllegalArgumentException` |
| 3 | `cache.check(question, 1)` 返回 `List<CacheHit>` | `check(String)` 返回 `Optional<CacheHit>`；取 topK 要用 **`checkTopK(prompt, k)`** |

另外两处数字也对不上远端：

- 原文写 `<artifactId>redis-vl-java</artifactId>` → Maven Central 上**实际 artifactId 是 `redisvl`**（`com.redis:redisvl:0.13.1`，2026-02-20）。`redis-vl-java` 这个 artifactId 在 repo1.maven.org 上 404。
- 原文写 `langchain4j-redis` 版本 `0.36.0` → 该坐标已废弃：0.36.x 之后**再无更新**（maven-metadata `lastUpdated=20241222135741`，2024-12 之后停更）。Redis 集成已迁到 **`dev.langchain4j:langchain4j-community-redis:1.21.0-beta31`**。

**所以：这篇文章适合当概念地图，不适合当 copy-paste 教程。**

---

## 三层架构

```
Redis 8 内核
├── 数据结构层
│   ├── Vector Set        原生类型，VADD / VSIM / VSETATTR，HNSW 索引
│   └── Hash / JSON       配 FT.CREATE 的 VECTOR 字段（RediSearch 已并入内核）
├── 检索层
│   ├── Vector Set 查询    VSIM + FILTER（向量 + 标量过滤一次调用）
│   └── Search 查询        FT.SEARCH 混合查询（全文 + 数值 + TAG + KNN）
└── Context Engine 层（Redis Iris，托管服务）
    ├── LangCache                    语义缓存
    ├── Agent Memory                 会话记忆 + 长期记忆
    ├── Context Retriever            业务数据 → 受治理的 MCP 工具
    └── Data Integration            CDC 近实时同步源库
```

**关键分界**：前两层是 Redis 8 开箱即用的开源能力；第三层 Redis Iris 是**托管服务**（Redis Cloud 上完全托管，或自己部署），本地起 Redis 拿不到 Iris 全套。

---

## 核心能力速查

### Vector Set（原生命令，Redis 8.0+）

| 命令 | 作用 |
|---|---|
| `VADD key [REDUCE dim] (FP32｜VALUES num) vector element [CAS] [NOQUANT｜Q8｜BIN] [EF n] [SETATTR attrs] [M nlinks]` | 加元素 / 更新向量 |
| `VSIM key (FP32｜VALUES num) vector [WITHSCORES] [COUNT n] [FILTER expr] [FILTER-EF n]` | 相似检索 + 标量过滤 |
| `VSETATTR key element json` | 挂标量属性，供 FILTER 用 |

向量检索 + 业务过滤在**一次调用**里完成，推荐系统、权限隔离的语义搜索省掉一整轮往返。

```bash
# 建集合 + 挂属性
VADD movies VALUES 4 0.12 0.88 0.35 0.91 "流浪地球"
VSETATTR movies "流浪地球" '{"year": 2019, "type": "科幻"}'

# 相似检索 + 一步过滤：只看 2015 年后的科幻片
VSIM movies VALUES 4 0.13 0.86 0.33 0.90 COUNT 2 \
     FILTER '.year > 2015 and .type == "科幻"'
```

### 量化：内存 vs 召回（官方 memory.md 数据）

| 模式 | 体积 | 召回 | 官方建议 |
|---|---|---|---|
| `NOQUANT` (FP32) | 1× | 最高 | 精度极致要求 |
| **`Q8`** | **4× 小** | High | **默认，绝大多数生产场景选它** |
| `BIN` | **32× 小** | 明显下降 | 超大规模 / 粗召回 |

官方 recommendation 就是「先用 BIN 粗召回捞几百条，再用原始精度向量精排」的两段式。另外还有 `REDUCE dim` 随机投影降维（投影矩阵随 vector set 一起持久化）。

> 注：M 参数别乱调大——官方警告单节点 `M=64` 光 links 就吃 ~1KB。

### Search 混合查询（RediSearch 已并入内核）

```bash
FT.CREATE idx:docs ON HASH PREFIX 1 doc: SCHEMA \
  title TEXT category TAG views NUMERIC SORTABLE \
  embedding VECTOR HNSW 6 TYPE FLOAT32 DIM 1536 DISTANCE_METRIC COSINE

# 过滤在前、KNN 在后 —— Redis 向量查询的标准写法
FT.SEARCH idx:docs \
  '(@category:{技术} @views:[1000 +inf])=>[KNN 5 @embedding $vec AS score]' \
  PARAMS 2 vec "<二进制向量>" SORTBY score ASC RETURN 2 title score DIALECT 2
```

索引类型支持 `HNSW`（近似，图分层跳跃，对数级延迟）与 `FLAT`（暴力，精确）。

---

## 开发者工具生态

| 组件 | 语言 / 坐标 | 最新版 | 用途 |
|---|---|---|---|
| **redisvl** (Python) | `pip install redisvl` | **0.28.0** | 主线客户端：索引管理 / 向量检索 / 混合检索 / 重排 / 语义缓存 / LLM Memory / MCP server（`pip install redisvl[mcp]`）|
| **RedisVL Java** | `com.redis:redisvl` | **0.13.1** (2026-02-20) | Java 17+ 客户端，⭐ 21，MIT |
| **langchain4j-community-redis** | `dev.langchain4j` | 1.21.0-beta31 | LangChain4j 官方 Redis 集成（旧的 `langchain4j-redis` 已停更在 0.36.2）|
| **mcp-redis** | `redis/mcp-redis` ⭐ 633 | 0.5.1 (2026-08-05) | 官方 MCP Server，MIT。Claude 等助手用自然语言直接操作 Redis |
| **agent-memory-client-java** | `com.redis` | 0.1.0 | Agent Memory Java SDK |

> ⚠️ RedisVL Java 上游最后提交 2026-06-05，⭐ 仅 21，**属于早期项目**。生产用之前自己验一遍。

### 语义缓存（LangCache）

最容易算清 ROI 的一块：官方口径 **LLM 成本最多降 70%、命中时响应快 ~15×**。

原理是比语义不比字符串——「怎么退货」「退货流程是什么」「我想退货咋办」三条不同字符串，向量足够近，第二次直接命中。

**Java 侧真实 Builder（跟原文不同）**：

```java
UnifiedJedis client = new UnifiedJedis("redis://localhost:6379");

SemanticCache cache = SemanticCache.builder()
        .name("llm_cache")
        .redisClient(client)                        // 必填，没有 redisUrl()
        .vectorizer(new OpenAIEmbeddingVectorizer()) // 必填
        .distanceThreshold(0.15f)                    // 默认 0.2，0.1~0.2 常用
        .ttl(3600)
        .build();

// 命中判定
Optional<CacheHit> hit = cache.check(question);      // 不是 check(q, 1)
if (hit.isPresent()) return hit.get().getResponse();
String answer = callLlm(question);
cache.store(question, answer);
```

`SemanticCache` 还带统计：`getHitCount()` / `getMissCount()` / `getHitRate()` / `resetStatistics()`，上线前先跑一轮阈值 sweep 量一下真实命中率。

### Agent Memory：双层记忆

| 层 | 生命周期 | 内容 |
|---|---|---|
| Working Memory | 会话级，TTL 自动过期 | 当前对话来龙去脉 |
| Long-term Memory | 持久，跨会话 | 用户偏好、过敏史、历史结论 |

**真实类名（不是原文的 `SemanticSessionManager`）**：

```java
SemanticMessageHistory history = new SemanticMessageHistory(
        "assistant_session",          // index 名
        new OpenAIEmbeddingVectorizer(),
        client);

history.addMessage(Map.of("role", "user", "content", "我对花生过敏"));

// 关键：按语义挑相关的，而不是把整段历史塞 prompt
List<Map<String, Object>> ctx =
        history.getRelevant("今晚吃什么", 3, 0.3);  // topK=3, distanceThreshold 默认 0.3
```

`getRecent(topK, asText, raw, sessionTag)` 拿最近 N 条，`getMessages()` 全量，`drop(id)` 清单个会话。

---

## 最小可跑示例：Python redisvl 建 RAG 索引

```bash
pip install redisvl
docker run -d --name redis -p 6379:6379 -p 8001:8001 redis:latest
```

```python
from redisvl.index import SearchIndex
from redisvl.query import VectorQuery, FilterQuery
from redisvl.query.filter import Tag
from redisvl.schema import IndexSchema

schema = IndexSchema.from_yaml("schema.yaml")   # 或用 builder 构造
index = SearchIndex(schema, redis_url="redis://localhost:6379")
index.create()

index.load([{
    "content": "Redis 8.0 引入了原生 Vector Set 数据类型",
    "source": "release-note",
    "embedding": embed("Redis 8.0 引入了原生 Vector Set 数据类型"),
}], id_field="content")

q = VectorQuery(
    vector=embed("Redis 的向量类型叫什么"),
    vector_field_name="embedding",
    num_results=3,
    return_fields=["content", "source"],
    filter_expression=Tag("source") == "release-note",   # 标量过滤与向量检索同时生效
)
for doc in index.query(q):
    print(doc["vector_distance"], doc["content"])
```

`HybridQuery`（文本 + 向量，`LINEAR` 或 `RRF` 融合）需要 **Redis 8.4.0+**；老版本走 `AggregateHybridQuery`。

---

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **纯 Redis 命令** | `redis-cli` / 任意 Redis 客户端，`VADD` / `VSIM` / `FT.SEARCH` | 已有 Redis、不想加依赖；索引小、逻辑简单 |
| **客户端库** | Python `redisvl` 0.28.0 / Java `com.redis:redisvl` 0.13.1 | 真正的应用代码：混合检索、重排、缓存、memory 一把梭 |
| **框架集成 / MCP** | LangChain4j `langchain4j-community-redis`、Spring AI、`redis/mcp-redis` | 已有 AI 应用框架，只换存储后端；或让 Claude 直接查 Redis |

---

## 实战建议 / 风险点

1. **Iris 不是本地版 Redis 的功能**。LangCache / Agent Memory / Context Retriever / Data Integration 是托管服务，本地 `docker run redis` 只有 Vector Set + Search。规划架构时要分清「开源能拿到」和「要买 Redis Cloud」。
2. **License 变过**。≤7.2 是 BSD-3，**8.0 起是 RSALv2 / SSPLv1 / AGPLv3 三选一**。如果项目要闭源分发，先确认你选的那条路（AGPL 有网络分发传染性；RSALv2/SSPL 都不算 OSI 开源许可）。GitHub API 对 redis/redis 报 `NOASSERTION` 就是因为这个。
3. **BIN 量化的 32× 不是白拿的**。召回明显下降，只能配两段式精排用。上线前用自己的数据集跑 recall，别信通用数字。
4. **语义缓存的 distanceThreshold 是业务参数不是技术参数**。0.15 太松会「怎么退款」命中「怎么退货」的答案。必须拿真实 query 集 sweep 出阈值再上线。
5. **RedisVL Java 成熟度低**。⭐21、Java 侧很多 API 跟文章里的写法不一致。真上生产建议先用 Python `redisvl`（0.28.0，功能全、文档全）。
6. **中文场景 embedding 维度要重新算**。文章示例统一用 1536（OpenAI 维度）。换通义/智谱/本地 bge 之后索引要重建，别只改 `DIM`。

---

## 跟我们的关系

**对我们的三个具体用法：**

1. **Hermes 记忆层选型 —— 这是 OpenViking 的正面竞品，值得对比**。iswiki 已收的 [openviking](openviking.md)（火山引擎 39,514⭐，`viking://` 虚拟文件系统 + L0/L1/L2 三层渐进加载 + benchmark 里把 Hermes 记忆准确率从 33.38% 拉到 82.86%）走的是「自建 agent 上下文数据库」路线；Redis 走的是「已有基础设施顺手接管记忆」路线。两条路**不冲突**——OpenViking 管长期语义记忆，Redis 管毫秒级会话记忆 + 向量检索 + 缓存，是可以叠的。选型时的真问题只有一个：**我们要不要为了记忆引入一个有 tri-license 的外部依赖**。
2. **iswiki 搜索可以零运维升级**。iswiki 现在是纯静态 mdbook + GitHub Pages，本地搜索靠 mdbook 自带的全文。如果以后文档量破百、上 GitHub 代码搜索慢，可以把每篇笔记的 embedding 灌进 Redis Vector Set，用 `VSIM` + `FILTER '.category == "ai-vibecoding-agents"'` 做语义检索 —— 一次调用同时完成「找相关内容」+「限定分类」，正好是 Vector Set FILTER 的典型场景。数据源就是仓库本身，同一个 Postgres/pgvector 或 Redis。
3. **语义缓存对 3 个 gateway 的直接价值**。飞书 3 个 gateway（curator / stock / coder）每天大量重复回答同类问题（持仓查询、简报口径、飞书格式要求）。在 LLM 调用前挂一层 `SemanticCache`，`distanceThreshold=0.15`、`ttl=3600`，按项目记忆里的口径，这是最容易算清 ROI 的一刀。

**建议动作**：不急着换栈，先用 `docker run redis:8` 半天做个小 spike —— 灌 50 篇 iswiki 笔记进去，测 `VSIM` 的召回和延迟，再决定值不值得动。

---

## 版本节奏

| 项目 | 关键节点 |
|---|---|
| Redis | 8.0 引入 Vector Set + 三重 license；8.4.0 起支持 `HybridQuery` 原生混合检索；8.10.2（2026-09-17）为当前最新 |
| redisvl (Python) | 0.28.0，功能最全（索引/检索/缓存/Memory/MCP），Python ≥ 3.10 |
| RedisVL Java | 0.13.1（2026-02-20），上游末次提交 2026-06-05 |
| langchain4j-community-redis | 1.21.0-beta31（替代停更的 `langchain4j-redis` 0.36.2）|
| mcp-redis | 0.5.1（2026-08-05），⭐ 633 |

---

## 参考链接

- 公众号原文《Redis 宣布正式接入AI》: https://mp.weixin.qq.com/s/EKM40ww-giB-rMr8_pMPWA
- Redis for AI and search 文档首页: https://redis.io/docs/latest/develop/ai/
- Vector Set 数据类型: https://redis.io/docs/latest/develop/data-types/vector-sets/
- Vector Set 内存与量化: https://redis.io/docs/latest/develop/data-types/vector-sets/memory/
- VADD / VSIM / VSETATTR 命令参考: https://redis.io/docs/latest/commands/vadd/
- redisvl (Python) PyPI: https://pypi.org/project/redisvl/
- RedisVL 文档: https://docs.redisvl.com/
- RedisVL Java 仓: https://github.com/redis/redis-vl-java
- langchain4j-community-redis Maven: https://central.sonatype.com/artifact/dev.langchain4j/langchain4j-community-redis
- redis/mcp-redis: https://github.com/redis/mcp-redis
- redis/docs 源码仓（本笔记所有 API 签名核对来源）: https://github.com/redis/docs