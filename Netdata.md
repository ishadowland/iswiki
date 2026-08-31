# Netdata — AI-powered 全栈可观测性平台(每 metric 每秒)

> 学习笔记 · 调研时间 2026-08-31
> 仓库: <https://github.com/netdata/netdata> · 官网: <https://www.netdata.cloud> · 文档: <https://learn.netdata.cloud>
> License: **GPL-3.0** (Agent) · **NCUL1** 闭源 (UI) · **闭源付费** (Cloud) · 语言: C/Go/Python 混合 · ⭐ 80.4k · 🍴 6.6k
> 最新版: v2.11.0 (2026-08-12) · 23,257 commits · 最后 push 1h ago · 活跃度极高

## 一句话定位

**Netdata = 开箱即用的 per-second 实时监控平台**,核心理念 "Every Metric, Every Second. No BS." —— 不需要写 PromQL,不用配 storage,Agent 装上立刻有 dashboard,自带 ML 异常检测和告警。

## 三种使用方式

| 方式 | 入口 | 适用 |
|---|---|---|
| **Self-hosted Agent** | `bash <(curl -Ls https://get.netdata.cloud)` → 访问 `http://NODE:19999` | 个人服务器、小团队、独立节点监控,完全本地、数据不出域 |
| **Netdata Cloud** | <https://app.netdata.cloud> 注册 → 把 Agent 接入 Space | 多节点集中看板、RBAC/SSO、跨云、团队协作,有免费层和付费层 |
| **Parents 模式** | 一个节点做 streaming 汇聚 + 长留存 + 告警配置 | 边缘节点多、不想让每台机器存全量历史、做层级监控 |

## 核心组件 / 模块 / 架构

### 三段式生态系统(README 官方表格)

| 组件 | 描述 | License |
|---|---|---|
| **Netdata Agent** | 核心监控引擎:收集/存储/ML/告警/export | **GPL v3+** 开源 |
| **Netdata UI** | Dashboard + 可视化,CDN 交付 | **NCUL1** 闭源(免费用) |
| **Netdata Cloud** | 企业功能:多节点、RBAC、集中告警 | 闭源,免费层 + 付费层 |

### Agent 内部 9 大能力(`How It Works` mermaid 流程)

```
Agent (单节点)
 ├─ Collect  系统/容器/应用/日志/API/synthetic check
 ├─ Store    高效分层 TSDB(内存→mmap→磁盘)
 ├─ Learn    每个 metric 单独训 ML 模型(基于近期行为)
 ├─ Detect   用训练好的模型识别异常
 ├─ Check    对接预置/自定义告警规则
 ├─ Stream   实时把数据推到 Parent 节点
 ├─ Archive  导出到 Prometheus / InfluxDB / OpenTSDB / Graphite
 ├─ Query    通过 API 暴露给 dashboard / 第三方工具
 └─ Score    跨 metric 模式匹配 + 相关性分析
```

### 仓内目录结构(2026-08)

```
src/
├─ web/                    ← Web 服务骨架(注:UI 代码不在这里)
│  ├─ server/              ← H2O HTTP/2 server(libh2o 是 git submodule)
│  ├─ api/                 ← 后端 API
│  ├─ websocket/           ← 实时数据推送
│  ├─ rtc/                 ← 实时通道
│  ├─ mcp/                 ← MCP 服务暴露
│  └─ README.md            ← 只描述 Agent Dashboard 的访问入口
├─ collectors/             ← 数百个数据采集器(debugfs/.../...)
├─ database/               ← 分层 TSDB + ML 引擎
├─ streaming/             ← Parent ↔ Child 节点流协议
├─ aclk/                   ← Agent ↔ Cloud 通信 + aclk-schemas 子模块
├─ libnetdata/             ← 公共 C 库
└─ ...
```

`.gitmodules` 包含 3 个子模块:`aclk-schemas`、`src/web/server/h2o/libh2o`、`debugfs.plugin/libsensors/vendored`。

## 前端设计与布局思路(重点)

### 1. **前端代码完全不在开源仓里**

这是最重要的事实,也是"调研前端"时最容易踩的坑:

- README §License 明确写 **"Netdata UI – Closed-source but free to use | Delivered via CDN"**
- 协议是 **NCUL1**(Netdata Cloud UI License 1)
- 仓里 `src/web/` 只有 API/Server/WebSocket/MCP,**没有任何 dashboard 前端代码**(没有 gui/、没有 src/、没有 components/)
- Agent 启动时 dashboard 页面是从 `https://app.netdata.cloud` CDN 拉到浏览器跑的

→ 想二次定制前端外观 → **不能 fork 这个仓**,得联系 Netdata 公司签 NCUL1 商业协议;或者基于暴露的 API 自己写(用任意前端框架都行,因为 API 完全公开)

### 2. **数据模型 NIDL —— 自动出 dashboard 的根本**

| 缩写 | 含义 |
|---|---|
| **N**odes | 节点 |
| **I**nstances | 实例(同 metric 多实例,如 disk1/disk2) |
| **D**imensions | 维度(每实例的具体指标) |
| **L**abels | 标签(K-V 自由标注) |

设计意图:**让"自动发现 → 自动成图"成为可能**。Agent 收完 metric,根据 NIDL 自动分组、生成时间序列、给 dashboard 拼出对应 panel。**用户不需要写任何 query 语言** —— 这跟 Prometheus 的 PromQL、Grafana 的手动 dashboard 是根本差异。

### 3. **布局 —— 双面板时间序列墙 + 实时滚动**

打开 `http://NODE:19999` 看到的:
- 顶部:节点 selector / 时间窗 / 缩放控件
- 主体:**自适应瀑布流 chart 网格**,每 chart 独立 1 个指标,实时刷新(per-second)
- 每 chart 自带 hover tooltip + 当前值 + min/max/p95 角标
- 左侧 collapsible tree:系统层级(Apps → Groups → Contexts → Dimensions)
- 无 page router,所有页面是同一张 dashboard,**滚动 = 时间轴纵深**

### 4. **实时性设计**

- 用 **WebSocket / RTC** 而不是轮询(对应 `src/web/websocket/`、`src/web/rtc/`)
- 后端 push 而不是前端 poll,Chrome DevTools 网络面板上每个 chart 只有一次 subscribe 请求,后续纯流式更新
- 配合 ML anomaly detector,异常点直接在 chart 上高亮

### 5. **Cloud UI 与 Agent UI 的关系**

- Agent UI = 单节点 dashboard,本地 19999,**零依赖**(脱离 Cloud 也能用)
- Cloud UI = 跨节点聚合 + 告警配置 + RBAC,**AI Copilot**(README 副标题 "AI-powered")
- 两套 UI 共用同一份 NCUL1 代码库,Cloud 是 SaaS 部署,Agent 是 CDN 拉相同 SPA

### 6. **第三方 UI 替代品**

由于 API 完全公开,有社区项目提供其他前端风格:
- **netdata-ui**(社区)用 React 重建
- **Grafana + Prometheus datasource** 用 `exporting-to-prometheus` 把 Netdata 数据导给 Grafana

## 安装与最小使用

### 一键安装 Agent(Linux/macOS)

```bash
# 经典一行装
bash <(curl -Ls https://get.netdata.cloud)

# 验装
systemctl status netdata    # Linux
brew services list          # macOS

# 访问 UI
open http://localhost:19999
```

### Docker 跑(隔离测试首选)

```bash
docker run -d --name netdata \
  -p 19999:19999 \
  --cap-add SYS_PTRACE \
  --security-opt apparmor=unconfined \
  netdata/netdata
```

### Kubernetes / Helm

```bash
helm repo add netdata https://netdata.github.io/helmchart
helm install netdata netdata/netdata
```

### 接 Cloud(多节点场景)

1. <https://app.netdata.cloud> 注册账号
2. 在 Agent 上运行 `sudo netdata-claim.sh -token=TOKEN -spaces=SPACE_ID`
3. 等 30 秒,Space 里出现节点

### 用 API 自己拉数据(写 dashboard 的标准做法)

```bash
# 拿一个 metric 当前值
curl http://localhost:19999/api/v1/info

# 拿某个 chart 的时间序列(伪 SQL-like)
curl 'http://localhost:19999/api/v1/data?chart=cpu.cpu0&points=60&group=average' | jq
```

## 跟我们的关系

| 场景 | 价值 |
|---|---|
| **本地 macmini 服务器监控** | 一行装,无需配置,马上看到 CPU/内存/磁盘/网络/per-container。可替换我现在的 `vm_stat` 轮询脚本 + 自己写的 Grafana。 |
| **Docker 多节点监控** | Netdata 对 containerd/Docker 是一等公民,自带 cgroup per-container 视图,比手动装 node_exporter 简单 |
| **ML 异常检测** | 不需要手写阈值告警,Agent 自带 per-metric ML,有"行为偏离"自动标 |
| **数据导出到现有 Prometheus** | `exporting.conf` 配 destination = Prometheus,Netdata 当 collector 用,前端还是 Grafana |
| **跟 Hermes / MCP 集成** | 仓里有 `src/web/mcp/`(新增),Netdata 自家已经做了 MCP server 暴露指标 —— 给 AI agent 提供基础设施 health endpoint 的现成方案 |

**对你相关项目最值得借鉴的点:** "UI 闭源 + API 开源" 这种**前后端彻底解耦 + CDN 交付**的架构,比传统 "开源 whole-stack" 更适合商业化(netdata 早期纯 OSS,后期把 UI 拆闭源换成 CDN,避免了被云厂商白嫖又拿不到钱的尴尬)。

## 风险点 / 注意事项

| 风险 | 说明 |
|---|---|
| **UI 不能改** | 想换主题/改交互/接 SSO 但不想用 Cloud,只能自己用 API 重写前端 —— 协议上不能 fork 原版 |
| **GPL-3.0** | Agent 本身 GPL,集成进闭源产品要先评估传染性(直接跑 binary 通常没事,集成到 SaaS 可能触发 AGPL-like 条款 —— 具体看 lawyer) |
| **Cloud 数据归 Netdata** | 用 Cloud = 把节点拓扑信息交给第三方,内部敏感基础设施慎用,纯本地场景用 Agent UI |
| **资源占用** | per-second 收集 + per-metric ML 训练,内存占用不低(典型 500MB-1GB/节点);**关闭不用的 collector** 是必做调优 |
| **NCUL1 不开源** | 这份调研**不能给出 UI 代码样例**,只能描述可见的设计意图;深度借鉴前端的同学看明白再投入 |

## 版本节奏 / Release 历史

- **v2.11.0** — 2026-08-12(本次调研最新版)
- **master** 分支活跃,**每天 10+ commits**
- 14 个 release assets(包含 docker/static binary/packages)
- 247 个 nightly build 在 `netdata/netdata-nightlies` 仓

## 参考链接

| 资源 | URL |
|---|---|
| GitHub 仓 | <https://github.com/netdata/netdata> |
| 官网 | <https://www.netdata.cloud> |
| 文档(Learn) | <https://learn.netdata.cloud> |
| Live Demo | <https://app.netdata.cloud/spaces/netdata-demo> |
| API 文档 | <https://learn.netdata.cloud/docs/netdata-agent/querying-the-agent/api> |
| UI License | <https://app.netdata.cloud/LICENSE.txt> |
| UI 三方依赖 | <https://app.netdata.cloud/3D_PARTY_LICURES.txt> |
| vs Prometheus 对比 | <https://www.netdata.cloud/blog/netdata-vs-prometheus-2025/> |
| 架构详解 | <https://learn.netdata.cloud/docs/netdata-agent/#distributed-observability-pipeline> |
| H2O 子模块 | <https://github.com/h2o/h2o> |
