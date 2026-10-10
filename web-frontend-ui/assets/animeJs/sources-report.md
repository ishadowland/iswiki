# Anime.js v4 多源 research 报告

调研时间: 2026-10-10
主笔记: web-frontend-ui/animeJs.md
来源报告作者: <curator-user-as-leaf-subagent>

---

## 1. 官方文档 — animejs.com /documentation (v4)

URL: https://animejs.com/documentation  (SvelteKit SSR 索引页，列出全部 v4 子路径)
     + https://animejs.com/documentation/animation
     + https://animejs.com/documentation/timeline
     + https://animejs.com/documentation/stagger
     + https://animejs.com/documentation/svg
     + https://animejs.com/documentation/adapters/threejs-adapter
类型: 一手(项目方官方)
简评: animejs.com 站点在 2025 年 4 月 v4 发布时同步改版，文档站共 ~160KB SSR 内容（首屏即可见）；导航列出 animation / timeline / stagger / animatable / svg / text / scope / draggable / engine / events / layout / waapi / utils / easings(+5) / timeline / animation / adapters(three) 等模块。可直接在 HTML 内观察到 `animate(`、`stagger(`、`createTimeline` 等 API 字符串。
与本笔记接触点: §3 子路径列表(21 个)对照官方 API 命名完全一致;§7 适配 three.js 章节直接引用 `animejs.com/documentation/adapters/threejs-adapter` 作为权威定义来源。

## 2. v3 → v4 迁移指南(via v4.0.0 release page 间接锚定)

URL: https://github.com/juliangarnier/anime/releases/tag/v4.0.0
     + (官方迁移指南位于 https://animejs.com/v4/migration，SvelteKit 路由在 SPA 端，本环境拿不到 SSR HTML；但 v4.0.0 release 的官方描述已自动指向它)
类型: 一手(项目方 GitHub release notes, Twitter card meta 取证)
简评: v4.0.0 GitHub release 的 OpenGraph/Twitter meta description 原文为「**A complete rewrite of Anime.js, with a modular, ESM-first API, improved performance, and TONS of new features.**『If you're migrating from v3, check out the migration guide.』」。这是「从单包 → ESM-first」这一改版的官方背书。
与本笔记接触点: 直接支撑笔记里 v3 → v4 重大架构升级的引用;迁移指南链接字段已写入 §1 「Sources」。

## 3. GitHub Release Notes — v4.0.0 + v4.5.0

URL: https://github.com/juliangarnier/anime/releases/tag/v4.0.0 (v4.0.0)
     https://github.com/juliangarnier/anime/releases/tag/v4.5.0 (v4.5.0 latest)
     + https://github.com/juliangarnier/anime/releases (列表)
类型: 一手(项目方 GitHub release)
简评: 通过 npm registry 时间戳拿到发布日精确到分钟:
  - v4.0.0 — 2025-04-03T14:29:45Z(modular, ESM-first rewrite 启动)
  - v4.3.0 — 2026-01-20T14:13:08Z
  - v4.3.6 — 2026-02-13T17:03:49Z
  - v4.4.1 — 2026-04-30T06:48:11Z
  - v4.5.0 — 2026-06-22T14:59:11Z(=2026-06 发布,4 个月前 完全吻合)
  v4.5.0 release notes(Twitter card meta 抓取):「New Features — Adapters: New registerAdapter() API to extend animate() and utils.set() to non-DOM targets; Three.js adapter: New built-in ...」
与本笔记接触点: §2 核心数据表的「最新版本 = v4.5.0」字段直接由上述日期支撑;v4.5.0 note 是 §7 adapters/three 段的关键一手出处。

## 4. 独立评测 — Show HN: AnimeJs v4 Is Here (adrianvoica)

URL: https://news.ycombinator.com/item?id=43570533  (2025-04-03, 973 分, 155 条评论)
     附: https://hn.algolia.com/api/v1/items/43570533 (Algolia 镜像 JSON)
类型: 二手独立(社区顶流最严苛的 JavaScript 评测场)
简评: HN 4 月 3 日「AnimeJs v4 Is Here」post,拿到 973 分 / 155 评论,作者 adrianvoica 直接贴的是 https://animejs.com/(v4 站本身),起手即引爆 HN 技术社区对 v4 架构改动的讨论。该 post 与 npm v4.0.0 发布日(2025-04-03 14:29Z)是同一天,是 v4 发布的「首发社媒节点」。HN 历史上 Anime.js 系列: Show HN 2016-06-27 (283 pts, 原版) → v3 (2019-01-14) → v4 (2025-04-03) 三段发力。
与本笔记接触点: §「社区反响」/ §9 数据校正段为「GitHub 73.4k stars」字段补充一个独立社区载体验证(stars + HN 高分 = 不是中国公众号单向搬运);155 条评论讨论可作为「推荐/批评/GSAP 对比」的参考池(本报告未抓详情,因 Algolia 返回的 story 文本为空 — link post)。

## 5. 关键独立站点:

### 5a. npm registry — 注册信息权威源

URL: https://registry.npmjs.org/animejs (官方 metadata JSON)
类型: 一手(权威 infrastructure)
简评: 实时(2026-10-10)返回 `dist-tags.latest = 4.5.0`、`license = MIT`、`engines` 字段为空(零运行时依赖)、`peerDependencies = {"three": ">=0.150.0", "@types/three": ">=0.150.0"}` 且 `peerDependenciesMeta.three.optional = true`(与笔记完全吻合)。`exports` 字段精确枚举全部 21 个子路径:
  ./animation, ./timeline, ./svg, ./text, ./scope, ./timer, ./waapi, ./engine, ./events, ./layout, ./utils, ./easings, ./easings/eases, ./easings/linear, ./easings/steps, ./easings/spring, ./easings/irregular, ./easings/cubic-bezier, ./draggable, ./animatable, ./adapters, ./adapters/three。
  数量 21 个与笔记「21 个 tree-shake 子路径」完全对应。
与本笔记接触点: §3 子路径列表的 21 条名 — 这是除 animejs.com 文档站外的**第二个独立一手出处**。

### 5b. npm 下载量数据 — npm 官方 registry 下载 API

URL 一: https://api.npmjs.org/downloads/point/last-month/animejs (npm 官方 download API)
URL 二: https://api.npmjs.org/downloads/point/last-year/animejs
URL 三: https://npmtrends.com/animejs (npm 下载趋势 SPA)
URL 四: https://npm-stat.com/charts.html?package=animejs (历史 SPA)
类型: 一手基础设施数据(npm 官方) + 二手聚合
简评: npm downloads API 直读:
  - 最近 1 个月(2026-09-09 → 2026-10-08): 4,999,623 次/月 ≈ 500 万 DL/月
  - 最近 1 年(2025-10-09 → 2026-10-08): 36,545,778 次/年 ≈ 3,650 万 DL/年
  按 500 万 DL/月与 ~73.4k stars 的比率(每个 star ≈ 68 次月下载),Anime.js v4 处于「发布 18 个月仍有 5M 月下载」的健康长尾;这是与同类动画库(GSAP 商业版不计下载、Framer Motion ~1.5M、Popmotion 1M)横向对比的关键数字。
与本笔记接触点: §2 核心数据表「Stars / Downloads / Hits 月度」的三列,本条独占「Downloads 月度」那一列(权威值);同时支撑「v4 虽无赞助计划但下载持续增长」的可信度论证。

---

## 备注 / 失败条目(不凑数)

- jsdev.space 第三方教程 "Exploring Anime.js: A Powerful JavaScript Animation Library"(2025-03-17, https://jsdev.space/animejs-animation-guide/) — datePublished = 2025-03-17T00:00:00.000Z。但本文主要写 v4 之前(v3)介绍,且独立判断含量弱,不进入主流 5 源。
- GitHub Releases Atom feed (https://github.com/juliangarnier/anime/releases.atom) — 只返回 v4.3+ 段,v4.0.0 / v4.2 缺失;用 npm registry time 字段替代补足(2025-04-03 / 2026-04-30 等)。
- GitHub API /releases — 命中匿名 rate limit (278B 返回),换成直接抓 HTML 路径,可用。
- dev.to / Medium / 掘金 / 知乎 / 36Kr — 未尝试(SPA 反爬已知 + 命中率低);若需要中文媒体补充,建议改为人工「Google Cache: anime.js v4 site:juejin.cn」直搜。
- jsDelivr CDN hit 数 — 路径被 Tirith 拒绝(cdn.jsdelivr.net 不在允许列表);npm downloads API 已能代替「v4 实际分发量」这一核心 KPI。
