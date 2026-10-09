# iswiki 多源资料：VoltAgent/awesome-design-md

为 §9 数据校正段提供的 5 个互证来源。每条均经过实际 HTTP 取回或 API 验证。

---

## 1. Google 官方博客 · DESIGN.md 规格开源公告【一手 / 必】
- **URL**: https://blog.google/innovation-and-ai/models-and-research/google-labs/stitch-design-md/
- **类型**: 一手（Google Labs 官方发布，Cassia Xu / Software Engineer, 2026-04-21）
- **关键摘录**（实测取回，388KB 文章正文）：
  > "Today, we're open-sourcing the draft specification for DESIGN.md, so it can be used across any single tool or platform… AI agents can know exactly what a color is for, and can validate their choices against WCAG accessibility rules."
- **与本仓接触点**:
  - 这是 awesome-design-md README 自称的"DESIGN.md 来源"的**真正原始出处**。
  - 时间 2026-04-21 在仓库建仓 2026-03-31 之后 → VoltAgent 是借力 Google 已开源 spec 起势，不是原创概念。
  - WCAG 验证条款 = awesome-design-md 各 DESIGN.md 里"Sections"反复出现的 Accessibility 检查项的来源。
  - 标题实际为 "Stitch app's DESIGN.md format is now open-source for designers"。

---

## 2. Hacker News · DeathArrow 投递【社区讨论】
- **URL**: https://news.ycombinator.com/item?id=48177822
- **类型**: 二手（HN 用户 DeathArrow 2026-05-18 投递，标题"Awesome DESIGN.md"）
- **数据**（HN Algolia API 实测）：4 points · 0 comments · 0 kids
- **与本仓接触点**:
  - 印证公共讨论热度**真实偏低**——4 pts / 0 评论，与 12 万★形成的差距说明大部分 star 来自 GitHub explore / 话题推荐而非 HN 流量。
  - DeathArrow 是 GitHub 话题红人（高频 awesome-* 列表搬运者），该贴本身不带独立判断价值，但**反证"vibe coding 圈外认知度"**——Hacker News 主社区对 DESIGN.md 概念本身关注度也低（同期"Show HN: Figma for Coding Agents" getdesign.md 主贴 11 pts / 6 c 才是 DESIGN.md 真正的 HN 高光时刻）。
- **HN API 实测副本**（备用源）:
  - https://hn.algolia.com/api/v1/items/48177822
  - 同期其他 3 条提及 VoltAgent 仓的 HN 故事（vanyle/granto/elwingo1）均为 1-3 pts、0 评论。

---

## 3. Google Stitch DESIGN.md 官方规格页【一手 / spec 原页】
- **URL**: https://stitch.withgoogle.com/docs/design-md/specification/
- **类型**: 一手（Google Stitch 文档站）
- **实测状态**: HTTP 200 返回 25KB，但**正文为 SPA shell**，`<title>` 仅 "Stitch - Design with AI"，需 JS 渲染才能看到章节正文。这是 iswiki 笔记需要明确标注的事实：
- **与本仓接触点**:
  - awesome-design-md README 在多处链接此页（"Stitch DESIGN.md format"），却无 preview.html → 反证本仓是**消费 Google spec 的下游**，而非上游合作方。
  - 同站 overview 页（https://stitch.withgoogle.com/docs/design-md/overview/）也是 SPA shell，相同 25KB 体积。
  - HN API 显示至少 2 条故事（fittingopposite / nigelgutzmann 2026-04）以 overview 页为外链 → 该页**确实有渲染内容**，但爬虫/CI 不可读，只能通过 HN 侧链印证其存在。

---

## 4. Google Stitch 官方概览页 + GitHub 仓 README【一手 / 双源】
- **URL**: 
  - https://stitch.withgoogle.com/docs/design-md/overview/
  - https://raw.githubusercontent.com/VoltAgent/awesome-design-md/main/README.md（已实测取回，257 行）
- **类型**: 一手（Google spec 概述 + VoltAgent 仓 README 全量原文）
- **实测关键事实**（README 原文）:
  - 徽章: `DESIGN.md count-73`（badge 声称 73，但 GitHub API 实测 `design-md/` 下子目录 = **74**，差异需在 §9 数据校正段标出）。
  - 仓库定义为: "Curated collection of DESIGN.md analysis by developer focused websites."
  - 设计哲学: "Drop it into your project root and any AI coding agent or Google Stitch instantly understands how your UI should look."
  - AGENTS.md / DESIGN.md 双文档分工表（这是 README 的核心创新叙事，不是 Stitch 原生概念）。
  - 表中宣称每个 DESIGN.md 配套 `preview.html`，**但 `design-md/stripe/` 实测仅含 DESIGN.md + README.md 两文件，无 preview.html**——parent 提示的"README 撒谎"得到验证。
- **与本仓接触点**:
  - 73 vs 74 的差异 = badge 与实际计数 lag，§9 应以 GitHub API 实时数为准。
  - 双文档分工叙事（"How to build the project" / "How the project should look and feel"）是 VoltAgent 营销主张，非 Stitch 官方术语。

---

## 5. GitHub API 实时数据 + Stitch spec 衍生项目【一手 / 元数据】
- **URL**: 
  - https://api.github.com/repos/VoltAgent/awesome-design-md（JSON，已实测）
  - https://github.com/bergside/awesome-design-md-skills（HN 同期 Show HN 衍生项目）
- **类型**: 一手元数据 + 衍生生态
- **实测数据**（2026-10-09 抓取）:
  - `watchers: 120,017` ✓ 与 parent 一致
  - `forks: 13,387` ✓ 一致
  - `open_issues: 313` ✓ 一致
  - `topics`: design-md, google-stitch, landing-page, vibe-coding, vibe-design, vibecoding（实测比 parent 提及的多了 vibe-design / vibecoding 两个）
  - `subscribers_count: 460`（额外信息，可入 §9）
  - `organization`: VoltAgent, id 201282378, Node ID `O_kgDOC_9TSg`
  - Issue #1 = "Site Request: Resend (resend.com)" by ScientificAJ, 2026-04-01 创建已 close → 印证仓库创建早期即有人提议新增网站。
- **衍生生态**:
  - https://github.com/bergside/awesome-design-md-skills（HN 2026-04-10 Show HN，作者 elwingo1，1 pt / 0 c）→ **说明社区存在"给 AI agent 加 DESIGN.md skill"的二次封装尝试**，本仓的影响已外溢到 skills 生态。
- **与本仓接触点**:
  - API 数据是 §9 数据校正段的**权威基线**。
  - 衍生仓的出现证明 DESIGN.md 概念**已有独立于 VoltAgent 的复刻尝试**，可作"生态扩张力"佐证。

---

## 备注 / 未完成项
- **中文媒体**：掘金 / 知乎 / 36Kr / CSDN / cnblogs / InfoQ 均未找到独立评述（搜过 Bing/Brave/Google site: 限定搜索），HV 断面此仓的中文能见度**低于英文圈**——这本身是 §9 数据校正段的一个可写判断点。
- **ProductHunt**：搜索 HTTP 200 但无 post URLs（PH 站 JS 渲染 + 反爬），无法取证，**已跳过**——按 parent 指引"不凑数"。
- **Medium / DEV.to**：搜索页 SPA，无具体文章 URL 可取证，**已跳过**。
- **Reddit**：JSON API 被反爬拦截，无可引用 URL，**已跳过**。
- **X.com**：HTTP 200 但无状态正文，无可引用搜索结果，**已跳过**。
- **getdesign.md**：本网络仍 timeout（parent 已声明），未深挖。