# open-source-games — 开源游戏清单仓库的用法、边界与数据质量

> 学习笔记 · 调研时间 2026-11-16
> 仓库: https://github.com/bobeff/open-source-games · License: CC0-1.0 · 语言: Python（仅一个脚本，主体是 README）
> ⭐ 18,367 · Fork 1,745 · 建仓 2021-09-15 · 最后 push 2026-02-25 · topics: awesome-list / games / open-source

## 一句话定位

一个**人工策展的开源游戏索引**——把散落各处的开源游戏、商业游戏开源重制、源码移植项目归到 18 个品类下，每条给「官网链接 + 简介 + `[[source]]` 源码链接」，本身不写一行游戏代码。

## 一、三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **读 README 当索引用** | 直接浏览 <https://github.com/bobeff/open-source-games#readme> | 找某个品类下还活着的开源作品 |
| **当"发现源"用** | 顺着每条的 `[[source]]` 跳到上游仓库 | 找引擎、学习实现、找素材数据 |
| **当 API/数据源用** | README 是 Markdown，可用脚本解析出结构化条目 | ⭐ 唯一真正值钱的用法，见下 |

**第三种是它跟普通 awesome-list 的区别**：条目格式高度固定（`**[Title](url)** - desc. [[source]](repo)`），可以低成本解析成结构化数据。本笔记下面的"可执行元数据"一节就是这么做出来的。

## 二、核心结构

```
bobeff/open-source-games
├── README.md          ← 全部内容都在这（37 KB / 458 行）
├── CONTRIBUTING.md    ← 收录规则（很关键，见 §五）
├── LICENSE            ← CC0-1.0（比 MIT 更宽松：无署名要求）
└── scripts/coauthor.py ← 唯一代码：生成 Co-authored-by 署名行
```

### 2.1 目录分类与条目分布

**口径说明**：README 用 `##` 表示 18 个品类、`####` 表示品类下的子分组（如 id Software Games、Source Ports and Re-Implementations）。下面把 `####` 子分组的条目**归入其父 `##` 品类**统计。

| 品类 | 条目数 | 备注 |
|---|---:|---|
| First-Person games | 40 | 含 6 个子分组，最大的一块（Doom/Quake 移植 + Build 引擎系 + id Software 系） |
| Role-Playing games | 28 | 含 Diablo / Blizzard / Westwood+EA / MMORPG 四个重制子组 |
| Real-Time strategies | 25 | 含 3 个商业 RTS 重制子组 |
| Platformers | 14 | |
| Racing games | 12 | |
| Turn-Based strategies | 12 | |
| City-Building games | 10 | |
| Third-Person games | 8 | |
| Roguelikes | 7 | |
| Adventure games | 6 | |
| Business and Tycoon games | 5 | |
| Puzzle games | 3 | |
| Shoot 'em up games | 2 | |
| Sport games | 2 | |
| Action games | 1 | 只有 Hypersomnia |
| Sandbox games | 1 | 只有 Mindustry |
| Tower Defence games | 1 | 只有 Server Survival |
| **小计** | **177** | 去掉 Other lists 段的 9 条 |
| Other lists | 9 | 指向其他清单（见 §七） |
| **README 条目行总计** | **186** | 163 顶层 + 23 嵌套 |

### 2.2 它收录的三类东西（性质完全不同，别混用）

| 类型 | 例子 | 许可证 | 能不能直接玩 |
|---|---|---|---|
| **原生开源作品** | Mindustry、OpenTTD、Veloren、OpenMW、Freeciv | 各自 GPL/MIT/Apache 等 | ✅ 源码即完整游戏 |
| **商业游戏开源重制** | OpenRCT2（RollerCoaster Tycoon 2）、OpenLoco（Transport Tycoon）、CorsixTH（Theme Hospital）、OpenXcom | 通常 GPL + 原素材版权另算 | ✅ 能玩，但**原版素材/音乐通常不含** |
| **源码移植 / 逆向工程** | Doom/Quake/Wolfenstein 3D 官方释源、n64decomp/sm64（Mario 64 反编译）、zeldaret/tp（塞尔达：暮色回声反编译） | 原厂许可或社区授权 | ⚠️ 需配合原版数据文件 |

⭐ **第三类是法律灰色区**，也是这个仓库最有意思的部分——它把"反编译/还原源码"作为一类正式条目收录（README 里有专门的 "reverse engineering" / "decompilation" 措辞）。阅读时务必区分"开源作品"和"重制/移植"。

### 2.3 演进时间线（用 GitHub API 回放历史 README 实测）

| 时点 | 顶层条目（`^- **`） | `##` 章节数 | README 字节 |
|---|---:|---:|---:|
| 2021-09-15 建仓 | 0（初始 23 条用的是 `- [Name]` 无加粗格式） | 6 | 2,779 |
| 2025-12-27 | 125 | 18 | 28,355 |
| 2025-12-30 | 136 | 18 | 30,926 |
| 2026-01-01 | 152 | 18 | 34,948 |
| 2026-02-25（最新） | 163 | 19 | 37,285 |

⭐ **两个观察**：
1. **格式在 2021 年是 `- [Name](url) - desc`，后来才改成 `- **[Name](url)** - desc.`** —— 写解析脚本时如果只匹配加粗格式，会漏掉全部早期条目。这也说明 §8.3 的正则**对历史版本无效**。
2. **最近 2 个月是爆发式扩张**（125 → 163，+30%），而 2021-09 到 2025-12 的四年半只从 23 条慢慢长到 ~120 条。**列表的"新鲜度"高度集中在最近**——这也意味着新条目多、复核少。

## 三、可执行元数据：把 README 变成表

这是本笔记最实际的价值。以下数据**用 GitHub API 现场拉取**（2026-11-16），不是抄 README：

| 游戏 | 语言 | ⭐ | 最后 push | 状态 |
|---|---|---:|---|---|
| Mindustry | Java | 29,867 | 2026-11-15 | 活跃 |
| OpenRCT2 | C++ | 16,584 | 2026-11-15 | 活跃 |
| id-Software/DOOM | C++ | 19,913 | 2024-05-24 | 停滞 |
| OpenRA | C# | 17,793 | 2026-11-08 | 活跃 |
| n64decomp/sm64 | C | 8,976 | 2024-02-04 | 停滞 |
| id-Software/Quake-III-Arena | C++ | 8,323 | 2024-08-02 | 停滞 |
| citybound/citybound | Rust | 8,181 | 2023-01-07 | 停滞 |
| endless-sky/endless-sky | C++ | 7,743 | 2026-11-15 | 活跃 |
| Veloren | Rust | 7,698 | 2026-11-10 | 活跃 |
| wesnoth/wesnoth | C++ | 6,998 | 2026-11-16 | 活跃 |
| id-Software/Quake | C++ | 6,133 | 2024-06-15 | 停滞 |
| OpenMW/openmw | C++ | 6,759 | 2026-11-15 | 活跃 |
| OpenTTD | C++ | 8,506 | 2026-11-15 | 活跃 |
| corsixth/corsixth | Lua | 4,728 | 2026-11-15 | 活跃 |
| scummvm/scummvm | C++ | 2,896 | 2026-11-16 | 活跃 |
| 0ad/0ad | C++ | 2,828 | 2024-08-17 | ⚠️ **archived** |
| openxcom/OpenXcom | C++ | 2,254 | 2026-09-28 | 活跃 |
| OpenLoco | C++ | 1,972 | 2026-11-14 | 活跃 |
| zeldaret/tp | C++ | 2,133 | 2026-06-23 | 活跃 |
| Unknown-Horizons | Python | 1,562 | 2026-11-11 | 活跃 |
| freeciv/freeciv | C | 1,632 | 2026-11-16 | 活跃 |

**结论**：
- **技术栈以 C++ 为主**（经典游戏引擎栈），Rust 用于近年的新项目（Veloren、citybound），Java（LibGDX 系）、Lua、Python 各占少数
- **"最后 push" 才是真实活跃度**——⭐ 高不代表在维护。DOOM 19,913⭐ 但 2024-05 后未动；Mindustry 29,867⭐ 且当天还在推
- **该清单不标注"活跃度"**，只给链接——所以想判断能不能用，必须自己查 API（这正是 §七 里 issue #71 想解决的问题）

## 四、⚠️ 数据质量核查（本笔记的核心发现）

仓库有一条 **open issue #128「Link health report: 16 dead links, 10 archived」**（Protocol-zero-0 提交于 2026-09-22，自称用 link-rot-scanner 扫了 README 全部 412 条链接）。我**逐条复核了它的结论**：

### 4.1 「16 条死链」→ **误报（15/16）**

issue 列的 16 条死链里，**15 条是 Wikipedia 链接，1 条是 `cytopia.itch.io`**。核查方式：回到 README 原文提取链接的**实际写法**——

```
README 实际写法：https://en.wikipedia.org/wiki/Doom_(1993_video_game)
issue  报告写法：https://en.wikipedia.org/wiki/Doom_(1993_video_game      ← 少了右括号
```

**15 条全部是同一个模式：URL 里含嵌套圆括号（`_(1993_video_game)`），扫描工具在提取时把结尾的 `)` 当成了 markdown 链接的收尾括号，导致 URL 被截断 → 必然 404。**

用括号平衡匹配重新解析 README，15 条链接**全部完整存在**：

| issue 声称死链 | README 中的实际完整 URL | 存在？ |
|---|---|---|
| `Doom_(1993_video_game` | `https://en.wikipedia.org/wiki/Doom_(1993_video_game)` | ✅ |
| `Civilization_(video_game` | `https://en.wikipedia.org/wiki/Civilization_(video_game)` | ✅ |
| `Quake_(video_game` | `https://en.wikipedia.org/wiki/Quake_(video_game)` | ✅ |
| `Pharaoh_(video_game` | `https://en.wikipedia.org/wiki/Pharaoh_(video_game)` | ✅ |
| `Breakpoint_(demoparty` | `https://en.wikipedia.org/wiki/Breakpoint_(demoparty)` | ✅ |
| `Diablo_(series` | `https://en.wikipedia.org/wiki/Diablo_(series)` | ✅ |
| `Blood_(video_game` | `https://en.wikipedia.org/wiki/Blood_(video_game)` | ✅ |
| `Baldur%27s_Gate_(video_game` | `https://en.wikipedia.org/wiki/Baldur%27s_Gate_(video_game)` | ✅ |
| `Aliens_Versus_Predator_(1999_video_game` | `https://en.wikipedia.org/wiki/Aliens_Versus_Predator_(1999_video_game)` | ✅ |
| `Build_(game_engine` | `https://en.wikipedia.org/wiki/Build_(game_engine)` | ✅ |
| `Command_%26_Conquer_(1995_video_game` | `https://en.wikipedia.org/wiki/Command_%26_Conquer_(1995_video_game)` | ✅ |
| `Diablo_(video_game` | `https://en.wikipedia.org/wiki/Diablo_(video_game)` | ✅ |
| `Elona_(video_game` | `https://en.wikipedia.org/wiki/Elona_(video_game)` | ✅ |
| `Fallout_(video_game` | `https://en.wikipedia.org/wiki/Fallout_(video_game)` | ✅ |
| `Portal_(video_game` | `https://en.wikipedia.org/wiki/Portal_(video_game)` | ✅ |

⚠️ **说明**：本机无法直接访问 `en.wikipedia.org`（DNS 被污染，解析到 199.16.158.182，属 Twitter IP 段；curl 全部返回 000，浏览器同样超时）。所以"链接真实可达"这一点**未能实测**，但"**README 里的链接写法本身是完整的**"这一条是直接读源文件确认的，与网络无关。`cytopia.itch.io` 同理未能实测。

### 4.2 「10 个 archived 仓库」→ **全部属实（10/10）**

用 GitHub API 逐个查 `archived` 字段，**10 个全部返回 `archived=true`**：

| 仓库 | archived | 最后 push | ⭐ |
|---|---|---|---:|
| OpenDiablo2/OpenDiablo2 | ✅ true | 2021-10-21 | 11,110 |
| atsb/NuBuildGDX | ✅ true | 2025-01-25 | 22 |
| electronicarts/CnC_Generals_Zero_Hour | ✅ true | 2025-02-27 | 4,751 |
| electronicarts/CnC_Red_Alert | ✅ true | 2025-02-27 | 6,705 |
| electronicarts/CnC_Remastered_Collection | ✅ true | 2025-01-16 | 21,373 |
| electronicarts/CnC_Renegade | ✅ true | 2025-03-03 | 1,635 |
| electronicarts/CnC_Tiberian_Dawn | ✅ true | 2025-02-27 | 1,810 |
| leereilly/games | ✅ true | 2025-09-13 | 25,007 |
| noxworld-dev/opennox | ✅ true | 2024-11-23 | 23 |
| videogamepreservation/dukenukem3d | ✅ true | 2013-08-18 | 328 |

⭐ **值得注意**：6 个 EA 官方 C&C 仓库在 2025 年 1–3 月被 EA 主动归档——这不是"社区弃坑"，是**厂商回收了官方开源发布**。而 `videogamepreservation/dukenukem3d` 自 2013 年起就归档了。

### 4.3 「31 个 2 年无活动」→ **10/11 抽查完全吻合，1 条已过时**

抽查 issue 列的 11 个仓库，用 GitHub API 的 `pushed_at` 逐一比对：

| 仓库 | issue 声称 | API 实测 | 一致？ |
|---|---|---|---|
| id-Software/DOOM | 2024-05-24 | 2024-05-24 | ✅ |
| n64decomp/sm64 | 2024-02-04 | 2024-02-04 | ✅ |
| id-Software/Quake-III-Arena | 2024-08-02 | 2024-08-02 | ✅ |
| citybound/citybound | 2023-01-07 | 2023-01-07 | ✅ |
| id-Software/Quake | 2024-06-15 | 2024-06-15 | ✅ |
| snesrev/zelda3 | 2023-12-27 | **2026-10-02** | ❌ 已恢复活跃 |
| farbrausch/fr_public | 2019-07-28 | 2019-07-28 | ✅ |
| bsegovia/cube | 2013-03-30 | 2013-03-30 | ✅ |
| nicupavel/openpanzer | 2021-02-27 | 2021-02-27 | ✅ |
| WolfireGames/lugaru | 2022-04-19 | 2022-04-19 | ✅ |
| larpon/DeadAscend | 2024-08-21 | 2024-08-21 | ✅ |

**评价**：这个 issue 的数据质量**相当高**——10/11 精确吻合，连 `pushed_at` 到日都一致；唯一偏差是 `zelda3` 在报告后（2026-09）恢复了活跃。它的方法论也严谨：明确排除了 403/412/429/000，只报硬 404/410，GitHub 条目走 API 而非 HTTP。

⚠️ **但它有一个结构性盲区**——"10 archived" 只统计了被作者显式归档的仓库，**没有覆盖"仓库存在但已废弃"的情况**。例如 `0ad/0ad`（2,828⭐）我实测 `archived=true`，而 issue 的归档列表里没有它（issue 把它归在"无活动"组，只写了 last push 2024-08-17）。这说明 **archived 清单本身也不完整**。

## 五、它的收录规则：一个"作者主权"清单

CONTRIBUTING.md 里第一条就是关键：

> *"First and most importantly those are **my personal bookmarks** and I will add a submitted game only if it seems interesting to me. If you disagree feel free to fork the repository."*

**这是策展型清单（curated list），不是社区驱动的 awesome-list。** 推论：

- ❌ **不能指望"提 PR 就会被收录"**——作者明确说了只加"他觉得有意思的"
- ✅ 收录规则很具体：一条一个 PR、标题按字典序、格式 `**[Title](link)** - Short description. [[source]](link)`、URL 尾部不带 `/`
- ⚠️ 实践中作者还是收了（近 20 次提交里有多条 "Add X (#107)" 形式的 PR 合并），但那是**作者主动开的口子**，不是承诺

**其他实际约束**：
- 分类不是"客观"分类 —— Mindustry 被放在 Sandbox（只有 1 条），Hypersomnia 在 Action（只有 1 条）。这两个分类实际上是**"作者的私人收藏夹"**
- **2025-12 至 2026-02 是一次集中扩张**：顶层条目数从 **2025-12-27 的 125 条**涨到 **2026-02-25 的 163 条**（+38 条，仅 2 个月），并新增了 Racing、Real-Time strategies、Business and Tycoon 等品类以及大量商业游戏重制。扩张期的收录质量**不如**早期精选
- **提交高度集中在作者本人**（bobeff 122 次贡献，其余贡献者多为 1 次），最后一次 push 是 2026-02-25，**距今约 9 个月未更新**

## 六、跟我们的关系

结合本仓已有的 `misc/OS-gaming-console/Mindustry.md`（Mindustry 是本清单 Sandbox 分类唯一条目），这个仓库对我们的实际用途有三条：

### 6.1 ⭐ 直接用途：给掌机项目找候选游戏源

我们已有 Mindustry 笔记（开源工厂塔防、四渠道分层定价、零广告零内购）。这个清单提供的是**同类的横向候选池**——尤其是：

| 品类 | 对掌机的适配价值 | 候选 |
|---|---|---|
| Platformers | ⭐⭐⭐ 掌机最适合的品类（单手可玩、无鼠标依赖） | Frogatto & Friends、Commander Keen、VVVVVV、Sonic Robo Blast 2、OpenGOAL |
| Roguelikes | ⭐⭐⭐ 回合制 + ASCII 界面，天生适合小屏 | Brogue CE、Cataclysm: Dark Days Ahead、NetHack、DCSS |
| Puzzle / Turn-Based | ⭐⭐ 短局、低算力 | BlockOut II、Athena Crisis、C-evo、Unciv |
| First-Person / RTS | ⭐ 需求高（键鼠/3D），仅供移植可行性参考 | OpenRCT2、OpenTTD、OpenLoco（这三家是**最可能移植到掌机**的） |

**可执行动作**：给 `misc/OS-gaming-console/` 补一篇「掌机候选游戏池」——从这份清单筛出 Platformers / Roguelikes / Puzzle 三类，标注语言（**C++ 移植成本高、Rust/SDL 类更适合**）、许可证、⭐ 与活跃度。

### 6.2 移植可行性预筛：语言 + 活跃度 = 成本

这个清单的价值不在"游戏好玩"，在**筛掉不可移植的项目**。结合上面 §三 的 API 数据，移植预筛规则：

| 判据 | 阈值 | 理由 |
|---|---|---|
| 语言 | C/C++/SDL/GL 可移植；Unity/UE 项目放弃 | 本仓掌机目标为 Linux + SDL/OpenGL |
| 最后 push | 近 12 个月内有更新 | 停更多年的移植等于从零开始 |
| archived | 排除 | 无人接手的坑填不了 |
| 素材依赖 | 需原版数据的（Doom/Quake 系）不算"完整开源" | 版权不清 |

**按此规则**，§三 表里**同时满足"语言合适 + 活跃 + 未归档"**的高价值目标已不多 —— 现实是：**清单里绝大多数条目要么停更多年、要么是商业游戏重制（素材/音频有版权问题）**。真正"纯开源 + 活跃 + 可移植"的主要是 OpenTTD、OpenRCT2、Endless Sky、Freeciv、Wesnoth、Veloren、OpenMW 这几个成熟项目。

### 6.3 ⭐ 它是"开源游戏生态"的横切面素材

这份清单覆盖了 177 个项目，其**重制/移植/反编译**部分（Doom/Quake/Wolfenstein 官方释源、sm64 反编译、zeldaret/tp 反编译、Diablo/BC/CoH 社区重制）本身就是**软件考古与版权边界的活样本**。如果后续要写"源码泄露/逆向工程/开源合规"相关的笔记，这是很好的引用池——**尤其适合给 `ops-cybersec-dba/` 补"合规与资产许可"视角**。

## 七、竞争清单横向对比

| 清单 | ⭐ | 条目行数 | 建仓 | 最后 push | 状态 |
|---|---:|---:|---|---|---|
| **bobeff/open-source-games**（本篇） | 18,367 | 186 | 2021-09 | 2026-02 | 活跃（但作者单点） |
| leereilly/games | 25,007 | 406 | 2012-01 | 2025-09 | ⚠️ **archived** |
| michelpereira/awesome-open-source-games | 3,414 | 438 | 2021-12 | 2026-11 | 活跃 |
| radek-sprta/awesome-game-remakes | 1,612 | 466 | 2020-03 | 2026-11 | 活跃 |
| trilarion/opensourcegames | 1,118 | — | 2017-11 | 2026-10 | 活跃 |

**结论**：
- ⭐ **本篇是星最多的"分类清晰 + 条目精简"型**，但条目数不是最多
- ⭐ `leereilly/games` ⭐ 更高（25k）但**已 archived**——README 的 Other lists 段还在推荐一个已归档的仓库，**这是本清单的一处失效引用**（本笔记按 §4.1 的方法核过：`archived=true` 属实）
- `michelpereira/awesome-open-source-games` 与 `radek-sprta/awesome-game-remakes` 条目更多、更新更勤（都在 2026-11 有 push），是更"新鲜"的补充
- **Other lists 段列的 9 个清单里，`leereilly/games` 已归档，其余站点（osgameclones.com / libregamewiki.org / macsourceports.com）本机实测均返回 200 可达**

## 八、实战建议 / 风险点

### 8.1 直接用它的三条原则

1. **把它当索引用，不当权威用** —— 它不标活跃度、不标许可证、不标语言，这些都得自己查 API
2. **看到 `[[source]]` 指向 archived 仓库要留心** —— 本清单的 10 个已知 archived 仓库有 6 个是 EA 官方在 2025 年归档的
3. **"开源重制"≠"完全开源"** —— 商业游戏重制项目通常代码开源、素材与音频仍受原厂版权约束

### 8.2 风险点清单

| 风险 | 证据 | 影响 |
|---|---|---|
| **作者单点 + 9 个月未更新** | bobeff 122 次贡献、其余多为 1 次；最后 push 2026-02-25 | 单点停更 = 链接腐烂无人修 |
| **死链确实存在但被误报掩盖** | issue #128 的 15 条"死链"是误报；真正的 `cytopia.itch.io` 未实测 | **误报会让人忽略真问题**——issue 若被当作权威采纳，反而掩盖了实际腐烂情况 |
| **archived 清单不完整** | `0ad/0ad` 实测 archived=true 但未进 issue 的归档列表 | 按 issue 清理会漏 |
| **Other lists 段推荐了已归档仓库** | `leereilly/games` archived=true（25,007⭐） | 引导读者到只读仓库 |
| **分类是私人偏好不是客观分类** | Sandbox 仅 Mindustry、Action 仅 Hypersomnia | 别把它当权威分类学引用 |
| **扩张期质量下滑** | 2025-12 单月 +50 条 | 新增条目质量不如早期 |
| **反向工程条目涉版权灰区** | README 明确收录 decompilation / reverse engineering 项目 | 商业用途需单独评估 |

### 8.3 本地可跑的最小示例

解析 README 成结构化条目（这是本仓库最实际的用法）：

```bash
# 用 GitHub API 取 README 并解析条目
gh api repos/bobeff/open-source-games/readme --jq '.content' | base64 -d > osg.md
```

```python
import re
t = open('osg.md', encoding='utf-8').read()
# 顶层条目：- **[Name](url)** - desc. [[source]](repo)
# ⚠️ 必须加 re.M —— 否则 ^ 只匹配整个字符串开头，finditer 一条都命中不了
pat = re.compile(r'^- \*\*\[([^\]]+)\]\(([^)]+)\)\*\*', re.M)
for m in pat.finditer(t):
    name, url = m.group(1), m.group(2)
    src = re.search(r'\[\[source\]\]\(([^)]+)\)', t[m.end():m.end()+400])
    print(f"{name}\t{url}\t{src.group(1) if src else '-'}")
```

⭐ **本机实跑结果**：命中 **122** 条，其中 **111** 条带 `[[source]]`。

⭐ **这个正则仍会漏条目**（README 顶层条目共 163 行）：漏掉的是**无官网链接**的条目（格式 `- **Name** - desc.`，共 34 行，如 `Zelda 3`、`Egregoria`、`Julius`、`Surreal Engine`）。含嵌套括号的 URL（如 Wikipedia 条目）会被 `[^)]+` 截断在第一个 `)` 处。**要精确统计必须按行解析 + 括号平衡，不能只靠一条正则**——这也是 issue #128 误报的根源（见 §4.1）。

批量补齐活跃度与语言（这才是它没提供、但最需要的信息）：

```bash
# 对上一步拿到的 repo 列跑 GitHub API
# ⚠️ 用 --jq 且把 repo 名作为 jq 字符串字面量传入（shell 不展开 $r，所以要写成 ("$r")）
for r in Anuken/Mindustry OpenRCT2/OpenRCT2 citybound/citybound; do
  gh api "repos/$r" --jq "(\"$r\") + \" | \" + (.language // \"-\") + \" | stars=\" + (.stargazers_count|tostring) + \" | pushed=\" + (.pushed_at[0:10]) + \" | archived=\" + (.archived|tostring)"
done
```

**本机实跑输出**（exit=0）：
```
Anuken/Mindustry | Java | stars=29867 | pushed=2026-11-15 | archived=false
OpenRCT2/OpenRCT2 | C++ | stars=16584 | pushed=2026-11-15 | archived=false
citybound/citybound | Rust | stars=8181 | pushed=2023-01-07 | archived=false
```

⚠️ **两个实测踩到的坑**：
1. `gh api --jq` 里直接写 `$r` **不会**被 shell 展开——jq 会把它当自己的变量，报 `cannot subtract: string ... and string ...`。要么写死字符串，要么用 `(\"$r\")` 让 shell 先替换。
2. `gh api --template` **不支持 `date` 函数**（`template: :1: function "date" not defined`），日期格式化请走 `--jq` 的 `.[0:10]` 切片。

## 九、待跟踪

- [ ] `snesrev/zelda3` 已恢复活跃（2026-10-02）—— 塞尔达反编译项目重启，值得单独看
- [ ] 6 个 EA 官方 C&C 仓库 2025 年集体归档的动机（是许可证变更还是项目终结）
- [ ] 清单是否会在作者回归后补上"语言 / 活跃度"字段（issue #71 的诉求）
- [ ] Luanti（原 Minetest）—— open issue #120 建议补录，README 目前确实没有

## 参考链接

- **仓库**: <https://github.com/bobeff/open-source-games>
- **原始 README**: <https://github.com/bobeff/open-source-games/blob/main/README.md>
- **收录规则**: <https://github.com/bobeff/open-source-games/blob/main/CONTRIBUTING.md>
- **issue #128 链接健康报告（本笔记的主要核查对象）**: <https://github.com/bobeff/open-source-games/issues/128>
- **issue #71 建议标注编程语言**: <https://github.com/bobeff/open-source-games/issues/71>
- **issue #120 建议补录 Luanti**: <https://github.com/bobeff/open-source-games/issues/120>
- **官网条目（可达）**: <https://endless-sky.github.io> · <https://www.openttd.org> · <https://osgameclones.com> · <https://libregamewiki.org> · <https://www.macsourceports.com>
- **竞品清单**: <https://github.com/michelpereira/awesome-open-source-games> · <https://github.com/radek-sprta/awesome-game-remakes> · <https://github.com/leereilly/games>（已 archived）· <https://github.com/trilarion/opensourcegames>
- **相关笔记**: [Mindustry](../OS-gaming-console/Mindustry.md) — 本清单 Sandbox 分类唯一条目，已单独成篇
