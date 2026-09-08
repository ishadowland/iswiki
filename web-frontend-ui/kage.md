# Kage (影) — MengTo 的 Three.js 京都夜行寺

> 学习笔记 · 调研时间 2026-08-28
> GitHub: <https://github.com/MengTo/kage>
> 在线演示: <https://mengto.github.io/kage/>
> 介绍: <https://mp.weixin.qq.com/s/W1Bs63h3NPxNtL_SQH973w>

---

## 1. 一句话定位

**"一个 244 KB 的单 HTML 文件,带你走过京都山寺的 5 章夜行路"** —— 全部 Three.js 程序生成 + 7 张手绘 WebP 前景图 + 编辑级别的排版,scroll-driven 镜头推进,做出 1000+ star 的沉浸式网页艺术作品。

## 2. 核心数据

| 字段 | 值 |
|---|---|
| **GitHub stars** | **1407** ⭐ (3 周前发布!) |
| **Forks** | 261 |
| **Size** | 23.7 MB (10 张 WebP + 1 个 608KB three.min.js + 1 个 244KB index.html) |
| **Language** | HTML (no build!) |
| **License** | **None** (no license granted — 不能复用) |
| **Topics** | `creative-coding, generative-art, interactive-storytelling, japanese-design, threejs, webgl` |
| **Homepage** | <https://mengto.github.io/kage/> |
| **Created** | 2026-08-08 (3 weeks ago) |
| **Updated** | 2026-08-28 (active) |

## 3. 文件结构 (27 files, 23.7 MB)

```
kage/
├── index.html                    # 244 KB — 文档结构 + CSS + Three.js scene + scroll 编排
├── PROMPT.md                     # 2.6 KB — 生成此作品的 prompt(惊人!)
├── README.md
├── assets/
│   └── kage-preview.webp         # 101 KB cover image
└── secret-pathways-assets/
    ├── fonts.css                 # 99 KB — 字体定义
    ├── three.min.js               # 608 KB — vendored Three.js r149 (MIT)
    ├── generated/
    │   ├── kage-approach.webp     # 180 KB
    │   ├── kage-lantern-court.webp # 198 KB
    │   ├── kage-moonwater.webp    # 102 KB
    │   └── kage-sanmon-preview.webp # 186 KB
    └── foreground/png/
        ├── basalt-stones.webp     # 168 KB
        ├── garden-bush.webp       # 286 KB
        ├── hill.webp              # 84 KB
        ├── maple-leaves.webp      # 178 KB
        ├── pine-tree.webp         # 196 KB
        ├── sakura-branch.webp     # 253 KB
        ├── shrine-ruins.webp      # 146 KB
        ├── stone-lantern.webp     # 150 KB
        ├── tall-grass.webp        # 352 KB
        └── temple-wall.webp       # 86 KB
```

**关键**:全部资产 **相对路径**,**GitHub Pages 子目录也能跑**;**无 build / 无 framework / 无外部字体 / 无 analytics**。

## 4. 5 章叙事结构(从 live demo snapshot 抓取)

| Chapter | 日文 | 主题 | 时长 |
|---|---|---|---|
| **00** | — | THE HIDDEN GATE 影之道 | (hero) |
| **01** | 山門 Sanmon | "Charred cypress, worn stone, one gate left open" | (开门) |
| **02** | 庭園 Teien | STILL GARDENS (3 sub: The Long Climb / Lantern Court / The Wet Court) | (院子) |
| **03** | 手業 Tegiwa | SACRED CRAFT — Five chapters. Ninety minutes. One quiet mind. (5 cards: Hidden Gate, Borrowed Scenery 借景 18min, Charred Cypress 焼杉 21min, Lantern Light 灯籠 17min, Vermilion Moon 朱月 22min) | (技艺) |
| **04** | 残光 Zankou | AFTERLIGHT — closing | (余光) |
| colophon | — | "A five-chapter night walk through a Kyoto mountain temple. Three illustrated garden field notes sit inside a live Three.js sanctuary." | (版权) |

**总时长**: 14 + 18 + 21 + 17 + 22 = **92 minutes** of reading time

## 5. 6 大核心特性

1. **Scroll-driven camera path** — 1 连续 Three.js 镜头推进,每章 1 个 composited shot (不是 hard cut)
2. **Procedural 3D scene** — 寺、鳥居、阶梯、石灯籠、月、地形、tree、雾、雨、飘叶、炭火、atmosphere 全部 runtime 构造
3. **Editorial typography** — 超大 left-aligned English heading + 大号 vertical Japanese display + 小 technical labels + chapter numbers + fine rules + 大量留白
4. **Layered assets** — 7 张 alpha-preserving WebP 前景(草、枫、樱、石、墙、废墟、bush、山、松、灯籠)在视口底部,**只在 section active 时显示并 pinned**
5. **Restrained post-processing** — bloom / film grain / vignette / depth haze / warm shoji light / cold moonlight / vermilion moon
6. **配色** — 接近黑 + blue-charcoal + warm amber + bone white + **vermilion(朱红)**

## 6. PROMPT.md 关键(他用 prompt 生成 prompt!)

> **PROMPT.md 就是生成此作品的 prompt 本身**。惊人 — MengTo 用 Claude / GPT 写出 design brief,然后 Claude 实际 implement。

设计约束:
- **结构**: hero / temple threshold / still gardens / sacred craft chapters / afterlight / manifesto footer
- **Motion**: word-by-word heading reveal + slow precise section transitions + parallax + eased camera interp
- **Interaction**: working anchor nav / mobile nav / responsive / semantic landmarks / accessible labels
- **Quality**: reduced-motion preserves full read experience / no frameworks / no remote fonts / no placeholder imagery / no glassmorphism / no excessive glow / no decorative motion
- **Test**: desktop + 390×844 mobile / asset 404 check / inline script parse / console check / full scroll test

## 7. 跟 redradman/artemis 范式对比

| 维度 | redradman/artemis | MengTo/kage |
|---|---|---|
| **Subject** | NASA Artemis II 火箭 | 京都夜行寺 |
| **Camera** | OrbitControls (用户控制) | scroll-driven (自动推进) |
| **Theme switch** | 3 themes (Blueprint/Space/Cinematic) | 无主题切换(单一 night) |
| **Asset count** | 0 (纯 procedural) | **10 手绘 WebP 前景 + 4 生成 WebP 背景** |
| **Size** | 51 KB (2000 行) | 244 KB HTML + 23 MB assets |
| **Stars** | 44 | **1407** (30x) |
| **License** | MIT | **None** |
| **CDN usage** | jsDelivr three.js | Vendored three.min.js (608 KB) |
| **Style** | Engineering diagram | Editorial art book |
| **Mood** | Technical precision | Atmospheric poetry |

**关键对比**: 都是 "single HTML + Three.js" 范式,但 Artemis 走 **data-density engineering**(3 主题切换 + select-to-isolate),Kage 走 **atmospheric storytelling**(scroll-driven 沉浸式 + hand-painted 艺术资产)。

## 8. 5 大技术亮点

1. **Self-contained delivery** — `python3 -m http.server 4173` 就能跑,**无 build / 无 env var / 无 network dep**
2. **GitHub Pages friendly** — 全部相对路径,子目录部署 OK
3. **Generated + hand-painted mixed assets** — 程序生成大场景(gpt-image-2 生成的 scene plates)+ 真人手绘细节点缀(grass, maple, sakura)
4. **Editorial typography system** — English + 日本語 display + 数字 + 留白 = 杂志排版感
5. **PROMPT.md 公开** — 把 design brief 公开,展示 "AI 协助设计" 的元透明度(他让你能复刻)

## 9. 8 大可借鉴元素

| Element | 借鉴难度 | 对 substation-blueprint 的价值 |
|---|---|---|
| scroll-driven camera | ⭐⭐ | substation-blueprint 已经用 OrbitControls,可以加 scroll-driven chapter tour |
| WebP foreground cutouts | ⭐ | 我们现在用纯 procedural,可加一些手绘点缀 |
| Editorial typography (EN + JP) | ⭐⭐ | 我们的 HUD 可以加更多文化参考元素(cyberpunk 工程感) |
| Single-file HTML + vendored three.min.js | ⭐ | 我们用 importmap,加 fallback vendor |
| PROMPT.md 公开 | ⭐ | 可在 substation-blueprint README 加 "设计意图" 章节 |
| No build / no framework | ⭐⭐⭐ | 我们的 substation-blueprint 已经符合(纯 vanilla) |
| Chapter navigation + reduced-motion | ⭐⭐ | substation-blueprint 可以加分章(主题切换) |
| Self-contained README | ⭐ | 学习他的 README structure |

## 10. 设计对比 substation-blueprint

substation-blueprint 我自己的项目是 **substation 3D visualization** with similar "blueprint + Three.js + single HTML" 哲学。Kage 是这个哲学的**更高级实现**:

| 维度 | substation-blueprint | Kage |
|---|---|---|
| 文件 size (HTML) | ~5 KB | **244 KB** (含 CSS + JS inline) |
| 3D 内容 | 升压站 + 2376 光伏组串 | 京都寺 + 鸟居 + 月 + 树 + 雾 + 雨 + 飘叶 + 炭火 |
| Asset 数量 | 0 (全 procedural) | **14 (4 背景 + 10 前景)** |
| 交互模式 | OrbitControls (自由) | **scroll-driven (自动)** |
| 主题切换 | 3 themes | 1 night scene |
| 性能 | 49 LineSegments (merge) | 程序生成 3D (动态) |
| Star (本仓库) | n/a | **1407** |
| 定位 | Engineering | Editorial art book |

== **学习重点**: Kage 的 **"editorial typography" + "generative + hand-painted asset mix"** 是 substation-blueprint 升级方向。

## 11. 其他 MengTo 项目 (相关 inspiration)

从 README 列出:
- **[Complete Shelf](https://mengto.github.io/complete-shelf/)** — Three.js 7 本可交互精装书
- **[Sketchbook](https://mengto.com)** — Singapore 翻页 sketchbook + 放大镜
- **[Agent Skills](https://github.com/MengTo/Skills)** — 他用 Claude 写的 reusable skills lib,包括:
  - `falling-leaves` (从 Kage 抽出来的技术)
  - `pointer-trail-emitter` (从 Kage 抽出来的 cursor trail)

**Kage 的 "agent skills"**: **他开源了他用来生成 Kage 的 skill 库**!

## 12. 适用 substation-blueprint 的具体建议

1. **加 scroll-driven camera tour** — Kage 风格的" 走过 substation " 5 章 tour
2. **加 hand-painted accent layer** — 现在的纯 procedural 可加几张 WebP 资产 (substation 周边环境、装饰元素)
3. **加 editorial typography** — 现在的 HUD 可加 EN + CN 混合 display typography
4. **学习 PROMPT.md pattern** — substation-blueprint 可加 `DESIGN_INTENT.md` 解释 design choices
5. **加 reduced-motion 支持** — Kage 强制要求 `prefers-reduced-motion: reduce` 仍能完整阅读

## 13. 相关 iswiki 项目

- **[redradman/artemis](artemis-redradman.md)** (44 ⭐) — 同范式 NASA wireframe
- **[artemis-art-direction](artemis-art-direction.md)** — Artemis 美术风格
- **[kage](kage.md)** — 京都夜行寺 (本文)
- **[mengto-skills](mengto-skills.md)** — MengTo Skills repo(待调研)

## 14. TL;DR

**Kage = MengTo 用 Three.js + Three 周手画艺术资产 做的"京都夜行寺"沉浸式叙事网站**。1407 ⭐,244 KB HTML,无 build / 无 framework,scroll-driven camera + 程序生成 3D + WebP 前景层 + 编辑级排版。

**最大启示**: **"single HTML + Three.js + hand-painted assets"** 是有真实用户基础的 production-quality 范式(1407 star 不是偶然),**substation-blueprint 的同范式项目完全有潜力走到类似高度**,关键差距在:
- **Editorial typography** (我们现在是工程师字体)
- **Asset depth** (我们 0 张手绘)
- **Scroll-driven narrative** (我们是 free OrbitControls)

== **下一步**:把 PROMPT.md 学到的方法学应用到 substation-blueprint 的 design intent 文档。
