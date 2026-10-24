# three-screen-lab(VIZ / LAB 可视化大屏展厅)深度审计

> **本文对象**:`github.com/ishadowland/three-screen-lab`(**private fork**,作者自用;公开访问会 404)
> **上游出处**:`github.com/agentthink/three-screen-lab`(实为 `yinweinidongle/screen-picture-demo` 的再发布快照)—— 原始审计即在此快照上完成
> **在线演示**(上游 public Pages,无需权限):https://yinweinidongle.github.io/screen-picture-demo/home.html
> **原始审计**:由另一 agent(MiniMax)在 `macOS 24.6.0 x64 · Node v24.8.0 · Python 3.13.7` 上完成完整克隆 + 构建 + 浏览器实测 + 素材重建管线
> **本文性质**:iswiki 改写收录 + **2026-10-24 第二次独立复核(Hermes,macOS 13.6 x64 · Node v24.13.0 · Python 3.11/3.12)**
>
> 🔺 **复核结论**:原审计的绝大多数结论**成立且可复现**(17/17 测试通过、构建成功、8 页运行时外部请求全 0、素材重建后 Git 跟踪文件零变更、风电计数器 131 draw calls / 20 批 / 381 实例与性能文档完全一致、GLB 可重生成差 0.37%)。但**有 4 处结论过宽或错误**,已在正文就地标注 `🔺 独立复核修正`,并在**附录 B** 汇总复现证据与新发现。引用本文数字时请以附录 B 为准。
> **修复进度**:private fork 已修 P0-1(CI 分支名 `master`→`main`,commit `80cc692`;CI 实测 build 全绿),并发现**第二层阻塞**:private repo + GitHub Free 计划不支持 GitHub Pages(`POST /pages` → 422),已加 `vars.pages_enabled` 开关绕开(commit `d923c1e`);另按 §6.2 建议修掉 inspection 用例的 flaky 超时(commit `0dcae39`)。其余 P0/P1 待处理。

---

## 一句话结论

**工程质量明显高于同类"大屏 Demo"的开源项目** —— 不是一次性的演示堆砌,而是一个带**注册表驱动的构建系统**、**严格的素材溯源管线**和**真实浏览器测试**的可扩展作品集框架。七个场景全部程序化建模(不依赖外部 CAD / 模型市场资源),Shader 功底扎实,无障碍设计有意识。

但存在**几处真实缺陷**,且**生命周期管理在场景之间严重不一致**(wind 规范,factory / population / inspection 三个场景完全不遵守仓库自己定义的 `VizLabRuntime` 契约)。

| 维度 | 评价 |
|---|---|
| 构建系统与工程化 | ★★★★★ 优秀,内容哈希 + 离线单文件双产物 |
| 渲染 / Shader 功底 | ★★★★☆ 扎实,`onBeforeCompile` 注入 + 深度预通道 + 可分离模糊 |
| 建模 | ★★★★☆ 真程序化(超椭圆放样、翼型扭转/锥度) |
| 素材溯源与合规 | ★★★★★ SHA-256 固定 + Natural Earth 公共领域 + 逐条许可清单 |
| 测试覆盖 | ★★★★☆ 真实 Playwright 交互测试(含 fallback / reduced-motion) |
| 无障碍 | ★★★☆☆ 键盘可达性优秀,但对比度与 ARIA 有硬伤 |
| 生命周期一致性 | ★★☆☆☆ 四个场景四种做法,工厂/人口/巡检无任何清理 |
| 数据诚实性 | ★★☆☆☆ 人口页用真实普查数据标 2022 且无提示 |

---

## 二、仓库身份:一个快照镜像,不是上游历史

| 项目 | 实际情况 |
|---|---|
| 提交历史 | **仅 1 个 commit**(`f413a2f init`,作者 "Your Name",2026-10-24)—— 被压平 |
| 默认分支 | `main`(唯一分支) |
| `package.json` repository | `github:yinweinidongle/screen-picture-demo` |
| README / 文档内所有链接 | 指向 `yinweinidongle.github.io` 与 `github.com/yinweinidongle/screen-picture-demo` |
| 上游来源 | `agentthink/three-screen-lab` 是 `yinweinidongle/screen-picture-demo` 的**再发布快照** |
| 本文对应副本 | `ishadowland/three-screen-lab`(**private**,agentthink/three-screen-lab 的 fork);已修 P0-1,commit `80cc692` |
| 待合并 PR | 4 个 dependabot:checkout-7 / upload-artifact-7 / upload-pages-artifact-5 / pillow-13.0.0 |

### 🔴 P0 — CI 与 Pages 在本仓库永远无法触发

`.github/workflows/ci.yml`:

```yaml
on:
  push:
    branches: [master]        # ← 但本仓库只有 main
...
- uses: actions/upload-pages-artifact@v4
  if: github.ref == 'refs/heads/master' && github.event_name != 'pull_request'
```

`master` 分支不存在 → **push 触发不生效、Pages 部署永不执行**。`pull_request` 触发仍然有效(CI 校验还能跑)。

> 🔺 **独立复核修正（2026-10-24）**:此缺陷**只影响 `agentthink` 这份公开快照**,不能推广到整个项目。实测:
>
> - `agentthink/three-screen-lab`:只有 `main` 分支 → workflow 监听 `master` → push 不触发、`gh api repos/agentthink/three-screen-lab/pages` 返回 **404**(Pages 从未部署)
> - 上游 `yinweinidongle/screen-picture-demo`:默认分支是 **`master`**,workflow 监听 `master` **匹配** → Pages 状态 **`built`**、`html_url` 正常,31 次 CI run 全部 success
>
> 所以准确表述是:**「`agentthink` 副本的部署从未通过;上游同名项目的部署一直正常」**。原文「这个项目在 GitHub 上的部署从来没通过」过宽。

**修复方式二选一**:把 workflow 的 `master` 改成 `main`,或把仓库默认分支改回 `master`。同时 `SECURITY.md:3`、`CONTRIBUTING.md:21,58`、`ROADMAP.md` 里的 `master` 也要同步。

> ✅ **已在 private fork 修复(2026-10-24)**:`ishadowland/three-screen-lab` commit `80cc692` 把 5 个文件里的 `master` 全部改成 `main`(`.github/workflows/ci.yml` 3 处 + `CONTRIBUTING.md` 2 处 + `README.md` / `SECURITY.md` / `docs/architecture.md` 各 1 处)。**未改** `.github/ISSUE_TEMPLATE/config.yml` 的 `blob/master/CONTRIBUTING.md` —— 那是指向上游 `yinweinidongle/screen-picture-demo` 的外链,非本仓库分支引用。
>
> ⚠️ **但修完分支名还不够 —— 审计未覆盖的第二层阻塞(2026-10-24 实测新增)**:修 `master` → `main` 后,CI 的 push 触发与 `build` job **实测全绿**(run `40100007065`,`npm ci` / `setup` / `format:check` / `check` / `test` / `build` / `test:browser` 全部 success,**Playwright 的 4 个 macOS 字体度量失败在 Linux CI 上完全没出现**,反向印证了审计"4 个失败是环境差异不是功能缺陷"的判断),但 `deploy` job 以 `HttpError: Not Found` 失败。根因**不是配置**:
>
> ```
> POST /repos/{owner}/{repo}/pages
> → 422 "Your current plan does not support GitHub Pages for this repository"
> ```
>
> **GitHub Free 计划不支持 private repo 的 GitHub Pages**,且 fork 不继承上游的 Pages 设置。fork + private 这条路走不通 —— 上游 public Pages 站点(`yinweinidongle.github.io`)依然可用。
> private fork 侧的解法(commit `d923c1e`):把 `upload-pages-artifact` 与 `deploy` job 都加上 `&& vars.pages_enabled == 'true'`(未定义 → 空串 → false → 整条 Pages 链路跳过,run 不再变红),并在 workflow 里写明两条真正解法 —— ① 升级 Pro/Team + 在 Pages 开启 + 加 Actions Variable `pages_enabled=true`;② 改部署到 Cloudflare Pages / Vercel / Netlify。

---

## 三、实际验证:项目能跑,构建产物合规

以下全部是**真实执行结果**,非推断。

```
npm ci            ✅
npm run setup     ✅  创建 .venv,装 black 26.10.1 / pillow 12.2.0
npm run check     ✅  Registry: 7 screens
npm test          ✅  Python 14 tests OK + Node 3 tests OK  = 17/17 通过
npm run build     ✅  10.2s,7 屏 + Home,web + standalone 双模式
npm run test:browser  ⚠️  6 passed / 4 failed(4.2m)— 见 §六
```

> 🔺 **独立复核修正**:二次实跑为 **7 passed / 3 failed** —— inspection 的截图超时在第二次跑通(转绿),三屏面板溢出仍失败。且**这三屏的失败不是字体环境差异**(见 §六·6.1 与附录 B),而是真的布局缺陷。

### 3.1 构建产物

| 产物 | 体积 | 说明 |
|---|---|---|
| `dist/*.html`(web) | 7–24 KB | 资源外链到 `_assets/<hash>.*`(51 个文件) |
| `dist/standalone/*.html` | 852 KB – 3.9 MB | 全部资源 base64 内嵌,**零外部运行时依赖** |
| `dist/factory-campus.glb` | 18.6 MB | 程序化厂区的**导出产物**,不是场景输入 |
| `dist/screen-picture-source.zip` | 33.7 MB | 源码包 |
| `dist/` 合计 | 109 MB | 含 docs/media 录屏 GIF |

**离线能力已验证**:对 `dist/standalone/*.html` 全量扫描 `src=`/`href=` 外链,除 home.html 一个指向 GitHub 的**导航链接**外,其余 7 个页面的外部运行时资源引用数**均为 0**。README 关于"离线版不依赖 CDN"的说法属实。

### 3.2 构建系统架构(`scripts/`)

```
tasks.mjs ──┬─→ build.py ──→ buildlib.py  (核心:标记注入 / 资源装配)
            ├─→ archive.py (源码 ZIP)
            └─→ setup.mjs / dev.mjs / server.mjs / check.mjs / new-screen.mjs
```

**核心机制**:模板里的 `/*__THREE__*/`、`/*__CSS__*/`、`/*__SCREEN_JS__*/` 等标记,在构建期被**字符串替换**为真实源码。

- `buildlib.py:347-353` 特别处理了 Prettier 可能把分号挪到标记后面导致的 `null; /*__CHINA__*/` 情况 —— `tests/test_build.py:72-93` 专门为这个坑写了回归测试。**这是真正被生产使用过的防御。**
- `buildlib.py:208-211` `finish()` 强制检查未解析标记,残留即构建失败。
- `buildlib.py:23-27` `safe_path()` 用 `is_relative_to` 防止路径穿越,`tests/test_build.py:34-36` 有专门用例。
- `buildlib.py:11` 资源名 = `stem + sha256[:16] + ext`,配合 `server.mjs:62-64` 对 16 位十六进制文件名发 `immutable` 缓存头,对 HTML 发 `no-cache` —— 缓存策略正确。
- `build.py:13-21` 全量构建只删除**上一份 manifest 记录过的文件**,不递归删任意目录 —— 防误删。

**注册表驱动**:`config/screens.json` 是唯一真相源。`buildlib.py:30-74` 校验 id 格式/重复、分类、尺寸范围、预览文件存在性、模板存在性。`src/home/card.html` 是一张通用卡片模板,Home 用同一份模板渲染全部 7 个场景 —— **新增场景零需改 Home**。`npm run new:screen -- solar` 一键生成骨架。

---

## 四、渲染实现分层

七个大屏实际只有**三套技术路线**:

```
                    ┌─────────────────────────────────────────┐
                    │        config/screens.json (注册表)      │
                    │   id / renderer / width / height / ...  │
                    └──────────────────┬──────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
   renderer: wind/factory        renderer: population/inspection   renderer: generic
   智慧风电 · 智慧工厂           全国人口 · AI 巡检                 农业 · 工业 · 园区
   Three.js + 自研 GLSL           地理数据专用注入                   共享 "Observatory" 框架
```

### 4.1 智慧风电 — 全程序化建模(无任何 GLB/贴图文件)

**建模质量是全项目最高的一档:**

- **机舱外壳**(`wind/model.js:399-435`):`shellPoint()` 定义超椭圆截面(`Math.sign(c)*Math.pow(Math.abs(c),0.54)`),沿 44 个截面 × 80 边放样,带真实 UV,约 7,040 三角形。
- **叶片翼型**(`model.js:528-558`):50 径向 × 22 弦向,含**真实气动扭转**(`0.4*(1-t)-0.1`)、锥度(`sin(pow(t,0.55)*π)`)、厚度分布、后缘后掠(`-0.45*t²`)。
- **环境光**:512×256 canvas 画渐变 + "影棚窗" → `CanvasTexture` → `PMREMGenerator` → `scene.environment`。**不携带 HDR 文件。**
- 齿轮箱 48 颗离散齿 + 3 组行星轮、发电机 52 片散热鳍 + 24 圈铜绕组。

**Shader(2 个,均为内联 GLSL):**

1. **X 光玻璃材质**(`model.js:91-101`):菲涅尔边缘辉光 + `fwidth` 抗锯齿的 22×14 UV 网格 + 固定方向高光条 + `uWire` 线框态切换。
2. **能流材质**(`model.js:579-588`):沿 U 轴 `fract(uv.x*9. - uTime*.65)` 滚动脉冲,`pow(...,8)` 形成彗头,沿"风能→机械能→电能"路径流动。配 90 个 additive `Points` 火星。

**实例化优化**(`model.js:631-669`):遍历所有 Group,按 `geometry.uuid + material.uuid` 分桶,**排除**带 `userData.part`、有子节点、透明、ShaderMaterial 的对象;**<3 个成员的桶跳过**;`InstancedMesh` 加回**同一个父 Group**,因此爆炸动画能带着批次一起动。

> ✅ **独立复核通过**:按确定性循环反推分桶,得到恰好 **20 批 / 381 实例** —— 与 `docs/performance.md` 声称的数字**分毫不差**。CI 用 `data-draw-calls < 300` 守护这个回归。

### 4.2 智慧工厂 — 全项目 Shader 水平最高

**没有 GLTFLoader,`factory-campus.glb` 是本项目自己导出的下载产物**(`app.js:754-768`)。场景全部程序化:冷却塔是真正的**双曲面**(`radius = 12.7 + 0.0078*(y-52)²`,`LatheGeometry` 160 段 + 内壁 BackSide + 144 根百叶梁)、600 棵实例化树(LCG 抖动)、11 条带虚线路标的道路、程序化混凝土/金属/草地贴图(512² canvas + 逐像素噪声)。

**Shader 链(6 层):**

| # | 技术 | 位置 | 效果 |
|---|---|---|---|
| B1 | 昼夜**屏幕空间擦除** GLSL | `model.js:797-801` | `gl_FragCoord.x` 映射到屏幕比例空间,wipe 从 −0.055 扫到 1.055,边缘叠高斯光束 |
| B2 | **`onBeforeCompile` 注入** `MeshStandardMaterial` | `model.js:802-833` | 所有材质按 `nightWeight()` 向夜色过渡;`customProgramCacheKey` 正确区分三个 shader 变体(**这是 three.js 里容易踩错的点,此处做对了**) |
| B3 | 菲涅尔 + 极细发光网格 | `model.js:843-877` | 视空间菲涅尔(指数 3.7)+ `fwidth` 抗锯齿 8×8 网格,被 `gridMap` 贴图调制 |
| B4 | **深度预通道遮挡** | `model.js:884-906` | `colorWrite:false` 的深度材质复制体,`renderOrder 0`,保证辉光被建筑正确遮挡 |
| B5 | **两趟可分离高斯模糊 + 加性合成** | `model.js:948-982` | 经典权重 0.383103/0.241843/0.060625/0.00598,`CustomBlending` 累加到已渲染帧 |
| B6 | 线框变体 | `model.js:943 + 823` | 夜间线框走独立 shader 分支 |

**日夜擦除的尺度不变性做得很到位**:`uWipeOffset/uWipeSpan` 由 host 与 `#factory-screen` 的 `getBoundingClientRect()` 推算(`model.js:1035-1038`),两者受同一 CSS transform 影响,所以缩放后擦除边界仍然对齐。

### 4.3 全国人口 — 真正的正交 WebGL 地球(非贴图球)

`globe.js` 用 `OrthographicCamera(0, 2160, 1200, ...)` + `SphereGeometry(570, 160, 112)`,**省份是挤出面球体上的独立网格**:

- `polygonGeometry()`(`globe.js:215-270`)用 `ShapeUtils.triangulateShape`(earcut)三角化,再经 `geo(lon,lat,r)` 投影到 `MAP_R = 650`(悬浮在球面上方 80 单位)。
- 5 个自定义 ShaderMaterial:地球昼夜光照合成、大气边缘壳、光晕平面、扫描壳、省份密度着色。
- 迁徙弧线用 `MigrationCurve extends THREE.Curve` 子类(`globe.js:427-442`),`TubeGeometry` 与 `getPoint()` 共用同一曲线定义 —— 惯用写法。
- **SVG fallback 是真工程**(`globe.js:712-769`):WebGL 构造失败时用 `d3.geoOrthographic` 重建地球 + `d3.geoGraticule10()` 经纬网,并安装一个**空实现 API 桩**,保证上层不崩。

### 4.4 AI 巡检 — 纯 SVG,无 WebGL

> ✅ 已独立核实:`grep -c "THREE\|three" src/screens/inspection/app.js src/screens/inspection/map-depth.js` → **两个文件均为 0**。

用 `d3.geoMercator()` + `d3.geoPath()` 绘制。**立体地图的原理很有意思**(`map-depth.js`):不是逐省挤出,而是**堆叠轮廓剪影** —— 把全国轮廓渲染 32 次,每次按 `(6z/32, z)` 亚像素错切,填色从 `#042d4e` 插值到 `#1489b5`。注释写明了理由:

> *"Render the whole country's silhouette at each elevation, avoiding seams and vertical walls along internal province borders."*

(宁可牺牲内部省界立体感,也不要省界处出现接缝和垂直墙 —— 这是理解 SVG 挤出伪影后才会做的取舍。)

`map-depth.js` 用 `<defs><path id>` + **38 个 `<use>` 实例**,5,517 顶点的轮廓只定义一次。装饰层设了 `aria-hidden="true"` + `pointer-events="none"`。**这是全仓库工程质量最高的单个文件。**

### 4.5 农业 / 工业 / 园区 — Observatory 共享框架

`src/shared/observatory.js`(779 行)+ `observatory-scene.js`(394 行)提供完整外壳:页头、导航、主题页签、指标条、3+1+3 面板栅格、SVG 图表、`<dialog>`、toast、CSV 导出、键盘模型。

**抽象边界是诚实的**:`observatory-scene.js` 对 `agriculture|industry|park|greenhouse|farm|cnc|agv` 的 grep **零命中** —— 场景层完全屏幕无关。

**但有两处泄漏:**
1. `observatory-header.js:28/51/68` 是**三分支 switch**,加第 4 个场景要改"共享"文件。
2. `observatory.js:136-138` 把 `resolved`(工业+园区)、`irrigating`/`taskDone`(农业)硬编码进通用 state。

**关键结论:框架本身不过度设计,但完全没被文档化。** `docs/adding-a-screen.md` 和 `scripts/new-screen.mjs:19` 都只描述了旧的 `renderer: generic` 路径 —— **框架被 3 个场景使用,被 0 个文档记录**。第 4 个贡献者根本不会知道它存在。

---

## 五、共享层:值得称道的部分

### 5.1 `VizLabRuntime`(`src/shared/runtime.js`,28 行)

```js
function onDispose(callback) { cleanups.add(callback); return () => cleanups.delete(callback); }
addEventListener('pagehide', (event) => {
  if (event.persisted) return;          // ← 正确跳过 bfcache
  for (const callback of cleanups) callback();
  cleanups.clear();
});
function mountStage(element, width, height, onResize = () => {}) { ... }
```

设计得很克制:固定设计分辨率 → `translate(-50%,-50%) scale()` 适配视口,resize 监听器通过 `onDispose` 自动摘除,`pagehide` 时统一清理。**这是一个正确的生命周期契约** —— 问题在于一半的场景没用它。

### 5.2 Home 展厅(`src/home/app.js`)

- **同屏只跑一个场景**:`active` 单例,切换时 `stop(active)` 移除 iframe 及其 document。
- iframe 用 `sandbox="allow-scripts allow-same-origin allow-downloads"`。
- **20 秒加载超时 + 截图兜底**(`app.js:67`),`onload` 后检查 `contentDocument.querySelector('canvas, svg, main')` 判断是否真渲染成功。
- `IntersectionObserver`(rootMargin 150px):卡片滚出视口自动停掉预览;`visibilitychange` 隐藏页面时也停。
- 尊重 `prefers-reduced-motion`(`app.js:111`)。

这是把"七个 WebGL 场景同时跑会烧爆显卡"这个真实问题解决得很干净的例子。

### 5.3 素材溯源管线(本次分析的亮点)

```
scripts/prepare_assets.py  → Natural Earth 下载 + 拓扑简化 + 名称映射
config/asset-sources.json  → 上游 URL + bytes + sha256 + version + licenseEvidence
assets/manifest.json       → 每个素材的 sha256 + commercialUse/redistribution/modification
scripts/verify_assets.py   → 校验"必须是已清权的许可,且三项权限显式为 true"
tests/test_assets.py       → 拒绝陈旧哈希、拒绝非法路径、拒绝"unverified"状态
```

`verify_assets.py` 的白名单:`CLEARED = {"Public domain", "MIT", "CC0-1.0", "CC-BY-4.0"}`,且 `licenseEvidence` 必须以 `https://` 开头。`tests/fixtures/retired-assets.json` 还专门防止已退役素材复活。

**这是同类开源可视化项目里最完整的合规处理。**

---

## 六、浏览器测试结果拆解

```
6 passed (4.2m)
4 failed:
  - inspection: province hover exposes tooltip without a dialog
  - agriculture / industry / park: real scene, contextual metrics, object details and mobile layout
```

**这 4 个失败全部是环境差异,不是功能缺陷。**

> 🔺 **独立复核修正（2026-10-24,第二次实跑）**:上面 4 个失败里,**inspection 的截图超时属环境问题**;但**农业 / 工业 / 园区的面板溢出不是字体环境差异** —— 实测是**产品布局本身零余量**。详见下文 §6.1 的修正与文末「附录 B:独立复核」。
>
> 二次实跑结果:**7 passed / 3 failed**(inspection 通过,三屏溢出仍失败)。

### 6.1 失败 2/3/4(农业 / 工业 / 园区)— 面板溢出 3–5px

测试断言所有 `.ob-panel` 不得出现 `scrollHeight > clientHeight + 2`。实测:

| 场景 | 溢出面板 | scrollHeight | clientHeight | 溢出量 |
|---|---|---|---|---|
| agriculture | 作物生长监测 / 土壤生命力 | 238 / 237 | 233 | **5px / 4px** |
| industry | 全流程质量控制 | 238 | 233 | **5px** |
| park | 企业创新生态 | 236 | 233 | **3px** |

根因:面板高度固定(内容盒 233px),字体栈是 `Inter, "SF Pro Display", "PingFang SC", "Microsoft YaHei", sans-serif`。macOS 走 PingFang SC,Linux CI 走 Noto Sans CJK,**中文字形行高差几个像素**,刚好把内容顶出容器。

> 🔺 **独立复核修正**:上面这段根因归给「macOS 走 PingFang SC,Linux CI 走 Noto Sans CJK,中文字形行高差几个像素」。**实测该假设不成立** —— 分别强制 `PingFang SC` / `Noto Sans CJK SC` / `Helvetica Neue` / `Times New Roman`,溢出量稳定不变(PingFang 与 Noto 均为 5px+4px,Helvetica 与 Times 为 5px+0)。字体只影响**溢出多少**,不影响**是否溢出**。
>
> **真实根因是布局零余量**:侧栏 `grid-template-rows: 234.656px / 234.672px / 234.672px`,而 `.ob-panel` 的 `padding: 17px 18px` 让内容盒只剩 **193px**;三个溢出面板的「内容 + margin」实际需要 **237 / 249 / 247px**。差 3–5px,不是几个像素的字体抖动 —— 是**产品侧没有留余量**。
>
> ⚠️ 附带印证:作者 private fork 在 Linux CI 上跑 `test:browser` **全部通过** —— 这确实说明字体度量有影响,但**不能推出「字体是失败根因」**。字体决定了*溢多少*,布局零余量决定了*会不会溢*。两者是「触发条件」与「根本原因」的区别。

> **这暴露了一个真实的设计脆性**:面板高度是**像素级精确贴合**的,零余量。任何字体渲染环境变化(不同 OS、语言包、浏览器版本)都会打破构建。
> **建议**:面板改用 `min-height` + `overflow-y:auto`,或给内容区留 6–8px 余量,测试断言改为容忍 ±6px。

### 6.2 失败 1(inspection)— afterEach 截图超时,非断言失败

错误信息是 `Test timeout of 45000ms exceeded while running "afterEach" hook`。错误上下文里的页面快照显示 **34 个省份按钮全部正常渲染** —— 断言本身通过了,是 `afterEach` 里的 `page.screenshot({fullPage:true})` 在软件渲染(swiftshader)下对超大 SVG 页面太慢。

加长超时重跑验证:

```bash
$ npx playwright test --grep "inspection" --timeout=120000
  ✓  1 tests/browser/gallery.spec.mjs:73:1 › inspection: province hover ... (53.3s)
  1 passed (54.3s)
```

**通过。** 修复建议:`playwright.config.mjs` 的 `timeout: 45000` 对含全页截图的 afterEach 偏紧,建议提到 90–120s,或把 `fullPage` 截图降级为视口截图。

> ✅ **该建议已在作者 private fork 落地并被 CI 反向验证(2026-10-24,Hermes)**:private fork 的 CI 实测确认这个用例**是 flaky 而非稳定失败** —— 同一份代码在 run `40100007065` **通过**、在 run `40100479694` 以 `page.waitForLoadState: Test timeout of 45000ms exceeded` **失败**。已按建议修(commit `0dcae39`):
> - `playwright.config.mjs`:`timeout` 45s → **120s**,`expect.timeout` 20s → **30s**
> - `tests/browser/gallery.spec.mjs` — afterEach 截图**按结果降级**:`fullPage: info.status !== info.expectedStatus`(成功的用例只截视口,失败的才截 fullPage —— 成功路径的 review.png 无人查看,却每次消耗几十秒)
>
> `info.status` 在 afterEach 里的取值用**最小 Playwright probe 实测确认**(不需浏览器):通过 → `expectedStatus=passed status=passed` → `fullPage=false`;失败 → `expectedStatus=passed status=failed` → `fullPage=true`。本地已过 `npm run format:check` / `npm run check` / `npm test`(3/3);浏览器测试需 macOS 14+ 的 Playwright 1.64,本机 macOS 13.6 装不了官方 chromium,故由 CI 验证(见 [附录 B.8](#b8-新发现二playwright-官方-chromium-不支持-macos-13))。

### 6.3 浏览器测试的实际含金量

值得肯定的是测试**真的在测交互**,而不是测"页面没崩":

- 断言 `data-draw-calls < 300`(wind)、`< 180`(三屏)—— **性能回归被 CI 守住**
- 断言 `data-exploded` / `data-wire` / `data-flow` / `data-running` 的状态迁移
- 断言键盘操作:方向键改变地球经纬度、图表页签 `ArrowRight` 移动焦点
- **注入 `getContext('webgl')` 返回 null 验证 fallback 路径**,且 fallback 下对象详情弹窗仍可用 —— 这个用例质量很高
- `emulateMedia({reducedMotion:'reduce'})` 验证动画确实停
- `afterEach` 断言**零 pageerror**

---

## 七、确认的真实缺陷

> 以下每条都经原审计独立 grep / 实测复核过,标注了 `文件:行号`。

### 🔴 P0 — 生命周期契约被一半场景忽略

| 场景 | `onDispose` | rAF 取消 | renderer.dispose | 定时器清理 |
|---|---|---|---|---|
| 农业/工业/园区 (Observatory) | ✅ | ✅ | ✅ | ✅ 全清 |
| 智慧风电 | ✅ | ✅ | ✅ | ❌ `setInterval` 未清、keydown 未摘 |
| **智慧工厂** | ❌ **完全没用** | ✅(模型内) | ⚠️ 有 `dispose()` 但**从未被调用** | ❌ |
| **全国人口** | ❌ | ❌ **永不取消** | ❌ **无 dispose** | ❌ `setInterval` 未清 |
| **AI 巡检** | ❌ | n/a(无 WebGL) | n/a | ❌ 时钟 `setInterval` 未清 |

**关键证据:**

```bash
$ grep -rn "dispose" src/screens/factory/app.js          # → 0 结果
$ grep -rn "VizLabRuntime|onDispose" src/screens/factory/ # → 0 结果
```

`factory/model.js:1257` 定义了完整的 `dispose()`(释放 renderer、glowA/glowB、blur/composite、所有材质、所有贴图),**但没有任何代码路径调用它**。`model.js:1259` 有 `cancelAnimationFrame`,但 `dispose()` 本身永远不执行。

```bash
$ grep -rn "dispose|cancelAnimationFrame|pagehide" src/screens/population/
app.js:9:const pReduced = matchMedia(...)
styles.css:1327:@media (prefers-reduced-motion: reduce) {
```

人口场景**没有任何 dispose 概念**。`globe.js:679` 的 `requestAnimationFrame(animate)` 在函数顶部无条件调用,无对应 `cancelAnimationFrame`;`globe.js:48` 的 `renderer.setSize(2160,1200,false)` 只执行一次且 `renderer.dispose()` 从未调用;7 个 canvas 事件监听器(`globe.js:562,570,595,606,610,613,627`)全部不移除。

> **实际影响**:单页独立访问时浏览器会整体回收,危害有限。但仓库**自己定义了 `VizLabRuntime` 契约**,一半场景不用,是明确的一致性缺陷;一旦这些场景被嵌进 SPA 外壳或 iframe 复用(**Home 实时预览正是 iframe 场景!**),泄漏就会显现。
> 特别注意:**Home 的实时预览正是用 iframe 加载这些页面的**,所以"离开卡片时移除 iframe"的路径会真实触发这些泄漏。

### 🔴 P0 — 配置与实现不符(人口页)

```bash
$ grep -A9 '"id": "population"' config/screens.json | grep -E 'width|height'
    "width": 1920,
    "height": 1080,
$ grep -n "2160\|1200" src/screens/population/app.js
127:  pScale = Math.min(innerWidth / 2160, innerHeight / 1200);
```

注册表声明 **1920×1080**,代码实际渲染 **2160×1200**。而 `src/home/card.html:33` 直接渲染 `{{width}} × {{height}}`,`src/home/app.js:22-29` 也按声明值缩放 iframe 预览。

**结果:Home 卡片对外宣称的人口大屏尺寸是错的,预览 iframe 的缩放比例也是错的。**

### 🟠 P1 — 风电换流器的管路/线束挂错了父节点

`wind/model.js:333-358` 调用 `tube(...)` 和 `link(...)` 时**漏传 `parent` 参数**,默认落到 `internals` 而非 `rear`(换流器)组。**爆炸拆解动画时,换流器柜体飞走了,配套管路和线束却留在原地 —— 装配体在视觉上被撕开。** 文件中其它所有 helper 调用都传了正确的 parent,说明这是笔误而非设计。

### 🟠 P1 — 风电玻璃 Shader 的 `uTime` 是死代码

```js
// wind/model.js:98  片元着色器声明
'uniform float uTime,uOpacity,uWire,uCool;...'
// wind/model.js:100 片元着色器主体 —— uTime 从未被使用
// wind/model.js:784 每帧写入
glassUniforms.uTime.value = clock;
```

`uTime` 声明了、每帧也写了,但**片元着色器主体里根本没用它** —— 玻璃材质不动画,这行每帧写入是纯粹的空操作。真正使用 `uTime` 的是能流材质(`model.js:587`)。`docs/screens/wind.md:3` 描述的"玻璃/流光 Shader"中,玻璃那半不成立。

### 🟠 P1 — 人口页:真实普查数据 + 2022 年标签 + 无任何提示

- `population/app.js:59-94` 的 `pPopulation` **确实是真实的 2020 年七普数据**(广东省 12601、山东省 10152、河南省 9937 —— 核对无误)。
- 但界面标签是 **2022**(`app.js:11` `pYear = 2022`,`template.html:112` 显示 `2022.05.10`,年份选择器提供 2022/2021/2020/2019)。
- **省份卡片上没有任何"演示数据"标注**,只有弹窗里才有 `pNote`(`app.js:537-538`)。
- 对比:**AI 巡检页在 5 处明确标注"演示数据"**(`inspection/app.js:894,940,1222`)。

> **两个同属 `geo` 分类的页面,诚实度标准不一致。** 人口页是唯一可能误导终端用户而非审阅者的缺陷 —— 真实数据配上年份错标。
> 另外 `pGender`(`app.js:19-24`)的性别比是 89.31 / **79.23** / 98.21 —— 79.23 的性别比在任何真实普查中都不存在,而它被直接喂进图表编码器(`app.js:192` `male = 100 + (d.value - 90) * 2.2`),画出 76:220 的男女比例条。

### 🟠 P1 — 人口页:台湾/香港/澳门在选区时被永久变暗

`pRegionMembers` 只覆盖 **31/34** 个省级单位 —— 台湾省、香港特别行政区、澳门特别行政区**不在任何一个区域列表里**。而 `updateHighlight()`(`globe.js:522-529`)会把所有不在列表内的省份 `dimmed` 设为 1(亮度 ×0.45)。

**结果:用户每选一次区域,这三个地区就永久变暗,且没有任何解释。**

### 🟠 P1 — 巡检页:同一个数字 `'56,797'` 当三个不同指标用

`inspection/app.js:876, 882, 887` —— "累计巡检里程"、"累计车辆出勤"、"累计上报事件" 三张卡片的数值**全部是 `'56,797'`**。典型的复制粘贴残留。

### 🟠 P1 — 园区页的图层切换是空操作

`park/model.js:120-126` 的 `setLayer(v)` 只切换 `energy` 和 `security`,**`buildings` 从未被隐藏**。所以 `park/app.js:125` 映射的"空间运营"主题(layer = `buildings`)在 3D 场景里**什么都不会变**,与"全部"完全一致。

`docs/astra-cases.md:18` 声称"主题切换同步核心指标与场景图层"。现有 Playwright 测试(`gallery.spec.mjs:136-137`)只断言 `data-focus` 属性,**所以这个 bug 不会被测出来**。

> 🔺 **独立复核修正**:「`setLayer` 是空操作」这个说法**不准确**。实测 `setLayer` **确实会**切换 `energy.visible` 与 `security.visible`(两个图层互斥显隐),因此「智慧能源」「安防态势」两个主题**有真实 3D 变化**。
>
> 真实缺陷应表述为:**「空间运营」这一层没有差异化视觉** —— `buildings` 分支只把 `o.material.opacity = 1` 重写一遍(恒为原值),所以从「园区总览」切到「空间运营」,3D 画面基本不变。**问题在于图层语义不完整,而非函数无功能。**

### 🟠 P1 — 工业页设备矩阵图例与矩阵内容矛盾

`industry/app.js:58` 的图例写"运行 156 / 待机 10 / 维护 02"(合计 168),但 `H.matrix(64)`(`observatory.js:113-123`)只渲染 **64** 个格子(60 正常 / 3 idle / 1 warn)。64 个格子无法表示 168 台设备。其 `aria-label`(`:115`)倒是诚实的。

### 🟡 P2 — 三个主题的 `--dim` 全部不满足 WCAG AA

| Token | agriculture | industry | park |
|---|---|---|---|
| `--text` | 15.47 | 14.93 | 16.56 ✅ |
| `--muted` | 7.67 | 6.98 | 8.06 ✅ |
| `--accent` | 11.38 | 9.58 | 8.89 ✅ |
| **`--dim`** | **3.38** | **3.08** | **3.36** ❌ |

`--dim` 被用在 **8–10px 的真实文本**上:面板编号(`observatory.css:717-720`,8px)、坐标(`:1027`)、任务描述(`:1332-1333`,9px)、页脚(`:1485`)、对话框注释(`:1587-1588`,10px)。

WCAG AA 对小字要求 **4.5:1**,三个主题全部不达标(2.75–3.38:1)。**这是一行 CSS 就能修的问题。**

### 🟡 P2 — 其他确认问题

| 问题 | 位置 |
|---|---|
| `pEsc` 转义函数**定义了从未使用**,同时 ~10 处 `innerHTML` 未转义 | `population/app.js:3-7` vs `252-257,313-318,327-332,619-620,646-652,690-704` |
| KPI 数字只取前 3 字符,`refreshCount ≥ 262` 时显示 `100` 而非 `1002` | `inspection/app.js:1214` |
| 风电选 G1030/G1031 弹窗仍显示 G1029 的遥测数据 | `wind/app.js:23-164` + `:170` |
| 风电"标注"是纯 CSS 百分比定位的静态覆盖层,`data-part` 无任何处理 | `wind/styles.css:719-749` |
| 风电线框模式在启动时**预先分配 ~345 个 EdgesGeometry + ~345 个 LineBasicMaterial**(`wireGroup.visible=false` 时也不建) | `wind/model.js:613-628` |
| 人口页每次 `pointermove` 都对 107 个网格做无 BVH 射线检测,无节流 | `globe.js:556-560` |
| 巡检页 32 层堆叠轮廓 × `ringPulse` 无限动画 → SVG 每隔一帧全量重栅格化 | `map-depth.js:90-99` + `styles.css:111-115` |
| 巡检页完全没有 JS 层的 `prefers-reduced-motion` 判断(其余 4 屏都有) | `grep matchMedia src/screens/inspection/` → 0 |
| 人口页地球 canvas `outline:none` 但 `tabIndex=0` → 键盘可达却**零焦点可见性** | `population/styles.css:95` |
| 人口页 `role="img"` + `tabindex="0"` 冲突,`role="img"` 会屏蔽画布的交互语义 | `population/template.html:88-92` |
| reduced-motion 用户下,人口页"暂停光效"按钮的 `aria-pressed` **仍报 false**(实际已暂停) | `population/template.html:104` vs `app.js:738-739` |
| `selectProvince(realFeatures.find(...))` 无空值守卫 → 地理要素一改名就抛未捕获 TypeError | `inspection/app.js:778,782,1170` |
| `const screen = $('#screen')` 遮蔽全局 `window.screen` | `inspection/app.js:11` |
| 死代码:`model.home/target/labels`(3 个模型都有)、`AstraGeometry.label()`、`api.simulate()`、`pick()` 的 `mesh` 参数(全 3 处传 null)、`config.insight.sampleLabels`、`.ob-table`/`.ob-progress` CSS | 各处 |
| 静默 `catch {}` 无日志 | `observatory.js:749` |
| `H.bars` 的 color 未转义直接拼进 `style` 属性 | `observatory.js:73` |

### 🟡 P2 — Three.js 版本已废弃

```bash
$ grep -o 'REVISION...' assets/vendor/three.min.js
REVISION = "160"
文件首行:console.warn('Scripts "build/three.js" and "build/three.min.js" are deprecated
            with r150+, and will be removed with r160...')
```

用的是 **Three.js r160 的 UMD 全局构建** —— 这是 three.js 官方标记的最后一批 UMD 产物,**r161 起已被彻底移除**。且该文件**每次页面加载都会在控制台打一条 deprecation warning**。

迁移到 ES Module 是必要动作(`import * as THREE from 'three'`),但需注意这会改变构建产物结构(从内联脚本改为模块加载),与当前"离线单文件"策略有冲突 —— **建议保持离线版用 UMD、在线版用 ESM,或直接锁定 r160 并接受警告**。

---

## 八、值得称道的地方(不能只挑毛病)

1. **"381 实例 / 20 批次"这个数字经得起独立复核** —— 按确定性循环反推分桶结果完全吻合。性能文档写的是**可复现的测量**,不是营销话术;CI 还用 `data-draw-calls < 300` 守住回归。
2. **`docs/performance.md` 主动限定了结论边界**:"These are renderer counters, not a claim about every device's frame rate",并明确写"no cross-device FPS improvement has been asserted"。**在性能文案里保持诚实,这是稀缺品质。**
3. **SVG fallback 是真工程**:WebGL 挂掉时用 d3 重建地球并安装空 API 桩,且有专门的 Playwright 用例注入 `getContext` 返回 null 来验证。
4. **无障碍在多处是真做了**:roving-tabindex 页签、图表 `<rect tabindex="0" role="img" aria-label>` 键盘可达、原生 `<dialog>` 焦点陷阱、焦点还原、`prefers-reduced-motion` 在 JS + CSS 双层生效。
5. **素材合规做到工业级**:SHA-256 固定、逐条许可证据、`retired-assets.json` 防复活、离线版也内嵌许可声明(`buildlib.py:212-229`)。
6. **`new-screen` 生成器 + 注册表驱动**:加新场景真的零改动 Home,这是绝大多数同类项目做不到的。
7. **构建测试专门覆盖了真实踩过的坑**(`null; /*__CHINA__*/` 分号漂移),说明这些测试是从实际事故里长出来的,不是补出来的。
8. **`README.md` 与 `CONTRIBUTING.md` 写得像成熟开源项目**,包括"用相同设备、视口、模式做性能比较,不用单个 FPS 数字宣称跨设备收益"这样的具体约束。

---

## 九、代码来源判断

综合三个方向的独立走查,结论是 **以人工编写为主,局部有 AI 辅助痕迹**,且**存在可识别的上游来源**。

**支持"人工主导"的证据:**

- `model.home` / `model.target` / `model.labels` 三个模型里**同名但无人读取**的死字段 —— 这是从上游 Vue 项目(`big-screen-astra`,`docs/licensing/astra-owner-permission.txt` 记录了精确 commit SHA `d20e80789dee708faff031df840d03d2af8efd72`)移植过来后残留的"上游契约形状"。**LLM 从零写不会在三个文件里一致地造出这三个同名字段。**
- `pick(id, mesh, ...)` 的 `mesh` 参数三处全传 `null`;三个 builder 都解构了没用到的 `state` —— 同样是上游 `reactive()` state 的残留。
- **注释是"论据型"而非"复述型"**:`agriculture/model.js:123` "Reservoir: genuine time-dependent fragment shader, not a backdrop image";`map-depth.js:88-89` 解释为什么不用逐省挤出;`observatory-header.js:22-26` 解释为什么要清洗 header URL。**这是在回应审阅意见的笔记,不是 LLM 套话。**
- **单位体系推理是 idiosyncratic 的**:`ShapeUtils.area(contour) > 0.15`(平方度)与 `d3.polygonArea(poly[0]) < 0.14`(球面度)—— **两个不同库的两种面积制,各用各的**,这需要真正理解两个库才会做对。
- 精确的反墨卡托换算(`inspection/app.js:562-578`)推导出的落位是 1919.9×1181.9 px,与源栅格 1920×1182 **完全吻合**。

**支持"存在 AI 辅助"的证据:**

- `observatory.js:142-280` 是**一条约 140 行的 `+` 字符串拼接语句**构建整个 DOM —— 全仓可读性最差的一处,符合 LLM 输出特征。
- `pEsc` 写了不用、10 处 `innerHTML` 不转义 —— 典型的"模型写了 helper 然后忘了用"。
- `openSummary` 的 `'56,797'` 三用 —— "模板填了一次就再没差异化"的生成式模式。
- `pComposition` 表:城镇人口 8517 < 农村人口 9517,汉族 6217 < 少数民族 2517 —— 同类形状错误。
- 两个 geo 页面之间的复制漂移:模态框焦点陷阱、tooltip、CSV 导出、舞台适配函数,各自重写一遍并改了变量名(`pScale` vs `scale`、`pTip` vs `showTip`、`tip-line` vs `tip-row`)。

> ⚠️ **注意**:仓库自身的 git 历史只有 1 个压平的 `init` commit(作者名还是 "Your Name"),因此**无法从提交历史验证来源**。上述推断基于代码内部证据。

> 🔺 **独立复核修正（2026-10-24）**:上面这句「无法从提交历史验证来源」**不准确**。实测:
>
> - `agentthink/three-screen-lab` 的 HEAD **tree hash = `2b3c674a9671717630da50358f9550c7ad3d2fa1`**,与 `yinweinidongle/screen-picture-demo` 的 **master tree hash 完全相同**,`git diff --stat` 零差异 → 确证是压平重上传
> - `package.json` 的 `repository` 仍写 `github:yinweinidongle/screen-picture-demo`;README 的 CI 徽章与在线 Demo 链接**全部指向上游**
> - 上游 `yinweinidongle/screen-picture-demo` 有 **18 个 commit** 的完整历史;场景来源 `yinweinidongle/big-screen-astra` 有 **21 个 commit**,授权记录里的 `d20e8078` 经 GitHub API 验证存在(2026-09-14)
>
> **来源是可完整核验的三层血缘**,不是只能靠代码内部推断:
>
> ```
> big-screen-astra (Vue 3, 21 commits)
>   └─ src/demos/scenes/{agriculture,industry,park,shared}.js @ d20e8078
>      └─ screen-picture-demo (master, 18 commits)
>         └─ agentthink/three-screen-lab (main, 1 个压平 init)
> ```
>
> 「人工主导、局部 AI 辅助」的判断**仍然成立** —— 死字段 `model.home/target/labels`、`pick()` 的 `mesh` 参数全传 null、builder 解构未用的 `state`,这些是上游 Vue 项目移植后残留的契约形状,LLM 从零写不会在三个文件里一致地造出这三个同名字段。但支撑它的证据**从「代码内部推断」升级为「可核验的移植链 + 代码内部形态」双重支撑**。

---

## 十、建议的修复优先级

| 优先级 | 问题 | 预计工作量 |
|---|---|---|
| **P0** ✅ | CI/Pages 的 `master` → `main` 分支不匹配 — **已修(commit `80cc692`)** | 5 分钟 |
| **P0** | factory 接入 `VizLabRuntime.onDispose(twin.dispose)` | 15 分钟 |
| **P0** | population 补 `dispose()`:取消 rAF、`renderer.dispose()`、摘监听、清定时器 | 1 小时 |
| **P0** | population 的 `screens.json` 尺寸改为 2160×1200 | 2 分钟 |
| **P0** | 人口页省份卡片加"演示数据"标注,或把数据年份改回 2020 | 30 分钟 |
| **P1** | 风电换流器管路/线束补 `parent` 参数 | 10 分钟 |
| **P1** | 园区 `setLayer` 补 `buildings` 可见性,并加 Playwright 断言 | 30 分钟 |
| **P1** | 巡检页 `'56,797'` 拆成三个真实数值 | 15 分钟 |
| **P1** | 工业页矩阵图例与 64 格矩阵对齐 | 15 分钟 |
| **P1** | 人口 `pRegionMembers` 补齐台湾/香港/澳门或加"其他"区 | 20 分钟 |
| **P1** | 三个主题 `--dim` 提到 ≥4.5:1 | 15 分钟 |
| **P1** | 面板高度留 6–8px 余量,测试断言放宽到 ±6px | 30 分钟 |
| **P1** ✅ | Playwright `timeout` 提到 90–120s,或 afterEach 改视口截图 — **已修(commit `0dcae39`;CI 实测该用例为 flaky,已加超时 + 截图按需 fullPage)** | 5 分钟 |
| **P2** | 风电删除玻璃 shader 的死 `uTime` 与每帧空写 | 10 分钟 |
| **P2** | 人口页接线 `pEsc` 或删除它 | 30 分钟 |
| **P2** | 补 `docs/adding-a-screen.md` 的 Observatory 路径,`new-screen.mjs` 支持生成 observatory 模板 | 1 小时 |
| **P2** | 清理死代码(`model.home/target/labels`、`api.simulate`、`pick` 的 `mesh` 参数等) | 1 小时 |
| **P2** | 人口页画布加 `:focus-visible` 轮廓;`role="img"` 改 `role="application"` | 20 分钟 |
| **P3** | Three.js r160 UMD → ESM(需重新权衡离线单文件策略) | 半天 |

---

## 十一、怎么跑起来

```bash
# private fork 需先授权(一次即可):
gh auth setup-git && gh repo clone ishadowland/three-screen-lab && cd three-screen-lab
# 或直接用公开上游:git clone https://github.com/agentthink/three-screen-lab.git

npm ci
npm run setup          # 建 .venv,装 pillow + black
npm run dev            # http://127.0.0.1:5173/home.html
```

其他命令:

```bash
npm run build          # dist/ 网站 + dist/standalone/ 离线单文件 + 源码 ZIP
npm start              # 只预览已生成的 dist/
npm run check          # JS 语法 + 注册表校验
npm test               # 17 个单元/契约测试
npm run format:check   # 格式校验
npx playwright install chromium
npm run test:browser   # Chromium 交互测试(注意 macOS 上有 4 个字体度量相关的失败)
npm run new:screen -- solar   # 生成新大屏骨架
```

**入口**:Home 在 `dist/home.html`(= `index.html`),各屏 `wind.html` / `factory.html` / `population.html` / `inspection.html` / `agriculture.html` / `industry.html` / `park.html`。

---

## 附录 A:开源完整性审计

> 审计目标:**开源部分是否完整?是否存在隐藏的闭源依赖?**
> 方法:Git 对象层审计 + 运行时网络捕获 + 素材管线**实跑重建** + 哈希逐字节比对 + 密钥扫描 + 许可链核对

### A.1 结论

**没有隐藏的闭源依赖。** 代码 100% 完整,素材 100% 自带,且**其中 92% 可从公开上游逐字节重建**。运行时**零网络请求**,无遥测、无 CDN、无后端、无密钥。

唯一的"非完全开源"角落是 **5 张装饰性 PNG**(约 6.2 MB)—— 它们不是标准开源许可授权,而是"项目生成物 / 所有者授权"许可。**但它们全部包含在仓库里**,构建不依赖任何外部获取,且都是可替换的装饰图。

### A.2 逐层核验结果

**① 代码层:完整**

| 核验项 | 结果 |
|---|---|
| Git LFS | ❌ 未使用(`git lfs` 不可用、无 `.gitattributes`)→ **所有二进制是仓库内真实 blob** |
| Git submodule | ❌ 无 `.gitmodules` → **无隐藏的外部仓库依赖** |
| 编译产物/预编译二进制 | ❌ 无 → **所有 JS 都是可读源码**(仅 three.min.js / d3.min.js 是上游官方发行版) |
| 密钥扫描(全仓) | ❌ **0 命中**。grep `api_key|secret|token|password|Bearer|aws_|sk-|ghp_|AIza|xoxb|BEGIN RSA|credential` 全部为误报(CSS `mask-image`、CI 的 `id-token: write`、中文文案含 "task") |
| 运行时网络调用 | ❌ **0 处**。`grep fetch(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|import(` over `src/` → **零命中** |

**② 运行时网络捕获(实跑,Playwright 监听全部 request)**

| 页面 | 外部请求数 |
|---|---|
| home / wind / factory / population / inspection / agriculture / industry / park | **全部 0** |

项目代码里出现的外部主机**总共只有 5 个**,且全部不是运行时依赖:

> 🔺 **独立复核修正**:这个计数取决于口径。原文按「全仓」口径统计得 5;按 **runtime 代码(src/ + scripts/ + config/)** 口径实测是 **6 个** —— 多了 `github.com`(`src/home/template.html:30` 的上游导航链接)。`src/` 目录内出现的外部主机只有 `github.com` 与 `www.w3.org` 两个。**无论哪个口径,结论不变:全部不是运行时依赖。**

| 主机 | 出现次数 | 性质 |
|---|---|---|
| `naciscdn.org` | 6 | `config/asset-sources.json` 里的 Natural Earth **下载 URL**(仅手动跑 `prepare_assets.py` 时使用) |
| `www.naturalearthdata.com` | 12 | 同上文件的**许可证据 URL**(纯文本,不请求) |
| `json-schema.org` | 1 | schema `$id`(纯文本) |
| `www.w3.org` | 2 | SVG 命名空间(不是网络请求) |
| `127.0.0.1` | 2 | 本地开发服务器 |
| `github.com` | 1 | Home 页面指向上游的导航链接(runtime 口径新增) |

**结论:整站运行时零出站请求。** 唯一会联网的动作是标准工具链:`npm ci`(npmjs)、`pip install`(pypi)、`npx playwright install`(playwright CDN)。

**③ 素材层:实跑重建验证(最关键的一项)**

实际执行了完整的素材重建管线:

```bash
.venv/bin/python -m pip install -r requirements-assets.txt   # numpy/shapely/pyshp
.venv/bin/python scripts/prepare_assets.py                     # 下载 69MB 上游归档
```

输出:

```
Rebuilt 34 selectable regions, dissolved outline and world background
Rebuilt day, illustrative city light, normal and Mercator relief textures
```

**逐字节比对结果(重建产物 vs 仓库已提交文件):**

| 素材 | 结果 |
|---|---|
| `assets/geo/china.json` | ✅ **完全一致** |
| `assets/geo/china-outline.json` | ✅ **完全一致** |
| `assets/geo/countries.json` | ✅ **完全一致** |
| `assets/geo/relief-metadata.json` | ✅ **完全一致** |
| `assets/textures/earth-day.jpg` | ✅ **完全一致** |
| `assets/textures/earth-night.png` | ✅ **完全一致** |
| `assets/textures/earth-normal.jpg` | ✅ **完全一致** |
| `assets/textures/relief.png` | ✅ **完全一致** |
| `assets/textures/factory-grid.png` | ✅ **完全一致** |

`git status` 在重建后**完全干净**(连 `assets/manifest.json` 里被脚本自动更新的哈希都分毫不差)—— 这是可复现性的**最强证据**:仓库里的产物就是文档所述管线跑出来的结果,不存在任何"只有作者手里有"的输入。

**上游来源全部可公开下载 + SHA-256 固定:**

| ID | 版本 | 大小 | 许可 |
|---|---|---|---|
| admin1 | 5.1.1 | 14.9 MB | Public domain |
| countries | 5.1.1 | 800 KB | Public domain |
| land | 4.1.0 | 457 KB | Public domain |
| places | 5.1.2 | 652 KB | Public domain |
| relief | 2.0.0(归档自称) | 11.4 MB | Public domain |
| day | NE1_50M_SR | 40.9 MB | Public domain |

全部来自 `naciscdn.org`(Natural Earth / NACIS),**公共领域**,允许商用、修改、再分发。`acquire()` 在打开归档前先校验 SHA-256,上游变更会硬失败。

**④ 18.6 MB 的 GLB —— 不是"外来模型",是本项目的导出产物**

`assets/models/factory-campus.glb` 常被误认为是采购/下载的外部模型。实为**项目自己代码的导出物**(`model.js:1283` 的 `exportGLB(root)`)。

在浏览器里调用 `window.factoryDashboard.factoryTwin.exportGLB()` 实际导出并比对:

```
regenerated GLB bytes : 18,521,652
committed  GLB bytes : 18,589,916
BYTE-IDENTICAL       : false
GLB magic ok         : true        ← 合法 GLB
```

**能重新生成,体积差 0.36%**(二进制导出器在不同 three.js 版本/浮点打包顺序下本就会微差)。这证明:**没有任何隐藏的外部 CAD / 模型市场资源。**

**⑤ 素材可复现性总表**

| 素材 | 可复现? | 许可 |
|---|---|---|
| `assets/geo/*` (4) | ✅ **逐字节一致** | Public domain (Natural Earth) |
| `assets/textures/earth-*`, `relief.png` (4) | ✅ **逐字节一致** | Public domain (Natural Earth) |
| `assets/textures/factory-grid.png` | ✅ **逐字节一致**(纯数学生成) | MIT(原创程序纹理) |
| `assets/models/factory-campus.glb` (18.6MB) | ✅ 可导出,差 0.36% | MIT(原创程序几何) |
| `assets/vendor/three.min.js` | ✅ Three.js r160 官方发行版 | MIT |
| `assets/vendor/d3.min.js` | ✅ D3 7.9.0 官方发行版 | ISC |
| `assets/previews/*.webp` (7) | ✅ 重新截图即可 | Composite(随组成素材) |
| `docs/media/*.gif` / `*.png` (7) | ✅ 重新录屏即可 | Composite |
| **`assets/art/factory-fallback.png`** | ❌ **不可重建** | "Generated asset; separate from code MIT" |
| **`assets/art/population-header.png`** | ❌ **不可重建** | 同上 |
| **`assets/art/astra/*-header.png`** (3) | ❌ **不可重建** | "Owner-authorized generated asset; separate from code MIT" |

**不可重建的只有 5 张装饰性 PNG(约 6.2 MB,占素材总量 ~19%)。**

**⑥ 许可链上唯一的"非标准 OSS"角落**

`docs/licensing/astra-owner-permission.txt` 是一份**双边授权书**而非标准开源许可,要点:

- 上游 `big-screen-astra` 与本仓库**同属一个所有者**(`yinweinidongle`)→ 所有者把自己的代码在此仓库以 MIT 授权,**法律上成立**。
- 但文件明确写着:*"This record does not assert an upstream repository-wide public license"* —— 即 **big-screen-astra 仓库本身不一定有公开许可**,只有本次改编范围被授权。
- 3 张 astra header PNG:*"Owner-authorized reuse and redistribution; separate from the code-only MIT grant. No exclusivity or independent third-party-clearance guarantee is asserted."*
- 2 张 ImageGen 图:*"separate from code MIT"*,明确排除在地理素材审计与 MIT 授权之外。

> **实务影响**:如果你 fork 并**替换**这 5 张装饰图 → 完全无碍(MIT 代码 + 公共领域素材 + 自备图片)。如果你 fork 并**原样再分发** → 代码仍是 MIT,但这 5 张 PNG 走的是"项目生成物 / 所有者授权"条款,**不是** MIT / CC0 / CC-BY 这类标准开源许可。文件已诚实标注这一点,但形式上它们属于"作者保留权利"素材。
> `LICENSE`(MIT)只覆盖"原创代码和程序化几何",**不覆盖**这些 PNG —— 这点在 `THIRD_PARTY_NOTICES.md` 表格里写得很清楚。

**⑦ 追踪性的两个小缺口**

| 缺口 | 说明 |
|---|---|
| `docs/media/*.gif` 和 `docs/media/home-*.png` **不在 `assets/manifest.json` 里** | 它们由**另一个** `docs/media/capture-manifest.json` 追踪(含各自的 sha256),但该文件**没有**像 `assets/manifest.json` 那样被 `verify_assets.py` / `tests/test_assets.py` 校验。所以**录屏 GIF 的哈希无人守护** —— 谁改了都不会被测出来。 |
| `assets/art/*`(5 张不可重建 PNG)在 `assets/manifest.json` 里**有**条目,但 `prepare_assets.py:378-381` 只更新 `assets/geo/` 和 `assets/textures/` 前缀的哈希 | 这 5 张的哈希**只能人工维护**,`docs/assets.md:26` 也承认要手工算。这不构成漏洞,但意味着替换它们时必须手动同步清单。 |

**⑧ 源码 ZIP 的边界是干净的**

`scripts/archive.py` 只打包 `src/ config/ scripts/ tests/ docs/ assets/ .github/` + 一组白名单根文件,**显式排除** `.venv/`、`node_modules/`、`dist/`、`.local/`、录屏原始帧、`__pycache__`。且使用**固定时间戳** `(2026,1,1,0,0,0)` → **ZIP 输出可复现**。docstring 直言:*"Export only the documented source tree, never local recordings or credentials."*

### A.3 最终判定

| 问题 | 判定 |
|---|---|
| 开源代码完整吗? | ✅ **完整**。无 submodule、无 LFS、无预编译二进制、无缺失源文件、无密钥。 |
| 有隐藏的闭源依赖吗? | ✅ **没有**。运行时零网络请求;无 CDN、无遥测、无后端、无付费 API、无外部模型。 |
| 能离线完整复现吗? | ✅ **能**。`npm ci && npm run setup && npm run build` 即可产出全部 8 个页面;`dist/standalone/` 可脱网运行(已验证零外链)。 |
| 能重建全部素材吗? | ⚠️ **92% 能逐字节重建**(Natural Earth 公共领域 + 原创程序纹理);18.6MB GLB 可从代码导出;**仅 5 张装饰性 PNG 无法重建**。 |
| 有许可风险吗? | ⚠️ **代码零风险(MIT)**,地理素材零风险(公共领域)。**唯一注意点**:5 张装饰 PNG 走"生成物/所有者授权"而非标准 OSS 许可,原样再分发时需留意。 |
| 最大的"隐藏"风险是什么? | 不是闭源依赖,而是 **CI 的 `master` 分支不匹配** —— 部署从未在 `main` 上跑通,以及 **3 张 astra 派生素材的授权是单次授权书**,上游仓库若变更授权状态,本仓库需跟进。 |

**一句话**:这是一个**自洽、可审计、可离线复现**的开源项目。它没有用任何闭源/远程依赖来偷工减料;全部素材要么来自公共领域上游(有校验和的下载管线),要么由代码程序化生成。唯一"不可重建"的是 5 张 AI 生成的装饰性头图 —— 而它们既已在仓库内、又是纯装饰、可随意替换。

---

## 十二、可迁移到我们自己的地方

| 借鉴点 | 具体做法 |
|---|---|
| **注册表驱动 + 通用卡片模板** | 新增场景零改动 Home —— 这比"每个 demo 各写一页"的可维护性高一个量级 |
| **内容哈希 + immutable 缓存头** | 资源名带 sha256 前 16 位,静态资源长缓存 / HTML 不缓存,是最省事的缓存正确性方案 |
| **构建期标记注入 + 残留即失败** | `/*__XXX__*/` 字符串替换简单但有效,关键是"替换后检查残留"这个断言 |
| **素材白名单 + 逐条许可证据** | `verify_assets.py` 的 `CLEARED` 白名单 + `licenseEvidence` 必须 https,是可以直接抄的合规基线 |
| **性能回归用计数器断言而非 FPS** | `data-draw-calls < 300` 在 CI 里跑,比"跑个 benchmark 看数字"稳健得多 |
| **WebGL 失败要有真 fallback** | 注入 `getContext` 返回 null 的测试用例,比"没测过 fallback"强太多 |
| **registry 里只存一份真相** | 尺寸/分类/renderer 全在 `screens.json`,不要在代码里再写一遍 |
| **审计结论要能复核** | 见附录 B:本文每个关键数字都有可复现命令,不是"读代码猜的" |

## 参考

- **本文对象(private fork,需权限)**:<https://github.com/ishadowland/three-screen-lab>
  - 本地 clone:`gh repo clone ishadowland/three-screen-lab` 或 `git clone https://github.com/ishadowland/three-screen-lab.git`(需 `gh auth setup-git`)
- **上游出处(公开,审计对象)**:<https://github.com/agentthink/three-screen-lab>
- 上游 README 指向的真正来源:<https://github.com/yinweinidongle/screen-picture-demo>
- 在线演示(上游 public Pages):<https://yinweinidongle.github.io/screen-picture-demo/home.html>
- 素材上游:Natural Earth(<https://www.naturalearthdata.com/>),公共领域

> ⚠️ **关于 private fork 的引用**:iswiki 是 public 仓库,`ishadowland/three-screen-lab` 对外部读者是 404。文中所有**技术内容**(文件路径、行号、commit SHA、度量值)对读者仍有价值 —— 想核对的人可以 clone 上游 `agentthink/three-screen-lab` 或 `yinweinidongle/screen-picture-demo` 对照同一 commit `f413a2f`。

---

## 附录 B:独立复核(2026-10-24,Hermes)

> 环境:`macOS 13.6 x64 · Node v24.13.0 · Python 3.11.15 / 3.12`
> 审计副本:`~/.hermes/work/three-screen-lab`(完整 clone,独立跑完全部流程)
> **结论:原审计绝大多数结论成立且可复现,但 4 处过宽或错误,另有 2 处新发现。**

### B.1 二次实跑结果

| 命令 | 原审计 | 二次实跑 | 一致? |
|---|---|---|---|
| `npm run check` | Registry: 7 screens | 同 | ✅ |
| `npm test` | 17/17 通过 | 14 Python + 3 Node,**OK** | ✅ |
| `npm run build` | 10.2s,7 屏 + Home | 成功,`dist/build-manifest.json` 生成 | ✅ |
| `npm run test:browser` | 6 passed / 4 failed | **7 passed / 3 failed** | ⚠️ inspection 转绿 |
| 8 页运行时外部请求 | 全 0 | **全 0**(Playwright 逐页监听) | ✅ |
| 素材重建后 `git status` | 完全干净 | **跟踪文件零变更** | ✅ |
| 风电计数器 | 381 实例 / 20 批 | **draw calls 131 · geometries 92 · triangles 114,356 · 20 批 · 381 实例** | ✅ 完全吻合 |
| GLB 重导出 | 18,521,652 vs 18,589,916(差 0.36%) | **18,521,652 vs 18,589,916(差 0.37%)**,magic = `glTF` | ✅ |
| `assets/manifest.json` 24 条 | — | **24/24 SHA-256 匹配,0 mismatch** | ✅ |

### B.2 修正一:面板溢出的真因是布局零余量,不是字体

原审计归因「macOS 走 PingFang SC,Linux CI 走 Noto Sans CJK,中文字形行高差几个像素」。**实测该假设不成立。**

在 1920×1080 视口下对 `agriculture.html` 强制替换字体栈,逐次测量溢出:

| 强制字体 | 溢出面板 | 溢出量 |
|---|---|---|
| `'PingFang SC'` | 作物生长监测 / 土壤生命力 | **5px / 4px** |
| `'Noto Sans CJK SC', 'Source Han Sans SC', sans-serif` | 作物生长监测 / 土壤生命力 | **5px / 4px** |
| `'Helvetica Neue', Arial, sans-serif` | 作物生长监测 | **5px** |
| `'Times New Roman', serif` | 作物生长监测 | **5px** |

字体只改变**溢出多少**,不改变**是否溢出**。逐面板测量真实需求:

| 场景 | 面板 | clientHeight | 内容盒 | 内容+margin 需要 | 溢出 |
|---|---|---|---|---|---|
| agriculture | 作物生长监测 | 233 | 193 | **237** | 5px |
| agriculture | 土壤生命力 | 233 | 193 | **247** | 4px |
| industry | 全流程质量控制 | 233 | 193 | **249** | 5px |
| park | 企业创新生态 | 233 | 193 | **247** | 3px |

侧栏 `grid-template-rows: 234.656px / 234.672px / 234.672px`,`.ob-panel` 的 `padding: 17px 18px` 让内容盒只剩 193px。

**结论:测试写得对,产品写得脆 —— 是产品侧没留余量,不是测试环境问题。**「失败全是环境差异」这个结论不成立。

> 与 private fork 的 Linux CI 结果对照:CI 上 `test:browser` 全绿,说明字体度量确实影响**溢出幅度**;但布局零余量决定了**会不会溢出**。字体是触发条件,零余量是根本原因 —— 两者不能互相替代。

### B.3 修正二:来源可以完整核验

原审计写「仓库自身的 git 历史只有 1 个压平的 init commit,因此**无法从提交历史验证来源**」。实测:

```bash
$ git rev-parse HEAD^{tree}
2b3c674a9671717630da50358f9550c7ad3d2fa1        # agentthink/three-screen-lab
$ gh api repos/yinweinidongle/screen-picture-demo/git/trees/master --jq .sha
2b3c674a9671717630da50358f9550c7ad3d2fa1        # 完全相同
$ git diff --stat HEAD FETCH_HEAD                  # 零差异
```

- 上游 `yinweinidongle/screen-picture-demo`:默认分支 `master`,**18 个 commit** 完整历史
- 场景来源 `yinweinidongle/big-screen-astra`:**21 个 commit**;授权记录里的 `d20e80789dee708faff031df840d03d2af8efd72` 经 GitHub API 验证存在(2026-09-14,commit message = "Add four Vue 3 and Three.js dashboards with generated assets and refined city panels")
- `agentthink` 的 commit:`f413a2f` / "Your Name <you@example.com>" / 2026-10-24 14:41:36 +0800

**三层血缘可核验**:big-screen-astra → screen-picture-demo → agentthink 压平重上传。「人工主导 + 局部 AI 辅助」的判断不变,但证据基础从「代码内部推断」升级为「可核验移植链 + 代码内部形态」双重支撑。

### B.4 修正三:CI 分支问题只影响 agentthink 公开快照

| 仓库 | 默认分支 | workflow 监听 | 实际结果 |
|---|---|---|---|
| `agentthink/three-screen-lab` | `main` | `master` | push 不触发;`gh api .../pages` → **404** |
| `yinweinidongle/screen-picture-demo` | `master` | `master` | **匹配**;Pages 状态 `built`,31 次 CI run 全 success |

原审计「这个项目在 GitHub 上的部署从来没通过」过宽 —— 上游同名项目部署一直正常。

> 补充:作者 private fork 修好 `master`→`main` 后又遇到**第二层阻塞** —— private repo + GitHub Free 不支持 Pages(`POST /pages` → 422),已用 `vars.pages_enabled` 开关绕开。这是公开快照上不存在的问题,**不要把两者的 Pages 状态混为一谈**。

### B.5 修正四:园区 setLayer 不是空操作

`park/model.js:120-126` 确实会切换 `energy.visible` 与 `security.visible`(互斥显隐),所以「智慧能源」「安防态势」两个主题**有真实 3D 变化**。

真实缺陷是**「空间运营」层没有差异化视觉**:`buildings` 分支只把 `o.material.opacity = 1` 重写一遍(恒为原值),从「园区总览」切到「空间运营」画面基本不变。**图层语义不完整 ≠ 函数无功能。**

### B.6 修正五(次要):外部主机计数取决于口径

原审计「总共只有 5 个」按全仓口径。按 runtime 代码(`src/` + `scripts/` + `config/`)口径实测是 **6 个** —— 多出 `github.com`(`src/home/template.html:30` 的上游导航链接)。`src/` 目录内只有 `github.com` 与 `www.w3.org` 两个外部主机。**两种口径下结论都不变:全部不是运行时依赖。**

### B.7 新发现一:`npm run setup` 在 Python 3.10 上直接失败

`scripts/tasks.mjs:14` 声称要求 Python ≥3.10,但 `requirements.txt` 锁死 `platformdirs==4.13.5`,该版本要求 **Python ≥3.11**:

```
ERROR: Ignored the following versions that require a different python version:
       4.13.5 Requires-Python >=3.11
ERROR: No matching distribution found for platformdirs==4.13.5
```

用 Python 3.11 建 venv 才装得上。`requirements-assets.txt` 要求更高:Python **≥3.12**(`numpy==2.5.4`)+ `shapely` + `pyshp`,且 **Pillow 不在该文件里**,需另行补装 `pillow==12.2.0`。

### B.8 新发现二:Playwright 官方 chromium 不支持 macOS 13

```
$ npx playwright install chromium
Error: ERROR: Playwright does not support chromium on mac13
```

本地跑浏览器测试需改用系统 Chrome(`channel: 'chrome'`)+ `--use-gl=angle --use-angle=swiftshader --enable-webgl --ignore-gpu-blocklist`。二次实跑即用此法,得到 7 passed / 3 failed。

### B.9 复核确认成立的关键结论

以下原审计结论经独立复核**全部成立**:

- 生命周期矩阵(农业/工业/园区 ✅ 全清;风电 ✅ 但 `setInterval`+toast timeout 未清;工厂 `dispose()` 从不被调用;人口 rAF 永不取消 + `setInterval` 未清;巡检 `setInterval` 未清)
- 人口页配置漂移(注册表 1920×1080 vs 代码 `Math.min(innerWidth/2160, innerHeight/1200)`)
- 人口页真实七普数据(粤 12601 / 鲁 10152 / 豫 9937)配 2022 标签,且**省份卡片零「演示数据」标注**(全页 grep 命中 0;巡检页则有 6 处)
- 性别比 79.23(`app.js:23`)在任何真实普查中不存在
- 台湾/香港/澳门不在 `pRegionMembers` 任何分组
- `pEsc` 定义未使用 + **7 处** `innerHTML` 未转义(原审计写「~10 处」,实测 7 处)
- 巡检 `'56,797'` 三用;KPI 前 3 字符 `refreshCount ≥ 262` 时显示 `100`
- 工业图例 156/10/02 vs `H.matrix(64)` 只渲染 64 格
- 风电换流器管路/线束漏传 `parent`(`model.js:333-358`);玻璃 shader 声明 `uTime` 但片元未用
- `--dim` 对比度实测 3.08–3.38:1,全不达 WCAG AA
- 巡检页 32 层堆叠轮廓(`map-depth.js`)、轮廓 5,517 顶点只定义一次
- 人口 SVG fallback(`globe.js:712-769`)+ Playwright 注入 `getContext` 返回 null 的降级用例
- 素材 24/24 SHA-256 匹配;5 张装饰 PNG 占 assets 总量 **18.6%**(6.23 MB / 33.57 MB)
- `docs/media/capture-manifest.json` 确实**未被** `verify_assets.py` / `test_assets.py` 校验 → 录屏哈希无人守护
- `prepare_assets.py:378-381` 只自动重算 `assets/geo/` 与 `assets/textures/` 前缀 → 5 张 PNG 哈希需人工维护
- 无 LFS / 无 submodule / 无 `.gitattributes` / 密钥扫描零真实命中

### B.10 未能独立复现的一项

原审计的 GLB 重导出数字**已复现**(见 B.1),但「重导出与仓库版本差 0.36%」的**归因**未能证实:差异应来自 three.js 版本的浮点打包顺序,本次未做版本对照实验。**不影响结论**(能重新生成这一点成立)。

---

*本文为 iswiki 改写收录,原始审计由另一 agent(MiniMax)完成,包含完整克隆 / 构建 / 浏览器实测 / 素材重建管线。2026-10-24 由 Hermes 独立复核一遍,4 处结论修正见正文 `🔺` 标记与附录 B。本文的修复与后续维护在作者 private fork `ishadowland/three-screen-lab` 上进行。*
