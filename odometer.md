# HubSpot Odometer — 平滑数字过渡 JS/CSS 库

> 学习笔记 · 调研时间 2026-08-12
> 仓库: <https://github.com/HubSpot/odometer>
> 文档: <https://github.hubspot.com/odometer/docs/welcome/>
> License: MIT · ⭐ 7.3k · 696 forks · 269 commits · 13 contributors
> Author: Adam Schwartz, Zack Bloom (HubSpot) · Languages: CSS 70.6% / CoffeeScript 25.6%
> **⚠️ Repository archived 2019-04-02 (read-only)** · Latest: v0.4.7 (12 年前)

## 一句话定位

**Smoothly transitions numbers with ease** —— 一个轻量级 JS + CSS 数字动画库(全套 < 3kb minified+gzipped),把 `<div class="odometer">123</div>` 改成 456 时,数字会**像翻牌倒计时一样滚动**,全程**纯 CSS transform** 渲染(性能极致),用 jQuery / 直接 `.innerHTML` 更新 value 时**自动过渡**。

## 核心设计

```
Odometer (主类)
├── el          ← DOM 元素 (required)
├── value       ← 起始数字
├── format      ← 数字格式化 '(,ddd).dd'
├── duration    ← CSS transition 时长 (默认 2000ms)
├── theme       ← 主题 (car / minimal / digital / plaza / train-station)
├── animation   ← 'count' (简单递加) 或 'slide' (默认翻牌)
└── update(newValue)  ← 触发新动画
```

**特点**:
- **JS 只负责规划 frames,CSS 负责渲染** → transform + transition
- **`requestAnimationFrame` 替代 setInterval** → 30fps
- **`MutationObserver`** 自动检测 element 内容变化触发动画
- **TRANSITION_SUPPORT 检测** + fallback 老浏览器
- **零依赖** (README: "Dependencies: None!")

## 5 步上手

```html
<!-- 1. 引 theme CSS -->
<link rel="stylesheet" href="odometer-theme-car.css" />
<!-- 2. 引 JS -->
<script src="odometer.js"></script>

<!-- 3. 加 class -->
<div class="odometer">123</div>

<!-- 4. 改值 → 自动过渡 -->
<div class="odometer" id="counter">0</div>
<script>
  document.getElementById('counter').innerHTML = 999;
  // 自动 slide 到 999
</script>
```

## 2 个使用模式

### Mode 1: 声明式 (auto-init, 给 class)

任何 `.odometer` 元素在 DOM ready 时**自动 init**,改 `.innerHTML` / `.innerText` 自动动画。

### Mode 2: 命令式 (manual new Odometer())

```js
var el = document.querySelector('.some-element');
od = new Odometer({
  el: el,
  value: 333555,
  format: '',         // 数字格式
  theme: 'digital'    // 主题
});
od.update(555);
// 或:el.innerHTML = 555;
```

## 全局配置

```js
window.odometerOptions = {
  auto: false,           // 不自动 init (默认 true)
  selector: '.my-numbers', // 自定义 selector
  format: '(,ddd).dd',   // 默认格式
  duration: 3000,        // CSS 动画时长
  theme: 'car',          // 主题
  animation: 'count'     // 'count' (递加) 或 'slide' (翻牌)
};
```

## Format 格式系统

| Format | Example |
|---|---|
| `(,ddd)` | `12,345,678` |
| `(,ddd).dd` | `12,345,678.09` |
| `(,ddd).dddd` | `12,345,678.0900` |
| `(.ddd),dd` | `12.345.678,09` |
| `( ddd),dd` | `12 345 678,09` |
| `d` | `12345678` |

`d` 数量 = 小数位;`(` `)` 内 `,` = 千分位分隔。

## 6 个内置主题

| Theme | 风格 |
|---|---|
| **car** | 经典翻牌 (default) |
| **minimal** | 极简 |
| **digital** | 数字电子 |
| **plaza** | LED-like 复古 |
| **train-station** | 老式翻牌 |
| **slot-machine** | 老虎机 |

每个主题 = 1 个 CSS 文件 (`themes/odometer-theme-{name}.css`)。**Resizable**: 改 `.odometer` 的 `font-size` 即可放大缩小。

## 性能特点

- **< 3kb minified + gzipped** (主 JS + 默认主题)
- **CSS transform only** → GPU 加速,主线程 0 计算
- **Auto fallback** → 老浏览器用 setInterval 简单动画
- **30fps framerate** (FRAMERATE = 30)
- **MAX_VALUES per digit** 自动 boost → 跨多 digit 滚动不卡

## DOM 结构

```html
<div class="odometer">
  <span class="odometer-digit"><!-- 千分位 -->
    <span class="odometer-digit-spacer">8</span>
    <span class="odometer-digit-inner">
      <span class="odometer-ribbon">
        <span class="odometer-ribbon-inner">
          <span class="odometer-value">1</span>
          <span class="odometer-value">2</span>
          <span class="odometer-value">3</span>
        </span>
      </span>
    </span>
  </span>
  <!-- repeat per digit -->
</div>
```

**关键 DOM 元素**:
- `.odometer-digit` 一个 digit 容器
- `.odometer-ribbon` 翻转面板 (CSS transform: translateY)
- `.odometer-value` 每个过渡 frame 的数字 (slide 用)
- `.odometer-formatting-mark` 千分位逗号等

## 算法:animateSlide

```coffee
animateSlide(newValue):
  oldValue = this.value
  diff = newValue - oldValue
  for each digit (digitCount):
    start = truncate(oldValue / 10^(digitCount-i-1))
    end = truncate(newValue / 10^(digitCount-i-1))
    if abs(dist) > MAX_VALUES:
      # Boost: 跨多 digit 时用 frames 子集
      incr = dist / (MAX_VALUES + MAX_VALUES*boosted*DIGIT_SPEEDBOOST)
    else:
      # 逐 1 走 frames
      frames = [start..end]
    frames[i] = frames[i] mod 10
    digits.push(frames)
  # reverse + appendChild 每个 frame, transition CSS 自动触发
```

## 浏览器支持

- **IE8+**
- **Firefox 4+**
- **Safari 6+**
- **Chrome**
- **Auto fallback** → 老浏览器切到 setInterval 简单模式

## 适用场景

| ✅ 适合 | ❌ 不适合 |
|---|---|
| 数字 metric 仪表盘 | 复杂动画 (> 1s 整体) |
| 计数器 / GitHub stars 实时数 | 数据可视化图表 (用 chart lib) |
| KPI dashboard | 进度条 / 加载条 |
| Live viewers / sales counter | 货币快速变动 (翻滚太快难读) |
| 滚动数字抽奖 | 时间倒计时 (用 `react-countdown` 等) |
| 实时价格 ticker | 数字编辑输入 |

## 类似工具对比

| 工具 | 厂商 | 形式 | 体积 | 主题 |
|---|---|---|---|---|
| **Odometer** | HubSpot | JS + CSS | < 3kb | 6 个 |
| **countUp.js** | inorganik | JS | ~10kb | 6 个 |
| **react-countup** | glennflanagan | React | npm | 1 (依赖 CSS) |
| **jQuery Counter** | various | jQuery | ~5kb | 0-1 |

## 历史 / 状态

- **2013-2014**: Adam Schwartz + Zack Bloom 创建
- **2019-04-02**: Repository archived (read-only)
- **Latest version**: v0.4.7 (12 年前)
- **v0.4.8** package.json 标识但 npm 没发布(commit `0bc5470` "Bump version" 10 年前)
- **Issue/PR**: 78 open issues, 16 PRs (积压)
- **Stars 仍在涨** 7.3k → 实际可能更多 (archive 后不再显示)
- **Hacktoberfest 标签** 一些 fork 还在维护

**为什么 archive**: HubSpot 战略调整,前端 focus 转向 React/HubSpot CMS,Odometer 不再维护。但功能稳定可用 → fork 仍在用。

## 风险与限制

- **Archived** — 不再接受 PR,不修 bug
- **No modern build** — 没有 ES module / no npm publish
- **依赖 jQuery 1.10** (demo) — 现代项目不推荐
- **CoffeeScript source** — 需 build (`grunt watch`) → 流程老旧
- **IE8 support** — Modern 项目不再需要,代码含 IE workaround
- **jQuery dep 残留在 AMD** (commit: "Remove jquery from dependencies in AMD")
- **CSS-only anim** — 高频更新 (> 60/sec) 可能丢帧
- **README/Issues 12+ 年未更新** — 新 issue 不会 merge

## 现代 fork / 替代

| Fork | Stars | 状态 |
|---|---|---|
| [leizongmin/odometer](https://github.com/leizongmin/odometer) | - | 持续维护 |
| 各种 npm `@xx/odometer` 包 | varies | 多数停止更新 |

## 使用 demo(README 示例)

```html
<script>
odometerOptions = { auto: false };

var exampleOdometerValue = 123456;
var el = document.querySelector('.odometer-example');
var exampleOdometer = new Odometer({ el: el, theme: 'car', value: exampleOdometerValue });
exampleOdometer.render();

setInterval(function(){
  exampleOdometer.update(exampleOdometerValue++);
}, 3000);
</script>

<div class="odometer odometer-theme-car odometer-example">123</div>
```

→ **每 3 秒滚动一次数字**

## 跟其他 iswiki 工具的关系

| 工具 | 关系 |
|---|---|
| [mapcn](mapcn.md) | 🟡 都是 UI 组件,但 mapcn 现代 + map |
| [StadiView](StadiView.md) | ⚪ 不相关 |
| [codex-security](codex-security.md) | ⚪ 安全 |
| [qoder-security](qoder-security.md) | ⚪ 安全 |
| [i-have-adhd](i-have-adhd.md) | ⚪ 输出风格 |
| [fireside-sprint1](fireside-sprint1.md) | 🟢 可用 Odometer 显示"在线人数" |

## 相关链接

- 仓库: <https://github.com/HubSpot/odometer>
- 文档: <https://github.hubspot.com/odometer/docs/welcome/>
- demo jsFiddle: <https://jsfiddle.net/adamschwartz/rx6BQ/>
- HubSpot 开源: <https://github.com/HubSpot>
- 同期 HubSpot 项目: messenger / facewall / jquery-zoomer / humanize / teeble