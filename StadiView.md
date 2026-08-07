# StadiView — 3D 足球场座位预览

> 学习笔记 · 调研时间 2026-08-08
> 仓库: https://github.com/thebuggeddev/football-stadium · 在线预览: https://football-stadium-ruddy.vercel.app
> License: **PolyForm Noncommercial 1.0.0** + 独立 Commercial License · 技术: Three.js r128 + GSAP 3.12.5 + Vite 8.1.1 · ⭐ 373

## 一句话定位
**纯过程化生成的 3D 足球场座位预览 demo** — 看台、座椅、球员、灯光、计分板全部代码生成（无任何导入 3D 模型），用 Three.js + GSAP 让用户能"飞进"任一座位看比赛视角。

## 核心特性
- **完全程序化 3D** — 不导入任何 .glb / .fbx，所有几何体代码生成
- **上千座独立可选** — Instanced rendering 高效渲染
- **动画相机飞行** — 点击座椅 → GSAP 平滑飞入第一人称视角
- **完整模拟** — 球员、足球、人群、灯光、计分板、场边显示屏都动起来
- **可访问性** — orbit 控制、键盘支持、reduced-motion 兼容
- **单文件部署** — index.html 149KB（Vite build 后），Three.js + GSAP 走 cdnjs

## 技术栈

| 层 | 技术 |
|---|---|
| 3D 渲染 | Three.js r128 (CDN: cdnjs) |
| 动画 | GSAP 3.12.5 (CDN: cdnjs) |
| 构建 | Vite 8.1.1 |
| 语言 | Vanilla JS / HTML / CSS |

## 仓库结构

```
football-stadium/
├── index.html              # 149 KB（Vite production build）
├── src/
│   ├── main.js             # 2.5 KB — 入口
│   ├── style.css           # 5 KB — 样式
│   ├── counter.js          # 247 B — 计数器
│   └── assets/
│       ├── hero.png        # 13 KB
│       ├── javascript.svg  # 863 B
│       └── vite.svg        # 8.7 KB
├── package.json
├── LICENSE.md              # 4.6 KB — PolyForm Noncommercial
├── COMMERCIAL-LICENSE.md   # 1.2 KB — 商业许可
├── THIRD_PARTY_NOTICES.md  # 811 B — Three.js + GSAP 第三方声明
└── README.md
```

## 交互控制

| 操作 | 控制 |
|---|---|
| 旋转球场 | 点击 / 触摸拖拽 |
| 缩放 | 鼠标滚轮 / 屏幕控制 |
| 预览座位 | 点击座椅 |
| 座位内环顾 | 在座位视角下拖拽 |
| 退出座位 | `Esc` / "Back to stadium" |
| 确认选择 | `Enter` / "Grab seat" |

## 模拟功能（不是真售票）
README 明确：**StadiView 是概念 demo**，比赛、票价、座位可用性、checkout 等都是**模拟数据**，**不卖真票**。

模拟的字段：
- 座位预览图（按区域生成）
- 票价
- 可用性
- 票档（tier）
- 区块（block）
- 福利（benefits）

## License 关键点 ⚠️

### PolyForm Noncommercial 1.0.0（社区版）
- ✅ 可学习、分享、非商业场景改编
- ✅ 需保留版权 + 许可证声明
- ❌ **不可用于商业产品**
- ⚠️ **不是 OSI 认证的开源**——是 "source available"

### 商业许可（需单独签）
要用于以下场景必须签商业合同：
- 集成进付费产品 / 服务
- 为俱乐部、场馆、活动、Agency、客户改编
- 白标部署
- 自定义球场几何 / 座位图开发
- 票务、可用性、定价、分析、预订集成
- 商业托管、支持和持续开发

联系方式：`thebuggeddev@gmail.com`（主题加 "StadiView commercial licensing"）

### 第三方
- Three.js r128 — MIT
- GSAP 3.12.5 — GreenSock Standard No-Charge License
- 运行时从 cdnjs 加载，**不**重新许可

## 本地运行
```bash
npm install
npm run dev      # vite dev
npm run build    # vite build（输出到 dist/）
npm run preview  # 预览 build 产物
```

## 技术亮点解析

### 1. 完全过程化的球场几何
- 看台、看台座椅分块、屋顶、广告牌、计分板都是代码生成
- 没有外部资源依赖，单仓可独立构建
- 类似 Babylon.js / Three.js 教程里的 "procedural city"，但聚焦单一建筑

### 2. Instanced Rendering 处理上千座
- 用 `THREE.InstancedMesh` 处理所有座椅
- 每个 instance 有独立位置 / 可选状态 / 颜色
- 即使上千座也只 1 个 draw call

### 3. GSAP 相机动画
- 点击座椅 → GSAP timeline 平滑飞入
- 退出 → 反向 timeline 回到 orbit 视角
- 可被打断（Esc 中断动画）

### 4. 模拟数据驱动
- 用确定性算法生成座位价格 / 区域 / 福利
- 没有后端，纯前端
- 适合做 demo / 概念验证 / 客户端原型

## 跟我们的关系

### 可借鉴
- **InstancedMesh 用法**：上千个同形状元素的标准模式（粒子、树、人群、车流都适用）
- **过程化生成**：3D 模型太重 / 难维护时，参数化生成是替代方案
- **GSAP timeline**：Web 3D 动画的标准选择，比纯手写 requestAnimationFrame 简洁
- **座位预览**：可改造成会议系统座位预定 / 培训教室座位 / 大巴选座

### 可改造方向
- **产品发布演示场**：把"足球场"换成"产品功能矩阵"或"架构图"
- **数据可视化**：3D 散点 / 热力图套用同套渲染管线
- **客户演示场景**：售前 Demo、概念验证场景

### 风险
- ⚠️ **License 不是真开源**：PolyForm Noncommercial + 商业 license 双重
- ⚠️ **依赖 CDN**：运行时从 cdnjs 拉 Three.js + GSAP，离线 / 内网场景需要本地化
- ⚠️ **Three.js r128 是旧版**（2021 年）：如果 fork 做新项目建议升级到 r150+

## 实战建议

### 如果要 Fork / 学习
1. `git clone` + `npm install` 直接跑
2. 重点看 `src/main.js`（2.5KB 是入口，但实际逻辑在 `index.html` 的 `<script>` 块里——Vite 把代码打包进去了）
3. 用浏览器 DevTools 调 InstancedMesh 的 `count` / `setMatrixAt` 理解大批量渲染
4. 试改座位颜色 / 数量 / 布局参数看实时效果

### 如果要做商业项目
**先签商业 license**，不要拿 PolyForm Noncommercial 直接商用。

### 如果要参考做自己的项目
- 把球场景改成会议室 / 教室 / 大巴 / 演唱会
- 把座位数据接真实接口（票务 / 预订）
- 升级 Three.js + GSAP 到最新稳定版
- 加 AR / VR 支持（Three.js 有 WebXR adapter）

## 参考链接
- 仓库: https://github.com/thebuggeddev/football-stadium
- 在线预览: https://football-stadium-ruddy.vercel.app
- 作者 GitHub: https://github.com/thebuggeddev
- 作者 X: https://x.com/thebuggeddev
- 商业许可联系: thebuggeddev@gmail.com
- PolyForm Noncommercial: https://polyformproject.org/licenses/noncommercial/1.0.0
- Three.js r128: https://github.com/mrdoob/three.js/blob/r128/LICENSE
- GSAP 3.12.5: https://gsap.com/standard-license/