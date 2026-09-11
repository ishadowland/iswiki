# HumanAtlas — 浏览器里把人体拆成 2234 个零件的 3D 解剖浏览器

> 学习笔记 · 调研时间 2026-09-11
> 仓库: https://github.com/ashemag/human-atlas · 在线 demo: https://human-atlas-seven.vercel.app · 文档: README.md
> License: MIT(应用代码) + CC BY 4.0(BodyParts3D 4.0 几何数据,二次发布须保留署名) · 语言: TypeScript 95.9% · ⭐ 3,104 · Fork 752 · 最近提交 2026-09-07

## 一句话定位

基于 BodyParts3D 4.0 + React + Three.js + shadcn/ui 的开源 3D 人体解剖浏览器:2234 个独立可点选 mesh、15 个人体系统、3432 个可搜索 FMA 概念,支持爆炸图拆解 + 系统分层 + 单结构隔离。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| 在线 demo | https://human-atlas-seven.vercel.app | 0 装,直接看 |
| 本地开发 | `npm ci && npm run dev` → `http://localhost:3016` | 二次开发 / 改源码 / 看 devtools |
| 静态部署 | `npm run build` → `dist/` 上传任意静态服务器 / Vercel | 生产部署 / 嵌入其他站 |

无 API key、无账号、无后端 — 全部几何数据预打包进前端 bundle(33 MB 压缩,228.8 万三角形)。

## 核心组件 / 模块 / 架构

```
human-atlas/
├── app/                     # Next.js / vinext app 路由入口
├── components/ui/           # shadcn/ui 组件 (Radix + Tailwind v4)
├── hooks/                   # React hooks(选中、隔离、爆炸图状态)
├── lib/                     # 业务逻辑(几何批处理、搜索索引)
├── public/
│   ├── data/                # BodyParts3D 4.0 转换后的二进制几何 + 概念映射
│   └── ATTRIBUTION.md       # 数据来源 + 许可明细
├── scripts/
│   ├── convert-anatomy.py   # OBJ → 中间格式(可选重建流程)
│   ├── optimize-anatomy.mjs # meshoptimizer 0.2% 误差简化
│   ├── compress-models.mjs  # KTX2 / Draco / 量化打包
│   ├── validate-atlas.mjs   # mesh buffer / 概念成员 / 爆炸布局校验
│   └── validate-interactions.mjs # 选点 / 系统切换 / 搜索 / 隔离 / 多视口交互契约
├── web/                     # 静态站点额外资源
├── vite.config.ts           # Vite 8 + @vitejs/plugin-react
├── vercel.json              # Vercel 部署配置(npm ci + build + dist)
├── tsconfig.json
└── package.json             # "anatomy-studio" v0.1.0
```

### 技术栈与关键依赖

| 层级 | 选型 | 版本 |
|---|---|---|
| 渲染引擎 | Three.js | ^0.159.0 |
| React 框架 | React 19 + vinext | 19.2.6 / 1.0.0-beta.5 |
| UI 组件 | shadcn/ui(@base-ui/react + @shadcn/react) | 1.7.0 / 0.3.0 |
| 样式 | Tailwind CSS v4 | 4.2.1 |
| 构建 | Vite 8 + @vitejs/plugin-rsc | 8.0.13 / 0.5.26 |
| 几何简化 | meshoptimizer | ^1.2.0 |
| Lint / 格式 | oxlint / oxfmt | 1.76.0 / 0.61.0 |
| 类型检查 | tsc | 5.9.3 |
| Node 要求 | >= 22.13 | - |

### 几何管线(How it works)

- **批处理合并** — 2234 个独立 mesh 合并为少量 batch,降低 draw call
- **GPU 纹理属性** — 用 per-structure GPU 纹理(translate / visibility / selection)控制每个 mesh
- **爆炸布局** — 只对当前可见 mesh 做 exploded packing,避免 2000+ 一次性排布
- **按需渲染** — 场景变化才重新渲染,OrbitControls 保持响应
- **WebMCP(可选)** — 在支持浏览器里暴露 anatomy search / inspection 工具调用接口

### 15 个解剖系统(展示用 preset)

骨架(Skeleton)、肌肉(Muscular)、消化(Digestive)、呼吸(Respiratory)、循环(Circulatory)、神经(Nervous)、内分泌(Endocrine)、淋巴(Lymphatic)、泌尿(Urinary)、生殖(Reproductive)、感觉(感官)、皮肤(Integumentary)... — 用户可单独开关或组合。

## 安装与最小使用

### 在线白嫖

```bash
open https://human-atlas-seven.vercel.app
```

### 本地跑

```bash
# 要求 Node.js >= 22.13
git clone https://github.com/ashemag/human-atlas.git
cd human-atlas
npm ci
npm run dev   # → http://localhost:3016
```

### 校验(可选,验证构建 + 几何 + 交互)

```bash
npm run check                          # tsc --noEmit
node scripts/validate-atlas.mjs        # mesh buffer / 概念成员 / 爆炸布局
node scripts/validate-interactions.mjs # 选点 / 搜索 / 隔离 / 多视口交互
npm run build                          # 产 dist/
```

### 部署

```bash
npm run build          # 产出 dist/
# 上传 dist/ 到任意静态服务器 / Vercel / Cloudflare Pages
```

Vercel 直接 import 仓库即可,`vercel.json` 已配好 `npm ci` + `npm run build` + `dist` 输出目录。

### 重建几何(可选)

仓库已自带浏览器可用几何。**只有**你想从原始 OBJ 重建才走:

1. 从 dbarchive.biosciencedbc.jp 下载官方 BodyParts3D OBJ 包 + 英文元数据
2. 准备 joined concepts + display-system 映射
3. `python scripts/convert-anatomy.py`
4. `node scripts/optimize-anatomy.mjs`(meshoptimizer,0.2% 误差)
5. `node scripts/compress-models.mjs`

## 数据来源与许可(关键)

| 资产 | 来源 | License | 备注 |
|---|---|---|---|
| 应用代码 | 本仓 | MIT | 可自由商用 |
| **3D 人体几何** | BodyParts3D 4.0(The Database Center for Life Science) | **CC BY 4.0** | 二次发布必须保留署名 + 链接 |
| FMA 概念层级 | 同上 | CC BY 4.0 | 3432 个可搜索概念 |
| 历史版本曾含的女性参考人体 | Kristen Browne & Heidi Schlehlein, Human Reference Atlas / HuBMAP, *3D Reference Organ Set for Female v1.5* (2023) | CC BY 4.0 | 当前 release 已**移除**(README 历史资产段) |

**BodyParts3D 论文**:Mitsuhashi et al. (2009), *BodyParts3D: 3D structure database for anatomical concepts*, https://doi.org/10.1093/nar/gkn613

**适配说明**:坐标轴 mm/Z-up → m/Y-up;每结构 meshoptimizer 简化(0.2% 误差);法线量化到 signed 16-bit;打包成二进制 chunk。

## 版本节奏

- 首次开源发布:`Publish male-only Human Atlas as open source`(约一周前)
- 主体扩展:`Build Human Atlas with male and female anatomy in a limestone studio`(后被 revert,见历史提交)
- 当前为 **male-only** 版本,female anatomy 已撤回
- 暂无正式 Release / Tag(`0 Tags`)

## 实战建议 / 风险点

| 风险 | 说明 |
|---|---|
| ❌ 不是医疗工具 | README 明确写"This is an educational explorer, not a diagnostic or surgical tool." — 任何医学决策不能依赖 |
| ⚠️ 仅成人男性 | BodyParts3D 4.0 是基于 TARO MRI 的**成人男性参考**,不代表人种/性别/年龄变异 |
| ⚠️ 二次发布必保留署名 | CC BY 4.0 要求 attribution — 仓库 / 网站 / README 都要带 BodyParts3D + DBCLS 链接 |
| ⚠️ 包大小 | 33 MB 压缩几何首屏下载;移动端弱网体验差,建议加 loading 进度条 |
| ⚠️ 仅在桌面浏览器充分测试 | 物理设备性能 + 真多点触硬件未测;手机端只验过 390×844 / 320×568 / 844×390 三种视口 |
| ⚠️ 互动复杂度 | 2234 个 mesh 同时显示会卡;实战靠系统过滤 + 隔离单结构 |
| ✅ Node 22.13+ | 老 Node 用户升级;macOS 自带 Node 通常不够 |
| ✅ 零 API key | 全部前端打包,无后端依赖 |

## 跟我们的关系

适用场景画像:

1. **生物课 / 解剖学辅助** — 双胞胎心儿/丞儿 25 月龄还早了点,但 5-6 岁后可作家庭科普辅助(公众号文原话推荐"给家里孩子当生物课的补充")
2. **医学生自学 / 教学演示** — 3D 旋转 + 爆炸图 比课本平面图直观得多,前面 artemis-redradman 是航天领域的同类思路
3. **二次开发参考** — 看如何把 N 个 mesh(本仓 2234)+ 大量元数据(3432 概念)在前端做选点 / 隔离 / 搜索 / 爆炸布局:
   - meshoptimizer 简化策略
   - per-structure GPU 纹理属性(替代上万个独立 draw call)
   - WebMCP 暴露给 AI agent(跟 pascalEditor / vgpu 思路同源)
4. **嵌入其他站** — 静态产物直接 iframe 嵌入;33 MB 体积可改用 CDN + lazy load
5. **FMA 概念搜索** — 3432 个解剖学术语索引可复用做"医学术语 ↔ 视觉"映射

跟现有 iswiki 仓对比:
- 同类视觉化:artemis-redradman(航天)、kage(京都)、stadiView(足球场)、shinjukuIndoorThreejsDemo(新宿站)
- 跨类复用:pascalEditor 的 WebMCP、threeui 的 Three.js 组件目录、nova3d 的过程化几何
- 不可作:不做医疗 / 临床;不想引入 CC BY 4.0 署名义务的二次发布就别用其几何

## 参考链接

- GitHub 仓库:https://github.com/ashemag/human-atlas
- 在线 demo:https://human-atlas-seven.vercel.app
- BodyParts3D 项目:https://dbarchive.biosciencedbc.jp/en/bodyparts3d/download.html
- BodyParts3D License:https://dbarchive.biosciencedbc.jp/en/bodyparts3d/lic.html
- 原始论文(DOI):https://doi.org/10.1093/nar/gkn613
- CC BY 4.0:https://creativecommons.org/licenses/by/4.0/
- 历史女性数据集(DOI):https://doi.org/10.48539/HBM352.BTSQ.586
- 调研参考文章:https://mp.weixin.qq.com/s/6eEgiYRhTOOGjQp6rvvx3A(开源日记,2026-09-09)
