# AgoraFlat — 声网开源在线互动教室（Web/Desktop/Android 全端）

> 学习笔记 · 调研时间 2026-09-03
> 主仓: https://github.com/netless-io/flat · 后端: https://github.com/netless-io/flat-server · Android: https://github.com/netless-io/flat-android · 官网: https://flat.agora.io/
> 在线体验: https://web.flat.shengwang.cn/login （海外）/ https://flat.apprtc.cn/ （国内 CN 版入口）
> License: **MIT** · 主仓语言: TypeScript · ⭐ 6.43k · 最近 push 2026-09-03 · 最近 release v2.3.6 (2025-01-20)

## 一句话定位

声网（Agora）开源的**全端在线互动教室**：monorepo 内含 Web / Electron Desktop / Android 三端 + Node.js 后端，集成 RTC 音视频、RTM 消息、互动白板、周期性房间与课堂录制一体，自带 CN / SG 双地域构建。

## 仓库矩阵（先把项目拓扑理清）

| 仓库 | ⭐ | 主语言 | 角色 | 最近活动 |
|---|---|---|---|---|
| [netless-io/flat](https://github.com/netless-io/flat) | 6,431 | TypeScript | **主仓 / monorepo**：Web + Electron Desktop + 共享包（flat-components / flat-stores / flat-i18n / flat-services / flat-server-api / flat-types / flat-vite-plugins）| 2026-09-03 |
| [netless-io/flat-server](https://github.com/netless-io/flat-server) | 684 | TypeScript | 后端服务（Node.js + Fastify 4 + TypeORM + MySQL + Redis）| 2026-07-08 |
| [netless-io/flat-android](https://github.com/netless-io/flat-android) | 125 | Kotlin | Android 客户端 | 2025-12-18 |

> **纠正**：微信文/某些转述里说「flat-server 正在用 Golang 重写」——**没有远端证据**。flat-server 仍是 Node.js + Fastify，仓库 `languages` 里 TypeScript 占绝对主导（Go Template 只有 1306 字节，是 Dockerfile 模板里的）。如有 Go 重写分支也是在组织其它 repo 里，未在 flat-server 主仓看到。**别按「Go 重写」做技术选型**。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **官方 SaaS（试用）** | https://web.flat.shengwang.cn/login （海外）/ https://flat.apprtc.cn/ （国内）| 5 分钟看效果，看功能覆盖；要先注册声网账号 |
| **自托管客户端** | `pnpm i && pnpm start`（跑 Electron）/ `pnpm start:web`（跑 Web）| **没有服务端也能跑客户端**——仓库 README 明说"You can build and run the Flat client without a server"，意味着前端有 mock / 演示模式 |
| **自托管全套** | 部署 flat-server + 配 Agora / Netless（白板）账号，跑客户端连自家后端 | 真正的私有化；最重但可控 |

## 核心组件 / 模块 / 架构

### 主仓 monorepo 拓扑（pnpm workspaces）

```
netless-io/flat/
├─ web/                 ← React + Mobx Web 客户端（flat-web 子包）
├─ desktop/             ← Electron 桌面壳（Windows / macOS / Linux）
├─ packages/
│   ├─ flat-components  ← 通用 UI 组件（Storybook 驱动开发）
│   ├─ flat-stores      ← Mobx store 层
│   ├─ flat-services    ← 业务服务层（API 适配）
│   ├─ flat-i18n        ← 国际化（中英双语）
│   ├─ flat-server-api  ← 服务端 API 类型 + 客户端 SDK
│   ├─ flat-pages       ← 页面级组件
│   ├─ flat-types       ← 全局类型定义
│   └─ flat-vite-plugins ← 自定义 Vite 插件
├─ service-providers/   ← 第三方服务适配（Agora / Netless / 微信登录 等）
├─ scripts/             ← 构建脚本（launch/、deployment/）
└─ config/              ← 共享构建配置
```

### 关键模块映射表

| 模块 | 实现位置 | 说明 |
|---|---|---|
| **RTC（音视频）** | `@netless/flatter` / Agora RTC SDK（service-providers 适配）| 走声网自家 Agora SDK，无需自建 SFU |
| **RTM（即时消息）** | 同上（Agora RTM SDK）| 群聊信令走 RTM，云端录制可回放 |
| **互动白板** | `@netless/whiteboard` SDK（Netless 是声网子品牌，专注白板）| 多人同步、PPT/图片/动画课件、白板信令云端录制 |
| **房间 / 周期性房间** | flat-server + flat-web | 普通房间 + 周期性房间（每周一同一时间这种）|
| **云录制** | flat-server 调声网云录制 API | 白板信令 + 音视频 + 群聊消息三路合一 |
| **登录** | service-providers（GitHub OAuth + 微信扫码）| OAuth 回调走后端 |
| **课件云盘** | flat-server（oss/aliyun 上传，scripts/deployment/upload-ali-oss.js）| 与 CN/SG 地域绑定 |
| **屏幕共享** | Web 端 Electron `desktopCapturer` / Web 端 `getDisplayMedia` | |

### CN / SG 双地域构建

```
pnpm start:cn   → FLAT_REGION=CN → 国内登录 + 国内云盘 + 屏蔽 aiTeacher
pnpm start:sg   → FLAT_REGION=SG → 海外登录 + 海外云盘
pnpm ship:cn:all / pnpm ship:sg:all → 桌面端按地域打包
pnpm pub:cn / pnpm pub:sg           → 静态资源按地域上传到阿里云 OSS
```

地域差异体现在：登录方式（CN 走微信，SG 走 GitHub）、AI 教师功能开关、第三方服务接入端点。要做 fork 私有部署，**先确认你的目标地域对应的环境变量**（`docs/env/README-zh.md`）。

## 安装与最小可运行

```bash
# 1. 前置：pnpm
npm i -g pnpm

# 2. clone monorepo + 装依赖
git clone https://github.com/netless-io/flat
cd flat
pnpm i

# 3a 跑桌面端（Electron）
pnpm start                  # 默认 CN
pnpm start:sg               # 海外

# 3b 跑 Web 端
pnpm start:web

# 4 打包桌面端
pnpm ship:mac   # macOS
pnpm ship:win   # Windows
```

> **踩坑提示**：装 Electron 慢是常态。建 `.npmrc`：
> ```
> ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/"
> ```
> 再 `pnpm i`。

Storybook 跑组件层（设计系统开发用）：
```bash
pnpm storybook   # 起 flat-components 的 storybook
```

## 版本节奏 / Release 历史

| 时间 | 版本 | 备注 |
|---|---|---|
| 2020-08-26 | 仓创建 | — |
| 2022-11-16 | v2.0.0 | 重大重构（v1 → v2） |
| 2023-09-05 | v2.3.0 | — |
| 2024-09-20 | v2.3.5 | — |
| **2025-01-20** | **v2.3.6（最新 release）** | 之后 8 个月**无新 release**，但 commit 一直在打（最近 2026-09-03）|
| 2026-09-03 | — | 最近 push（feat(login): 400006 UserBlacklisted 识别）|

**信号**：release 节奏放缓但代码在维护——典型的"功能稳定、版本号不再追新"状态。私有化部署直接吃 v2.3.6 即可，不用追 tag。

## 实战建议 / 风险点

| 风险 | 说明 |
|---|---|
| **依赖 Agora / Netless 商业服务** | RTC、RTM、白板三件套**全部走声网/Netless SDK**。自托管时**必须申请 Agora AppID + Netless AppID**，否则跑不通核心功能。这不是纯开源替代品，是「开源壳子 + 商业音视频底座」 |
| **后端必须配 MySQL + Redis** | flat-server 启动时 TypeORM 连 MySQL、ioredis 连 Redis，README 没 docker-compose 新部署指引 |
| **React 17 / Vite 3 / TypeScript 4.8 / Webpack 5** | 主仓依赖**落后当前主流 1-2 代**。直接 fork 想升级到 React 18+ / Vite 5+ 要做迁移，flat-components / flat-stores 这两层牵一发动全身 |
| **CN/SG 双地域强绑定** | `FLAT_REGION` 在构建期就写死，**运行时切换地域不支持**。要做 fork 私有部署，先确认用户群落 |
| **fastify 4 老版本** | fastify 已经出到 5.x，flat-server 用 4.1，TypeORM 0.3 也相对旧 |
| **微信登录需要国内备案** | CN 版微信扫码登录需「微信开放平台」审核通过的个人/企业开发者，自托管时是必须做的合规项 |
| **录制 = 走声网云端 = 按用量计费** | 课堂录制功能依赖 Agora 云录制 API，私有部署后**这部分成本依然走声网账单** |
| **国内访问 GitHub 困难** | flat / flat-server / flat-android 三个仓主分支都在 GitHub，国内 fork 后 CI/CD 要自配代理 |
| **包管理锁 pnpm** | `preinstall: npx only-allow pnpm`，不能用 npm / yarn |

## 跟我们的关系（用户工作相关 — 必填段）

| 项目/场景 | 能不能用上 |
|---|---|
| **在线教育 SaaS 二次开发（创业方向）** | ✅ 直接 fork 三仓 + 配 Agora/Netless 账号，最快搭出 MVP；声网做底层省掉了 SFU / 录制的坑 |
| **企业内部培训系统** | ✅ 自托管私有化可行，但要预算好「Agora SDK 调用费 + Netless 白板服务费」两笔；阿里云 OSS 国内 CN 版默认走这个 |
| **互动会议 / 协作工具** | ⚠️ 它**不是会议产品**——核心是「教室」，周期性房间、教室录制回放、PPT 动画课件这些是教学域特征。改造成「会议室」要撕掉很多教育专属逻辑 |
| **白板 SDK 单独用** | ✅ 它的核心白板 `@netless/whiteboard` 是**独立 SDK**，**不必用 Agora Flat 全套就能用**——如果只想白板，去 netless-io/whiteboard 仓库单独看 |
| **国内监管合规 / 微信生态** | ✅ CN 版默认微信登录 + 国内节点 + 国内云盘（阿里云 OSS），国内运营**省掉一堆合规选型** |
| **直播间 / 1vN 大班课** | ✅ 1vN、1v1、小班课都是支持的；周期性房间 = 长期固定课表 |
| **国内中小学校 / 双减后教培** | ⚠️ 教育行业政策敏感，如果客户是 K12 校内用，自托管 + 内容审核是必须的；面向 C 端家长要小心预收款监管 |
| **想学习 RTC / 白板协同怎么落地** | ✅ 翻它的 service-providers/ 目录能看到完整的 Agora / Netless 接入范式，比看官方文档更接地气 |
| **海外市场 SaaS** | ✅ 海外版（FLAT_REGION=SG）走 GitHub OAuth，但**流量分发依然受国际网络环境影响**——CN/SG 都用阿里云 OSS，海外节点体验要测 |

## 依赖矩阵 / 关键版本

| 组件 | 版本（实测） |
|---|---|
| React / React DOM | ^17.0.50 / ^17.0.17（types）|
| React Router | ^5.3.3 |
| TypeScript | ^4.8.3 |
| Vite | ^3.2.7 |
| Webpack | ^5.74.0（Electron 桌面端用）|
| Mobx | 业务栈主状态管理 |
| flat-server Fastify | ^4.1.0 |
| flat-server TypeORM | ^0.3.6 |
| flat-server MySQL driver | mysql2 ^2.2.5 |
| flat-server Redis | ioredis ^4.19.2 |

> 缺 Electron / Agora SDK / Netless SDK 的精确版本号——需要的话进 `pnpm-lock.yaml` 再挖。

## 配套生态 / 相关项目

- **白板独立 SDK**：[@netless/whiteboard](https://github.com/netless-io/whiteboard)——不必用 Flat 全套就能用
- **声网 Agora RTC SDK**：https://docs.agora.io/cn/rtc —— Flat 的音视频全靠它
- **同组织其它项目**：在 https://github.com/netless-io 一堆——flat-rtc（已废弃？）、whiteboard、app、appdemo 等

## 参考链接

- 主仓: https://github.com/netless-io/flat
- 后端: https://github.com/netless-io/flat-server
- Android: https://github.com/netless-io/flat-android
- 官网: https://flat.agora.io/
- 海外体验: https://web.flat.shengwang.cn/login
- 国内体验: https://flat.apprtc.cn/
- 中文文档入口: https://github.com/netless-io/flat/blob/main/docs/readme/README-zh.md
- 环境变量参考: https://github.com/netless-io/flat/blob/main/docs/env/README-zh.md
- Release notes: https://github.com/netless-io/flat/tree/main/docs/releases
- Slack 社区: https://github.com/netless-io/flat/issues/926 （issue 926 里挂了 Slack 入口）