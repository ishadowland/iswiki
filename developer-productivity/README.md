# ⚡ 开发者生产力

> 开发者日常工具 / 提效库 / 数字过渡 / 体验优化 / 个人项目

---

## 索引

| 文档 | 描述 |
|------|------|
| [programWangPrivateProjects](programWangPrivateProjects.md)
| [ReArk](ReArk.md) — HarmonyOS + Android 桌面逆向与 AI 辅助分析工作台
| [remote-obd-deep-analysis](remote-obd-deep-analysis.md)
| [remote-obd-usb-over-ip](remote-obd-usb-over-ip.md)
| [sdrangel](sdrangel.md) — 开源软件无线电「全家桶」工作台 (NOAA / AIS / FT8 / LoRa 87+ 插件)
| [press-fit-guard](press-fit-guard.md) — 新能源三电压装上位机,全行程位移-压力包络线判定 + Modbus 从站仿真(⚠️ 仓库空,仅领域/工程模式可读)
| [hermes-feishu-gateway-bug](hermes-feishu-gateway-bug.md) | Hermes feishu gateway 入站消息缺 `message_id` 时静默丢弃整条消息(仅 DEBUG 日志,生产无告警)。含已装 fallback patch 的一手复核、6 处初稿偏差、**第二层 bug:`grep -c` 撞 `set -e` 让 cron 监控静默失效 12 天**。 |
| [mygo](mygo.md) | `github.com/egoist/mygo` —— **用 Go 写跨平台桌面应用的框架**(39 天 ⭐4,445 / 259 forks / 1,045+ commits / 30+ releases,仍未到 1.0)。**三条同时成立的差异化**:① **零 cgo**(`purego`+`syscall`,三平台可任意机器交叉编译)② **同一份 `ui` 代码能跑在浏览器**(`GOOS=js GOARCH=wasm`+WebGL 2,`mygo dev -web` 直接在浏览器预览原生 UI —— Tauri/Wails 都没有)③ **Go→TS 类型化绑定自动生成**(省掉 OpenAPI/protobuf/tRPC)。**~7 MB 二进制 / 35 MB 内存 / idle 0.005% CPU per core**。**官方 21 个 showcase 应用**(本文收录 4 张真实截图):邮件客户端带 Claude Sonnet 5.5 AI 总结、**真 zsh 终端 + lazygit 风格 Git TUI + Snake**(terminal plugin 用 purego 调 libghostty-vt,证明不是玩具 demo)、音乐/追番应用 6+ 页面渐变主题。**32 个 official examples** 覆盖终端/IDE 级 editor/富文本/游戏/shader 可视化/桌面 UX 全家桶;**9 个 plugin** 含 `glass`(Liquid Glass 跨平台)、`terminal`、`game`、`sqlite`。⚠️ 边界:**39 天 + v0.7.4 + 89 open issues,生产押注风险高**;原生 UI 工作量接近 SwiftUI 但无组件市场;零 cgo 的代价是**每个平台特性都要手写 syscall + 版本分支**,long tail 上是三倍工作量;**移动端明确不在范围**(Tauri 有);强依赖 Bun(仅开发期);`docs/architecture.md` 298 KB 上手门槛高。 |

---

**共 8 个文档**。