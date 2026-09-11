# Leaf — Miniloong Pocket 1 掌机的自定义固件(SD 卡安装)

> 学习笔记 · 调研时间 2026-09-11(基于 v0.11.0 release)
> 官网: <https://leaf.game> · GitHub: <https://github.com/Utility-Muffin-Research-Kitchen/Leaf>
> 硬件: **Miniloong Pocket 1 (MLP1)** — 国产开源掌机,Loongson CPU
> License: MIT · ⭐ 36 · 最新版 v0.11.0(2026-09-05)

## 一句话定位

Leaf 是 **Miniloong Pocket 1 掌机上的「自定义固件」**,通过 SD 卡启动,**叠加在 stock LoongOS 上(不替换)**,提供游戏库 + 多模拟器(RetroArch + 独立 PPSSPP / NDS / N64 / Dreamcast / Saturn / Amiga)+ 系统管理 + Central Scrutinizer Web 管理界面。device 永远可回退 stock。

## 安装指南(基于 v0.11.0)

### 三种安装场景

| 场景 | 操作 |
|---|---|
| **升级现有安装**(推荐) | 在设备上:`Menu > Actions > System Update`。OTA 自动下载并应用 |
| **全新安装** | 把 `leaf-mlp1-sd-v0.11.0.zip` 解压到 FAT32 或 ext4 SD 卡**根目录**,插卡开机。游戏 / 存档 / state / 设置**不会动** |
| **回退 stock LoongOS** | 把 `leaf-mlp1-recovery-v0.11.0.zip` 解压到卡根,开机**一次**即可恢复出厂 stock |

### 升级前注意

- 之前用过 beta 通道的,在升级前把 **Update Channel** 切回 **Stable**,否则下次只会看到 beta 推送
- 升级过程 games / saves / states / settings 都在原位,不会丢
- v0.11.0 已包含 v0.10.0 及之前所有 release 的内容(plus unreleased 0.10.1 beta 的改进)

### v0.11.0 主要变更(2026-09-05 发布)

- **Fun DraStic** — 由 tenlevels 捐赠的 Nintendo DS 替代前端,DraStic 仍是默认;从 DS 游戏的 Core 选项切换
- **游戏内 shader 选择** — In-game menu > Shader,可按 This game / This folder / All RetroArch 三个 scope 应用预设
- **可配置游戏内快捷键** — Settings > Controls & Feedback > In-game Shortcuts 自定义 Game Switcher / Screenshot / Recording 的副键
- **YabaSanshiro 独立 Saturn 模拟器** — 含 BIOS 选择(BIOS 放 `BIOS/SATURN/`,512 KiB),解决部分游戏 HLE 黑屏
- **Amiga 支持** — PUAE 2021 默认 + PUAE 备选,Kickstart 放 `BIOS/puae/`
- **Pak Rat 加系统** — 通过 content pak 加系统/模拟器,首个例子 ScummVM(游戏放 `Roms/SCUMMVM/` + `.scummvm` game-ID 文件)
- **RetroArch 配置持久化** — Quit / 重启 / 关机后设置保留;每个 launch 独立 working config
- **Appearance 改进** — System Icons 可选 Automatic / Flat / Photographic,独立于 home layout
- **中文界面** — Thing-File 加审过的简体中文,共享 CJK 字体显示中日文文件名

### 升完后第一次设置建议

1. **Wi-Fi**:`Menu > Settings > Network` 连一次,之后会自动恢复
2. **时区 / 显示**:`Menu > Settings > Display & Language`
3. **BIOS**:Saturn / Amiga 需要的 BIOS 提前放进 `BIOS/SATURN/`、`BIOS/puae/`
4. **ROM 库**:游戏按系统分目录放进 `Roms/<SYSTEM>/`(例:`Roms/AMIGA/`、`Roms/SCUMMVM/`)
5. **Cover Flow 美术**:扫描 + 拉取由 Central Scrutinizer(Leaf 自带 Web 管理器)做

### 故障兜底

| 现象 | 处理 |
|---|---|
| 升级后无法启动 | 用 recovery ZIP 回退,boot 一次回 stock |
| Beta 通道用户没看到 v0.11.0 | 先在 Update Channel 切回 Stable,再 System Update |
| Saturn 游戏黑屏 | 用 YabaSanshiro 备选 core + 放外部 BIOS 到 `BIOS/SATURN/` |
| RetroAchievements 连不上 | RetroArch 已内置 TLS,检查 Wi-Fi 与时间同步 |

## 硬件 — Miniloong Pocket 1 (MLP1)

| 项 | 规格 |
|---|---|
| **CPU** | Loongson(龙芯)— **aarch64 + LoongArch** 异构 |
| **GPU** | Mali(ARM)|
| **OS** | LoongOS(基于 Linux) |
| **开源** | ✅ 完全开源硬件 + 软件 |
| **掌机形态** | 模拟摇杆 + ABXY + L1/R1/L2/R2 + SELECT/START/MENU/STICK |

== **核心数据**:36 ⭐,0 Fork(早期但已经在生产),MIT,size 695 KB。

## 项目结构 — UMRK workspace

Leaf 不是一个独立项目,它是 **UMRK workspace** 的中央 glue / 编排层,协调 14+ sibling repos:

```
~/dev/UMRK/
├── Leaf/                       # ⭐ 自定义固件 + 部署编排(本文)
├── Catastrophe/                # 模拟器核心 packaging
├── Jawaka/                     # Loong 设备 GUI launcher
├── Thing-File/                 # 文件管理器 app
├── ssh-server/                 # SSH 服务 app
├── CentralScrutinizer/         # Web 管理器 app
├── Fugazi/                     # Shader tuner app
├── PPSSPP-spruce/              # PSP emulator
├── steward-fu-nds/             # NDS emulator(含 Fun DraStic)
├── N64-standalone/             # N64 emulator
├── Flycast-standalone/         # Dreamcast emulator
├── YabaSanshiro-standalone/    # Saturn emulator(v0.11.0 加)
├── retroarch-builds/           # RetroArch binary
├── Cores-spruce/               # RetroArch cores
├── mlp1-toolchain/             # LoongArch 交叉编译工具链
└── miniloong-launcher-switcher/ # Launcher 切换工具
```

**作为终端用户**,你只需要拿到 Leaf 安装 ZIP,**不需要 clone 这些 repo** — 它们是开发方内部的子模块。

## 5 大核心设计哲学(仍然适用)

1. **「叠加,不替换」** — Leaf 不替换 stock LoongOS,而是叠加在它上面。device 永远 recoverable
2. **「Dispatcher 不实现」** — Leaf 只调度 sibling repos 的 build/package/stage,不重新实现 product builds
3. **「每个产品一个独立 repo」** — Jawaka/Catastrophe/RetroArch/cores/apps 都独立,Leaf 只是胶水
4. **「Checksum-bound staging」** — `targeted-build-report.json` 必须经过校验才允许 stage
5. **「Pre-flight gates before stage」** — read-only cache preflight 必须在 stage 前通过

## 版本节奏

| 版本 | 日期 | 主题 |
|---|---|---|
| **v0.11.0** | 2026-09-05 | Fun DraStic / Shaders / Saturn / Amiga |
| v0.10.0 | 2026-08-24 | Simplified Chinese / Multiplayer / New Systems |
| v0.9.0 | 2026-08-07 | Recording / USB-C Audio / 32X Support |
| v0.8.0 | 2026-07-29 | Rumble / Shaders |
| v0.7.0 | 2026-07-24 | 5-Game Mode / Screenshots / Emulator Upgrades |

约 **每 2-3 周**一个稳定 release,active 维护中。

## TL;DR

**Leaf = MLP1 掌机的用户级自定义固件**(不是开发工具),通过 SD 卡安装 / OTA 升级 / recovery 回退,36 ⭐,MIT。

== **用户怎么用**:
1. **升级**:设备上 `Menu > Actions > System Update`(从已装的旧版升到 v0.11.0)
2. **新装**:下载 `leaf-mlp1-sd-v0.11.0.zip`,解压到 FAT32/ext4 SD 卡根目录,插卡开机
3. **回退**:下载 `leaf-mlp1-recovery-v0.11.0.zip`,解压到卡根,开机一次

== **v0.11.0 必玩 3 件事**:
1. 试 **Fun DraStic**(DS 游戏的 Core 选项里切) — tenlevels 捐赠,全新界面
2. In-game menu > **Shader** — 给当前游戏挑 CRT / LCD 滤镜
3. **Pak Rat** 加 ScummVM,玩经典冒险游戏

## 参考链接

- 官网: <https://leaf.game>
- GitHub 仓: <https://github.com/Utility-Muffin-Research-Kitchen/Leaf>
- v0.11.0 release notes: <https://github.com/Utility-Muffin-Research-Kitchen/Leaf/releases/tag/v0.11.0>
- Central Scrutinizer 文档(子项目): <https://github.com/Utility-Muffin-Research-Kitchen/CentralScrutinizer>
