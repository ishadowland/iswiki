# Leaf — UMRK 游戏机的 custom firmware 部署编排器 (35 ⭐)

> 学习笔记 · 调研时间 2026-09-07
> 官网: <https://leaf.game>
> GitHub: <https://github.com/Utility-Muffin-Research-Kitchen/Leaf>
> 硬件: **Miniloong Pocket 1 (MLP1)** — Loongson 架构的国产开源掌机

---

## 0. 一句话定位

**Leaf = Miniloong Pocket 1 掌机的「自定义 firmware」部署编排器**(跟 stock LoongOS 共存,可回退)+ **UMRK workspace 的中央命令面**(负责 clone 14+ sibling repos / bootstrap / preflight / payload 装配 / SD-card 部署)。

==**核心哲学**:**在 stock OS 上叠加,不替换**(device 永远 recoverable)。

## 1. 硬件 — Miniloong Pocket 1 (MLP1)

| 项 | 规格 |
|---|---|
| **CPU** | Loongson(龙芯)— **aarch64 + LoongArch** 异构 |
| **GPU** | Mali(ARM)|
| **OS** | LoongOS(基于 Linux) |
| **开源** | ✅ 完全开源硬件 + 软件 |
| **掌机形态** | 模拟摇杆 + ABXY + L1/R1/L2/R2 + SELECT/START/MENU/STICK |

== **关键**:**游戏手柄 bus=0x0019, vendor=0x9903, product=0x9913, version=0x0102, name="Loong Gamepad"** — SDL 从这些 GUID 派生,如果用错设备会被映射成 game controller 而非 raw joystick(face button A 会变 B)。

## 2. 核心数据

| 字段 | 值 |
|---|---|
| **Stars** | 35 ⭐(早期,但已经在生产)|
| **Forks** | 0 |
| **License** | MIT |
| **Language** | Python(Makefile + bash orchestration)+ C(leaf 内核工具) |
| **Size** | 676 KB / 115 文件 |
| **Created** | 2026-06-04(3 个月)|
| **Updated** | 2026-09-07(active,今天)|
| **Topics** | `miniloong, retro-gaming, retrogaming` |
| **Homepage** | <https://leaf.game> |

## 3. UMRK Workspace 架构 — 14+ sibling repos

```
~/dev/UMRK/
├── Leaf/                       # ⭐ 部署编排器(本文)
├── Catastrophe/                # 模拟器核心 packaging
├── Jawaka/                     # Loong 设备 GUI launcher
├── Thing-File/                 # 文件管理器 app
├── ssh-server/                 # SSH 服务 app
├── CentralScrutinizer/         # Web 管理器 app
├── Fugazi/                     # Shader tuner app
├── PPSSPP-spruce/              # PSP emulator
├── steward-fu-nds/             # NDS emulator
├── N64-standalone/             # N64 emulator
├── Flycast-standalone/         # Dreamcast emulator
├── retroarch-builds/           # RetroArch binary
├── Cores-spruce/               # RetroArch cores
├── mlp1-toolchain/             # LoongArch 交叉编译工具链
├── miniloong-launcher-switcher/# Launcher 切换工具
├── miniloong-adb-keeper/       # ADB keeper
└── umrk-workspace/             # (可选,private internal docs/plans)
```

==**关键设计**:**每个 repo 独立** + Leaf 是 **dispatcher**(不重新实现 product builds)— 见 Makefile 头部注释:

```
This Makefile is a DISPATCHER over each sibling repo's own build/package/stage
targets. It does not reimplement product builds.
```

## 4. 4 大核心功能

### 4.1 Bootstrap(workspace 启动)

```bash
mkdir -p ~/dev/UMRK
cd ~/dev/UMRK
git clone https://github.com/Utility-Muffin-Research-Kitchen/Leaf.git
cd Leaf

make bootstrap      # clone 所有 public sibling repos
make -C ../mlp1-toolchain image  # 交叉编译工具链镜像
make doctor         # preflight: adb / docker / toolchain / device
make stage DEVICE=mlp1  # 完整 stage
```

### 4.2 Stage(部署编排)

| 命令 | 作用 |
|---|---|
| `make stage DEVICE=mlp1` | 完整 stage:launcher + 所有 apps |
| `make stage-jawaka DEVICE=mlp1` | 只 stage launcher payload |
| `make stage-retroarch DEVICE=mlp1` | RetroArch binary + cores + info + shaders |
| `make stage-core-test CORE=np2kai DEVICE=mlp1` | 测试单个 core |
| `make stage-emulator EMULATOR=ppsspp DEVICE=mlp1` | stage 独立模拟器 |
| `make stage-app APP=ssh-server DEVICE=mlp1` | stage 单个 app |
| `make stage-emulators DEVICE=mlp1` | PPSSPP + DraStic + N64 + Dreamcast |

### 4.3 Release(发布)

```bash
make release-zips DEVICE=mlp1        # install + recovery ZIPs
make release-sd-zip DEVICE=mlp1      # install ZIP only
make release-recovery-zip DEVICE=mlp1# recovery ZIP only
make beta-zips TAG=v0.8.0-beta.3 DEVICE=mlp1    # beta ZIPs from one tag
make stable-zips TAG=v0.10.0 DEVICE=mlp1        # stable ZIPs from one tag
```

### 4.4 adb 工具(开发期间连接设备)

```
scripts/
├── adb-install-wrapper.sh           # app 安装
├── adb-large-library-fixture.sh     # 大 ROM 库压测
├── adb-package-quiesce.sh           # 暂停 LoongOS package manager
├── adb-portmaster-ota-fingerprint.sh # PortMaster OTA 指纹
├── adb-resolve-umrk-sd.sh           # 解析 UMRK SD 卡路径
├── adb-restart-loong.sh             # 重启 LoongOS
├── adb-set-marker.sh                # 标记 deploy 状态
├── adb-stage-app-package-smoke.sh   # stage app smoke test
└── devtools/
    └── uipad.c                     # ⭐ 合成手柄(input proxy)
```

## 5. ⭐ `uipad.c` — 关键技术细节(我要借鉴)

### 5.1 用途
**uipad** = 通过 adb 在设备上创建一个虚拟游戏手柄,**用于驱动 Leaf app UI 进行 UI 测试**。

### 5.2 关键约束

```
约束 1: 设备必须在 app 启动前存在
- SDL 在 init 时枚举 joystick,后来添加的 pad 看不见
- 解决: --serve 模式: 创建 pad 一次,保持存活,从 fifo 读命令
- 验证日志: "tracked (joystick)" ✅ / "tracked (gamecontroller+joystick)" ❌

约束 2: 必须克隆真实 Loong Gamepad 身份
- bus=0x0019, vendor=0x9903, product=0x9913, version=0x0102, name="Loong Gamepad"
- SDL 从这些 GUID 派生设备类型
- 用错身份 → "A" 变 "B" → app 退出
```

### 5.3 命令格式

```bash
uipad A                 # 按下 + 释放 A
uipad LEFT LEFT A       # 序列执行
uipad --hold 300 A      # 按住 300ms 再释放
uipad --serve PATH      # 从 fifo 读按钮序列(space-separated),直到 "quit"

# 12 个按钮: A B X Y L1 R1 L2 R2 SELECT START MENU STICK + 4 向 HAT
```

### 5.4 这是「跨设备 adb 控制掌机 UI」的典范

== uipad 是**任何想要自动测试掌机 UI 的人**的标准答案** — 不需要物理手柄,可以编程驱动任意按钮序列。

## 6. 5 大核心设计哲学

1. **"叠加,不替换"** — Leaf 不替换 stock LoongOS,而是叠加在它上面。device 永远 recoverable
2. **"Dispatcher 不实现"** — Leaf Makefile 只调度 sibling repos 的 build/package/stage,不重新实现 product builds
3. **"每个产品一个独立 repo"** — Jawaka/Catastrophe/RetroArch/cores/apps 都独立,Leaf 只是胶水
4. **"Checksum-bound staging"** — `targeted-build-report.json` 必须经过校验才允许 stage
5. **"Pre-flight gates before stage"** — read-only cache preflight 必须在 stage 前通过

## 7. 用户问题回答:**在 MLP1 上开发小工具,技术栈 + 如何开始**

### 7.1 技术栈总览

| 维度 | 技术栈 |
|---|---|
| **OS** | LoongOS(基于 Linux,LoongArch + aarch64)|
| **GUI** | SDL2(Miniloong 启用了 SDL 摇杆枚举) |
| **语言** | **C / C++**(原始,跟 SDL 集成最好)/ **Rust**(可选)/ **Go**(可选) |
| **包管理** | `package-quiesce-v1` barrier(Leaf 自创的 staged package install)|
| **部署** | **adb 推到设备**(Leaf 提供了 adb-install-wrapper.sh)|
| **调试** | adb logcat + adb shell |
| **构建工具链** | `mlp1-toolchain` (LoongArch 交叉编译)|
| **版本控制** | 每个 app 一个 git repo(独立) |

### 7.2 起步 7 步(具体可执行)

```bash
# Step 1: 准备 workspace + clone Leaf
mkdir -p ~/dev/UMRK
cd ~/dev/UMRK
git clone https://github.com/Utility-Muffin-Research-Kitchen/Leaf.git
cd Leaf

# Step 2: Bootstrap(自动 clone 14+ sibling repos)
make bootstrap
# 这会 clone: Catastrophe / Jawaka / Thing-File / ssh-server / CentralScrutinizer / Fugazi 等

# Step 3: 装交叉编译工具链
make -C ../mlp1-toolchain image
# 这会 build LoongArch cross-compiler(aarch64 + LoongArch 双架构支持)

# Step 4: 跑 preflight,确认 adb / docker / toolchain / device 都 ok
make doctor

# Step 5: 连接你的 MLP1 设备
adb devices   # 应该看到 Miniloong 设备

# Step 6: 学习 sibling repos 的结构 — 找一个最像你的 app 模板
ls ../ssh-server/   # 最小 app,适合学习结构
ls ../Thing-File/   # 文件管理器,适合学习 GUI

# Step 7: 开始开发
# - 用 ../mlp1-toolchain 编译
# - 推到设备: adb push your-binary /data/local/tmp/
# - 调试: adb logcat
```

### 7.3 推荐技术栈组合

== **「最简小工具」组合**:

| 组件 | 推荐 |
|---|---|
| **语言** | **C99**(原始,跟 SDL 完美集成,工具链完整)|
| **GUI**(可选)| SDL2(系统已带,Leaf 默认用)|
| **构建** | `make`(Leaf 风格统一)|
| **部署** | `adb push + adb shell + adb install-wrapper` |
| **自动化测试** | `uipad`(合成手柄)|
| **版本控制** | 独立 git repo,clone 到 `~/dev/UMRK/your-app/` |

== **「想用现代语言」组合**:

| 组件 | 推荐 |
|---|---|
| **Rust** | rustup + aarch64-loongson64-linux-gnu target |
| **Go** | GOOS=linux GOARCH=arm64(LoongArch 支持还不完整)|
| **C++** | g++ + SDL2 |

### 7.4 不推荐的

| 不推荐 | 原因 |
|---|---|
| 直接在设备上编译 | 资源受限,LoongArch 工具链交叉编译更快 |
| 假设 device 永远是 USB 连接 | Leaf 提供 adb-install-wrapper.sh,优先 push 而不是 mount |
| 自己写 GPU 驱动 | Leaf 已用 stock Mali 驱动 |

### 7.5 5 大可立即用的工具

| 工具 | 路径 | 作用 |
|---|---|---|
| **`make bootstrap`** | Leaf/ | 一键 clone 14+ sibling repos |
| **`make doctor`** | Leaf/ | preflight 全套检查 |
| **`make stage-app APP=xxx`** | Leaf/ | stage 一个 app 到 SD 卡 |
| **`adb-install-wrapper.sh`** | scripts/ | adb 推送 app 到设备 |
| **`uipad`** | scripts/devtools/ | 合成手柄驱动 UI(自动化测试) |

## 8. 跟我已有项目的可借鉴性

### 8.1 跟 OpenOPC 对比

| 维度 | Leaf | **OpenOPC (我 fork)** |
|---|---|---|
| **Orchestration** | Makefile dispatcher | Python orchestrator |
| **Sibling repos** | 14+ 独立 repo | ❌ 没分 |
| **Bootstrap** | `make bootstrap` 一键 clone | ❌ 没 |
| **Doctor / preflight** | `make doctor` | ❌ 没 |
| **Checksum gate** | `targeted-build-report.json` | ❌ 没 |

### 8.2 跟 img2threejs 对比

| 维度 | Leaf | img2threejs |
|---|---|---|
| 跨产品集成 | 多 sibling repos | 单一 repo |
| 部署目标 | 真实硬件(掌机)| 软件(Three.js 代码)|
| 工具链 | 交叉编译 | Python stdlib |

### 8.3 5 大可借鉴到 OpenOPC

1. **Sibling repo 架构** — 每个 OPC task type 独立 repo,Leaf 只 orchestration
2. **Makefile dispatcher** — OpenOPC 可以有 `Makefile` 调度各个 task 的 build/run
3. **`make doctor` preflight** — OpenOPC 启动前检查工具链 / API key / MCP
4. **Checksum gate** — 任务 artifact 必须经过校验才能 commit
5. **`uipad` 思路** — OpenOPC task 可以加自动化 UI / interaction test(不只是 LLM call)

### 8.4 4 大可借鉴到 substation-blueprint

1. **Sibling 主题配置** — 每个 theme 独立 json
2. **Pre-flight gate** — 启动前检查 WebGL / three.js / device pixel ratio
3. **adb-style 部署** — substation-blueprint 已经用 GitHub Pages,这是天然的「推送 + 部署」

## 9. 5 大相关参考

- **Miniloong Pocket 1 硬件**: 国产开源掌机,Loongson CPU
- **LoongOS**: 基于 Linux,LoongArch 架构
- **Jawaka**: Leaf 自家 launcher(GUI)
- **Catastrophe**: 模拟器核心 packaging 系统
- **Cores-spruce**: RetroArch cores 管理

## 10. TL;DR

**Leaf = MLP1 掌机的 custom firmware 部署编排器**,**不是替代 stock OS 的 CFW,而是叠加**,35 ⭐,MIT,Python + C + bash。

== **用户问题回答**:**在 MLP1 上开发小工具**:
- **技术栈**: **C99 / C++ / Rust / Go**(推荐 C99),**SDL2 GUI**(可选),**adb 部署**
- **起步 7 步**:
  1. `mkdir -p ~/dev/UMRK && cd ~/dev/UMRK`
  2. `git clone https://github.com/Utility-Muffin-Research-Kitchen/Leaf.git`
  3. `cd Leaf && make bootstrap`(clone 14+ sibling repos)
  4. `make -C ../mlp1-toolchain image`(装工具链)
  5. `make doctor`(preflight)
  6. `adb devices`(连接设备)
  7. 学习 `../ssh-server/`(最小 app 模板)+ `../Thing-File/`(GUI 模板)

==**最值得学的 1 点**:**`uipad.c`** — 用 Linux uinput 合成真实 gamepad 身份(bus/vendor/product 严格克隆),**自动化测试掌机 UI 不需要物理手柄**。
