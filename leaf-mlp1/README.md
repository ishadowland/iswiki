# Leaf / MLP1 — 掌机二次开发 / 模拟游戏专题

> 收录跟 **Miniloong Pocket 1 (MLP1)** + **Leaf (UMRK)** 相关的所有调研。
> 包括:硬件 / 部署编排器 / 模拟器 / 自定义 firmware / 掌机应用开发 / 反向工程 / 自动化测试 等。

---

## 0. 索引

| 文档 | 类型 | 描述 |
|---|---|---|
| **[leaf-deploy](leaf-deploy.md)** | 部署编排器 | UMRK workspace 中央命令面,14+ sibling repos 调度 |

---

## 1. 项目背景

### 1.1 硬件 — Miniloong Pocket 1 (MLP1)

- **CPU**: Loongson(龙芯)— aarch64 + LoongArch 异构
- **GPU**: Mali(ARM)
- **OS**: LoongOS(基于 Linux)
- **形态**: 模拟摇杆 + ABXY + L1/R1/L2/R2 + SELECT/START/MENU/STICK
- **游戏手柄身份**: bus=0x0019, vendor=0x9903, product=0x9913, version=0x0102, name="Loong Gamepad"

### 1.2 软件生态 — UMRK Workspace

```
UMRK/
├── Leaf/                 # 部署编排器
├── Catastrophe/          # 模拟器核心 packaging
├── Jawaka/               # Loong 设备 GUI launcher
├── Thing-File/           # 文件管理器
├── ssh-server/           # SSH 服务
├── CentralScrutinizer/   # Web 管理器
├── Fugazi/               # Shader tuner
├── PPSSPP-spruce/        # PSP emulator
├── N64-standalone/       # N64 emulator
├── Flycast-standalone/   # Dreamcast emulator
├── retroarch-builds/     # RetroArch binary
├── Cores-spruce/         # RetroArch cores
├── mlp1-toolchain/       # LoongArch 交叉编译工具链
└── ... 14+ sibling repos
```

---

## 2. 跟掌机开发相关的核心主题

### 2.1 部署 / 编排
- [leaf-deploy](leaf-deploy.md) — Makefile dispatcher 模式,`make bootstrap` / `make doctor` / `make stage DEVICE=mlp1`

### 2.2 自动化测试
- `uipad.c` — 用 Linux uinput 合成真实 Loong Gamepad 身份,自动化测试掌机 UI

### 2.3 交叉编译
- `mlp1-toolchain` — aarch64 + LoongArch 双架构支持

### 2.4 模拟器集成
- PPSSPP / DraStic / mupen64plus / Flycast / yabasanshiro / Fun-Drastic

---

## 3. 推荐技术栈组合(根据 leaf-deploy.md)

| 组件 | 推荐 |
|---|---|
| **语言** | C99(原始,工具链完整)/ Rust / Go |
| **GUI** | SDL2(系统已带) |
| **部署** | adb(`adb-install-wrapper.sh`) |
| **构建** | `mlp1-toolchain` 交叉编译 |
| **调试** | adb logcat + adb shell |
| **版本控制** | 独立 git repo |

---

## 4. 起步 7 步(完整版见 leaf-deploy.md)

```bash
# 1. 准备 workspace
mkdir -p ~/dev/UMRK && cd ~/dev/UMRK

# 2. Clone Leaf
git clone https://github.com/Utility-Muffin-Research-Kitchen/Leaf.git
cd Leaf

# 3. 一键 bootstrap
make bootstrap

# 4. 装交叉编译工具链
make -C ../mlp1-toolchain image

# 5. 跑 preflight
make doctor

# 6. 连接 MLP1
adb devices

# 7. 学习 sibling repos 模板
ls ../ssh-server/   # 最小 app
ls ../Thing-File/   # GUI app
```

---

## 5. 核心资源

- **官网**: <https://leaf.game>
- **GitHub**: <https://github.com/Utility-Muffin-Research-Kitchen/Leaf>
- **Discord**: <https://discord.gg/QEH8mzcwdR>
- **论文**: (TBD)

---

## 6. 后续可扩展主题(规划中)

- [ ] **掌机硬件深度** — SoC / GPU / 屏幕 / 电池 拆解
- [ ] **LoongOS 内核** — 编译 / 定制 / 调试
- [ ] **模拟器反向** — RetroArch cores / PPSSPP-spruce 原理
- [ ] **J[/x]awaka launcher 二次开发** — GUI / 主题 / 字体
- [ ] **uipad 深度** — Linux uinput 高级用法 / SDL GUID 派生
- [ ] **adb 高级调试** — logcat / 性能 / 内存
- [ ] **PortMaster** — MLP1 OTA / 集成
- [ ] **Catastrophe packaging** — 模拟器核心打包系统
- [ ] **Fugazi shader tuner** — shader 调优工具

---

## 7. 外部参考(可加入 iswiki)

- **Miniloong 官方**: <https://miniloong.com>(待确认)
- **LoongArch 文档**: <https://loongson.github.io/LoongArch-Documentation/>
- **RetroArch 文档**: <https://docs.libretro.com/>
- **SDL2 游戏手柄**: <https://wiki.libsdl.org/SDL_JoystickEvent>
- **Linux uinput**: <https://www.kernel.org/doc/html/latest/input/uinput.html>
