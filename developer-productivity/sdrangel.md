# SDRangel — 开源软件无线电「全家桶」工作台

> 学习笔记 · 调研时间 2026-09-23
> 仓库: https://github.com/f4exb/sdrangel · 官网: https://f4exb.github.io/sdrangel/ · 文档: https://github.com/f4exb/sdrangel/wiki
> License: 自定义 (BSD-style, 商业使用允许, 详见 LICENSE) · 语言: C++ (Qt5) + CMake · ⭐ 4059 · 最近提交 2026-09-21 · 最新发布 v7.27.2 (2026-08-19)

## TL;DR
把 SDR (Software Defined Radio) 从「一根电视棒 + 一个解调小程序」升级成「一个 Qt 工作台 + 100+ 插件」——气象卫星云图 / 船舶 AIS / FT8 短波 / LoRa / Meshtastic / 探空气球数据 都用同一套软件收。硬件 100 元起, 跑 Win/macOS/Linux。

---

## 0.5 配图速览

| 场景 | 截图 |
|---|---|
| 官方 banner (频谱 + 蓝标) | ![](assets/sdrangel/01-official-banner.png) |
| 主界面 3D 频谱瀑布 | ![](assets/sdrangel/02-main-3d-spectrum.png) |
| APT 卫星轨迹地图 | ![](assets/sdrangel/03-apt-noaa.png) |
| APT 红外温度着色 | ![](assets/sdrangel/04-apt-temp-colormap.png) |
| AIS 船舶 3D 地图 | ![](assets/sdrangel/05-ais-map-3d.png) |
| FT8 短波解码界面 | ![](assets/sdrangel/06-ft8-decoder.png) |
| ChirpChat LoRa 解调 | ![](assets/sdrangel/07-chirpchat-lora.png) |
| ADSB 飞机 3D 地图 | ![](assets/sdrangel/08-adsb-map-3d.png) |

---

## 1. 一句话定位
把电脑变成「业余无线电工作台」——前端接廉价的 RTL-SDR 电视棒/HackRF/PlutoSDR,后端用 Qt 工作台 + 100+ 插件做频谱、解调、解码、卫星追踪、3D 地图可视化。开源、跨平台、支持收发(配 HackRF 类全双工硬件)。

## 2. 核心数据(以 GitHub API 为准,纠正原稿「4000」模糊说法)

| 字段 | 值 |
|---|---|
| Star | **4059** |
| Fork | 599 |
| 默认分支 | `master` |
| 创建 | 2015-08-30 |
| 最近 commit | 2026-09-21 |
| 最近 release | v7.27.2 (2026-08-19) |
| 主仓体积 | 252 MB |
| Issue 数 | 102 open |
| 解调/接收插件 (channelrx) | 44 个 |
| 调制/发送插件 (channeltx) | 20 个 |
| 功能面板 (feature) | 23 个 |
| 硬件驱动 (devices/) | 10 个 (Airspy/HF+/BladeRF/HackRF/Lime/Metis/Perseus/Pluto/Soapy/USRP/XTRX) |
| Topics | airspy, hackrf, limesdr, plutosdr, rtl-sdr, sdr, sdrplay, bladerf, d-star, dmr, dpmr, ysf, funcube, receiver, transmitter |

## 3. 核心架构(ASCII)

```
┌─────────────────────────────────────────────────────────┐
│         SDRangel Qt5 工作台(主程序 / GUI / headless)     │
└──────────────────┬──────────────────────┬───────────────┘
                   │                      │
       ┌───────────▼──────────┐   ┌───────▼─────────┐
       │   App bench / app     │   │ AppSrv (Web/CLI) │
       │   GUI flavor          │   │ headless flavor  │
       └───────────┬──────────┘   └───────┬─────────┘
                   │                      │
                   ▼                      ▼
┌──────────────────────────────────────────────────────┐
│      plugins/  (87 plugins, 模块化热插拔)             │
├──────────┬──────────┬────────────┬───────────┬────────┤
│channelrx │ channeltx│ feature    │ sampleMIMO│ sample │
│(44 个解调)│(20 个调制)│ (23 功能)  │ /Sink/    │ Source │
│          │          │            │           │  驱动  │
├──────────┼──────────┴────────────┴───────────┴────────┤
│ APT/AIS/ │ FT8/LoRa/  │ Tracker / │ SDR 设备抽象 SoapySDR │
│ ADS-B / │ M17/Mesh / │ Map / 3D │ / RTL-SDR / HackRF /   │
│ WFM/SSB │ DVB-T/DATV │ Sky Map / │ Airspy / LimeSDR /    │
│ Packet/ │ ChirpChat/ │ Astronomy │ PlutoSDR / USRP / XTRX │
│ Navtex /│ FreeDV/DSD │ / Web ctrl│                          │
│ VOR/ILS │ NFMAIS etc.│ 远控接口  │                          │
└──────────┴───────────┴────────────┴──────────┴────────────┘
                          │
                          ▼
                  ┌────────────────┐
                  │   devices/      │
                  │   10 硬件驱动   │
                  │(SoapySDR 抽象) │
                  └────────────────┘
```

**关键设计**:每个功能(气象卫星、AIS、FT8...)是独立 `.so`/`.dll` 插件,不依赖 GUI,可被 `SDRangelcli` (Web 控制台) 或 `SDRangelDocker` 跑成 headless 容器。

## 4. 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **GUI 桌面应用** | 官方安装包 / flatpak / apt | 桌面用户,想边看频谱边点插件 |
| **Headless 服务端** | `appsrv` + `SDRangelcli` (Web) | 把接收机扔到窗边 / 山顶,客厅远程连 |
| **Docker 容器** | `f4exb/sdrangel-docker` | CI 集成 / 无头采集 / Linux server 集成 |

## 5. 三种接收玩法(以应用价值排序)

### 5.1 NOAA 气象卫星云图(被动接收,最容易出片)

* **频段**:137 MHz (APT 模拟信号)
* **硬件**:RTL-SDR 电视棒 + V-dipole 或 QFH 天线
* **插件路径**:`APTDemod` 插件 → 卫星过境前 10 分钟架好 → 软件按星历算多普勒补偿
* **为什么酷**:一张免费、完全开源的天线,直接收下"卫星自己拍的地球"。

详见下面 §7 配图速览里的 `03-apt-noaa.png` 和 `04-apt-temp-colormap.png`。

### 5.2 AIS 船舶追踪(沿海有用)

* **频段**:161.975 / 162.025 MHz (VHF)
* **插件**:`AISDemod` → 3D 地图实时标船名/位置/航速/目的港
* **限制**:海运 AIS 沿海可收,远海用不上。`05-ais-map-3d.png`。

### 5.3 FT8 短波数字(全球互通)

* **频段**:HF (7/14/21/28 MHz 等 9 个业余段)
* **插件**:`FT8Demod` → 一分钟窗口期自动解码
* **惊喜**:信号弱到听不见(–24 dB SNR)都能解;一晚能解出几十个国家/地区的电台活动,不需要网络。

## 6. 安装(以 Linux flatpak 为例,其它平台命令见原文)

```bash
# Ubuntu/Debian 系
flatpak install flathub org.sdrangel.SDRangel
flatpak run org.sdrangel.SDRangel

# 或者直接 apt (Ubuntu PPA)
sudo add-apt-repository ppa:lxdejo/hamradio-sdrangel
sudo apt install sdrangel
```

装好启动 → 插上 RTL-SDR 电视棒 → 源设备选中 → 点 ▶ → 频谱动起来 → 右侧面板按需挂插件。

## 7. 跟同类竞品对比(去营销,讲定位)

| 项目 | 收发 | 插件数 | 平台 | 入门门槛 | 定位 |
|---|---|---|---|---|---|
| **SDRangel** | ✅ Rx+Tx (Tx 需 HackRF/Pluto) | 100+ | Win/macOS/Linux | 中(界面密) | 「一个软件搞定一摊」 |
| **SDR# (SDRSharp)** | ❌ 仅 Rx | ~10 (纯插件不算) | Windows 为主 | 低 | Windows 圈最入门的纯接收 |
| **GQRX** | ❌ 仅 Rx | ~10 (GNU Radio 组件) | macOS/Linux | 低 | Linux 圈最轻便 |
| **SatDump** | ❌ 仅 Rx (主) | 专精卫星 | Win/macOS/Linux | 低 | 卫星云图解码的天花板 |
| **CubicSDR** | ❌ 仅 Rx | 少 | Win/macOS/Linux | 低 | 跨平台轻量替代 |
| **GNU Radio** | ✅ Rx+Tx | 无限(自己拼) | Linux 强,Win/macOS 弱 | 高 | 元框架,SDRangel 自己也用它做底层 |

**SDRangel 的差异化**:在 Rx+Tx+全频段+卫星追踪+3D 地图+远程控制都齐全的「一体化工作台」中,免费 + 开源 + 跨平台 + 维护活跃,几乎没有第二个。

## 8. 硬件成本与可玩性的真实阶梯

| 投入 | 硬件 | 能玩 |
|---|---|---|
| ¥100 入门 | RTL-SDR V3 电视棒 + 简易天线 | NOAA 云图 / FM / AIS / ADS-B / 探空气球 |
| ¥500 进阶 | RTL-SDR + 专用天线(QFH/Diamond) | 同上 + FT8 / LoRa 短距消息 |
| ¥1000–3000 | + HackRF One (半双工 1 MHz–6 GHz) | 同上 + 简单发射实验(M17/LoRa 网关)|
| ¥3000+ | + LimeSDR Mini 2.0 (全双工) | 严肃的 SDR 开发 / 多用户接入 / 多通道并行 |

软件本身免费,没有功能阉割。

## 9. 跟我们的关系(为什么写进 iswiki)

> 这一段是 iswiki 的差异化定位:不是通用文档搬运,是「跟用户私活/项目相关的复用场景」。

SDRangel 是 **类 Unix + Qt** 的老派 C++ 工程(2015 年起,2026 年仍在活跃),跟我手头的几个方向有可借鉴点:

* **Hermes gateway 的"插件化调度"思路** — 87 个 .so 插件按 channelrx/channeltx/feature 划目录,主程序只是容器。如果以后要把现在 `gateway-ops` skill 里零散的 cron job/launchd watcher 抽象成统一调度器,SDRangel 的 plugin 装载架构是一份直观参考:每个 skill 是独立模块 + 元数据描述,启动时 `dlopen` 注册。
* **可视化的工作台哲学** — 频谱 + 瀑布图 + 3D 频谱 + Map 是同一个信号源的三种视图,UI 不预判你要什么。这种"原始数据 + 多维呈现"对我们做 [teamai-cli](../ai-vibecoding-agents/teamai-cli.md) / [wake](../ai-vibecoding-agents/wake.md) 这种 agent log browser 有借鉴价值。
* **Qt5 + CMake** — 跟 [armorpaint-tech-selection](../armorpaint-tech-selection.md) 一样,是 C++ 大型桌面项目的代表。值得对照看 ARM 工具如何做跨平台 GUI 工程化。

**用户直接可用场景**:
* **儿童科普 / 心儿 + 丞儿早教**:阳台放一根天线,实时看 NOAA 卫星云图直播地球 + ISS 过境提醒 + 探空气球追踪。同龄段小孩看「一颗星划过天 + 软件屏幕上显示同一颗星的数据」,比动画震撼。这是 [MiceInTheMuseum](../ai-vibecoding-agents/MiceInTheMuseum.md) 思路的现实延伸 —— 让抽象的东西"摸得到"。
* **远海出行 / 帆船 / 海钓**:手机 + Raspberry Pi + SDRangel 跑 AIS 追踪,知道附近渔船动态。
* **业余无线电入门**:FT8 / M17 都是数字模式,门槛比传统模拟 AM/SSB 低很多。

## 10. 风险与坑点

* **License 不是 SPDX 标准**:`sdrangel` 自定义许可, 看 `LICENSE` 文件,以"允许商业使用 + 留版权 + 不担保"为骨架,BSD-style 但要自己读一遍。
* **信息密度高的 UI**:第一次打开满屏面板,新手需要 1-2 小时消化。建议**先读 Wiki 的 Quick Start** 而不是直接点。
* **macOS Apple Silicon 上的 flatpak 稳定性**:用户本机是 Intel Macmini8,1 + macOS 13.6,兼容没问题。新 Apple Silicon 用 `brew install --cask sdrangel` 或跑 Docker。
* **天线位置决定 137 MHz 信号的成败**:室内钢筋水泥衰减明显,阳台/窗边/户外更佳。
* **卫星过境窗口期**:NOAA 一日 4-6 次,每次 10-15 分钟,要提前用卫星追踪面板算好时刻。
* **依赖多**:`apt` 装一次 200+ 包,Qt5 + SoapySDR + Codec2 / libhackrf / libusb / airspy 等;C++ 编译需时。

## 11. 参考链接(所有都验证可用, 2026-09-23 核)

| 资源 | URL |
|---|---|
| GitHub 仓库 | https://github.com/f4exb/sdrangel |
| Wiki(含 Quick Start) | https://github.com/f4exb/sdrangel/wiki |
| Readme | https://raw.githubusercontent.com/f4exb/sdrangel/master/Readme.md |
| Releases | https://github.com/f4exb/sdrangel/releases |
| Web 控制台(独立仓) | https://github.com/f4exb/sdrangelcli |
| Docker 镜像(独立仓) | https://github.com/f4exb/sdrangel-docker |
| 用户讨论组 | https://groups.io/g/sdrangel |
| flatpak 包 | https://flathub.org/apps/org.sdrangel.SDRangel |
| APT PPA(Ubuntu) | launchpad.net/~lxdejo/+archive/ubuntu/hamradio-sdrangel |
| 驱动:SoapySDR | https://github.com/pothosware/SoapySDR |
| 驱动:RTL-SDR | https://www.rtl-sdr.com/ |
| 配对参考:SDR# | https://airspy.com/quickstart/ |
| 调研源:微信公众号 | https://mp.weixin.qq.com/s/8k6QrEB-9xMnXXqtralhtg |
