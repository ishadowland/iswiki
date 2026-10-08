# press-fit-guard — 新能源三电压装上位机(全行程包络线判定)

> 学习笔记 · 调研时间 2026-10-08
> 仓库: https://github.com/agentthink/press-fit-guard · 公众号原文: https://mp.weixin.qq.com/s/ukm32Q16ySD83QPAj2OsJw
> License: **无**(仓库未添加) · 语言: 仓库未初始化(文章称 C# / .NET 8 / WPF) · ⭐ 0 · 创建 2026-10-06

> [!WARNING] 调研时仓库为空仓(2026-10-08 核验)
> `git ls-remote` 无任何 ref · `GET /contents` 返回 "This repository is empty" · `size=0` · 无 commit / 无 branch / 无 release / 无 LICENSE / 无 topics。
> 下文所有功能描述**均来自公众号文章,无法用代码核验**。文章发布时间早于或等于仓库创建时间(均 2026-10-06),推测代码尚未 push 或已删。
> 本笔记的价值主要在**领域知识 + 可迁移工程模式**,代码部分请勿当作已验证事实。仓库放码后应回来补充实际实现。

---

## 1. 一句话定位

新能源三电压装(定子压装 / 减速器装配 / 电池极柱)的**压装质量监控上位机**,核心是把整条「位移-压力」曲线套进动态公差带做全行程比对,替代只看峰值压力的传统判法。

## 2. 领域背景:为什么「只看峰值」不够

传统压装判定只取**峰值压力**是否在窗口内。失效场景:

| 缺陷 | 峰值压力表现 | 传统判定 | 全行程判定 |
|---|---|---|---|
| 工件歪着压入 | 峰值可能合格 | 漏检 | 曲线形状畸变 → NG |
| 壳体微裂 | 峰值合格 | 漏检 | 后段压力塌陷 / 斜率突变 → NG |
| 倾斜卡滞 | 峰值合格 | 漏检 | 中段位移-压力斜率异常 → NG |
| 虚压配合 | 峰值偏高 | 可能误判 NG | 曲线不匹配标定包络 → NG |

**一句话**:峰值是「结果点」,全行程是「过程」——过程对了,结果点才有意义。这套判法做质检系统工程师一眼能认出来。

## 3. 功能全景(据公众号文章)

```
压装上位机完整链路
├── 数采 ──► 判定 ──► 配置 ──► 追溯 ──► 仿真
│    │       │        │        │        │
│  50Hz     全行程    配方     SQLite    Modbus 从站
│  采集    包络线     多工位    归档      仿真器
```

| 模块 | 文章描述的关键设计 |
|---|---|
| 数采/UI 解耦 | .NET 8 `System.Threading.Channels` 有界无锁管道;采集线程只 push,UI 线程 60 FPS 批量取 64 点局部刷新;渲染 CPU < 3% |
| 断线恢复 | 四状态看门狗,500 ms 查一次心跳;重连按 1→2→4→8→16 s 指数退避 |
| 全行程判定 | 动态公差带包络线,曲线任一点冲出即 NG(不等周期结束);判定耗时 < 5 ms;NG 点位直接标在曲线上 |
| 数字孪生 | 内置 Modbus 从站仿真器,监听 `127.0.0.1:5020`,含伺服推进 / 测量白噪声物理模型;前台有故障注入抽屉(拔网线 / 超时 / 卡滞一键模拟) |
| 配方追溯 | SQLite + WAL 模式,压装结果与曲线落本地库;配方 / 条码 / PASS-NG 一一对应;多工位各存各的配方 |

## 4. 可迁移的工程模式 ⭐(本笔记真正的价值)

这四条与压装业务无关,是**任何上位机 / 实时采集 / 边缘数采系统都能搬走**的工程做法:

### 4.1 有界 Channel 做数采与 UI 解耦

传统 WPF/.NET 上位机在 50–100 Hz 采样下,一个 `Dispatcher.Invoke` 就把主线程堵死 → 掉帧 + GC 抖动,产线工人一眼看出卡。

```
采集线程 (50–100Hz)                UI 线程 (60 FPS)
  生产数据点 ──► Channel.CreateBounded(cap) ──► TryRead 批量取 64 点
                    │  (有界 = 满了丢弃/背压,内存不爆)     └── 局部刷新,不 Invalidate 全表
```

要点:**有界**(防 OOM)+ **批量**(减 Invalidate 次数)+ **单向上传**(UI 永不阻塞采集)。换成任何语言同构:Go channel、Rust crossbeam、MPC 队列。

### 4.2 四状态看门狗 + 指数退避重连

车间网线松一下、PLC 重启一下是常态。指数退避 1/2/4/8/16 s 避免**网络风暴**(掉线时全体客户端同时猛重连会把网关打死)。

状态机建议四态:`Disconnected → Connecting → Connected → Faulted`,500 ms 心跳窗口判死。核心是「自动恢复」——夜班不派人守着。

### 4.3 内置 Modbus 从站仿真器做无硬件开发

**没有压机也能跑完整链路**。这不是玩具:Modbus 报文是真的,可以直接用来练协议调试,练熟再上真机。故障注入模拟的是真实事故,不是假数据。

同类思路:每个硬件项目都该有「协议级仿真器 + 故障注入开关」,比 mock 有用得多——mock 骗自己,仿真器能练协议栈。

### 4.4 SQLite WAL 做本地追溯

WAL 模式下读写不互斥,高频写入不卡界面;开机即跑,无外部服务依赖。多工位各存配方 → 换产线不用重配。

选型判断:**单工位/单机追溯别上 MySQL/时序库**,SQLite + WAL 足够,零运维。真需要跨机聚合再迁。

## 5. 最小使用(据文章,需代码放码后核验)

环境:Windows 10/11 + .NET 8 SDK(有 Visual Studio 更好)。

```bash
git clone https://github.com/agentthink/press-fit-guard
cd press-fit-guard
dotnet build PressFitMaster.sln
dotnet run --project src/PressFit.UI/PressFit.UI.csproj
```

启动后虚拟从站默认后台运行,选配方 → 直接触发压装周期,全程不碰硬件。

⚠️ 当前 `git clone` 会失败(空仓),`.sln` 路径与工程名均来自文章,未核验。

## 6. 同作者生态(已核验 GitHub API,2026-10-08)

作者 `agentthink`(注册 2026-01-08,80 个公开仓)做的是一整条工控工具线,全是 C# / .NET 8 / WPF / Modbus 方向,值得横向扫:

| 仓库 | ⭐ | 语言 | 定位 |
|---|---|---|---|
| [modbus-studio](https://github.com/agentthink/modbus-studio) | 85 | C# | 现代化 Modbus 主站调试 + 轻量组态监控 |
| [sim-foundry](https://github.com/agentthink/sim-foundry) | 79 | Python | 工业仿真 |
| [MeterSim645](https://github.com/agentthink/MeterSim645) | 52 | C# | 电表仿真 |
| [WL.Mock_SWJDemo2](https://github.com/agentthink/WL.Mock_SWJDemo2) | 35 | C# | 上位机模拟 Demo |
| [hmicore-wpf](https://github.com/agentthink/hmicore-wpf) | 21 | C# | WPF HMI 核心库 |
| [next-scada-hmi](https://github.com/agentthink/next-scada-hmi) | 14 | TypeScript | Web 侧 SCADA HMI |
| [plc-sweep](https://github.com/agentthink/plc-sweep) | 14 | C# | PLC 扫描 |
| [modbus-sight](https://github.com/agentthink/modbus-sight) | 17 | TypeScript | Modbus TCP/RTU/RTU-over-TCP 一体调试仿真 |
| [ics-console](https://github.com/agentthink/ics-console) | 5 | C# | 工控控制台 |
| [modbus-understudy](https://github.com/agentthink/modbus-understudy) | 0 | — | 顶替设备身份上线 + 抓包解码 + 故障注入 |

**观察**:作者在有系统地铺「上位机 / 组态 / 仿真 / SCADA」这条线,项目普遍**低星但功能完整**,适合拆开读源码学 .NET 8 工业软件写法,而不是当成熟产品用。

## 7. 跟我们的关系

- **跟压装业务无关**(我们不做产线质检),但 §4 的四条工程模式直接适用于我们手上的**实时数据采集 / 边缘网关 / 遥测**场景:有界队列解耦采集与渲染、指数退避重连、协议级仿真器先行、SQLite WAL 本地归档。
- **可借鉴的选型判断**:单机追溯不上重数据库;每个硬件对接项目配一个仿真器 + 故障注入。
- **阅读价值**:作者 `agentthink` 那 10 个 C#/.NET 8 工控仓是现成的 .NET 8 工业软件源码样本库,想快速了解 WPF + Modbus + 实时曲线这一套怎么写,直接读 `modbus-studio` / `modbus-sight` 源码比看文档快。
- **不适用**:文章里的压装判定算法(包络线、公差带调参)对我们没有复用价值,不用深挖。

## 8. 风险 / 注意

| 风险 | 说明 |
|---|---|
| 仓库为空 | 无代码可读,本文所有实现细节不可信,等放码后回来补 |
| 无 License | 仓库未添加 LICENSE → 默认版权保留,**不可直接复用代码**;等作者加协议再说 |
| 平台锁定 | Windows + .NET 8,macOS / Linux 跑不了(至少文章未提) |
| 软文性质 | 公众号推文,性能数字(渲染 CPU <3%、判定 <5ms、60 FPS)均无 benchmark 代码佐证,当作营销口径看 |
| 判据阈值依赖工艺 | 全行程包络线方案的成败在公差带怎么标定,文章完全没讲,实际落地是工艺活不是软件活 |

## 9. 参考链接

- 仓库: https://github.com/agentthink/press-fit-guard (空仓,2026-10-08 核验)
- 公众号原文: https://mp.weixin.qq.com/s/ukm32Q16ySD83QPAj2OsJw
- 作者主页: https://github.com/agentthink
- 相关: https://github.com/agentthink/modbus-studio · https://github.com/agentthink/modbus-sight