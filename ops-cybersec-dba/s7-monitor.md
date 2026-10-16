# s7-monitor (TIdeMonitoring) — 西门子 S7 PLC 设备监测预警上位机

> 学习笔记 · 调研时间 2026-10-16
> 仓库: https://github.com/agentthink/s7-monitor · 公众号原文: https://mp.weixin.qq.com/s/grnpFsbV_QzQqywZ11vd5g
> License: **MIT**（Copyright 2026 周历强） · 语言: C# / .NET 10 / WinForms · ⭐ **0**（fork 0） · 创建 2026-10-16 13:50 (+0800) · **仅 1 个 commit `init`，无 tag / 无 release / 无 CI / 无测试**

> [!WARNING] 开箱编译被私有 NuGet 包卡住（2026-10-16 一手核验）
> `Zhaoxi.CustControls` 1.0.7 在 **nuget.org 上不存在**（flatcontainer 302 → `nuget.azure.cn` → `BlobNotFound`；azuresearch 搜 "Zhaoxi" 只返回 3 个无关包）。全仓有 **53 处 `UButton` + 26 处 `ULine` + 26 处 `UGroupPanel`** 依赖它。
> README 承诺的兜底「离线包随仓库提供：`controlPackages/Zhaoxi.CustControls.1.0.7.nupkg`」**是假的** —— `controlPackages/` 目录不存在，且 `.gitignore` 第 196 行的 `*.nupkg` 从未放行过。
> **结论：没拿到作者的内部包源，`dotnet build` 直接失败。** 本笔记的架构 / 数据 / 落库规则全部经源码核实（无编译验证），但「能否跑起来」未验证。

---

## 1. 一句话定位

单文件部署的 Windows 工控上位机：S7 TCP 直连西门子 PLC 采集 9 台设备 × 4 个参数，越限即报警，过程全落本地 SQLite，带操作审计。

## 2. 三种进入方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **桌面 GUI（唯一形态）** | `dotnet run --project com.zlq.IntelligentDeviceCenter` | 产线现场常驻工控机，操作工看卡片 + 处理报警 |
| **命令行体检模式** | `*.exe --audit [目录]` / `*.exe --diag [目录]` | 逐页实例化导出 PNG / 输出表格列宽，`MessageHelper.Silent=true` 不弹窗，自动化流程不会被卡住 |
| **PLCSIM 仿真** | TIA 博途 PLCSIM Advanced + 仓库自带截图链路 | 无真机时演示与自测（README 截图即此环境产出） |

没有 Web / API / 服务端形态。想远程看数据只能自己再包一层。

## 3. 核心架构

```
UI (WinForms, 91 文件 / 23,190 行 — 含 9,121 行 Designer)
 │
 ▼
BLL (6 文件 / 746 行)  DbInitBLL 启动迁移 · AlarmEventBLL · UserBLL
 │
 ▼
DAL (9 文件 / 2,062 行)  DbMigrator 只增不删 · SQLiteHelper(WAL) · AlarmEventDAL(22KB)
 │
 ▼
Models (5 文件 / 337 行) + Common (6 文件 / 893 行)
```

约束写死在 README：**UI 不直接引用 DAL**，要摸数据源必须走 `BLL/DbSourceBLL` 转发。UI 内部按 `SysConfigs/ · UControls/ · Utils/ · Models/` 分区，`FormBase` 是所有窗体基类（统一样式 + 双缓冲 + `Ui()` 线程封送）。

**⭐ 三层持久化刻意分工，互不替代**（这条最值得抄）：

| 层 | 载体 | 回答的问题 |
|---|---|---|
| 运行日志 | `Logs\app-yyyyMMdd.log`（Serilog，保留 30 天） | 程序为什么崩了 |
| 业务数据 | `DeviceDataLog` / `AlarmEvent` | 某台设备三点钟压力多少 |
| 操作审计 | `OperationLog` | 谁在什么时候改了阈值 |

## 4. 采集与落库（本笔记最有价值的部分）

**采集**：`System.Timers.Timer` 每 **1 秒** 一轮，跑在线程池线程（不是 UI 线程），只有刷控件时才封送回 UI。

**连接超时必须显式设**（源码注释原话）：

```csharp
private const int PlcIoTimeoutMs = 1500;   // 默认一轮 5 次 Read 最长阻塞 25 秒
plc.ReadTimeout  = PlcIoTimeoutMs;
plc.WriteTimeout = PlcIoTimeoutMs;
```

不设的后果：掉线时 UI 线程一直等 `_ioLock`，整个窗口假死且毫无提示。

**落库三条规则**（`Utils/DataLogWriter.cs` 25KB，注释密度极高的一文件）：

| 规则 | 触发 | 说明 |
|---|---|---|
| 降频采样 | 四参数全正常 | 每 **30 秒** 写一行 `RecordType=1`，**降频计时不被报警行重置** |
| 报警即时写 | 参数首次越限 | 边沿触发，立刻写 `RecordType=2`，不等降频点 |
| 恢复即时写 | 参数回到正常 | 立刻写 `RecordType=3`，带当时当前值 |

设计原话：**「边沿要即时、持续要降频」** —— 报警发生/恢复是事件，晚 30 秒就丢了真实时刻；持续报警只是状态延续。

| `RecordType` | 含义 | 内容 |
|---|---|---|
| 1 | 采样行 | 一时刻一行，四参数全填，参数列留空 |
| 2 | 报警行 | **一个异常参数一行**，带该参数的值/等级/阈值快照 |
| 3 | 恢复行 | 恢复瞬间，带当时当前值 |

`AlarmState`：`1` 正常 / `2` 低值 / `3` 高值，判定为纯阈值闭区间（`AlarmJudge.Judge`：`value < min → Low; value > max → High; else Normal`，**边界值算正常**）。

**`AlarmEvent` 表 = 一条记录 = 一次「设备 + 参数 + 一段连续越限过程」**，四个环节闭环：起报（`RaiseTime/Value`）→ 峰值（`PeakValue`，内存里 `ActiveEvent.TryUpdatePeak` 攒）→ 恢复（`RecoverTime/Value`）→ 确认（`AckTime/AckBy/HandleNote`）。

### 4.1 崩溃后重启的「孤儿报警」修复 ⭐

判定基准存在**内存**里，程序一挂就丢。`DataLogWriter.RebuildBaseline()` 启动时对齐三类情况：

| 库中状态 | 现在状态 | 处理 |
|---|---|---|
| 报警中 | 已正常 | 补一条恢复行，备注写明「实际恢复时间未知」 |
| 报警中 | 仍报警 | 不写行，基线对齐成「报警」，视为同一次持续 |
| 正常 | 异常 | 基线对齐成「正常」，下个周期自然写出报警行 |

源码自陈边界：**「掉线期间真正发生了什么，是补不回来的」**（采集端跑在 PC 上的固有边界），真实系统得靠 PLC 侧 SOE 打时间戳 + 采集端冗余。

顺带两个细节：首次采集用 `_baselineReady` **只建基线不产生事件行**（避免启动瞬间抖动被写成报警）；`LoadOpenEventsFromDb()` 必须在 `DeviceDataLog` 基线**之前**执行，否则本轮发现已恢复时会重复开新事件而不是闭合旧事件。

### 4.2 重连不能用 `plc.IsConnected` 短路 ⭐⭐

这条是全仓最有价值的坑，源码注释整段在讲它：

> `IsConnected` 是 S7.Net 的本地标志位（底层 `TcpClient.Connected`），不会主动探测链路。对端掉线后只要本机还没收到 FIN/RST，它就一直返回 `true`。于是「掉线 → 判失败 → 起重试 → 一进来看到 IsConnected 还是 true → 立刻判成功 → UI 回运行态」循环往复，界面上完全看不出断过线 —— **这正是之前「监控中断开虚拟机，上位机状态没变」的原因**。

正确做法：**强制重建 + 真实读取探活**（先 Close 再 Open，最后真读一次）。

配套：连续失败 `ConsecutiveFailuresToDrop = 2` 次才降级；`RetryIntervalMs = 5000` 固定间隔（**不是指数退避**，与 [press-fit-guard](../developer-productivity/press-fit-guard.md) 的 1→2→4→8→16s 不同）；`Timer.Stop()` 不会撤销已排队的回调，故 stop 后另有守卫。

### 4.3 串口备用通道（自动切换）

PLC 连不上时后台 `RunRetryLoopAsync` **只在第一轮**试串口（`rounds == 0 && serialLink == null`）—— 每轮都试会一直占 COM 口、失败日志刷屏。主链路恢复后 `OnConnectSucceeded()` 主动 `CloseSerialLink()` 切回去。

| 配置 | 文件 | 示例（实测拉取） |
|---|---|---|
| PLC 通信 | `ConfigFiles\Communicate.txt` | `CpuType:S71500;Ip:192.168.0.10;port:1102;rack:0;slot:1` |
| 设备信息 | `ConfigFiles\Devices.json` | 9 台，`StateAddress` 形如 `0.0` / `1.0` |
| 参数点位 | `ConfigFiles\StoreSets.json` | 温度 DWord@0 / 压力 DWord@36 / 功率 Word@72 / 速度 Word@90 |
| 存储 / 串口 / 预警 | `storeFilePath.txt` / `ComPort.txt` / `AlarmSets.txt` | — |

串口帧（一行一帧，`\n` 结尾，字段 `;` 分隔，同字段多设备 `,` 分隔）：

```
ST=0110;T=36.5,52.1;P=1.20,3.40;W=12,34;S=1500,1600
```

`ST` 是按设备 `Position` 顺序的状态位串（1=运行 0=停止）。字段可只上送一部分，缺失的按 0 处理。**波特率/校验位写进文件不起作用**（`SerialLink` 注释明说，只有 `PortName` 是真开关）。

### 4.4 配置锁定当安全锁用 ⭐

`enableSetting` 默认 `false`（`CommonHelper.isEnableSetting = false`）。语义是**「启用配置」= 锁定**：

- 勾选 → 六个配置子页的「确定」按钮**隐藏**（不是置灰）
- 取消 → 若监控正在跑，弹窗问「是否停止设备监控」；选取消则**回退为勾选态**并写一条 `result=Fail` 的审计（否则事后只看到配置一直锁着，看不出有人试过）
- 确认 → 先 `StopMonitoring()` 再解锁，两个动作的审计在日志里能对上

### 4.5 存储路径降级 + 幽灵副本提示

`StorePathBootstrap.cs`（17KB）：程序目录优先（绿色部署），不可写时（装到 `C:\Program Files`）降级到 `%LOCALAPPDATA%\TIdeMonitoring\Data`。运行期改动写用户配置 `%LOCALAPPDATA%\TIdeMonitoring\user.config`，**重新编译不丢**。启动时若发现「存储目录 ≠ 程序目录」，日志里提示存在幽灵副本。

## 5. 曲线与报表

### 5.1 抽稀保留极值（`FrmTrends.AddDecimated`）

按时间均分成 `bucketCount` 个桶，**每桶取「最小值点 + 最大值点」**（按时间先后输出，否则线往回折）。故障瞬间的尖峰脉冲不会被抹掉。

配套两个容易漏的点：原始数据 `_historyRows` 留一份，缩放/平移后按「当前看得见的那一段」重新抽稀（否则放大到 10 分钟还是按 10 小时抽稀过的那批点）；`valCount.Maximum = 2000`（设计器默认只有 100，历史档想画 500 点就不够）。

### 5.2 实时档禁鼠标交互

`Chart1_MouseDown` 首行 `if (rbtnRealTrends.Checked) return;`，且 `CursorX.IsUserEnabled = false` 关掉内置十字线（工业现场十字线跟着鼠标晃很乱）。**「实时」类页面还有 `MonitorGuard` 统一守卫**：监控没启动时切到实时会给「数据在动」的错觉，实际是几分钟前的陈旧数据，三个入口共用一份文案。

### 5.3 报表与导出

日/周/月报；实时数据报表 + 异常记录报表两类。CSV 用 `new UTF8Encoding(true)` 写（**带 BOM**，否则 Excel 直开中文全乱码）。

### 5.4 审计 6 模块 + 登录失败留痕

`AuditLog` 是 UI 层薄门面，补齐「当前账号 + 角色 + 时间」，页面只写一句 `AuditLog.Write(...)`。覆盖：系统配置 / 设备监控 / 预警管理 / 报表统计 / 登录认证 / 用户管理。

两个设计决定：

1. **审计是旁路** —— `try/catch` 全吞，只留一条运行日志。写不进去绝不能把正在做的业务操作带崩，但「审计悄悄失效」本身要留痕。
2. **登录失败必须显式传账号** —— 那种场景还没有会话，账号由调用方传入，否则事后查「谁在试别人的密码」查到的是空串。

## 6. 数据库

SQLite 单文件 `DeviceDBase.sqlite`，启动自动迁移。连接级 pragma 三行（`DeviceDataLogDAL`）：

```sql
PRAGMA journal_mode=WAL;      -- 读写不再互相阻塞
PRAGMA synchronous=NORMAL;    -- 兼顾性能与安全
PRAGMA busy_timeout=3000;     -- 遇锁自动重试 3 秒
```

**`DbMigrator` 三条设计取舍**（源码注释，可整段抄）：全程 `IF NOT EXISTS` + 列存在性检测保证幂等；**只增不删**（SQLite 对删列改列支持很差，真需要就重建表，不该放在启动路径自动跑）；**加列必须带 DEFAULT**（否则 `ADD COLUMN` 带 `NOT NULL` 时老行无法填值直接报错，这是最常见迁移坑）。

| 表 | 用途 | 索引 |
|---|---|---|
| `UserInfos` | 账号（`MD5(MD5(明文))`）、角色、启停、最后登录 | `UX_UserName`（唯一） |
| `DeviceDataLog` | 数据主表（采样/报警/恢复行 + 报警处理字段） | `CollectTime` / `(DeviceNo,CollectTime)` / `IsHandled` / `EventId` |
| `AlarmEvent` | 报警事件（起报/峰值/恢复/确认闭环） | `RaiseTime` / `Status` / `(DeviceNo,ParaType)` |
| `OperationLog` | 操作审计 | `OperTime` / `UserName` |

索引建不上（如历史脏数据重名账号）**降级为 warning 而非拦住启动** —— 索引只影响查询快慢，不该因此起不来。

## 7. 依赖与构建

| 类别 | 选型 | 版本 | nuget.org 核验 |
|---|---|---|---|
| 运行时 | .NET | `net10.0-windows`（UI）/ `net10.0`（其余） | — |
| PLC 通信 | S7.Net（包名 `S7NetPlus`） | 0.20.0 | ✅ 存在（该包最新版即 0.20.0） |
| 串口 | System.IO.Ports | 10.0.11 | ✅ |
| 数据库 | System.Data.SQLite.Core | 1.0.119 | ✅（该包最新版即 1.0.119） |
| 日志 | Serilog / Sinks.File | 4.4.0 / 7.0.0 | ✅ |
| JSON | Newtonsoft.Json | 13.0.4 | ✅ |
| Excel | NPOI | 2.8.0 | ✅ |
| 拼音 | NPinyin.Core | 3.0.0 | ✅ |
| **UI 控件** | **Zhaoxi.CustControls** | **1.0.7** | ❌ **不存在** |

构建基线（README 自述）：**0 错误 / 约 261 警告（250 唯一）**，均为历史存量（空值可空性、NPOI 许可证）。

`Common.csproj` 留了个耐人寻味的注释：6 个工具文件（`DesEncrypt` / `MD5Encrypt` / `RsaEncrypt` / `ExcelHelper` / `PinYinHelper` / `StringHelper`）本是**从同级目录 `Zhaoxi.IDMWCM` 项目拷进来的副本**，目的是让本仓独立编译；并警告不要再用 `<Compile Include="../../Zhaoxi.IDMWCM/...">` 引入，否则同一份代码编译两次报「命名空间已包含 XXX」。

**残留命名空间佐证**：`com.zlq.DAL/UserDAL.cs`、`DAL/Base/SQLiteQueryHelper.cs` 的 namespace 仍是 `Zhaoxi.IDMWCM.DAL` / `...Models`，`DAL/Helper/SQLiteHelper.cs` 仍是 `Zhaoxi.Helper` —— 典型的「从商业项目抽出改名后忘改干净」。

**DPI 策略**（`.csproj` 注释解释了为什么不能改）：

```xml
<ApplicationHighDpiMode>DpiUnaware</ApplicationHighDpiMode>
<ForceDesignerDPIUnaware>true</ForceDesignerDPIUnaware>
```

锁死 96 DPI 虚拟化：布局尺寸与字体渲染同一套坐标，绝不错位（代价是高 DPI 下系统位图放大略发虚）；配合所有窗体 `AutoScaleMode=None`。**不能改成 PerMonitorV2** —— DPI 感知下坐标是物理像素而布局按 96 DPI 设计，字体放大 DPI 倍数而控件不放大，必然文字溢出。`ForceDesignerDPIUnaware` 需 VS 2022 17.8+（注意 `.slnx` 格式本身还需更新的 IDE，README 只说「本机 VS 18 可用」）。

## 8. 最小使用

环境：Windows 10/11 + **.NET 10 SDK**。

```bash
git clone https://github.com/agentthink/s7-monitor
cd s7-monitor/com.zlq.IntelligentDeviceCenter
dotnet build com.zlq.IntelligentDeviceCenter.slnx
dotnet run --project com.zlq.IntelligentDeviceCenter
```

首次登录 **`admin` / `123456`**（`UserBLL.DefaultAdminName` / `DefaultAdminPwd` 硬编码常量），进去立刻改密码。若库里有账号但没有管理员，会把最早的可用账号提权（密码沿用）。`Role` 列默认 0=操作员，历史库里的 admin 迁移后会变操作员，所以要显式兜底提权。

⚠️ 前面说的私有包问题会让第 2 步失败。

## 9. 跟我们的关系

- **同作者姊妹篇**：[press-fit-guard](../developer-productivity/press-fit-guard.md)（压装上位机）也是 `agentthink`。两篇对照读能看出作者的固定套路：**同一套分层（UI→BLL→DAL→Models）+ 同一个 `Zhaoxi.*` 控件库 + 同款 SQLite WAL + 源码注释当设计文档**。作者的 91 个公开仓（注册 2026-01-08，115 followers）是现成的 .NET 工控源码样本库。
- **可直接搬走的四条**：① **重连必须真实读取探活，不能信 `IsConnected`**（这条对任何 TCP/串口采集都成立，我们做遥测网关必踩）；② 边沿即时 + 持续降频的落库规则；③ 崩溃重启后重建判定基线防孤儿报警；④ 三层持久化分工（运行日志 / 业务数据 / 操作审计各答一个问题）。详见 [netdata](netdata.md) 那篇的监控视角对照。
- **选型判断一致**：单机追溯不上重数据库，SQLite + WAL 够；审计写不进去不能拖垮业务操作。
- **不适用**：WinForms + Windows 锁定，我们主业不是工控；S7 PLC 协议本身对我们无直接需求。
- **读源码价值 > 跑起来价值**：编译被私有包卡死，但 117 文件 / 27,228 行 C#（其中 9,121 行是 Designer 生成的）里手写部分注释密度极高，是 WinForms 工业软件的写法样本。

## 10. 风险 / 注意

| 风险 | 说明 |
|---|---|
| **编译阻塞** | `Zhaoxi.CustControls` 不在 nuget.org，README 承诺的离线包也不在仓（被 `*.nupkg` gitignore），拿不到包源就编不过 |
| **README 有假** | 宣称有 `Database/` 建表脚本目录 —— **实际不存在**，且 `.gitignore:364` 的 `/Database` 把它永久忽略了。`DbMigrator` 注释里「与 `Database/04_升级_报警事件表.sql` 保持一致」指向的文件从未提交 |
| **单 commit / 无 release** | 只有 `init` 一个 commit（作者字段还是 `Your Name <you@example.com>` 模板未改），⭐0 fork0，**没有任何使用反馈可参考**，成熟度无法验证 |
| **默认口令** | `admin/123456` 硬编码；密码 `MD5(MD5(明文))` 无 salt —— 内网工控场景可接受，但任何联网部署都不能直接用 |
| **无 CI / 无测试 / 无 .editorconfig** | 117 个 .cs 零测试，`.github/` 目录不存在 |
| **串口备用通道只试一次** | `rounds == 0` 限制意味着串口在第二轮才插上也认不出来，要重启监控 |
| **停机设备无数据** | 停机设备不进采集集合，查它历史曲线为空是**预期行为不是故障** —— 但这个坑没在 UI 上提示 |
| **重连非指数退避** | 固定 5 秒间隔，多个工控机同时掉线可能对网关造成周期性冲击（同作者 press-fit-guard 反而做了指数退避） |
| **作者时间极短** | 仓库创建当天即 init + push，当天发公众号。可能是商业项目切片，不能当成熟开源产品看待 |
| **平台锁定** | Windows + WinForms + .NET 10；macOS / Linux 完全跑不了 |

## 11. 参考链接

- 仓库: https://github.com/agentthink/s7-monitor
- 公众号原文: https://mp.weixin.qq.com/s/grnpFsbV_QzQqywZ11vd5g （2026-10-16 17:02 发布）
- 作者主页: https://github.com/agentthink （91 个公开仓，同族: modbus-studio / sim-foundry / MeterSim645 / hmicore-wpf）
- PLC 通信库: https://www.nuget.org/packages/S7NetPlus
- 同作者姊妹篇（本仓）: [press-fit-guard](../developer-productivity/press-fit-guard.md)
- 监控视角对照（本仓）: [netdata](netdata.md)
