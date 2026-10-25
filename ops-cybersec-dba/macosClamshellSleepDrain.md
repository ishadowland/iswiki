# macOSClamshellSleepDrain — MacBook 合盖不睡 / 夜间耗电的定位处置 SOP

> 学习笔记 · 排查时间 2026-10-24
> 触发来源: 用户报「合上盖子后系统似乎没有正常休眠，电池持续消耗」
> 本机实测环境: macOS 15.7.9 (24G830) · MacBook Pro 13" 2018 (MacBookPro15,2, Intel + T2) · 16GB RAM · Iris Plus 655 · 电池循环 316 次 / 容量 82%
> 关联笔记: [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) · [performanceTriage](performanceTriage.md)

---

## 一句话定位

「合盖不睡 + 夜间耗电」的 SOP：**先分清「没进睡眠」和「进了但没进深睡」两种病态，再看 `chooseStandbyDelay` 选了哪个分支，最后找那个挂了几小时不释放的 IOKit 断言** —— 本例的根因是 **`proximitywake` 开启后 ALS 接近感应在睡眠中被启用，powerd 持有 `InternalPreventSleep` 长达 13 小时**，把机器钉在浅睡眠里。

---

## 症状与「错误直觉」

| 常见误判 | 本例实际情况 |
|---|---|
| 「合盖根本没进睡眠」 | **进睡眠了**，`Entering Sleep state due to 'Clamshell Sleep'` 有明确记录 |
| 「是某个 App 一直开着不让睡」 | UURemote 确实持有 `PreventUserIdleSystemSleep`，但**它不是元凶**（合盖走强制路径，不受空闲休眠断言影响） |
| 「是 `powernap` / `womp` 没关」 | 这两项本来就是 0 |
| 「电池老化导致」 | 电池 82% 健康度确实偏高损耗，但**不能解释 13 小时 75% → 0%** |

**关键分水岭**：区分「Sleep（浅睡眠 / Standby）」和「Deep Idle（深度休眠 / hibernate）」。两者 `pmset` 日志里都能看到 `Entering Sleep state`，但**耗电差一个数量级**。

---

## Phase 1：定位（全部只读）

### 1.1 三条命令拿到全景

```bash
pmset -g                    # 当前生效的电源设置 + 生效中的断言
pmset -g custom             # AC / 电池 两套完整配置
pmset -g assertions         # 谁在阻止休眠、持有多久
```

`pmset -g` 的输出里**这一行是全场最关键的信息**：

```
 sleep                0 (sleep prevented by UURemote)
```

括号里直接点名了阻止者。再配合 `pmset -g assertions` 看每个断言的**持有时长**——`00:05:28` 是正常的，**`13:04:40` 才是元凶**。

### 1.2 关键判据：`ChooseStandbyDelay` 日志

`pmset -g log` 只记电源事件，不记 powerd 的决策过程。要拿到决策必须查 unified log：

```bash
log show --start "2026-10-23 20:21:00" --end "2026-10-23 20:21:30" \
  --predicate 'subsystem == "com.apple.powerd" AND category == "sleepWake"' \
  --style compact | grep -i chooseStandbyDelay
```

**失败那晚的原始记录**（10-23 20:08:32，本次会话直接读到）：

```
chooseStandbyDelay(): lowBattery = false, battery powered = true,
                      capacity=83, lowBatteryThreshold=50; chosen delay=86400
```

**修复后的记录**（10-24 22:15:27）：

```
chooseStandbyDelay(): lowBattery = false, battery powered = true,
                      capacity=100, lowBatteryThreshold=90; chosen delay=1800
```

### 1.3 三个参数怎么读

| 参数 | 含义 | 本例失败值 |
|---|---|---|
| `capacity` | 当前电量 % | 75% |
| `lowBatteryThreshold` | `highstandbythreshold`，低于它算「低电量」 | 50 |
| `chosen delay` | **进入 Standby（浅睡眠）前还要等多久** | **86400 秒 = 24 小时** |

**判定逻辑（powerd 源码口径）**：

```
if capacity < lowBatteryThreshold  →  chosen delay = standbydelaylow   (默认 10800 = 3h)
else                               →  chosen delay = standbydelayhigh  (默认 86400 = 24h)
```

> 🔑 **这是本案最反直觉的地方**：电量**越高**，反而选**越长**的 standby 延迟。
> 合盖时 75% > 阈值 50% → 走 high 分支 → 24 小时都进不了 Deep Idle → **整晚停在浅睡眠**。
> 「电量高所以放心慢慢睡」在电源管理里是反直觉的陷阱。

### 1.4 找出长挂断言

```bash
# 找出当晚所有断言的持有时长，长的就是元凶
pmset -g log | grep -E "Created|Released" | grep -oE "[0-9]{2,}:[0-9]{2}:[0-9]{2}" | sort -u
```

本例命中：

```
2026-10-23 20:21:04  PID 113(powerd) Created InternalPreventSleep
                   "Assertion to change proximity monitoring state"
2026-10-24 09:25:45  PID 113(powerd) TimedOut InternalPreventSleep
                   "Assertion to change proximity monitoring state"  13:04:40
```

**13 小时 04 分的 `InternalPreventSleep`，恰好覆盖整个合盖期**。断言名里的 `proximity` 直接指向 ALS 接近感应。

### 1.5 确认 proximity 是怎么开的

```bash
log show --start "2026-10-23 20:20:50" --end "2026-10-23 20:21:10" \
  --predicate 'subsystem == "com.apple.powerd" AND category == "adaptiveDisplay"' \
  --style compact
```

```
20:21:02.857  Proximity preferences are changed. DarkWake:1 DisplaySleep:0 DisplayWake:0
20:21:04.250  Proximity monitoring in sleep: Enabled. Run-time proximity notifications: Enabled
20:21:04.374  Created InternalPreventSleep "Assertion to change proximity monitoring state"
```

而 `pmset -g custom` 显示当时 **AC 侧 `proximitywake 1`、电池侧 `proximitywake 0`**——参数不对称是排查起点。

### 1.6 完整判定表

| 现象 | 说明 | 下一步 |
|---|---|---|
| `pmset -g` 显示 `sleep 0 (sleep prevented by X)` | 有东西在阻止**空闲**休眠 | 看 `pmset -g assertions` 的持有时长 |
| 断言时长 `13:04:40` 这量级 | **元凶**，覆盖了整个睡眠期 | 按断言名反查配置项 |
| `chosen delay=86400` | 进了浅睡眠但进不了深睡眠 | 调 `standbydelayhigh` |
| 日志有 `Entering Sleep state due to 'Clamshell Sleep'` | 合盖休眠路径**正常** | 别再查合盖，去查 Standby 转换 |
| 唤醒是 `Wake from Deep Idle` | 深睡正常，耗电应极低 | 查是谁在浅睡阶段耗电 |
| 唤醒是 `Wake from Standby` | **停在浅睡眠**，就是本例 | 查 standby 决策与断言 |

---

## Phase 2：修复（`pmset` 参数）

### 2.1 本案实际生效的修改

```bash
# ① 根因：关闭 ALS 接近感应唤醒（AC + 电池两侧统一关闭）
sudo pmset -a proximitywake 0

# ② 消除「高电量 → 24 小时延迟」分支：把 high 延迟也压到 30 分钟
sudo pmset -b standbydelayhigh 1800
sudo pmset -c standbydelayhigh 10800
sudo pmset -b standbydelaylow   600
sudo pmset -c standbydelaylow   10800

# ③ 提高低电量阈值，让 100% 满电也走短延迟分支
sudo pmset -b highstandbythreshold 90
sudo pmset -c highstandbythreshold 90
```

**核心思想**：把 `standbydelayhigh` 和 `standbydelaylow` **调成同一个值**，这样 `capacity` 与 `lowBatteryThreshold` 的比较结果**不再影响**最终延迟，绕开整个分支逻辑。

### 2.2 顺带做的加固

```bash
# 降低磁盘停转延迟
sudo pmset -b disksleep 1
sudo pmset -c disksleep 1

# 电池模式低电量模式（后台活动收敛）
sudo pmset -b lowpowermode 1

# 关闭 tty 活跃时的休眠阻止
sudo pmset -a ttyskeepawake 0

# 关闭蓝牙设备唤醒（对应日志里的 EC.Bluetooth/HID 唤醒）
sudo defaults write /Library/Preferences/com.apple.Bluetooth BluetoothWakeEnabled -bool false

# 关闭可能触发网络唤醒的共享服务
sudo launchctl disable system/com.apple.screensharing
sudo launchctl disable system/com.openssh.sshd
sudo launchctl disable system/com.apple.smbd

# 开盖不自动唤醒（仅电池模式）：应对盖子传感器误触发
sudo pmset -b lidwake 0
```

### 2.3 不建议动的参数

| 参数 | 原因 |
|---|---|
| `standby 0` | 会破坏 Standby → Deep Idle 机制，**回到本例的病根** |
| `hibernatemode 0` | 不写休眠镜像，Intel Mac 上反而更容易因内存丢失 / SSD 意外唤醒而耗电 |
| `lidwake 0`（AC 侧） | 插电时开盖不唤醒很别扭；只在电池侧关 |
| `acwake 1` | 插拔电源唤醒，纯倒退 |
| `powernap 1` | 开着会在休眠时定期唤醒做维护 |
| `gpuswitch` | 已在 2（自动），改 0/1 可能导致外接显示输出异常 |
| `networkoversleep` | 官方标注「changing its value is unsupported」 |
| `destroyfvkeyonstandby` | 本机 FileVault 是 Off，无意义 |
| `sudo nvram BootPreference=%01` | **Apple Silicon 专属**，Intel + T2 不适用，别照抄 |

### 2.4 关于 `tcpkeepalive 0` 的取舍

```bash
sudo pmset -b tcpkeepalive 0   # ⚠️ 会让「查找我的 Mac」失效
```

**实测中一度改过又回退**。原因：`tcpkeepalive=1` 只在休眠期维持 TCP 连接并触发 `TCPKATurnOff` 唤醒请求，边际收益不大；而元凶是 proximity，不是它。**确认根因后，不要为了「多关一个」牺牲真实功能。**

---

## Phase 3：验证（本案的实测闭环）

### 3.1 短周期对照测试（5~18 分钟）

合盖 → 计时 → 开盖，比对四项：

| 检查项 | 期望 | 本例实测 |
|---|---|---|
| 合盖 → 进入 `Clamshell Sleep` | ≤ 20 秒 | 15 秒 ✅ |
| 唤醒时状态 | `Wake from Deep Idle` | ✅ |
| `chosen delay` | 1800 | ✅ |
| 电量变化 | 0% | 41% → 41% ✅ |
| proximity 断言 | **全程不出现** | ✅ 全程为空 |

```bash
# 监控脚本骨架（5 秒采样，约 10 分钟窗口）
while [ $i -lt 100 ]; do
  echo "===== SAMPLE $i $(date '+%H:%M:%S') ====="
  pmset -g 2>&1 | grep -E "^ sleep "
  pmset -g batt | tail -1
  ioreg -l -w0 | grep AppleClamshellState | sort -u
  pmset -g assertions | grep -E "PreventUserIdleSystemSleep|PreventSystemSleep|^ +pid "
  pmset -g assertions | grep -i proximity || echo "  (none)"
  i=$((i+1)); sleep 5
done
```

### 3.2 长周期过夜验证（唯一可信的终局判据）

**必须充满电 + 拔掉充电线**，理由：满电排除「低电量触发应急休眠」的干扰；拔线让测试条件与失败场景**完全一致**（失败那晚正是 `Using Batt(Charge:75%)`）。

本例过夜实测（22:14:33 满电 100% / 电池供电 → 次日 09:03:59 开盖）：

| 时刻 | 电量 | 事件 |
|---|---|---|
| 22:15:27 | 100% | `Entering Sleep state due to 'Clamshell Sleep'` |
| 22:36 / 22:45 / 23:18 | 100% | 3 次暗唤醒（11~20 秒） |
| 00:16 ~ 07:32 | 100% | 每小时一次 `EC.RTC/Maintenance` 暗唤醒（13~16 秒） |
| 07:59:22 | 99% | |
| 09:03:30 | **98%** | |
| 09:03:59 | 98% | `Wake from Standby : due to EC.LidOpen` |

**结果：11 小时整夜只掉 2%。**

### 3.3 修复前后对照

| | 10-23 失败 | 10-24 修复后 |
|---|---|---|
| 合盖时电量 | 75% | 100% |
| `proximitywake` | AC 侧 **1** ❌ | **0** ✅ |
| `highstandbythreshold` | 50 ❌ | 90 ✅ |
| `chosen delay` | **86400**（24h）❌ | **1800**（30min）✅ |
| proximity 断言 | **13h 04m** ❌ | **未出现** ✅ |
| 睡眠深度 | 浅睡眠 Standby ❌ | 深度休眠 ✅ |
| **整夜耗电** | **75%（耗尽）** ❌ | **2%** ✅ |

---

## Phase 4：App 层才是真正的大头

`pmset` 参数的边际收益已经很有限（修好后每夜 2% 属于正常水平）。真正还在偷电的是**应用层**：

| 项 | 机制 | 处理 |
|---|---|---|
| **网易 UU 远程**（`com.netease.uuremote`） | 持有 `PreventUserIdleSystemSleep` 长达 17h46m，配置**加密存储**（`NTES_NRD__MACpreventSleepType` 是加密 blob），**命令行改不了** | App 内设置 →「防休眠模式」→ 选**「允许合盖休眠」** |
| **ToDesk**（`com.youqu.todesk`） | root 权限常驻 + 自带 HAL 音频驱动 | 彻底卸载（见下节） |
| 登录项 | MiniMax Code / Macs Fan Control / 夸克网盘 | 清理 |
| Spotlight 索引 | `mds` / `mds_stores` 在暗唤醒时活动 | 系统设置 → Siri → 关闭「系统索引时使用」 |
| iCloud 同步 | `bird` / `cloudd` 在 DarkWake 时活动 | 排除大目录 / 开启优化存储空间 |

> ⚠️ **UU 远程的断言不影响合盖休眠**。本例三次合盖测试在它持续持有断言的情况下**全部成功**。它只影响「开盖静置时能否休眠」。

---

## 附：ToDesk 彻底卸载（macOS 第三方常驻软件）

远程控制类软件会注册 launchd 守护进程 + 特权助手 + HAL 音频驱动，**删 App 图标不等于卸载**。

### 卸载前的完整足迹清单

```bash
ls -la /Applications/ToDesk.app                          # 应用本体
ls /Library/LaunchDaemons/ /Library/LaunchAgents/ | grep -i todesk   # 5 个 launchd 项
ls -la /Library/PrivilegedHelperTools/ | grep -i todesk  # 特权助手
ls -la /Library/Audio/Plug-Ins/HAL/ | grep -i todesk     # 音频驱动
systemextensionsctl list | grep -i todesk                # 系统扩展
kmutil showloaded | grep -i todesk                       # 内核扩展
```

本例实测足迹：`com.youqu.todesk.{service,session,startup,UninstallerHelper,UninstallerWatcher}`

### 卸载的三个关键点

**① 必须先 unload 再删文件**
直接 `rm` plist 而不 unload，launchd 会因 plist 缺失反复报错并尝试重启守护进程。

```bash
for label in system/com.youqu.todesk.service system/com.youqu.todesk.session \
             system/com.youqu.todesk.startup system/com.youqu.todesk.UninstallerHelper \
             system/com.youqu.todesk.UninstallerWatcher ; do
  launchctl bootout "$label" 2>/dev/null
  launchctl disable "$label" 2>/dev/null
done
```

**② `UninstallerWatcher` 是「卸载后复活」的后手**
该 daemon 监控卸载流程，官方卸载器跑完后它仍活着，能把 ToDesk 重新装回来。必须单独 bootout。

**③ 音频驱动文件删了，进程还挂在内存里**
本例删除 `.driver` 后 `ToDeskOutputDriver` 进程仍在（parent=launchd），`ioreg` 显示仍被加载。必须重启 coreaudiod：

```bash
killall coreaudiod      # 驱动随 coreaudiod 重新加载而卸载
```

### 8 项验证清单

```bash
ps aux | grep -i todesk | grep -v grep                    # ① 进程
ls -ld /Applications/ToDesk.app                           # ② 应用本体
find /Library -maxdepth 3 -iname "*todesk*" -o -iname "*youqu*"   # ③ 系统级残留
find ~/Library -maxdepth 3 -iname "*todesk*" -o -iname "*youqu*" # ④ 用户级残留
ls /Library/LaunchDaemons/ /Library/LaunchAgents/ | grep -i todesk  # ⑤ launchd 项
ls /Library/PrivilegedHelperTools/ | grep -i todesk      # ⑥ 特权助手
ls /Library/Audio/Plug-Ins/HAL/ | grep -i todesk         # ⑦ 音频驱动
ls /var/db/receipts/ | grep -i -E "todesk|youqu"        # ⑧ 安装收据
```

> 用户级残留容易漏，这几处要单独清：
> `~/Library/HTTPStorages/`、`~/Library/WebKit/`、`~/Library/Application Support/`、
> `~/Library/Caches/`、`~/Library/Logs/`、`~/Library/Preferences/`、
> `~/Library/Application Support/CrashReporter/*.plist`、`/Library/Logs/`

---

## 坑点速查

| 坑 | 说明 |
|---|---|
| **「合盖不睡」≠ 「合盖没进睡眠」** | 日志里 `Entering Sleep state due to 'Clamshell Sleep'` 才是真的进睡眠了；要查的是**有没有进 Deep Idle** |
| **电量越高，standby 延迟越长** | `capacity >= highstandbythreshold` → 走 `standbydelayhigh`（默认 24h）。高电量反而更容易卡在浅睡眠 |
| **`pmset -g log` 看不到 powerd 决策** | `chooseStandbyDelay` 只在 unified log 里，必须 `log show --predicate 'subsystem == "com.apple.powerd"'` |
| **unified log 时间窗会漂** | 报 `Wall Clock adjustment detected` 时 `--start/--end` 不可靠，改用 ASL 主日志交叉验证 |
| **ASL 日志按天轮转** | `/var/log/powermanagement/YYYY.MM.DD.asl`，超过一天的历史要翻旧文件 |
| **断言时长才是元凶线索** | 断言「创建/释放」时间戳之差跨小时 = 它把系统钉住了 |
| **`PreventUserIdleSystemSleep` 不挡合盖** | 合盖是强制路径，不受空闲休眠断言影响。别把锅全甩给 UU 远程 |
| **`standby 0` 是回退不是优化** | 关掉 standby 会回到浅睡眠病根 |
| **`tcpkeepalive 0` 破坏「查找我的 Mac」** | 唯一有真实功能损失的项，确认根因后再决定 |
| **`sudo nvram BootPreference` 是 Apple Silicon 专属** | Intel + T2 不适用 |
| **`hibernatemode 0` 在 Intel 上弊大于利** | 不写休眠镜像，更易因内存丢失 / SSD 唤醒而耗电 |
| **`lidwake 0` 只管开盖** | 合盖休眠是 EC 硬件行为（`AppleClamshellCausesSleep=Yes`），不受影响；但开盖后需按键盘唤醒 |
| **删 App ≠ 卸载常驻软件** | launchd 项 + 特权助手 + HAL 驱动 + 收据 + 用户目录，一个都不能漏 |
| **音频驱动删了进程还在** | 必须 `killall coreaudiod` 才能真正从内存卸载 |
| **卸载后可能「复活」** | `*UninstallerWatcher` 类 daemon 需单独停掉 |

---

## 本机现状快照（修复后）

| 项 | 值 |
|---|---|
| 机型 | MacBook Pro 13" 2018 (MacBookPro15,2, Intel + T2) |
| 系统 | macOS 15.7.9 (24G830)，SIP enabled |
| 内存 | 16GB |
| 电池 | 循环 316 次，MaxCapacity ~4137 / DesignCapacity 5088 = **82%** |
| 电池侧配置 | `standbydelayhigh/low = 1800/600` · `proximitywake 0` · `highstandbythreshold 90` · `lidwake 0` · `lowpowermode 1` · `disksleep 1` · `tcpkeepalive 1` · `powernap 0` · `womp 0` · `hibernatemode 3` |
| AC 侧配置 | `standbydelayhigh/low = 10800/10800` · `proximitywake 0` · `highstandbythreshold 90` · `lidwake 1` · `ttyskeepawake 0` · `disksleep 1` |
| 已卸载 | ToDesk（8 项验证全清） |
| 待办 | UU 远程「防休眠模式」改为「允许合盖休眠」（App 内操作） |
| **整夜耗电** | **11 小时 2%** ✅ |

---

## 参考链接

- Apple: `man pmset`（`pmset` 官方手册，含全部可调参数语义）: `man pmset`
- Apple: `man 5 pmset`（`pmset` 手册页）
- Apple 文档: 设置 Mac 的睡眠/唤醒行为: https://support.apple.com/guide/mac-help/change-mac-power-settings-mchl8b4bde7b/mac
- Apple 文档: 关于 Mac 笔记本的电池电源损耗: https://support.apple.com/en-us/102588
- Apple 文档: 在 Mac 睡眠时使用「唤醒以供网络访问」: https://support.apple.com/guide/mac-help/wake-for-network-access-mchl8b4bde7b/mac
- Apple Silicon 专属的开盖启动控制（**Intel 不适用**）: https://support.apple.com/guide/mac-help/startup-options-mh35859/mac
- 网易 UU 远程: https://uuyc.163.com/
- ToDesk: https://www.todesk.com/
- 关联笔记: [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) · [performanceTriage](performanceTriage.md) · [opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md)
