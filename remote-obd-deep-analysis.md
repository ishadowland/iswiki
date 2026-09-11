# 远程 OBD USB 诊断方案 — 深度技术分析

> 学习笔记 · 调研时间 2026-09-11
> 项目名: 车载 OBD 远程 USB 透传方案(基于 VirtualHere + FRP + N1 + Armbian)
> 来源: 微信公众号「老杨的折腾日记」— <https://mp.weixin.qq.com/s/y-RUYGUFuWlnZdJMU8WRrw>
> 设备: Ross-Tech HEX-V2 Dual-K & CAN(汽车 OBD 诊断)

---

## 0. 项目本质(一句话)

把**车里 USB OBD 设备**通过**「USB over IP + 内网穿透」**技术,**「搬到」远程 Windows 电脑**,让 VCDS 等 OBD 软件**对物理距离完全无感**。

== **核心突破**:**USB 协议栈被「端到端」搬运**,而不是「WiFi 替代 USB」**;软件不需要任何改动**,看到的就是本地 USB 设备。

---

## 1. 项目要解决的 6 大核心问题

| # | 问题 | 严重度 | 本文方案的解决 |
|---|---|---|---|
| 1 | **物理位置绑定**:OBD 软件必须装在车旁边 | 业务核心 | USB over IP + 内网穿透 |
| 2 | **汽车网络无公网 IP**:4G/5G 都在 NAT 后 | 网络层 | FRP 反向代理 |
| 3 | **车机 24×7 稳定性**:熄火断电、颠簸、温度 | 硬件层 | N1 + Armbian + DC-DC |
| 4 | **无人值守自启动**:不可能每次远程点启动 | 运维层 | systemd + NetworkManager 自动连 |
| 5 | **USB 设备安全**:HEX-V2 是专用 OBD 设备 | 业务核心 | 协议层透明 |
| 6 | **远程维护通道**:USB 出问题怎么办 | 运维层 | 顺便保留 SSH 通道 |

---

## 2. 项目的 3 层技术架构

### 2.1 物理层(车里)
```
车辆 OBD-II 接口(J1962 标准)
       ↓
Ross-Tech HEX-V2 Dual-K & CAN 诊断器
   ├─ USB-A 接口 → 接 N1 USB 端口
   ├─ 支持 CAN / K-Line / L-Line
   └─ 需要 Windows 驱动 + VCDS 软件
       ↓
斐讯 N1(ARM64 Linux SBC)
   ├─ USB 2.0 × 2
   ├─ 千兆网口 + Wi-Fi 5
   ├─ DC 5V/2A 供电(从汽车 12V 经 DC-DC)
   └─ 跑 Armbian
       ↓
华为移动热点(或车载 Wi-Fi / 5G CPE)
   └─ 提供 4G/5G 蜂窝公网入口
```

### 2.2 协议层(USB over IP)
```
VirtualHere USB Server(在 N1 上,`vhusbd`)
   ├─ 监听 TCP 7575
   ├─ 接管 N1 的 USB 子系统
   ├─ 把每个 USB 设备的请求/响应流化
   └─ 通过自定义二进制协议(VH 协议)序列化
       ↓
VirtualHere USB Client(在 Windows 上)
   ├─ 接收 VH 协议
   ├─ 在 Windows 上模拟 USB 设备「插入」
   ├─ 调用 Windows USB 子系统
   └─ 通知设备驱动(HEX-V2 驱动)有设备插入
```

### 2.3 网络层(内网穿透)
```
FRP(开源内网穿透工具)
   ├─ FRPS(公网服务器上,coordinator)
   ├─ FRPC(N1 上,expose 服务)
   ├─ FRPC Visitor(Windows 上,consume 服务)
   ├─ 支持 TCP / UDP / HTTP / HTTPS / XTCP / STCP
   └─ XTCP 模式:打洞建立点对点连接(失败回退中转)
       ↓
公网 FRPS 服务
   ├─ bindPort: 7000(控制端口)
   ├─ 暴露 remotePort(TCP 模式)或协调(XTCP 模式)
   └─ Token 认证
```

---

## 3. 5 大技术深度细节

### 3.1 VirtualHere 协议不是简单 TCP 转发

== **VirtualHere 不是「TCP 转发」**,而是**「USB 协议序列化」**:

| 维度 | 简单 TCP 转发 | VirtualHere |
|---|---|---|
| **协议** | 把 TCP 包当字节流转发 | 解析 USB 控制请求、中断、bulk transfer |
| **延迟** | 网络延迟 | USB 协议解析 + 网络延迟 |
| **可靠性** | TCP 可靠,但 USB 设备丢失需重连 | VH 自带心跳 + 设备重连机制 |
| **性能** | 适合 SSH 等 | 专门为 USB isochronous(音频/视频)优化 |

**USB over IP 协议栈**:
```
Windows 应用 (VCDS)
   ↓ USB 请求(scsi / serial / bulk)
Windows USB 子系统
   ↓ USB request block (URB)
VirtualHere Client
   ↓ 序列化 URB → VH 二进制帧
TCP 7575
   ↓ 网络包
VirtualHere Server
   ↓ 反序列化 URB
N1 USB 子系统 (linux USB stack)
   ↓ 物理 USB 包
HEX-V2 设备
```

== **关键**:**VirtualHere Client 必须装对应 USB 设备的 Windows 驱动**(HEX-V2 的 VCDS 驱动)。它做的是**「USB 搬运」**,**不是「USB 模拟」**。

### 3.2 FRP XTCP 的打洞原理

== **XTCP 是 FRP 的「点对点打洞」模式**(基于 NAT 穿透技术):

```
FRPS 的角色:协商中心(信令服务器)

NAT 穿透类型决定了 XTCP 能否成功:
┌──────────────────┬─────────────────────────────────────┐
│ NAT 类型         │ XTCP 能否穿透                          │
├──────────────────┼─────────────────────────────────────┤
│ Full Cone        │ ✅ 容易(Symmetric 反过来)             │
│ Restricted Cone  │ ✅ 通常可以                            │
│ Port Restricted  │ ✅ 通常可以                            │
│ Symmetric        │ ❌ 困难(每次端口不同)                 │
└──────────────────┴─────────────────────────────────────┘
```

== **关键洞察**:
- **家用宽带 / Wi-Fi**:通常是 Full Cone 或 Restricted → **XTCP 高概率成功**
- **4G/5G 移动网络**:越来越多运营商用 **CGNAT + Symmetric NAT** → **XTCP 失败概率高**
- **解决**:如果 XTCP 失败,**回退到普通 TCP 转发**(数据全部经过 FRPS,牺牲带宽换稳定)

### 3.3 HEX-V2 + VCDS 的协议细节

== **Ross-Tech HEX-V2 是 VCDS(VAG-COM Diagnostic System)专用硬件**:
- **支持协议**:K-Line(ISO 9141-2)+ CAN(ISO 15765)+ KWP2000
- **覆盖车型**:大众 / 奥迪 / 斯柯达 / 西雅特 / 保时捷 / 奔驰(MB UDS)
- **驱动**:Windows 安装 VCDS 后,自动安装 HEX-V2 USB 驱动
- **软件**:VCDS 扫描工具 + 编码工具 + 故障码读取 + 刷隐藏

**为什么 VCDS 必须 Windows?**:
- 早期 VCDS 只支持 Windows
- HEX-V2 驱动基于 WinUSB / libusb-win32
- 不支持 Web 版或 Mac 版

**远程 VCDS 数据流**(典型的 CAN 通信):
```
VCDS 软件
   ↓ 发送 ISO-TP 数据帧(CAN ID 0x7E0 / 0x7E8)
HEX-V2 驱动(libusb)
   ↓ USB bulk transfer (EP 0x01 OUT, EP 0x81 IN)
USB 子系统
   ↓ VirtualHere Client 序列化
VH 协议 → TCP 7575 → 网络
VirtualHere Server
   ↓ 反序列化 → USB bulk transfer
HEX-V2 固件
   ↓ K-Line 电压变化(ISO 9141)/ CAN 收发器(ISO 15765)
汽车 ECU(多个模块:J519 / J527 / J285 / J393 等)
```

### 3.4 车载 N1 的「恶劣环境」生存策略

== **车里 N1 跟家里 Linux 服务器完全不同**:

| 维度 | 家里服务器 | 车里 N1 |
|---|---|---|
| **断电** | 关机有序(SIGTERM → 卸载文件系统)| 熄火**直接断电** |
| **温度** | 18-25°C | **-20°C - 70°C**(冬天/夏天车内)|
| **振动** | 无 | **持续颠簸** |
| **网络** | 稳定光纤 | **4G/5G 信号不稳** |
| **电源** | 220V 稳定 | **12V 电压波动**(启动时掉到 9V)|
| **物理安全** | 安全 | **可能被偷** |

**应对方案**:
- **电源**:DC-DC 降压线(输入 9-16V,输出 5V 稳定)+ 自恢复保险丝
- **温度**:N1 工作温度通常 0-40°C,极端地区可能不行(实际车里 ~50°C 算极限)
- **振动**:N1 装在手套箱 + 减震垫
- **网络**:FRPC `Restart=always` 自动重连 + 4G 模组用工业级(本文用 Wi-Fi 间接走,稍好)
- **硬断电**:用 overlayfs(只读 rootfs) + 关键数据 RAM 盘 + 定期 fsck
- **安全**:隐藏手套箱 + 软件防火墙(只开必要端口)

### 3.5 systemd 服务化的关键细节

== **2 个 systemd 单元都遵循同一模式**:

```ini
[Unit]
Description=...
After=network-online.target   # 关键:等网络起来
Wants=network-online.target   # 关键:网络是软依赖

[Service]
Type=simple
ExecStart=...
Restart=always                # 关键:崩溃自动重启
RestartSec=3-5                # 不要太快,给上游恢复时间

[Install]
WantedBy=multi-user.target   # 标准多用户模式
```

**`network-online.target` 的关键作用**:
- Armbian 默认 30 秒等待网络(包括 DHCP)
- 如果没有这个,**FRPC 启动时 Wi-Fi 还没连上 → 启动失败**
- `Wants=` 表示希望但不强制;`After=` 表示**依赖关系**

---

## 4. 完整数据流时间线(从开机到 USB 设备可用)

```
T=0:00   汽车点火
T=0:02   12V 稳定,DC-DC 输出 5V
T=0:05   N1 上电,Bootloader 启动(uboot, ~3-5 秒)
T=0:10   Armbian kernel 启动
T=0:15   systemd 接管,开始起服务
T=0:18   NetworkManager 启动 → 自动连车载 Wi-Fi (10 秒内)
T=0:25   Wi-Fi DHCP 完成 → 拿到 IP
T=0:28   virtualhere.service 启动
T=0:29   vhusbd 检测 USB 设备 lsusb → 看到 HEX-V2
T=0:30   vhusbd 监听 TCP 7575
T=0:32   frpc.service 启动
T=0:33   FRPC 连接公网 FRPS (认证 + 注册)
T=0:34   N1 端 XTCP proxy 上线
T=0:36   Windows 端 FRPC Visitor 启动 / 重连
T=0:37   Windows 端 XTCP 打洞尝试 → 成功 / 失败
         (失败则 FRPC Visitor 维持 tunnel,数据走中转)
T=0:40   Windows FRPC Visitor bind 127.0.0.1:7575
T=0:41   Windows VirtualHere Client 连接 127.0.0.1:7575
T=0:42   Windows 看到 HEX-V2 设备
T=0:43   Windows 自动安装 HEX-V2 驱动(首次)
T=0:45   VCDS 软件启动 → 找到 USB 设备 → 远程诊断可用

总耗时:~45 秒
```

---

## 5. 6 个失败模式 + 排查路径

### 5.1 lsusb 看不到 HEX-V2
**症状**:N1 不识别 USB 设备
**根因**:USB 接触不良 / 供电不足 / USB 控制器没启动
**排查**:
```bash
lsusb -v                # 详细看 USB 设备描述符
lsusb -t                # 看 USB 总线拓扑
dmesg | grep -i usb     # 看内核 USB 日志
```

### 5.2 vhusbd 启动失败
**症状**:ss -lntp | grep 7575 没看到
**根因**:port 占用 / 权限不足 / 缺库
**排查**:
```bash
/usr/local/sbin/vhusbd -h           # 看 help
strace -f /usr/local/sbin/vhusbd    # trace 系统调用
journalctl -u virtualhere -n 50    # systemd 日志
```

### 5.3 FRPC 连接 FRPS 失败
**症状**:journalctl -u frpc 看到 login to server failed
**根因**:Token 不对 / 网络问题 / FRPS 没起
**排查**:
```bash
# 从 N1 测试到 FRPS 的网络
nc -zv frps.example.com 7000

# 验证 token(直接 TCP 测试 FRP 协议)
# 用 frpc 客户端 debug
frpc -c /etc/frp/frpc.yaml --log-level=debug
```

### 5.4 XTCP 打洞失败
**症状**:Windows FRPC Visitor 日志看到 tunnel not established
**根因**:NAT 类型不兼容(对称 NAT)
**解决**:改成普通 TCP 转发(数据走 FRPS 中转)

### 5.5 VirtualHere Client 连接 127.0.0.1:7575 失败
**症状**:VirtualHere 客户端没看到设备
**根因**:FRPC Visitor 没 bind / Windows 防火墙拦截
**排查**:
```cmd
netstat -an | findstr 7575
netsh advfirewall firewall show rule
```

### 5.6 VCDS 软件找不到 USB 设备
**症状**:VCDS 报「no interface found」
**根因**:HEX-V2 驱动没装 / VirtualHere 没正确 claim 设备
**排查**:
- 设备管理器看有没有「HEX-V2 Dual-K」设备
- VirtualHere 客户端右键「Use this device」
- 重装 VCDS 驱动

---

## 6. 项目的 5 大创新点(作者原创性)

1. **「车载 N1 + 移动 Wi-Fi + FRP」组合** — 把家庭 NAS 思路搬到车里,创新但不发明新工具
2. **「TCP + XTCP 混搭」** — SSH 用 TCP(稳定),USB 用 XTCP(低延迟),扬长避短
3. **「DC-DC 直接供电」** — 拒绝 12V → 220V → 5V 的低效方案,工程素养
4. **「分层排错 6 步法」** — 任何复杂系统都适用,不只是 USB 透传
5. **「顺便保留 SSH」** — 既然 N1 都在车里了,顺手开 SSH 通道,运维友好

---

## 7. 项目的 5 大局限

1. **延迟不可控** — USB over IP 50-200ms + 4G 30-100ms,**对实时诊断勉强可用**
2. **带宽消耗大** — USB isochronous 模式(实时流)带宽需求高,XTCP 才能省
3. **车机硬件风险** — 夏天车内 70°C 可能让 N1 死机,冬天 -20°C 启动困难
4. **法律风险** — 远程诊断 ≠ 远程行车;**行驶中禁止远程操作**
5. **单一设备限制** — VirtualHere 是「独占式」,**同一时间只能一个 client 使用 USB 设备**

---

## 8. 项目的工程价值评估

| 维度 | 评分 | 说明 |
|---|---|---|
| **创新性** | ⭐⭐⭐ | 工具组合新颖,但每个工具都是已有的 |
| **实用性** | ⭐⭐⭐⭐⭐ | 解决车主真实痛点(远程诊断 / 刷隐藏) |
| **可复用性** | ⭐⭐⭐⭐ | 模式可迁移到任何「远程 USB 设备」场景 |
| **文档完整度** | ⭐⭐⭐⭐⭐ | 27 节文章,每步都有命令 |
| **稳定性** | ⭐⭐⭐ | 取决于 NAT 类型 / 4G 信号 / N1 硬件稳定性 |
| **安全考虑** | ⭐⭐ | Token 简单,SSH 用 TCP 暴露公网,有被扫描风险 |

---

## 9. 项目的商业化可能

| 场景 | 商业模式 | 困难 |
|---|---|---|
| **远程 4S 店诊断** | SaaS(订阅) | 需要跟主机厂合作 |
| **远程刷隐藏服务** | 一次性收费 | 法律风险(影响车辆保修)|
| **车队 OBD 监控** | B2B SaaS | 车队量要够大 |
| **个人 DIY** | 开源 / 教程 | 没有持续商业模式 |

== **结论**:**适合个人 DIY + 极客圈分享**,商业化需要解决「车辆安全责任」问题。

---

## 10. 我的 5 大启发(给自己)

1. **「USB over IP」是经典问题** — VirtualHere 是商业解,开源方案有 `usbip`(Linux 内核模块,需要 Linux 客户端)
2. **XTCP 对 4G 不可靠** — 商业场景必须 fallback 到 TCP,不能用 XTCP 当唯一方案
3. **「ARM64 SBC + Armbian」组合** — 比树莓派便宜 + 比 x86 省电,**「车里 24×7」首选**
4. **「分层排错」是工程基本功** — 任何复杂系统,先画清楚依赖图再调试
5. **「系统化思维」** — USB 透传不只是一个软件问题,**涉及物理、网络、协议栈、应用** 4 层

---

## 11. TL;DR — 给本项目总结

> **远程 OBD USB 诊断方案的精髓**:**用「USB over IP + 内网穿透」**把物理距离变成网络距离,**让 VCDS 这种 Windows 专用软件完全无感**。VirtualHere 处理 USB 协议层,FRP/XTCP 处理网络层,N1 提供 24×7 平台,**每个组件职责单一、可替换**。**值得借鉴的工程模式**:**「分层 + 标准 + 拆分」** 而不是「一个大一统方案」。

== **关键 takeaway**:当你下次遇到「某设备只能本地用,我想远程用」的痛点,**优先想「USB over IP」** 模式 — 协议层透明,**几乎任何 USB 设备都能远程**(打印机、扫描仪、加密狗、SDR、工业 CAN、医学设备、IoT 编程器)。

---

## 12. 引用与参考

- 原文: <https://mp.weixin.qq.com/s/y-RUYGUFuWlnZdJMU8WRrw>
- VirtualHere 官网: <https://www.virtualhere.com/>
- VirtualHere 协议(部分开源 client): <https://github.com/virtualhere>
- FRP GitHub: <https://github.com/fatedfader/frp>
- FRP 文档: <https://gofrp.io/docs/>
- USB over IP(开源替代): <https://linux.die.net/man/8/usbipd>
- Ross-Tech VCDS: <https://www.ross-tech.com/vcds/>
- Ophub Armbian: <https://github.com/ophub/amlogic-s9xxx-armbian>
- NAT 穿透技术: <https://en.wikipedia.org/wiki/UDP_hole_punching>