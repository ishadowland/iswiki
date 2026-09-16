# TCPPortExhaustion — 调大 ulimit 反而雪崩的端口耗尽复盘

> 学习笔记 · 调研时间 2026-09-16
> 原文: https://mp.weixin.qq.com/s/fvk3Lrg4Qag1yFy5H_VfdA (胡哥Linux运维 · 2026-08-28)
> 主题: Linux 出站连接端口耗尽 (EADDRNOTAVAIL / errno 99) 生产事故复盘
> 关键命令: `ip_local_port_range` · `tcp_tw_reuse` · `tcp_tw_recycle` · `tcp_fin_timeout` · `LimitNOFILE`

## 一句话定位

「调大 fd 上限只把瓶颈往后挪了一步」——出站短连接模型的服务器,真正卡点在 `ip_local_port_range`(2.8 万端口 ÷ 60s ≈ 470 连接/秒),而不是文件描述符。

## 三个核心概念(全文最重要的认知前提)

| 概念 | 含义 | 关键事实 |
|---|---|---|
| **TIME_WAIT** | TCP 连接主动断开方进入的等待态 | 内核写死 **60 秒**,不可调;**谁主动关谁进** |
| **ephemeral port 池** | 出站连接占用的临时端口范围 | 由 `net.ipv4.ip_local_port_range` 决定(默认 32768-60999,**28232 张**) |
| **fd (nofile)** | 进程能打开的文件描述符上限 | `ulimit -n` / systemd `LimitNOFILE` / `limits.conf`,三者作用域不同 |

## 一道算术题(本次事故的数学本质)

```
出站吞吐上限 = 端口池大小 / TIME_WAIT 时长
            = 28232 / 60s
            ≈ 470 连接/秒(对上同一个目标)
```

→ 出站稳定超过这个量级 → 端口必然耗尽 → `connect() failed (99: Cannot assign requested address)`。

## 「调大反而崩」的本质

> fd 后面是端口,端口后面是 TIME_WAIT,TIME_WAIT 后面是连接模型。一层一层追下去,早该追到「每秒 500 个短连接」这个根子上。

把 `nofile` 从 1024 调到 65535 → 进程不被 fd 卡了 → 并发真实打到端口池 → 端口池比 fd 早崩。

## 定位思路(原文「排查链路」3 步)

### 第 1 步:数 TIME_WAIT

```bash
ss -s                           # 看 TCP 各状态汇总
ss -tan | grep -c TIME-WAIT     # 精确数 TIME_WAIT 个数
```

判据:`TIME_WAIT` 数接近端口池大小(2 万多)→ 已经在雪崩边缘。

### 第 2 步:看端口池

```bash
sysctl net.ipv4.ip_local_port_range
# 输出示例: net.ipv4.ip_local_port_range = 32768 60999
```

→ 60999 − 32768 + 1 = **28232 张**「出口闸机票」。

### 第 3 步:算账

```
端口池 28232 ÷ TIME_WAIT 60s ≈ 470 conn/s(对上同一目标)
```

→ 只要出站稳定 ≥ 500/s,数学上必崩。

## 解决方法(原文「3 层修复」)

### 第 1 层:先止损(临时,重启失效)

```bash
sysctl -w net.ipv4.ip_local_port_range="10240 65535"
```

⚠️ **起点别用 1024 以下**——3306、8080 这类业务监听端口扎堆,会撞车。**10240 起步**是经验值。

### 第 2 层:治本(参数 + 代码)

**参数层:**

```bash
sysctl -w net.ipv4.tcp_tw_reuse=1
```

两个前提:
1. **只对出站连接有效**(本案正好是出站方 ✓)
2. **新内核默认值是 2(仅回环生效)**——必须显式设 `1` 才对真实出站生效;不显式设等于没配

**代码层(真正治本):**

| 比喻 | 错误做法 | 正确做法 |
|---|---|---|
| 一人一辆出租车 | 每请求新建一条 TCP 连接 | **连接池**——几十条长连接复用 |
| 大巴车 | - | Nginx upstream `keepalive` / DB 连接池(HikariCP、gRPC pool…) |

把「每秒 500 次新建连接」压成「几十条长连接来回复用」,TIME_WAIT 自然就没了。

### 第 3 层:持久化

写入 `/etc/sysctl.d/99-network-tuning.conf`:

```ini
net.ipv4.ip_local_port_range = 10240 65535   # 扩大出口端口池
net.ipv4.tcp_tw_reuse       = 1              # 出站连接复用 TIME_WAIT 端口(仅出站)
net.ipv4.tcp_fin_timeout    = 30             # 只管 FIN_WAIT_2,不影响 TIME_WAIT
```

生效:

```bash
sysctl --system
# 老发行版没 --system 的:sysctl -p /etc/sysctl.d/99-network-tuning.conf
```

## 新手最容易踩的 3 个坑

### 坑 1:`tcp_tw_recycle=1` 别开

Linux 4.12(2017 年)**已从内核删除**;NAT 环境下静默丢包。任何让你开 recycle 的教程,写的时间都比你内核老。

### 坑 2:两个参数误解

| 误解 | 真相 |
|---|---|
| `tcp_fin_timeout` 能缩短 TIME_WAIT 的 60 秒 | **不能**——它只管 FIN_WAIT_2;TIME_WAIT 60s 内核写死 |
| `tcp_tw_reuse` 默认开着 | **不是**——新内核默认 2(仅回环),**不显式设 1 等于没配** |

### 坑 3:`limits.conf` 管不到 systemd 拉起的进程

| 配置文件 | 适用场景 |
|---|---|
| `/etc/security/limits.conf` | **登录会话**(ssh/su)走的 PAM,认这份 |
| systemd unit `LimitNOFILE=` | **systemd 拉起的进程**(绝大多数线上服务)认这个 |

**systemd 服务正确改法(Nginx 例):**

```bash
systemctl edit nginx.service
```

弹出 override.conf,填:

```ini
[Service]
LimitNOFILE=65535
```

```bash
systemctl restart nginx.service
systemctl show nginx.service -p LimitNOFILE          # 应显示 65535
cat /proc/$(pgrep -f nginx | head -1)/limits | grep "Max open files"
```

## 自查清单(只读,不伤任何东西)

```bash
ss -s | grep -i time          # TIME_WAIT 堆积情况
sysctl net.ipv4.ip_local_port_range   # 端口池大小
ss -tan | grep -c TIME-WAIT   # 数等待中的连接
```

判据:**TIME_WAIT 数 ≥ 端口池数 70%** → 距「Cannot assign requested address」只差一次峰值。

## 跟我们的关系

| 我们的资产 | 这次事故的复用价值 |
|---|---|
| **VPS / 网关(Nginx upstream)** | upstream 必须配 `keepalive`;跑前用自查清单 3 条命令验证 |
| **Hermes gateway(飞书 3 gateway)** | stock launchd 守护的常驻进程要核对 fd + 端口池,**不能用登录会话的 ulimit 套** |
| **任何「调大上限」的变更** | 变更文档先写算术题:卡在谁头上?放开后下一个瓶颈?新瓶颈扛不扛得住峰值? |
| **.NET / Java / Go 服务** | HttpClientFactory / HikariCP / gRPC pool 默认就开,**确认在用**而不是裸 `new TcpClient()` |

## 复盘方法论(原文抽象)

> 任何「调大上限」的变更,必须先在变更文档里写一道算术题,算清楚放开之后的新瓶颈在哪。

**3 个问题:**
1. 这个限制现在卡在谁头上?
2. 放开之后,下一个瓶颈是什么?
3. 新瓶颈的量级扛不扛得住峰值?

> 生产环境,慢就是快。优化之前,先花十分钟把账算明白——这十分钟,是全场最值钱的十分钟。

## 参考链接

- 原文:https://mp.weixin.qq.com/s/fvk3Lrg4Qag1yFy5H_VfdA(胡哥Linux运维 · 2026-08-28)
- Linux man `ip(7)` — `IP_LOCAL_PORT_RANGE` 文档
- Linux man `tcp(7)` — `TCP_TW_REUSE` / `TCP_FIN_TIMEOUT` 文档
- `systemd.exec(5)` — `LimitNOFILE=` 配置项
- Linux 4.12 changelog — `tcp_tw_recycle` 移除说明
