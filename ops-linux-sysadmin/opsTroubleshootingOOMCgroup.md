# 运维思路:free 还有 8G,OOM 却杀了我的数据库 —— 「账本思维」之 cgroup 篇

> 学习笔记 · 调研时间 2026-08-12
> 调研来源: 微信公众号「胡哥Linux运维」,作者胡登治(RHCA,15 年 Linux 运维)
> 原文: https://mp.weixin.qq.com/s/b7Vur9bhRwPs-PHDsdXBoA
> 系列定位: 「Linux 诡异现象排错」系列(与 [`OpsTroubleshootingDiskGhost.md`](./OpsTroubleshootingDiskGhost.md) 同系列同作者)
> 用途: 提炼「OOM 不看 free,看 cgroup 账本」的反直觉案例 + 通用排查方法论

## 一句话定位

**`free` 报空闲 ≠ 系统认为不杀你** —— OOM Killer 看的是**进程所属 cgroup 的「小笼子」账本**,不是整台机器的总账。运维第一反应应该是查「这本账是谁记的」,而不是「这台机器还剩多少」。

---

## 一、案例还原

### 现象

```
大促凌晨 00:07,MySQL 主库挂了,订单全卡
↓
监控 first 反应:free 还有 8G,不可能
↓
dmesg:Out of memory: Killed process 3821 (mysqld)
↓
8G 空闲,但数据库被杀了
```

### 核心思想(作者原话)

> free 有 8G 就以为安全,跟看余额就以为能买房一个道理 —— 得看的是「那笔钱在不在你账上、能不能动」。

> 生产环境,**慢就是快**。出 OOM 别急着加内存,先花五分钟,把系统真正看的那本账翻出来。

### 经典误区图(作者比喻)

```
你住酒店,房间迷你吧满了
前台说"大厅还有 8G 饮料"
→ 跟你房间里渴不渴,两码事

free 是前台的总账
OOM 看的是你房间的迷你吧(cgroup memory.max)
```

---

## 二、三招排查(直接复用作者思路)

### 第一招:看 cgroup 自己的账本

```bash
# cgroup v2
cat /sys/fs/cgroup/<容器>/memory.max        # 笼子上限(比如 8G)
cat /sys/fs/cgroup/<容器>/memory.current    # 当前用了多少
cat /sys/fs/cgroup/<容器>/memory.oom_control # 看 oom_kill 计数(注:v2 已移到 events)

# cgroup v1(老系统)
cat /sys/fs/cgroup/memory/<容器>/memory.limit_in_bytes
cat /sys/fs/cgroup/memory/<容器>/memory.usage_in_bytes
cat /sys/fs/cgroup/memory/<容器>/memory.failcnt
cat /sys/fs/cgroup/memory/<容器>/memory.oom_control
```

**判定 OOM 实锤**:

```
memory.current ≈ memory.max
memory.events.local.oom_kill > 0
或 dmesg: Out of memory: Killed process <pid>
```

**踩坑点(作者强调)**:

- 容器里敲 `free`,**默认显示 host 视角**(除非 cgroup 正确挂载)
- 所以「free 还有 8G」是个**假象** — 那是大厅的账,不是你房间的
- 真要查,**直接看 cgroup 这仨文件**
- Docker/K8s 默认 `cat /sys/fs/cgroup/system.slice/docker-<id>/memory.current` 看容器视角

---

### 第二招:拆 `/proc/meminfo`,揪内核态的「隐形消耗」

```bash
grep -E '^(MemTotal|MemFree|MemAvailable|SReclaimable|SUnreclaim|Slab):' /proc/meminfo
```

**关键字段对照**:

| 字段 | 含义 | OOM 时会动吗 |
|---|---|---|
| `MemTotal` | 总内存 | ❌ 不会 |
| `MemFree` | 完全空闲 | ❌ 不会 |
| `MemAvailable` | **应用层视角「可用」** | ⚠️ 估算,会 |
| `SReclaimable` | 可回收内核缓存(dentry / inode) | ✅ 理论上能还 |
| `SUnreclaim` | **不可回收内核缓存** | ❌ **不会,实打实占着** |
| `Slab` | SReclaimable + SUnreclaim | ⚠️ 拆开看 |

**踩坑点**:

- `free` 的 `buff/cache` 里**混着内核 slab**,你看着 cache 一堆,以为清了就松口气
- 实际上 `SUnreclaim` 那块**纹丝不动**
- OOM 看的是「真能用的」,不是「看着像能用的」
- 大量小文件 + 频繁 `stat` + 容器密度高 → **slab 暴涨**,`SUnreclaim` 悄悄吃掉几个 G
- 案例当晚 `SUnreclaim` 吃了 3G 多 → 这是大块隐形内存

---

### 第三招:查 THP(transparent hugepage)和 swappiness

```bash
cat /sys/kernel/mm/transparent_hugepage/enabled   # 多半是 [always]
grep -i huge /proc/meminfo                         # AnonHugePages 占了多少
cat /proc/sys/vm/swappiness                        # 默认 60
```

**两个雷区**:

| 项 | 默认 | 数据库场景推荐 | 原因 |
|---|---|---|---|
| **THP** | `[always]` | `never` | 分配时要做「页合并」,过程中 STW(全局停顿),Redis/Mongo/MySQL 延迟尖刺;大页一预留,`free` 口径更对不上 |
| **swappiness** | 60 | **1 或 10**(DB 机器) | 默认 60 = 内存一紧先 swap 再 OOM,**慢死**;设 0 = 压力下直接杀进程;DB 折中用 1~10 |

**踩坑点**:

- Redis / Mongo / MySQL 官方文档**都明着写「关 THP」**
- 很多「诡异卡顿 + 随后 OOM」的组合,根子就在 THP 合并
- 别等出了事才想起这行

---

## 三、由「OOM vs free」提炼的**通用「账本思维」**

跟上一篇 [`OpsTroubleshootingDiskGhost.md`](./OpsTroubleshootingDiskGhost.md) 的「账本对账」是同一套底层方法论,**两次事故讲的同一件事**。

### 1. 三大「账本」到底谁说了算

| 账本 | 谁用 | 怎么查 |
|---|---|---|
| **整机的总账** | `free` / `vmstat` | 人眼看,运维心理安慰 |
| **cgroup 的小笼子** | **OOM Killer / Cgroup memory controller** | `/sys/fs/cgroup/.../memory.current`、`memory.max` |
| **应用自己的账** | 数据库 buffer pool / JVM heap | 应用 metrics |

> **运维铁律**:**永远先查「OOM 决策者看的那本账」**,不是「人眼最熟的那本账」。

### 2. OOM Killer 决策的"实际账本"清单

```
OOM Killer 实际看:
1. cgroup memory.current vs memory.max   ← 主决策
2. /proc/meminfo 的 SUnreclaim           ← 内核不可回收
3. oom_score_adj(单进程权重)            ← 谁先被杀
4. THP / swappiness / 内存压缩(zswap)   ← 触发时机

OOM Killer 不看的(尽管你盯着):
✗ free -m 的 available
✗ top 的 RES
✗ 整机 MemAvailable
```

### 3. 通用排查清单(任意"OOM 类"故障)

```bash
# Step 1: 是不是 OOM Killer 干的?
dmesg -T | grep -iE "out of memory|killed process" | tail -20
# 或
journalctl -k --since "10 min ago" | grep -iE "oom|killed"

# Step 2: 谁被杀了?cgroup 视角
grep -E "memory.events|memory.current|memory.max" /sys/fs/cgroup/**/memory.*

# Step 3: 隐形内存消耗(SUnreclaim + slab)
grep -E "^(SReclaimable|SUnreclaim|Slab)" /proc/meminfo

# Step 4: 内核参数健康度
cat /sys/kernel/mm/transparent_hugepage/enabled
cat /proc/sys/vm/swappiness
cat /proc/sys/vm/overcommit_memory  # 0=启发式 1=总是 2=禁止(注意风险)

# Step 5: 单进程 oom_score
cat /proc/<pid>/oom_score
cat /proc/<pid>/oom_score_adj    # -1000(永不杀)~ 1000(优先杀)
cat /proc/<pid>/cgroup          # 归属哪个 cgroup
```

### 4. 紧急止血 vs 长期根治

| 阶段 | 目标 | 典型动作 |
|---|---|---|
| **T+0 ~ 5min: 止血** | 让服务先起来 | 临时调高 cgroup memory.max / kill 不重要进程 / `echo 1 > /proc/sys/vm/drop_caches`(临时释放 page cache,**注意 SUnreclaim 清不掉**) |
| **T+5 ~ 30min: 定位** | 找到根因 | dmesg / cgroup memory.events / SUnreclaim / THP / 应用 buffer pool |
| **T+30min+: 根治** | 不再复发 | 调整 cgroup limit / 关 THP / swappiness / 应用层 buffer 调优 / 加 swap 容量评估 |
| **T+1day: 复盘** | 防止下次 | 加监控(memory.usage / cgroup events)、调容量规划、考虑 NUMA |

### 5. 同类「账本对不上」场景速查(扩充自上一篇)

| 场景 | 账本 1(决策者) | 账本 2(看着像) | 排查命令 |
|---|---|---|---|
| **OOM killer 误杀** | cgroup `memory.current` vs `memory.max` | `free -m` 看着还有 | `dmesg`、`memory.events.local.oom_kill` |
| **磁盘满** | `df` (superblock) | `du` (目录树) | `lsof +L1`、`df -i` |
| **inode 满** | `df -i` | `df -h` 看着有空间 | `df -i`、找小文件 |
| **load 高 CPU 闲** | `runqueue` / `D 状态` | `top` CPU% | `ps -eLf`、`iostat`、`/proc/pressure/io` |
| **带宽满但 idle** | cgroup net_cls / `tc` qdisc | `nload` 整机 | `iftop`、`nethogs`、`ss -ntp` |
| **fd 耗尽** | `fs.file-nr` | `ulimit -n` | `cat /proc/sys/fs/file-nr`、`lsof \| wc -l` |
| **CPU 时间片用完** | cgroup `cpu.cfs_quota_us` / `cpu.max` | `top` CPU% | `cat /sys/fs/cgroup/.../cpu.max` |

---

## 四、预防机制(把救火变常态)

### 1. 监控覆盖 — 三层账本都要看

```yaml
# cgroup 视角(给容器化业务用)
cgroup_memory_usage_percent:    > 80%  warn / > 90% critical
cgroup_memory_oom_kill_count:   rate > 0
cgroup_memory_failcnt:          rate > 0    # v1 only,v2 用 events

# 内核视角(整机和隐形消耗)
meminfo_SUnreclaim_mb:          > 10% of MemTotal
meminfo_anon_hugepages_mb:      ratio(AnonHugePages/MemTotal) > 5%
oom_kills_total:                rate > 0 for 5min

# 应用视角
jvm_heap_used_percent:          > 85%
mysql_buffer_pool_usage:        ratio
redis_used_memory:              ratio(used_memory/maxmemory)
```

### 2. 上线前的 cgroup 健康度 checklist

```bash
#!/bin/bash
# 部署到容器/K8s 前必跑

# 1. cgroup limit 是不是设置合理?(根据业务峰值 × 1.5)
test "$(cat /sys/fs/cgroup/$CGROUP/memory.max)" -gt "$PEAK_MEM_MB""M"

# 2. THP 必须关(数据库类)
test "$(cat /sys/kernel/mm/transparent_hugepage/enabled)" == "[never]"

# 3. swappiness 必须调低(数据库类)
test "$(cat /proc/sys/vm/swappiness)" -lt 30

# 4. 应用进程 oom_score_adj 是不是 -500 以下?(保命)
test "$(cat /proc/$PID/oom_score_adj)" -lt 0

# 5. 监控是否到位(memory.usage / memory.peak / memory.events)
```

### 3. THP / swappiness 调优(标准 SOP)

```bash
# THP 永久关闭
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
# 加到 /etc/rc.local / systemd-tmpfiles / tuned profile 都行

# swappiness 调低(DB 机器推荐 1~10)
sysctl -w vm.swappiness=10
echo "vm.swappiness = 10" >> /etc/sysctl.d/99-db.conf

# 关闭 NUMA balancing(可选,DB 场景)
echo 0 > /proc/sys/kernel/numa_balancing

# tuned profile(推荐:database / latency-performance)
tuned-adm profile latency-performance
```

### 4. K8s 时代的 cgroup 调优要点

| 维度 | 调优点 |
|---|---|
| **QoS 类** | 数据库 / 关键服务 → **Guaranteed**(requests = limits) |
| **memory limit** | 业务峰值 × 1.3~1.5,**不要留太大**(留太大 → 节点压力上来时 cgroup 杀谁先) |
| **oom_score_adj** | 关键进程设 -997(基本永不杀),无关进程设 +1000(替死鬼) |
| **node-level** | kubelet `--eviction-hard=memory.available<500Mi` + `--system-reserved` |
| **sidecar 限制** | 日志收集 / metrics agent 必须有独立 cgroup limit,不能跟主进程抢 |

---

## 五、跟我们的关系

| 关联点 | 用法 |
|---|---|
| **Spring Boot 后端** | JVM heap 用 `-XX:MaxRAMPercentage=70`(不要默认的 25%),**容器 limit 留 30% 给 native memory / direct buffer / metaspace** |
| **MySQL / Redis** | Kylin V10 + MySQL 部署,**必须**关 THP + swappiness=10 + OOM score=-997 |
| **品行者 / ptm Java 应用** | JVM 启动参数固化到 systemd unit / K8s manifest,避免 OOM killer 误杀业务进程 |
| **PVE 主机(10.10.66.208) VM 100** | VM 100 跑日常工作,VM 内应用 OOM 跟 host OOM **不是一回事** — 排查时一定要进 VM 内部看 cgroup |
| **WAF 巡检机器** | 频繁的 curl / python 内存分配 → 关注 SUnreclaim 增长;AkShare / akshare ETL 任务临时吃内存,建议给 cgroup limit + oom_score_adj=-900 |
| **等保 2.0/3.0** | 容量监控要覆盖 **cgroup / container** 视角,不只是整机内存 |

---

## 六、一图总结(给团队传阅)

```
OOM Killer 决策账本 = cgroup memory.current vs memory.max
                       + /proc/meminfo 的 SUnreclaim
                       + 单进程 oom_score_adj

✗ 不要只看 free -m
✗ 不要只看整机 MemAvailable
✗ 不要把 buff/cache 当"可用内存"

✓ 第一反应:这是 cgroup 杀的还是整机杀的?
✓ 第二反应:memory.events.local.oom_kkill > 0 吗?
✓ 第三反应:SUnreclaim 是不是隐形吃了内存?
✓ 第四反应:THP / swappiness 健康吗?

数据库硬性配置:
  THP = never
  swappiness = 1~10
  oom_score_adj = -997
  cgroup memory.max = 业务峰值 × 1.3~1.5
```

---

## 七、与系列上一篇的呼应

```
[OpsTroubleshootingDiskGhost.md]  df vs du 幽灵空间   → 「账本对账」(superblock vs 目录树)
[OpsTroubleshootingOOMCgroup.md]  free vs OOM 误杀    → 「账本对账」(cgroup vs 整机)
                                                  ↓
                              同一个底层方法论:你看到的 ≠ 系统做决定用的
```

> 你看到的指标,不一定是系统做决定用的那本账。
> 慢一点,把账本翻出来再动手,比加 100G 内存都管用。

---

## 参考链接

- 原文: https://mp.weixin.qq.com/s/b7Vur9bhRwPs-PHDsdXBoA
- 作者公众号: 胡哥Linux运维
- 同系列前篇: [df vs du 幽灵空间](./OpsTroubleshootingDiskGhost.md)
- 同系列其他: load 飙高 CPU 闲(占位,待补)
- 内核文档: `Documentation/admin-guide/sysctl/vm.rst`、`Documentation/cgroup-v2.txt`