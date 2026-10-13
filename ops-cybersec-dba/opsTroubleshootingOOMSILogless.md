# 运维思路:进程被 OOM Killer 杀了,应用日志里却什么都没留 —— 「三本账」排查法

> 学习笔记 · 调研时间 2026-10-13
> 调研来源: 微信公众号「胡哥Linux运维」,作者胡登治(RHCA 2015 版,15 年 Linux 运维)
> 原文: https://mp.weixin.qq.com/s/KG6A-RCCa6Br8qO7rMLIgg
> 系列定位: 「Linux 诡异现象排错」系列姊妹篇。上一篇 [`opsTroubleshootingOOMCgroup.md`](./opsTroubleshootingOOMCgroup.md)(free 还有 8G 却 OOM)讲的是**「该杀谁 / 什么时候杀」**;本篇讲**「死了之后去哪找证据」**。
> 一手核验: 内核 `mm/oom_kill.c`(**master + v4.19 双版本逐行比对**) + `Documentation/admin-guide/cgroup-v2.rst`(v4.19 / v5.10 / v5.19 三版比对)+ systemd `NEWS` v237/v243/v252/v259 + systemd v243 `service.h` + rsyslog `runtime/ratelimit.c` + `plugins/imjournal/imjournal.c` + kernel `Documentation/sysctl/kernel.txt`(4.19)
> ⚠️ **麒麟 V10 SP3 用户(kernel 4.19.90)请优先读 §三·五「麒麟专项」**,该节逐条列出与新内核不兼容的命令。

---

## 一句话定位

**SIGKILL 不可捕获,所以「优雅退出日志」在 OOM 场景下天然不存在** —— 日志框架没坏,是你翻错了账本。排障第一课不是「查日志」,而是先确定**谁动的手、这本账记在哪**。

---

## 一、案例还原:凌晨两点的空白

```
凌晨 02:00  监控告警:跑了半年的采集服务挂了
值班同事    翻应用日志 → 最后一行停在 23:47 的正常心跳,之后干干净净
            → 折腾一小时,差点怀疑日志框架坏了
01:58       内核留下的白纸黑字(注意时间早于告警 2 分钟):
            Out of memory: Killed process 23841 (collector)
结论        进程是被 OOM Killer 杀的,而应用日志里一个字都没有
```

### 为什么必然没有?—— 一手核验

内核 [`mm/oom_kill.c`](https://github.com/torvalds/linux/blob/master/mm/oom_kill.c) 里,内核送信号的方式是**直接绕过用户态**:

```c
/* mm/oom_kill.c:943 —— 发信号前一句话注释都没有 */
do_send_sig_info(SIGKILL, SEND_SIG_PRIV, victim, PIDTYPE_TGID);
```

`do_send_sig_info()` 在**内核态**把 SIGKILL 塞进目标进程的信号队列。SIGKILL 的铁律是**不可捕获、不可忽略、不可屏蔽**:

- `signal()` / `sigaction()` 注册的处理函数永远不会被调用
- `atexit` / `__attribute__((destructor))` / defer 清理链全部跳过
- 写缓冲区的最后半条日志直接随进程地址空间一起蒸发

所以「优雅退出日志」不是丢了,是**从来就没有机会产生**。日志框架无辜。

---

## 二、「三本账」框架(全文核心)

排障第一步不是 grep,是**分清这件事归谁记账**:

| 账本 | 记什么 | 不记什么 | 怎么翻 |
|---|---|---|---|
| **应用日志** | 进程生前的事 | **自己的死**(SIGKILL 抓不到) | 应用自己的框架 |
| **systemd 日志** | 「被杀」这个事实 | **凶手是谁**(可能是别人 `kill -9`) | `journalctl -u` |
| **内核日志** | 凶手、动机、现场 | 不记业务语义 | `dmesg` / `journalctl -k` |

> **铁律**:`status=9/KILL` 只能证明「被 SIGKILL 了」,**不能证明是 OOM 干的**。人敲 `kill -9` 也是同一行日志。必须跟内核那本账**时间对得上、PID 对得上**才结案。

---

## 三、第一本账:`dmesg` —— 翻内核的口袋

### 命令

```bash
dmesg -T | grep -iE "oom|killed process"
```

`dmesg` 读的是内核的 **ring buffer**(固定大小的环形缓冲区,新消息挤掉最老的)。`-T` 把「开机至今的秒数」换算成人类可读时间。

### 找到 OOM 记录后重点看 4 处(一手核验:逐版比对 `mm/oom_kill.c`)

**① 抬头行** —— 谁触发的 OOM:

> ⚠️ **本节行号按上游 master 写。Kylin V10 SP3(kernel 4.19.90)的格式串和列数都不一样,见下方「麒麟 V10 SP3 专项」**。

```c
/* master oom_kill.c:458 */
pr_warn("%s invoked oom-killer: gfp_mask=%#x(%pGg), order=%d, oom_score_adj:%d\n", ...);
```

**② 进程清单表** —— 这是「为什么死的是它」的答案所在:

```c
/* master oom_kill.c:425 —— 表头 */
[  pid  ]   uid  tgid total_vm      rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name
```

`oom_score_adj` 分越高越先被杀 → **这一列就是你找的「被杀优先级」**。

> ⚠️ 进程清单的打印受 sysctl `kernel.oom_dump_tasks` 控制(默认值 `1`,4.19 见 `mm/oom_kill.c:54` / `:449`,master 见 `:58` / `:717`)。有些发行版为了省日志量调小过它,看不到清单不代表没杀进程,`Killed process` 那行永远在。

**③ 凶手那一行** —— 整机 OOM vs cgroup OOM 的**唯一分水岭**:

```c
/* master oom_kill.c:1169 —— 一个三目运算符决定全部 */
oom_kill_process(oc, !is_memcg_oom(oc) ? "Out of memory" :
                                 "Memory cgroup out of memory");
/* master oom_kill.c:945 —— 拼上 ": Killed process ..." */
pr_err("%s: Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB, UID:%u pgtables:%lukB oom_score_adj:%d\n", ...);
```

| 内核日志开头 | 含义 | 排查方向 |
|---|---|---|
| `Out of memory: Killed process` | **整机**物理内存耗尽 | 全局泄漏 / cache 爆炸 / slab 吃内存 |
| `Memory cgroup out of memory: Killed process` | **cgroup limit** 到了 | 容器 limit 太小,详见 [`opsTroubleshootingOOMCgroup.md`](./opsTroubleshootingOOMCgroup.md) |

> 「一个字样之差,排查方向完全不同」—— 这是本篇最有价值的一句。

**④ 受害进程的内存画像** —— `anon-rss` 是压物理内存的大头(堆 + 数据段),它爆了基本就是罪魁祸首;`swapents` 非 0 说明还在换页挣扎。

### 四个坑(作者提示 + 一手核验补充)

| 坑 | 说明 | 核验依据 |
|---|---|---|
| **重启即清空** | ring buffer 在内存里,机器一重启就没了 | 内核 ring buffer 设计 |
| **被新记录顶掉** | 内核打印量大时旧记录被挤掉,dmesg 是**第一现场,不是档案库** | 环形缓冲区语义 |
| **容器里看不了** | 默认无 `CAP_SYSLOG` → `Operation not permitted` | 4.19 `Documentation/sysctl/kernel.txt:275-284` 与新版 `kernel.rst` 均写明 `dmesg_restrict=1` 时需要 `CAP_SYSLOG` |
| **`-T` 时间有偏差** | 拿「开机时间 + 运行秒数」倒推,休眠过 / 跑很久会偏 | 建议只看事件**先后次序**,别掐秒 |

`dmesg_restrict` 原文(4.19 路径是 `Documentation/sysctl/kernel.txt`,新版才改名为 `kernel.rst`):

> When `dmesg_restrict` is set to (1), users must have CAP_SYSLOG to use dmesg(8).
> 编译选项 `CONFIG_SECURITY_DMESG_RESTRICT` 决定它的默认值。

---

## 三·五、麒麟 V10 SP3 专项(必读)

我们的生产服务器是 **Kylin Linux Advanced Server V10 SP3**,内核 **4.19.90-89.24.v2401.ky10.aarch64**。它属于 **RHEL 8 血统**(用户态基本对齐 RHEL 8),但内核是 4.19 而非 RHEL 8 的 4.18,**两者在 OOM 日志格式和 cgroup 文件上有实质差异**。

### 3.5.1 OOM 日志格式完全不同(最容易踩的坑)

4.19 的 `Killed process` 格式串**没有 `UID:` 也没有 `oom_score_adj:`**:

```c
/* v4.19 mm/oom_kill.c:864 —— 注意结尾没有 UID、没有 oom_score_adj */
pr_err("Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB\n",
        task_pid_nr(victim), victim->comm, K(victim->mm->total_vm), ...);

/* v4.19 mm/oom_kill.c:433 —— 多了 nodemask,少了 UID */
pr_warn("%s invoked oom-killer: gfp_mask=%#x(%pGg), nodemask=%*pbl, order=%d, oom_score_adj:%hd\n", ...);
```

| 项 | master(5.x / 6.x) | **Kylin V10 SP3(4.19)** |
|---|---|---|
| 凶手前缀 | `Out of memory: Killed process` | **同样适用**(`v4.19:1120-1121` 三目运算符一致) |
| 抬头行含 `nodemask=` | ❌ | **✅ 有**(4.19 有,master 已移除) |
| 抬头行分隔符 | `oom_score_adj**=**%d`(等号) | `oom_score_adj**:**%hd`(**冒号**,类型是 `%hd`) |
| `Killed process` 行含 `UID:` | ✅ | **❌ 无** |
| `Killed process` 行含 `oom_score_adj:` | ✅ | **❌ 无** |
| 进程清单**列数** | 12 列(含 `rss_anon` / `rss_file` / `rss_shmem`) | **8 列**(`v4.19:404`,无三个 rss 分项) |
| 进程清单表头 | `... rss rss_anon rss_file rss_shmem pgtables_bytes swapents ...` | **`... rss pgtables_bytes swapents oom_score_adj name`** |

> ⚠️ 分隔符差异(`=` vs `:`)意味着**跨版本的 grep 规则不能直接复用**。写自动化解析脚本时,用 `awk '{print $NF}'` 取进程名这种相对位置解析,比匹配具体字段名稳。

**实战影响**:

```bash
# ❌ 在麒麟上这样 grep 不到 —— 4.19 格式里根本没有这两个字段
dmesg -T | grep oom_score_adj        # 只能匹配到抬头行,匹配不到 Killed process 行

# ✅ 4.19 上要看被杀优先级,只能从进程清单表的最后一列看
dmesg -T | grep -A 30 "invoked oom-killer" | tail -20

# ✅ 4.19 判定被杀的 UID,用 ps 反查,不能从日志里读
dmesg -T | grep "Killed process" | awk '{print $4}'
```

> **结论**:「从 `Killed process` 那一行读出 `oom_score_adj`」这个动作,在麒麟 V10 SP3 上**做不到**。必须到进程清单表里找。这也是为什么我把「进程清单受 `oom_dump_tasks` 控制」那条单独标了 ⚠️ —— 在麒麟上如果这个 sysctl 被调成 0,你会**同时失去被杀进程的身份信息和优先级分数**。

### 3.5.2 cgroup 文件:哪些能用,哪些会报错

4.19 支持 cgroup v1/v2 **共存**(RHEL 8 血统通常只挂 v2,Kylin V10 SP3 需现场确认)。**文件可用性逐个核对**:

| 文件 / 字段 | Kylin V10 SP3 (4.19) | 说明 |
|---|---|---|
| `memory.events` 的 `oom` / `max` / `high` | ✅ 有 | `v4.19 cgroup-v2.rst:1093-1135` |
| `memory.events` 的 **`oom_kill`** | ✅ **有** | 铁证字段,4.19 已在(行 1130) |
| `memory.events.local` | ❌ **没有** | 该文件 **v5.10 才引入**,4.19 上写它 = `No such file or directory` |
| `oom_group_kill` 字段 | ❌ 没有 | 同上 |
| **`memory.peak`** | ❌ **没有** | `memory.peak` **v5.19 才引入**,麒麟上 `cat` 会报 `No such file or directory` |
| `memory.high` | ✅ 有 | 4.19 起可用(`cgroup-v2.rst:1049`) |
| `memory.max` / `memory.current` | ✅ 有 | 基础文件 |
| `memory.swap` | ✅ 有 | 4.19 起可用 |
| cgroup v1 的 `memory.failcnt` | ⚠️ 仅 v1 模式 | 见 `opsTroubleshootingOOMCgroup.md` |

**因此 §5.3 那段在麒麟上必须改成**:

```bash
# ❌ 麒麟 V10 SP3 上三条都会报错
cat /sys/fs/cgroup/system.slice/collector.service/memory.peak
cat .../memory.events.local     # 5.10+
grep oom_group_kill .../memory.events

# ✅ 麒麟上能用的
cat /sys/fs/cgroup/system.slice/collector.service/memory.events   # 看 oom_kill
cat /sys/fs/cgroup/system.slice/collector.service/memory.max
cat /sys/fs/cgroup/system.slice/collector.service/memory.current
cat /sys/fs/cgroup/system.slice/collector.service/memory.high    # 回收阈值
```

> `memory.peak` 缺失有实际影响:老内核上没有「峰值」记录,事后无法回答「这个服务历史峰值到底多高」。**容量规划只能靠 `memory.events` 的 `max` 计数 + `memory.high` 触发频次反推**,别指望 `memory.peak`。

### 3.5.3 systemd 侧:版本相关行为(**以现场为准**)

麒麟 V10 SP3 用户态对齐 **RHEL 8**,systemd 大版本落在 **239~243** 区间(随 SP 补丁级别浮动)。

> ⚠️ **这一点我没有拿到麒麟官方 version 清单做硬证据**,是基于「RHEL 8 血统 + systemd 243 发布于 2019-10」的推断。**上生产前请先跑 `systemctl --version` 确认真实值**,下面表格按推断版本给出行为对照。

| 项 | 需要的版本 | 239~242 | 243 | 备注 |
|---|---|---|---|---|
| `journalctl --grep=` | **237** | ✅ 可用 | ✅ 可用 | ≥237 即有,本区间**不需要退回 `grep` 管道** |
| `Storage=auto` 默认行为 | <259 是 auto | ⚠️ **是 auto** | ⚠️ **是 auto** | `/var/log/journal` 不存在就写内存盘 —— **麒麟上最该先做的事** |
| `OOMScoreAdjust=` | 早已支持 | ✅ 可用 | ✅ 可用 | 关键服务防误杀用这个 |
| `OOMPolicy=` | **243** | ❌ **写了会启动失败** | ✅ 可用 | 243 以下写进 unit 文件是**硬错误**,systemd 解析 unit 时报未知指令 |
| `systemd-tmpfiles --prefix=` | **212** | ✅ 可用 | ✅ 可用 | 早于本区间 |
| `journalctl -b -1` | 早已支持 | ✅ 可用 | ✅ 可用 | **依赖持久化**,先做 §4.3 |

```bash
# 上生产前必跑这一条,把推断换成事实
systemctl --version | head -1
grep -c 'OOMPolicy' /etc/systemd/system/*.service 2>/dev/null   # 已有 unit 里若出现先清理
```

**麒麟上 journald 持久化的实际执行**(因为默认是 auto,这一步是必须的):

```bash
# 1. 先确认当前到底是落在哪(决定你要不要做)
systemctl show systemd-journald -p ExecStart | grep -o '/[^ ]*log[^ ]*journal' | sort -u
ls -ld /var/log/journal 2>/dev/null || echo "⚠️ /var/log/journal 不存在 → 现在写的是 /run/log/journal → 重启即丢"

# 2. 做持久化(二选一,推荐第 2 种可追溯)
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald

# 或改配置文件
printf '[Journal]\nStorage=persistent\n' | sudo tee -a /etc/systemd/journald.conf
systemctl restart systemd-journald
```

> **系统族 CLI 差异**:麒麟 V10(`klas-root`,见 [`kylinV10DisableIPv6.md`](./kylinV10DisableIPv6.md))部分服务管理走 systemd,部分仍用 SysV 的 `service`/`chkconfig`。`journalctl -u <unit>` 只对 systemd 管理的 unit 有效;若服务是 SysV 的,改查 `journalctl -t <syslog-tag>` 或直接 `grep /var/log/messages`。

### 3.5.4 麒麟上可直接用的完整排查脚本

```bash
#!/bin/bash
# Kylin V10 SP3 OOM 排查(4.19 内核,已避开 memory.peak / events.local)
echo "===== 0. 环境确认(先跑这个,别跳) ====="
uname -r
systemctl --version | head -1
stat -fc %T /sys/fs/cgroup/            # cgroup2fs = v2 统一; tmpfs = v1(混合模式)
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "dmesg_restrict: 读不到(4.19 路径正常)"

echo "===== 1. 内核账:被杀的进程 ====="
dmesg -T | grep -iE "out of memory|killed process" || echo "本机未见 OOM 记录"

echo "===== 2. 抬头行(4.19 特有 nodemask) ====="
dmesg -T | grep -A 40 "invoked oom-killer" | grep -E "invoked oom-killer|task=|^\[" | head -30

echo "===== 3. 进程清单表(4.19 只有 8 列,优先级在倒数第 2 列) ====="
dmesg -T | grep -E "^\[ *[0-9]+\] " | tail -20

echo "===== 4. 被杀进程身份反查(4.19 日志里没有 UID) ====="
dmesg -T | grep "Killed process" | tail -5 | sed 's/[^0-9]\([0-9]\+\).*/PID=\1/'
ps -o pid,user,comm,rss -p <上面的PID>

echo "===== 5. cgroup 视角(仅 v2 且已确认是 v2) ====="
if [ "$(stat -fc %T /sys/fs/cgroup/)" = "cgroup2fs" ]; then
  D=/sys/fs/cgroup/system.slice/<服务名>.service
  [ -d "$D" ] || D=$(systemctl show -p ControlGroup --value <服务名> 2>/dev/null)
  cat "$D"/memory.events        # oom_kill > 0 = 铁证
  cat "$D"/memory.max
  cat "$D"/memory.current
  cat "$D"/memory.high
else
  echo "当前是 cgroup v1(混合模式),走 memory.failcnt / memory.oom_control"
fi

echo "===== 6. systemd 账 ====="
systemctl show <服务名> -p NRestarts,ExecMainStatus,ExecMainCode,Result
journalctl -u <服务名> -e | tail -20
journalctl --list-boots | tail -3   # 只有做了持久化才有意义

echo "===== 7. journald 是否落盘 ====="
ls -ld /var/log/journal 2>/dev/null \
  && echo "✅ 已落盘" \
  || echo "❌ 未落盘,重启后 OOM 证据全丢 —— 见笔记 §4.3"
```

### 3.5.5 麒麟 V10 SP3 上**不能**用的命令速查

| 命令 / 文件 | 状态 | 原因 |
|---|---|---|
| `cat .../memory.peak` | ❌ | 4.19 没有,v5.19 才引入 |
| `cat .../memory.events.local` | ❌ | 4.19 没有,v5.10 才引入 |
| `memory.events` 里找 `oom_group_kill` | ❌ | 4.19 无该字段 |
| 从 `Killed process` 行读 `oom_score_adj` | ❌ | 4.19 格式串不含该字段 |
| 从 `Killed process` 行读 `UID:` | ❌ | 4.19 格式串不含该字段 |
| `OOMPolicy=`(未先确认版本) | ⚠️ | systemd 243 才加,239~242 写进 unit 会导致**服务起不来** |
| `journalctl -k --grep=` | ✅ 可用 | 麒麟在 239~243 区间,≥237 即有;保险起见先 `systemctl --version` |

---

## 四、第二本账:`journalctl` + `/var/log/*` —— 档案库

### 4.1 journald 存档

```bash
journalctl -k --grep="oom|Killed process" --since "2 days ago"
```

`-k` 只看内核消息,内容等价 dmesg,但读的是 **journald 落盘的存档**(dmesg 重启就丢,这里能翻更早)。

> ⚠️ **`--grep` 是 systemd 237 才加的参数**(一手核验:systemd `NEWS` v237 原文 `journalctl gained a new --grep= option to list only entries in which ...`)。v237 发布于 **2018-01-28**。RHEL 7 / CentOS 7 是 systemd **219**,**没有这个参数**,只能退回:
> ```bash
> journalctl -k | grep -iE "oom|killed process"
> ```

### 4.2 发行版传统日志文件

| 发行版系 | 内核日志文件 |
|---|---|
| RHEL / CentOS / Rocky | `/var/log/messages` |
| Debian / Ubuntu | `/var/log/kern.log` |

翻更早的历史要 grep 轮转日志(压缩过的用 `zcat`):

```bash
grep -i oom /var/log/messages-*
zcat -f /var/log/messages-*.gz | grep -i oom
```

### 4.3 两个「日志没留」的真实暗坑

#### 坑一:journald 默认可能**根本没落盘**

`Storage=` 的四种取值(核验自 freedesktop `journald.conf` 官方手册):

| 值 | 行为 |
|---|---|
| `volatile` | 只写内存 `/run/log/journal`,**重启即丢** |
| `persistent` | 优先写盘 `/var/log/journal`,早期启动 / 磁盘不可写时回落内存 |
| `auto` | **`/var/log/journal` 存在就等于 persistent,不存在就等于 volatile** —— 目录的存在与否决定行为 |
| `none` | 全丢(转发到 console / syslog socket 仍工作) |

默认值的**版本变化**(这是原文没说清、但很关键的一条):

| systemd | 默认 Storage |
|---|---|
| ≤ v252 | **`auto`** —— `/var/log/journal` 目录在不在,全凭运气 |
| **v259 起** | **`persistent`**(NEWS v259 "Feature Removals and Incompatible Changes": `The default storage mode for the journal is now 'persistent'`) |

**也就是说**:老机器上没人手动 `mkdir /var/log/journal`,journald 就一直写内存盘,重启后连 `--since "2 days ago"` 都翻不出东西。**这不是「日志没留」的玄学,是目录不存在导致的确定性行为。**

持久化的标准三步(两种写法任选):

```bash
# 写法 A:直接建目录
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald

# 写法 B:改配置文件(推荐,可追溯)
# /etc/systemd/journald.conf
#   [Journal]
#   Storage=persistent
systemctl restart systemd-journald
```

> `systemd-tmpfiles --prefix=` 这个参数**从 systemd 212 才引入**(核验自 freedesktop `systemd-tmpfiles` 手册 "Added in version 212"),CentOS 7(219)可以用,更老的系统请改用写法 B。

持久化之后,重启也能破案 —— **这是重启之后翻案的关键一招**:

```bash
journalctl -k -b -1      # -b -1 = 上一次开机(previous boot)
journalctl --list-boots  # 先看有哪些次开机记录
```

#### 坑二:rsyslog `imjournal` 会「超速丢件」

转发的这一份确实有速率限制。**一手核验(rsyslog 源码)**:

```c
/* plugins/imjournal/imjournal.c:1700-1701 —— 默认值写死 */
if (cs.ratelimitInterval == -1) cs.ratelimitInterval = 600;
if (cs.ratelimitBurst == -1)    cs.ratelimitBurst = 20000;
/* :1350 */
ratelimitSetLinuxLike(ratelimiter, cs.ratelimitInterval, cs.ratelimitBurst);
```

即 **`Ratelimit.Interval=600` / `Ratelimit.Burst=20000`**(10 分钟 2 万条)。日志里的丢件提示(核验自 `runtime/ratelimit.c:2395`):

```c
snprintf(msgbuf, sizeof(msgbuf),
         "%s: %u messages lost due to rate-limiting (%u allowed within %u seconds)",
         ratelimit->name, ratelimit->missed, ...burst, ...interval);
```

> **重要澄清(原文未提及)**:丢的只是 rsyslog 转发到 `/var/log/messages` 的**这一份**,**journald 自己的存档不受影响**。所以 messages 里查不到的时候,`journalctl -k` 往往还有 —— **两路互相备份**。这正是把「两路都查」写成标准动作的理由。
>
> 另外,`journald` **自己**也有独立的一套限速(`RateLimitIntervalSec=30s` / `RateLimitBurst=10000`,核验自 journald.conf 手册 "Defaults to 10000 messages in 30s"),它是**按 service 分别计算**的。这是第三道防线,和 imjournal 的限速不是同一套。

---

## 五、第三本账:systemd 的死亡证明

```bash
systemctl status collector              # collector 换成你自己的服务名
journalctl -u collector -e              # -e = 跳到末尾
systemctl list-units --type=service --state=running   # 不确定服务名先列出来
```

服务被 OOM 杀掉后会出现:

```
Main process exited, code=killed, status=9/KILL
```

翻译:主进程被 9 号信号(SIGKILL)杀了。**但 systemd 只证明「被杀」,不指认凶手。**

### 5.1 一手核验:这条日志是怎么拼出来的

systemd `src/shared/unit-result.c` 里,退出的**代码类型**和**状态值**是两个独立字段:

```c
{ "ExecMainCode",   "i", NULL, offsetof(UnitResult, exit_code)    },
{ "ExecMainStatus", "i", NULL, offsetof(UnitResult, exit_status)  },
```

拼串逻辑在同文件第 72-80 行:

```c
"code=%s, status=%i/%s",
    strna(sigchld_code_to_string(u->exit_code)),   // → "killed"（被信号杀）
    u->exit_status,                                 // → 9
    strna(u->exit_code == CLD_EXITED ?
          exit_status_to_string(u->exit_status, EXIT_STATUS_FULL) :  // 正常退出码路径
          signal_to_string(u->exit_status))                            // 信号路径 → "KILL"
```

```c
/* src/core/dbus-service.c:398 */
SD_BUS_PROPERTY("NRestarts", "u", bus_property_get_unsigned, offsetof(Service, n_restarts), ...)
```

所以 `code=killed` = `CLD_KILLED`(被信号终止),`status=9` = 信号编号。**两者分开存储**,这解释了为什么单看 `status` 会误判(退出码 9 和信号 9 完全不是一回事)。

### 5.2 服务配了 `Restart=always` 怎么办

进程早被拉起来了,当前状态看不出问题。要看**历史**:

```bash
systemctl show collector -p NRestarts,ExecMainStatus
systemctl show collector -p ExecMainCode,ExecMainStatus,NRestarts,Result
```

| 属性 | 含义 |
|---|---|
| `NRestarts` | 被自动拉起的次数 —— 半夜反复重启的元凶 |
| `ExecMainStatus` | 上次主进程的退出状态,SIGKILL 时 = `9` |
| `ExecMainCode` | 退出类型,`1` = CLD_KILLED(被信号杀)、`0` = CLD_EXITED(正常退出) |
| `Result` | `oom-kill` / `exit-code` / `signal` / `timeout` 等结论性字段 |

### 5.3 cgroup v2 的铁证

```bash
cat /sys/fs/cgroup/system.slice/collector.service/memory.events
```

核验自 `Documentation/admin-guide/cgroup-v2.rst:1525-1535`:

| 字段 | 含义 |
|---|---|
| `max` | 用量即将越过 max 边界的次数 |
| `oom` | 用量到达 limit、分配即将失败的次数 |
| **`oom_kill`** | **该 cgroup 内被任何 OOM killer 杀掉的进程数** |
| `oom_group_kill` | 发生 group OOM 的次数 |

**`oom_kill > 0` = 这个服务被 OOM 杀过的铁证。** 配套看:

> ⚠️ **`memory.peak` 是 v5.19 才引入的**。麒麟 V10 SP3(4.19)上 `cat memory.peak` 会报 `No such file or directory`;`memory.events.local`(v5.10+)同样不存在。老内核上可用的是下面这四个。详见 §三·五。

```bash
cat /sys/fs/cgroup/system.slice/collector.service/memory.high   # 回收阈值
cat /sys/fs/cgroup/system.slice/collector.service/memory.max    # 硬上限
cat /sys/fs/cgroup/system.slice/collector.service/memory.current # 当前用量
cat /sys/fs/cgroup/system.slice/collector.service/memory.peak   # 峰值(v5.19+,老内核无)
```

> cgroup v1(老系统)对应文件是 `memory.failcnt` 和 `memory.oom_control`,详见 [`opsTroubleshootingOOMCgroup.md`](./opsTroubleshootingOOMCgroup.md) 的 cgroup v1 段。

---

## 六、容器 / K8s 里的版本

容器内 `dmesg` 看不了(无 `CAP_SYSLOG`),**容器视角的证据在 kubelet 那边**:

```bash
kubectl describe pod <pod名>
```

```
Last State: Terminated, Reason: OOMKilled, Exit Code: 137
```

内核视角的完整记录要**登上 Pod 所在的节点**再 `journalctl -k`。

### `137` 这个魔数(重要,原文说得不够准)

| 项 | 值 |
|---|---|
| 137 = 128 + 9 | shell 惯例:`128 + 信号编号` |
| 9 = SIGKILL | 确实是被 SIGKILL 干掉的 |
| **但** | **人为 `kill -9` 也是 137** —— 137 只说明「被 SIGKILL」,**不说明是 OOM** |

**必须跟内核日志联动确认。** 这个坑特别值得记:很多监控只配了「exit code 137 → OOM 告警」,结果把人为 kill 和 OOM 混在一起,白查半天。

在 K8s 里还有一个更准确的字段:**`Reason: OOMKilled`** 是 kubelet 根据 cgroup 的 `memory.events` / `oom_kill` 计数自己判定的,**比 exit code 可信**。

---

## 七、防患于未然:三件该提前做的事

### 1. journald 持久化(见 §4.3)

老机器上 `Storage=auto` + `/var/log/journal` 不存在 = 内存盘,重启即丢。这是第一件事。

### 2. 关键服务调低 `OOMScoreAdjust`

```ini
# /etc/systemd/system/collector.service
[Service]
OOMScoreAdjust=-500
```

核验自 freedesktop `systemd.exec` 手册原文:

> Takes an integer between **-1000** (to disable OOM killing of processes of this unit) and **1000** (to make killing of processes of this unit under memory pressure very likely). If not specified, defaults to the OOM score adjustment level of the service manager itself, which is normally at **0**.

配套的现代做法是 **`OOMPolicy=`**(systemd 243+):决定 systemd 收到内核 OOM 通知后**自己**要不要杀自己的进程(`continue` / `stop` / `kill`),以及是否要做 prekill hook。`OOMScoreAdjust` 调的是**内核选人**的权重,`OOMPolicy` 管的是**被杀之后的反应**,两者互补。

### 3. 监控把 exit code 137 做成告警(但要带条件)

```yaml
# ✅ 正确:137 + 内核日志 OOM 记录同时满足才告警
- alert: ContainerOOMKilled
  expr: |
    (container_last_seen{...} != 0)
    and increase(kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}[5m]) > 0
  # 优先用 Reason=OOMKilled,而不是 exit_code=137

- alert: ExitCode137WithoutOOM
  expr: |
    exit_code_137_total > 0
    and rate(node_kernel_oom_kill_total[5m]) == 0   # 内核这边没杀 → 大概率是人干的
  annotations:
    summary: "exit 137 但内核无 OOM 记录 —— 大概率人为 kill,别浪费排查时间"
```

> **反向告警更有价值**:137 出现但内核日志没有 OOM 记录 = 人为 `kill -9`,直接转查发布/运维操作记录,省掉一次无头绪的内存排查。

---

## 八、进阶:用户态守护进程 earlyoom

内核 OOM 触发时是**瞬时决策 + 立刻 SIGKILL**,中间没有任何缓冲窗口。`earlyoom` 是用户态守护进程,内存吃紧到阈值时**在内核动手之前先杀进程**(按 `oom_score_adj` 排序挑倒霉蛋),给你留出一个处理窗口。

与 systemd 官方的 `systemd-oomd` 是同一思路的两个实现:前者靠 cgroup PSI + swap/内存压力,后者基于 cgroup v2 的 `memory.pressure` + swap 阈值。两者都是「提前动手」,不改变内核 OOM 的最终决定权。

---

## 九、一图总结

```
进程被 OOM 杀了,应用日志里什么都没留
                ↓
别怪日志框架 —— SIGKILL 是 do_send_sig_info() 从内核态硬塞的
                         应用连"我要死了"都来不及写
                ↓
三本账,一本一本翻:

① 内核账(dmesg / journalctl -k)   ← 凶手、动机、现场,只有这本能指认 OOM
   Out of memory:              → 整机 OOM
   Memory cgroup out of memory: → cgroup OOM  ← 一个字之差,方向全反

② systemd 账(journalctl -u)      ← 只证明"被 SIGKILL 杀"
   status=9/KILL  ≠  是 OOM 干的  ≠  是人 kill -9 干的

③ 应用账(应用自己的日志)         ← 记不了自己的死,这本永远查不出 OOM

结论只有两种,别自欺:
  ✓ 内核日志有 OOM 记录 + 时间 PID 对得上 → 结案
  ✗ 只有 137 / 9/KILL,内核无 OOM 记录     → 大概率人为 kill,别往内存上查
```

---

## 十、跟我们的关系

| 关联点 | 用法 |
|---|---|
| **Macmini 本机(launchd 而非 systemd)** | 这套命令**不能直接照搬** —— macOS 没有 `dmesg` / `journalctl` / `OOMScoreAdjust`。等价物是 `log show --predicate 'eventMessage contains "memorystatus"'`(jetsam)和 `vm_stat` / `memory_pressure`。**但「三本账」的思维通用**:应用日志(自己的) / launchd 日志(`log show --predicate 'process == "xxx"'`) / 内核日志(`log show --style compact --predicate 'sender == "kernel"'`) 三层对照 |
| **Linux 服务器 / Kylin V10 等保机** | 上线 checklist 加一条:`/var/log/journal` **必须存在**,否则重启后 OOM 证据全丢(systemd ≤252 默认 `Storage=auto`)。**麒麟 V10 SP3 正是这个状态,见 §三·五** |
| **麒麟 V10 SP3 生产机(kernel 4.19.90)** | **本篇 §三·五 是专机专用的执行版**。三条必记:① 日志格式与新内核不同,**不能**从 `Killed process` 行读 `oom_score_adj` / `UID`;② `memory.peak` / `memory.events.local` **不存在**,别照抄 §5.3;③ `OOMPolicy=` 写进 unit 前必须先 `systemctl --version`(243 才有) |
| **CentOS 7 / RHEL 7(systemd 219)** | 查内核日志**不能用 `journalctl -k --grep=`**(v237 才加的),必须退回 `journalctl -k \| grep`。写脚本时按 `systemctl --version` 探测 |
| **容器化业务 / K8s** | 监控告警优先用 `Reason: OOMKilled`,不要只用 exit code 137;宿主机上给关键服务配 `OOMScoreAdjust=-500`(内核选人)+ `OOMPolicy=kill`(被杀后的反应) |
| **VPS / 云主机(纯调度编排)** | 我们 VPS 上没有重负载推理,OOM 概率低,但**飞书 gateway 3 个进程(coder / curator / stock)** 是长期常驻服务,值得给关键的设 `OOMScoreAdjust` + 确认 journald 持久化,防止某天被误杀后查不出原因 |
| **通用方法论** | 「先定位是谁记账的,再翻账」 —— 跟 [`opsTroubleshootingOOMCgroup.md`](./opsTroubleshootingOOMCgroup.md)(cgroup vs 整机)和 [`opsTroubleshootingDiskGhost.md`](./opsTroubleshootingDiskGhost.md)(superblock vs 目录树)是同一套「账本思维」。**你看到的指标,不一定是系统做决定用的那本账** |

---

## 参考链接

**原文与系列**

- 原文《进程被 OOM Killer 杀了,日志里却什么都没留》: https://mp.weixin.qq.com/s/KG6A-RCCa6Br8qO7rMLIgg
- 作者公众号: 胡哥Linux运维(胡登治,RHCA 2015 版)
- 同系列姊妹篇:[free 还有 8G,OOM 却杀了我的数据库](./opsTroubleshootingOOMCgroup.md) ← 讲「为什么杀」
- 同系列前篇:[df 说满了,du 说没满](./opsTroubleshootingDiskGhost.md) ← 讲「账本对账」

**内核源码 — master(一行号均按 master)**

- `mm/oom_kill.c` — `:425` 进程清单表头、`:458` invoked oom-killer、`:945` Killed process、`:943` `do_send_sig_info(SIGKILL, ...)`、`:1169` 整机/cgroup OOM 分水岭、`:58`/`:717` `oom_dump_tasks`
- `Documentation/admin-guide/cgroup-v2.rst:1525-1535` — `memory.events` 字段定义
- `Documentation/admin-guide/sysctl/kernel.rst:253-264` — `dmesg_restrict` / `CAP_SYSLOG`

**内核源码 — v4.19(麒麟 V10 SP3 实际内核,行号完全不同,勿混用)**

- `v4.19 mm/oom_kill.c` — `:404` 进程清单表头(8 列)、`:433` invoked oom-killer(**含 `nodemask`**)、`:864` Killed process(**无 UID / 无 oom_score_adj**)、`:862` `do_send_sig_info(SIGKILL, SEND_SIG_FORCED, ...)`、`:1120-1121` 整机/cgroup OOM 分水岭、`:54`/`:449` `oom_dump_tasks`
- `v4.19 Documentation/admin-guide/cgroup-v2.rst` — `:1049` `memory.high`、`:1061` `memory.max`、`:1093-1135` `memory.events`(**`oom_kill` 在 `:1130`,已存在**)
- `v4.19 Documentation/sysctl/kernel.txt:275-284` — `dmesg_restrict` / `CAP_SYSLOG`(4.19 阶段该文件名为 `.txt`,新版才改名 `.rst`)

**版本引入时间线(麒麟对照用)**

| 特性 | 引入版本 | 4.19 / 麒麟 |
|---|---|---|
| `memory.events` 的 `oom_kill` | 很早 | ✅ 有 |
| `memory.events.local` | **v5.10** | ❌ 无 |
| `memory.peak` | **v5.19** | ❌ 无 |
| `oom_group_kill` 字段 | 晚于 4.19 | ❌ 无 |

**systemd 文档与源码(一手核验)**

- `journalctl --grep=` 引入版本:**systemd v237**(2018-01-28,`NEWS` 原文 "journalctl gained a new --grep= option")
- `Storage=` 默认值变更:**systemd v259** 起默认从 `auto` 改为 `persistent`(`NEWS` v259)
- `systemd-tmpfiles --prefix=` 引入版本:**systemd 212**(freedesktop 手册 "Added in version 212")
- `OOMPolicy=` 引入版本:**systemd 243**(实测 `v243 src/core/service.h:194` 已有 `OOMPolicy oom_policy;`,v243 之前无)
- journald 限速:`RateLimitIntervalSec=30s` / `RateLimitBurst=10000`(按 service 分别计算,journald.conf 手册)
- `OOMScoreAdjust=` / `OOMPolicy=`: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- systemd 最新版:**v262**(2026-09-22 发布)

**rsyslog 源码(一手核验)**

- `plugins/imjournal/imjournal.c:1700-1701` — `Ratelimit.Interval=600` / `Ratelimit.Burst=20000` 默认值
- `runtime/ratelimit.c:2395` — `"%s: %u messages lost due to rate-limiting (%u allowed within %u seconds)"`

**延伸阅读**

- systemd 各版本 NEWS: https://github.com/systemd/systemd/blob/main/NEWS
- journald.conf 手册: https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html
- systemd.exec 手册: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- cgroup v2 文档: https://docs.kernel.org/admin-guide/cgroup-v2.html
- `earlyoom`: https://github.com/rvoicilas/earlyoom
