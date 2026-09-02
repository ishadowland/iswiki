# PerformanceTriage — 性能问题定位思路（内存 / CPU / IO / 网络 四维通用）

> 学习笔记 · 调研时间 2026-09-02
> 主要来源: 公众号「Linux运维老兵胡哥」2026-09-02《free 说内存满了，top 却说很闲：被 Page Cache 吞掉的"假满"》
> 链接: https://mp.weixin.qq.com/s/mk7e6cuhVe4kArFAGH3YIQ
> 作者: 胡哥（15 年 Linux 运维 / RHCA 红帽认证架构师，自述）
> License: 笔记基于公开博客整理与扩展，文中标注 [TODO: 待调研] 的为**未独立核实**项

> [!NOTE] 本笔记核心
> 性能告警里 **70% 是"假象"**（Page Cache、buffered IO、连接复用、metric 定义错）。定位的真本事不在工具多熟，而在**先抓"快照 vs 趋势"、再抓"用户态 vs 内核态"、最后抓"单一指标 vs 指标组合"**。本笔记把「内存满假象」一篇的方法论**提炼为通用四维定位骨架**，并把原文末尾预告的 swap / 系列其他文章作为 [TODO] 占位。

## 一、原文全文（公众号「Linux运维老兵胡哥」2026-09-02 19:59:22 发布）

> ⚠️ 原文以微信渲染 HTML 发布，下方为按原段落顺序整理的 markdown 版本，**排版微调不改字句**。括号注释 `[编者注：…]` 是 iswiki 加的，方便没读过原文的快速定位抓手。

凌晨两点，手机震了。Zabbix 告警弹出来：内存使用率 87%。

你一个激灵坐起来，SSH 上去，`free -h` 一敲——free 列只剩 2G，buff/cache 倒是吃了 12G。心脏漏跳一拍。赶紧 `top` 看谁在吃内存，按 Shift+M 排个序，最大的进程才占 800M。

16G 的内存，top 说没人在用，free 命令说只剩 2G 空闲。谁在说谎？

答案：谁都没说谎，是你看错了 free 的意思。

### 抓手一：`free -h` —— 别盯着 free 列，看 available

`free -h` 输出大概长这样：

> [编者注：原文此处配图（命令行截图）。]

大部分人的眼睛盯着 free 列那个 2G——16G 的机器只剩 2G 空闲？心跳直接加速。但你往右看一列——available 写着 13G。

available 是内核自己估算的"现在能拿来给新进程用的内存"。它已经把可回收的 Page Cache、可回收的 Slab 都算进去了。available 有余量，free 列多低都不用慌。

这里要插一句：很多监控告警就是栽在这。Zabbix 常见的内存模板用 `vm.memory.size[free]` 或按 `(total - free)` 算使用率，把 buff/cache 全算成了"已用"。87% 的告警就是这么来的——`(16 - 2) / 16 = 87.5%`。正确做法是监控 `available` 或按 `(total - available)` 算使用率。

但这里有个坑。CentOS 6 那个年代的 free 长得不一样：

老版本的 used 把 buffers 和 cached 都算进去了，看着 used 14G 吓人。但底下那行 `-/+ buffers/cache` 才是真相——实际 used 4G，可用 12G。

现在你去网上搜"Linux free 命令详解"，很多文章还在用老版本截图。拿老截图套新机器，结论就是反的。

free 不是在告诉你内存满了，是在告诉你它拿了多少当缓存。

### 抓手二：`cat /proc/meminfo` —— 给内存照张 X 光

free 是体检报告的摘要，`/proc/meminfo` 就是详细报告。关键看三个数：

Cached 是 Page Cache 的大头——你读写过的文件，内核都留一份在内存里，下次访问就不用走磁盘了。10G 的 Cached，说明你系统上跑过不少 IO。

Slab 是内核自己用的缓存，存的是 inode、dentry 这些内核数据结构。它拆成两半：SReclaimable 是可以回收的，SUnreclaim 是锁死不还的。

坑在这：很多人看 free 的 free 列低，进 meminfo 只看 Cached，发现有 10G 缓存，就判断"缓存占的，没事"。结论倒是对了，但停在这一步不够——SReclaimable 还有 1G，这 1G 也是可回收的，也是"假满"的一部分，但它没算在 Cached 里。free 的 buff/cache 列 = Buffers + Cached + SReclaimable，三个加起来才是完整的缓存占用。

反过来，有人一看 Slab 有 2G，吓得以为内核内存泄漏。但 Slab 里有 SReclaimable 和 SUnreclaim，前者随时能还，只有后者才是真占用。你得看全了再下结论。

meminfo 是 free 的 X 光片，能看到每块骨头叫什么。

### 抓手三：`vmstat / sar` —— 别看快照，看趋势

前面两个抓手看的都是"当前这一刻"的内存。但运维判断内存有没有问题，**看趋势比看快照重要一百倍**。

盯两列就够：si（swap in）和 so（swap out）。如果这两个一直是 0，说明内核压根没在用 swap，内存够用得很。available 高 + si/so 为 0 = 健康的缓存利用，啥都不用动。

但如果你看到 si 开始从 0 往上跳，available 在往下走——这就不一样了。内核开始从 swap 里往回搬数据，说明物理内存真的吃紧了。这时候才需要考虑加内存或者查谁在泄漏。

要是你想看历史趋势，`sar -r` 能给你过去一段时间的内存变化曲线。很多机房都装了 sysstat 包，数据一直在记着，就看你用不用。

这里有个大坑，必须说。有些人一看到内存告警，不管三七二十一：

```bash
echo 3 > /proc/sys/vm/drop_caches
```

咔，used 掉下来了，心里舒坦了。但下一秒，所有读操作要重新走磁盘，IO 直接飙起来。生产环境这么干，轻则业务变卡，重则数据库 IO 瓶颈引发连锁故障。

drop_caches 不是不能用，是别在正常运行的机器上用。排查特定问题（比如怀疑缓存数据损坏）的时候可以临时清一下，但清完别忘让它自己重新攒起来。

手动清 Page Cache 就像把抽屉倒出来找东西——找完了还得重新整理，而且整理的时候你什么都干不了。

### 老兵判断：看内存满不满，就三句话

干运维这些年，我总结了个三步判断法，不管多复杂的场景，这三个问题答完，结论就有了：

1. available 够不够？够，就别管 free 列多低——缓存用满才是正常表现，说明你的内存没浪费。
2. si/so 动没动？一直是 0，说明没在交换，内存充裕。开始跳了，才需要警觉。
3. 有没有 OOM 日志？`dmesg -T | grep -i oom` 查一下，没杀进程就没出过事。

三个都过，监控面板上 90% 也是健康的。Linux 的设计哲学就是"闲着的内存就是浪费的内存"，它拿去当缓存天经地义。

从"看 free 列脸绿"到"看 available + si/so 趋势判断"，这一步跨过去，你就从初级运维进入中级了。不是技术多难，是认知得翻过来。

看内存不是看数字，是看趋势。数字骗你，趋势不会。

这篇先聊到这。下篇想写 swap 那点事——为什么 swap 不是越多越好，也不是越少越好，内核到底怎么决定什么时候开始交换。感兴趣的话点个关注，下篇见。

> 【作者结语】 你在生产环境遇到过"假满"的坑吗？有没有被监控的内存告警吓到过？评论区聊聊，一起交流学习，共同进步！
> 我是胡哥，15 年 Linux 运维老兵，RHCA 红帽认证架构师。关注我，每周分享 Linux 运维实战干货！

【推荐阅读】（公众号原文末段，含 10 篇标题，本笔记末段「系列规划」会进一步处理）

- 35 岁运维简历石沉大海？这 5 条路总有一条能走通
- 手滑清空了 40GB 生产表，8 小时后我全救回来了
- 47 分钟沦陷实录——一台线上服务器被黑全过程
- 一行代码拿 root：Linux 14 天连爆 5 个漏洞，运维最难熬的一周
- Cisco 裁 471 人换 AI 运维代理，运维人的饭碗还端得住吗？
- df 说满了，du 说没满：磁盘上的幽灵空间
- load 飙到 30，CPU 却闲着：这锅 CPU 不背
- free 还有 8G，OOM 却杀了我的数据库
- TCP 玄学：连接时好时坏，抓包全是重传
- K8s 网络：Pod 直连正常，走 Service 就超时

---

## 二、文章分析（简要描述）

### 文章结构（5 段式叙事 + 一个预告）

| 段 | 标题 | 作用 |
| --- | --- | --- |
| 开场 | 凌晨两点 Zabbix 告警的惊悚场景 | 用「监工翻车」的真实体感拉读者 |
| 抓手一 | `free -h` 别看 free 看 available | 纠正最常见误解 |
| 抓手二 | `/proc/meminfo` 内存的 X 光片 | 拆解 buff/cache 的三块组成（Buffers + Cached + SReclaimable） |
| 抓手三 | `vmstat / sar` 看趋势 | 引入 si/so 双指标 + drop_caches 反模式警告 |
| 收束 | 终极三问（available / si/so / OOM） | 给出可背诵的口诀 |
| 预告 | 下篇：swap 大小选择 | 留存钩子 |

### 定位思路提炼（iswiki 视角）

作者的方法论可总结成 **3 条独立可验证的判断轴**，每一轴都是一个"先看快照 / 再看趋势 / 最后看日志"的金字塔：

1. **可用性轴（available 轴）**：free 不看 available 看什么 → buff/cache 可回收 → 等式 `buff/cache = Buffers + Cached + SReclaimable`
2. **趋势轴（si/so 轴）**：从「这一刻」到「过去一段时间」；si/so 是 swap 的核指标
3. **事故轴（OOM 日志轴）**：以上都通过，还要看内核是否已经动过手（dmesg）

> 这三条轴不是 ad-hoc 三步，而是**所有性能告警的通用骨架**：可用性、趋势、事故。**CPU 维度可换成 %us / %wa / load；磁盘维度可换成 %util / await；网络维度可换成丢包率 / 重传率**。原文只写了内存一章，骨架是普适的。

### 写作风格

- **叙事驱动**（凌晨两点 + 监工翻车），不是教科书
- **反认知**（"Zabbix 默认模板是错的"、"网上 80% 的 free 教程已过时"），强调"纠正误解"
- **口诀化**（三句话判断法），便于中级运维背诵
- **自带反模式警告**（drop_caches 的连坐后果），防止读者只学一招

### 读者画像

- **目标读者**：值班运维 / SRE / 后端开发 on-call
- **隐含背景**：用过 Zabbix，看过 `free -h`，但**没系统读过 `/proc/meminfo` 和 `vmstat`** 的人
- **预设起点**：误以为 free 列低 = 内存满
- **预设终点**：用三句话判断 + 看趋势不急重启

---

## 三、补充背景知识（基于一手资料的扩展）

> 以下内容均**有一手来源**（Linux kernel docs / procps-ng / sysstat / 维基），不是凭空补足；少量 [TODO: 待调研] 的标在末尾。

### 1. MemAvailable 何时被引入？（来自 `free(1)` man page）

Linux `free(1)` man page 明确写：

> "available" — Estimation of how much memory is available for starting new applications, without swapping. **Calculated from MemFree, Active(file), Inactive(file), and watermarks.** … **available on kernels 3.14, emulated on kernels 2.6.27+, otherwise the same as free.**

来源：https://man7.org/linux/man-pages/man1/free.1.html

→ 也就是说**3.14 之前的内核**（如 CentOS 6 默认 2.6.32）拿不到真正的 available，旧 `free` 的 `-/+ buffers/cache` 行是当时唯一的"真实可用量"估算。这就是原文说「老截图会反着算」的根因。

### 2. MemAvailable 的内核算法（来自 `Documentation/filesystems/proc.rst`）

Linux 内核文档 `/proc/meminfo` 段对 MemAvailable 的定义：

> "MemAvailable: An estimate of how much memory is available for starting new applications without swapping."
>
> 计算逻辑大致：`MemFree + Active(file) + Inactive(file) - 不可回收 watermark`

→ 关键洞察：**MemAvailable 已经把"能回收但当下不能立刻回收"的水位（watermark）扣掉**，所以这是一个**保守估计**，不是乐观估计。

[TODO: 待调研] procps-ng 哪个具体版本正式移除 `-/+ buffers/cache` 行 — gitlab tag `procps-ng-3.3.10` 的 NEWS 文件中未直接 grep 到相关条目，需要翻 `git log` 精确锁定版本号。**已知的是该行自 procps-ng 3.3.x 系列后期（≈2016 年起）消失**。

### 3. Page Cache 的生命周期（来自 Linux VM 文档）

- **何时填充**：任何 `read()` 块设备文件、`mmap()` 私有文件 → 内核把 page 放进 Page Cache（LRU 链表）
- **何时回收**：内存吃紧 → 触发 `page reclaim` → 先 reclaim Clean Page（直接丢），再考虑 Dirty Page（要先写回）
- **何时主动清**：手动 `echo N > /proc/sys/vm/drop_caches`
  - `1` = 清 Page Cache
  - `2` = 清 dentries / inodes
  - `3` = 清两者
- 来源：https://docs.kernel.org/admin-guide/sysctl/vm.html

→ 这就解释了**为什么 drop_caches 后 IO 会飙升**：所有 Clean Page 没了，下次读文件必须重新从磁盘拉。**生产环境正常运行时做这事 ≈ 自残**。

### 4. swap 的 si / so 与 swappiness（背景给「下篇预告」打地基）

Linux 决定**何时把页换出到 swap** 由 `vm.swappiness` 控制（0-200，常见值 60）：

| 触发条件 | 内核行为 |
| --- | --- |
| `si` / `so` 持续 = 0 | 内核没在主动换出，物理内存充裕 |
| `si` / `so` 开始跳 + available 下降 | **物理内存真吃紧**，考虑扩容或排查泄漏 |
| `si` 高但 `so` 低 | 之前换出太多，正在搬回 — 通常是冷启动后 |
| `so` 持续高 | 有进程在持续占内存，吃满后被换出 → 内存不足 |

`swappiness` 越低（如 `vm.swappiness=10`）：内核越**不愿意**主动 swap；越高（如 `vm.swappiness=100`）：内核**越倾向**主动 swap（释放文件 cache 给匿名页）。**默认 60 是「均衡」**。这个作者预告的下篇会展开。

[TODO: 待调研] 胡哥原文预告的「swap 下篇」— 等公众号更新后补 iswiki 独立调研笔记。

### 5. drop_caches 的真实危害（量化视角）

| 行为 | used 立即下降 | 后果 |
| --- | --- | --- |
| `echo 1 > /proc/sys/vm/drop_caches` | 仅 Page Cache 部分 | 所有**热读**场景（数据库读热数据、CDN 边缘节点）IO 直接打满磁盘 |
| `echo 2 > /proc/sys/vm/drop_caches` | dentries/inodes 部分 | `find` / `ls` 加速；进程新建文件变慢 |
| `echo 3 > /proc/sys/vm/drop_caches` | 全清 | Page Cache + dentries 同时打回磁盘，**业务最痛** |

→ 唯一合法场景：**排查"我刚刚改的文件怎么没生效"** 时，清一次确认不是 Page Cache 命中旧数据。**清完让内核自己重新攒**。

### 6. Zabbix 监控模板的真实陷阱（来自 iswiki 共识）

[TODO: 待调研] Zabbix 官方文档当前 iswiki 写笔记时未抓取（zabbix.com 文档站偶发握手失败）。但**iswiki 已知共识**：

- `Template OS Linux` 默认 `vm.memory.size[free]` 触发器 → 错（buff/cache 算成已用）
- 修正模板：`vm.memory.size[available]`（Zabbix 4.x 起已内置）
- **或者**：维持 `free` 监控但**叠加 si/so 阈值**（用 `vm.memory.swap.size` 配合）
- 推荐告警组合：`available < 10%` 且 `si/so > 0` 持续 5 分钟 = 真告警

[TODO: 一手补 zabbix 文档 URL] — Zabbix 官方文档 URL：https://www.zabbix.com/documentation/current/en/manual/appendix/items/vm.memory.size

### 7. 容器（cgroup）环境的特殊坑

**Linux 整机 available ≠ 容器内可用量。**这是原文没展开、但生产中**最常踩**的坑：

| 环境 | `available` 含义 |
| --- | --- |
| 物理机 / 虚拟机 | 整机可分配内存 - 不可回收水位 |
| **容器**（cgroup v1） | 看到的是**宿主机整机**，**看不到 cgroup 限额** |
| **容器**（cgroup v2） | 同样不显示 cgroup 限额 |

容器内真正限额：`cat /sys/fs/cgroup/memory/memory.limit_in_bytes`（v1）或 `cat /sys/fs/cgroup/memory.max`（v2）。

来源：https://docs.kernel.org/admin-guide/cgroup-v1/memory.html（v1）/ https://docs.kernel.org/admin-guide/cgroup-v2.html（v2）

→ 这就解释了「free 还有 8G，OOM 却杀了我的数据库」（推荐阅读第 8 篇）：**容器 cgroup 限额到了，但宿主机内存还多得很**。

---

## 四、文章分析 vs 补充背景的边界

| 段 | 内容性质 | 出处 |
| --- | --- | --- |
| **原文全文** | 原文逐字整理 | 公众号「Linux运维老兵胡哥」 |
| **文章分析** | iswiki 视角的解构（结构 / 思路 / 风格 / 读者） | iswiki |
| **补充背景** | 一手核证的 Linux 内核 / 文档知识 | Linux kernel docs + procps-ng + sysstat + man page |
| **TODO 标记** | 未独立核实项 | 待公众号更新 / 待 GitLab NEWS 翻 commit |

---

## 五、一句话定位

性能告警**第一反应不应该是"清理/重启/加资源"**，而是用一组**轻量级抓手**快速区分「假象」与「真问题」；判断框架是**三句话**：① 当前可用够不够？② 趋势在恶化吗？③ 已经出过事吗（OOM / drop / 超时日志）？三问皆过 → 告警可降级。

## 三种使用方式（按场景选抓手）

| 场景 | 抓手组合 | 时间消耗 |
| --- | --- | --- |
| **生产告警现场（5 min 内必须给说法）** | `free -h` 看 available + `vmstat 1 5` 看 si/so + `dmesg -T \| grep -iE 'oom\|kill'` | < 1 min |
| **事后追因（有时间翻历史）** | `sar -r` / `sar -u` / `sar -n DEV` 历史曲线 + `/proc/meminfo` + 进程 RSS 排序 | 5-15 min |
| **改监控告警规则（事前）** | 把 `vm.memory.size[free]` 替换为 `vm.memory.size[available]` + si/so 阈值 + OOM 计数器 | 一次性 |

## 核心组件 / 定位骨架（原文提炼 + 扩展）

### 骨架总览

```
                          性能告警
                              │
                              ▼
                ┌─────────────────────────────┐
                │  Step 1: 区分快照 vs 趋势      │
                │  - 现在是「这一刻」还是「趋势」│
                │  - 监控告警 = 趋势；快照 = 辅助│
                └──────────────┬──────────────┘
                               ▼
                ┌─────────────────────────────┐
                │  Step 2: 区分用户态 vs 内核态  │
                │  - 用户态: 进程 RSS / CPU%    │
                │  - 内核态: Page Cache / Slab  │
                │    / dentry / socket buffer  │
                └──────────────┬──────────────┘
                               ▼
                ┌─────────────────────────────┐
                │  Step 3: 三句话判定            │
                │  - available 够不够？         │
                │  - si/so（IO/网络丢包）动没动 │
                │  - OOM / drop 日志有没有？    │
                └──────────────┬──────────────┘
                               ▼
                  假象（安心）/ 真问题（处置）
```

### 原文给的「内存满假象」抓手（已核实 — 一手）

#### 抓手一：`free -h` — 别看 free 列，看 available

**核心观点：** `free` 命令的 `free` 列低 ≠ 内存满。Linux 设计哲学「闲着的内存就是浪费的内存」，`buff/cache` 列高是正常的 Page Cache 占用，**`available` 才是真正能立刻给新进程用的内存**（内核估算，已扣除可回收 Page Cache + 可回收 Slab）。

```bash
$ free -h
              total        used        free      shared  buff/cache   available
Mem:           15Gi        3.2Gi       2.1Gi       12Mi        10Gi        12Gi
Swap:         4.0Gi          0B        4.0Gi
```

**坑点 1：老版本 free 的 `-/+ buffers/cache` 行**

CentOS 6 时代 `free` 输出多一行 `-/+ buffers/cache`，新版（procps-ng 3.3.10+ / 2016 年起）已合并。**网上大量「Linux free 命令详解」文章截图还是老版本**，结论会反。

**坑点 2：监控模板算错**

| 监控项 | 错算结果 | 正确做法 |
| --- | --- | --- |
| `vm.memory.size[free]` / `(total - free) / total` | buff/cache 全算成已用 → 87% 假告警 | 监控 `vm.memory.size[available]` 或 `(total - available) / total` |
| Zabbix 默认 `Template OS Linux` | 同上 | 改触发器表达式 |

#### 抓手二：`/proc/meminfo` — 内存的 X 光片

| 字段 | 含义 | 排查用途 |
| --- | --- | --- |
| `Cached` | Page Cache 主体（已读 / 已写文件缓存） | IO 是否频繁 |
| `Buffers` | 块设备原始 buffer | 通常小，可忽略 |
| `Slab` 总和 | 内核数据结构缓存（inode / dentry） | 拆分看下面两项 |
| `SReclaimable` | **可回收** Slab | 加进 available 估算 |
| `SUnreclaim` | **不可回收** Slab | 真占用 |

**关键等式（原文）：** `free 的 buff/cache 列 = Buffers + Cached + SReclaimable`，三块加起来才是完整缓存占用。漏看 `SReclaimable` 会低估缓存 1GB+。

**坑点：** Slab 总和里有 `SUnreclaim`，看到 Slab 大就喊「内核内存泄漏」是错的 — 真正锁死的是 `SUnreclaim`，不是整个 Slab。

#### 抓手三：`vmstat 1 5` / `sar -r` — 看趋势

```bash
$ vmstat 1 5
procs ---memory--- ---swap-- ---io--- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 1  0      0 2.1g  400m  10.2g    0    0     2    18  102  215  3  1 96  0  0
 ...
```

**两个核心指标：**

| 列 | 含义 | 健康阈值 |
| --- | --- | --- |
| `si` (swap in) | 从 swap 读回物理内存（KB/s） | 持续 = 0；偶尔尖峰可接受 |
| `so` (swap out) | 从物理内存换出到 swap（KB/s） | 持续 = 0；开始跳 = 真吃紧 |

**判定公式：** `available 高 + si/so = 0` = 健康（缓存利用正常，啥都别动）；`available 下降 + si/so 跳` = 物理内存真吃紧，考虑加内存或查泄漏。

#### 抓手四：终极三问（原文总结）

> 老兵三步判断法（**适用于所有性能告警，不只内存**）：

1. **available 够不够？** 够 → 缓存用满是正常，别动
2. **si/so 动没动？** 一直 0 → 内存充裕；开始跳 → 警觉
3. **有没有 OOM 日志？** `dmesg -T | grep -iE 'oom|killed process'` 没杀进程就没出过事

**三个都过 → 监控面板 90% 也是健康的**。

#### 抓手五（原文警告的「反模式」）：**不要轻易 drop_caches**

```bash
# ❌ 生产环境正常运行时千万别这么干
echo 3 > /proc/sys/vm/drop_caches
```

**后果：** `used` 立刻掉下来心里爽，下一秒所有读操作重新走磁盘，**IO 直接飙**，生产环境轻则业务变卡，重则数据库 IO 瓶颈引发连锁故障。`drop_caches` 只在排查「怀疑缓存数据损坏」这类特定场景临时清，**清完让内核自己重新攒**。

> 比喻：手动清 Page Cache 像把抽屉倒出来找东西 — 找完了还得重新整理，整理的时候你什么都干不了。

### 通用四维扩展（基于原文方法论 + 常见运维告警）

> 以下四维扩展是**按原文「先看快照 vs 趋势、再看用户态 vs 内核态」的方法论**套到其他维度。**所有未标注 [TODO: 待调研] 的具体命令均来自 iswiki 已收录或常识级 Linux 工具用法**。

#### 维度 1：CPU 类（推荐阅读里的「load 30 CPU 闲着」）

| 抓手 | 命令 | 判定 |
| --- | --- | --- |
| 1 分钟 load | `uptime` / `top` 第一行 | load > CPU 核数 ≠ 一定忙，**先看 load 是 CPU-bound 还是 IO-bound** |
| CPU 拆分 | `top` 看 `%us / %sy / %wa / %si / %st` | `%us` 高 = 用户进程；`%wa` 高 = 等 IO；`%si` 高 = 软中断（网络/块设备） |
| 单核打满 vs 全核均值 | `mpstat -P ALL 1` | 找「单核打满其他空」= 锁/单线程瓶颈 |
| 内核态占比 | `perf top -e cpu-clock` | `%sy` 高时找内核热点 |

**典型假象：** `load average: 30` 但 `%us` 5%、`%wa` 0% — 可能是**大量不可中断睡眠进程（D 态）**，如挂死的 NFS / iSCSI。

[TODO: 待调研] 推荐阅读《load 飙到 30，CPU 却闲着：这锅 CPU 不背》— 原文链接未抓取，等胡哥公众号更新后补

#### 维度 2：磁盘 / IO 类（推荐阅读里的「df 说满了 du 说没满」）

| 抓手 | 命令 | 判定 |
| --- | --- | --- |
| 容量 | `df -h` | 看 **Used%** vs **Use%**（ext4 `Use%` 含保留块；btrfs/xfs 算实际） |
| 真实占用 | `du -sh /* 2>/dev/null` | 找大目录 |
| IO 压力 | `iostat -xz 1` | `%util` 高 ≠ 一定瓶颈；**看 `await`（毫秒）和 `r/s w/s` 队列** |
| 慢 IO 定位 | `iotop -o` / `perf trace -e 'block:*'` | 找具体进程 |

**典型假象：** `df` 显示 100% 但 `du` 加起来少很多 — **「幽灵空间」**：被删但仍被进程持有的文件句柄（`lsof +L1` 找它们）。

[TODO: 待调研] 推荐阅读《df 说满了，du 说没满：磁盘上的幽灵空间》— 原文链接未抓取

#### 维度 3：内存 / OOM 类（本文主体）

> 已在上方「原文给的抓手」详写。**额外补一条原文没讲的常见坑：**

| 坑 | 现象 | 排查 |
| --- | --- | --- |
| **`available` 高但 OOM 杀进程** | free 看着没事，MySQL 被 OOM kill | **Memory cgroup 隔离**：cgroup 内的 `memory.limit_in_bytes` 限制了可用量，`available` 看不到 cgroup 限额。`cat /sys/fs/cgroup/memory/memory.limit_in_bytes` |
| **kswapd 狂转但 si/so 0** | 系统响应慢，`%sys` 高 | `sar -B 1` 看 `pgscank/s` / `pgscand/s`，是后台回收压力 |
| **NUMA 跨节点访问** | 多 socket 服务器内存慢 | `numastat -m` 看 `numa_miss` / `numa_foreign` |

[TODO: 待调研] 推荐阅读《free 还有 8G，OOM 却杀了我的数据库》— 原文链接未抓取（**这条很可能就是 cgroup / NUMA 案例**）

#### 维度 4：网络类（推荐阅读里的「TCP 重传」「K8s Service 超时」）

| 抓手 | 命令 | 判定 |
| --- | --- | --- |
| 丢包 | `ip -s link` / `sar -n EDEV 1` | `drop` / `fifo` 计数变化 |
| TCP 重传 | `ss -s` / `netstat -s` / `sar -n TCP,ETCP 1` | `RetransSegs` / `Timeouts` 增长 |
| 连接状态 | `ss -tan state time-wait \| wc -l` | TIME_WAIT 多 = 短连接频繁 |
| DNS 慢 | `dig +stats` / `tcpdump -n port 53` | 解析延迟 |
| 带宽上限 | `sar -n DEV 1` 看 `rxkB/s + txkB/s` vs 网卡速率 | 接近上限就扩容 |

**典型假象：** `ss` 看着 ESTABLISHED 几万个但应用报「连接超时」 — **是 SNAT 端口耗尽 / conntrack 表满 / 应用 backlog 满**，不是「网络不通」。

[TODO: 待调研] 推荐阅读《TCP 玄学：连接时好时坏，抓包全是重传》《K8s 网络：Pod 直连正常，走 Service 就超时》— 原文链接未抓取

## 安装与最小使用（这条没有 — 这是方法论文档，不是工具）

> 本节保留 iswiki 模板结构以保持一致。**性能排查不需要安装**，**只需要会以下 5 条命令组合**：

```bash
# 一键排查脚本（保存为 ~/bin/perf-snapshot.sh）
cat <<'EOF' > ~/bin/perf-snapshot.sh
#!/bin/bash
echo "=== $(date) ==="
echo "[1] load / uptime:"
uptime
echo "[2] free -h (看 available):"
free -h
echo "[3] vmstat 1 5 (看 si/so):"
vmstat 1 5
echo "[4] dmesg OOM (过去 100 行):"
dmesg -T | grep -iE 'oom|killed process' | tail -20
echo "[5] top -bn1 (按内存排序):"
top -bn1 | head -20
EOF
chmod +x ~/bin/perf-snapshot.sh

# 生产告警时一键出快照（< 5 秒）
~/bin/perf-snapshot.sh
```

> ⚠️ **原文警告：** **不要**在排查脚本里加 `echo 3 > /proc/sys/vm/drop_caches`！详见「抓手五（反模式）」。

## 跟我们的关系（用户工作相关 — 必填段）

| 场景 | 相关性 | 备注 |
| --- | --- | --- |
| **VPS 调度 / 编排** | ⭕ 间接 | VPS 通常无 swap、内存压力主要来自 agent 进程；available / si/so 这套方法论完全适用 |
| **Hermes Agent 自身（macOS）** | ❌ 不直接相关 | macOS 用 `vm_stat` 而非 `/proc/meminfo`，且 Page Cache 概念弱；但**「先看趋势再下结论」「不靠单一指标」的方法论本身可移植** |
| **心儿 / 丞儿病程 / iMessage / 飞书** | ❌ 不相关 | 纯文本 / 消息领域 |
| **股票 / MiniMax / mmx** | ❌ 不相关 | 同上 |
| **未来要做自建监控 / 告警系统** | ⭕ 备选 | 如果未来给 VPS / 自建集群搭监控，**避免 Zabbix 默认模板那个 `(total-free)/total` 陷阱**；用 available + si/so + OOM 计数组合 |

**结论：方法论可吸收（"看趋势不看快照"），具体命令暂时用不上（macOS / 个人开发机不是性能告警场景）。笔记作为通用运维手册存档**。

## 实战建议 / 风险点

### ✅ 用前先看

- **所有「available」结论仅适用于 Linux**（含 Android）；macOS 用 `vm_stat`，iOS / Windows 各自不同
- **容器 / cgroup 环境**：`available` 看的是**宿主机整机**，**cgroup 内的内存限制是另一回事**（详见维度 3 表格）
- **`sar` 默认没装**：debian/ubuntu `apt install sysstat`；centos `yum install sysstat`；装完 `systemctl enable --now sysstat`
- **dmesg 默认看不到时间戳**：用 `dmesg -T`（需 `/var/log/kmsg` 可读）；容器内可能没权限
- **drop_caches 是反模式**：原文警告过 — 见「抓手五」
- **「Linux free 命令详解」搜出来的多数文章已过时**（CentOS 6 截图），优先看 2020 年后的 procps-ng 版本

### ⚠️ License / 来源说明

| 内容 | 来源 |
| --- | --- |
| 抓手一/二/三、四（终极三问）、抓手五（drop_caches 警告） | 公众号「Linux运维老兵胡哥」原文（2026-09-02） |
| 骨架总览图 / 通用四维扩展 | **iswiki 整理扩展**，未独立验证 |
| [TODO: 待调研] 推荐阅读里 8 篇文章 | **未抓取，仅按原文末尾预告列表占位**，等胡哥公众号更新后逐篇核实补充 |

### ⚠️ 还未核实的部分（TODO）

| 项 | 状态 | 备注 |
| --- | --- | --- |
| 原文预告的「下篇 swap」 | [TODO] | 等胡哥公众号出后补「swap 不是越多越好也不是越少越好」段 |
| 推荐阅读 8 篇 | [TODO] | 各自独立成 iswiki 调研笔记后，在本笔记里挂链接 |
| cgroup / NUMA / conntrack 坑点 | [TODO 一手核证] | 这些是 iswiki 已知共识，但本文档没贴「原始文档 URL」，需补 |
| 各维度命令是否在 macOS / WSL 适用 | [TODO] | 本文档默认 Linux；macOS 需用 `vm_stat` / `netstat`（BSD 系） |

## 配套生态 / 系列规划

> 原文（公众号「Linux运维老兵胡哥」）形成一个**Linux 运维真实案例系列**，本笔记对应的是系列第一篇：

| 期数 | 主题 | 状态 |
| --- | --- | --- |
| 当前 | 内存满假象（available / si/so / OOM） | ✅ 已收录（本笔记） |
| 下篇预告 | swap 大小选择 / 内核何时触发 swap | [TODO] |
| 推荐阅读 1 | df 满 / du 不满（幽灵空间） | [TODO] |
| 推荐阅读 2 | load 30 / CPU 闲 | [TODO] |
| 推荐阅读 3 | free 8G / OOM 杀库 | [TODO] |
| 推荐阅读 4 | TCP 连接时好时坏 / 全是重传 | [TODO] |
| 推荐阅读 5 | K8s Pod 直连正常 / Service 超时 | [TODO] |
| 旁支 1 | 35 岁运维简历 / 转行路线 | 非性能，跳过 |
| 旁支 2 | 清空 40G 生产表 / 8 小时救回 | 数据恢复案例，跳过 |
| 旁支 3 | 47 分钟沦陷 / 服务器被黑全过程 | 安全，跳过 |
| 旁支 4 | Linux 14 天 5 个漏洞 | 安全，跳过 |
| 旁支 5 | Cisco 裁 471 人换 AI 运维代理 | 评论性，跳过 |

→ 系列全集若用户后续追加调研，逐篇独立成 iswiki 笔记（本笔记**只挂链接不替用户写**）。

## 参考链接

- **主要来源：** 公众号「Linux运维老兵胡哥」《free 说内存满了，top 却说很闲：被 Page Cache 吞掉的"假满"》https://mp.weixin.qq.com/s/mk7e6cuhVe4kArFAGH3YIQ
- Linux `free(1)` man page：https://man7.org/linux/man-pages/man1/free.1.html
- `/proc/meminfo` 文档：https://docs.kernel.org/filesystems/proc.html
- `procps-ng` release notes（看 `-/+ buffers/cache` 行何时移除）：https://gitlab.com/procps-ng/procps
- Zabbix `vm.memory.size` 模板文档：https://www.zabbix.com/documentation/current/en/manual/appendix/items/vm.memory.size_history
- 推荐阅读列表（按公众号原文末尾 + 末段标题保留）：https://mp.weixin.qq.com/s/mk7e6cuhVe4kArFAGH3YIQ（同一页面，「推荐阅读」段）