# 磁盘有空间却报 No space：inode 被小文件吃光的排查

> 学习笔记 · 调研时间 2026-11-12
> 调研来源: 微信公众号「WAKE UP技术」 https://mp.weixin.qq.com/s/cSPxTHquiJFeCvVxS_mO6g
> 发布: 2026-11-13 07:41 CST（页面原始 `ct=1794526902` → UTC 2026-11-12 23:41:42）· 作者 WAKE UP技术 · 个人主页 https://lweiqiang.xyz
> 定位: **原文的「df -h 有空间、df -i 100%、却写不进任何文件」排查流程**，补上原文没讲的两件事 —— **inode 计数在什么文件系统上会变**、**监控该怎么配才不误报**
> 姊妹篇: [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md)（df 满 du 不满 · 幽灵空间）· [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md)（Docker 磁盘满）

---

## 一句话定位

「空间明明有，却写不进东西」的**另一半真相**：不是磁盘块满了，是**文件数量额度（inode）满了** —— `df -h` 只管块、不管文件数，所以它在告警里永远是绿的。

---

## 一、原文案例还原

### 现象

一台跑日志采集 agent 的服务器，凌晨 2 点开始告警：采集进程写入失败，报 `No space left on device`。

值班同学第一反应是磁盘满了，`df -h` 一打：

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/vdb1      200G   62G  139G  31% /data
```

**才用了三成，离满还远**。`dmesg` 也没看到 OOM。重启服务能缓几分钟，之后继续报错，写入完全卡死。

> ⭐ 这是本文最有价值的一点：**`No space left on device` 这个 ENOSPC 错误码，不只由"块满"触发**。第一次遇到很容易怀疑应用 bug 或文件系统损坏，于是在代码层翻了半天 —— 方向完全错了。

### 第一层排查：`df -i` 直接点破

`df -h` 看的是**块（block）**用量，它还有一个兄弟指标管着**文件数量**：`df -i`。

```
Filesystem      Inodes   IUsed   IFree IUse% Mounted on
/dev/vdb1    13107200 13107000     200   100% /data
```

**inode 100%，只剩 200 个。**

inode 是文件系统里记录每个文件元数据（权限、时间、位置）的结构体，**文件再多再小，每个都要占一个**。哪怕你文件加起来才 1KB，只要有 1300 万个文件，inode 就先耗光了。

### 第二层：定位是谁在造小文件

```bash
for d in /data/*; do echo "$(find $d -type f 2>/dev/null | wc -l) $d"; done | sort -n
```

### 第三层：确认「账是不是真的对不上」

```bash
du -sh /data                    # 实际块占用
stat -f /data                   # inode 总量与剩余（ext4/xfs 通用）
# Filesystem: /dev/vdb1  Type: ext2/ext3 ...
# Inodes: 13107200   Free: 200

tune2fs -l /dev/vdb1 2>/dev/null | grep -i 'inode count'
# Inode count: 13107200
```

**块和 inode 是两本独立的账，块没满不代表 inode 没满。**

### 根因

锁定到 `/data/agent/buffer/`，里面躺着 **1200 多万个 `.tmp` 缓存文件**。

agent 把每条日志先落一个临时文件，正常情况落盘后会被打包上传并删掉；**那晚对象存储 endpoints 抖动，上传一直失败，临时文件不再被清理，于是无限堆积**。

> ⭐ 根因链条值得单独拎出来：**外部依赖抖动 → 本地缓冲无上限 → 无界堆积**。这不是"磁盘故障"，是**应用缺一个自限的缓存策略**。

---

## 二、原文根因分析（可迁移的三条）

### ① inode 数量在格式化时就定死了

> 文件系统格式化的时候，inode 数量就按分区大小和预设比例一次性分好了，之后不会自动增长。`df -h` 只报告块占用，完全不体现 inode 占用。

⚠️ **这条对 ext4 成立，对 XFS 不成立** —— 见 §四 核查。

### ② 小文件场景最容易踩这个坑

日志缓存、邮件队列、爬虫碎片、应用高频写临时文件 —— **它们的文件数量增长远快于文件体积增长，块没满，inode 先满**。

### ③ inode 真不够用，唯一的根本办法是重格式化

> `tune2fs` 只能调预留比例，没法事后给已存在的文件系统加 inode。遇到 inode 真不够用，唯一的根本办法是备份数据、用更大的 `-i` 重新格式化、再恢复。

---

## 三、原文的解决方案与预防

### 止血：清掉堆积的临时文件（分批删避免 shell 卡死）

```bash
# 先统计确认数量，别直接 rm 误伤
find /data/agent/buffer -name '*.tmp' -mtime +1 | wc -l
# 分批删除
find /data/agent/buffer -name '*.tmp' -mtime +1 -delete
```

清理后：

```
Filesystem      Inodes   IUsed   IFree IUse%
/dev/vdb1    13107200   85000 13022200    1%
```

### 长期方案：给 agent 加上传失败的本地上限与定时清理

```yaml
buffer:
  max_files: 500000       # 缓冲目录文件数硬上限
  max_age: 3600           # 1 小时未上传即回收
  flush_on_full: true
```

### 新分区：格式化时调大 inode 密度

```bash
mkfs.ext4 -i 4096 /dev/vdb1     # 每 4KB 一个 inode，适配小文件多
```

### 监控：inode 使用率必须单独采集

```yaml
- alert: InodeAlmostFull
  expr: node_filesystem_files_free{mountpoint="/data"} / node_filesystem_files{mountpoint="/data"} < 0.1
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "{{ $labels.instance }} /data inode 剩余不足 10%"
```

### 规范层面

- 日志、缓存这类「会无限增长」的目录，必须配独立的**生命周期管理**（logrotate / TTL 清理 / 配额），**不能指望人工发现**
- 应用写临时文件也要有**上限和失败回收**，**上传失败不能只堆积不报警**
- 选云盘或分区时**按业务文件大小倒推 inode 密度**：文件平均越小，inode 越要配密；存视频/压缩包这种大文件为主的盘，inode 太密反而浪费元数据空间

⭐ **补一条原文没讲的：监控是最后一道防线，不是第一道防线。**

原文把"监控只看容量不看 inode"当作教训。但更本质的教训是 —— **监控只能告诉你"要出事了"，不能阻止它发生**。这次事故的真正根因是"agent 缺一个自限的缓冲策略"，Prometheus 告警只是让**发现时间从"凌晨 2 点写入失败"提前到"buffer 文件数开始异常上涨"**。

所以防复发要分三层，**优先级从高到低**：

| 层 | 手段 | 性质 |
|---|---|---|
| **① 应用层（最该做）** | 缓冲目录**文件数硬上限** + 超限即丢弃最旧 + 上传失败告警 | ⭐ 根治：不依赖任何运维动作 |
| **② 主机层** | inode 使用率告警（贴 100%）+ **单目录文件数告警** | 兜底：早发信号 |
| **③ 基础设施层** | 建盘时按业务文件大小定 inode 密度 | 预防：一次做对，不用返工 |

⚠️ **只做 ② 是最常见的错配** —— 告警响的时候，1200 万个文件已经躺在那里了。

---

## 四、事实核查（一手核验，9 条）

| # | 原文表述 | 核查方式 | 结论 | 备注 |
|---|---|---|---|---|
| 1 | `df -h` 只报块、不报 inode | `df(1)` 语义 + 本机 macOS 实测 `df -h` 输出**确实带 `iused/ifree` 两列** | ✅ 成立（但有例外） | ⚠️ **BSD/macOS 的 `df -h` 默认就显示 inode 两列**（本机实测：`228Gi 13Gi 133Gi 9% 487k 1.4G 0%`），Linux 的 `df -h` 默认不显示。原文是 Linux 语境，结论在 Linux 上成立 |
| 2 | ext4 默认每 16KB 一个 inode | ArchWiki Ext4 引 mke2fs(8)：*mkfs.ext4 uses by default a rather low ratio of one inode every 16384 bytes (16 KiB)* | ✅ 精确吻合 | 补充：**这是 `[defaults]` 的 `inode_ratio = 16384`**（mke2fs.conf 官方 manpage 一致）；`small` usage type 是 4096、`floppy` 是 inode_size=128 |
| 3 | inode 数量格式化后定死、事后加不了 | ArchWiki：*it is not possible to change either the bytes-per-inode ratio or the inode count after the filesystem is created* | ✅ **对 ext4 成立** | ⚠️ **对 XFS 不成立** —— 见 #4 |
| 4 | （隐含）「inode 计数是固定值」 | **Red Hat KB 5687161**：*XFS supports dynamic inode allocation. i.e. the inodes are allocated as needed as per the files created.* 官方实例：故障时 `df -i` 显示总数 57,085,024 → 空闲后变 2,321,190,784 | ❌ **对 XFS 不成立** | ⭐ **这是原文最大的普适性缺口**。XFS 上 `df -i` 的 "Inodes" 总数会随使用**漂移**，照搬「重格式化」结论会做错决策 |
| 5 | `stat -f /data` 能看 inode 总量与剩余 | stat(1) `-f` 输出 filesystem 信息，字段含 `File System: / Type: / Blocks: / Inodes: / Free inodes:` | ✅ 成立 | ⚠️ 原文注释写成 `Free: 200`，Linux 实际字段名是 **`Free inodes:`**；`Free:` 是 blocks 的字段 —— 抄命令时容易看错列 |
| 6 | `tune2fs -l \| grep 'inode count'` | tune2fs `-l` 打印 superblock，字段为 `Inode count: N` | ✅ 成立 | 且 **仅对 ext2/3/4 有效**，XFS 用 `xfs_info /data` |
| 7 | Prometheus 指标名 `node_filesystem_files_free` / `node_filesystem_files` | node_exporter issue #1392 正文确认这两个名字；brian-brazil 补充命名理由 | ✅ 成立 | ⚠️ 名字里是 **`files` 不是 `inodes`**（历史命名，因为部分 fs 没有真 inode）。想按 inode 语义告警得自己换算 |
| 8 | `mkfs.ext4 -i 4096` 可调 inode 密度 | mke2fs(8) `-i bytes-per-inode` | ✅ 成立 | ⚠️ 但**事后不能改**（#3），所以这只能是**建盘时**的选择 —— 原文放在"如果是新分区"下是对的 |
| 9 | 发布时间 2026-11-13 07:41 | 页面原始 JS 变量 `ct = 1794526902` → 换算 UTC 2026-11-12 23:41:42 / CST 2026-11-13 07:41:42 | ✅ 与页面显示一致 | 页面 `#publish_time` 显示 "Nov 13, 2026, 7:41 AM"（浏览器按本地时区渲染） |

> **核查小结**：**9 条里 7 条成立、1 条有普适性缺口（XFS）、1 条是字段名笔误**。原文的排查流程和 ext4 结论可靠；唯一要补的是 **inode 计数在 XFS 上会漂移**这一条 —— 它直接改变「该怎么办」的结论。

---

## 五、⭐ 原文没讲但决定成败的三件事

### ① XFS 上 inode 总数会漂移 —— 先确认文件系统类型，再套结论

**XFS 动态分配 inode**（Red Hat KB 5687161 官方确认）：

```
故障时:   /dev/mapper/VG-LV  57085024  54386345  2698679  96%  /data
空闲后:   /dev/mapper/VG-LV 2321190784 54342614 2266848170  3%  /data
```

注意 **`IUsed` 几乎不变（都是 ~5400 万），但总数从 57,085,024 变成 2,321,190,784`**。

⭐ **这带来两个直接后果**：

| 后果 | 说明 |
|---|---|
| **「重格式化」结论对 XFS 是错的** | XFS 上 inode 会自己涨回来。清理文件即可，**不需要备份+重格式化+恢复**（那是 ext4 独有的重活） |
| **「inode 数固定」这个前提不能跨文件系统假设** | 排查第一步应是 `stat -f /data \| grep Type` 或 `df -T /data`，**先确认 fs 类型，再决定结论** |

**其他文件系统的 inode 语义**：

| 文件系统 | inode 计数 | 事后能加吗 |
|---|---|---|
| ext2/3/4 | 格式化时定死 | ❌ 不能（只能备份重格式化） |
| **XFS** | **动态分配，会漂移** | ✅ 能（自动涨） |
| ZFS | 元数据全部动态分配，**没有 inode 数量上限** | ✅ 概念上不存在此问题 |
| Btrfs | 动态分配 | ✅ |
| **APFS（macOS）** | 64 位 inode 号，**上限 9.2×10¹⁸ 个文件** | ✅ 实践中不会遇到 |

> ⚠️ **本机（macOS 27.2.1 / APFS）实测**：`df -i` 显示 `iused 1032166 / ifree 1396068480 / %iused 0%` —— `ifree` 是 13 亿量级，**APFS 上 inode 耗尽在实践中不会发生**。所以这套排查流程**只对 Linux 服务器有意义**，本机跑 `df -i` 只会得到误导性的"一切正常"。
>
> （APFS 上限 9.2×10¹⁸ 个文件，见参考链接的 fast.io 条目；Wikipedia 原页在本机网络不可达。）

### ② `find | wc -l` 逐层下钻在千万级文件上会非常慢

原文用的定位命令：

```bash
for d in /data/*; do echo "$(find $d -type f 2>/dev/null | wc -l) $d"; done | sort -n
```

**问题**：1200 万文件时，每个 `find` 都要全量遍历一次子树。顶层目录几个还好，**一旦下钻到那个有 1200 万文件的目录内部，这一条会跑很久**。

**更快的替代**（按可得性排序）：

```bash
# ① 最快：du --inodes（GNU coreutils 8.22+），一次遍历出每个目录的 inode 数
du --inodes -d 1 /data | sort -n

# ② 只在真要逐目录精确定位时再用 find（-xdev 避免跨文件系统）
find /data -xdev -type f -printf '.' | wc -c

# ③ 已知目标目录、只想看它有多少文件时，直接数（不再遍历整棵树）
find /data/agent/buffer -maxdepth 1 -type f | wc -l
```

> ⭐ **`du --inodes` 这个选项就是为这个问题生的** —— coreutils 8.22（2013-12）由 Bernhard Voelker 提交，patch 标题直接叫 *"finding directories with many files in a file system"*。它比 `find | wc -l` 快得多，因为一次遍历就同时统计了所有层级。
>
> ⚠️ **GNU 专属**：`du --inodes` / `find -printf` / `stat -c` 都是 GNU 扩展，**BSD/macOS 上不存在**。本机实测：`du: unrecognized option '--inodes'`、`find: unknown primary or operator`、`stat: illegal option -- c`。在 macOS 上要数文件只能用 `find ... -type f | wc -l`（慢）或 `ls -1 | wc -l`（仅当前层）。
>
> ⚠️ **不要用 `stat -c '%h'` 数文件** —— 这是我初稿写错的地方，review 时核出来的：目录的 `i_links_count`（link count）统计的是**子目录数**（`.` 和 `..` 各占 1），**不是文件数**。ext4 文档与内核邮件列表都明确了这点（*"the directory link count ... only counts subdirectories"*），而且 ext4 的 `dir_nlink` 特性在超过 65,000 个子目录后**会直接把链接数置 1**。所以 `stat -c %h` 只能告诉你"这目录下面有多少层子目录"，跟文件数无关。

⚠️ **`find` 在大目录上还会撞上另一个坑**：单个 ext4 目录项过多时，`ls`/`find` 变慢；上千万文件时 `-delete` 分批删是必须的（原文已提到这点，做对了）。

### ③ 监控不能只看 inode 使用率，还要看「单目录文件数」

原文的告警规则：

```yaml
expr: node_filesystem_files_free{mountpoint="/data"} / node_filesystem_files{mountpoint="/data"} < 0.1
```

**这个表达式的方向是对的，但有两处需要注意**：

| 注意点 | 说明 |
|---|---|
| **指标名是 `files` 不是 `inodes`** | node_exporter 历史命名（issue #1392 讨论过）。要按 inode 语义写告警得自己换算 |
| **inode 用了 90% 不一定是问题，inode 用了 100% 一定是问题** | 因为 inode 总数是**建盘时按默认比例配的**，通常远大于实际需要。ext4 上 inode 用到 80% 可能只是"默认值配得稀"，**不代表业务异常**。真正该告警的是**接近 100%** |
| ⭐ **还要加一条「单目录文件数」告警** | inode 耗尽是**结果**不是**原因**。真正早发的信号是"某个目录文件数在涨"—— 那次事故里，agent 的 buffer 目录从 0 涨到 1200 万，**在 inode 耗尽前很久就该告警** |

**建议的规则组合**：

```yaml
- alert: InodeAlmostExhausted        # 接近耗尽（真会写失败）
  expr: node_filesystem_files_free / node_filesystem_files < 0.02
  for: 10m
  labels: { severity: critical }

- alert: SingleDirFileCountHigh      # 早发信号：某目录文件数异常
  # 需 exporter 配合，粒度到目录
  labels: { severity: warning }
```

---

## 六、跟我们的关系

> 本节是 iswiki 的差异化定位：不是通用文档搬运，是「跟用户自己的活 / 项目相关的复用点」。

### ⭐ 1. 这套流程**不适用于本机**，但适用于我们的服务器

本机是 **macOS 27.2.1 / APFS**：

```
$ df -i
Filesystem    512-blocks      Used Available Capacity  iused      ifree %iused  Mounted on
/dev/disk3s1 478622592 140212848 279213696     34% 1032166 1396068480    0%  /System/Volumes/Data
```

- `ifree` 是 **13.96 亿**量级，`%iused` 恒为 0% —— **APFS 上 inode 耗尽实际不会发生**
- 而且 macOS 的 `df -h` **默认就带 inode 两列**（`487k` / `1.4G`），比 Linux 更早暴露这个维度
- ⭐ **但 macOS 上有它自己的"文件数"问题**：不是 inode 耗尽，而是**单个目录项过多导致 `ls` 变慢**、以及 **APFS 快照/Time Machine 在大量小文件下吃满空间**

### ⭐ 2. 真正会踩这个坑的三个场景（我们有的）

| 场景 | 为什么危险 |
|---|---|
| **Docker / Colima Linux VM 里的构建产物** | buildkit 层、容器日志（json-file driver 每容器一个文件）、volume 里的依赖碎片 —— [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) 里已实测过 `Docker.raw` 24.8G 稀疏文件的坑，inode 是**同一类"看不见的额度"** |
| **日志采集 agent / 转发器** | ⭐ **和原文案例完全同构** —— 本地缓冲 + 外部存储上传，**外部抖动 → 缓冲无上限**。我们的 VPS 上如果跑 logrotate 之外的采集器，这是高危模式 |
| **`~/.hermes` 这类多 profile / 多 agent 本地目录** | 本机虽不会 inode 耗尽，但**"小文件无限堆积"这个模式一样成立**（cache / scratch / 快照目录）—— 排查手法可复用 |

### ⭐ 3. 直接可复用的产物

| 产物 | 从哪来 |
|---|---|
| **inode 排查 checklist** | §一 的五步（`df -i` → `df -T` 确认 fs 类型 → `stat -f` → 定位目录 → 分批删），加上 §五 的 XFS 分支判断 |
| **服务器巡检脚本的 inode 项** | §三 的 Prometheus 规则 + §五 的"单目录文件数"早发信号 |
| **"自限缓存"配置模板** | §三 的 yaml（`max_files` / `max_age` / `flush_on_full`）—— 直接套到我们自己的 agent/采集器上 |

### ⚠️ 4. 别把这次事故的结论套到我们头上

原文根因是"**对象存储 endpoints 抖动 → 临时文件不被清理**"。我们如果做类似缓冲层，**要防的是同一个失效模式**：
- 缓冲目录**必须有文件数硬上限**（不是只有时间上限）
- 上传失败**必须告警**（原文复盘明确点了这条）
- 清理要**按"最后修改时间"而非"创建时间"**（原文用 `-mtime +1` 是对的）

---

## 七、可直接跑的排查脚本

> 存成 `inode-triage.sh`，**只读、不删任何东西**。
>
> ✅ **已在本机（macOS 27.2.1 / APFS）实跑验证**：`bash -n` 语法通过；用 70 个测试文件跑通全流程 —— fs 类型正确识别为 `apfs`、inode% 正确取到第 8 列（`%iused`）、块% 取到第 5 列、结论判定正确、顶层目录自身文件数正确计入。
> **Linux 侧路径（`df -T` / `du --inodes` / `stat -f -c %T`）未在本机验证** —— macOS 上没有这些 GNU 工具，走的是降级分支。
>
> ⭐ **脚本里三个坑是实跑踩出来的，不是设计出来的**（都已在代码里修掉）：
> ① `df -i` 的 inode% **列号 Linux 是 5、macOS 是 8**（BSD 表头多 `Capacity/iused/ifree` 三列）—— 写死列号会读到 `ifree`，直接把 0% 误报成 1375053440% → 改为**按表头名 `%iused|IUse%` 动态定位**
> ② macOS 的 `stat -f` 把 `-c` **当格式串**，会输出字面量 `-c` → 每次取值后**校验是否像真实 fs 类型**，不像就降级
> ③ 判断 fs 类型要**按设备名匹配 `mount` 行**（`/dev/disk3s1 on ... (apfs, ...)`），按挂载点字段匹配在 macOS 上对不上

```bash
#!/usr/bin/env bash
# inode-triage.sh —— "df 有空间却写不进" 的只读排查
# 用法: ./inode-triage.sh [挂载点]   默认 /
# ⚠️ 全量扫描在大目录上很慢 —— 排查时优先传更小的范围（如 /data/agent/buffer）
# ⚠️ 跨平台: Linux(GNU) 与 macOS(BSD) 都可跑, 列号按表头动态定位
set -uo pipefail

MOUNT="${1:-/}"

# ---- 工具函数: 按表头名定位列号, 不写死列 ----
# Linux df -i : Filesystem Inodes IUsed IFree IUse% Mounted on
# BSD  df -i : Filesystem 512-blocks Used Available Capacity iused ifree %iused Mounted on
hdr_col() {  # $1 = df 的参数(-h/-i) ; $2 = 正则(如 %iused|IUse%)
  df "$1" "$MOUNT" 2>/dev/null | awk -v pat="$2" '
    NR==1 { for (i=1; i<=NF; i++) if ($i ~ pat) { print i; exit } }
  '
}

echo "===== 1. 块 vs inode: 两本独立的账 ====="
echo "--- 块用量 ---"
df -h "$MOUNT"
echo "--- inode 用量 ---"
df -i "$MOUNT"

INODE_COL="$(hdr_col -i '%iused|IUse%')"
BLOCK_COL="$(hdr_col -h '^Use%$|^Capacity$')"
echo "--- 定位到列: inode%=$INODE_COL  块%=$BLOCK_COL (按表头名动态定位) ---"

df_pct() {  # $1 = -h 或 -i ; $2 = 列号
  df "$1" "$MOUNT" 2>/dev/null | awk -v c="$2" 'NR==2 { gsub("%","",$c); print $c }'
}
USE_PCT="$(df_pct -i "${INODE_COL:-5}")"
BLOCK_PCT="$(df_pct -h "${BLOCK_COL:-5}")"

echo
echo "===== 2. 文件系统类型 (决定结论走哪条分支) ====="
# 三条路, 逐级降级, 每级都要校验结果像不像 fs 类型:
#   a) df -T            (GNU ext)
#   b) mount 输出括号   (Linux/macOS 通用)
#   c) stat -f -c %T    (GNU ext)
# ⚠️ macOS 的 stat -f 把 "-c" 当格式串, 会输出 "-c" —— 所以必须校验
FS_TYPE=""
FS_TYPE="$(df -T "$MOUNT" 2>/dev/null | awk 'NR==2{print $2}')"
if ! echo "${FS_TYPE:-}" | grep -qiE '^(ext[234]|xfs|btrfs|zfs|apfs|hfs|ufs|f2fs|reiserfs|jfs|vfat|ntfs|exfat)'; then
  # mount 行形如: /dev/disk3s1 on /System/Volumes/Data (apfs, local, journaled, ...)
  # ⚠️ 按【设备名】匹配, 不要按挂载点字段 —— macOS 上 df 的挂载点列与 mount 的 $2 对不上
  DEV_NAME="$(df -P "$MOUNT" 2>/dev/null | awk 'NR==2{print $1}')"
  FS_TYPE="$(mount 2>/dev/null | awk -v d="$DEV_NAME" '
    $1==d && index($0,"(") {
      t = substr($0, index($0,"(")+1); split(t, b, ","); print b[1]; exit
    }')"
fi
if ! echo "${FS_TYPE:-}" | grep -qiE '^(ext[234]|xfs|btrfs|zfs|apfs|hfs|ufs|f2fs|reiserfs|jfs|vfat|ntfs|exfat)'; then
  FS_TYPE="$(stat -f -c %T "$MOUNT" 2>/dev/null | head -1)"
fi
# 最后一档仍可能是 BSD stat 把 "-c" 当格式串输出的垃圾值, 校验不过就清空
if ! echo "${FS_TYPE:-}" | grep -qiE '^(ext[234]|xfs|btrfs|zfs|apfs|hfs|ufs|f2fs|reiserfs|jfs|vfat|ntfs|exfat)'; then
  FS_TYPE=""
fi
echo "文件系统类型: ${FS_TYPE:-未知}"

case "$FS_TYPE" in
  ext[234])
    echo "  -> ext 系: inode 数量格式化时定死, 事后加不了。"
    echo "  -> 唯一根治手段是 备份 -> 用更大 -i 重新格式化 -> 恢复 (风险高, 最后手段)。"
    ;;
  xfs)
    echo "  -> XFS: inode 是动态分配的, 总数会漂移, 清理文件即可恢复, 不需要重格式化。"
    echo "  -> 若看到 '总数 5700 万 / IUsed 5400 万 / 96%' 这类数字, 那是动态收缩, 不是真耗尽。"
    ;;
  btrfs|zfs)
    echo "  -> $FS_TYPE: 元数据动态分配, 无 inode 数量上限问题。"
    ;;
  apfs)
    echo "  -> APFS: 64 位 inode 号, 上限 9.2e18 个文件, 实践中不会 inode 耗尽。"
    ;;
  *)
    echo "  -> 未知类型, 先用 'df -i' 判断是否接近 100%。"
    ;;
esac

echo
echo "===== 3. 谁在造小文件 (顶层下钻) ====="
if du --inodes --help >/dev/null 2>&1; then
  echo "(用 du --inodes, GNU coreutils 8.22+)"
  du --inodes -d 1 "$MOUNT" 2>/dev/null | sort -n | tail -20
else
  echo "(无 du --inodes, 退回 find | wc -l)"
  echo "⚠️ 注意: 下面的 find 会遍历整棵子树, 大目录可能跑很久。"
  echo "   建议先指定更小的范围, 例如: $0 /data/agent/buffer"
  # 先算挂载点自身 (根目录下的文件容易漏掉), 再算每个一级子目录
  printf '%s %s\n' "$(find "$MOUNT" -xdev -maxdepth 1 -type f 2>/dev/null | wc -l)" "$MOUNT (自身)"
  for d in "$MOUNT"/*; do
    [ -d "$d" ] || continue
    printf '%s %s\n' "$(find "$d" -xdev -type f 2>/dev/null | wc -l)" "$d"
  done | sort -n | tail -20
fi

echo
echo "===== 4. 幽灵空间交叉检查 (inode 满常伴随已删除文件被持有) ====="
if command -v lsof >/dev/null 2>&1; then
  lsof +L1 2>/dev/null | grep -i deleted | head -10 || echo "  无已删除但被持有的文件"
  echo "  (详见 opsTroubleshootingDiskGhost.md)"
else
  echo "  lsof 不可用, 跳过"
fi

echo
echo "===== 5. 结论 ====="
echo "块使用率: ${BLOCK_PCT:-?}%   inode 使用率: ${USE_PCT:-?}%"
if [ -n "${USE_PCT:-}" ] && [ "$USE_PCT" -ge 98 ] 2>/dev/null; then
  echo "-> inode 接近耗尽, 这就是 'No space left on device' 的真因。"
elif [ -n "${BLOCK_PCT:-}" ] && [ "$BLOCK_PCT" -ge 95 ] 2>/dev/null; then
  echo "-> 块接近耗尽 (inode 尚可), 查块账本 —— 见 opsTroubleshootingDiskGhost.md"
else
  echo "-> 两本账都宽松, 不是这两类问题。"
fi
```

> ⚠️ **脚本是只读的**，不会替你删任何东西。真要清理时的安全做法见 §八「风险点」第 2 条。

---

## 八、实战建议与风险点

### 排查口诀（一行版）

```
df -h 有空间 + ENOSPC  →  df -i 看文件数  →  df -T 确认 fs 类型  →  定位目录  →  分批删
```

### 十一个容易踩的坑（原文没写全）

1. **XFS 的 inode 总数会漂移** —— 别照搬 ext4 的"重格式化"结论（§五①）
2. **`stat -f` 的字段是 `Free inodes:` 不是 `Free:`** —— `Free:` 是 blocks 的（§四#5）
3. **`node_filesystem_files` 不叫 `node_filesystem_inodes`** —— 命名历史遗留（§四#7）
4. **inode 用到 90% 可能只是默认值配稀** —— 告警阈值应贴近 100%，并配「单目录文件数」早发信号（§五③）
5. **千万级文件下 `find | wc -l` 很慢** —— 用 `du --inodes -d 1` 替代（§五②）
6. **`stat -c '%h'` 不是文件数** —— 那是**子目录数**，ext4 超 65,000 子目录后还会被置 1（§五②）
7. **这些命令 GNU 专属** —— `du --inodes` / `find -printf` / `stat -c` 在 macOS/BSD 上全无（§五②）
8. **`df -T` 也是 GNU 扩展** —— 判断文件系统类型在 Linux 上用 `df -T`、或 `stat -f | grep Type`；macOS 上 `df -T` 直接报错，本机实测无输出
9. **没有 `du --inodes` 时，`find` 那条 fallback 本身就是慢的那条路** —— 本机（macOS）实测跑 §七 的脚本时卡在这里超时。所以：**先缩小范围再跑脚本**，别拿整盘当参数
10. **`df -i` 的列号两个平台不一样** —— Linux 第 5 列是 `IUse%`，macOS/BSD 第 8 列才是 `%iused`（BSD 表头多 `Capacity/iused/ifree`）。**写死列号会读到 `ifree`** → 按表头名动态定位
11. **BSD 的 `stat -f` 会把 `-c` 当格式串** —— `stat -f -c %T /path` 在 macOS 上输出字面量 `-c`，不报错、退出码 0 → 取值后必须校验是否像真实 fs 类型

### 监控配置模板

```yaml
# ① inode 接近耗尽（真会写失败）
- alert: InodeAlmostExhausted
  expr: node_filesystem_files_free{mountpoint="/data"} / node_filesystem_files{mountpoint="/data"} < 0.02
  for: 10m
  labels: { severity: critical }

# ② 块使用率（原有）
- alert: DiskSpaceLow
  expr: node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.1
  for: 15m
  labels: { severity: warning }
```

### 风险点

- ⚠️ **重格式化是最后手段** —— ext4 上要备份 + 重格式化 + 恢复，**过程中数据全断**。优先清理，其次才是重建
- ⚠️ **`find -mtime +1 -delete` 会误删正在用的文件** —— 如果 agent 还在跑，先停写或改用"先 rename 到同分区临时目录再删"（rename 是原子的，删错的窗口更小）
- ⚠️ **删完 inode 释放了，块不一定释放** —— 如果还有进程持有已删除文件，会撞上 [DiskGhost](opsTroubleshootingDiskGhost.md) 的"幽灵空间"，两个问题可能同时存在
- ⚠️ **XFS 上 `df -i` 数字会让人误判严重性** —— 看到 "总数 5700 万、用了 5400 万" 别急着重格式化

---

## 九、跟已有笔记的关系

| 笔记 | 关系 |
|---|---|
| [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md) | **姊妹篇 —— 同一个"账本思维"框架的两半**。DiskGhost 讲「df 满 du 不满」（块账对不上），本文讲「df 有空间却写不进」（文件数额度用完）。DiskGhost §第二板斧已经点到 `df -i`，但只是一行提要 —— 本文是它的**深挖篇**。⭐ **两者可同时发生**：inode 耗尽的现场往往也伴随幽灵空间，排查时两个都要查 |
| [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) | **容器场景的同构问题** —— 那边是"缓存 GC 只管自己那块"，这边是"inode 额度只管文件系统那块"，都是**看不见的额度** |
| [opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md) | 同属「账本思维」系列（内存侧） |
| [opsTroubleshootingOOMSILogless](opsTroubleshootingOOMSILogless.md) | 同属「账本思维」系列（三本账） |

---

## 参考链接

**原文一手**
- 微信公众号「WAKE UP技术」·《磁盘有空间却报 No space：inode 被小文件吃光的排查》: <https://mp.weixin.qq.com/s/cSPxTHquiJFeCvVxS_mO6g>
- 作者个人主页: <https://lweiqiang.xyz>
- 相关阅读（原文自述的同系列）: 《Linux 删了大文件磁盘却没释放》·《systemd journald 日志爆盘》

**核查依据**
- ArchWiki · Ext4（bytes-per-inode ratio / inode 数量不可事后更改）: <https://wiki.archlinux.org/title/Ext4>
- mke2fs.conf(5) 官方 manpage（`inode_ratio = 16384` / `small`=4096 / `floppy` inode_size=128）: <https://manpages.debian.org/trixie/e2fsprogs/mke2fs.conf.5.en.html>
- mke2fs(8)（`-i bytes-per-inode`）: <https://man7.org/linux/man-pages/man8/mke2fs.8.html>
- **Red Hat KB 5687161 · XFS 支持动态 inode 分配（本文最关键的纠偏依据）**: <https://access.redhat.com/solutions/5687161>
- node_exporter issue #1392（`node_filesystem_files` / `node_filesystem_files_free` 命名由来）: <https://github.com/prometheus/node_exporter/issues/1392>
- Prometheus · Monitoring Linux host metrics with the Node Exporter: <https://prometheus.io/docs/guides/node-exporter/>
- APFS 限制（64 位 inode 号 / 上限 9.2×10¹⁸ 个文件）: <https://fast.io/resources/apfs-file-size-limit/>　（Apple File System 词条: <https://en.wikipedia.org/wiki/APFS> —— ⚠️ 本机网络对 wikipedia.org / handwiki.org 整站不可达，curl 返回 000、浏览器亦超时；**非死链**，是本地出口限制，换用上面可达的 fast.io 作引用）
- Linux 文档 · ext4 Index Nodes（inode size）: <https://docs.kernel.org/filesystems/ext4/inodes.html>
