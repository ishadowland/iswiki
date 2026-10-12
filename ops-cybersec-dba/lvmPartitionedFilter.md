# LVM `partitioned` filter — `pvcreate /dev/vdb` 报 `excluded by a filter` 的真因

> 学习笔记 · 调研时间 2026-10-12(2026-10-12 二次核验:五处结论按 `main` + `v2_03_14` 两份源码逐行比对后修正)
> 触发来源: DeepSeek 分享对话(用户排查 20T 云盘 `pvcreate` 被拒,AI 结论只对了一半)
> 对话链接: https://chat.deepseek.com/share/e60sxa3wzhxukag3p4
> 上游仓库: https://gitlab.com/lvmteam/lvm2
> 核验代码版本: `main` 与 `v2_03_14`(**两份都下载实读**,`v2_03_14` 是那台机器所在区间)
> License: GPL-2.0 / LGPL-2.1 · 语言: C

---

## 一句话定位

`pvcreate /dev/vdb` 被 `excluded by a filter` 拒掉,**大概率不是你的 `lvm.conf` 写错了**,而是 LVM 内置的 `partitioned` filter 检测到整盘上有分区表(含**哪怕一个分区都没定义**的空 GPT)就把整盘判为不可用 —— 这是 LVM 的防误操作保护,不是 bug。

---

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| 命令行 | `pvcreate` / `vgcreate` / `pvs` / `pvscan --cache` | 日常建 PV,直接对**分区**操作 |
| 配置文件 | `lvm.conf` 的 `devices { filter / global_filter }` | 长期屏蔽设备(光驱、u 盘、loop),**和本问题无关** |
| 代码级核验 | `lib/filters/filter-partitioned.c` + `lib/device/dev-type.c` | 想确认为什么被判拒 / 排查老版本行为差异 |

---

## 一、对话原文的结论对不对

DeepSeek 给的核心判断**方向对了,但有几处不准 / 不完整**:

| 原文说法 | 核验结果 | 说明 |
|---|---|---|
| 「有分区表就拒绝整盘」 | ⚠️ **不准确(新版)** / **在旧版上恰好成立** | 新版是「有分区表 **且 至少有一个分区被真正定义**」才拒;但对话里那台机器的旧版(≤2.03.14)**只看 PMBR**,所以对 GPT 盘确实是一见就拒。见 §三 的版本差异 |
| 「`filter`/`global_filter` 为空所以与配置无关」 | ✅ 对 | 但它没给出**怎么验证**这条(filter 为空不代表过滤链只有内置 filter) |
| 「`wipefs -a` 能解决」 | ⚠️ **半对** | `wipefs` 清的是**签名**不是分区表,且按源码分析可能只擦到主头、漏掉尾部备份 GPT 头。清分区表要用 `sgdisk --zap-all`。见 §五 |
| 「建议对 `/dev/vdb1` 操作」 | ✅ 对 | 这是标准做法 |
| 「partitioned filter 是 LVM 默认保护机制」 | ✅ 对 | 见 §二 源码 |
| 「升级 LVM 就能拿到更精确的报错」 | ❌ **不存在这个说法** | `device is partitioned` 在 2.03.14 就有了,不需要升级 |

**最关键的一条它没说**:`filter partitioned deferred` 里的 `deferred` **不是「延迟判断」的修辞**,是 LVM 的一个**真实机制** —— 需要读盘的 filter 在扫描前先返回 `-EAGAIN` 放行,扫描后再跑一遍。DeepSeek 把它解释成「延迟判断」,属于对机制的误读。

---

## 二、一手核验:LVM 的 filter 链是怎么串的

### filter 链顺序(`lib/commands/toolcontext.c::_init_filter_chain()`)

实测 `main` 分支的装配顺序(`grep -n "_filter_create"` 逐行核对,行号为 `toolcontext.c` 实际行号):

| 顺序 | filter | 装配行 | 作用 |
|---|---|---|---|
| 0 | `global` regex | 1236 / 1245 | `global_filter` 配置 |
| 1 | `filter` regex | 1236 / 1245 | `filter` 配置 |
| 2 | `type` | 1253 | 设备类型识别 |
| 3 | `deviceid` | 1260 | `devices/devicesfile` |
| 4 | `sysfs` | 1273 | sysfs 信息完整性 |
| 5 | `usable` | 1278 | `usable_filter`(内核报告的可用状态) |
| 6 | `mpath` | 1286 | multipath 组件 |
| 7 | **`partitioned`** | **1291** | **本篇主角** |
| 8 | `signature` | 1298 | 已有 PV / MD / FC 签名 |
| 9 | `md` | 1307 | md 组件 |
| 10 | `fwraid` | 1314 | firmware RAID 组件 |
| 11 | `composite` | 1318 | 把上面 0~10 打包成单一 filter |
| 外层 | `persistent`(缓存) | 1364 | **包住 composite**,做 filter 结果缓存 |

关键代码(`_init_filter_chain()`,main 分支,行 1291):

```c
/* partitioned device filter. Required. */
if (!(filters[nr_filt] = partitioned_filter_create(cmd->dev_types))) {
        log_error("Failed to create partitioned device filter");
        goto bad;
}
```

两个要点:

- **`partitioned` 排在 `signature` 之前** —— 意思是「先看有没有分区表,再看有没有 PV 签名」。一块既有分区表又有 PV 标签的盘,报出来的 reason 会是 `device is partitioned` 而不是 `device has a signature`。
- **`persistent` 是最外层**(行 1364 接收的是 composite 而非单条 filter),它缓存整条链的结果。所以改了 `lvm.conf` 的 `filter` 之后**必须** `pvscan --cache` 清缓存,否则还会按旧判定走。

**`partitioned` filter 没有配置开关** —— 它在 `lib/config/` 下零命中,`partitioned_filter_create()` 无条件调用。所以任何「改 `lvm.conf` 的 `filter` 来绕过」的建议都是错的方向。

### `partitioned` filter 本体(`lib/filters/filter-partitioned.c`)

```c
#define MSG_SKIPPING "%s: Skipping: Partition table signature found"

static int _passes_partitioned_filter(struct cmd_context *cmd, struct dev_filter *f,
                                      struct device *dev, const char *use_filter_name)
{
	int ret;

	if (cmd->filter_nodata_only)
		return 1;

	dev->filtered_flags &= ~DEV_FILTERED_PARTITIONED;

	ret = dev_is_partitioned(cmd, dev);
	if (ret) {
		if (dev->ext.src == DEV_EXT_NONE)
			log_debug_devs(MSG_SKIPPING, dev_name(dev));
		else
			log_debug_devs(MSG_SKIPPING " [%s:%p]", dev_name(dev),
					dev_ext_name(dev), dev->ext.handle);
		dev->filtered_flags |= DEV_FILTERED_PARTITIONED;
		return 0;                    // ← 拒
	}

	return 1;
}
```

（上面是 `main` 分支全文。`v2.03.14` 少掉 `if (dev->ext.src == DEV_EXT_NONE)` 那层判断,直接 `log_debug_devs(MSG_SKIPPING, dev_name(dev));`。)

### 老版本(对话里那台机器)多一段 `-EAGAIN`

分享的日志里出现 `filter partitioned deferred`,对应 **≤ v2_03_15** 的实现。`v2.03.14` 原文:

```c
	ret = dev_is_partitioned(cmd, dev);

	if (ret == -EAGAIN) {
		/* let pass, call again after scan */
		log_debug_devs("filter partitioned deferred %s", dev_name(dev));
		dev->flags |= DEV_FILTER_AFTER_SCAN;
		return 1;                       // 先放行,扫描后再判
	}

	if (ret) {
		if (dev->ext.src == DEV_EXT_NONE)
			log_debug_devs(MSG_SKIPPING, dev_name(dev));
		else
			log_debug_devs(MSG_SKIPPING " [%s:%p]", dev_name(dev),
					dev_ext_name(dev), dev->ext.handle);
		dev->filtered_flags |= DEV_FILTERED_PARTITIONED;
		return 0;
	}
```

> ⚠️ 注意 `filter_nodata_only` 那道前置判断**在 2.03.14 里也有** —— 它和 `-EAGAIN` 是并存的两道机制,不是替代关系。

**版本定位结论(可复现)** —— 那台机器的 LVM 版本能锁死在:

| 证据 | 只存在于 | 结论 |
|---|---|---|
| `filter partitioned deferred`(`lib/filters/filter-partitioned.c` 里的 `-EAGAIN` 分支) | ≤ v2_03_15 | 上界 |
| `dev-type.c` 里**完全没有 GPT 判定逻辑**(见下方 ⚠️) | ≤ v2_03_15 区间 | 更严的上界 |
| `filter %s deferred` / `filter cache deferred` | ≤ v2_03_14 | 更严的上界 |
| `Usable device filter initialised (scan_lvs 0)` | v2_03_05 ~ 现状 | 下界 |
| `Partitioned filter initialised` | 全部版本 | 无信息量 |

→ **那台机器跑的是 LVM 2.03.05 ~ 2.03.14 之间**。

> ⚠️ **这个版本区间有一个被严重低估的后果**,直接改变排查思路 —— 见 §三 的「版本差异」框。那台机器上跑的**根本不是**下面 §三 引用的那段 GPT 源码。

关于报错措辞:`dev_filtered_reason()` 的 reason 字符串表(`lib/cache/lvmcache.c`)**在 v2.03.14 里就已经存在**,且已经包含 `"device is partitioned"` / `"device has a signature"` / `"device is not in devices file"`。所以「新版才给更精确的理由、老版本只有笼统的 `excluded by a filter`」这个说法**不成立** —— 老版本同样有精确 reason,只是默认日志级别下不一定打印出来。要拿到它必须显式提高日志等级(见 §六)。

---

## 三、判定条件逐行拆解 —— 到底什么算「有分区表」

> 🔴 **本节引用的代码是 `main` 分支。分享对话里那台机器跑的不是这套 —— 见本节末尾的「版本差异」框,那里是本次调研最重要的发现。**

真正的判定在 `lib/device/dev-type.c::_has_partition_table()`:

```c
/* Check for msdos partition table */
if (buf.magic == PART_MSDOS_MAGIC) {
    for (p = 0; p < 4; ++p) {
        if (buf.part[p].boot_ind & 0x7f) { ret = 0; break; }  // 表损坏
        if (buf.part[p].nr_sects) {                             // 至少一个非空分区
            if (buf.part[p].sys_ind == PART_MSDOS_TYPE_GPT_PMBR && !ret)
                ret = _has_gpt_partition_table(dev);            // PMBR → 再查真 GPT
            else
                ret = 1;
        }
    }
} else
    ret = _has_gpt_partition_table(dev);
```

main 分支返回值的语义(`dev-type.c` 注释原文):

> `1` — 有分区表**且至少有一个真实分区被定义**
> `0` — 没有分区表,**或者有分区表但一个分区都没定义**,或者出错

`_has_gpt_partition_table()` 的判定更严格:必须遍历 GPT 分区项数组,**只要有一项的 `part_type_guid` 非零就算「有分区」**:

```c
for (i = 0; i < nr_entries; i++) {
    dev_read_bytes(dev, entries_start + i * sz_entry, sizeof(gpt_part_entry), &gpt_part_entry);
    if (gpt_part_entry.part_type_guid)   /* 只要有一项非零 */
        return 1;
}
return 0;
```

**所以在 `main` 上,「`parted mklabel gpt` 写了个空 GPT 但没建分区」—— 不该被拒**。

但**这恰恰是那台老机器最容易踩的误判**:它跑的是 ≤2.03.14,`dev-type.c` 里**一条 GPT 判定代码都没有**,只看 PMBR 的 `nr_sects` —— 所以空 GPT 在那台机器上**照样被拒**。别拿新版的这条结论去安慰自己那台机器。确认办法只有一个:上机 `sgdisk -p /dev/vdb`。

### 判定优先级:native 优先,udev 兜底

```c
int dev_is_partitioned(struct cmd_context *cmd, struct device *dev)
{
	if (!_is_partitionable(dt, dev))
		return 0;                       // 分区本身 / 非分区型 major → 直接放行
	if (_dev_is_partitioned_native(dt, dev) == 1)
		return 1;
	if (external_device_info_source() == DEV_EXT_UDEV) {
		if (_dev_is_partitioned_udev(dt, dev) == 1)
			return 1;               // 读 ID_PART_TABLE_TYPE
	}
	return 0;
}
```

→ 实际运维里 `external_device_info_source` 默认走 `udev`,所以 **`parted`/`fdisk` 建完分区后 udev 的 `ID_PART_TABLE_TYPE=gpt` 立刻生效**,这也解释了为什么对话里「新建分区后操作分区就正常」。

### 🔴 版本差异(本次调研最重要的发现)

`dev-type.c` 在 2.03.14 → main 之间**补上了整套 GPT 判定**,这不是小改动,直接改变判定结果:

| 维度 | `v2.03.14` | `main` |
|---|---|---|
| GPT 判定代码 | ❌ **一个 `gpt` 字符都没有**(实测 `grep -ci gpt dev-type.c` → **0**) | ✅ `_has_gpt_partition_table()` 完整实现 |
| MBR 分支 | 只要有任一分区 `nr_sects != 0` → 判定为分区盘 | 额外识别 `sys_ind == 0xEE`(GPT PMBR)→ 转去查真 GPT |
| GPT 空标签 | — | 只有存在 `part_type_guid != 0` 的分区项才算「分区盘」 |
| `PART_GPT_HEADER_OFFSET_LBA` / `PART_MSDOS_TYPE_GPT_PMBR` 宏 | 不存在 | 存在 |

**对 20T 云盘那台机器意味着什么:**

那台机器的 `/dev/vdb` 是 **GPT** 布局(`parted mklabel gpt` 建的)。但在 2.03.14 上:

1. MBR 判定读到的是 **PMBR**(protective MBR)—— 它的 `nr_sects` 恒非 0,所以 **`ret = 1`,LVM 直接判定「这是个分区盘」并拒掉**
2. 它**根本没有能力去检查 GPT 分区项数组**,也不知道「GPT 只有标签、一个分区都没定义」其实是不该拒的

所以那台机器的拒判路径其实是:

```
PMBR 的 nr_sects != 0  →  ret = 1  →  partitioned filter 拒
   (压根没走到 GPT 判定那一步)
```

**这带来两个实操差异:**

- 🎯 **在那台机器上,「空 GPT(只有 mklabel 没建任何分区)」也一样会被拒** —— 因为旧版只看 PMBR,不看分区项。草稿原先说「空 GPT 不该被拒」只对新版成立,对那台机器**是错的**。要确认只能上机跑 `sgdisk -p /dev/vdb` 看有没有真实分区项。
- 🎯 **旧版比新版更「粗」,所以升级 LVM 不一定让你被拒的盘变可用,反而可能让原本能 `pvcreate` 的空标签盘变成能用了。**排查时别把「升级了 LVM」当成结论。

> 📌 那台机器要拿精确 reason,`-vvv` 里的 `device is partitioned` 在 2.03.14 就已经有了(§二 末尾),不必升级 LVM。

---

## 四、`deferred` 是什么(对话里误读的那点)

`filter <name> deferred <dev>` 是 **LVM 的两阶段过滤**机制,不是修辞。老版(≤2.03.15)的 `filter-partitioned.c` 里这段是原文:

```c
ret = dev_is_partitioned(cmd, dev);

if (ret == -EAGAIN) {
        /* let pass, call again after scan */
        log_debug_devs("filter partitioned deferred %s", dev_name(dev));
        dev->flags |= DEV_FILTER_AFTER_SCAN;
        return 1;                       /* 先放行,扫描后再判 */
}
```

语义拆开:

1. **扫描前**:需要读盘才能判定的 filter 返回 `-EAGAIN`,LVM 先放行(返回 1),打 `deferred` 日志
2. **扫描后**:`DEV_FILTER_AFTER_SCAN` 标记让 `label scan` 在读完 label 后**再跑一遍**完整 filter 链
3. 设计要点:**「已排除」优先于「延迟」** —— 一旦某条 filter 已经明确拒了这个设备,后面那条 filter 延迟返回什么都改变不了结果,所以没必要等扫描后重跑

**新版(main)的等价物**:不再用 `-EAGAIN`,改用 `cmd->filter_nodata_only` 标志位。`filter-partitioned.c` / `signature` / `md` / `fwraid` 四个需要读盘的 filter 开头都是这句:

```c
	if (cmd->filter_nodata_only)
		return 1;
```

即「**这一轮不需要读盘数据,直接过**」。注意这个标志**在 2.03.14 的 `filter-partitioned.c` 里就已经存在**(它是 `-EAGAIN` 分支之外的另一道前置判断),只是当时 `-EAGAIN` 路径仍然有效,所以两者是叠加而非替代 —— 真正去掉 `-EAGAIN` 的提交在 2.03.16 之后。

---

## 五、`wipefs` 到底清不清得掉分区表(对话里说错了)

DeepSeek 说「`wipefs -a /dev/vdb` 就能清空」,这在 GPT 场景**不够**。查了 util-linux 的源码(`libblkid/src/partitions/gpt.c`, `probe_gpt_pt()`):

```c
/* 头部识别:优先 GPT_PRIMARY_LBA,拿不到才回退到 lastlba(备份头) */
h = get_gpt_header(pr, &hdr, &e, (lba = GPT_PRIMARY_LBA), lastlba);
if (!h && !errno)
        h = get_gpt_header(pr, &hdr, &e, (lba = lastlba), lastlba);
...
blkid_probe_use_wiper(pr, lba * blkid_probe_get_size(pr), 8);
blkid_probe_set_magic(pr, blkid_probe_get_sectorsize(pr) * lba, ...);
```

**关键在 `lba` 这个变量**:它记录的是**实际读到头部的那一个**(可能是主头,也可能是尾部备份头),`use_wiper` / `set_magic` 只针对这一个 LBA 写擦除标记。

这意味着 `wipefs -a` 的行为取决于当时主/备两个头**是否都还在**:

| 情形 | `wipefs -a` 结果 |
|---|---|
| 主头、备份头都完整 | 只标记主头 → **备份头还在 → GPT 仍可被识别** |
| 备份头已损坏/被 dd 过 | 落到 `lastlba` 分支 → 备份头也被标记 |
| 主头在、只跑了 `wipefs -a` 一次 | 备份 GPT 头**留存** |

这就是「`wipefs` 跑完还是 `excluded by a filter`」的机制来源。

**手段对照表**:

| 手段 | 清什么 | 对 GPT 是否够 | 备注 |
|---|---|---|---|
| `wipefs -a /dev/vdb` | 文件系统/RAID 签名(LVM `LABELONE`、文件系统 UUID 等) | ⚠️ **不保证** | **不清分区表本身**;且按上面分析可能漏掉尾部备份头 |
| `sgdisk --zap-all /dev/vdb` | 主分区表 + **两个 GPT 头** | ✅ 够 | 20T 场景的标准做法 |
| `dd if=/dev/zero of=/dev/vdb bs=1M count=34` | 头尾 GPT 区 | ⚠️ **只清头尾,不清中间分区项数组** | GPT 头在 LBA1/末尾,但分区项数组紧随主头,`count=34` 覆盖得到;**备份头之外的扇区不动** |
| `blkdiscard /dev/vdb` | 整盘返回 zeros(SSD/NVMe) | ✅ 够 | **会丢整盘全部数据** |

> ⚠️ 注意 `dd count=34` 这一行的精确边界:`_has_gpt_partition_table()` 读的是 **LBA 1 的头 + 从 `part_entries_lba` 开始的分区项数组**。`bs=1M count=34` 覆盖 LBA 0~67,足以覆盖默认 GPT 的头部区(含最多 128 个分区项,32MB)。但如果 `sgdisk` 用过很大的 `-e` 扩展分区项数量,就需要相应加大 `count`。**不确定就别用 dd,用 `sgdisk --zap-all`。**

---

## 六、正确的操作顺序(可直接抄)

```bash
# 0) 先确认盘上到底有没有「真实分区项」
#    注意:旧版 LVM 只看 PMBR,新版才看 GPT 分区项,这一步两个版本都要做
sgdisk -p /dev/vdb
# 或
fdisk -l /dev/vdb

# 1) 20T 大盘的标准做法:先分区,再建 PV
parted -s /dev/vdb mklabel gpt
parted -s -a optimal /dev/vdb mkpart primary 0% 100%
# 或一条龙: parted -s -a optimal /dev/vdb mklabel gpt mkpart primary 0% 100%
partprobe /dev/vdb     # 不重启也能让内核看到 /dev/vdb1

# 2) 对分区建 PV / VG —— 这是 LVM 期望的输入
pvcreate /dev/vdb1
vgcreate vg_data /dev/vdb1
pvs
vgs

# 3) 建 LV
lvcreate -n data -L 19T vg_data
```

**排查「为什么被拒」的标准命令**:

```bash
# 1) 最直接:让 LVM 把每条 filter 的判定和精确 reason 都打出来
#    那台机器(LVM 2.03.05~2.03.14)也能直接打印 'device is partitioned' —— 不需要升级
pvcreate -vvv /dev/vdb 2>&1 | grep -iE "partitioned|Skipping|excluded|device is"

# 2) 确认盘上到底有没有「真实分区项」
#    旧版只看 PMBR,新版才看 GPT 分区项,这一步两个版本都要做
sgdisk -p /dev/vdb
fdisk -l /dev/vdb

# 3) 改过 lvm.conf 的 filter 之后必须清 filter 缓存(persistent filter 会缓存整条链的结果)
pvscan --cache
```

拿到精确 reason 的输出长这样(`dev_filtered_reason()`,2.03.14 起就有):

```
  Cannot use /dev/vdb: device is partitioned
```

reason 字符串全表(`lib/cache/lvmcache.c`),排查时可对照:

| filtered_flags | reason 字符串 |
|---|---|
| `DEV_FILTERED_PARTITIONED` | `device is partitioned` |
| `DEV_FILTERED_SIGNATURE` | `device has a signature` |
| `DEV_FILTERED_REGEX` | `device is rejected by filter config` |
| `DEV_FILTERED_SYSFS` | `device is missing sysfs info` |
| `DEV_FILTERED_MINSIZE` | `device is too small (pv_min_size)` |
| `DEV_FILTERED_UNUSABLE` | `device is not in a usable state` |
| `DEV_FILTERED_DEVICES_FILE` | `device is not in devices file` |
| `DEV_FILTERED_IS_LV` | `device is an LV` |
| `DEV_FILTERED_FWRAID` | `device is a firmware RAID component`(**仅 main 有**) |

> 🎯 这张表就是「报错只说现象,`-vvv` 才给真因」的落地方式 —— 一行 grep 就能区分「有分区表被拦」vs「有 PV 签名被拦」vs「配置把它过滤了」vs「盘太小」。

---

## 七、风险点 / 容易踩的坑

| 坑 | 后果 | 对策 |
|---|---|---|
| 对**整盘**跑 `pvcreate` | 被 `partitioned` filter 拒,白折腾 | 先分区,或 `sgdisk --zap-all` 后重建 |
| 以为改 `lvm.conf` 的 `filter` 能绕过 | 白改配置,还可能误伤别的设备 | `partitioned` filter **无配置开关** |
| 改完 `lvm.conf` 没 `pvscan --cache` | persistent filter 缓存旧结果,看起来「改了没用」 | 改完立刻清缓存 |
| 以为 `wipefs -a` 清 GPT | 白跑一遍还是被拒 | `sgdisk --zap-all` / `blkdiscard` |
| **拿新版 LVM 的判定逻辑去解释老机器的行为** | 结论对不上那台机器 | 老版 `dev-type.c` **零 GPT 逻辑**,只看 PMBR。见 §三 |
| **以为「升级 LVM」能解决拒判** | 升级后判定更严,原本能建的盘可能反而不能建 | 先上机 `sgdisk -p` 确认真实分区项,再决定 |
| 分完区忘 `partprobe` | udev 没更新,`/dev/vdb1` 不存在 | `partprobe /dev/vdb` 或 `udevadm settle` |
| 分区表在**用**的盘上被 `zap` | VG 损坏 / 数据丢失 | 先 `vgexport` + 确认无 LV 挂载 |
| 20T 用 MBR | 只支持 2T,且 fdisk 存不下 | 必须 GPT |

---

## 八、跟我们的关系

- **和本机无关**:Mac mini 是 macOS 13.6,没有 LVM。本篇是**给 Linux 云主机 / 内网 Kylin V10 那台机**用的排查条目 —— 对应本仓已有的 [kylinV10DisableIPv6](kylinV10DisableIPv6.md)(同一台机器的 IPv6 处置)和 [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md)(磁盘账本排查思路)。
- **可复用的方法论**:和 [performanceTriage](performanceTriage.md) 同源 —— **不要只信报错文本,要跑 `-vvv` 拿到底层判定**。`excluded by a filter` 是笼统措辞,`dev_filtered_reason()` 在 2.03.14 起就已经能区分 `device is partitioned` / `device has a signature` / `device is not in devices file`,只是默认日志级别不打印。**这不是版本问题,是「没开 -vvv」的问题。**
- **本篇真正的方法论收获**:拿到不确定结论时,**把目标机器对应的那个版本也拉下来读**。这份草稿初稿全部基于 `main` 分析,结果对着 ≤2.03.14 的机器讲「新版才有的 GPT 精细判定」—— 而那台机器 `dev-type.c` 里**连一个 `gpt` 字符串都没有**。凡是「排查某台特定机器」类笔记,**代码引用必须锁定该机器的版本**,这是本次踩的坑。
- **同类「笼统报错」清单**:本仓 [opsTroubleshootingTCPPortExhaustion](opsTroubleshootingTCPPortExhaustion.md) 里的 `EADDRNOTAVAIL` 也是同一类 —— 报错只说现象,`ss`/`-vvv` 才给真因。
- **下次遇到**:直接 `pvcreate -vvv /dev/vdX 2>&1 | grep -i partitioned`,90% 的场景一行就能定位。

---

## 参考链接

- LVM2 上游仓库: https://gitlab.com/lvmteam/lvm2
- `partitioned` filter 源码(`main`): https://gitlab.com/lvmteam/lvm2/-/blob/main/lib/filters/filter-partitioned.c
- `partitioned` filter 源码(`v2_03_14`,**那台机器所在区间**): https://gitlab.com/lvmteam/lvm2/-/blob/v2_03_14/lib/filters/filter-partitioned.c
- 分区表判定逻辑(`main`): https://gitlab.com/lvmteam/lvm2/-/blob/main/lib/device/dev-type.c
- 分区表判定逻辑(`v2_03_14`,**无 GPT 逻辑**): https://gitlab.com/lvmteam/lvm2/-/blob/v2_03_14/lib/device/dev-type.c
- filter 链装配(`main`): https://gitlab.com/lvmteam/lvm2/-/blob/main/lib/commands/toolcontext.c
- 过滤原因 reason 字符串(`main`): https://gitlab.com/lvmteam/lvm2/-/blob/main/lib/cache/lvmcache.c
- 过滤原因 reason 字符串(`v2_03_14`): https://gitlab.com/lvmteam/lvm2/-/blob/v2_03_14/lib/cache/lvmcache.c
- util-linux GPT 探测(`wipefs` 擦除哪一头): https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/plain/libblkid/src/partitions/gpt.c
- `pvcreate` man: https://man7.org/linux/man-pages/man8/pvcreate.8.html
- `pvscan` man: https://man7.org/linux/man-pages/man8/pvscan.8.html
- `sgdisk` man(8): https://man7.org/linux/man-pages/man8/sgdisk.8.html
- `wipefs` man: https://man7.org/linux/man-pages/man8/wipefs.8.html
- 原始对话: https://chat.deepseek.com/share/e60sxa3wzhxukag3p4