# 运维思路:df 说满、du 说没满 —— 磁盘上的「幽灵空间」排查与延伸

> 学习笔记 · 调研时间 2026-08-12
> 调研来源: 微信公众号「胡哥Linux运维」,作者胡登治(RHCA,15 年 Linux 运维)
> 原文: https://mp.weixin.qq.com/s/VZ4NGs_IXLs5j8gUiB0ATw
> 系列定位: 「Linux 诡异现象排错」收官篇(前 4 篇:load 飙高 CPU 闲 等)
> 用途: 把文章里零散的「三板斧」梳理成可复用的运维排查思路

## 一句话定位

`df` 满、`du` 不满,**空间没丢**,只是被账本外的「幽灵」占着 —— 从这一个反直觉现象提炼出**「账本对账」**的运维通用排查思路,可迁移到 CPU、内存、inode、文件句柄、网络连接等所有「账本对不上」的场景。

---

## 一、案例还原

### 现象

```
某机器磁盘告警 100% → 删了 20G 日志 → 告警还在响
df -h    : 100% used
du -sh / : 比 df 报的小 20G+ ← 「账本对不上」
```

### 核心思想(作者原话)

> 系统从不骗你,骗你的是你只看了一半。
> 慢一点,把账本和目录对上,比删十遍日志都管用。

`df` 看的是**文件系统超级块(superblock)**的统计,`du` 看的是**目录树遍历**的实际占用。两者本来就不该严格相等,但差距大到影响判断时,就是有东西在「账本外」占着空间。

---

## 二、三板斧排查(直接复用作者思路)

### 第一板斧:`lsof +L1` —— 找「已删除但还被进程占着」的文件

```bash
# 列出所有已被删除、但仍被进程打开的文件
lsof +L1 | grep deleted

# 看具体被谁占着、占多大
lsof +L1 | awk '$5=="REG" {print $1, $2, $7, $9}'
```

**原理**: 文件被 `rm` 后,目录项消失 → `du` 看不见;但进程的 fd 还指向那个 inode → 空间不释放,`df` 仍记账。

**处理(踩坑点)**:

| ❌ 新手做法 | ✅ 资深做法 |
|---|---|
| 看到 deleted 直接 `kill -9` | 先 `kill -HUP` 让进程重开日志 |
| 强杀进程导致线上故障 | 优雅重启 / reload,让句柄自然释放 |
| 一次杀到底 | 一个个进程的 `fd` 看明白再动手 |

**经验法则**:
- 日志类进程(nginx/rsyslog/java)大多数支持 reload 配置文件 + 重开日志句柄
- 不支持的(`kill -HUP` 不响应)才考虑 graceful restart
- 实在不行再 `kill -TERM` 给 graceful shutdown 时间
- **绝不**上来就 `kill -9`(等于线上故障的快速通道)

---

### 第二板斧:`df -i` —— inode 是不是耗尽了

```bash
df -i              # inode 使用率
df -hT /           # 同时看块使用率 + 文件系统类型

# 找哪个目录小文件最多
find /path -xdev -type f | awk -F/ '{print $2}' | sort | uniq -c | sort -rn | head
```

**踩坑点**:
- `df -h` 正常但**写文件报 "No space left on device"** —— 第一反应别怀疑权限,**先 `df -i`**
- 海量小文件场景(会话文件、缓存碎片、Docker 层)很容易把 inode 打满
- ext4/xfs 的 inode 数量在**建文件系统时基本定死**,后期不好扩
- 预防靠:**目录生命周期规划** + **清理脚本** + **建文件系统时给 inode ratio 留余量**

---

### 第三板斧:挂载点遮挡 + Docker 日志

#### ① 挂载点遮挡

```bash
# 把盘 mount 到 /data 之后,/data 原文件被"盖住"看不到
mount | grep /data
# 想看底层真实占用:umount 再看,或用 bind mount 另看
```

**原理**: mount 后,VFS 把挂载点替换成新文件系统,旧目录内容"被遮蔽"但 inode 仍占用超级块。

#### ② Docker 日志没轮转

```bash
du -sh /var/lib/docker  # 看 docker 占了多少
docker system df        # 看 image/container/volume/build cache 分布

# 给容器日志加大小限制(/etc/docker/daemon.json)
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "100m", "max-file": "3" }
}
```

**踩坑点**:
- Docker 日志**默认不限制**,跑半年几十 G 很正常
- 别等满了才加 `max-size`,**上线就该配**
- `overlay2` 的已退出容器层也会占空间,定期 `docker system prune`
- 清之前 `docker ps -a` 确认没在跑

---

## 三、由「磁盘幽灵」提炼的**通用运维排查思路**

文章表面在讲磁盘,但底层是**「账本对账」**这一通用思路。可迁移到所有「账面数字 vs 实际现象对不上」的场景。

### 1. 三类「账本」要分清

| 账本 | 谁在维护 | 怎么查 | 特点 |
|---|---|---|---|
| **内核统计** | VFS / 内核子系统 | `df` / `free` / `lsof` / `ss` | 实时准,但跟目录树不一定对得上 |
| **文件系统遍历** | 用户态工具 | `du` / `find` / `tree` | 慢,但跟"人眼看到的文件"一致 |
| **应用层计数** | 业务进程 | 应用 metrics / 日志 | 跟业务耦合,口径自定义 |

> **运维第一反应**: 账本对不上 = **多个账本**,不是系统坏了。

### 2. 由表及里的排查顺序

```
现象(告警/报错)
  ↓
账本 1: 资源账面数字(df / free / nstat / iostat)
  ↓
账本 2: 用户态遍历(du / find / lsof / ss / ps)
  ↓
账本 3: 应用层 metrics + 日志
  ↓
内核层: /proc / /sys (单进程视角、fd、句柄、中断、slab)
  ↓
硬件层: smartctl / dmesg / IPMI / BMC
```

**核心原则**:**先对账,再动手**。`kill -9` 和 `rm -rf` 是最后手段,不是第一步。

### 3. 紧急止血 vs 长期根治

| 阶段 | 目标 | 典型动作 |
|---|---|---|
| **T+0 ~ 5min: 止血** | 让告警先消 | 删大文件、reload 日志、扩容临时盘 |
| **T+5 ~ 30min: 定位** | 找到根因 | lsof / df -i / docker inspect / 应用日志 |
| **T+30min+: 根治** | 不再复发 | 改配置(logrotate/max-size/inode ratio)、改流程(归档 SOP)、改监控 |
| **T+1day: 复盘** | 防止下次 | 写 incident doc、加自动化巡检、容量规划更新 |

### 4. 同类「账本对不上」场景速查

| 场景 | 账本 1(账面) | 账本 2(实际) | 排查命令 |
|---|---|---|---|
| **CPU 闲但 load 高** | `top`/`uptime` load 飙 | `top` 看 CPU% 闲 | `ps -eLf` 看 D 状态进程;`iostat` 看 IO wait |
| **内存够但 OOM** | `free` 还有 | 业务 OOM killed | `dmesg \| grep -i oom`;`/proc/pressure/memory` |
| **inode 满** | `df -h` 有空间 | `touch` 报 no space | `df -i` |
| **fd 耗尽** | `ulimit -n` 看着够 | 进程开不了新 fd | `cat /proc/sys/fs/file-nr`;`lsof \| wc -l` |
| **连接数满** | `ss -s` 总数大 | 新建连接失败 | `ss -s`;`netstat -ant \| awk '{print $6}' \| sort \| uniq -c` |
| **磁盘满** | `df -h` 100% | `du` 找不到大文件 | `lsof +L1`;`df -i`;`mount`;`du /var/lib/docker` |
| **带宽满但 idle** | `nload` 100% | 业务流量看着不多 | `iftop`/`nethogs` 看谁在打;`ss -ntp` 看长连接 |

---

## 四、预防机制(把救火变常态)

### 1. 监控覆盖 —— 不止盯「块」,还要盯「inode / fd / 句柄」

```yaml
# 典型告警阈值(给监控/Prometheus 参考)
disk_used_percent:        > 85%  warn / > 92% critical
disk_inode_used_percent:  > 85%  warn / > 92% critical
open_files:               > 80% of fs.file-max
load_average:             > 2 * cpu_count for 5min
oom_kills:                rate > 0 for 5min
```

### 2. 容量规划 —— 不止算「大小」,还要算「数量」

```bash
# 建文件系统时显式调 inode ratio
mkfs.ext4 -N <inode_count> /dev/sdb     # ext4: 固定 inode 数
mkfs.xfs  -i maxpct=5 /dev/sdb          # xfs:  5% 给 inode 块
```

业务侧:任何会**高频创建小文件**的模块(session、cache、log、临时文件),上线前算清楚 inode 预算。

### 3. 日志治理 —— 默认就限,别等满了再加

| 服务 | 治理项 |
|---|---|
| 系统日志 | rsyslog `/etc/logrotate.d/` |
| Nginx/Apache | 自带 `logrotate` + `daily/rotate 30` |
| Java 应用 | Logback `SizeBasedTriggeringPolicy` + `maxHistory` |
| Docker | daemon.json `log-opts.max-size: 100m` |
| 数据库 | binlog 保留天数 + slow log 单独目录 |

### 4. 自动化巡检 —— 把救火脚本沉淀成 cron

```bash
# 每天巡检(放到 cron.daily)
#!/bin/bash
# 1. 删了但还占着的文件
ALERT=$(lsof +L1 | awk '$5=="REG"' | wc -l)
[ "$ALERT" -gt 10 ] && alert "deleted files held by processes: $ALERT"

# 2. inode 紧张
df -i | awk 'NR>1 && $5+0>85 {print $6, $5}'

# 3. docker 占用
du -sh /var/lib/docker

# 4. 日志 7 天没转
find /var/log -name "*.log" -mtime +7 -size +100M
```

### 5. Runbook 沉淀 —— 把救火经验变成知识

每处理一次「磁盘满」,在知识库留一份:
- 现象 / 排查路径 / 处理动作 / 根因 / 改进项
- 下次新人接手能 5 分钟定位而不是一晚上懵

---

## 五、跟我们的关系

| 关联点 | 用法 |
|---|---|
| **PVE 主机(10.10.66.208)** | VM 100 跑日常工作,磁盘满直接卡住;巡检脚本加 `lsof +L1` + `df -i` 检查 |
| **Kylin V10(国产 OS)** | 内核/文件系统跟 CentOS 略有差异,`lsof`/`df` 行为一致,但 `/var/log/messages` 大小可能更夸张(国密/审计日志多) |
| **WAF 巡检机器** | `/var/log/waf` 是高频写日志目录,必有 logrotate + inode ratio 留余 |
| **等保 2.0/3.0** | 容量监控 + 告警阈值是必查项,「inode 满但磁盘有空间」这种反直觉案例要进整改清单 |
| **私活 / 后端服务** | Spring Boot 日志 logback 默认无限增长,生产**必须** `SizeBasedTriggeringPolicy` + `maxHistory=30` |

---

## 六、一图总结(给团队传阅)

```
运维救火三原则
  ① 先对账,再动手(df vs du、free vs slab、load vs CPU)
  ② 紧急止血 ≠ 长期根治(分阶段做事,别混在一起)
  ③ 每救一次火,沉淀一份 Runbook(别让下次再懵一晚上)

排查顺序
  现象 → 账本 1(内核) → 账本 2(用户态) → 账本 3(应用) → /proc → 硬件

磁盘案例(本次)
  lsof +L1     →  进程占着的 deleted
  df -i        →  inode 耗尽
  mount/docker →  挂载遮挡 / docker 日志
```

---

## 参考链接

- 原文: https://mp.weixin.qq.com/s/VZ4NGs_IXLs5j8gUiB0ATw
- 作者公众号: 胡哥Linux运维
- 同系列前篇: load 飙高 CPU 闲(占位,待补)
- 配套工具:`lsof`(自带)、`df`、`mount`、`docker system df`、`/proc`