# 数据恢复 SOP — 误删数据表 / 文件损坏的恢复思路

> 学习笔记 · 调研时间 2026-09-05
> 原文: 微信公众号「胡哥Linux运维」— *手滑清空了 40GB 生产表，8 小时后我全救回来了*
> URL: <https://mp.weixin.qq.com/s/ir0co7yRPyW5Ba2rd79ETg>
> 作者: 胡登治 (15年Linux运维,RHCA架构师)

---

## 0. 一句话定位

**误删不可怕,可怕的是没有预案** — 任何数据丢失场景(MySQL DROP / DELETE / UPDATE / 文件 `rm -rf` / RAID 故障 / git 误推 / 容器删 PVC)的通用恢复 SOP,**核心思路都是「先止损 → 再备份现场 → 定方案 → 验证 → 回放 → 校验」**。

== 本文以原文 MySQL DELETE 误删 40GB 表 8 小时恢复为案例,**扩展到 5 大通用场景**。

## 1. 原文案例 (MySQL DELETE 误删 40GB 表)

### 1.1 灾难现场

```
2019 年 22:47
业务低峰期,DBA 准备清理一张核心业务表的历史数据:
  DELETE FROM 表名 WHERE create_time<'2019-xx-xx';

手指滑了,WHERE 条件漏掉,回车 → 整表被清空!

数据库: MySQL 5.7 + 主从架构
影响范围: 一张表 ≈ 40GB,几千万行,每天几十万写入
```

### 1.2 8 小时恢复时间线

| 时段 | 步骤 | 耗时 |
|---|---|---|
| **Hour 1** | 先止损,再确认「命根子」 | 22:47 - 23:10 |
| **Hour 2** | 动手前,先把现场备份下来(后悔药) | 23:10 - 23:45 |
| **Hour 3** | 定方案(主闪回 + Plan B 备份兜底) | 23:45 - 00:45 |
| **Hour 4-5** | 生成反转 SQL(MyFlash / binlog2sql) | 00:45 - 02:45 |
| **Hour 6-7** | 独立环境验证 → 主库回放 | 02:45 - 05:15 |
| **Hour 8** | 校验 / 切流量 / 复盘 | 05:15 - 07:00 |

**07:00 业务方上班前,事故结束**。

## 2. 通用 SOP — 5 大场景适用

== 这套思路**不只是 MySQL DELETE 误删**,任何数据丢失场景都适用:

| 场景 | 核心思路 | 关键工具 |
|---|---|---|
| **MySQL DELETE 忘 WHERE** | binlog ROW 前像 → 反转 INSERT | binlog2sql / MyFlash |
| **MySQL DROP TABLE** | 全备 + binlog 重放 | mysqldump / xtrabackup |
| **误 `rm -rf` 文件** | fs 反删除 + extundelete + 快照 | extundelete / photorec / git reflog |
| **RAID 损坏 / 磁盘掉线** | ddrescue + RAID 重组 | ddrescue / mdadm |
| **git 误推 (force push)** | reflog 恢复 + revert | git reflog |
| **容器 PVC 误删** | k8s snapshot + CSI restore | velero / snapshot-controller |

== **底层 SOP 是同一个**:**「止损 → 备份现场 → 评估工具 → 验证 → 回放 → 校验」**

## 3. 通用 9 步恢复 SOP(从原文 + 扩展)

```
┌──────────────────────────────────────────────────────────────────┐
│  STEP 1: 锁库止损(read_only=ON, 停写入)                       │
│  - MySQL: SET GLOBAL read_only=ON; 停止应用写入                │
│  - 文件: 立即 umount 文件系统 / 停相关服务                      │
│  - K8s: cordon 节点,停止 Pod                                     │
│  - Git: 联系协作者暂停 push                                       │
│                                                                  │
│  ⏱ 时长: 5-15 分钟                                                │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 2: 确认「命根子」在不在(工具能不能用的前提)              │
│  - MySQL:                                                          │
│      SHOW VARIABLES LIKE 'binlog_format';        -- 必须是 ROW   │
│      SHOW VARIABLES LIKE 'binlog_row_image';     -- 必须是 FULL   │
│      SHOW VARIABLES LIKE 'expire_logs_days';     -- 覆盖事发时段  │
│  - 文件:                                                          │
│      mount | grep <fs>                                            │
│      df /data                                                     │
│  - K8s:  PV/PVC snapshot 状态                                    │
│  - Git:  reflog 是否还有记录                                      │
│                                                                  │
│  ⚠️ 这是命根子检查 — 没有这些,工具直接抓瞎                     │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 3: 备份现场(后悔药 — 整个 SOP最反直觉但最关键)        │
│  - binlog 物理隔离 + 只读:                                       │
│      rsync -avp /data/mysql/binlog/ /backup/incident/binlog/     │
│      chmod -R a-w /backup/incident/binlog/                       │
│  - 现状全量备份:                                                  │
│      xtrabackup --backup --target-dir=/backup/incident/full      │
│  - 文件 dd 整个磁盘:                                              │
│      dd if=/dev/sda of=/backup/disk.img bs=4M conv=noerror,sync │
│  - Git reflog export:                                             │
│      git reflog > /backup/git-reflog-$(date +%s).txt              │
│  - K8s PV snapshot:                                                │
│      kubectl create snapshot <name> --selector ...                │
│                                                                  │
│  ⚠️ 备份「已经被清空」的状态 — 看似没用,但恢复失败时是兜底    │
│  💡 慌的时候最想省这一步,恰恰最不能省                            │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 4: 定方案(主路径 + Plan B 兜底)                          │
│  - MySQL DELETE 误删:                                              │
│      主: binlog 闪回(DELETE → INSERT)                          │
│      Plan B: 全备 + 增量 + binlog 回放                           │
│  - MySQL DROP TABLE:                                                │
│      全备恢复 + binlog 重放到 DROP 前                            │
│  - 文件误删:                                                        │
│      extundelete / photorec / testdisk                           │
│  - 磁盘 RAID 损坏:                                                  │
│      ddrescue 单盘 → RAID 重组                                    │
│  - Git force push:                                                   │
│      git reflog → git reset --hard <old-sha>                      │
│  - K8s PVC 误删:                                                    │
│      restore from snapshot via Velero / snapshot-controller         │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 5: 定位误删范围(从 BEGIN 算起)                          │
│  - MySQL: binlog2sql 找到 DELETE 事务范围:                        │
│      python binlog2sql.py -h ... -d 库名 -t 表名                  │
│          --start-file='mysql-bin.000XXX' --sql-type=DELETE        │
│  - Git: git fsck --lost-found                                      │
│  - 文件: debugfs 找到删除 inode                                   │
│                                                                  │
│  ⚠️ 起点要从事务 BEGIN 算,不是从 DELETE 那行                   │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 6: 生成恢复 SQL(工具干活,反复核对)                     │
│  - MySQL: MyFlash (C++, 更快):                                    │
│      ./myflash --binlogFile=mysql-bin.000XXX                     │
│          --start-position=XXXX --stop-position=YYYY               │
│          --database=库名 --table=表名 --sqlTypes=DELETE          │
│          --outBinlogFileNameBase=rollback                        │
│  - 或 binlog2sql -B (flashback) 参数                              │
│  - Git: git checkout <old-sha> -- .                               │
│  - 文件: extundelete --restore-all                                │
│                                                                  │
│  ⏱ 40GB 表 几千万行 → 好几个 GB 的 SQL 文件(几个小时)            │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 7: 独立环境验证(从库 / sandbox,不能直接上生产)         │
│  - MySQL: 拉从库停复制,执行 rollback.sql,做 3 组对比:        │
│      SELECT COUNT(*) vs 被删前记录数                              │
│      SELECT MIN(create_time), MAX(create_time) 抽查时间范围      │
│      SELECT SUM(amount) 业务对账                                  │
│  - Git: 检出到新分支,跑测试 / CI                                  │
│  - 文件: 校验 MD5 / 内容对比                                     │
│                                                                  │
│  ⚠️ 反向 SQL 不能直接往主库扔 — 必须先验证                      │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 8: 主库 / 主环境回放                                       │
│  - MySQL:                                                          │
│      SET sql_log_bin=OFF;  -- 避免 INSERT 再写 binlog            │
│      SET FOREIGN_KEY_CHECKS=0;  -- 防外键卡死                    │
│      source rollback.sql                                           │
│  - Git: git push --force-with-lease (默认拒绝 force-push)        │
│  - 文件: cp 回去原路径                                            │
│  - K8s: kubectl apply -f restored-pvc.yaml                        │
│  - 几个 GB 的 SQL 逐行执行,IO 压力很大 → 只能硬等                │
└──────────────────┬───────────────────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────────────────┐
│  STEP 9: 校验 + 切流量 + 复盘                                    │
│  - 记录数对账 + 业务冒烟 + 主从复制状态                          │
│  - 通知业务方,观察无延迟/无报错                                  │
│  - 写事故报告 + 改进措施(下次前不踩坑)                       │
└──────────────────────────────────────────────────────────────────┘
```

## 4. 关键命令清单(MySQL DELETE 误删场景)

### 4.1 止损

```sql
-- 主库立即只读
SET GLOBAL read_only=ON;

-- 停止应用写入(应用层断开)
```

### 4.2 确认命根子

```sql
-- binlog 格式必须是 ROW
SHOW VARIABLES LIKE 'binlog_format';

-- 行镜像必须完整
SHOW VARIABLES LIKE 'binlog_row_image';

-- 保留期覆盖事发时段
SHOW VARIABLES LIKE 'expire_logs_days';

-- 当前 binlog 文件 + 位点
SHOW MASTER STATUS;
```

### 4.3 备份现场(后悔药)

```bash
# binlog 物理隔离 + 只读
rsync -avp /data/mysql/binlog/ /backup/incident_2019/binlog/
chmod -R a-w /backup/incident_2019/binlog/

# 现状全量备份(用 xtrabackup,在线热备)
xtrabackup --backup --target-dir=/backup/incident_2019/current_full
```

### 4.4 定位误删窗口

```bash
# binlog2sql 列出 DELETE 事件
python binlog2sql.py -h 127.0.0.1 -P 3306 -uroot -p'xxx' \
    -d 库名 -t 表名 \
    --start-file='mysql-bin.000XXX' \
    --sql-type=DELETE
```

### 4.5 生成反转 SQL

```bash
# MyFlash (C++, 更快)
./myflash --binlogFile=mysql-bin.000XXX \
    --start-position=XXXX --stop-position=YYYY \
    --database=库名 --table=表名 --sqlTypes=DELETE \
    --outBinlogFileNameBase=rollback

# 或 binlog2sql -B (Python, 社区用更广)
python binlog2sql.py ... -B > rollback.sql
```

### 4.6 验证 + 回放

```sql
-- 独立环境(从库停复制)执行
source rollback.sql;

-- 验证 3 组对比
SELECT COUNT(*) FROM 表名;
SELECT MIN(create_time), MAX(create_time) FROM 表名;
SELECT SUM(amount) FROM 表名;

-- 主库回放时
SET sql_log_bin=OFF;
SET FOREIGN_KEY_CHECKS=0;
source rollback.sql;
COMMIT;
```

## 5. 5 大场景命令对比表

| 步骤 | MySQL DELETE | MySQL DROP | 文件 rm | Git force | K8s PVC |
|------|---------------|-------------|---------|-----------|---------|
| **止损** | `read_only=ON` | `read_only=ON` | `umount` | `联系协作者` | `cordon node` |
| **命根子** | `binlog_format=ROW` | `binlog_format=ROW` | `mount` 检查 | `git reflog` | `PV snapshot` |
| **现场备份** | `rsync binlog + xtrabackup` | 同左 | `dd 整个磁盘` | `git reflog > file` | `kubectl snapshot` |
| **方案** | binlog 闪回 | 全备 + binlog 回放 | extundelete | reflog reset | restore from snapshot |
| **定位** | `binlog2sql` | `binlog2sql --sql-type=DROP` | `debugfs inode` | `git fsck` | `velero restore` |
| **恢复工具** | MyFlash / binlog2sql -B | xtrabackup prepare + binlog replay | extundelete | `git reset --hard` | `velero restore --from-backup` |
| **验证** | 3 组 SELECT 对账 | 全表 COUNT 对账 | MD5 对比 | 跑 CI | Pod 启动测试 |

## 6. 5 大反直觉点(原文核心)

### 6.1 **「反直觉点 1」:恢复前先备份现场**

```
恢复动作本身就是最高风险操作
反转 SQL 回放失败 / 位点算错 / 主从复制错乱
任何一个环节翻车都可能把环境进一步污染
所以动手前必须先给现场留一份「后悔药」
```

### 6.2 **「反直觉点 2」:备份「已经被清空」的状态**

```
这份备份看起来没用(已经被清空)
但它是兜底中的兜底:
万一恢复过程把环境搞得更糟(主从错乱、binlog 被污染)
至少能回到现在这个「已知状态」重新来
而不是在未知里越陷越深
```

### 6.3 **「反直觉点 3」:DELETE 忘 WHERE 比 DROP 更危险**

```
DROP TABLE: DDL, 权限管控严,普通账号没有权限
DELETE: DML, 连得上库的账号都能执行,连 DBA 权限都不用
执行完还不报错 — 只是回显「影响行数很大」,不红字警告
```

### 6.4 **「反直觉点 4」:熟手最容易栽在「我以为」上**

```
低峰期不等于安全期
熟手最容易栽在「我以为」上:
- 你以为写对了语句
- 你以为不会误触
- 你以为影响行数正常
三个「我以为」,就是一次 P0
```

### 6.5 **「反直觉点 5」:慌的时候最想省的就是这一步**

```
「先备份现场」是慌的时候最想省的一步
恰恰最不能省
恢复失败不可怕,可怕的是失败之后连现场都没了
```

## 7. 6 大预防铁律(原文作者贴工位上)

| # | 铁律 | 实施 |
|---|---|---|
| 1 | **UPDATE/DELETE 前先 SELECT COUNT(*)** | 看影响行数,清历史数据写进变更流程,两人确认 |
| 2 | **高危操作包在事务里** | BEGIN → 确认 → COMMIT,忘 WHERE 一条 ROLLBACK 救回 |
| 3 | **延迟从库 1 小时** | 真出事直接跳过错误语句 |
| 4 | **先 RENAME 再 DROP** | 改名到回收站,观察一个备份周期再真删 |
| 5 | **恢复前先备份现场** | binlog + xtrabackup 兜底 |
| 6 | **没有预案 = 灾难** | 备份 + binlog = 慌时能走通的路 |

## 8. 6 大常见踩坑(扩展)

### 8.1 起点选错,缺主键约束

```
定位起点要从 DELETE 事务的 BEGIN 算起
不是从 DELETE 那行开始
否则反转 SQL 缺主键约束
```

### 8.2 回放时 INSERT 再写 binlog

```
SET sql_log_bin=OFF
避免回放产生的 INSERT 再写 binlog(否则循环引用)
```

### 8.3 外键约束卡死

```
SET FOREIGN_KEY_CHECKS=0
防外键约束卡死(主从复制也会卡)
```

### 8.4 位点差一位,缺行 / 卷进别人

```
binlog 解析几个 GB 的日志
确认每一段事件的边界,容不得半点马虎
位点差一位,反转出来的 SQL 就可能缺行
或者把别人的操作也卷进来
```

### 8.5 多个 GB 的 SQL 逐行执行,IO 大

```
磁盘 IO 压力很大,只能硬等
```

### 8.6 备份「已知现场」+ 兜底中的兜底

```
不要在未知里越陷越深
至少能回到现在这个「已知状态」重新来
```

## 9. 5 大工具对照(MySQL 闪回)

| 工具 | 语言 | 速度 | 适用 | URL |
|------|------|------|------|-----|
| **MyFlash** | C++ | 快(几 GB 几小时) | 大表恢复 | 美团开源 |
| **binlog2sql** | Python | 慢 | 通用,社区广 | danfengcao/binlog2sql |
| **mysqlbinlog** | C | 最快但需手工 | 熟练 DBA | MySQL 官方 |

== 原理都一样:**读 ROW 事件的前像,DELETE → INSERT,UPDATE → 反向 UPDATE**。

## 10. 5 大扩展场景(我加的,原文只有 MySQL)

### 10.1 文件系统误删

```bash
# extundelete 恢复 ext4 文件
umount /dev/sda1  # 先 umount,防止覆盖
extundelete /dev/sda1 --restore-all

# 或 photorec (更广,但只能按文件类型恢复)
photorec /dev/sda1
```

### 10.2 Git force push 误操作

```bash
# 1. 立刻找到 force 前的 commit
git reflog  # 找 :before-force-push 那一行

# 2. reset 到那个 commit
git reset --hard <old-sha>

# 3. 强制推送(默认拒绝,要 override)
git push --force-with-lease origin main
# 或者 webhook 联系协作者不要 pull

# 4. 预防:设 remote 拒绝 force-push
# GitHub: Settings → Branches → Branch protection rules
# Enable: "Do not allow force pushes"
```

### 10.3 RAID 损坏 / 磁盘掉线

```bash
# 1. 立即停读写,dd 整盘镜像
ddrescue /dev/sda /backup/sda.img /backup/sda.log

# 2. 尝试 RAID 重组(mdadm)
mdadm --assemble --force /dev/md0 /dev/sd[abcd]1

# 3. 失败:extundelete / photorec 恢复文件
```

### 10.4 K8s PVC 误删

```bash
# 1. 立即 cordon 节点(防止新 Pod 重启写入空卷)
kubectl cordon <node>

# 2. Velero restore (推荐,有快照前提)
velero restore create --from-backup <backup-name>

# 3. 或 volume snapshot restore
kubectl apply -f restored-pvc.yaml
```

### 10.5 Postgres 类似场景

```sql
-- pg_dump 恢复
pg_restore -d dbname dumpfile

-- WAL replay 到指定时间点 (PITR)
recovery_target_time = '2026-09-05 22:47:00'
```

## 11. 5 大可迁移的工程方法(到我自己的项目)

### 11.1 OpenOPC

- **scope.md 有 auth 状态记录**(类比 MySQL binlog 的前置条件)
- **任务执行前先 snapshot state**(类比「备份现场」)
- **task artifact 持久化**(类比「备份 binlog」)

### 11.2 substation-blueprint

- **scene.js 是 source of truth**(类比 Nova3D 哲学)
- **3D 资产修改前先 git commit**(类比「先备份现场」)
- **theme 切换不动 source**(类比 MySQL 「回放不破坏环境」)

### 11.3 iswiki

- **写文档前先 fetch + rebase**(类比「先备份现场」)
- **commit 前先看 git diff**(类比「验证」)
- **rollback 到 last working commit**(类比「主库回放」)

## 12. 5 大跟火灾 / 不损失的关联(防呆设计)

| 设计 | 作用 |
|---|---|
| **「先备份现场」** | 任何变更前的快照 |
| **「独立环境验证」** | 类似 staging 环境 |
| **「兜底中的兜底」** | 多层备份 |
| **「从 BEGIN 算起」** | 起点精确,边界不漏 |
| **「核3次再 COMMIT」** | 慢一点但安全 |

== **核心哲学**:**任何高风险操作前,先给现场留一份后悔药**。

## 13. 相关 iswiki 项目

- **[linux-permission-debug](linux-permission-debug.md)** — chmod 777 翻车排查(同作者系列,Linux 故障)
- **(待补充)ops-recovery-sop** — 通用运维恢复 SOP(本文)

## 14. TL;DR

**误删不可怕,可怕的是没有预案** — 通用 9 步 SOP:

```
1. 止损(read_only / umount / cordon)
2. 确认命根子(binlog ROW / mount / git reflog / k8s snapshot)
3. 备份现场(后悔药 — 整个 SOP 最反直觉但最关键)
4. 定方案(主路径 + Plan B 兜底)
5. 定位误删范围(从 BEGIN 算起)
6. 生成恢复 SQL(工具干活,反复核对)
7. 独立环境验证(从库 / sandbox)
8. 主库 / 主环境回放
9. 校验 + 切流量 + 复盘
```

==**5 大反直觉**:
1. 恢复前先备份现场(最想省的一步,最不能省)
2. 备份「已经被清空」的状态(看似没用,实是兜底)
3. DELETE 忘 WHERE 比 DROP 更危险(DML 不要权限,不报错)
4. 熟手最容易栽在「我以为」上
5. 慌的时候最想省的就是这一步

==**6 大铁律**(作者贴工位上):
1. UPDATE/DELETE 前先 SELECT COUNT(*)
2. 高危操作包在事务里(BEGIN → 确认 → COMMIT)
3. 延迟从库 1 小时
4. 先 RENAME 再 DROP
5. 恢复前先备份现场
6. 没有预案 = 灾难

==**最值得学的 1 点**:**「先备份现场再动手」** — 任何高风险操作(MySQL / 文件 / Git / K8s / 业务代码 deploy)都适用,**后悔药永远不能省**。