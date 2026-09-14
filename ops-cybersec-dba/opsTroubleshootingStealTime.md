# 运维思路:CPU 只用了 30%,云主机却卡得动不了 —— 「云上 CPU 假象」之 steal time 篇

> 学习笔记 · 调研时间 2026-09-14
> 调研来源: 微信公众号「胡哥Linux运维」,作者胡登治(RHCA,15 年 Linux 运维)
> 原文: https://mp.weixin.qq.com/s/_BFLQyCyvyJH3EpAcAyRvg
> 系列定位: 「Linux 诡异现象排错」系列(与 [`opsTroubleshootingDiskGhost.md`](./opsTroubleshootingDiskGhost.md)、[`opsTroubleshootingOOMCgroup.md`](./opsTroubleshootingOOMCgroup.md) 同系列同作者)
> 用途: 提炼「云上 CPU 不一定是你的 CPU」的反直觉案例 + steal time 排查三板斧 + 工单取证话术

## 一句话定位

**云主机面板 CPU 30% ≠ 你能用 30%** —— 监控面板默认不显示 `steal time`(`st`),邻居抢物理 CPU 时你的 vCPU 在排队,**这段干等就是被偷走的时间**;排查从「登机器看 top 的 st 列」开始,而不是「急着升配 / 改代码 / 开批斗会」。

---

## 一、案例还原

### 现象

```
大促前一周,压测群里炸了锅
  接口 P99: 80ms → 2s,超时报错刷屏
  监控面板: CPU 30% / 内存 58% / 磁盘正常 / 网络正常 → 全绿
  应用日志: 慢查询无、GC 正常、连接池正常
  开发/DBA: 代码没动 / 库没问题
  排查: 三天,能查的全查了,瓶颈像空气一样看不见
```

### 关键发现

第四天凌晨 `top` 看到那行一直直接跳过的数字:

```
%Cpu(s): 30.2 us, 4.1 sy, 0.0 ni, 22.6 id, 1.8 wa, 0.0 hi, 0.3 si, 41.0 st
                                                       ^^^
                                                       41% — 被偷走的
```

**us 30% + st 41% = 你能用的 CPU 不是 30%,是不到 30%** —— 监控面板显示的"CPU 总使用率"压根不含 steal time。面板绿 ≠ 没事。

> 物理机时代,CPU 是你的;云时代,CPU 是大家的。监控里的「空闲」,可能是假象。

---

## 二、steal time 是什么

### 一句话定义

你的云主机是虚拟机,vCPU 是从宿主机物理 CPU 切出来的一份。当宿主机上别的虚拟机(邻居)把物理 CPU 抢光,**你的 vCPU 想干活却排不上队 —— 这段干等时间就是 steal time**。

### top 输出逐字段含义

| 字段 | 含义 | 解读 |
|---|---|---|
| `us` | user — 用户态 | 你的业务代码在跑 |
| `sy` | system — 内核态 | 内核在干活(系统调用、IO) |
| `ni` | nice — 低优先级 | 几乎可忽略 |
| `id` | idle — 真·空闲 | CPU **真的没事干** |
| `wa` | iowait — 等 IO | 在等磁盘/网络,不是被偷 |
| `hi` | hardirq — 硬中断 | 网卡/磁盘中断 |
| `si` | softirq — 软中断 | 内核软中断处理 |
| **`st`** | **steal — 被偷走** | **邻居抢走 CPU,你在等** |

**算账**:可用 CPU ≈ `us + sy` ≈ `100 - id - wa - st`。st 高 = 你能跑业务的时间被压缩。

### 为什么会有:超售

一台 64 核的物理宿主机,云厂商可能切出 200 个 vCPU 往外卖。平时大家错峰使用相安无事,邻居一上大促压测,你就跟着遭殃 —— **看不见的"邻居"才是云上最大的不可控变量**。

---

## 三、三板斧排查(直接复用作者思路)

### 抓手 1:`top` / `mpstat` 一分钟定性

```bash
top           # 看 %Cpu(s) 行最后的 st
mpstat -P ALL 1  # 看每一个核的 %steal,粒度更细
```

**两个小技巧**:
- `top` 里 st 是 **滚动平均**,瞬时尖峰可能被抹平;`mpstat -P ALL 1` 每秒采一次,能看到毛刺
- 用 `mpstat` 看**每个核**的 steal —— 邻居可能只吃几个核,你,多线程压测时瓶颈就明显

**踩坑点**:**别只盯云监控面板**。很多厂商默认只显示"CPU 总使用率",口径里压根不含 steal。面板全绿 ≠ 没被抢。这就是为什么必须登机器看 top,**面板会骗你,top 不会**。

### 抓手 2:`sar` / `vmstat` 拉趋势,排除"自己作"

```bash
vmstat 1 10         # cpu 段最后一列就是 st
sar -u              # 看今天的历史曲线
sar -u 1 60         # 压测现场抓秒级数据(60 秒)
```

**排除法这么用**:

| 现象 | 是不是 steal |
|---|---|
| `us + sy` 高 + `st` 低 | 真·CPU 忙 → 自己作,排查代码/GC |
| `wa` 高 | 等 IO → 看磁盘/网络,不是被偷 |
| `id` 高 + `st` 高 | 邻居抢的 + 你没事干 → 偷 CPU 但你没需求,影响小 |
| **`us` 不高 + `st` 高** | **典型云上假象** → 邻居在跑,你排队 |

**踩坑点 1**:`sar -u` 默认 10 分钟采一次样,平均值会把毛刺抹平。**压测和故障现场必须用 `sar -u 1` 秒级抓**,别用默认值。

**踩坑点 2**:Debian/Ubuntu 下,sysstat 的历史采集**默认是关闭**的 —— 装了包 `sar -u` 也查不到历史数据。要改 `/etc/default/sysstat` 里的 `ENABLED="true"`,再重启服务。**别到取证的时候才发现日志是空的**。

### 抓手 3:取证 + 提工单 + 换"房型"

定性是 steal time 之后,排查变成**维权**,三步走:

**第一步,取证**。三件套对齐到同一时间段:
1. `top` 截图(st% 数字)
2. `sar` 历史曲线
3. 业务超时时间点(P99 曲线 / 告警时间戳)

空口说"我觉得卡"没用,**数据拍在工单里才有分量**。

**第二步,提工单**。话术四件套,别啰嗦:

```
实例 ID:     i-xxxxxxx
时间段:      9 月 8 日 20:00-23:00
现象:        st% 持续 40+,业务 P99 从 80ms 恶化到 2s
诉求:        核查宿主机负载,迁移到空闲宿主机
```

**第三步,换"房型"**(长期解法,也是花钱的决策点)。两种"便宜型"的慢法别混为一谈:

| 类型 | 特点 | 解法 |
|---|---|---|
| **共享型 / 突发型** | 多租户共享宿主机,CPU 时间被切分;便宜但 steal 高 | 升"计算型 / 独享型",贵但稳 |
| **超分型**(看上去规格高) | 厂商标注的 vCPU 数 > 物理核数,本质是超售 | 同上,升"独享核"实例 |
| **真·CPU 密集**(自身优化差) | us 高 / st 低,GC 抖动 / 死循环 / 锁竞争 | 改代码,别怪云厂商 |

**踩坑点**:提工单之前,**先看清自己买的是什么规格**。你买共享型跑去投诉 st 高,客服只会礼貌地请你去看产品说明 —— 你买的就是会被抢的产品。

---

## 四、由 steal time 提炼的云上通用排查思路

### 1. 云上"看不见的邻居"是最大的不可控变量

```
你看到的(监控面板)        你能用的(实际)
  CPU 30%            ≠    30%
  内存 58%           ≈    58%(内存不会"被偷",这条基本可信)
  磁盘 IO 正常       ≈    正常
  网络带宽正常       ≈    正常
  ────────────────
  vCPU 时间          ←    会被邻居偷
  网卡 PPS           ←    会被邻居争(物理网卡共享)
```

**云上只有"自己的内存"是稳的**。CPU / 网络 PPS / IOPS 都有共享成分,出问题第一反应别怪自己。

### 2. 监控面板可信度排序(云上经验)

| 指标 | 面板可信度 | 原因 |
|---|---|---|
| **CPU 总使用率** | **低** | 不含 steal,严重低估真实负载 |
| 内存使用率 | 高 | 内存是实例独占(除非开超分) |
| 磁盘使用率 | 高 | 块存储是实例独享 |
| 磁盘 IOPS / 吞吐 | 中 | 可能共享后端存储 |
| 网络带宽 | 中 | 共享物理网卡 |
| P99 / 错误率 | 高 | 业务侧指标,跟邻居无关 |

**结论**:云上排障,**业务指标 + 登机器看 top + sar 历史** 比监控面板准。

### 3. 取证 → 工单 → 换房型 三步法(适用所有"云上假象")

```
现象(面板数字 vs 业务感知对不上)
  ↓
取证:登机器 + 工具 + 时间戳对齐
  ↓
定责:是自己作(us/wa 高)还是被偷(st 高)?
  ↓
行动:自己作 → 改代码 / 调配置;被偷 → 取证 → 工单 → 换房型
```

### 4. 紧急止血 vs 长期根治

| 阶段 | 目标 | 典型动作 |
|---|---|---|
| **T+0 ~ 5min: 止血** | 让告警先消 | 临时升配 / 摘流量 / 重启实例 |
| **T+5 ~ 30min: 定位** | 找到根因 | top / sar / mpstat 区分 us vs st |
| **T+30min+: 根治** | 不再复发 | 换"计算型"实例 / 改架构(读分离、缓存) |
| **T+1day: 复盘** | 防止下次 | 把 steal time 加进巡检 / 监控增加 st 指标 |

---

## 五、steal time 实操速查

### 一分钟排查脚本(直接复用)

```bash
#!/bin/bash
# steal_time_check.sh — 登机器就跑
echo "=== 1. 当前 st 快照(看 %Cpu(s) 末列)==="
top -bn1 | head -5

echo ""
echo "=== 2. 每核 steal 分布(找被偷最狠的核)==="
mpstat -P ALL 1 3

echo ""
echo "=== 3. 历史趋势(确认是不是常态)==="
sar -u | tail -20

echo ""
echo "=== 4. 当前 st 高过 5% 直接告警 ==="
CURRENT_ST=$(top -bn1 | grep "%Cpu" | awk '{print $11}' | sed 's/%//')
[ "${CURRENT_ST%.*}" -gt 5 ] && echo "WARN: steal time ${CURRENT_ST}% > 5%,需取证" || echo "OK: steal time ${CURRENT_ST}%"
```

### 工单取证包(出问题时打包提交)

```bash
mkdir -p /tmp/incident_$(date +%Y%m%d)
cd /tmp/incident_$(date +%Y%m%d)

# 1. 当前 st 快照
top -bn1 > top_snapshot.txt

# 2. 每核 steal 分布
mpstat -P ALL 1 10 > mpstat_per_core.txt

# 3. 历史趋势(sar 历史采集必须开,见 §三 抓手 2 踩坑点 2)
sar -u > sar_history.txt

# 4. 业务侧时间对齐
#    报错时间戳从应用日志 / APM / NGNIX access log 捞
grep "$(date -d '1 hour ago' +'%Y-%m-%d %H')" /var/log/app/error.log > app_errors.txt

# 5. 实例信息
cat /proc/cpuinfo | grep "model name" | head -1 > instance_info.txt
curl -s http://169.254.169.254/latest/meta-data/instance-type >> instance_info.txt  # AWS
# 阿里云:curl -s http://100.100.100.200/latest/meta-data/instance/instance-type

echo "取证包完成: $(pwd)"
```

### 监控增加 steal 指标(Prometheus node_exporter)

```yaml
# prometheus.yml 加报警规则
groups:
- name: steal_time
  rules:
  - alert: HighStealTime
    expr: |
      100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
      - (avg by(instance) (rate(node_cpu_seconds_total{mode="steal"}[5m])) * 100)
      < 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "{{ $labels.instance }} steal time 高,vCPU 在排队"
      description: "st > 5% 持续 5 分钟,可能邻居抢 CPU,建议登机器 top/mpstat 确认"
```

---

## 六、预防机制(把救火变常态)

### 1. 选规格:别贪便宜买共享型

| 业务类型 | 推荐规格 | 理由 |
|---|---|---|
| 核心交易(订单/支付/库存) | **独享型 / 计算型** | 不能容忍 steal,直接上贵的 |
| 内部系统(OA/CRM) | 共享型 / 突发型 | 用量低,被偷也无所谓,省钱 |
| 离线计算(ETL/报表) | 抢占式 / 突发型 | 本来就不稳,被偷了 retry |
| 中间件(Redis/MQ) | 独享型 | 内存吃满时 steal 高 = 雪崩 |

**经验法则**:**核心业务不上共享型** —— 一个月省省下来的钱,一次大促故障就亏回去。

### 2. 监控增加 st 指标(防面板骗你)

云监控面板默认不显示 steal,**自己加**:
- node_exporter:`node_cpu_seconds_total{mode="steal"}` 直接 alert
- 阈值:**st > 5% 持续 5min = 警告**,st > 20% = 严重
- 告警渠道:不要只走监控平台,直接拉群(运维 / SRE),这玩意儿面板看不到只能靠告警

### 3. 大促前提前预案

```bash
# 大促前一周:实例清单 + 规格核对
for instance in $(cat prod-instances.txt); do
  TYPE=$(curl -s http://100.100.100.200/latest/meta-data/instance/instance-type)
  echo "$instance $TYPE"
  # 共享型 / 突发型 大促期间建议临时升独享
done

# 大促期间:每 5 分钟巡检 steal time
*/5 * * * * /opt/scripts/steal_time_check.sh | mail -s "steal_time_$(date)" ops@company.com
```

### 4. Runbook 沉淀(出一次沉淀一次)

每次遇到 steal 高:
- 取证包 + 工单回复 + 最终处理动作,沉淀进 `ops-runbook/steal-time.md`
- 下次新人 5 分钟定位,而不是一晚上懵

---

## 七、跟我们的关系

| 关联点 | 用法 |
|---|---|
| **PVE 主机(10.10.66.208)** | PVE 是 KVM 虚拟化,**也有 steal time**(KVM 对应 `st`),只是自家宿主机不会被超售,steal 通常 < 1%。监控面板没显示的话,补 `node_cpu_seconds_total{mode="steal"}` |
| **macmini 集群** | macOS 没 steal time 概念,但 Docker Desktop / OrbStack / Colima 跑的容器底层如果用 vz 后端,**VM 内 top 一样有 st**,注意 Apple Silicon 宿主基本不被超分 |
| **VPS(国内云厂商)** | 国内云(阿里云/腾讯云)共享型 ECS steal 比 AWS 严重 —— 用户量大、超分比高。**核心服务必须上独享型** |
| **私活 / 后端服务** | 选最低配测试没事,上生产一定要选"计算型 c5/c6"或独享核;突发型实例(经济型 e / 抢占式)只能跑不重要的 worker |
| **排障思路沉淀** | 「面板数字 vs 实际感知对不上」= 一定有看不见的变量,不止 steal —— 还有磁盘(见 DiskGhost 笔记)、内存(cgroup,见 OOMCgroup 笔记);统一在「账本对账」思路里 |
| **运维避坑清单** | 加一条:**大促 / 压测前 7 天登机器 top 看一遍所有生产实例的 st**,后置排查三天的代价远超事前五分钟 |

---

## 八、一图总结(给团队传阅)

```
云上排障第一原则:
  先怀疑「你看到的 CPU 不是你的 CPU」
  监控里看不到 steal time = 裸奔

排查三板斧:
  ① top / mpstat 看 st 列         → 一分钟定性
  ② sar / vmstat 拉趋势           → 排除自己作
  ③ 取证 + 工单 + 换房型         → 维权三步走

云上"被偷" vs "自己作"速判:
  us 高 + st 低   → 自己作(改代码)
  us 低 + st 高   → 被偷(取证 + 工单 + 换房型)
  wa 高          → 等 IO(看磁盘/网络)
  id 高          → 真·闲(不用管)

云上只有"自己的内存"是稳的:
  CPU / 网络 / IO 都可能被邻居偷
  业务指标 + 登机器 + sar 才准,监控面板不可全信
```

---

## 参考链接

- 原文: https://mp.weixin.qq.com/s/_BFLQyCyvyJH3EpAcAyRvg
- 作者公众号: 胡哥Linux运维
- 同系列前篇(同作者):
  - [df 说满 du 说没满](./opsTroubleshootingDiskGhost.md) —— 磁盘「账本对不上」篇
  - [free 还有 8G,OOM 却杀我的数据库](./opsTroubleshootingOOMCgroup.md) —— 内存「cgroup 小笼子」篇
  - load 飙到 30,CPU 却闲着(占位,待补)
  - TCP 玄学:连接时好时坏(占位,待补)
  - K8s 网络:Pod 直连正常,走 Service 就超时(占位,待补)
- 同作者下一期预告(原文末尾):「磁盘没满,iowait 却飙到 90% —— 99% 的人第一步就查错了」
- 配套工具:`top`(自带)、`mpstat`(sysstat)、`vmstat`、`sar`、`node_exporter`
- 进一步参考: Linux man page `top(1)` / `mpstat(1)` / `proc(5)`