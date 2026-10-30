# 🛠️ Ops / Cybersec / DBA

> Linux 故障排查 / 数据恢复 / 性能 triage / 监控可观测 / WAF / 安全任务路由 / 渗透测试 / 漏洞研究

---

## 索引

| 文档 | 一句话 |
|---|---|
| [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md)
| [minerSelfCheck](minerSelfCheck.md) | 公众号《你的服务器被挖矿了吗?5 分钟自查,附一键检测脚本》(胡哥Linux运维,2026-10-29)实战拆解:**FakeSvc 挖矿组织**(CNCERT 2026-07-31 风险提示,安天科技参与样本分析)累计感染 **16,054 台**、单日最高 2,511 台肉鸡,经 **SSH 弱口令爆破** → 伪装系统进程 → 计划任务持久化 → 部署门罗币矿机 → **以受害主机为跳板爆破同网段**。**七项自查**(进程血统/定时任务全家桶/登录即执行/SSH 后门钥匙/外连与矿池端口/临时目录与 chattr/ps 完整性)每条都带边界(`ps` 的 %cpu 是历史平均不是瞬时、端口≠证据、数量相同≠无隐藏进程、immutable 只对 ext4/xfs 有效、`sshd -T` 有 Match 块时不带 -C 不代表最终配置、爆破统计别用 `awk "{print $11}"`)。**处置五步且顺序不能反:先取证 → 断持久化 → 封出口 → 收兵 → 换锁**(杀进程只是打地鼠,5 分钟复活);PGID 冻结整组前必须同时满足三条(>1 / ≠ 当前 shell PGID / 组内无业务进程),否则只动已确认 PID。⚠️ **原文附的 `check_miner.sh` 有 15 处 bug 会直接崩**(`warn "A""B"` 参数被合并 → `set -u` 下 `unbound variable`,且崩在第 1 项入口,后面 6 项全跑不到;另有 2 处漏空格导致 `authorized_keys` 家目录替换静默漏检)—— **本文已修复、附修复版脚本,并实跑验证 7/7 项通过**;另发现 `net`/`networkservice` 关键词在 macOS/Linux 均会误报、`-perm /111` 在 BSD find 上报错。 |
| [bash-reference-manual](bash-reference-manual.md)
| [blackBoxPentestPlaybook](blackBoxPentestPlaybook.md) | 黑盒渗透测试完整打法(脱敏方法论):Phase 0 授权边界 → Phase 1 **JS chunk 迭代收敛提取**(收敛判据=本轮新增为 0)+ 8 类 JS 挖掘目标 → Phase 2 应用层加密识别复现 → Phase 3 未授权矩阵探测(路径 × 多前缀)→ Phase 4 **双账号 diff 四维度**(总数/集合差集/字段集/值内容)+ 三层越权分离 + **跨边界验证区分"隔离层缺失"vs"行级过滤缺失"** → Phase 5 注入/上传/RCE/对象存储四专项 → Phase 6 未成立项归档 + 跨版本 diff。核心认知:黑盒信息差只在**前端 JS / 加密协议 / 登录态数据边界**三处,扫描器只覆盖第一张表的一小部分。 |
| [codex-security](codex-security.md)
| [curlImpersonate](curlImpersonate.md) | 伪装浏览器 TLS+HTTP2 指纹的 curl 补丁版(Chrome 走 BoringSSL / Firefox 走 NSS)。本机实测三指纹 ja3+ja4 对比、GREASE 随机化实测、**macOS Firefox 版因 `libnsspem` 缺失不可用**、指纹停在 2023 年 Chrome 116 的时效性风险。含使用边界。
| [cve-2026-91403-emudhra-java-truststore](cve-2026-91403-emudhra-java-truststore.md) | eMudhra 中间 CA 私钥泄露(CVE-2026-91403):本机 Java 信任库体检 + 14 个官方测试端点实测矩阵 + 只封中间 CA 的手工兜底(附 16 张证书指纹清单)。 |
| [disable-ipv6-multi-kernel](disable-ipv6-multi-kernel.md)
| [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) | Docker 磁盘满的四阶段处置 SOP:Phase 1 只读定位(`context show` / `system df -v` / `buildx ls` / `buildx du`)→ Phase 2 由窄到宽分层清理 → Phase 3 阈值兜底 → Phase 4 复发预防。含 `buildx du` 的 `*` 号语义(共享存储导致"清完没释放")、`--filter` 全表 9 个 key、daemon.json 单 `=` vs buildkitd.toml 双 `==` 的坑、**本机实测 `Docker.raw` 实际 24.8G / 表观上限 1224G** 的稀疏文件陷阱。 |
| [frpc-desktop](frpc-desktop.md) — FRP 内网穿透跨平台桌面客户端(Electron + Vue 3),可视化配 frpc 代理,6,875⭐ 头部项目
| [kylinV10DisableIPv6](kylinV10DisableIPv6.md)
| [K8sHostsEndpointsFailure](K8sHostsEndpointsFailure.md) | K8s「控制面全绿、业务全挂」事故复盘 + **K8s 小白概念补课**(架构图 / 名词表 / Service 转发链路 / 控制循环)。根因链:节点集体重启 → cloud-init `update_etc_hosts` 重写 `/etc/hosts` → endpoint slice controller 状态未恢复 → EndpointSlice 停在旧 Pod IP → kube-proxy 指向死 Pod。**⚠️ 一手核验纠正原文 7 处偏差**(最重要:`manage_etc_hosts` 官方默认是 `false` 不是"出厂预置 true";**Endpoints 自 v1.33 已弃用**,真实数据源是 EndpointSlice;§五的 metrics 日志是 metrics-server 而非 apiserver 在请求 kubelet)。含静态 Pod 目录禁放备份的官方警告 + 控制器工作计数量化「假活」的排查法。 |
| [linux-permission-debug](linux-permission-debug.md)
| [lvmPartitionedFilter](lvmPartitionedFilter.md) | `pvcreate` 报 `excluded by a filter` 的真因是内置 partitioned filter,改 lvm.conf 绕不过。含源码级核验、**2.03.14 vs main 的 GPT 判定差异(老版零 GPT 逻辑、只看 PMBR)**、对话里 5 处错判纠正。 |
| [macosClamshellSleepDrain](macosClamshellSleepDrain.md) | MacBook 合盖不睡/夜间耗电的定位处置 SOP:先分清「没进睡眠」vs「进了没进深睡」→ 读 `chooseStandbyDelay` 决策分支 → 找长挂 IOKit 断言。根因是 **`proximitywake` 开启后 ALS 接近感应在睡眠中被启用,powerd 持有 `InternalPreventSleep` 长达 13h04m** 把机器钉在浅睡眠;叠加 **`capacity >= highstandbythreshold` → 走 `standbydelayhigh`(默认 24h)分支**,高电量反而卡在浅睡眠。反直觉点:电量越高,standby 延迟越长。含 `pmset -g log` 看不到 powerd 决策(unified log 才看得到)、ASL 日志按天轮转、unified log 时间窗漂移等坑,以及**第三方常驻软件(ToDesk)彻底卸载的 8 项验证清单**(先 unload 再删文件 / `UninstallerWatcher` 会复活 / 音频驱动需 `killall coreaudiod`)。本机实测 MacBookPro15,2:整夜耗电 **75% → 0% 修复为 100% → 98%(11h 掉 2%)**。 |
| [netdata](netdata.md)
| [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md)
| [opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md) | 「账本思维」cgroup 篇:`free` 报空闲 ≠ 系统认为不杀你,OOM Killer 看的是进程所属 cgroup 的 memory.current vs memory.max。含 meminfo 拆解(SUnreclaim/slab)、THP + swappiness 调优、「七大账本对不上」速查表。**姊妹篇见 [opsTroubleshootingOOMSILogless](opsTroubleshootingOOMSILogless.md)**。 |
| [opsTroubleshootingOOMSILogless](opsTroubleshootingOOMSILogless.md) | 「三本账」排查法:进程被 OOM Killer 杀了,应用日志里却什么都没留。SIGKILL 由 `do_send_sig_info()` 从内核态硬送,应用连遗言都写不了;证据在 dmesg / journalctl -k / systemd 三层。一手核验 `mm/oom_kill.c`(master + **v4.19 双版本**) + systemd NEWS + rsyslog 源码,补 5 处原文缺失(**journald `Storage=auto` 默认 v259 才改 persistent**、`--grep` 需 ≥237、imjournal 默认 600s/20000 条、`status=9` ≠ 退出码 9、**137 只说明被 SIGKILL 不代表 OOM**)。**§三·五 麒麟 V10 SP3 专项**:4.19 日志格式无 `UID`/`oom_score_adj`(列数 12→8、抬头行多 `nodemask`)、`memory.peak`(v5.19+)/`events.local`(v5.10+)不存在、`OOMPolicy=` 需 systemd 243,附可直接跑的排查脚本。 |
| [opsTroubleshootingSanfine521](opsTroubleshootingSanfine521.md) | Cloudflare 521 排查 ——「接受 TCP 连接却零字节返回」= 源站实例层停机指纹。四层定位法(代理后 DNS 查不到回源 IP,靠 `~/.ssh/config` 翻出真实 IP)。**初判「高防到期转黑洞」已被后续证伪**,真实根因是实例系统损坏需重装 —— 多个成因共享同一网络指纹,客户端探测定不了案。含巡检脚本固化(--direct / --no-network / --json / 退出码分级)与 macOS Python OpenSSL 空目录坑。 |
| [opsTroubleshootingStealTime](opsTroubleshootingStealTime.md) — 云上 CPU 30% 却卡:steal time 排查三板斧 + 工单取证话术
| [opsTroubleshootingTCPPortExhaustion](opsTroubleshootingTCPPortExhaustion.md) | 调大 ulimit 反而雪崩:出站 TCP 端口耗尽 `EADDRNOTAVAIL` 三层修复 + 自查清单。 |
| [overseas-youtube-security-channels](overseas-youtube-security-channels.md)
| [performanceTriage](performanceTriage.md)
| [qoder-security](qoder-security.md)
| [recovery-sop](recovery-sop.md)
| [s7-monitor](s7-monitor.md) | 西门子 S7 PLC 设备监测预警上位机(.NET 10 / WinForms,MIT,⭐0):9 设备 × 4 参数、越限报警、SQLite WAL 单文件落库、操作审计 6 模块。含三条可搬走的工程模式:**重连必须真实读取探活、不能信 `plc.IsConnected`**(S7.Net 本地标志位不探链路,掉线仍返 true,导致界面看不出断过线)、边沿即时 + 持续降频落库、崩溃重启重建基线防孤儿报警。⚠️ 一手核验推翻 README 2 处(承诺的离线 nupkg 与 `Database/` 脚本目录均不存在,私有包 `Zhaoxi.CustControls` 不在 nuget.org → 开箱编不过);仅 1 个 commit、无 CI 无测试。 |
| [strix](strix.md)
| [tier-1-housekeeping](tier-1-housekeeping.md)
| [wafKnowledgeBase](wafKnowledgeBase.md)

---

**共 29 个文档**。
