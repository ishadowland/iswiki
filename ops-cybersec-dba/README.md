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
| [opsTroubleshootingInodeExhaustion](opsTroubleshootingInodeExhaustion.md) | 「磁盘有空间却报 No space」的 inode 耗尽排查 —— `df -h` 只管块不管文件数,ENOSPC 也可能由 inode 满触发。**一手核验 8 条:6 条成立 / 1 条普适性缺口 / 1 条字段名笔误**。⭐最大纠偏:**XFS 动态分配 inode、总数会漂移**(Red Hat KB 官方实例:总数 5700 万↔23 亿漂移),照搬 ext4 的"备份+重格式化"结论会做错决策 —— 排查第一步应是 `df -T` 确认 fs 类型。含 ext4 默认 inode_ratio=16384 核实、`stat -f` 字段是 `Free inodes:` 非 `Free:`、`node_filesystem_files`(非 inodes)命名由来、千万级文件下用 `du --inodes -d 1` 替代 `find|wc -l`、inode 用到 90% 可能只是默认值配稀(告警应贴 100% + 配单目录文件数早发信号)。**本机 APFS 实测 `ifree` 13.96 亿量级 → inode 耗尽在本机不会发生**,只对 Linux 服务器有意义;与 [DiskGhost](opsTroubleshootingDiskGhost.md) 可同时发生。 |
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
| [llmCodeAuditMethodology](llmCodeAuditMethodology.md) | 公众号《从碰运气到体系化——如何让 LLM 尽可能找全漏洞？》方法论拆解 + **与作者自己 7 月一手方法论的对照**。核心是**双向搜索**:反向追踪(危险操作→入口,适合有 Sink 的) + 正向推演(入口→业务效果,适合**无固定 Sink** 的越权/金额覆盖/令牌重放/状态绕过);配套漏洞分类体系(能力坐标系/运行路由/评测切片)+ 分层 Skill 组合(公共方法+大类方法+小类差异,编排层按需组合)+ 发现求全/验证求真分离。⚠️ 一手核验:一手源 `purpleroc/llm_code_audit` ★17/**仅 3 个 commit**(最后推送 2026-07-20)且 **README 15 条链接有 3 条失效**(`schemas/` 整个目录不存在)—— **文章描述的系统未开源**,只能核方法论。⭐ 最硬发现:作者 7 月 V2 §2.5 **明确「反驳」过本文核心主张之一**(发现/验证分离不能自动制造认知独立性),而 V2 §0 的北极星「不是让 AI 尽可能多报漏洞」与本文标题正相反 —— 引用时不宜称其为「当前最佳实践」。V2 另提供文章没有的硬框架:**证据阶梯 E0–E5**(证据等级与业务严重度正交)/事实-推理-决策三平面(推理平面无生产权限)/评测样本量(precision 80% 半宽 5% → **246 条**)/三道上线关口/净安全收益决策函数。 |
| [pentagi](pentagi.md) | 开源自托管多智能体渗透测试平台(Go + React,34,520⭐,MIT **+ 附加 EULA**)。20+ 专业工具沙箱、pgvector 记忆 + Neo4j 图谱、10+ LLM provider(含 DeepSeek/GLM/Kimi/Qwen/MiniMax)。⭐官方主动划能力边界(**不是 BAS 产品**);GitHub Discussion #217 官方**认账误报率 10-30%、缺乏端到端利用验证**。⚠️**habr 独立实测:296 个发现里 42 CRITICAL+50 HIGH 共 92 个高危无一可利用**(部分 PoC 是模板粘贴的他人 CVE),且**agent 发现网段属他方后仍继续扫描,须人工叫停**。另:`admin@pentagi.com`/`admin` 默认口令、`.env` 里 10 个弱默认口令、`DOCKER_NET_ADMIN=true` 默认开启、**Docker Hub 镜像滞后源码约 6 周**。 |
| [airecon](airecon.md) | 零 API Key 的本地化自主渗透侦察 agent(Python 3.12+,1,095⭐,MIT):**本地 Ollama/任意 OpenAI 兼容网关 + Kali Docker 沙箱 + Textual TUI**,目标情报与工具输出可**完全不出本机**。⭐**七层反幻觉机制**(幻觉短语黑名单 / 工具调用 schema 校验 / **无证据报告直接拒收** / 字段级规则 / CVSS 分级 / **只学已验证的** / 工作区 scope 隔离)+ 本地 **1.09M 条**安全知识库 FTS5 + 实测 **141 个** skill 文件。⚠️**install.sh 硬编码 `/usr/bin/python3`,macOS 会选到 3.9 直接退出**(已给绕过方法);**GitHub Releases 停更 7 个月、无 PyPI 包**;README 的 skill 数(57)已过时。第三方独立实测**基本缺失**(多为新闻稿转述)。 |
| [tier-1-housekeeping](tier-1-housekeeping.md)
| [wafKnowledgeBase](wafKnowledgeBase.md)
| [newPowerSystemSecurity](newPowerSystemSecurity.md) | 中科院院刊《新型电力系统的安全风险、关键问题与应对策略》(中国工程科学 2026, 28(5): 12-21)深度解析:五维风险→三大体系→8 关键问题→对策。⭐三个真洞见(**装机≠可信出力**,3 亿 kW 晚峰只顶 <1 亿 kW / **储能兜底是负反馈**,缺口越大越充不进电 / **电网"空心化"**=送端受端双向失支撑)。⚠️ **一手核验 12 条**:核心量化锚点 6 条精确吻合(负荷/特高压/分布式光伏/APT),**4 条有出入或夸大**(伊比利亚停电归因与 ENTSO-E 官方结论相反——真因是过电压保护动作不是热浪 / Moss Landing **单位错**(300 MW/1200 MWh 非 MW·h)+疏散 1200-1500 人非"超 2000"+起火原因官方仍未定论 / 台风麦德姆 **14 级**非 10~12 级 / 柔直均压电阻"卡脖子"存疑,换流阀本体已国产化)。⚠️ 四个结构性弱点:8 问题**无排序**、成本反复提但**不讲谁付钱**、作者全是系统内机构=**运营方视角**(供应链风险被归因于外部而非自己扛)、分布式侧只写风险源不写资源(湖北已实现万户级柔性同调,10461 户成功率 97%+)。+ §六 跟我们的关系:论文 C 体系=用户上位机产品**未来的合规压力表**(工控协议加固→`plc.IsConnected` 不可信 / 云边端→单机上位机攻击面最大)。 |
| [emqxPvMigration](emqxPvMigration.md) | 《基于 EMQX Cloud 实现光伏储能平台万级网关平滑迁移》(EMQ 中文社区,2026-11-12)落地拆解:某光伏逆变器/储能厂商把**自建开源 EMQX 接入层**迁到 **EMQX Cloud 专有版**,**不换域名、不改设备固件**。**五个挑战**:上行链路环节多致丢失难定位 / 网关汇聚下高并发与混合流量并存(KB 报文 + QoS1 毫秒指令 + >1MB 大包)/ **Kafka 单条 1MB 硬限制** / 万级存量长连接迁移要业务连续 / 扩容运维负担。**平滑迁移五步**:14 天试用额度搭环境 → 测试域名验 TLS → 1000 线→20000 线 POC(稳态/峰值/大包/重连风暴)→ **下调 DNS TTL + CNAME + 旧集群 REST API 分批踢连接(速率 ≤1000 连接/秒)** → **先生产者、后消费者**(旧消费者消费到积压清零再切);回退 = DNS 回切 + 批量踢连接。**双通道集成**:遥测走**规则引擎→Kafka**(四环节砍到两环节),**高敏感告警走 HTTP 直达**(不过队列、不排队),**>1MB 波形/日志走 HTTP 旁路直传对象存储**,MQTT 只传元数据。**认证缓存条数 = 部署连接数**(重连风暴时认证服务零压力)。⚠️ **原文未提但落地必须知道(官方文档核对)**:① Kafka `Max Batch Bytes` 默认 **896 KB**(非 1MB,故意留编码开销,**超限单条会单独成批** —— 原文把拒收责任归错层,真限制在 broker `message.max.bytes`)② **专有版起价 $0.32/小时 ≈ $234/月**(原文全程不提成本)③ `Buffer Mode` 可选 disk/hybrid,**告警链路用 memory 会在节点重启时丢消息**④ 50 条规则上限在官方文档/源码均未找到,需向商务确认。成果:万级连接稳定、**迁移期间无批量业务中断**、写入成功率 99.99%。 |

---

**共 36 个文档**。
