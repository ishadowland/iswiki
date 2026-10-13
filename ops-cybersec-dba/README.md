# 🛠️ Ops / Cybersec / DBA

> Linux 故障排查 / 数据恢复 / 性能 triage / 监控可观测 / WAF / 安全任务路由 / 渗透测试 / 漏洞研究

---

## 索引

| 文档 | 一句话 |
|---|---|
| [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md)
| [bash-reference-manual](bash-reference-manual.md)
| [blackBoxPentestPlaybook](blackBoxPentestPlaybook.md) | 黑盒渗透测试完整打法(脱敏方法论):Phase 0 授权边界 → Phase 1 **JS chunk 迭代收敛提取**(收敛判据=本轮新增为 0)+ 8 类 JS 挖掘目标 → Phase 2 应用层加密识别复现 → Phase 3 未授权矩阵探测(路径 × 多前缀)→ Phase 4 **双账号 diff 四维度**(总数/集合差集/字段集/值内容)+ 三层越权分离 + **跨边界验证区分"隔离层缺失"vs"行级过滤缺失"** → Phase 5 注入/上传/RCE/对象存储四专项 → Phase 6 未成立项归档 + 跨版本 diff。核心认知:黑盒信息差只在**前端 JS / 加密协议 / 登录态数据边界**三处,扫描器只覆盖第一张表的一小部分。 |
| [codex-security](codex-security.md)
| [curlImpersonate](curlImpersonate.md) | 伪装浏览器 TLS+HTTP2 指纹的 curl 补丁版(Chrome 走 BoringSSL / Firefox 走 NSS)。本机实测三指纹 ja3+ja4 对比、GREASE 随机化实测、**macOS Firefox 版因 `libnsspem` 缺失不可用**、指纹停在 2023 年 Chrome 116 的时效性风险。含使用边界。
| [disable-ipv6-multi-kernel](disable-ipv6-multi-kernel.md)
| [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) | Docker 磁盘满的四阶段处置 SOP:Phase 1 只读定位(`context show` / `system df -v` / `buildx ls` / `buildx du`)→ Phase 2 由窄到宽分层清理 → Phase 3 阈值兜底 → Phase 4 复发预防。含 `buildx du` 的 `*` 号语义(共享存储导致"清完没释放")、`--filter` 全表 9 个 key、daemon.json 单 `=` vs buildkitd.toml 双 `==` 的坑、**本机实测 `Docker.raw` 实际 24.8G / 表观上限 1224G** 的稀疏文件陷阱。 |
| [frpc-desktop](frpc-desktop.md) — FRP 内网穿透跨平台桌面客户端(Electron + Vue 3),可视化配 frpc 代理,6,875⭐ 头部项目
| [kylinV10DisableIPv6](kylinV10DisableIPv6.md)
| [linux-permission-debug](linux-permission-debug.md)
| [lvmPartitionedFilter](lvmPartitionedFilter.md) | `pvcreate` 报 `excluded by a filter` 的真因是内置 partitioned filter,改 lvm.conf 绕不过。含源码级核验、**2.03.14 vs main 的 GPT 判定差异(老版零 GPT 逻辑、只看 PMBR)**、对话里 5 处错判纠正。 |
| [netdata](netdata.md)
| [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md)
| [opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md) | 「账本思维」cgroup 篇:`free` 报空闲 ≠ 系统认为不杀你,OOM Killer 看的是进程所属 cgroup 的 memory.current vs memory.max。含 meminfo 拆解(SUnreclaim/slab)、THP + swappiness 调优、「七大账本对不上」速查表。**姊妹篇见 [opsTroubleshootingOOMSILogless](opsTroubleshootingOOMSILogless.md)**。 |
| [opsTroubleshootingOOMSILogless](opsTroubleshootingOOMSILogless.md) | 「三本账」排查法:进程被 OOM Killer 杀了,应用日志里却什么都没留。SIGKILL 由 `do_send_sig_info()` 从内核态硬送,应用连遗言都写不了;证据在 dmesg / journalctl -k / systemd 三层。一手核验 `mm/oom_kill.c` + systemd NEWS + rsyslog 源码,补 5 处原文缺失:**journald `Storage=auto` 默认在 v259 才改 persistent**(老机器重启后证据全丢)、`--grep` 需 systemd ≥237(CentOS 7 无)、imjournal 默认 600s/20000 条限速、`status=9` 与退出码 9 是两回事、**137 只说明被 SIGKILL 不代表 OOM**。 |
| [opsTroubleshootingStealTime](opsTroubleshootingStealTime.md) — 云上 CPU 30% 却卡:steal time 排查三板斧 + 工单取证话术
| [opsTroubleshootingTCPPortExhaustion](opsTroubleshootingTCPPortExhaustion.md) | 调大 ulimit 反而雪崩:出站 TCP 端口耗尽 `EADDRNOTAVAIL` 三层修复 + 自查清单。 |
| [overseas-youtube-security-channels](overseas-youtube-security-channels.md)
| [performanceTriage](performanceTriage.md)
| [qoder-security](qoder-security.md)
| [recovery-sop](recovery-sop.md)
| [strix](strix.md)
| [tier-1-housekeeping](tier-1-housekeeping.md)
| [wafKnowledgeBase](wafKnowledgeBase.md)

---

**共 24 个文档**。
