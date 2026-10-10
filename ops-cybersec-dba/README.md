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
| [disable-ipv6-multi-kernel](disable-ipv6-multi-kernel.md)
| [dockerDiskSpaceSOP](dockerDiskSpaceSOP.md) | Docker 磁盘满的四阶段处置 SOP:Phase 1 只读定位(`context show` / `system df -v` / `buildx ls` / `buildx du`)→ Phase 2 由窄到宽分层清理 → Phase 3 阈值兜底 → Phase 4 复发预防。含 `buildx du` 的 `*` 号语义(共享存储导致"清完没释放")、`--filter` 全表 9 个 key、daemon.json 单 `=` vs buildkitd.toml 双 `==` 的坑、**本机实测 `Docker.raw` 实际 24.8G / 表观上限 1224G** 的稀疏文件陷阱。 |
| [frpc-desktop](frpc-desktop.md) — FRP 内网穿透跨平台桌面客户端(Electron + Vue 3),可视化配 frpc 代理,6,875⭐ 头部项目
| [kylinV10DisableIPv6](kylinV10DisableIPv6.md)
| [linux-permission-debug](linux-permission-debug.md)
| [netdata](netdata.md)
| [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md)
| [opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md)
| [opsTroubleshootingStealTime](opsTroubleshootingStealTime.md) — 云上 CPU 30% 却卡:steal time 排查三板斧 + 工单取证话术
| [overseas-youtube-security-channels](overseas-youtube-security-channels.md)
| [performanceTriage](performanceTriage.md)
| [qoder-security](qoder-security.md)
| [recovery-sop](recovery-sop.md)
| [strix](strix.md)
| [tier-1-housekeeping](tier-1-housekeeping.md)
| [wafKnowledgeBase](wafKnowledgeBase.md)

---

**共 20 个文档**。
