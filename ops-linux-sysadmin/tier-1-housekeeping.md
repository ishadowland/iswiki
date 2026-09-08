# Fireside Sprint 1.6 — Tier 1 housekeeping

> 学习笔记 · 调研时间 2026-08-05
> 仓库: https://github.com/ishadowland/fireside · License: MIT
> 关联: [fireside-sprint1](fireside-sprint1.md) · [STATUS.md](https://github.com/ishadowland/fireside/blob/main/STATUS.md)

## 一句话定位

**Sprint 1.6 Tier 1 = 收 outstanding housekeeping**。
Sprint 1 + Sprint 1.5 review (`#27`-`#36`) 全部 closed。剩两件 outstanding:
1. 两个 RFC §2.3 deviations 没决策文档
2. dashboard 缺 `display_name` modal (RFC Q6)

Tier 1 范围:**只做小修,不做大块**。
**不做**: WP-9 Android (Sprint 1.5 deferred), Sprint 2 Agent (新功能)。

## 改动清单

### 1. ADR-0020: hub 独立包 决策记录

**问题**: RFC §2.3 deviation flag — `internal/hub` 是独立包,不在 `internal/ws`。

**决策**: 保留独立包。
- REST handlers (rooms, messages) + WS dispatch 都 broadcast 通过 hub
- 反过来:如果 hub 合进 ws, REST handlers 要 import ws, 反依赖方向

**LOC**: ~60 (含模板)

### 2. ADR-0021: WS msg.send handler-layer check 决策

**问题**: RFC §2.3 deviation flag — WS `msg.send` handler 不做 on_stage check, 依赖 service。

**决策**: handler 不加 check。
- service 已经有 row lock,加 handler check 是 1 round-trip 重复工作
- 0 额外安全保证 (service 已经在事务里)

**LOC**: ~30

### 3. Dashboard display_name modal (RFC Q6 收尾)

**问题**: dashboard 登录后没弹 `display_name` modal, user 用 stub display_name=""。

**改动**:
- 加 `display_name_modal.js` 模块 (Fireside.jwtFetch 调用 `/v1/users/me`)
- `rooms.html` 嵌 modal HTML/CSS
- `lib.js` 加 `Fireside._token` 缓存 (modal 跟 rooms.js 共享 login)
- 2 新 dashboard tests pass

**LOC**: ~150 (含 CSS + JS + 2 tests)

### 4. RFC §2.3 deviation table 更新

加 2 行 (ADR-0020, ADR-0021)。

**LOC**: ~10

### 5. 测试验证

- `go test -race -count=1 ./...` 7/7 packages pass, 47.7s wall
- 12 dashboard tests (含 2 new for modal)
- 14+ auth tests (含 reviewer 4 refresh tests)

## LOC 回顾 (per `LOC 估算` rule)

| | 乐观 | 正常 | 悲观 | **实际** |
|---|---|---|---|---|
| A1.1 (ADR-0020) | 30 | 60 | 100 | ~60 |
| A1.2 (ADR-0021) | 15 | 30 | 60 | ~30 |
| A1.3 (display_name modal) | 100 | 200 | 400 | ~150 |
| A3 (testutil CI 验证) | 30 | 50 | 100 | ~10 (reviewer 已覆盖) |
| RFC §2.3 update | 5 | 10 | 30 | ~10 |
| **Total** | **180** | **350** | **690** | **~260** |

== **实际 ~260 LOC, 落在乐观-正常区间** ==。无需偏差归因。

## 不做 (其他 Tier)

| Tier | 任务 | 估 LOC | 何时 |
|---|---|---|---|
| Tier 2 | Retention worker (keep_messages_on_end) | 800-1500 | Sprint 2 backlog |
| Tier 2 | RFC §2.3 文档更新 (旧 entry 已解决) | 100-200 | 本次 |
| Tier 3 | WP-9 Android (#11) | 1000-2500 | Sprint 1.5 |
| Tier 3 | Sprint 2 WS-2 Agent RFC | 1000-2500 RFC | Sprint 2 |

## Sprint 1.6 Tier 1 Final

- ✅ RFC §2.3 deviations 全部 decision-documented (ADR-0020, ADR-0021)
- ✅ Dashboard display_name modal 完
- ✅ Testutil CI 路径 verification (reviewer Sprint 1.5 已 covered)
- ⏸ Sprint 1 唯一剩 open: #11 WP-9 Android (Sprint 1.5 by design)

## 后续

- **立即**: Sprint 1.6 Tier 1 commit + push (when network OK)
- **Sprint 2 backlog**: Retention worker + RFC §2.3 文档清理
- **Sprint 1.5 / Sprint 2**: Android + Agent persona

## Reference

- `fireside-sprint1.md` — Sprint 1 完整复盘
- `STATUS.md` — 当前 total state
- ADR-0020, ADR-0021 — 新 decision 文档
