# Fireside Sprint 1 + Sprint 1.5 — Minimal Demo

> 学习笔记 · 调研时间 2026-08-05
> 仓库: https://github.com/ishadowland/fireside · License: MIT
> Language: Go 1.26 backend + TypeScript dashboard · 4 commits 起，Sprint 1 终点 ~12,580 LOC

## 一句话定位

**异步圆桌会议平台** — Clubhouse 异步版，Android + Go 后端 + Web Dashboard 三角协作。Sprint 1 完整闭环：**REST 创建房间 → 加入(on_stage) → 发消息(WebSocket broadcast 到全员) → EndRoom**，两步浏览器实测 RPC §7.2 全通过。

## 最终 commits 历史（Sprint 1 完成）

```
292e48a feat(dashboard): Sprint 1 WP-8 — rooms lobby + chat UI
1587275 fix: Sprint 1 review cleanup — #20 #23 #24 #25 (reviewer)
e9a509c fix: Sprint 1 Wave 1 P0 — #18 #19 #21 #22
fe1d21f fix(ws,hub): WP-5/WP-6 review (reviewer)
c846c9c feat(ws): Sprint 1 WP-6 — business-frame dispatch loop
761094f feat(hub): Sprint 1 WP-5
5ab6de5 ci: pin sqlc v1.27.0 (#16 L-1)
12550b5 feat(db,store): Sprint 1 WP-1
9b4fb47 feat(rooms): Sprint 1 WP-2
d38cb0e feat(messages): Sprint 1 WP-3
ccaaff5 feat(participants): Sprint 1 WP-4
```

## Tech Stack

| 层 | 选型 | 版本 |
|---|---|---|
| Backend | Go | 1.26.5（dev）/ 1.22（CI） |
| HTTP | gin-gonic/gin | latest |
| WebSocket | gorilla/websocket | latest |
| DB | PostgreSQL | 16 |
| DB driver | jackc/pgx + jackc/pgx/v5/stdlib | v5 |
| Migrations | golang-migrate | v4.17 |
| Query | Hand-augmented sqlc (1.27 pinned) | v1.27 |
| UUID | oklog/ulid + google/uuid | ULID 26字符主键 |
| JWT | golang-jwt/jwt v5 | HS256 |
| Dashboard | Vanilla JS + Gin embed | (no framework) |
| CI | GitHub Actions (Node 24 / Go 1.22) | actions v6/v7 |

## Sprint 1 架构

```
internal/
├── auth/              # JWT + login + middleware + refresh tokens
├── rooms/             # rooms REST + service
├── messages/          # messages REST + service + cursor pagination
├── participants/      # on_stage + presence + capacity check
├── hub/               # in-process WS broadcast (11 methods)
├── ws/                # business-frame WS dispatch + frames
├── dashboard/         # loopback-only HTML/JS dashboard
├── users/             # display_name profile
├── store/             # hand-augmented sqlc queries
├── testutil/          # per-package DB test infra
└── cmd/fireside/      # main.go wiring
```

## RFC §7.2 acceptance gate

- ✅ 7.1 backend tests + ci gate
- ✅ 7.2 dashboard demo step 1-8 (full RFC)
- ⏸ 7.3 Android (Sprint 1.5, #11)
- ✅ 7.4 docs sync

## 26 issues closed

WP-1 to WP-8 全完成，#1-#26 全 closed, #27-#36 (reviewer Sprint 1.5 batch) 全 closed。

- **Wave 1 P0** (#18 #19 #21 #22): REST→WS broadcast, capacity race, idempotent login, ended-room 409
- **Wave 2 P1** (#20 #23 #24 #25 #26): dashboard TestMain fix, ::CHAR(26)→VARCHAR, comment fix, replay defense uid, housekeeping
- **WP-7** (#9): refresh token rotation with replay defense + display_name
- **WP-8** (#10): dashboard rooms.html + room.html + lib.js/rooms.js/room.js
- **#16** (L-2/L-3): per-package test infra + Node 24 Actions bump

## 测试

- `go test -race -count=1 ./...` — 7/7 packages, ~20s parallel
- 24/24 e2e dashboard smoke checks
- 4 review-defense unit tests

## Sprint 1.5 review acceptance

3 reviewer commits 全 accepted，10 issues #27-#36 解决:
- ci: golangci-lint v2.0.0 → v2.1.0
- WP-7/WP-8 batch: dashboard participants endpoint fix, fmtTime RFC3339, display_name runes
- Sprint 1.5 batch: refresh jti replay defense, testutil hardening (PGPASSWORD env, url.Parse, fallback to base DSN, isSafeIdent)

## 下一个 Sprint

- **Sprint 1.5 (#11 WP-9 Android)** — 1000-2500 LOC，唯一 open issue
- **Sprint 2 WS-2 Agent** — agent persona + brain seat 架构设计（IPD cycle）
- **Sprint 1.6 housekeeping** — RFC §2.3 deviations + dashboard display_name modal + retention worker

## 关联项目

- **mapcn** — 暂时不需要，但 Sanfineart 用得到
- **Strix** — 安全测试工具，与 Fireside 无关但是 research 可参考
- **OpenKimiPPTSkill** — Kimi PPT skill, 与 Fireside 无关
- **StadiView** — 3D 足球场可视化, 与 Fireside 无关

## RFC 文档

- `docs/rfc/phase-2-minimal-demo.md` — Sprint 1 RFC
- `docs/design/01-data-model.md` — 数据模型
- `docs/design/03-protocol.md` — 协议
- `docs/reviews/pdcp-checklist.md` — 设计评审清单

## 关键 commit 教训

- **LOC 估算偏差**: Sprint 1 估算 ~1200 LOC, 实际 ~10,000 (8x). 乐观/正常/悲观 模式在 Sprint 1 后用，原因是 test 占比 40% + cross-pkg deps + race fix
- **hand-augmented store 比 sqlc generate 稳** — Sprint 1 选 hand-aug 是 对的 (可 control 可 reproduce)
- **SQLSTATE 42P08 cast** — 所有 N 个 cast 都需 +$N::type 语法
- **CHAR(26) trailing-space bug** — Sprint 1.5 reviewer fix 用 VARCHAR(26)
- **gorilla/websocket concurrent write** — 必须 per-conn write mutex
- **per-package test infra** — testutil + docker pg_dump + psql 是 warchest (有 fallback)
