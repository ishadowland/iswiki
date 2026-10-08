# Hermes Feishu Gateway — Inbound Message-ID 缺失时的静默丢弃漏洞

> 学习笔记 · 初次调研 2026-09-26 · **事实复核 + 修正 2026-10-08**
> 调研对象: Hermes agent feishu gateway(本机使用 `coder` / `stock` / `curator` / `default` 四个 profile,实测)
> 源码位置: `~/.hermes/hermes-agent/plugins/platforms/feishu/adapter.py`
> 上游仓库: <https://github.com/NousResearch/hermes-agent>(本地副本,remote 已配,尚未提 PR)
> 监控脚本: `~/.hermes/bin/check-feishu-drop.sh`(已装 crontab,`*/15 * * * *`)
> ⚠️ 本地 patch **尚未 commit**,见 §「未提交状态」

## 一句话定位

**Hermes feishu gateway 在 inbound 消息 `message.message_id` 为 None 时会**默默丢弃整条消息**(既不入 dedup cache,也不入 agent 队列),且**只在 DEBUG 级别日志记录** — **生产环境看不到任何告警**。当前所有正常飞书消息都有 `om_xxx` ID 所以 bug 没触发,但**任何未来 event schema 变更 / 飞书机器人新订阅事件类型都可能导致消息静默丢失**。

**修复已在本机装上**(2026-09-26 落盘),本文档记录:原始 bug → 已装 patch 的实际代码 → 2026-10-08 的一手复核 → 复核中发现的第二层 bug。

## 触发场景

不是当下正在发生的 bug — 是**潜伏型 bug**。已搜过本机全部 profile 日志,两个模式命中均为 **0 次**:

| 日志模式 | 含义 | 本机命中 |
|---|---|---|
| `Dropping duplicate/missing message_id` | patch 前的静默丢弃 | **0**(patch 前从没触发过) |
| `Inbound message missing message_id; using fallback id` | patch 后的 fallback 生成 | **0**(patch 后也从没触发过) |

即:两条路径都没被真实流量走到过。**patch 的有效性至今未经真实流量验证。**

但以下情况会触发:

| 场景 | 触发方式 |
|---|---|
| 飞书机器人新订阅事件类型(如卡片表单 / 日历 / 任务 / AI 智能伙伴) | 新事件对象可能不填 `message_id` |
| 飞书消息对象 schema 演进 | 字段改名 / 嵌套结构变了 → `getattr(message, "message_id", None)` 返回 None |
| 自定义 webhook 转发进来事件 | 飞书以外的 gateway 不会填标准 `message_id` |
| 卡片表单 submit (`Card.ActionTrigger`) | 见 §「card 路径复核」— 当前代码已经不依赖 `message_id`,这条已不成立 |

## 复现路径

发一条 inbound 飞书事件到 gateway,如果 `event.message.message_id` 是 None:

1. `adapter.py:2565`:`message_id = getattr(message, "message_id", None)` → None
2. `adapter.py:2566`:`if not message_id:` → 命中 fallback 分支(**已 patch**;patch 前是 `if not message_id or self._is_duplicate(...)` → 直接 return)
3. **patch 后**:`adapter.py:2571-2579` 合成 `feishu:fallback:<sha1[:16]>` + 打 `logger.warning` → `adapter.py:2582` 走正常 dedup → `adapter.py:2592` 进入 `_process_inbound_message`

**关键问题(patch 前)**:

- **不写入 `_seen_message_ids`** → 下次同样的 None message 不会触发 dedup
- **不进 `_pending_inbound` 队列** → 不会被重试
- **DEBUG 日志** → `INFO`-level filter / production log shipper 看不到
- **`return` 不抛异常** → 不会有 stack trace / alert

**结果**:用户看不到任何信号,agent 永远不响应,但用户误以为 "agent 没收到我的消息 / 飞书抽风"。

## 源码位置(patch 后实际代码,2026-10-08 一手核对)

```python
# ~/.hermes/hermes-agent/plugins/platforms/feishu/adapter.py:2565-2584
message_id = getattr(message, "message_id", None)
if not message_id:
    # Synthesize a stable fallback id so dedup still works AND the
    # message actually reaches the agent instead of being silently
    # dropped. Uses (sender, chat, content_hash, 1-min time bucket) so
    # the same burst of retries does not each get a fresh id.
    sender_id = getattr(sender, "sender_id", None) or "unknown"
    chat_id = getattr(message, "chat_id", None) or "unknown"
    raw_content = (getattr(message, "content", "") or "")[:200]
    time_bucket = int(time.time()) // _FEISHU_FALLBACK_DEDUP_TTL_SECONDS
    seed = f"{sender_id}|{chat_id}|{raw_content}|{time_bucket}".encode("utf-8")
    message_id = "feishu:fallback:" + hashlib.sha1(seed).hexdigest()[:16]
    logger.warning(
        "[Feishu] Inbound message missing message_id; using fallback id=%s "
        "(sender=%s chat=%s) — please report upstream if seen often",
        message_id, sender_id, chat_id,
    )
if self._is_duplicate(message_id):
    logger.debug("[Feishu] Dropping duplicate message_id: %s", message_id)
    return
```

**函数名更正**:处理函数实际叫 **`_handle_message_event_data`**(不是初次笔记写的 `_on_message_received`),位于 `adapter.py:2556`,docstring 写明是 websocket + webhook 两种 transport 共用的 inbound 处理路径。

**常量(patch 新增,`adapter.py:222`)**:

```python
_FEISHU_FALLBACK_DEDUP_TTL_SECONDS = 10 * 60    # 10 min — fallback ids dedup on (sender,chat,content,bucket)
```

### 复核发现的 6 处偏差(初稿 vs 实际代码)

| # | 初稿写的 | 实际代码 | 性质 |
|---|---|---|---|
| 1 | patch「待打」 | **patch 2026-09-26 11:44 已落盘**,`git diff` 有 19 增 2 删未提交改动 | 状态判断错误 |
| 2 | `time_bucket = int(time.time() // 60)`(1 分钟桶) | `int(time.time()) // _FEISHU_FALLBACK_DEDUP_TTL_SECONDS` = **10 分钟桶** | patch 与实际不符 |
| 3 | 用 Python 内置 `hash(raw_content)` | **`hashlib.sha1(seed).hexdigest()[:16]`** | 内置 `hash()` 每进程随机加盐 → 跨重启不稳定;实际用了 sha1(正确做法,注释还漏写「1-min」但代码是 10 min) |
| 4 | 新增 `_missing_id_seen` 独立 dict + `_persist_missing_id_seen()` 独立持久化 | **不存在**。fallback id 直接进 `_seen_message_ids`,走同一套 24h TTL + 同一份 JSON | 初稿虚构了不存在的字段 |
| 5 | sibling 漏洞 `_on_card_action_trigger` 会丢消息 | **不成立**。card 路径用 `event.token` 判重(`_is_card_action_duplicate`,`adapter.py:3034-3036`),按 `open_chat_id` + `operator.open_id` 取值,**全程不依赖 `message_id`** | 初稿误判 |
| 6 | seed 分隔符 `:` | 用 `\|`(管道符) | 小差异,避免与内容里的 `:` 冲突 |

**偏差 4 的后果**(值得单独记):因为 fallback id 复用 `_seen_message_ids` 而非独立 store,它受 `_FEISHU_DEDUP_TTL_SECONDS = 24 * 60 * 60`(`adapter.py:221`)约束。而 seed 里的 `time_bucket` 只保证**同一 10 分钟桶内**id 相同;跨桶后 seed 变化 → id 变化 → **必然被当作新消息处理**。所以「24h TTL 防重发」对 fallback id 是**名义上的**,实际只由 10 分钟桶决定去重窗口。这一点初稿没意识到。

### card 路径复核(初稿误判 #5 的展开)

```python
# adapter.py:3031-3043  _handle_card_action_event
token = str(getattr(event, "token", "") or "")
if token and self._is_card_action_duplicate(token):
    logger.debug("[Feishu] Dropping duplicate card action token: %s", token)
    return

context = getattr(event, "context", None)
chat_id = str(getattr(context, "open_chat_id", "") or "")
operator = getattr(event, "operator", None)
open_id = str(getattr(operator, "open_id", "") or "")
if not chat_id or not open_id:
    logger.debug("[Feishu] Card action missing chat_id or operator open_id, dropping")
    return
```

→ 卡片的判重键是 **`event.token`**(飞书为每次卡片动作生成的唯一 token),不是 `message_id`。缺 `token` 时只跳过判重(不拦消息),缺 `chat_id`/`open_id` 才丢(且此时丢的是上下文缺失,不是 id 缺失,属合理的 fail-closed)。**本条初稿描述的「同型 bug」在当前代码里不存在。**

## 期望行为 vs 实际行为

| 期望 | 实际 |
|---|---|
| **消息不丢**:log 一条 WARN,生成一个稳定的 fallback id,继续处理 | ✅ **patch 后已满足**(WARN + fallback id + 继续处理) |
| **去重仍然有效**:fallback id 写入 dedup cache,避免同一条 None 消息重发时被 N 次处理 | ⚠️ **部分满足**。同 10 分钟桶内有效;跨桶必被当新消息(见偏差 4) |
| **可监控**:`feishu_messages_dropped_total{reason="missing_id"}` Prometheus 指标 / WARN 日志 | ⚠️ **仅 WARN 日志**。Prometheus 指标未实现;监控靠 grep 脚本 |
| **agent 上下文保留**:消息即使没 id,至少应该到达 agent | ✅ **patch 后已满足** |

## 监控脚本

已装:`~/.hermes/bin/check-feishu-drop.sh`,crontab 已配:

```
*/15 * * * * /Users/liuyin/.hermes/bin/check-feishu-drop.sh >> /Users/liuyin/.hermes/feishu-drop.log 2>&1
```

脚本行为(扫全部 profile 的 `logs/gateway.log`,exit code 供 cron 分级):

| 条件 | verdict | exit |
|---|---|---|
| 命中 `Dropping duplicate/missing message_id`(patch 前模式) | `✗ PATCH MISSING (silent drops)` | **2** |
| fallback id 命中 ≥ 50 | `⚠ INVESTIGATE` | 2 |
| fallback id 命中 ≥ 5 | `⚠ INVESTIGATE` | 1 |
| 其他 | `✓ ok` | 0 |

### ⚠️ 第二层 bug:`grep -c` + `set -e` 让脚本静默失效(2026-10-08 复核发现并修复)

初稿(以及**已经装在 crontab 里的那份脚本**)有个致命缺陷:

```bash
#!/usr/bin/env bash
set -euo pipefail
...
silent_drops=$(grep -c "Dropping duplicate/missing message_id" "$gateway.log" 2>/dev/null | head -1)
```

`grep -c` 在**无匹配时返回 exit 1**。在 `set -euo pipefail` 下,这个非零 exit 会让**整个脚本立刻退出** —— 而本机日志里两个模式命中都是 0,即**每次 cron 都在第一个 profile 就崩掉**,零输出、零告警。

实测证据:

```
$ bash -x ~/.hermes/bin/check-feishu-drop.sh; echo "exit=$?"
...
+ '[' -f .../curator/logs/gateway.log ']'
++ grep -c 'Dropping duplicate/missing message_id' .../gateway.log
+ silent_drops=0
(脚本在此终止,无后续输出)
exit=1
```

**这个监控从 2026-09-26 12:09 装上 crontab 起,静默失败了 12 天**(`~/.hermes/feishu-drop.log` 大小 0 字节,cron 重定向只写 stdout,脚本没输出就什么都没有)。

**修复**(已落盘,原文件备份为 `check-feishu-drop.sh.bak`):

```diff
-    silent_drops=$(grep -c "Dropping duplicate/missing message_id" "$gateway_log" 2>/dev/null | head -1)
+    silent_drops=$( { grep -c "Dropping duplicate/missing message_id" "$gateway_log" || true; } 2>/dev/null | head -1 )
     silent_drops=${silent_drops:-0}
-    fallback_ids=$(grep -c "Inbound message missing message_id; using fallback id" "$gateway_log" 2>/dev/null | head -1)
+    fallback_ids=$( { grep -c "Inbound message missing message_id; using fallback id" "$gateway_log" || true; } 2>/dev/null | head -1 )
     fallback_ids=${fallback_ids:-0}
```

`|| true` 让无匹配时 `grep` 的 exit 1 变成 0,计数照常是 `0`。

**修复后验证**(三个场景实测):

```
$ bash ~/.hermes/bin/check-feishu-drop.sh; echo "exit=$?"
✓ ok
exit=0

# 喂 1 条静默丢弃的假日志
$ HOME=$T bash ~/.hermes/bin/check-feishu-drop.sh; echo "exit=$?"
✗ PATCH MISSING (silent drops) | 1 events silently dropped in lifetime — patch may have been rolled back
  [test] silent=1 fallback=0
exit=2

# 喂 1 条 fallback id 命中的假日志(未达阈值 5,判 ok 正确)
$ HOME=$T bash ~/.hermes/bin/check-feishu-drop.sh; echo "exit=$?"
✓ ok
  [test] silent=0 fallback=1
exit=0
```

`bash -n` 语法检查通过。

**通用教训**:`set -euo pipefail` + `grep -c` 是 shell 监控脚本的经典陷阱 —— **`grep -c` 无匹配返回 1 是正常语义,不是错误**。任何 `$(grep -c ...)` 都要么 `|| true`,要么 `|| echo 0`,否则「监控没发现问题」会伪装成「监控自己挂了」。

## 未提交状态(2026-10-08 一手核对)

```
$ cd ~/.hermes/hermes-agent && git status --short
 M plugins/platforms/feishu/adapter.py
?? plugins/web/serper/

$ git diff --stat plugins/platforms/feishu/adapter.py
 plugins/platforms/feishu/adapter.py | 21 +++++++++++++++++++--
 1 file changed, 19 insertions(+), 2 deletions(-)

$ git log -1 --format='%h %ad' --date=short   # HEAD
470cf66b03 2026-08-01
```

- patch 在工作区未 commit,**从未 push 到上游**(`origin` = `https://github.com/NousResearch/hermes-agent.git`)
- 本地 HEAD 停在 2026-08-01,`adapter.py` 最后一次正式提交是 `1f45ff9e8a`(2026-07-29),**上游此后 10 天对该文件的改动没被本地同步**
- `plugins/web/serper/` 是无关的未跟踪目录,跟本 bug 无关
- **风险**:gateway 是 launchd 常驻进程,跑的就是这份被改过的代码。下次 `git pull` / hermes 更新 / hermes-agent 自动更新时,若上游动了同一区域,**冲突或静默丢失 patch 的可能**。已在 §行动建议 列为优先级最高项

## 验证 patch 是否生效

patch 已装 12 天但**从未被真实流量触发**(两个日志模式命中均为 0),所以有效性未经实测:

1. **正常路径**(消息有 id):行为完全不变 — `om_xxx` 仍正常 dedup。这条每天都在跑,零异常。
2. **缺失 id 路径**:**未验证**。需用 `feishu` webhook tester 发一条手工构造的 `p2_im_message.message_receive_v1` payload,`message.message_id` 字段缺失 → 应看到 `[Feishu] Inbound message missing message_id; using fallback id=...` WARNING + agent 收到消息。
3. **fallback id 稳定性**:跨 gateway 重启后重发同一条无 id 消息,sha1 seed 只依赖 `(sender, chat, content[:200], 10min-bucket)`,**不含进程内状态** → id 应完全一致 → dedup 生效。这点从代码可推断,但未实测。
4. **回归检查**:本机没有 `diagnose-hermes-agent.sh`(初稿提到的 `hermes-gateway-self-recovery` skill 也不存在,实际是 `hermes-gateway-ops` + `hermes-gateway-local`)。改 adapter.py 的风险面是 inbound dedup / card 路由 / 出站发送,改的只是 dedup 前置分支,不影响 base_url / fallback chain / live probe。

## 相关代码片段(参考)

### `_is_duplicate`(未改动,值得复用)

```python
# adapter.py:4589-4603
def _is_duplicate(self, message_id: str) -> bool:
    now = time.time()
    ttl = _FEISHU_DEDUP_TTL_SECONDS
    with self._dedup_lock:
        seen_at = self._seen_message_ids.get(message_id)
        if seen_at is not None and (ttl <= 0 or now - seen_at < ttl):
            return True
        self._seen_message_ids[message_id] = now
        self._seen_message_order.append(message_id)
        while len(self._seen_message_order) > self._dedup_cache_size:
            stale = self._seen_message_order.pop(0)
            self._seen_message_ids.pop(stale, None)
        self._persist_seen_message_ids()
        return False
```

### `_FEISHU_DEDUP_TTL_SECONDS` 与 fallback TTL

```python
# adapter.py:221-222
_FEISHU_DEDUP_TTL_SECONDS = 24 * 60 * 60              # 24 hours — matches openclaw
_FEISHU_FALLBACK_DEDUP_TTL_SECONDS = 10 * 60          # 10 min — fallback ids dedup on (sender,chat,content,bucket)
```

### `_admit`(dedup 之后的第二道闸,patch 未触碰)

`adapter.py:4316` 起的 `_admit(sender, message)` 在 dedup 之后做准入判断:self_echo / bots_disabled / bot_not_mentioned / dm_policy_rejected / group_policy_rejected。**即使 message_id 缺失被 fallback 救回来,消息仍可能被 `_admit` 拦掉**(例如群消息未 @ bot)。这条链路初稿没提,排查「agent 不响应」时要一并看。

### `_process_inbound_message`(真正的入口)

`adapter.py:2592` 调用,`message_id` 作为参数传下去,贯穿去重、限流、日志与投递。

## 跨 iswiki 引用

- [recovery-sop.md](../ops-cybersec-dba/recovery-sop.md) — Hermes 服务整体恢复 SOP
- [wafKnowledgeBase.md](../ops-cybersec-dba/wafKnowledgeBase.md) — 静默丢弃 vs 主动告警的对比思想(本 bug 是典型静默丢失)

## 行动建议

1. **最优先 —— commit 并提 PR 到上游**。本地 patch 裸奔 12 天,HEAD 停在 2026-08-01,`git pull` 一冲突就可能丢。upstream `AGENTS.md` 明确把这类修复列为 wanted work(「Fix real bugs, well」+「fix the whole bug class — sibling call paths included」),这个 patch 正好符合。提 PR 时 note 里带上「sibling path 已复核、card 路径不依赖 message_id」。
2. **把 fallback 去重窗口的语义想清楚再提**。现在 10 分钟桶 + 24h TTL 是两套语义混用:bucket 保证桶内幂等,bucket 边界会放行。选哪个取决于上游重发窗口有多长 —— **不知道上游行为就不该固化 10 分钟这个魔数**。建议改成从配置读,或至少注释说明依据。
3. **给监控加 Prometheus 指标**(可选)。现在只有 grep + WARN。要真正可观测,应该把 `missing_id` 计一个 `feishu_messages_dropped_total{reason="missing_id"}`,而不是让人去 grep 日志。
4. **给 `check-feishu-drop.sh` 加个自检**(建议)。这次的教训是「监控自己挂了没人知道」。最省事的做法:cron 行尾加 `|| echo "check-feishu-drop.sh FAILED exit=$?" >> ~/.hermes/feishu-drop.log`,这样脚本崩了也留痕。
5. **生产日志采集过滤掉 DEBUG** 是本 bug 的隐性放大器。即便 patch 前有日志,DEBUG 级在生产 filter 下也等于没有。