# Nginx 502 vs 504 — 故障域排查(老兵翻车 5 小时)

> 学习笔记 · 调研时间 2026-09-12
> 调研来源: 胡哥Linux运维《网关报 502 别乱调超时,老兵翻车 5 小时才搞清 504 才是真超时》 https://mp.weixin.qq.com/s/GCX3RqfjT0EIumD1uDuCVw
> 关联笔记: [performanceTriage.md](performanceTriage.md) · [opsTroubleshootingDiskGhost.md](opsTroubleshootingDiskGhost.md) · [opsTroubleshootingOOMCgroup.md](opsTroubleshootingOOMCgroup.md)

## 一句话定位
502/504 不是「严重程度」的两个级别,而是**两个完全不同的故障域**;503 调超时是 90% 运维栽过的坑。

## 三种使用方式

| 场景 | 入口 | 适用 |
|---|---|---|
| 应急排查(事故中) | curl -v 测后端 + tcpdump 抓包 | 任何 Nginx/OpenResty/Traefik 网关场景 |
| 复盘 / 写 SOP | access/error log 顺序 + 抓包比对 | 写给团队的故障手册 |
| 沉淀为 skill | 故障域判定 + 三招命令 | 给 AI Agent / 新人排错 |

## 核心结论:故障域定义

| 状态码 | 含义 | 故障域 | 常见诱因 |
|---|---|---|---|
| **502 Bad Gateway** | 网关访问后端**没拿到正常响应** | **后端进程 / 网络层** | 进程崩 / 连接被拒 RST / OOM 被 kill / 防火墙拦截(云厂商安全组默认回 RST) / 上游提前断连(`upstream prematurely closed connection`) |
| **504 Gateway Timeout** | 连上后端、发出请求,**等到超时也没收到响应** | **链路 / 性能** | 后端处理慢 / DB 慢查询 / 链路抖动 / 上游限流 |

**最容易栽的坑**:看到 502 第一反应调 `proxy_*_timeout` ——
- 对 504:调大有效(让网关愿意多等)
- 对 502:**完全反方向** — 等一个根本不会来的连接,等于把故障面放大(文中案例:35% → 52% → 70%)

**记忆口诀(胡哥原话)**:"502 和 504 看起来只是两位数差距,但它们指向的完全是两个世界——一个在后端进程,一个在链路性能。**你以为是同一个房间的左右墙,其实是两个机房的门。**"

## 三招排查动作(可 copy-paste)

### 第 1 招:`curl -v` 区分「症状」

```bash
# 502 场景:连接被拒(后端没起 / 被防火墙挡 / 进程 OOM)
$ curl -v http://10.0.0.5:8080/pay
* Trying 10.0.0.5:8080...
* connect to 10.0.0.5 port 8080 failed: Connection refused
* Failed to connect to 10.0.0.5 port 8080

# 504 场景:连上了但等到超时(后端慢 / DB 慢查询)
$ curl -v --max-time 5 http://10.0.0.5:8080/pay
* Trying 10.0.0.5:8080...
* Connected to 10.0.0.5 (10.0.0.5) port 8080
> GET /pay HTTP/1.1
* Operation timed out after 5001 milliseconds with 0 bytes received
```

**判定规则**:
- `Connection refused` 或 `Connection reset by peer` → **502 域,绝对不要调超时**
- `Operation timed out` 但前面有 `Connected to` → **504 域,调超时才有意义**

### 第 2 招:网关层 `tcpdump` 看 SYN 是否到达后端

```bash
tcpdump -i eth0 -nn -s 0 'host 10.0.0.5 and port 8080' -w /tmp/cap.pcap
# Wireshark 打开 /tmp/cap.pcap,看三件事:
```

| 抓包现象 | 含义 | 故障域 |
|---|---|---|
| SYN 出去,SYN-ACK 没回来 | 后端没收到 / 没回 | **502** |
| 三次握手成功,但响应中收到 FIN/RST | 上游提前断连(`upstream prematurely closed connection`) | **502** |
| 三次握手成功,应用层一直不返回数据 | 后端连上了但卡 | **504** |

**避坑**:很多人只看 SYN 数不对就慌,忽略 FIN/RST — **FIN/RST 也是 502 信号**,意思是「连上了又被踢出来」。

### 第 3 招:正确顺序 — 先看后端 log,再决定调网关参数

正确顺序(胡哥复盘):
1. **后端 access/error log**(最便宜、最快定位)
2. **curl -v 旁路测后端**(确认故障域)
3. **tcpdump 抓包**(确认网络层有没有 FIN/RST)
4. **最后才调网关参数**(且必须先确认是 504 域)

**核心原则**:**调网关超时参数永远是最后一步,不是第一步**。

## 完整 Nginx 502 误调反模式(警告)

```nginx
# ❌ 错误示范:看到 502 就调这俩
proxy_connect_timeout 60s;
proxy_send_timeout    60s;
proxy_read_timeout    60s;
# ↑ 这套对 504 有效,对 502 等于"等一个不会来的连接"
```

```nginx
# ✅ 正确做法:先排查,再决定是否调;且上限通常 30s 就够
proxy_connect_timeout 5s;   # 502 域就改排查思路,不是改这里
proxy_send_timeout    30s;
proxy_read_timeout    30s;
proxy_next_upstream   error timeout;   # 配合 upstream 块做 failover
```

## 跟我们的关系

| 场景 | 用法 |
|---|---|
| **AI coding agent 的 on-call skill** | 把「三招 + 顺序」写成 SKILL.md,给 agent 在 502/504 时自动执行:先 curl -v 后端、再 tcpdump、最后才考虑改 Nginx |
| **生产事故复盘模板** | 跟 [performanceTriage.md](performanceTriage.md) 配合:先四维定位(快照 vs 趋势 / 用户态 vs 内核态),再用 502/504 域判定收敛到具体动作 |
| **新人 / 跨团队培训** | "慢就是快"是反复出现的运维心法 — 跟「幽灵空间」「cgroup OOM」同系列,可做整套运维翻车笔记归档 |
| **跟现有笔记的呼应** | [opsTroubleshootingDiskGhost.md](opsTroubleshootingDiskGhost.md) + [opsTroubleshootingOOMCgroup.md](opsTroubleshootingOOMCgroup.md) 都是胡哥同系列,**命名风格一致,索引一起浏览价值高** |

## 风险点 / 容易重蹈覆辙

1. **「想当然」陷阱**:老运维栽在自信,新运维栽在不懂 — 同样栽 5 小时
2. **工具近邻陷阱**:网关配置离得最近、改起来最快,但**往往不是源头**(运维领域普适规律,见 [performanceTriage.md](performanceTriage.md) 「工具越近,误诊越深」)
3. **FIN/RST 漏看**:抓包只盯 SYN,忽略 FIN/RST,误判为网络问题
4. **云厂商安全组默认值**:多数云厂商安全组拒绝时回 RST(表现为 502),不是丢包 — 排查时别只看 nginx 日志
5. **「调超时万能」迷信**:只在 504 域有效;502 域调超时等于扩大故障面(文中案例 5 小时教训)

## 版本 / 适用性

- **适用网关**:Nginx / OpenResty / Tengine(配置项 `proxy_*_timeout` 通用)
- **适用层**:L7 反向代理网关(本文不覆盖 L4 负载均衡器如 HAProxy / Envoy 的对应错误码)
- **协议**:HTTP/1.1 为主;HTTP/2 / gRPC 流式场景下 502/504 仍适用,但需额外看 GOAWAY 帧

## 参考链接

- 原文: 胡哥Linux运维《网关报 502 别乱调超时,老兵翻车 5 小时才搞清 504 才是真超时》 https://mp.weixin.qq.com/s/GCX3RqfjT0EIumD1uDuCVw
- RFC 7231 §6.6.3 502 定义: <https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.3>
- RFC 7231 §6.6.5 504 定义: <https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.5>
- Nginx `proxy_*_timeout` 文档: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout>
- 关联笔记: [performanceTriage.md](performanceTriage.md) · [opsTroubleshootingDiskGhost.md](opsTroubleshootingDiskGhost.md) · [opsTroubleshootingOOMCgroup.md](opsTroubleshootingOOMCgroup.md)