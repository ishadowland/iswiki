# Nginx 502 vs 504 — 给初级 D&O 的故障域排查手册

> 学习笔记 · 调研时间 2026-09-12(2026-09-12 二次润色:面向初级开发 / 运维)
> 调研来源: 胡哥Linux运维《网关报 502 别乱调超时,老兵翻车 5 小时才搞清 504 才是真超时》 https://mp.weixin.qq.com/s/GCX3RqfjT0EIumD1uDuCVw
> 关联笔记: [performanceTriage.md](performanceTriage.md) · [opsTroubleshootingDiskGhost.md](opsTroubleshootingDiskGhost.md) · [opsTroubleshootingOOMCgroup.md](opsTroubleshootingOOMCgroup.md)

---

## 写在最前面:你大概率会栽的坑(先看这一段)

如果你在生产事故里看到 502,**第一件事不是改 Nginx 配置,而是读这一段**。

**胡哥老兵 15 年经验,凌晨事故栽 5 小时**,核心教训就是:

> "**502 和 504 看起来只是两位数差距,但它们指向的完全是两个世界——一个在后端进程,一个在链路性能。你以为是同一个房间的左右墙,其实是两个机房的门。**"

**最常见的错操作**(把胡哥的翻车当反面教材背下来):

| ❌ 你想做的 | 实际后果 | 为什么错 |
|---|---|---|
| 看到 502 → 调大 `proxy_*_timeout` | 错误率从 35% → 52% → 70% | 502 的根因是后端**根本没回响应**,你调超时等于让网关花更多时间等一个**永远不会来的连接** |
| 看到 504 → 重启后端 | 后端起来后被同样流量再次压垮 | 504 是后端**活着但慢**,重启不解决根因 |
| 抓包只盯 SYN 数 | 漏掉 FIN/RST,误判是网络问题 | **FIN/RST 也是 502 信号**(上游提前断连),但很多工具默认不显眼展示 |
| 看到错误码就改配置 | 5 小时翻车 | **改配置永远是最后一步**,不是第一步 |

> [!CAUTION] **记住一句心法**:**慢就是快**。先确认问题域,再动手调参。盲目调参是 90% 运维栽过的坑。

---

## 一句话定位

**502/504 不是「严重程度」的两个级别,而是两个完全不同的故障域**;看到 502 就调超时,是 90% 运维(包括 15 年老兵)栽过的坑。

---

## 0. 预备知识:5 分钟搞清楚「网关在干嘛」

如果你刚开始接触 Nginx,先看这段;老司机可以跳过。

**典型架构**:

```
[用户] → [Nginx 网关] → [你的后端服务(Python/Java/Go/Node...)]
              │
              └── 也可能: [Nginx] → [L7 负载均衡(SLB/ALB)] → [后端集群]
```

- **Nginx = 网关(也叫「反向代理」)**:用户的请求先打到 Nginx,Nginx 再转发给后端真正的服务
- **后端 = 真正干活的程序**:处理订单、查数据库、调第三方接口
- **网关和后端之间的连接,跟用户和网关之间的连接,是两段独立的网络**

**为什么会有 502/504?**
因为 Nginx 在中间,它**没办法控制后端在干嘛**。它只能观察到「我去访问后端,后端给了我什么反馈」,然后把这个反馈翻译成 HTTP 状态码返回给用户。

所以 502/504 本质上是 Nginx 在跟你说:**"我去访问后端,出了状况"**。但「什么状况」,得你自己去查。

---

## 1. 故障域定义(整篇文章最核心的一张表)

| 状态码 | 网关实际做了什么 | 故障域 | 通俗理解 |
|---|---|---|---|
| **502 Bad Gateway** | 去访问后端,**没拿到正常响应** | **后端进程 / 网络层** | "后端**没起来**,或者**起了但又被踢出来**" |
| **504 Gateway Timeout** | 连上后端、发出请求,**等到超时都没收到响应** | **链路 / 性能** | "后端**活着**,但**慢得跟死了一样**" |

**对应到现实场景**:

| 502 的常见诱因 | 504 的常见诱因 |
|---|---|
| 后端进程崩了 / 没启动 | 后端处理慢(死循环、慢查询) |
| OOM 被 Linux kill 掉 | 数据库慢查询 |
| 防火墙拦截 → RST(云厂商安全组默认行为) | 第三方接口慢 / 超时 |
| 进程 listen 的 IP/端口错(只 listen 127.0.0.1,外部访问不到) | 后端线程池打满 |
| 上游提前断连(`upstream prematurely closed connection`) | 链路抖动 / 丢包重传 |
| 容器/Pod 没就绪就被流量打进来(K8s readiness 没配) | 上游限流 / 熔断 |

> [!TIP] **怎么记**:502 = **连不上 / 连上被踢**;504 = **连上了但慢**。

---

## 2. 排查总览:三招 + 一个顺序

**记住这个顺序,出事故照着抄作业**:

```
第 1 步:curl -v 测后端(30 秒,确认故障域)
   ↓
第 2 步:tcpdump 抓包(2 分钟,确认网络层)
   ↓
第 3 步:看后端 access/error log(确认具体原因)
   ↓
第 4 步:才考虑改 Nginx 配置(且必须先确认是 504 域)
```

**核心原则**:**调网关超时参数永远是最后一步,不是第一步**。

---

## 3. 第 1 招:`curl -v` 区分「症状」(事故中第一步)

**为什么用 curl 而不是浏览器**:浏览器会缓存、会重试、会隐藏细节;`curl -v` 把每一次握手、每一个字节都摊给你看。

### 命令模板(直接抄)

```bash
# 把 10.0.0.5 换成你的后端 IP,8080 换成后端端口
# --max-time 5 是关键:5 秒没响应就放弃,避免你跟着卡住

# 测后端(绕过 Nginx,直接打后端)—— 这一步 90% 能定性
curl -v --max-time 5 http://10.0.0.5:8080/你的接口路径

# 同时测通过 Nginx 的请求,对比两边表现
curl -v --max-time 5 http://nginx的域名或IP/你的接口路径
```

### 怎么读输出

#### 场景 A:看到 `Connection refused`(典型的 502)

```
$ curl -v --max-time 5 http://10.0.0.5:8080/pay
* Trying 10.0.0.5:8080...
* connect to 10.0.0.5 port 8080 failed: Connection refused
* Failed to connect to 10.0.0.5 port 8080
* Closing connection 0
```

**怎么读**:`connect to ... failed: Connection refused` 翻译过来就是**"我去敲门,门里面没人,操作系统直接把我赶走了"**。

**这是 502 域**,而且是 502 里最好定位的一种(连接级失败)。

**怎么修**:去查后端为啥没起来 — 见 §6 速查清单。

#### 场景 B:看到 `Connection reset by peer`(也是 502)

```
* Trying 10.0.0.5:8080...
* Connected to 10.0.0.5 (10.0.0.5) port 8080
> GET /pay HTTP/1.1
* Recv failure: Connection reset by peer
* Closing connection 0
```

**怎么读**:连上了,但**对方主动把我的连接掐了**(发了 RST 包)。常见原因:防火墙规则、安全组拦截、上游服务发现我扛不住把我踢了。

**这也是 502 域**,但比 A 难定位(因为"连上了又被踢"原因更多)。

#### 场景 C:看到 `Operation timed out`(典型的 504)

```
$ curl -v --max-time 5 http://10.0.0.5:8080/pay
* Trying 10.0.0.5:8080...
* Connected to 10.0.0.5 (10.0.0.5) port 8080    ← 注意:Connected to
> GET /pay HTTP/1.1
> Host: 10.0.0.5:8080
>
* Operation timed out after 5001 milliseconds with 0 bytes received
```

**怎么读**:**连上了**,但是**等了 5 秒什么都没收到**。

**这是 504 域**。调超时参数**对这种场景有效**(让网关愿意等更久)。

### 判定速查表

| curl 输出关键词 | 故障域 | 该做什么 | 不该做什么 |
|---|---|---|---|
| `Connection refused` | **502** | 查后端进程 / 端口监听 | ❌ 调 `proxy_*_timeout` |
| `Connection reset by peer` | **502** | 查防火墙 / 安全组 / OOM | ❌ 调 `proxy_*_timeout` |
| `Operation timed out`(有 `Connected to`) | **504** | 查后端慢的原因(DB/线程池) | ✅ 此时调大超时才有意义 |
| `No route to host` | 网络层 | 查路由表 / VLAN / 安全组 | — |
| HTTP 5xx 状态码(502/504 之外的 500/503) | 后端应用 | 看后端 log | — |

---

## 4. 第 2 招:`tcpdump` 抓包看 SYN/FIN/RST(确认网络层)

**什么时候用**:curl 输出模糊(`Operation timed out` 但不确定是网络还是后端慢),或者需要给老板/同事「眼见为实」的证据。

### 命令模板(直接抄)

```bash
# 在 Nginx 服务器上抓包(不是后端)
# -i eth0:网卡,按你的实际情况改成 eth0 / ens33 / ens192
# host 10.0.0.5:后端 IP
# port 8080:后端端口
# -w /tmp/cap.pcap:存到文件,用 Wireshark 打开看

tcpdump -i eth0 -nn -s 0 'host 10.0.0.5 and port 8080' -w /tmp/cap.pcap

# 抓包过程中,在另一台机器(或同一台)触发请求:
curl --max-time 5 http://nginx域名/接口路径

# 抓 5-10 个请求就够了,Ctrl+C 停
# 然后 scp /tmp/cap.pcap 到本地,用 Wireshark 打开
```

### Wireshark 看什么:过滤表达式(直接抄)

在 Wireshark 的过滤栏输入:

```
# 只看 TCP 三次握手
tcp.flags.syn == 1

# 只看 RST(被踢)
tcp.flags.rst == 1

# 只看 FIN(主动关闭)
tcp.flags.fin == 1

# 看某个连接的完整生命周期
tcp.stream eq 0
```

### 三种抓包现象速查

| 抓包现象 | 含义 | 故障域 |
|---|---|---|
| **SYN 出去,SYN-ACK 没回来** | 后端没收到 / 没回包 | **502**(可能防火墙、可能后端没起) |
| **三次握手成功,但响应中收到 FIN 或 RST** | 上游**主动**断连(`upstream prematurely closed connection`) | **502**(常见于 OOM、安全组拦截、容器被驱逐) |
| **三次握手成功,应用层一直不返回数据** | 后端连上了但卡 | **504** |

### ⚠️ 新人最容易踩的坑:只盯 SYN,漏掉 FIN/RST

很多新人抓包后,只数 SYN 数,看到 SYN 数对就以为没事。**这是错的**。

> [!WARNING] **FIN/RST 也是 502 信号**,意思是「连上了又被踢出来」。如果你的抓包里三次握手都有,但中间有 FIN 或 RST,**别怀疑,这就是 502**。

---

## 5. 第 3 招:看后端 log,定位具体原因

**为什么这一招排第三**:前两招确认了故障域(502 还是 504),这一招定位具体原因(后端是 OOM 了?还是慢查询?还是没启动?)。

### 5.1 后端进程根本没启(最常见的 502 根因之一)

```bash
# 1. 看进程在不在
ps aux | grep 你的服务名
# 或 systemctl
systemctl status 你的服务名

# 2. 看端口有没有在 listen
ss -tlnp | grep 8080
# 期望看到:LISTEN 0  128  *:8080  *:*  users:(("你的服务",pid=1234,fd=7))
# 如果没输出 → 进程没启,或 listen 的端口不对

# 3. 看启动日志
journalctl -u 你的服务名 -n 100 --no-pager
# 或
tail -100 /var/log/你的服务/error.log
```

**常见「启不来」的原因**:

| 现象 | 排查命令 | 典型原因 |
|---|---|---|
| 进程不在 | `ps aux \| grep xxx` | 启动失败 / OOM 被 kill / 配置错误退出 |
| 进程在但端口没 listen | `ss -tlnp` | 配置里 listen 的是 127.0.0.1 不是 0.0.0.0 |
| 进程在、端口有 listen,但 curl 还是 refused | 看防火墙 | 云厂商安全组没放行(常见!) |
| 启动日志报 `Address already in use` | `lsof -i :8080` | 端口被别的进程占着 |

### 5.2 后端进程在,但响应慢(典型 504 根因)

```bash
# 1. 看 CPU
top -c
# 按 P 按 CPU 排序,看是不是某个进程吃满了

# 2. 看内存 / 是否 OOM
dmesg | grep -i "killed process"
# ↑ 看到这种日志,说明进程被 Linux OOM killer 杀了

# 3. 看后端应用日志里的慢请求
grep "耗时\|elapsed\|duration" /var/log/你的服务/*.log | tail -50
# 大部分框架会把请求耗时打出来

# 4. 看数据库慢查询(如果用 MySQL)
SHOW FULL PROCESSLIST;     -- 看正在执行的 SQL
SHOW VARIABLES LIKE 'long_query_time';
-- 慢查询日志路径一般写在 my.cnf 里
```

### 5.3 看 Nginx 自己的 error log(辅助)

```bash
tail -f /var/log/nginx/error.log
```

**关键错误模式速查**:

| Nginx error log | 含义 | 故障域 |
|---|---|---|
| `connect() failed (111: Connection refused) while connecting to upstream` | 后端没启 / 端口没人 listen | **502** |
| `connect() failed (113: No route to host) while connecting to upstream` | 路由/安全组问题 | **502**(网络层) |
| `upstream prematurely closed connection while reading upstream` | 后端连上了又踢了 | **502** |
| `upstream timed out (110: Connection timed out) while reading upstream` | 后端没在超时内返回 | **504** |
| `no live upstreams while connecting to upstream` | upstream 块里所有后端都挂了 | **502** |
| `worker connections are not enough` | Nginx 连接打满了 | 调 `worker_connections` |

---

## 6. Nginx 配置速查(只在确认是 504 域后才动)

### 6.1 认识三个 timeout 参数

```nginx
location / {
    proxy_pass http://backend;

    # 三个 timeout,新手最容易搞混的就是它们
    proxy_connect_timeout 5s;   # Nginx → 后端的 TCP 连接阶段超时
                                # 502 通常在这里失败,但调大它对 502 没用!
    proxy_send_timeout    30s;  # Nginx → 后端「发送请求体」超时
    proxy_read_timeout    30s;  # Nginx 等「后端返回响应」超时 ← 504 通常在这里失败
}
```

**三句话记牢**:

- **`proxy_connect_timeout`**:Nginx 去敲后端的门,多久没人开门就放弃。**对 502 域来说,后端根本没人,调大没用**。
- **`proxy_send_timeout`**:Nginx 把请求发给后端,多久发不完就放弃。极少触发。
- **`proxy_read_timeout`**:Nginx 等后端回响应,多久没回就放弃。**504 主要靠调这个**。

### 6.2 反面教材 ❌(胡哥翻车配置)

```nginx
# 看到 502 错误率涨,下意识调成这样:
proxy_connect_timeout 60s;   # ❌ 对 502 无效,只会让失败更久才返回
proxy_send_timeout    60s;
proxy_read_timeout    60s;
```

### 6.3 正确做法 ✅

```nginx
# 默认值就够了,真有 504 再适度调大
proxy_connect_timeout 5s;    # 通常不用动
proxy_send_timeout    30s;
proxy_read_timeout    30s;   # 真有 504 时调这个,且别超过 60s

# 配合 upstream failover
upstream backend {
    server 10.0.0.5:8080 max_fails=3 fail_timeout=10s;
    server 10.0.0.6:8080 max_fails=3 fail_timeout=10s;   # 备用节点
    keepalive 32;
}

proxy_next_upstream error timeout http_502 http_504;
# ↑ 一个节点挂了,自动切下一个。但注意:http_502 也会触发 failover,
#   如果 502 是因为所有后端都没启,切来切去还是 502,这时要查后端
```

---

## 7. 速查清单:502/504 故障树

事故中没空读长文?直接对照这张表查:

### 7.1 看到 502,按顺序排查

```
502 Bad Gateway
├─ curl -v 后端报 "Connection refused"
│   ├─ ss -tlnp | grep 端口 → 没输出
│   │   ├─ systemctl status xxx → inactive(dead)
│   │   │   └─ journalctl -u xxx -n 50 → 看启动报错(配置错 / 依赖没起)
│   │   └─ 配置里 listen 127.0.0.1,改成 0.0.0.0
│   ├─ ss -tlnp 有,但云厂商安全组没放行 → 去控制台加规则
│   ├─ dmesg | grep "killed process" → OOM 了,查内存泄漏
│   └─ 容器/Pod 场景 → kubectl describe pod 看 Events
│       └─ Readiness probe 没配 / 探针失败
│
├─ curl -v 后端报 "Connection reset by peer"
│   ├─ tcpdump 抓包确认 RST
│   ├─ 云厂商安全组 / iptables 规则拦截
│   ├─ 后端 OOM 被 kill(看 dmesg)
│   └─ 后端主动拒连(配了限流 / 黑名单)
│
└─ curl -v 后端正常,但通过 Nginx 报 502
    ├─ 看 Nginx error.log 的具体错误
    ├─ upstream 块配错了(server IP / 端口错)
    └─ proxy_pass 路径少了 / 多 /
```

### 7.2 看到 504,按顺序排查

```
504 Gateway Timeout
├─ curl -v 后端也超时 → 后端真慢
│   ├─ top 看 CPU 哪个进程吃满
│   ├─ 数据库慢查询(MySQL: SHOW PROCESSLIST)
│   ├─ 第三方接口超时(查调用链)
│   └─ 线程池 / 连接池打满(看应用日志)
│
├─ curl -v 后端很快,但通过 Nginx 超时
│   ├─ Nginx 本身 CPU / 连接数打满
│   ├─ proxy_read_timeout 设太小(< 后端实际耗时)
│   └─ Nginx 和后端之间有别的链路瓶颈(看网卡流量)
│
└─ 所有后端都 504
    └─ 集群性问题:数据库主库挂了 / 共享依赖挂了
        (这种情况下调 Nginx 参数完全无效)
```

---

## 8. 出事故时的「不要做清单」(新人保护清单)

> [!CAUTION] 这些操作在没确认故障域前**绝对不要做**:

1. ❌ 看到 502/504 就改 `proxy_*_timeout` —— **90% 翻车原因**
2. ❌ 看到 504 就重启后端 —— 不解决根因,起来还是慢
3. ❌ 看到错误就 `systemctl restart` 整个链路 —— 故障面扩大
4. ❌ 看到 502 就加机器 / 加节点 —— 如果是配置错的 502,加机器没用
5. ❌ 在事故中改大超时然后忘记改回去 —— 上线后所有慢请求都会累积
6. ❌ 跳过抓包,凭直觉判断是「网络问题」—— 90% 不是网络问题
7. ❌ 不看后端 log 就怀疑 Nginx —— 多数时候问题在后端

**正确做法**:**先抓数据(curl / tcpdump / log),再下结论,最后改配置**。

---

## 9. 完整事故演练:照着走一遍(15 分钟)

假设你接到告警:支付接口 502 率 30%。

```bash
# === 步骤 1:确认故障域(30 秒) ===
# 在 Nginx 服务器上测后端(假设后端是 10.0.0.5:8080)
curl -v --max-time 5 http://10.0.0.5:8080/pay

# 看到 "Connection refused" → 502 域,继续步骤 2a
# 看到 "Operation timed out" → 504 域,跳到步骤 2b
# 看到正常返回 → 503 / 500 域,看后端 log

# === 步骤 2a:502 域 — 后端没启或被挡(2 分钟) ===
ssh 10.0.0.5
ps aux | grep pay       # 进程在不在
ss -tlnp | grep 8080    # 端口在不在 listen
systemctl status pay    # 服务状态
journalctl -u pay -n 50 # 启动日志
dmesg | grep "killed"   # OOM 痕迹

# === 步骤 2b:504 域 — 后端慢(2 分钟) ===
ssh 10.0.0.5
top -c                  # CPU 谁在吃
# MySQL 慢查询
mysql -e "SHOW FULL PROCESSLIST;"
# 应用慢请求日志
grep "elapsed\|duration" /var/log/pay/*.log | tail -20

# === 步骤 3:抓包取证(2 分钟) ===
# 在 Nginx 服务器上
tcpdump -i eth0 -nn -s 0 'host 10.0.0.5 and port 8080' -w /tmp/cap.pcap &
# 触发几个请求
for i in {1..5}; do curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://localhost/pay; done
# 停抓包
kill %1
# 下载 /tmp/cap.pcap 用 Wireshark 看

# === 步骤 4:定位后,再决定改不改配置 ===
# 确认是 504 域 + 确认后端慢是因为合理耗时 → 可以适度调大 proxy_read_timeout
# 确认是 502 域 → **不调超时**,改排查思路或修后端
```

---

## 10. 跟我们的关系

| 场景 | 用法 |
|---|---|
| **AI coding agent 的 on-call skill** | 把「三招 + 顺序 + 不要做清单」写成 SKILL.md,给 agent 在 502/504 时自动执行:先 curl -v 后端、再 tcpdump、看后端 log,最后才考虑改 Nginx |
| **生产事故复盘模板** | 跟 [performanceTriage.md](performanceTriage.md) 配合:先四维定位(快照 vs 趋势 / 用户态 vs 内核态),再用 502/504 域判定收敛到具体动作 |
| **新人 / 跨团队培训** | "慢就是快"、"工具越近误诊越深"是反复出现的运维心法 — 跟「幽灵空间」「cgroup OOM」同系列,可做整套运维翻车笔记归档 |
| **面试题 / 自测** | "502 和 504 的区别" 是高频面试题,这篇笔记能让你答到「故障域」层面,远超「一个是超时一个不是」 |

---

## 11. 常见误区 FAQ(新人最爱问的)

### Q1:「Connection refused」和「Connection reset by peer」有什么区别?

| | refused | reset |
|---|---|---|
| 含义 | **没人监听**(操作系统内核直接 RST) | **对方主动掐断**(发了 RST/FIN) |
| 常见原因 | 后端没启 / 端口错 / 安全组 | 防火墙拦截 / OOM / 上游限流 |
| 故障域 | **502** | **502**(但更可能是中途被杀) |
| 排查难度 | 容易(后端没起一眼看出来) | 难一点(得查为什么被踢) |

### Q2:为什么调大 `proxy_connect_timeout` 对 502 无效?

因为 `proxy_connect_timeout` 控制的是「Nginx 跟后端**建立 TCP 连接**」等多久。502 的根因是**后端没人 accept 连接**(操作系统直接 RST)。无论你等 5 秒还是 60 秒,后端都没人接,结果一样 —— 只是用户多等一会才看到 502。

### Q3:502 域调 `proxy_next_upstream http_502` 切下一个节点有用吗?

**有时候有用,有时候是掩盖问题**:

- ✅ **有用**:一个节点挂了,另一个活着 — 切过去就正常
- ❌ **掩盖问题**:所有后端都没启 / 都有同样问题 — 切来切去还是 502,只是错误日志变多

切之前先确认:其他节点是不是真正常(`curl -v` 测一下)。

### Q4:K8s 里 Pod 起来了但还是 502,常见原因?

- **Readiness probe 没配 / 失败**:流量打进去的时候 Pod 还没准备好(常见!)
- **Service 配错 targetPort**:Service 指向的端口跟容器实际 listen 的端口不一致
- **NetworkPolicy 拦截**:K8s NetworkPolicy 没放行网关 Namespace
- **CNI 问题**:某些 CNI 插件在节点刚启动时还没完全就绪

排查命令:`kubectl describe pod`,`kubectl get endpoints`,`kubectl logs`。

### Q5:看到 503 跟 502/504 啥关系?

503 是**后端主动说「我忙不过来了」**(通常配了限流),属于**后端能正常响应,只是业务上拒绝**。跟 502/504 是不同维度的问题,排查思路也不一样(看限流配置、看后端队列)。

---

## 12. 风险点 / 容易重蹈覆辙

1. **「想当然」陷阱**:老运维栽在自信,新运维栽在不懂 — 同样栽 5 小时
2. **工具近邻陷阱**:网关配置离得最近、改起来最快,但**往往不是源头**(运维领域普适规律,见 [performanceTriage.md](performanceTriage.md) 「工具越近,误诊越深」)
3. **FIN/RST 漏看**:抓包只盯 SYN,忽略 FIN/RST,误判为网络问题
4. **云厂商安全组默认值**:多数云厂商安全组拒绝时回 RST(表现为 502),不是丢包 — 排查时别只看 nginx 日志
5. **「调超时万能」迷信**:只在 504 域有效;502 域调超时等于扩大故障面(胡哥 5 小时教训)
6. **不抓包就下结论**:90% 的 5 小时翻车,根源都是「跳过了抓包这一步」

---

## 13. 适用性 / 范围

- **适用网关**:Nginx / OpenResty / Tengine(配置项 `proxy_*_timeout` 通用)
- **适用层**:L7 反向代理网关(本文不覆盖 L4 负载均衡器如 HAProxy / Envoy 的对应错误码)
- **协议**:HTTP/1.1 为主;HTTP/2 / gRPC 流式场景下 502/504 仍适用,但需额外看 GOAWAY 帧
- **不适用**:CDN 回源错误(看 CDN 控制台);浏览器前端跨域(那是 CORS,不是 502)

---

## 参考链接

- 原文: 胡哥Linux运维《网关报 502 别乱调超时,老兵翻车 5 小时才搞清 504 才是真超时》 https://mp.weixin.qq.com/s/GCX3RqfjT0EIumD1uDuCVw
- RFC 7231 §6.6.3 502 定义: <https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.3>
- RFC 7231 §6.6.5 504 定义: <https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.5>
- Nginx `proxy_*_timeout` 文档: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout>
- Nginx `proxy_next_upstream` 文档: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream>
- Wireshark 抓包过滤语法: <https://wiki.wireshark.org/DisplayFilters>
- 关联笔记: [performanceTriage.md](performanceTriage.md) · [opsTroubleshootingDiskGhost.md](opsTroubleshootingDiskGhost.md) · [opsTroubleshootingOOMCgroup.md](opsTroubleshootingOOMCgroup.md)