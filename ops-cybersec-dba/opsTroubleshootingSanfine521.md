# 运维排错：Cloudflare 521 —— 「接受连接却不返回数据」的源站停机指纹

> 学习笔记 · 调研时间 2026-10-24（案例发生 2026-09-02 → 2026-10-22 闭环）
> 案例：sanfine.art（腾讯云 CVM + Cloudflare 代理，旧站 WordPress PHP 7.4）
> 配套：`~/Desktop/Sanfineart/ops/health_check.py`（巡检）· `ops/RUNBOOK.md`（完整手册）· `ops/PIN-GUIDE.md`

---

## 一句话定位

Cloudflare 521 只说明「边缘活着、源站死了」，真正的难点在于**源站已经代理（proxied）时，DNS 里看不到回源 IP**，排查会卡在「连谁去问」。本篇沉淀一套**四层定位法**，外加一个可复用的指纹判据：**源站「接受 TCP 连接但一个字节都不回」= 实例层面停机**，而不是某个服务进程挂了。

---

## 一、案例还原

### 现象

```bash
$ curl -sSI https://sanfine.art
HTTP/2 521
server: cloudflare
cf-ray: a4e554d97f93dd9e-HKG
```

站点从 2026-09-02 之后再没成功服务过（当时的抓取脚本还能正常跑完）。

### 证据链

| 层 | 命令 | 结果 | 判读 |
|---|---|---|---|
| DNS | `dig +short sanfine.art A` | `104.21.79.85` / `172.67.169.105` | 委派正常，**但这是 CF 的 IP，不是源站** |
| 边缘 | `curl https://sanfine.art` | 521 | CF 收到请求，**回源失败** |
| TLS | `openssl s_client` | 有效期至 2026-11-30，Google Trust Services | CF 在正常发证书，边缘无恙 |
| 源站 | `nc` 22/80/443 | **TCP 握手成功，零字节返回** | 源站在「接受连接但不服务」 |
| 源站 | `curl -H "Host: sanfine.art" http://<ip>/` | `Empty reply from server` | 同上 |
| 源站 | `ssh -vv` | `kex_exchange_identification: Connection closed` | **连 banner 都没发** |
| 对照 | `curl http://example.com` | 200 | 排除本地网络 / 代理误判 |
| 对照 | `curl http://1.1.1.1` | 301 | 排除「直连 IP 整体不通」 |

### 根因判定（⚠️ 初判已被后续推翻，见 §一·补）

两个候选源站 IP（`43.135.123.102` 生产机、`43.128.51.242` 历史机）、三个端口（22/80/443）**全部是「握手成功 + 零字节返回」**。

这个组合排除了「某个服务进程崩了」——那会得到 `Connection refused`。
它指向**整个实例层面不可用**，初判两种成因：

1. **腾讯云 CVM 实例已停机**（欠费 / 到期 / 手动关机 / 欠费隔离）
2. **高防实例到期转黑洞** —— 腾讯云高防是 SYN 代理，源站真机挂了但代理 IP
   仍然完成握手，后端无响应时表现就是「握手成功 + 空回复」

### 🔺 补：最终真实根因（2026-10-22 闭环时确认）

初判第 2 条**被证伪**。最终确认是：

> **实例内部系统损坏，必须重装** —— 不是高防到期，也不是欠费停机。

2026-10-22 实例被重装为 Debian 13.2 64bit（`ins-6dhol1uw`，内网 10.0.8.14，1 vCPU / 967MB / 25GB），SSH 端口改为 65022，装 nginx 部署占位页，13:00 起 `https://sanfine.art` 返回 200。

**这个修正对方法论的意义**：初判时「高防到期」和「实例停机」两个假设**在网络层完全无法区分**——两者都产生一模一样的「握手成功 + 零字节」指纹。区分它们**必须拿到云厂商控制台**（看实例状态 / 高防实例到期时间），光靠客户端探测到不了底。

> 💡 **可迁移的教训**：症状收敛到网络层指纹时，往往有多个成因共享同一指纹。**指纹能告诉你「故障域在哪一层」，不能告诉你「具体哪个组件坏了」**。别在客户端探测上无限加码，找到指纹后就该上控制台。

---

## 二、四层定位法

遇到「CDN 后面的站挂了」，固定按四层问，别跳步：

```
① DNS    委派还在吗？记录指向谁？（注意：代理后的 A 记录指向的是 CDN，不是源站）
   ↓     判据：NS 正常 = 域名没过期
② 边缘    CDN 自己活着吗？
   ↓     判据：能拿到 HTTP 响应头（含 cf-ray）+ 证书有效 = CDN 侧健康
         521/522/523/524 的区别：
           521 = 源站拒绝/无法建立连接（源站挂了）
           522 = 连接超时（源站无响应或被墙）
           523 = 源站不可达（路由/防火墙丢包）
           524 = 连接建立但超时（源站慢/超大响应）
③ 源站    回源 IP 直连什么反应？
   ↓     判据：Connection refused = 进程挂了（能自愈）
         握手成功 + 零字节 = 实例层面停机（本篇指纹）
         404/502 = 服务活着但路由/应用有问题
④ 应用    服务本身起来了吗？
         判据：systemctl status / df -h / ss -lntp
```

**第 ③ 步的坑**：代理后的 DNS 查不到回源 IP。线索来源：
- `~/.ssh/config` 里的 `Host` 别名（**本案真实生产 IP 就是从这儿翻出来的**）
- 源站侧安全组规则
- CDN 控制台的回源配置
- 历史规划文档里的旧 IP

### 主动探测与「连上就活着」的陷阱

用「能不能连上」判断服务器生死的脚本，在有高防/SYN 代理的机器上会得到**错误的「活着」结论**。

**必须读一次应用层数据才算数**：

```bash
# 握手成功但空回复 = 实例层停机
nc -zv 43.135.123.102 443 && curl -sS -m 5 http://43.135.123.102/ ; echo "exit=$?"
```

⚠️ 反过来也成立：**直连源站时回程也可能被丢** —— curl 报 `000` 但请求其实到了（nginx 日志里有 200）。所以判断源站是否正常，**以 nginx 日志为准**，不要只信本机 curl 的返回码：

```bash
bash ops/ssh_direct.sh 'tail -20 /var/log/nginx/access.log'
```

---

## 三、别忘了：站挂了，内容还在吗

排障的人容易一头扎进「把服务拉起来」，忘了问一句**「万一拉不起来呢」**。

站点类事故的第一顺位不是修服务，是**确认内容副本**：

```bash
# 备份分卷完整性（多段 zip 要逐段验）
unzip -t backup/*.part001.zip

# SQL 导出首尾完整性：头要有 CREATE TABLE，尾要有 UNLOCK TABLES
head -c 4096 db/*_backup_db.sql | grep -q "CREATE TABLE" && echo "头 OK"
tail -c 2048 db/*_backup_db.sql | grep -q "UNLOCK TABLES" && echo "尾 OK"

# 内容基线 DB 完整性 + 行数漂移
sqlite3 sanfine.db "PRAGMA integrity_check; select count(*) from post;"
```

**行数漂移检测**值得单独强调：把抓取当时的行数记成基线
（`post 18 / page 8 / artwork 50 / media 245`），每次巡检对一遍。对不上就说明站点在抓取后发生过变更，**迁移清单要重算**。
这比「备份文件还在」这种只验文件存在的检查有用得多。

---

## 四、把排查固化成脚本

一次性排查靠手，站点要长期管就必须**固化成可重复执行的检查**。

巡检脚本 `ops/health_check.py` 的设计要点：

| 要点 | 做法 |
|---|---|
| 分层输出 | DNS / 边缘 / 源站 / 资产四段，段落化排版 |
| 严重度分级 | CRIT / WARN / OK 三级，WARN 附「下一步怎么办」 |
| 退出码可编程 | 0 = 通过，1 = 有 CRIT，可直接挂 cron / CI 告警 |
| 机器可读 | `--json` 输出结构化结果 |
| 深检可选 | `--deep` 才做读 300MB+ 的 zip 完整性校验，日常不拖慢 |
| 离线可用 | `--no-network` 只查本地资产，飞机上也能用 |
| 离线资产也要能自动发现路径 | 走 `config.json` 声明的项目路径与源站列表 |
| **绕代理直连** | `--direct` 临时切 OpenClash 到 `GLOBAL=DIRECT` 再测（`trap` 自动还原） |

**踩坑：python.org 版 macOS Python 自带的 OpenSSL 目录是空的**，
`ssl.get_default_verify_paths()` 返回 `cafile=None`，
于是所有 HTTPS 校验一律失败（`unable to get local issuer certificate`），
而 curl 用 `/etc/ssl/cert.pem` 一切正常。

排查这类「curl 能连、Python 连不上」的经典差异：

```bash
python3 -c "import ssl; print(ssl.get_default_verify_paths())"
# DefaultVerifyPaths(cafile=None, capath=None, ...)   ← 空的就是它
```

**解法**：默认路径为空时回落到系统证书库；
`/etc/ssl/cert.pem` → `/etc/ssl/certs/ca-certificates.crt` →
`/etc/pki/tls/certs/ca-bundle.crt` 依次试。
同时把「TLS 信任链问题」单独报一条，**别让它把 HTTP 状态码这个关键信号一起吃掉**。

### 巡检要在好的时候建

站点正常时写脚本、验证基线，站点挂了才现写脚本，等于在火场里搭积木。

---

## 五、跟我们的关系

- ** sanfine.art 是我们自己的生产站**，本篇的每个命令都对着它实跑过 —— 不是通用文档搬运。
- **`ops/health_check.py` 可直接复用为其他自建站的巡检基线**：四层结构 + 严重度分级 + `--json` + `--direct` 是通用骨架，换 `config.json` 里的源站列表就能套到别的站。
- **「内容基线 + 行数漂移」这套检查方式**可以搬到 `~/Desktop/cilixiong/` 的爬虫库：那边也是「站上抓数据 → 本地 SQLite」，同理该记基线行数（`items 4646 / details 116`）并在每次重爬后比对漂移，而不是只看「文件还在」。
- **`~/.ssh/config` 作为回源 IP 的第一手线索源**这个习惯，对任何托管在云上的自建服务都适用。
- **巡检基线的三个要素**（分层 / 严重度 / 可编程退出码）跟我们已有的 Hermes cron watchdog 是同一套思路，可以互相参照。

---

## 六、实战建议 / 风险点

- **云厂商的 SYN 代理会骗过你的 `connect()`**。凡是用「能不能连上」判断服务器生死的脚本，在有高防的机器上都会得到错误的「活着」结论。必须读一次应用层数据才算数。
- **代理后的 DNS 隐藏了回源 IP**，这是 CDN 架构的固有代价。排查前先从「谁配置的回源」入手：源站侧安全组规则、CDN 控制台、或历史规划文档里的旧 IP。
- **别在客户端探测上无限加码**。指纹能定位故障域，不能定位具体坏掉的组件 —— 多个成因共享同一指纹是常态。
- **本机流量被 OpenClash 代理时，源站公网 IP 的境外流量会被腾讯云 SYN 代理丢弃**（同样是「握手成功 + 零字节」）。不加 `--direct` 会误报源站已挂。**同样的坑适用于传文件**（`ops/deploy_direct.sh` 就是干这个的）。
- **内容基线要在站点正常时建立**。站点挂了才想「内容还在吗」，多半已经晚了。

---

## 参考链接

- 完整手册：`~/Desktop/Sanfineart/ops/RUNBOOK.md`（资产盘点 / 恢复步骤 / 还原 SOP / 待办清单）
- 巡检脚本：`~/Desktop/Sanfineart/ops/health_check.py`
- 上线记录：`~/Desktop/Sanfineart/_planning/12-go-live.md`
- 姊妹篇：[opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md)（cgroup 账本思维）
- 姊妹篇：[opsTroubleshootingOOMSILogless](opsTroubleshootingOOMSILogless.md)（三本账排查法）
- Cloudflare 521 官方文档: https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-521/
- Cloudflare 5xx 错误码总览（521/522/523/524 判读）: https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/
- 腾讯云 CVM 文档：https://cloud.tencent.com/document/product/213
