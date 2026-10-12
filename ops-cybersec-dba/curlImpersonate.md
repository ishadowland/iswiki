# curl-impersonate — 用浏览器指纹伪装 TLS/HTTP2 握手的 curl 补丁版

> 学习笔记 · 调研时间 2026-10-13
> 仓库: https://github.com/lwthiker/curl-impersonate · License: MIT · 语言: C
> ⭐ 7.1k · 版本 v0.6.1(2024-03 打包) · 最后提交 `822dbef`(2 年前)
> 实测平台: macOS 13.6 x86_64(Intel Macmini8,1) · 本机已安装并完成指纹对比
> **使用边界: 仅限授权测试 / 自有 WAF 规则验证,见 §八**

---

## 一句话定位

curl-impersonate 是**重新编译的 curl**,把 TLS ClientHello 和 HTTP/2 SETTINGS 改成和真实浏览器逐字节一致 —— 用来验证自家 WAF / 反爬规则是否真的在按 TLS 指纹拦截,而不是绕过第三方站点的封禁。

---

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| wrapper 脚本 | `curl_chrome116` / `curl_ff117` / `curl_safari15_5`(17 个) | 命令行直接替换 curl,**必须用 wrapper**,不能直接跑裸二进制 |
| libcurl-impersonate | `libcurl-impersonate.so` + `curl_easy_impersonate()` | 集成进自己的程序,替代 libcurl |
| LD_PRELOAD(仅 Linux) | `LD_PRELOAD=libcurl-impersonate.so CURL_IMPERSONATE=chrome116 my_app` | 已有程序用了 libcurl,不改代码 |

---

## 一、先纠正三个常见误解

调研前我以为它是「专门伪装 TLS 指纹绕过 Akamai/EdgeSuite 的工具」。实读源码后,实际情况更复杂:

**一,它是 TLS + HTTP/2 两层一起伪装,不是只改 TLS。**
只改 TLS 不改 HTTP/2 SETTINGS,JA3 + JA4 组合照样能识别。README 原文列的改动:`--ciphers` / `--curves` / `--signature-hashes` / `--cert-compression` / `--alps` / `--tls-permute-extensions` / `--http2-no-server-push` / `--http2-pseudo-headers-order`,外加**换掉整个 TLS 库**(Chrome/Edge/Safari 用 BoringSSL,Firefox 用 NSS)。

**二,指纹库冻结在 2023 年。**
最新目标版本是 Chrome 116 / Firefox 117 / Safari 15.5,而真实浏览器早已迭代多代。项目最后提交停在 2 年前。这是它当前最大的短板,§六 有量化说明。

**三,工具本身不知道目标站是谁。**
它不针对 Akamai、不针对 Cloudflare、不针对任何一家。Akamai 指纹只是它「像浏览器」之后的**副产品**,不是设计目标。

---

## 二、架构:两个二进制 + 17 个 wrapper

```
curl-impersonate-chrome   ← BoringSSL,服务 Chrome / Edge / Safari
curl-impersonate-ff       ← NSS,服务 Firefox

wrapper 脚本(17 个)← 真正的入口,负责把指纹参数喂给二进制
└── curl_chrome{99,100,101,104,107,110,116}
└── curl_chrome99_android
└── curl_edge{99,101}
└── curl_safari15_{3,5}
└── curl_ff{91esr,95,98,100,102,109,117}
```

**关键:直接跑 `curl-impersonate-chrome https://x` 是没有效果的。**
实测确认 —— 二进制本身默认指纹不等于浏览器,必须经 wrapper 脚本传 `--ciphers` / `-H` / `--alps` 等一整套参数。这是 docs/02_USAGE.md 里明确写的,也是最容易踩的坑。

### wrapper 脚本长什么样(实测 `curl_chrome116`)

```bash
"$dir/curl-impersonate-chrome" \
    --ciphers TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,... \
    -H 'sec-ch-ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"' \
    -H 'sec-ch-ua-mobile: ?0' \
    -H 'sec-ch-ua-platform: "Windows"' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/116.0.0.0 Safari/537.36' \
    -H 'Accept: text/html,application/xhtml+xml,...' \
    -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' ... \
    -H 'Accept-Encoding: gzip, deflate, br' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    --http2 --http2-no-server-push --compressed \
    --tlsv1.2 --alps --tls-permute-extensions \
    --cert-compression brotli \
    "$@"
```

**头部的顺序本身就是指纹的一部分**,docs 里明确警告:要改头就得改脚本,否则会出现重复头或顺序错乱。

---

## 三、实测:三个客户端的指纹对比(本机真实抓取)

同一台机器、同一网络,打 `https://tls.peet.ws/api/all` 取回服务端观测到的指纹:

| 客户端 | TLS 栈 | ja3_hash | ja4 |
|---|---|---|---|
| 系统 curl 8.1.2 | SecureTransport + LibreSSL | `2bab0327a296230f9f6427341e716ea0` | `t13d497h2_0d8feac7bc37_7395dae3b2f3` |
| `curl_chrome116` | **BoringSSL** | `7df085449f911b2ad11b9f2a47a1b24f` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| `curl_safari15_5` | **BoringSSL** | `773906b0efdefa24a7f2b8eb6985bf37` | `t13d2014h2_a09f3c656075_14788d8d241b` |

**三个指纹完全不同** —— 这正是工具存在的意义。

### TLS 扩展列表差异(实测抓取)

| | 系统 curl | curl_chrome116 |
|---|---|---|
| 扩展数量 | 7 | **17** |
| GREASE 填充 | ❌ 无 | ✅ 有(每次连接随机) |
| `compress_certificate` | ❌ 无 | ✅ brotli |
| `application_settings`(ALPS) | ❌ 无 | ✅ `h2` |
| `padding` | ❌ 无 | ✅ |
| `extended_master_secret` | ❌ 无 | ✅ |
| `psk_key_exchange_modes` | ❌ 无 | ✅ |
| ALPN | `h2,http/1.1` | `h2,http/1.1`(相同) |

### GREASE 随机化实测 —— JA4 为什么稳定

连续两次请求 `curl_chrome116`,对比 ClientHello 里的 GREASE 值:

| | GREASE 扩展 | key_share 的 GREASE | ja4 |
|---|---|---|---|
| 第 1 次 | `0x9a9a`, `0xaaaa` | `0x1a1a` | `t13d1516h2_8daaf...` |
| 第 2 次 | `0x9a9a`, `0xbaba` | `0x9a9a` | `t13d1516h2_8daaf...` |

**GREASE 值每次都变,ja4 完全不变。** 这正是 JA4 相对 JA3 的核心改进 —— 计算哈希前先把 GREASE 归一化,所以「像浏览器」不等于「每次指纹都一样」,反而是这种「随机但归一化后稳定」的模式才符合真实 Chrome 行为。

### HTTP 请求头差异(实测 `-v` 输出)

```
# curl_chrome116
> GET / HTTP/2
> sec-ch-ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
> sec-ch-ua-platform: "Windows"
> Upgrade-Insecure-Requests: 1
> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/116.0.0.0 Safari/537.36
> Sec-Fetch-Site: none / Sec-Fetch-Mode: navigate / Sec-Fetch-Dest: document
> Accept-Encoding: gzip, deflate, br

# 系统 curl
> GET / HTTP/2
> User-Agent: curl/8.1.2
> Accept: */*
```

---

## 四、怎么自己验证指纹对不对(重要,附一个我自己踩的坑)

项目自带**权威签名库**:`tests/signatures/{chrome,safari,edge,firefox}.yaml`,每个浏览器版本一段精确的 ClientHello 期望值。这比自己猜准得多。

### 我踩的坑

我最初把实测 extension **顺序**和 YAML 里 `chrome_116` 段的顺序逐位比对,结果**全盘不符**,差点当成「指纹不匹配」的重大发现写进笔记。

查 `tests/test_impersonate.py:589` 才发现,chrome116 的签名里声明了:

```yaml
signature:
  options:
    tls_permute_extensions: true
```

而比较函数:

```python
allow_tls_permutation = browser_signatures[expected_signature]["signature"] \
                        .get("options", {}).get("tls_permute_extensions", False)
equals, msg = sig.equals(expected_sig, allow_tls_permutation=allow_tls_permutation, reason=True)
```

**Chrome 110+ 会主动打乱 extension 顺序**,所以 YAML 里存的是「一种合法顺序」,实测顺序不同才是对的。

### 正确的验证方法

**第一步,查目标版本是否声明 permute:**

| 目标 | `tls_permute_extensions` |
|---|---|
| chrome99 | **false** |
| chrome110 | **true** |
| chrome116 | **true** |

**第二步,按声明选判据:**

- `permute = false` → 逐位比对顺序
- `permute = true` → 比对**集合**,不比顺序

**第三步,实测验证(两个对照都跑过):**

```
chrome116: 扩展集合是否相等(忽略顺序) → True    17/17 完全一致,无多无少
chrome99 : 顺序完全一致            → True    permute=false,逐位对得上
```

**结论:指纹完全正确,是我的比较方法错了。** 如果只测一个版本就下结论,50% 概率误判。

---

## 五、macOS 安装实测(踩到真实缺陷)

### 安装

官方有 macOS x86_64 预编译包(v0.6.1,3,015,633 字节,SHA256 `61bbd268...`),本机直接可用:

```bash
curl -LO https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-macos.tar.gz
tar xzf curl-impersonate-v0.6.1.x86_64-macos.tar.gz
```

**依赖(README 只说了 nss,实测还要另两个):**

```bash
brew install rtmpdump zlib nss
```

- `rtmpdump` 提供 `librtmp.1.dylib` —— 不装二进制直接 `dyld: Library not loaded` 崩掉
- `zlib` —— Safari 版 `--cert-compression zlib` 需要
- `nss` —— Firefox 版需要,macOS 上**从源码编译,88MB tarball,耗时 2 分 13 秒**(没有 bottle),这一步是整个安装里最慢的

### ⚠️ 真实缺陷:macOS 上 Firefox 版无法工作

装完 nss 3.131 后,`curl_ff117` **仍然完全不可用**:

```
* WARNING: failed to load NSS PEM library libnsspem.dylib.
  Using OpenSSL PEM certificates will not work.
*  CAfile: /private/etc/ssl/cert.pem
* Closing connection 0        ← TLS 握手直接断,http=000
```

**根因**:brew 的 `nss` 3.131 在 macOS 上**不构建 `libnsspem.dylib`**。实测 `find /usr/local/Cellar/nss -name "libnsspem*"` 零结果,`nss/lib/` 下只有 `libnss3/libssl3/libsmime3/libfreebl3/libsoftokn3/libnssckbi` 等,**没有 pem 模块**。这是 NSS 上游在 macOS 构建目标里的已知打包缺口。

**影响**:Chrome / Edge / Safari 三个系列在 macOS 上完全可用,**只有 Firefox 系列不可用**。README 里没提这个限制,踩坑时很容易以为是装错了。

**临时绕过**:没有。curl 走 NSS 就必须 PEM 解析证书,这个库缺失无解。

---

## 六、时效性风险:指纹停在 2023 年(量化)

| 维度 | curl-impersonate | 现实 |
|---|---|---|
| Chrome 目标版本 | **116**(2023-08) | 早已 130+ |
| Firefox 目标版本 | **117**(2023-08) | 早已 130+ |
| Safari 目标版本 | **15.5**(2022) | 早已 18+ |
| 最后提交 | 2 年前 | 主动维护中 |

**风险**:如果防护方(如 Akamai Bot Manager)把「Chrome 116 但请求头声称更高版本」或「116 这个 ja4 本身」加入黑名单,工具就从优势变成特征。而且新版 Chrome 持续在 ClientHello 上加扩展(ALPS、ML-DSA、Encrypted Client Hello),116 的指纹缺这些。

**结论:能用,但要知道自己在用一个 2023 年的浏览器画像。** 拿来验证自家 WAF 规则够用;要对抗生产环境的 Bot Management,需要先确认对方黑名单里有没有 116 这一档。

---

## 七、实战建议 / 风险点

| 坑 | 后果 | 对策 |
|---|---|---|
| 直接跑裸二进制 | 指纹完全不是浏览器,白装 | **必须用 wrapper 脚本** |
| 自定义 `-H` 头顺序 | 头部顺序本身就是指纹,乱改会露馅 | 要改就改 wrapper 脚本 |
| 加 `--ciphers` / `--curves` / `--tls-max` 等 | **直接改变 TLS 签名**,破坏伪装 | docs 明确列了这些「会改签名的 flag」,见下 |
| 拿裸顺序比 YAML | 误判(我踩过) | 先看 `tls_permute_extensions` |
| macOS 装 Firefox 版 | `libnsspem` 缺失,不可用 | macOS 上只用 Chrome/Edge/Safari |
| 期待它解 IP 层封禁 | 无效 | 它只管 TLS/HTTP2 层 |

**docs 明确列出的「会改变 TLS 签名」的 flag**(加了就会破坏伪装):

```
--ciphers  --curves  --no-npn  --no-alpn
--tls-max  --tls13-ciphers  --tlsv1.0  --tlsv1.1  --tlsv1.2  --tlsv1.3  --tlsv1
```

### 实测:它过不去什么

打 Cloudflare 行为检测站(nowsecure.nl):

| 客户端 | HTTP | 耗时 |
|---|---|---|
| `curl_chrome116` | 200 | 5.91s |
| `curl_safari15_5` | 200 | 3.57s |
| 系统 curl | 200 | 3.21s |
| `curl_ff117` | 000 | 0.009s | ← §五 的 nss 问题,非指纹问题 |

**三家都过了** —— 说明这个站点对纯 curl 客户端放行度高,区分不出指纹差异。这正好说明:**能不能过主要看防护策略,而不是工具**。

**它明确解决不了的**:IP 段信誉、JS 挑战(`bm_sz` cookie)、行为分析、账号风控。这些跟 TLS 指纹不在一个层面。

---

## 八、使用边界(必须先读)

**正当用途:**
- 验证自家 WAF / 反爬规则是否真的在按 TLS 指纹拦截(「我以为拦了,其实没拦」是极常见的误判)
- 抓取**自己拥有或已获书面授权**的站点
- 测试自己的 API 网关、反爬中间件
- 安全研究:研究 TLS 指纹识别原理

**禁止用途:**
- 绕过任何未经授权的第三方站点的访问控制
- 规避付费墙、速率限制、账号限制
- 违反目标站点服务条款或 robots 协议的自动化抓取

**法律提醒**:多数司法辖区(如中国《反不正当竞争法》、美国 CFAA)下,未授权绕过技术保护措施可能构成违法或违约。工具本身 MIT 合法,但**用它做什么是另一回事**。

判断标准很简单:**这个站是不是你的,或者你有没有书面授权。没有就别用。**

---

## 九、跟我们的关系

- **能直接用上的场景**:本仓 [wafKnowledgeBase](wafKnowledgeBase.md)(WAF 拦截行为分类)讲的是「攻击行为怎么分类」,这篇补的是**另一层** —— 「WAF 还能按连接层指纹分类」。两者结合才是完整的 WAF 认知:请求层(header/参数)+ 连接层(TLS/HTTP2 指纹)。
- **配对笔记**:[reverse-skill](../ai-vibecoding-agents/reverse-skill.md)(安全/逆向任务路由)、[blackBoxPentestPlaybook](blackBoxPentestPlaybook.md)(黑盒测试里「客户端指纹」这一维度目前是空白,可以补)。
- **本机现状**:已装在 `/tmp/ci/`(临时目录,重启会丢)。如果要做常规验证,建议移到 `~/.hermes/tools/curl-impersonate/` 并把 wrapper 加进 PATH。注意 `zlib` 是 keg-only 的,不影响运行但编译其他东西时需要 `export LDFLAGS=-L/usr/local/opt/zlib/lib`。
- **别做的事**:不要拿它去抓不属于自己的站点。

---

## 参考链接

- 仓库: https://github.com/lwthiker/curl-impersonate
- Releases(v0.6.1): https://github.com/lwthiker/curl-impersonate/releases/tag/v0.6.1
- 签名数据库(权威): https://github.com/lwthiker/curl-impersonate/tree/main/tests/signatures
- 测试逻辑(看 `tls_permute_extensions`): https://github.com/lwthiker/curl-impersonate/blob/main/tests/test_impersonate.py
- 命令行用法文档: https://github.com/lwthiker/curl-impersonate/blob/main/docs/02_USAGE.md
- 作者技术博客(原理,两篇): https://lwthiker.com/reversing/2022/02/17/curl-impersonate-firefox.html · https://lwthiker.com/reversing/2022/02/20/impersonating-chrome-too.html
- TLS 指纹原理: https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html
- HTTP/2 指纹原理: https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html
- JA4 规范: https://github.com/Foresight-Technologies/ja4
- 实测指纹服务: https://tls.peet.ws/api/all