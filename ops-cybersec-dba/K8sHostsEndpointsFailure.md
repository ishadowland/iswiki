# K8s 控制面全绿、业务全挂 —— 故障藏在 /etc/hosts 里

> 学习笔记 · 调研时间 2026-10-25
> 调研来源: 微信公众号「胡哥Linux运维」，作者胡登治（RHCA，15 年 Linux 运维），2026-10-02 发布
> 原文: https://mp.weixin.qq.com/s/JYEreZfkJExzbVbeODiAHw
> 定位: **K8s 小白向** —— 提取原文事故链路 + 补齐原文没讲的基本概念（Pod/Service/Endpoints/EndpointSlice/控制器/静态 Pod/kube-proxy/DNS 全景）
> 一手核验: cloud-init 官方模块文档与源码、canonical/cloud-init 仓库、hosts.debian.tmpl 模板、cloud-init `cc_update_etc_hosts.py` 源码、Kubernetes 官方文档（Service / EndpointSlice / Static Pod / 弃用指南 / node-metrics）、metrics-server 仓库、labring/sealos 源码
> ⚠️ 本篇**纠正了原文 7 处技术偏差**，逐条列在 §九

---

## 一句话定位

**K8s 最吓人的故障不是组件 Crash，而是「都在跑，但都不干活」** —— 节点集体重启后 `/etc/hosts` 被 cloud-init 重写，节点名解析不到，`kube-controller-manager` 的 Endpoints 控制器状态卡死，Service 背后挂着一份「昨天的 Pod IP 清单」，于是控制面全绿、业务全挂。

---

## 〇、给 K8s 小白的基础概念补课（原文默认你已知，这里补齐）

> 原文面向 1-5 年运维，直接跳到了 Endpoints 和控制器。**如果你刚接触 K8s，请先读这一节再读事故部分**，否则第三节的每一步都会变成"听天书"。

### 0.1 一张图看懂 K8s 的"谁给谁干活"

```
                        ┌──────────────────────────────┐
                        │      控制面 Control Plane      │
                        │  ┌────────────────────────┐  │
   你敲 kubectl ────────▶│  │ kube-apiserver         │  │  ← 所有组件的唯一入口
                        │  │ (唯一有状态的 HTTP 服务) │  │
                        │  ├────────────────────────┤  │
                        │  │ kube-controller-manager│  │  ← 「控制循环」大脑
                        │  │ kube-scheduler         │  │  ← 「该把 Pod 放哪」调度器
                        │  │ etcd                   │  │  ← 唯一真正的数据存储
                        │  └────────────────────────┘  │
                        └───────────┬──────────────────┘
                                    │ ① 声明 / 查询
                                    │ ② watch（长连接看变化）
                                    ▼
        ┌───────────────────────────────────────────────────────┐
        │                    工作节点 Node                       │
        │  ┌─────────────────────────────────────────────────┐  │
        │  │ kubelet                                        │  │  ← 节点管家
        │  │  · 读 manifests 目录 → 拉起静态 Pod              │  │
        │  │  · 跟 apiserver 汇报本节点 Pod 状态              │  │
        │  │  · 监控容器健康 → 重启/重建                     │  │
        │  ├─────────────────────────────────────────────────┤  │
        │  │ kube-proxy                                     │  │  ← 流量搬运工
        │  │  · 读 Service/EndpointSlice → 写 iptables/ipvs   │  │
        │  │  · 把 ClusterIP 转发到真实 Pod IP                │  │
        │  ├─────────────────────────────────────────────────┤  │
        │  │ Pod  nginx-7d9f-x2k1  (IP: 10.0.2.238)         │  │
        │  │ Pod  nginx-7d9f-p8m3  (IP: 10.0.2.199)         │  │
        │  └─────────────────────────────────────────────────┘  │
        └───────────────────────────────────────────────────────┘
```

### 0.2 核心名词速查表

| 名词 | 一句话 | 小白理解 |
|---|---|---|
| **Pod** | 最小调度单位，里面跑 1+ 容器 | 「一个应用的运行实例」 |
| **Pod IP** | Pod 的虚拟 IP，**会变**（Pod 重建就换） | 「临时工牌，重来一次就换号」 |
| **Node / 节点** | 一台物理机或虚拟机 | 「工位」 |
| **Control Plane / 控制面** | 集群的大脑：apiserver + controller-manager + scheduler + etcd | 「管理层」 |
| **etcd** | 集群唯一真实存储（所有对象都存这） | 「档案室」 |
| **apiserver** | 所有组件唯一入口，REST API | 「总前台」 |
| **controller-manager** | 一堆「控制循环」的集合 | 「制度 + 巡逻队」 |
| **scheduler** | 决定新 Pod 放哪个节点 | 「排班员」 |
| **kubelet** | 节点上的管家，管容器生命周期 | 「车间主任」 |
| **kube-proxy** | 节点上的网络代理，把 Service VIP 转 Pod IP | 「门口的引导员」 |
| **Service** | 一个**稳定的名字 + 稳定 IP（ClusterIP）**，背后挂多个 Pod | 「总机号码，不随员工流动变化」 |
| **Selector** | Service 用来「认领」Pod 的标签规则 | 「按工牌认人」 |
| **Endpoints / EndpointSlice** | Service 背后**真实 Pod IP 的清单** | 「花名册」 |
| **kubelet 的 manifests 目录** | 放 YAML 的目录，kubelet 会照着起 Pod | 「值班表」 |
| **静态 Pod (static Pod)** | 不由 controller 创建、只由 kubelet 直接管的 Pod | 「领导直接派的工，不由制度生」 |

### 0.3 Service 到底怎么把流量送到 Pod 的（**理解第三节的关键**）

```
客户端
  │  curl http://my-service.default.svc.cluster.local:80
  ▼
DNS（CoreDNS）解析出 ClusterIP，例如 10.96.0.10
  │
  ▼
kube-proxy（跑在每个节点上）提前把规则写进内核：
  「凡目标是 10.96.0.10:80 的包 → 转发到 10.0.2.238:80 / 10.0.2.199:80」
  │
  ▼
Pod 收到请求
```

**关键点（原文没强调，但至关重要）：**

> **kube-proxy 的转发规则来自 EndpointSlice/Endpoints 清单。清单里写的是 Pod IP，而且是「过去某一刻」的 Pod IP。**
> 如果 Pod 换了 IP 而清单没更新，kube-proxy 规则就还指着旧 IP → 流量进黑洞。
> **这就是「假活」的本质：进程活着，活没干。**

### 0.4 Controller / 控制循环是什么（原文第二节的关键概念）

```
    ┌────────────┐  想让「最终状态 = 期望状态」
    │ 期望状态    │  例如：Service nginx 要有 3 个健康 Pod
    └─────┬──────┘
          │  compare
          ▼
    ┌────────────┐  不断 watch 实际状态，差异就动手修正
    │ 控制循环    │  reconcile loop
    └─────┬──────┘
          │
          ▼
    实际状态 → 写回 apiserver → 下一轮再 compare
```

K8s 里的控制器都是这个模式。**本文涉及的 `endpoints controller`（在 kube-controller-manager 里）干的事是：**

> watch Service 和 Pod → 把「匹配 Service selector 且健康就绪」的 Pod IP 写进 Service 的 Endpoints / EndpointSlice 对象。

**所以：** 如果 controller-manager 自己状态卡死（比如 watch 断了没恢复），它就「看不见」Pod 变化 → 花名册不更新 → Service 指向死 Pod。原文第二节说的就是这个。

---

## 一、案例还原：现象与背景

| 项 | 值 |
|---|---|
| 环境 | Ubuntu 24.04 |
| 部署工具 | sealos（一个 K8s 发行版 / 生命周期管理工具） |
| 拓扑 | 1 Master + 3 Node，**单节点 etcd** |
| 触发 | 国庆节当天，客户说「4 台机器昨晚好像自己重启了」 |
| 现象 | Pod 都是 Running，Pod IP 能 ping 通，但 **Service 完全访问不了** |

面板看起来一片祥和：

```
Node：Ready ✅
etcd：healthy ✅
apiserver / CoreDNS / kube-proxy：全部 Running ✅
```

**控制面一片祥和，业务面哀鸿遍野。**

---

## 二、根因链：节点「集体失忆」

### 2.1 现场证据

打开 `/etc/hosts`，当初手敲的和 sealos 添加的**五条节点解析全没了**，只剩：

```
# 现在只剩这个
127.0.1.1 k8s-master-1
127.0.1.1 localhost

# 我当初写的和sealos添加的一面五条全都不见了
10.16.240.12 k8s-master-1
10.16.240.13 k8s-node-01
10.16.240.14 k8s-node-02
10.16.240.15 k8s-node-03
10.16.240.12 apiserver.cluster.local
```

### 2.2 元凶：cloud-init 的 `update_etc_hosts` 模块

**cloud-init 是什么？** 一句话：服务器开机时自动跑一遍的初始化工具，主机名、网络、hosts 它都能管。云厂商装机靠它省了很多事，但在非云环境的物理机/虚拟机上，它有时是个「热心过头」的管家。

原文的关键推理链：

1. `grep -r manage_etc_hosts /etc/cloud/` → **是空的**（没显式配置）
2. 但 `update_etc_hosts` 模块 `frequency: always`（每次开机都执行）
3. 只要 `manage_etc_hosts` 被设为 `true` 或 `template` → 每次开机都按模板重写 hosts
4. 模板在 `/etc/cloud/templates/hosts.debian.tmpl`

### 2.3 「签名」识别法（原文最精彩的一处）

那行 `127.0.1.1 k8s-master-1` 正是 Debian 系 hosts 模板（`hosts.debian.tmpl`）的**签名**。看到它，就知道 hosts 是被模板重写的，不是手滑的。

**一手核验（本次亲自拉取 canonical/cloud-init 仓库 `templates/hosts.debian.tmpl` 原文）：**

```jinja
{# The value '{{hostname}}' will be replaced with the local-hostname -#}
127.0.1.1 {{fqdn}} {{hostname}}
127.0.1.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

✅ **原文的「签名」判断成立。** 这段模板正是 Debian 系的默认 hosts 内容，`127.0.1.1 <fqdn> <hostname>` 是它的第一行。

### 2.4 查日志确认

```bash
grep -i "etc/hosts" /var/log/cloud-init.log
```

### 2.5 原文点破的三个「新手想当然」

1. 以为 hosts 写一次就能管一辈子
2. 以为 K8s 通信用 IP 就不需要 hosts
3. 以为节点重启顶多触发 etcd 重新选主，不会「改名换姓」

> **第 2 条要展开说（原文没说透）：** 集群内部组件间通信**确实大量走 IP**（apiserver 用 Service VIP + CA 证书做双向 TLS，节点身份靠证书而不是 hosts）。但**节点名 → IP 的解析**在很多场景下是必需的：kubelet 上报、`kubectl logs`、CoreDNS 的节点域名、kubeadm 生成的证书 SAN、以及 `apiserver.cluster.local` 这类固定域名。**hosts 被清空不会让 apiserver 立刻挂，但会让「名字解析」这条路径彻底断掉** —— 后面 §四 的 metrics 报错正是这条路径。

---

## 三、Service 没坏，是「花名册」指向了死掉的 Pod

### 3.1 现场证据

```bash
kubectl get endpoints nginx-service
# 输出：10.0.2.15:80      ← 昨天就死掉的旧 IP

kubectl get pod -o wide
# 输出：10.0.2.238   k8s-node-02   Running   ← 实际在跑的 Pod
```

**Endpoints 就是 Service 背后真实的 Pod IP 清单**，流量最终是按它转发的。清单上写着一个昨天就死掉的旧 IP，新 Pod 的 IP 根本没登记上去 —— **Service 还指着「昨天」在干活。**

### 3.2 三个常见错误动作（原文列出，都不管用）

1. 狂重启业务 Pod
2. 删了 Service 重建
3. 怀疑 kube-proxy，疯狂 restart

### 3.3 真正的机理（原文这一段是全文技术含量最高的地方）

> 真正「没醒过来」的是 **kube-controller-manager 里的 Endpoints 控制器**。
>
> 控制器本身是**无状态**的，状态全在 apiserver 里。但 4 台节点集体重启后，它跟 apiserver 的 **watch 通道**（监听 Pod 变化的长连接）要重建、全量状态要重新同步 —— 在这个空窗期甚至卡住的状态下，Pod 已经换了 IP，它却「看不见」，Endpoints 自然停在旧值。

**把这段翻译成 §0.4 的控制循环语言：**

```
期望状态：Service nginx 的后端应该是「当前健康的 Pod」
实际状态：apiserver 里的 Endpoints = 10.0.2.15（昨天的死 Pod）
控制器状态：卡住了，watch 断了没恢复 → 根本没触发 reconcile
结果：差异永远不会被修正 → 花名册永远停在昨天
```

**核心洞察（值得单独记住）：**

> **控制面组件「Running」只代表进程活着，不代表它「在做对的事」。**
> 控制器是一个 reconcile 循环；如果它卡在某个状态（watch 断了、informer 没 resync），进程可以完全健康，但循环永远不转 —— 这就是「假活」（liveness ≠ readiness ≠ correctness）。

### 3.4 ⚠️ 一手核验纠正：Endpoints 已经过时了，真实数据源是 EndpointSlice

**原文在这里有一个重要的时代性偏差**（详见 §九 偏差 #4）：

| API | 状态 | 说明 |
|---|---|---|
| `v1.Endpoints` | **自 Kubernetes v1.33 起已弃用** | 官方文档原文：「Endpoints (deprecated) Feature state: Deprecated since Kubernetes v1.33」 |
| `discovery.k8s.io/v1.EndpointSlice` | **v1.21 起 Stable** | kube-proxy 转发规则的**真实数据源** |

一手核验的 Kubernetes 官方 Service 文档原文：

> The deprecated Endpoints API has several problems relative to EndpointSlice: It does not support dual-stack clusters. It does not contain information needed to support newer features, such as `trafficDistribution`. It will truncate the list of endpoints if it is too long to fit in a single object. Because of this, it is recommended that all clients use the EndpointSlice API rather than Endpoints.

**并且，官方明确说明：控制面会把用户创建的 Endpoints 资源「镜像」成对应的 EndpointSlice。**

> The control plane mirrors most user-created Endpoints resources to corresponding EndpointSlices. (However, this feature... is deprecated.)

**所以对今天（2026 年）的小白来说，更准确的心智模型是：**

```
Service (selector: app=nginx)
    │
    │  endpoint slice controller（kube-controller-manager 内）
    ▼
EndpointSlice  ← kube-proxy 真正的数据源（v1.21+ Stable）
    │
    │  （控制面自动镜像，旧集群仍保留 Endpoints 作为兼容视图）
    ▼
Endpoints    ← v1.33 已弃用，你仍能在 kubectl get endpoints 看到它
```

**这不改变原文的排查逻辑**（Endpoints 看到的现象和 EndpointSlice 是同一份健康状态的两种视图），但**排查时应该同时看 EndpointSlice**：

```bash
# 新集群（v1.21+）应该主要看这个
kubectl get endpointslice -l kubernetes.io/service-name=nginx-service

# 展开看某个 slice 里的 endpoint 状态
kubectl get endpointslice nginx-service-xxxxx -o yaml
```

> **EndpointSlice 的三个 condition 值得记（官方文档）：**
> - `serving`（v1.26 Stable）：endpoint 正在正常服务，**这个才应该被转发流量**
> - `terminating`（v1.26 Stable）：正在终止。Service 代理通常会忽略它，**但如果所有 endpoint 都在 terminating，仍会转发过去**（避免滚动更新期间丢流量）
> - `ready`：本质是「serving 且非 terminating」的快捷判断

---

## 四、别修业务，先救控制面

### 4.1 恢复动作（原文的操作）

```bash
cd /etc/kubernetes/manifests
mv kube-apiserver.yaml /tmp
mv kube-controller-manager.yaml /tmp
mv kube-scheduler.yaml /tmp
sleep 30
mv /tmp/*.yaml .
```

**原理一句话：** manifests 目录下的 yaml 移走，kubelet 会自动停掉对应组件；移回来，自动拉起。等于让控制面「重启一遍但不丢数据」。

> ⚠️ 这就是 §0.1 图里说的**静态 Pod 机制**。官方文档对静态 Pod 的定义（kubernetes.io/docs/tasks/administer-cluster/static-pod/）：
> > Use the `staticPodPath: <the directory>` field in the kubelet configuration file, which periodically scans the directory and creates/deletes static Pods as YAML/JSON files appear/disappear there.
>
> **kubelet 定期扫描该目录，文件出现就创建 Pod，文件消失就删除 Pod。** 所以「移走文件 = 停组件，移回文件 = 拉起组件」。

### 4.2 验证

```bash
# 等 1 分钟
kubectl get endpoints nginx-service
# 10.0.2.238:80 ✅
```

### 4.3 ⚠️ 一手核验纠正：静态 Pod 目录有个官方明确警告的坑

**官方文档原文警告（本次一手抓取）：**

> Caution: The kubelet processes **all files not starting with a dot** in the static Pod directory — **there is no filtering by file extension**. For example, if you create a backup of a manifest by running `cp kube-apiserver.yaml kube-apiserver.yaml.backup`, the kubelet will read both files and attempt to create a static Pod from each. When two files define a Pod with the same name, the resulting behavior is **undefined** and can cause the backup's outdated spec to **silently take effect** instead of the current manifest. If you do create a backup, store it outside the static Pod directory (for example, `/etc/kubernetes/backup/`).

**翻译：**

> ⚠️ **`mv` 到 `/tmp` 是对的，但绝对不要在 manifests 目录里 `cp xxx.yaml xxx.yaml.bak`。**
> kubelet 不按扩展名过滤，会把 `.backup` 也当成一份 Pod 定义，两个同名 Pod 冲突时行为 **undefined** —— 轻则新版 manifest 被旧备份静默顶替，重则整个控制面起不来。
> 备份请放 `/etc/kubernetes/backup/`。

### 4.4 官方文档还提了一条「静态 Pod 的镜像 Pod」常识

> You can see the mirror Pod on the API server: `kubectl get pods` → `static-web-my-node1`
>
> If you try to `kubectl delete pod static-web-my-node1`, the kubelet doesn't remove the static Pod: the Pod is still running.

**小白要点：** `kubectl get pods` 里那三个带 `static-web-my-node1-` 后缀的 Pod 是**镜像 Pod（mirror pod）**，真正的本体在节点本地 manifests 目录里。**你 `kubectl delete` 删不掉它**，删了 kubelet 会立刻重建。控制面三件套的 Pod 名都带 `-master-1` 后缀就是这个原因。

---

## 五、别被日志带偏：metrics.k8s.io 只是「喊疼的」

### 5.1 唬人的日志

```
Get "https://10.0.3.185:10250/apis/metrics.k8s.io/v1beta1:":
context deadline exceeded
```

### 5.2 原文的判断（方向对，但因果链讲反了）

> 新手看到这就去修 metrics-server 了。**错。**
> 10250 是 kubelet 的端口。apiserver 连不上 kubelet，说明节点级控制通道有问题 —— 根子还是那条：hosts 被清，控制面组件之间「认识但握不住手」。
> metrics-server 只是第一个喊疼的，不是病根。

### 5.3 ⚠️ 一手核验纠正：这行日志的**方向**恰好是反的

原文说「apiserver 连不上 kubelet」，但这条 URL 的方向恰恰相反：

```
Get "https://10.0.3.185:10250/apis/metrics.k8s.io/v1beta1:"
  └─ 谁在 Get？→ apiserver
  └─ 去 Get 谁的 10250？→ 10.0.3.185（某个节点）的 kubelet
```

**但是 —— 关键在这里 —— `metrics.k8s.io/v1beta1` 这个 API 路径根本不是 kubelet 提供的。**

一手核验两处官方来源：

**① kubelet 自己的路由表**（kubernetes/kubernetes `pkg/kubelet/server/server.go`，master 分支实测抓取）：

```go
metricsPath         = "/metrics"
cadvisorMetricsPath = "/metrics/cadvisor"
resourceMetricsPath = "/metrics/resource"
proberMetricsPath   = "/metrics/probes"
statsPath           = "/stats/"
```

**kubelet 只提供 `/metrics/resource`（和 `/stats/summary` 等），不提供 `/apis/metrics.k8s.io/v1beta1`。**

**② metrics-server 官方仓库 README 原文：**

> Metrics Server to Kubelet on all nodes. Metrics server needs to reach node address and Kubelet port. Addresses and ports are configured in Kubelet and published as part of Node object... port in `.status.daemonEndpoints.kubeletEndpoint.port` field (default 10250).

> Metrics Server to Kubelet on all nodes. **Metrics Server will pick first node address** based on the list provided by `kubelet-preferred-address-types` command line flag (default `InternalIP,ExternalIP,Hostname` in manifests).

**所以真实故障链应该是：**

```
❌ 原文说的：apiserver → kubelet:10250 连不上
✅ 实际是：  metrics-server → kubelet:10250 连不上
             （metrics-server 自己拿不到节点数据，
               因为 kubelet-preferred-address-types 里含 Hostname，
               而 Hostname 的解析依赖 /etc/hosts —— 被清空了！）
```

**这反而让原文「hosts 被清 → 节点级控制通道有问题」的结论更精确了：**

> **`kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname` 是 metrics-server 官方 manifest 的默认值。**
> 当 Hostname 需要 DNS 解析而 `/etc/hosts` 被清空、集群 DNS 又依赖 CoreDNS（CoreDNS 也依赖集群网络）时，metrics-server 就会解析不出节点地址 → `context deadline exceeded`。
>
> **metrics-server 依然是"喊疼的"，但喊疼的原因链条和原文描述的不同：它不是 apiserver 撞上了 kubelet，而是 metrics-server 自己因为解析节点名失败而拿不到数据。**

**教训（比原文更有价值）：**

> **读错误日志时，先确认「谁在发起这个请求」「这个 URL 是谁提供的」。**
> 很多运维看到 `apiserver → kubelet` 就去查 apiserver，实际发起方是 metrics-server。
> 而且 **`context deadline exceeded` 是「超时」不是「拒绝」** —— 超时往往意味着 DNS 解析卡住或网络黑洞，而非服务真的挂了。

### 5.4 官方文档里一个值得记的细节（本次核验发现）

K8s 官方 node-metrics 文档提到：

> Beginning with **metrics-server 0.6.x**, metrics-server queries the `/metrics/resource` kubelet endpoint, and not `/stats/summary`.

**且 metrics-server ≥ 0.6 的默认 secure-port 就是 10250**，与 kubelet 的 kubeletEndpoint.port 默认值相同 —— 这也是为什么这行日志长得像「apiserver 在访问 kubelet 的 metrics API」。

---

## 六、给 1-5 年运维的 5 条硬经验（原文原话 + 小白解读）

| # | 原文原话 | 小白/执行层解读 |
|---|---|---|
| ① | hosts 不是配置文件，是「会被系统背叛的文件」 | K8s 节点上的 hosts、时区、内核参数、kubelet 参数，都不存在「配了就完事」 |
| ② | Ubuntu 24.04 装机，第一件事就定 hosts 策略 | 三选一：`manage_etc_hosts: false` / 改 cloud-init 的 hosts 模板 / `chattr +i /etc/hosts` 锁死。**客户的机器别擅自动，写进复盘让客户拍板** |
| ③ | Service 不通，先看 Endpoints，别急着 restart kube-proxy | 口诀：**Pod Running ≠ Endpoint 登记在册；Service 存在 ≠ 流量出得去** |
| ④ | 控制面「全绿」是危险的信号 | 真正稳的集群，靠的是告警、选主日志、重启后自检，不是面板好看 |
| ⑤ | 复盘不是写「我修了什么」，是写「下次怎么不半夜爬起来」 | 低级复盘：重启 apiserver，好了。高级复盘：节点集体重启 → cloud-init 清 hosts → 控制器状态未恢复 → Endpoints 僵尸 → 防护措施落地 |

### 6.1 三个 hosts 策略的展开（原文只给了名字）

| 策略 | 做法 | 优点 | 缺点 / 注意 |
|---|---|---|---|
| **A. 关掉 cloud-init 管理** | 在 `/etc/cloud/cloud.cfg` 或 `/etc/cloud/cloud.cfg.d/*.cfg` 里设 `manage_etc_hosts: false` | 最干净，一劳永逸 | 需要确认这个值真的生效（见 §九 偏差 #1） |
| **B. 改模板** | 改 `/etc/cloud/templates/hosts.debian.tmpl`，把你需要的节点解析写进模板 | 模板重写时你的内容还在 | 模板是 Jinja2，变量语法要写对 |
| **C. 锁文件** | `chattr +i /etc/hosts` | 最暴力也最有效，**谁都改不了** | ⚠️ **很多工具（包括某些运维脚本、扩容工具）需要写 hosts 时会直接失败**；解锁 `chattr -i` 后再改 |

> ⚠️ **策略 C 的副作用要特别注意**（原文没提）：
> `chattr +i` 之后，如果 sealos / 扩容脚本 / 某些监控 agent 需要 append hosts 条目，会收到 `Operation not permitted`。
> 而且**文件被锁后 cloud-init 尝试重写时会报错**，可能导致 cloud-init 的模块失败（进而影响其他模块）。
> **推荐顺序：C > A > B**，但 C 要先确认没有任何自动化在写 hosts。

---

## 七、应急手册：节点重启后照着跑一遍（原文提供 + 本次补全）

### 7.1 原文的四步

```bash
# 1. hosts 还在不在
cat /etc/hosts | grep k8s-

# 2. 节点和控制面状态
kubectl get nodes
systemctl status kubelet

# 3. 有没有僵尸 Endpoints
kubectl get endpoints -A | grep -i none

# 4. 控制面组件重启次数监控 + Endpoints 为空告警
```

### 7.2 本次补全的诊断命令（一手核验过参数与路径）

```bash
# === 1. hosts 与节点名解析（最优先，成本最低）===
cat /etc/hosts | grep -E "k8s-|apiserver"
getent hosts k8s-node-01        # 解析不出来 = hosts 丢了
grep -i "etc/hosts" /var/log/cloud-init.log   # 确认是不是 cloud-init 干的
grep -rn "manage_etc_hosts" /etc/cloud/       # 看当前策略

# === 2. 控制面组件状态 ===
kubectl get nodes -o wide
kubectl get pods -n kube-system -o wide | grep -E "apiserver|controller-manager|scheduler|etcd|coredns|kube-proxy"
systemctl status kubelet
crictl ps                                    # 节点上容器真实状态

# === 3. 后端清单（Endpoints 已弃用，两个都看）===
kubectl get endpoints -A | grep -i none
kubectl get endpointslice -l kubernetes.io/service-name=nginx-service
kubectl get endpointslice nginx-service-xxxxx -o yaml | grep -A3 conditions

# === 4. 控制器是否真的在 reconcile（看它有没有干活）===
kubectl get --raw "/metrics" | grep -i endpointslice_controller   # controller 的工作计数
kubectl -n kube-system logs kube-controller-manager-xxxx | grep -i -E "endpoint|error"

# === 5. 节点级通道是否正常（原文 §五 的正确版本）===
kubectl get --raw "/api/v1/nodes/k8s-node-01/proxy/metrics/resource"   # kubelet 直接提供的指标路径
kubectl -n kube-system logs deploy/metrics-server | tail -50

# === 6. 静态 Pod 目录体检 ===
ls -la /etc/kubernetes/manifests/          # 有没有 .bak/.backup 混在里面
ls -la /etc/kubernetes/backup/ 2>/dev/null # 备份应该在这里，不在 manifests 里
```

> **第 4 步是本次新增的「小小白白能看懂」的关键**：
> `kubectl get --raw "/metrics"` 能拿到 controller 自己的工作计数。
> 如果 **Pod Running 但这个计数不涨**，就说明控制器进程活着但循环没转 —— **这就是「假活」的量化证据**。
> 这比原文「看面板」强得多。

---

## 八、跟我们的关系（用户工作相关）

> 按 iswiki 定位，这段必填 —— 不是通用文档搬运，是「跟用户私活 / 项目能怎么用上」。

| 关联点 | 用法 |
|---|---|
| **VPS 编排架构** | 用户 VPS 是纯调度/编排、无本地算力。本文的「控制器假活」模型可直接平移：**Hermes gateway / cron job / agent 编排器都是「进程活着但循环没转」的高发区**。对应动作：给每个长驻 agent 加 `kubectl get --raw /metrics` 式的「心跳计数」检查，而不是只看进程 PID 在不在。 |
| **ToDesk wakeup 风暴** | 本机 Mac 侧的同类故障（Mac mini 8,1 + macOS 13.6 的 ToDesk 4.7.4.9 唤醒风暴），已沉淀为本机运维经验，不在本仓。**本文的 hosts 教训在 Mac 侧同样适用**：`/etc/hosts` 被任何自动化改写会导致本机服务解析失败。**建议在 Mac 上也检查是否有 launchd 任务或 shell profile 在写 hosts**。 |
| **端口选型偏好** | 用户偏好 5 位数端口、避免 macOS 常见撞车端口。本文 §七 第 5 步的 `metrics/resource` 排查思路适用于自建服务：**端口不通时先分清「谁连谁」**（呼应用户「先需求澄清再编码」的排障风格）。 |
| **单节点 etcd 风险** | 原文环境是「1 Master + 3 Node，单节点 etcd」。用户 VPS 场景同样存在「单点」偏好 —— 但**单点 etcd 不能像 K8s 那样靠重启自愈**，etcd 挂了就是真挂。这条已写进 §九 风险清单。 |
| **家庭设备 / IoT** | 心儿、丞儿家的智能设备如果有本地 DNS 解析依赖，`/etc/hosts` 类文件被自动覆盖是同类问题。**核心教训通用：任何「写一次就以为 forever」的文件，都要假设它会被系统覆写。** |

### 8.1 可直接搬走的工程模式

| 模式 | 落地方式 |
|---|---|
| **心跳计数 > 进程存活** | 任何长驻服务都暴露一个「我干过多少活」的计数器并做阈值告警。K8s 里就是 `controller` 的 work 计数；在 Hermes 里可以是「本次会话处理任务数」。 |
| **配置文件要防被系统覆写** | `chattr +i` / 只读挂载 / 模板化（让系统重写时带上你的内容）。**凡是你自己写、但系统也会写同一个文件的，必须先问「谁会覆写我」。** |
| **按依赖方向定位** | 读错误日志先画「谁请求谁」的箭头，别默认发起方是你以为的那个。 |
| **改之前写进复盘让客户拍板** | 原文原文态度：客户的机器别擅自动。这条对用户做交付/运维服务同样适用。 |

---

## 九、⚠️ 一手核验：纠正原文的 7 处技术偏差

> 按 iswiki 方法论，用户给的文章必须以一手资料核验为准。以下每条都标注了核验来源。

| # | 原文说法 | 一手核验结论 | 核验来源 |
|---|---|---|---|
| **1** | 「`manage_etc_hosts` 被设为 true 或 template —— **很多云镜像出厂就是这么预置的**，配置常藏在 `/etc/cloud/cloud.cfg.d/` 下你没想到的文件里」 | **官方默认是 `false`。** cloud-init 模块文档原文：「manage_etc_hosts: (True / False / localhost / template)... **Default: false.**」且 **`template` 值已在 22.2 弃用**（源码里 `lifecycle.deprecate(deprecated_version="22.2")`），22.3 起文档直接写「Use of *template* is deprecated, use true instead」。**「出厂预置 true」不是通用事实，需按具体发行版逐台确认** —— 这恰恰强化了原文「去 grep 一下」的动作建议。 | cloud-init 官方 modules 文档 + `cc_update_etc_hosts.py` 源码 |
| **2** | 「配置常藏在 `/etc/cloud/cloud.cfg.d/` 下你没想到的文件里」 | **路径说法不完整。** cloud-init 的配置搜索路径是 `/etc/cloud/cloud.cfg` → `/etc/cloud/cloud.cfg.d/*.cfg` → **`/var/lib/cloud/seed/nocloud-net` 等 datasource 目录** → `/var/lib/cloud/instance/user-data.txt`（用户自定义 datasource）。**只查 `cloud.cfg.d/` 可能漏掉 datasource 注入的 cloud-config**（例如 NoCloud 的 `user-data`）。 | cloud-init 官方配置文档 + `config/cloud.cfg.tmpl` |
| **3** | 「那行 `127.0.1.1 k8s-master-1` 正是 Debian 系 hosts 模板（hosts.debian.tmpl）的签名」 | ✅ **成立。** 本次直接拉取 `templates/hosts.debian.tmpl` 确认首行即 `127.0.1.1 {{fqdn}} {{hostname}}`。但需补充：**这段模板只有在 `manage_etc_hosts: true` 时才会被渲染**；`localhost` 模式则走 `cloud.distro.update_etc_hosts()` 增量追加（Debian 系是 Debian 自己的实现，非模板）。 | canonical/cloud-init `templates/hosts.debian.tmpl` + `cc_update_etc_hosts.py` |
| **4** | 「Endpoints 就是 Service 背后真实的 Pod IP 清单」「没醒过来的是 kube-controller-manager 里的 **Endpoints 控制器**」 | **术语已过时。** `v1.Endpoints` API **自 Kubernetes v1.33 起已弃用**（官方文档：「Endpoints (deprecated) Feature state: Deprecated since Kubernetes v1.33」）。**kube-proxy 的真实数据源是 `discovery.k8s.io/v1.EndpointSlice`（v1.21 起 Stable）**，由 **endpoint slice controller** 维护。控制面仍会把 Endpoints **镜像**成 EndpointSlice 以兼容旧客户端，但镜像特性本身也已弃用。**排查时两个都要看，但主看 EndpointSlice。** | Kubernetes 官方 Service 文档 + EndpointSlice 文档 + `pkg/controller/endpointslice/endpointslice_controller.go`（master 分支确认该控制器仍存在） |
| **5** | 「**apiserver** 连不上 kubelet」（§五 对日志的解读） | **方向讲反了。** kubelet 的路由表里只有 `/metrics`、`/metrics/resource`、`/stats/` 等，**不提供 `/apis/metrics.k8s.io/v1beta1`**。该路径是 **apiserver 的聚合 API**（Aggregation Layer），由 metrics-server 注册。**发起这次 Get 的是 metrics-server，不是 apiserver。** | kubernetes/kubernetes `pkg/kubelet/server/server.go` + metrics-server 官方 README |
| **6** | 「metrics-server 连不上 = 节点级控制通道有问题」 | **方向对但机制不同。** metrics-server 官方 manifest 默认 `--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname`。**Hostname 的解析依赖 DNS/hosts** —— hosts 被清空后，metrics-server 可能因解析不出节点名而超时。**结论（metrics-server 只是喊疼的、不是病根）仍然成立**，但链条更精确。 | metrics-server 仓库 README + `manifests/base/deployment.yaml`（实测 `--secure-port=10250`、`--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname`） |
| **7** | 静态 Pod 恢复操作 `mv kube-apiserver.yaml /tmp` | **操作正确，但漏了官方明确警告的坑。** 官方文档原文：「The kubelet processes **all files not starting with a dot** in the static Pod directory — there is no filtering by file extension... if you create a backup by running `cp kube-apiserver.yaml kube-apiserver.yaml.backup`, the kubelet will read both files... the resulting behavior is **undefined** and can cause the backup's outdated spec to **silently take effect**」。**备份必须放 `/etc/kubernetes/backup/`，绝不能留在 manifests 目录。** | Kubernetes 官方 Create static Pods 文档 |

### 9.1 核验为「准确」的部分（避免只挑刺）

| 原文说法 | 核验结论 |
|---|---|
| hosts.debian.tmpl 的 `127.0.1.1` 签名 | ✅ 完全成立（已拉取模板原文确认） |
| `update_etc_hosts` 模块「每次开机都会执行」 | ✅ 成立（源码 `frequency: PER_ALWAYS`） |
| `grep -i "etc/hosts" /var/log/cloud-init.log` 查日志 | ✅ 方法正确 |
| 「Service 还指着昨天在干活」的现象判断 | ✅ 成立 |
| 「先救控制面，别修业务」的处理顺序 | ✅ 成立（先修控制循环，Pod 重启无意义） |
| 「控制面全绿是危险的信号」 | ✅ 成立，且本文 §七 第 4 步给出了量化版本 |
| 「Pod Running ≠ Endpoint 登记在册」 | ✅ 成立，且在 EndpointSlice 时代更应说「≠ 在 EndpointSlice 里登记为 serving」 |

---

## 十、风险清单 / 实战注意

| 风险 | 说明 | 建议 |
|---|---|---|
| **单节点 etcd** | 原文环境是单节点 etcd。**etcd 单点没有选主可做**，挂了就是全挂。且 etcd 数据在 `/var/lib/etcd`，重启前要确认数据目录健康 | 至少 3 节点 etcd（原复盘里客户待决策项之一）；定期 `etcdctl snapshot save` |
| **`chattr +i /etc/hosts` 的副作用** | 会让任何需要写 hosts 的自动化失败（含 sealos `sealctl hosts add`、部分扩容/监控脚本） | 上锁前先 `grep -rn "/etc/hosts" /etc/cron* /opt /usr/local/bin` 排查写入方 |
| **静态 Pod 目录混放备份** | 官方明说行为 undefined，可能静默用旧 manifest | 备份统一到 `/etc/kubernetes/backup/`；每次操作前 `ls -la /etc/kubernetes/manifests/` |
| **Endpoints API 已弃用** | 你的脚本/告警如果还在 `kubectl get endpoints` 做判断，v1.33+ 集群上未来可能失效 | 改成同时查 `kubectl get endpointslice`；告警条件用 `serving`/`ready` condition 而非「Endpoints 为空」 |
| **`context deadline exceeded` 误判** | 超时 ≠ 服务挂了，常是 DNS 解析卡住或网络黑洞 | 先画「谁请求谁」，再决定查 DNS 还是查服务 |
| **`manage_etc_hosts` 默认值是 false** | 很多人在「没配过」的错误假设上做决策 | 每台机器 `grep -rn manage_etc_hosts /etc/cloud/` + `cloud-init query` 实测 |
| **云镜像 vs 私有镜像差异** | 同一 Ubuntu 版本，官方镜像 / 云厂商镜像 / 私有定制镜像的 cloud-init 配置可能完全不同 | 不要假设「这台机器和其他一样」 |

---

## 十一、一图总结（给团队传阅）

```
故障全貌
  4 台节点集体重启
        │
        ▼
  cloud-init update_etc_hosts（frequency=always）重写 /etc/hosts
        │  证据：127.0.1.1 <hostname> ← hosts.debian.tmpl 签名
        ▼
  节点名 / apiserver.cluster.local 解析断
        │
        ├──────────────▶ metrics-server 解析不出节点名 → 超时喊疼（第一个症状）
        │
        ▼
  kube-controller-manager 的 endpoint slice controller 状态未恢复
        │  进程 Running ✅ 但 reconcile 循环不转 ❌  ← 「假活」
        ▼
  EndpointSlice / Endpoints 花名册停在旧 Pod IP
        │
        ▼
  kube-proxy 规则仍指向死 Pod → Service 不通
        │  现象：Pod Running ✅、Pod IP 能 ping ✅、Service 全挂 ❌

排查主线
  ① hosts 在不在      → cat /etc/hosts | grep k8s-
  ② 清单对不对        → kubectl get endpointslice -l kubernetes.io/service-name=X
  ③ 控制器在不在干活  → kubectl get --raw /metrics | grep endpointslice_controller
  ④ 节点通道通不通    → kubectl get --raw /api/v1/nodes/<node>/proxy/metrics/resource
  ⑤ 修控制面          → 移走/移回 manifests 里的静态 Pod yaml（备份放 /etc/kubernetes/backup/）

三条硬经验
  ① hosts 不是配置文件，是「会被系统背叛的文件」
  ② Pod Running ≠ Endpoint 登记在册；Service 存在 ≠ 流量出得去
  ③ 复盘要写「下次怎么不半夜爬起来」，不是「我修了什么」
```

---

## 参考链接

**原文**
- 微信公众号「胡哥Linux运维」《K8s 控制面全绿，业务全挂：问题藏在 /etc/hosts 里》—— https://mp.weixin.qq.com/s/JYEreZfkJExzbVbeODiAHw

**cloud-init（一手核验来源）**
- cloud-init 模块参考（`update_etc_hosts` / `manage_etc_hosts` 官方 schema 与默认值）—— https://cloudinit.readthedocs.io/en/latest/reference/modules.html
- cloud-init CLI 参考（`query` / `analyze` / `status`）—— https://cloudinit.readthedocs.io/en/latest/reference/cli.html
- `cc_update_etc_hosts.py` 源码（`frequency: PER_ALWAYS`、模板/ localhost 分支、22.2 弃用 `template`）—— https://github.com/canonical/cloud-init/blob/main/cloudinit/config/cc_update_etc_hosts.py
- `templates/hosts.debian.tmpl`（`127.0.1.1` 签名原文）—— https://github.com/canonical/cloud-init/blob/main/templates/hosts.debian.tmpl
- cloud-init 配置模板（`config/cloud.cfg.tmpl`，`manage_etc_hosts` 默认段落）—— https://github.com/canonical/cloud-init/blob/main/config/cloud.cfg.tmpl

**Kubernetes 官方（一手核验来源）**
- Service 概念（**Endpoints 自 v1.33 弃用**、EndpointSlice 镜像机制、over-capacity 注解）—— https://kubernetes.io/docs/concepts/services-networking/service/
- EndpointSlices（v1.21 Stable、serving/terminating/ready 三个 condition、`--max-endpoints-per-slice`）—— https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/
- Create static Pods（**kubelet 扫描目录机制 + 不按扩展名过滤的官方警告 + 镜像 Pod**）—— https://kubernetes.io/docs/tasks/administer-cluster/static-pod/
- Pod 概念与生命周期 —— https://kubernetes.io/docs/concepts/workloads/pods/
- Nodes / 节点架构 —— https://kubernetes.io/docs/concepts/architecture/nodes/
- Kubernetes 架构总览 —— https://kubernetes.io/docs/concepts/architecture/
- Workload 控制器（Deployment / ReplicaSet / StatefulSet 概念）—— https://kubernetes.io/docs/concepts/workloads/controllers/
- 弃用 API 迁移指南（EndpointSlice v1beta1 在 v1.25 移除等时间线）—— https://kubernetes.io/docs/reference/using-api/deprecation-guide/
- Node metrics data（**kubelet 提供的指标路径**、PSI）—— https://kubernetes.io/docs/reference/instrumentation/node-metrics/
- kubelet 配置 API（`staticPodPath` 字段）—— https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
- 集群调试 —— https://kubernetes.io/docs/tasks/debug/debug-cluster/
- kubectl 速查 —— https://kubernetes.io/docs/reference/kubectl/quick-reference/
- kubeadm —— https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/
- 自定义 DNS —— https://kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/

**相关组件**
- metrics-server（**`--secure-port=10250`、`--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname`**、kubelet 通信前提）—— https://github.com/kubernetes-sigs/metrics-server
- sealos（**`sealctl hosts` 直接 append `/etc/hosts`，不配置 cloud-init**）—— https://github.com/labring/sealos
