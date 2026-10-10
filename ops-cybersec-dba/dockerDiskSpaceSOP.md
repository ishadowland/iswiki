# DockerDiskSpaceSOP — Docker 磁盘满的定位处置 SOP

> 学习笔记 · 调研时间 2026-10-10
> 触发来源: 公众号《Docker 会自动清缓存，为什么磁盘还会满？》 https://mp.weixin.qq.com/s/YSSNcDQ2BDv0ro8zQAInSQ
> 官方文档: https://docs.docker.com/build/cache/garbage-collection/ · https://docs.docker.com/reference/cli/docker/buildx/du/ · https://docs.docker.com/reference/cli/docker/buildx/prune/ · https://docs.docker.com/reference/cli/docker/system/prune/ · https://docs.docker.com/desktop/troubleshoot-and-support/faqs/macfaqs/
> 本机实测环境: macOS 13.6 · Docker CLI 20.10.17 + buildx v0.9.1 · 三 context 共存(colima 当前 / default / desktop-linux)

---

## 一句话定位

「Docker 磁盘满」的 SOP：**先定位是哪台机器、哪个构建器、哪个存储层占的，再按对象分层清理，最后回到阈值配置做长期兜底**——三步走完才算处置闭环。

---

## 为什么"自动清理开着"还是会满

一句话：**GC 只管它负责的那块，不是整盘配额**。

三个必须先讲清的机制（官方 `garbage-collection.md` 原文口径）：

1. **GC 阈值 ≠ 整盘容量预留**。默认策略里 `reservedSpace` 是「GC 不会把缓存压到低于这个值」的**地板**，不是「磁盘留这么多空间」的**天花板**。缓存目标 20GB、其他数据吃掉 90% 的盘，GC 依然"工作正常"——它只负责那 20GB。
2. **构建过程中会现写新数据**。下载依赖、解压、写入中间层都在峰值时刻发生。空闲空间只剩几百 MB 时，后台 GC 腾不出下一步要用的量。
3. **GC 完全不管这些**：数据库卷、容器 json-log、宿主机项目目录、**另一个 builder 的存储**。

---

## SOP：三阶段

```
Phase 1 定位（L1 只读）──▶ 判定表 ──▶ Phase 2 处置（按对象）──▶ Phase 3 兜底（阈值配置）
```

---

## Phase 1：定位（全部只读，先跑完这 4 条）

```bash
docker context show      # ① 你到底在跟哪台机器说话
docker system df -v      # ② 该 Engine 的镜像/容器/卷/构建缓存 分项占用
docker buildx ls         # ③ 一共几个 builder，当前选中哪个（带 * ）
docker buildx du         # ④ 当前 builder 的缓存明细 + 可回收量
```

**这 4 条能直接排除掉一半的误判：**

| 现象 | 说明 |
|---|---|
| `context show` ≠ 你以为的机器 | 远程 context 下这 4 条命令看的**根本不是本机** |
| `buildx ls` 里多个 builder，只有带 `*` 的在涨 | 清理了 default，涨的是另一个 |
| `system df` 总和 ≠ 各分项之和 | 构建缓存与镜像**共享数据**，不能简单相加（这也是 `du` 输出里 `*` 号的含义，见下）|
| `du` 里 `RECLAIMABLE=false` | 该记录**正被 builder 某个组件占用**，`prune --all` 也删不掉 |

### `buildx du` 输出怎么读（官方口径）

```
ID                                RECLAIMABLE    SIZE          LAST ACCESSED
12wgll9os87pazzft8lt0yztp*        true           1.704GB       13 days ago
rz2zgfcwlfxsxd7d41w2sz2tt         true           8.224kB*      43 hours ago

Shared:        115.5MB
Private:       10.25GB
Reclaimable:   10.36GB
Total:         10.36GB
```

- **ID 后的 `*`** = 该记录是 **mutable**，大小会变，下次跑可能就没了
- **size 后的 `*`** = 该记录**与镜像共享存储**。prune 它只删元数据，实际层还被镜像占着 —— **这就是「清完没释放多少」的根因**
- `Reclaimable < Total` 的差额 = 正在使用 + 共享的部分

### 判定表：清理对象 → 命令

| 谁在占 | 命令 | 默认删什么 | 慎用标志 |
|---|---|---|---|
| 构建缓存 | `docker buildx prune` | 当前 builder 未使用缓存 | 加 `--all` 会连 frontend/internal 镜像一起删 |
| 构建缓存（仅镜像/网络/容器不动） | `docker builder prune` | 同上 | 旧式入口，仍可用 |
| 悬空镜像 | `docker image prune` | dangling | `-a` 会删所有未被容器引用的镜像 |
| 大范围 | `docker system prune` | 停止容器 + 未用网络 + 悬空镜像 + 未用构建缓存 | **`--volumes` 会删匿名卷 = 数据库数据** |
| 匿名卷 | `docker volume prune` | 未被容器引用的匿名卷 | 生产环境先 `docker volume ls` 逐个确认 |

---

## Phase 2：处置（由窄到宽，一级级加）

### Step 2.1 — 最窄：只清构建缓存（默认首选）

```bash
# 先看能回收多少（只读）
docker buildx du

# 保守：只删 48 小时以上没碰过的未使用缓存
docker buildx prune --filter 'until=48h'

# 或按空间目标倒逼（比 until 更可控）
docker buildx prune --max-used-space 10GB          # 压到 ≤10GB
docker buildx prune --min-free-space 20GB         # 目标是留出 ≥20GB 空闲
docker buildx prune --reserved-space 5GB          # 地板：至少给缓存留 5GB
```

**官方 `--filter` 全表**（多个 `--filter` 是 **AND** 关系）：

| key | 说明 |
|---|---|
| `until=48h` / `2h30m` | 保留最近使用过的；单位 h/m/s |
| `id=xxx` | 精确打某个 image ID |
| `parents=id1;id2` | 某镜像的所有父层（分号分隔）|
| `description~=golang` | 描述子串，`~=` 是正则 |
| `inuse=true` | 正被占用、不可回收的 |
| `mutable=true` / `immutable=true` | 可变 / 不可变记录 |
| `shared=true` / `private=true` | 共享 / 非共享 |
| `type=source.local` | 按类型：`internal` / `frontend` / `source.local` / `source.git.checkout` / `exec.cachemount` / `regular` |

> `daemon.json` 里的 GC filter **不支持 `mutable` 和 `immutable`** 这两个 key（官方明确说明），BuildKit 的 `buildkitd.toml` 才支持。

### Step 2.2 — 定位到日志/卷/挂载异常时

**容器 json-log 是第二大隐形杀手**，Docker 默认 `json-file` 驱动**不限制大小**，一个刷日志的容器能吃掉几十 G。

```bash
# 找出日志最大的容器
docker inspect --format '{{.Name}}\t{{.LogPath}}' $(docker ps -aq) 2>/dev/null | head

# 查真实大小（macOS 用 -h，Linux 加 -s 看块数）
ls -lh /var/lib/docker/containers/*/*-json.log 2>/dev/null | sort -k5 -h | tail
```

**治本（改 daemon.json，需重启 daemon）：**

```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "50m", "max-file": "3" }
}
```

> ⚠️ 改 daemon.json 会**重启 Docker daemon，所有容器停掉**。生产环境走变更窗口。改完只对**新建容器**生效，老容器要 recreate。

### Step 2.3 — 确认无用后才扩大范围

```bash
# 逐层看，别上来就 system prune
docker image prune                    # 只删悬空
docker image prune -a                 # 删所有未被容器引用的镜像（本地镜像未必都能重拉！）

# 最后一档：删匿名卷前务必先列
docker volume ls
docker system prune --volumes         # ⚠️ 删匿名卷 = 可能删库数据
```

**停掉的容器不等于没价值**：它的可写层可能存着你手工 `docker cp` 进去的东西。确认顺序：`docker ps -a` → 看 `STATUS` 和 `COMMAND` → 需要的数据先 `docker cp` 出来。

---

## Phase 3：长期兜底（处置完必须做，否则下次照旧）

### 3.1 配对配置文件：按驱动选，别照抄

**这是最容易翻车的地方——两个文件、两种语法、两套 key。**

| 场景 | 配置文件 | filter 运算符 |
|---|---|---|
| 默认 `docker` 驱动 | `~/.docker/daemon.json`（Docker Desktop 是 Settings → Docker Engine）| `type=source.local`（**单等号**）|
| 其他驱动（`docker-container` 等）| `buildkitd.toml` | `type==source.local`（**双等号**）|

```json
// daemon.json —— 最简做法：只调 defaultKeepStorage
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  }
}
```

**默认 4 条策略展开后**（20GB 时长什么样）：

```json
{
  "builder": {
    "gc": {
      "enabled": true,
      "policy": [
        { "reservedSpace": "2.764GB", "keepDuration": "48h",
          "filter": ["type=source.local,type=exec.cachemount,type=source.git.checkout"] },
        { "reservedSpace": "20GB", "keepDuration": ["1440h"] },
        { "reservedSpace": "20GB" },
        { "reservedSpace": "20GB", "all": true }
      ]
    }
  }
}
```

读法：**超 2.764GB 就开始清 48h 前的 local context / cachemount；超 20GB 就清 60 天前未用的；再超就清未共享的；最后全清。**

### 3.2 buildkitd.toml 的三个高阶选项

| Option | 语义 | 默认值 |
|---|---|---|
| `reservedSpace` | **地板**：缓存不得被 GC 压到低于此值 | 总盘 10% 或 10GB，取小 |
| `maxUsedSpace` | **天花板**：超过此值开始回收 | 总盘 60% 或 100GB，取小 |
| `minFreeSpace` | 必须留出的空闲空间 | 20GB |

> 🔑 **优先级：`reservedSpace` 最高**。即使 `maxUsedSpace` / `minFreeSpace` 算出更小的值，缓存也不会被压到 `reservedSpace` 以下。同时设了 `reservedSpace=10GB` 和 `maxUsedSpace=20GB`，GC 后缓存大小落在 **[10GB, 20GB)** 区间。

```toml
[worker.oci]
  gc = true
  reservedSpace = "10GB"
  maxUsedSpace = "100GB"
  minFreeSpace = "20%"

[[worker.oci.gcpolicy]]
  filters = [ "type==source.local", "type==exec.cachemount", "type==source.git.checkout" ]
  keepDuration = "48h"
  maxUsedSpace = "512MB"
```

### 3.3 macOS 特有的第三个数

Docker Desktop for Mac 把所有 Linux 容器和镜像塞进宿主机上一个**巨大的稀疏文件 `Docker.raw`**，所以 Mac 上要同时盯**三个数**：

```
① Docker 内部用量      → docker system df -v
② Docker.raw 配置上限   → Settings → Resources → Advanced（滑块）
③ Docker.raw 实际占用   → 宿主机文件系统（最关键）
```

**官方明确提醒：很多工具显示的是最大文件尺寸，不是实际占用。** 区分办法：

```bash
# ls -s 输出第一列是 1K 块数（= 实际），最后一列是表观大小（= 上限）
ls -lsh ~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw
```

**本机实测（2026-10-10，直接命中这个坑）**：

```
2333548 blocks → 实际 24.8 GB
Docker.raw    → 表观上限 1224 GB (1.2T)
宿主 Docker 容器目录合计 25G
```

即：**上限看着有 1.2T，实际只吃 24.8G**。只看 `ls -lh` 的表观值会得出「Docker 占了 1.2T」的完全错误结论。

**Mac 专有操作：**

| 操作 | 做法 | ⚠️ 代价 |
|---|---|---|
| 看真实占用 | `ls -lsh .../Docker.raw`（`s` = 块数 = 真实） | 无 |
| 移动到外置盘 | Settings → Resources → Advanced → Disk image location 改路径 → Apply | **绝不要在 Finder 里直接搬文件**，Docker 会失去追踪 |
| 缩上限 | 同页面拖滑块 → Apply | **缩小上限 = 删掉当前 disk image = 容器和镜像全丢** |
| 强制回收宿主空间 | `docker run --privileged --pid=host docker/desktop-reclaim-space` | 无，但删除容器内文件不自动回收，删完要跑这个 |

> 删掉运行中容器里的文件**不会自动把空间还给宿主**，需要手动跑一次 `reclaim-space` 镜像。

---

## Phase 4：复发预防（下次告警时先做这个）

按公众号最后一段的意思——**「再跑一次 prune」不该是唯一动作**：

1. **监控真正承载数据的文件系统**，不是监控 Docker 的内部统计
2. **给构建峰值留余量**：峰值需求 ≈ 依赖下载 + 解压 + 最终镜像层，`minFreeSpace` 要设在峰值之上
3. **日志和卷单独设保留策略**：日志加 `max-size`，卷单独做备份与清理节奏
4. **告警时先找增长来源**，按上面 Phase 1 的 4 条命令跑一遍再决定清什么

---

## 坑点速查

| 坑 | 说明 |
|---|---|
| 清 default builder，涨的是另一个 | 多 builder 环境必踩，先 `buildx ls` 看 `*` |
| `du` 显示 reclaimable 但 prune 后没释放多少 | size 后的 `*` = 与镜像共享存储，只删了元数据 |
| `prune --all` 删了 frontend/internal 镜像 | 后续构建要重新下载，慢但不出错 |
| `system prune --volumes` 删了数据库 | 匿名卷里就是数据，删前必须 `volume ls` |
| 把 `keepBytes` / `defaultKeepStorage` 贴到任意配置文件 | 驱动不对就不生效；`=` vs `==` 也分两种文件 |
| `ls -lh` 看着 1.2T 就以为 Docker 吃满了 | Mac 上必须 `ls -lsh` 看块数 |
| 调小 Docker.raw 上限 | **容器和镜像全丢**，不是"压缩" |
| 在 Finder 里搬 Docker.raw | Docker Desktop 失去追踪，镜像损坏 |
| 改 daemon.json 忘了它会重启 daemon | 生产要走变更窗口，且只对新容器生效 |

---

## 本机现状快照（写 SOP 时的实测）

| 项 | 值 | 备注 |
|---|---|---|
| Docker CLI | 20.10.17 | buildx v0.9.1 |
| 当前 context | `colima` | 另有 `default` / `desktop-linux`，**三个共存** |
| `~/.docker/daemon.json` | `defaultKeepStorage: 20GB`, `enabled: true` | 未配 `log-opts`，**日志无上限** |
| `~/.colima` | 2.0G（`_lima` 2.0G） | 实际 context 指向的引擎 |
| Docker Desktop `Docker.raw` | 实际 24.8G / 上限 1224G | Desktop 不用但没卸载，仍占 25G |
| 宿主 Data 卷 | 1.5Ti 已用 / 356Gi 可用（82%） | 真正紧张的是这个，不是 Docker |

> 按项目偏好：Docker Desktop 保留作 GUI 兜底，Colima 是当前实际引擎。所以 SOP 里 Phase 3.3 只在用 Desktop 时才需要。

---

## 参考链接

- 公众号原文《Docker 会自动清缓存，为什么磁盘还会满？》: https://mp.weixin.qq.com/s/YSSNcDQ2BDv0ro8zQAInSQ
- Docker: Build garbage collection（GC 阈值与策略权威口径）: https://docs.docker.com/build/cache/garbage-collection/
- docker buildx du（RECLAIMABLE / `*` 号语义）: https://docs.docker.com/reference/cli/docker/buildx/du/
- docker buildx prune（--filter 全表 + 三个空间参数）: https://docs.docker.com/reference/cli/docker/buildx/prune/
- docker system prune（各子命令删除范围）: https://docs.docker.com/reference/cli/docker/system/prune/
- docker system df: https://docs.docker.com/reference/cli/docker/system/df/
- Docker Desktop for Mac FAQ（Docker.raw / 稀疏文件 / reclaim-space）: https://docs.docker.com/desktop/troubleshoot-and-support/faqs/macfaqs/
- Docker 日志驱动配置（json-file max-size）: https://docs.docker.com/engine/logging/configure/
- Docker 存储卷: https://docs.docker.com/engine/storage/volumes/
- 关联笔记: [opsTroubleshootingDiskGhost](opsTroubleshootingDiskGhost.md) · [opsTroubleshootingOOMCgroup](opsTroubleshootingOOMCgroup.md) · [performanceTriage](performanceTriage.md)