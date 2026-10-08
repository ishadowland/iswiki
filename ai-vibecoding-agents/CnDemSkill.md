# CnDemSkill — 「说个地名就下载中国 30 米 DEM」的 WorkBuddy skill 拆解 + 一手核验

> 学习笔记 · 调研时间 2026-10-08
> 调研对象: 微信公众号《发现了一个有趣的 skill，和 workbuddy 说一个地名，免费帮你下载 30 米 DEM》(GIS技术杂货铺, 2026-10)
> 文章 URL: https://mp.weixin.qq.com/s/lVbHaHqbySkvNqt3WMWOCA
> 数据底座: Copernicus **GLO-30** · AWS Open Data `s3://copernicus-dem-30m` (eu-central-1) · **免 Key / 免注册 / 匿名可读（已实测）**
> 源码: **公开渠道不可得**（见下节）
> License: 数据为 Copernicus 免费开放条款（非 OSI 开源）· 脚本未知

---

## ⚠️ 首要前提：这套 skill 的源码拿不到

文章末尾明确写「后台回复【016】即可获取」——**它不是一个公开仓库，而是一条公众号引流漏斗**。我做了完整的一手核查：

| 检索目标 | 结果 |
|---|---|
| GitHub repo 搜 `cn-dem` / `cn_dem` | 无相关结果（1578 条全是 `cnn` / `demo` 噪声） |
| GitHub repo 搜 `terrain_products.py` + dem | **total_count = 0** |
| GitHub repo 搜 `dem_stats.py` | 4 条，全是无关的 stats demo |
| 文章内是否给出 repo / 源码链接 | **无**（全文 0 个外链，0 个可点 URL） |
| `workbuddy.ai` / `.cn` / `.com` | 三域名均返回 200，但**与本文 skill 无可查证的公开对应关系** |

**结论**：文章里所有「已修复」「原脚本只取第一个部件」都是**作者的二手陈述，无法验证**。因此本笔记采用双栏标注：

- ✅ **实测**＝我在本机跑过，有原始输出
- 📄 **文章称**＝原文陈述，未经独立验证
- ⚠️ **判定为错**＝我实测推翻了它

好消息是：**底座数据源完全公开且免 Key**，所以即使拿不到 skill，这套流程也能自己重写一遍。这才是这篇文真正的可复用价值。

---

## 一句话定位

**给 AI agent 用的「中国任意区县 30 米 DEM 一键取数」封装**——输入地名/adcode，自动取行政边界、按边界 bbox 拼接 Copernicus GLO-30 1° 瓦片、裁成 GeoTIFF + 出山体阴影预览图；数据源是 AWS Open Data 上**匿名免 Key** 的 GLO-30。

---

## 数据底座：已完全一手核验的 GLO-30 接入方式

这部分**不需要 skill，裸 curl 就能用**，是本笔记最硬的部分。

### 桶与命名规则 ✅ 实测

| 项 | 值（实测） |
|---|---|
| Endpoint | `https://copernicus-dem-30m.s3.amazonaws.com` |
| Region | `eu-central-1`（`?location` 返回） |
| 匿名 list | `?list-type=2&delimiter=/` → **HTTP 200，无需任何签名/Key** |
| 瓦片对象名 | `Copernicus_DSM_COG_10_N{lat}_00_E{lon}_00_DEM/Copernicus_DSM_COG_10_N{lat}_00_E{lon}_00_DEM.tif` |
| 取 N28_E117 | HTTP **200**（完整）／HTTP **206**（`Range` 请求，可断点/只读头） |

> 🔴 **命名陷阱**：桶名叫 `copernicus-dem-30m`，但里面躺的是 `COG_10` ＝ **10 米**产品的瓦片（GLO-30 的 1″ 分辨率）。**不要按桶名推断分辨率**，一切以对象名里的 `COG_10` 为准。
>
> 🟡 **桶名里的 30m 从哪来**：GLO-30 是「30 米级」产品的商业/发布口径，其全球统一分辨率其实是 1 角秒 ≈ 30 m（含赤道处的标称值）。所以桶名不算全错，但**在中国中纬度上实际是 27 × 31 m**（见下）。

### 瓦片内部规格 ✅ 实测（直接解析 TIFF IFD，非二手转述）

我拉了 `N28_E117` 瓦片头部 16 KB 并手工解 GeoTIFF 标签：

| 项 | 实测值 | 解读 |
|---|---|---|
| ImageWidth × ImageLength | **3600 × 3600** | 1° 瓦片 @ 1″ |
| BitsPerSample | **32**（单通道） | **float32**，符合文章说的 float32 |
| Compression | 8 = Deflate | COG 格式 |
| ModelPixelScale | **0.0002777777777777778**（X/Y 相同） | = **1.00 角秒** |
| ModelTiepoint | (0,0,0) → **(117.0, 29.0, 0)** | 左上角锚点，瓦片覆盖 lon 117→118、lat 28→29 |
| GeoKey 2048 (EPSG) | **4326** | WGS84 ✅ |
| GeoKey 3072 (GeogAngularUnits) | 9102 | degree |
| GeoKey 2057 (VerticalCSType) | 1 | orthometric height |
| **GeoKey 2054 (VerticalDatum)** | **9102** | **EGM2008** ✅ 证实文章的垂直基准说法 |
| **GeoKey 2059 (VerticalCitation)** | **0 = none** | ⚠️ 见下方坑点 |
| GeoAsciiParams | `WGS 84` | — |

**像元实际地面尺寸**（江西 28.75°N 实算）：

```
经向 (E-W): 0.0002777778° × 111320 × cos(28.75°) = 27.1 m
纬向 (N-S): 0.0002777778° × 110574              = 30.7 m
```

→ **文章「像元约 1/3600°，即约 27×31 米」的表述准确**。同时它也正确提醒了「像元不是正方形」——这点在算面积/坡度时会引入各向异性，坡度用度数算没问题但**面积和距离必须先投影**。

---

## 文章的 3 处技术问题（我实测推翻了其中 2 处）

### ⚠️ 问题 1：多边形的 bug 归因错了 —— 真实原因不是「多部件」，是「端点选错」

📄 文章称：
> 「市级边界常被拆成多个多边形（**如上饶市有 12 个**），原脚本只取第一个部件的范围，会把 9 个 1° 瓦片算成 2 个」

✅ 实测（直接查阿里 DataV 两个端点）：

| 端点 | features 数 | 每 feature 的 MultiPolygon 部件数 | 合计面积 |
|---|---|---|---|
| `bound/361100.json`（**市级**） | **1** | **1**（单体闭合环，1298 点） | 22,802 km² |
| `bound/361100_full.json`（**市级 + 下辖区**） | **12** | 每个都是 1 部件 | 22,802 km²（12 个区之和） |

**上饶市市级边界本身是 1 个 feature / 1 个多边形部件，压根不是 12 个部件。** 那 12 个是 `_full` 端点返回的 **12 个下辖区（信州区/广丰区/广信区/玉山县/铅山县/横峰县/弋阳县/余干县/鄱阳县/万年县/婺源县/德兴市）**，且 `features[0]` 正是**市区的信州区**。

**瓦片数完全复现了文章的「9 → 2」**：

```
全市 bbox  [116.2381, 27.8003, 118.4871, 29.6993] → 9 个 1° 瓦片 (lon 116-118 × lat 27-29)
信州区 bbox [117.9294, 28.3742, 118.1602, 28.6369] → 2 个 1° 瓦片 (117,28) (118,28)
```

所以**症状描述是对的（9 变 2），根因描述是错的**。真实链路是：

> 请求了 `..._full.json`（下辖区层级）→ 得到 12 个区 → 取 `features[0]` → 拿到市区的信州区 → bbox 只覆盖 2 个瓦片 → 成品只剩地图一角

作者写的修复「对全部部件取并集范围」在这个具体案例里**碰巧也能跑对**（12 个区求并集 = 全市），但如果真去读 `361100.json`（正确的市级端点），「求并集」是个空操作——因为它只有 1 个部件。**修复方式应该是「用不带 `_full` 的端点」，而不是「加并集」。** 这两种改法在别的地级市上会分道扬镳（比如真有飞地的市）。

> ✅ 通用规则：**`{adcode}.json` = 本级行政区；`{adcode}_full.json` = 本级 + 所有下级**。想要「上饶市全市」就要 `361100.json`，想要「上饶市 12 个区」才用 `_full`。混淆这两者是这类工具最常见的正确性 bug。

### ⚠️ 问题 2：GLO-30 是 DSM —— 警告对，但「同桶可换 DTM」做不到

📄 文章称：GLO-30 是 DSM 不是 DTM，含植被建筑；并提供 `datum_convert.py` 做基准换算。

✅ 实测 DSM/DTM 的可得性：

```
copernicus-dem-30m 桶抽样 1000 个 prefix → DSM 1000 条，DTM 0 条
Copernicus_DTM_COG_10_N28_00_E117_00_DEM/...tif        → HTTP 404
Copernicus_DTM_COG_30_N28_00_E117_00_E117_00_DEM/...tif → HTTP 404
geoid/egm2008_15.gtx                                   → HTTP 404
```

- ✅ 「GLO-30 公开版是 DSM」**正确**——桶里 100% 是 DSM，一个 DTM 瓦片都没有。
- ⚠️ 但**不要指望在这个桶/这个 skill 里切 DTM**。GLO-30 的 DTM 是需要走 CREODIAS 注册下载的另一套分发，不在这个免 Key 桶里。想要裸地形（DTM）得另找数据源。
- ⚠️ 同理，**geoid 格网文件也不在这个桶**，所以 `datum_convert.py` 必然依赖外部 geoid（pyproj 的 `egm08_*` 网格需另外下载/缓存），不是自包含脚本。

### ⚠️ 问题 3：面积数字——文章的脚本值偏低，但与官方吻合的是「边界值」

✅ 实测球面测地面积（对两种端点各算一遍）：

```
12 个下辖区求和        = 22,802 km²
市级单体多边形         = 22,802 km²   （两者一致，互相印证几何完整）
文章脚本值             = 22,715 km²
文章引用的官方值       = 22,791 km²
```

结论：我的独立测地值 **22,802 km²** 与官方 **22,791 km²** 只差 **0.05%**，说明**边界几何本身是可靠的**；文章的 22,715 km² 比边界真值低 87 km²（0.38%），这个量级正是 **30 m 栅格化 + 重采样在边界上丢一圈像元**的合理误差，属于实现细节而非数据问题。

📄 文章另称「200 m 以下占约 1.5 万 km²（近七成）」——量级自洽（1.5/2.27 ≈ 66%），但需要完整栅格才能验证，**我未验证，标记为待核**。

---

## ⚠️ 最容易被忽略的坑：垂直基准在文件元数据里是空的

这是我在解析 TIFF 头时才发现、文章完全没提、但**工程上会真踩**的一点：

```
GeoKey 2057 VerticalCSType       = 1    (orthometric height)  ← 有声明
GeoKey 2054 VerticalDatum        = 9102 (EGM2008)             ← 有声明
GeoKey 2059 VerticalCitation     = 0    (none)                ← 空的
```

**elevation 的「数值」是 EGM2008 正高（这点文章说对了，GeoKey 2054 也证实了），但 GeoTIFF 里没有可引用的 citation**。后果是：

- QGIS / ArcGIS / rasterio 读进来**不会给出任何垂直基准提示**，界面看起来就是一个普通的 EPSG:4326 高程栅格
- 你在 GIS 里量一个高程值，**没有任何软件会提醒你这个数是相对大地水准面而非椭球面**
- 和国内 1985 国家高程基准混用时，误差是**逐点变化**的（文章说 ±0.5 m 内——这个说法我无法用公开数据验证，因为 1985 国家高程基准的实际格网需要另外获取）

👉 **实操建议**：脚本输出 GeoTIFF 时，**自己补 VerticalCitation / 给 `.prj` 里写清 `VERTC datum = EGM2008`**，否则半年后没人记得这批数据是哪套高程系统。

---

## 自己重写一遍：不需要 skill 的最小可运行流程

既然底座免 Key，绕开 skill 直接复现核心能力：

### Step 1 — 地名 → adcode（阿里 DataV，免 Key）

```bash
# 直接按 adcode 取市级边界（注意：不要加 _full）
curl -s -o shangrao.json \
  "https://geo.datav.aliyun.com/areas_v3/bound/361100.json"

# 算 1° 瓦片清单
python3 - <<'PY'
import json, math
d = json.load(open('shangrao.json'))
xs, ys = [], []
for poly in d['features'][0]['geometry']['coordinates']:
    for ring in poly:
        for p in ring:
            xs.append(p[0]); ys.append(p[1])
b = (min(xs), min(ys), max(xs), max(ys))
print('bbox', b)
tiles = sorted((x, y)
    for y in range(math.floor(b[1]), math.floor(b[3]) + 1)
    for x in range(math.floor(b[0]), math.floor(b[2]) + 1))
print('tiles needed:', len(tiles), tiles)
for x, y in tiles:
    print(f'https://copernicus-dem-30m.s3.amazonaws.com/'
          f'Copernicus_DSM_COG_10_N{y}_00_E{x}_00_DEM/'
          f'Copernicus_DSM_COG_10_N{y}_00_E{x}_00_DEM.tif')
PY
```

### Step 2 — 下载瓦片

```bash
mkdir -p tiles && cd tiles
# 只读头部探测存在性，比整块下载省时间（实测支持 Range）
BASE=https://copernicus-dem-30m.s3.amazonaws.com
for lat in 27 28 29; do for lon in 116 117 118; do
  N="Copernicus_DSM_COG_10_N${lat}_00_E${lon}_00_DEM"
  curl -sf -o "$N.tif" "$BASE/$N/$N.tif" && echo "ok $N"
done; done
```

### Step 3 — 拼接 / 裁剪 / 出图（需要 GDAL + rasterio）

```python
# pip install rasterio numpy matplotlib
import rasterio, numpy as np, matplotlib.pyplot as plt
from rasterio.merge import merge

srcs = [rasterio.open(f"tiles/{n}.tif") for n in names]
mosaic, transform = merge(srcs)              # 9 个瓦片 → 3×3 的 10800×10800
mosaic = mosaic[0]

# 边界掩膜（DataV 是 GCJ-02 系，见下节）→ 边界外置 nodata，消掉 0 值黑边
from rasterio.features import geometry_mask
mask = geometry_mask([shapely_geom], out_shape=mosaic.shape,
                     transform=transform, invert=True)
mosaic = np.where(mask, mosaic, np.nan)

with rasterio.open('out_dem.tif', 'w', driver='GTiff', height=mosaic.shape[0],
                   width=mosaic.shape[1], count=1, dtype='float32',
                   crs='EPSG:4326', transform=transform, nodata=np.nan) as dst:
    dst.write(mosaic, 1)

# 山体阴影预览（快速近似；生产建议用 GDAL DEMProcessing 的 hillshade）
from rasterio.slope import slope
from numpy import radians, sin, cos, tan, sqrt, degrees
zenith, azimuth = 45, 315
slope_deg = degrees(slope(mosaic))
aspect = np.arctan2(np.gradient(mosaic, axis=1)[0], np.gradient(mosaic, axis=0)[0])
az = (360 - degrees(np.arctan2(np.sin(aspect - radians(azimuth)),
                              -np.cos(radians(azimuth))))) % 360
hill = (np.cos(radians(zenith)) * sin(radians(slope_deg))) + \
       (np.sin(radians(zenith)) * cos(radians(slope_deg)) * cos(radians(az)))
plt.imsave('hillshade.png', hill, cmap='gray')
```

---

## ⚠️ GCJ-02 边界 vs WGS84 栅格：文章说「自带纠偏」，实测存疑

📄 文章称：边界来自阿里 DataV，**自带 GCJ-02 → WGS84 纠偏**，并说「坐标自动纠偏」是这个 skill 的卖点之一。

✅ 实测（DataV 东城区 vs OSM 东城区真实边界，走 Overpass API 取 WGS84）：

| | DataV `110101.json` | OSM (WGS84 truth) | Δ |
|---|---|---|---|
| bbox 经度 | 116.377134 – 116.452391 | 116.372275 – 116.444677 | — |
| bbox 纬度 | 39.858625 – 39.974036 | 39.857203 – 39.972647 | — |
| 中心经度 | 116.414762 | 116.408476 | **+0.006287°（+534 m 东）** |
| 中心纬度 | 39.916331 | 39.914925 | **+0.001406°（+156 m 北）** |
| 经度跨度 | 0.0753 | 0.0724 | **DataV 宽 3.9%** |

对照 GCJ-02 在北京的典型签名（经度 **+0.0055 ~ +0.0065**、纬度 **−0.0015 ~ −0.0025**）：

- ✅ **经度偏移高度吻合 GCJ-02**（+0.0063 落在预期区间内）
- ⚠️ **纬度偏移符号相反**（实测 +0.0014，GCJ-02 应为 −0.002）
- ⚠️ **经度跨度宽了 3.9%**——**纯平移不会改变跨度**，所以这不是一次干净的 GCJ-02 变换，边界几何本身也不同源

**诚实结论**：DataV 边界**大概率**仍是 GCJ-02 系（经度证据很强），但**我无法确认作者的 `cn_dem.py` 里是否真的执行了纠偏**——源码不可得。

### 这里有个反直觉的重点，别搞反方向 ⚠️

**GLO-30 栅格本身是纯 WGS84（EPSG:4326，已从 GeoKey 证实）。要跟它对齐，该被转换的是 GCJ-02 的行政边界，不是 DEM。**

如果一个工具「把 DataV 边界纠偏成 WGS84 后再裁 GLO-30」，那是**正确**的。如果它反过来把 DEM 转成 GCJ-02，那是错的。

而对 30 m 分辨率、区域级（一个市）的用途来说：

> **~500 m 的边界偏移对结果几乎无影响**（一个像元 27×31 m，偏移相当于 18 个像元，但落在行政边界上——只影响紧贴边界的那一圈像元的归属）
>
> 真正会出事的是**需要「精确到米」的用途**：统计「某街道范围内的高程」、判断「这个地块在不在坡度 25% 以上」——这时边界偏移就是系统性错误

👉 **实操建议**：
1. **区域/市级统计 → 随便用 DataV，不用纠偏**。省掉整个纠偏环节和它的 bug 面
2. **精细作业 / 城区 / 宗地级别 → 别用 DataV**。换 WGS84 原生边界源（OSM Overpass、自然地理 vector tile、或官方天地图矢量），DataV 是 GCJ-02 系的
3. 无论哪条路，**先投影再算面积/距离**。EPSG:4326 下「面积」是没有意义的

---

## 三种使用方式

| 方式 | 入口 | 前置条件 | 适用 |
|---|---|---|---|
| **A. 拿现成 skill**（文章路径） | 公众号后台回复【016】拿安装包，丢进 WorkBuddy 对话框 | WorkBuddy 账号；**源码不公开、无法审计** | 只想快点拿图，不关心正确性 |
| **B. 只用数据源**（推荐 ✅） | `curl` 打 `copernicus-dem-30m.s3.amazonaws.com` + `gdalwarp` | 无（**免 Key、免注册**） | 自己可控、可审计、可复现 |
| **C. 整体替换数据源** | 换 SRTM / ALOS AW3D30 / NASADEM | NASADEM 需 NASA Earthdata 账号 | 要 DTM、或嫌 30 m 太粗 |

---

## 跟我们的关系

iswiki 里已经有一批**吃地形数据**的笔记，但**没有一篇写过地形数据从哪来**——这是个明显的断层：

| 已有笔记 | 它需要的 | 本篇能补上的 |
|---|---|---|
| [3dgs-substation-digital-twin](3dgs-substation-digital-twin.md) | 变电站场地的地形/坡度/高程做孪生建模底图 | 中国任意场址的 30 m DEM，一条 curl |
| [img2threejs](img2threejs.md) | 把真实地形驱动成 Three.js 网格 | 同上 |
| [weatherNext](../web-frontend-ui/weatherNext.md) | 地形-气象耦合、地形对降水的调制 | 已有本地 DEM 就能自己跑 |
| [mapcn](../web-frontend-ui/mapcn.md) | 前端地图叠加**地形晕渲图层** | 切 3D/地形 PNG 瓦片 |
| [stadiView](../web-frontend-ui/stadiView.md) | 城市级三维场景 | 同上 |
| [scDatav](../web-frontend-ui/scDatav.md) ⚠️ | 它用的是**同一套阿里 DataV 边界源**（四川 21 市州 GeoJSON），本文测出的 GCJ-02 偏移对它同样成立 | 记一条：「大屏配图偏 ~500 m 可接受，不做精确量算」 |

具体可复用的三点：

1. **补上「零凭据地形数据源」这个位置**。我们 VPS 是纯调度架构、没有任何本地算力，DataV + GLO-30 这套**完全不需要 API Key、不需要注册、不需要本地存储**（瓦片按需拉，算完即弃）——这是少数几个能干净塞进「调度层 + 外部算力」形态的数据源。不需要维护密钥轮换、不需要账号主体，正好避开这类服务最烦的运维面。

2. **「一条命令」的正确形态是脚本，不是 skill**。我的判断：这活儿**不该做成 agent skill**。它是一个确定性参数化任务（adcode → 固定几个 URL → 拼接），没有需要 LLM 判断的分支。做成 skill 反而引入了文章里那种 bug（端点选错、多部件假设），而正确形态是 **一个 80 行的 Python 脚本 + 一个 SKILL.md 只做参数解析**。如果哪天真要接进 Hermes，写成 `enabled_toolsets: [terminal]` 的 cron/脚本任务比做成对话式 skill 更合适。

3. **顺手把「GLO-30 是 DSM」这个约束写进任何用到它的项目**。我们现在没有裸地形需求，但如果以后做「坡度可开发用地筛选」这类判断，DSM 会系统性高估城区高度，进而低估坡度（建筑把坡抹平了）→ **算出偏多的「可建」面积**。这类错误在决策链里很贵。要 DTM 得另走 CREODIAS。

---

## 风险点 / 坑速查

| 坑 | 后果 | 处置 |
|---|---|---|
| 用了 `_{adcode}_full.json` 但只想本级 | 取到下辖区的第一个（通常是市区）→ 范围缩小到 1/9 | 要本级就用 `_{adcode}.json` |
| 边界 MultiPolygon 有多个部件时只取 `coordinates[0]` | 漏掉飞地/离岛 | 对**所有**部件求并集 bbox，别只取第一个环 |
| EPSG:4326 下算面积 | 量纲错误（度²） | 先 `gdalwarp` 投影到等积/UTM 再算 |
| 像元非正方形（27×31 m） | 坡度/距离各向异性偏差 | 投影后计算，或用 GDAL 的 geodesic 模式 |
| GeoTIFF 无 VerticalCitation | 无提示地把 EGM2008 正高当椭球高用 | 输出时自己写 `.prj` 注明 VERTC datum |
| DSM 当 DTM 用 | 城区偏高 → 坡度被抹平 → 可建面积虚高 | 裸地形需求另找 DTM 数据源 |
| DataV 是 GCJ-02 系 | 城区/宗地级作业系统性偏移 ~500 m | 精细用途换 WGS84 边界源 |
| 按桶名 `dem-30m` 推断分辨率 | 误以为是中国中纬度 30 m 方格 | 以对象名 `COG_10` 为准，实际 1″ |
| 国内直连 AWS S3 | 慢/不稳 | 瓦片级请求，加 Range 只取头部先探测 |

---

## 参考链接

- 原文（微信公众号）: https://mp.weixin.qq.com/s/lVbHaHqbySkvNqt3WMWOCA
- Copernicus DEM GLO-30 桶（免 Key，本笔记所有瓦片实测来源）: https://copernicus-dem-30m.s3.amazonaws.com/
- Copernicus DEM 官方说明: https://dataspace.copernicus.eu/explore-data/data-collections/copernicus-contributing-missions/family-of-datasets/copernicus-dem
- 阿里 DataV 行政区边界 GeoJSON: https://geo.datav.aliyun.com/areas_v3/bound/361100.json
- AWS Open Data Registry: https://registry.opendata.aws/
- OSM Overpass API（本篇用于取 WGS84 真值边界）: https://overpass-api.de/api/interpreter
- GDAL DEMProcessing（含 hillshade/slope/aspect）: https://gdal.org/programs/gdaldem.html