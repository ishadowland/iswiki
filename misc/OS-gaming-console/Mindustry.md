# Mindustry — 免费开源的工厂自动化塔防,独立开发者的「教科书级」变现样本

> 学习笔记 · 调研时间 2026-10-08
> 仓库: <https://github.com/Anuken/Mindustry> · 官网: <https://mindustrygame.github.io> · Wiki: <https://mindustrygame.github.io/wiki>
> License: **GPL-3.0** · 语言: Java · ⭐ **29,267** · 最新版 **v160.7**(2026-10-08)· 主版本 **v8**

## 一句话定位

**一人开发 9 年的开源工厂自动化塔防 RTS** —— 用 GPL-3.0 圈住源码生态,同时在四个渠道把**同一份游戏**分别定价为「免费 / 随心付费 / $1.99 / $9.99 买断」,靠免费版拉量、Steam 版收钱,**不卖任何 DLC、不加广告、不加内购**。

## 纠正:原始结论里有 3 处与一手数据不符

调研起点是一段「教科书级操作」的总结,逐条核一手后发现**三处需要修正**:

| 原始说法 | 一手核验结果 | 判定 |
|---|---|---|
| itch.io 免费下载,随意打赏 | itch.io 标注 **"Name your own price"**,v160.7 | ✅ 正确 |
| 手机端(Play / App Store / F-Droid)**免费** | Play 免费 ✅ / F-Droid 免费 ✅ / **App Store $1.99 ❌** | ⚠️ 部分错误 |
| Steam $9.99 买断,另有**一些纯装饰性 DLC** | $9.99 ✅(当前 60% off = $3.99),但 **Steam 上没有任何 DLC** | ❌ DLC 部分错误 |
| 源码随便下载、编译、修改、二次分发 | GPL-3.0,自带完整 Gradle 构建 | ✅ 正确 |
| Steam 卖约 **67 万份**,总收入约 **390 万美元** | 现为 **约 130 万份 / 约 $630 万**(Gamalytic) | ❌ 数据严重过期 |

> **67 万 / $390 万很可能是 2021–2022 年的旧数据**。SteamSpy 与 Gamalytic 两个独立第三方都指向 1M–2M 区间,Steam 后台近期仍在以 60% 折扣促销(说明是长尾运营,不是首发期清库存)。

## 四渠道定价矩阵(2026-10-08 实测)

| 渠道 | 价格 | 版本 | 广告 | 内购 | 关键差异 |
|---|---|---|---|---|---|
| **itch.io** | 自愿付费($0 起) | v160.7 | 无 | 无 | 缺成就 / 无缝联机 / 地图浏览与创意工坊 |
| **Google Play** | **免费** | 最新(10-08 更新) | 无 | 无 | 5M+ 下载,139K 评价,4.5★ |
| **F-Droid** | 免费 | **8-fdroid-160.5(落后主线)** | 无 | 无 | 16+ 内置地图(vs itch.io 的 24),已裁剪 |
| **iOS App Store** | **$1.99** | 8.160.6 | 无 | 无 | 开发者 Anton Kramskoi(Anuke 本人) |
| **Steam** | **$9.99**(现 60% off → $3.99) | 持续更新 | 无 | 无 | 87 成就 + 创意工坊 + 无缝联机 + Steam Cloud |

### 各渠道数据一览

| 渠道 | 关键指标 |
|---|---|
| Steam | 28,373 条评价(27,158 好评 / 1,215 差评,95.7%),22 种语言,164 位鉴赏家,发布 2019-09-26 |
| Google Play | 5M+ 下载,139K 评价,4.5★,「Everyone 10+ / Fantasy Violence」,**不收集数据、不与第三方共享** |
| itch.io | 1,792 条评论,Win/Mac/Linux/Android APK/**独立 server** 直供 |
| App Store | $1.99,v8.160.6(2026-10-07 更新) |

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **零成本完整体验** | itch.io 打包 zip / Play / F-Droid | 只想玩单机与本地合作,不想花钱 |
| **付费买断** | Steam $9.99(常促 $3.99)/ App Store $1.99 | 联机 PvP、创意工坊地图、成就系统 |
| **自建服务端** | itch.io 提供 `[Server]Mindustry.zip`(17 MB) | 局域网 / VPS 开私服,支持插件与自定义游戏模式 |

**免费版与 Steam 版不是同一份东西** —— itch.io 官方页面原话:「Consider buying this game on Steam for features like **achievements, seamless multiplayer and map browsing/Workshop support**」。而 F-Droid 版本地图数从 24 降到 16+,是明确裁剪过的构建。

## 核心架构

```
Anuken/Mindustry (GPL-3.0, Java)
│
├── core/          ★ 823 个 Java/Kotlin 文件 —— 全部游戏逻辑都在这
│   └── src/mindustry/
│       ├── world/      279  ★ 全世界最大的包:方块 / 液体 / 逻辑
│       ├── entities/   147  单位、载具、投射物(comp 组件式)
│       ├── ui/          89  游戏内界面
│       ├── graphics/    42  渲染层(基于 arc)
│       ├── maps/        38  地图加载与序列化
│       ├── logic/       37  ★ 玩家可编程的逻辑指令(Logic block)
│       ├── ai/          32  单位 AI / 敌方波次
│       ├── editor/      30  内置地图编辑器
│       ├── mod/         26  ★ mod 加载器
│       └── net/         16  联机同步
│
├── desktop/  7     桌面端(LWJGL3 + arc)
├── server/   2     独立服务端(可跑在无显卡的 VPS 上)
├── android/  2     Android 端
├── ios/      1     iOS 端
├── tools/    8     精灵打包器
└── annotations/ 18  @Remote 网络 RPC 注解
```

| 项 | 值 |
|---|---|
| 主力语言 | Java(部分 Kotlin,用于注解处理 `kapt`) |
| **构建硬性要求** | **必须 JDK 17,其他版本不工作** |
| 渲染后端 | [arc](https://github.com/Anuken/Arc)(Anuke 自研引擎库,非 libGDX) |
| 代码生成 | `mindustry.gen.*` 全部**构建时生成**:`@Remote` 方法 → 网络包;`entities.comp` 组件类 + `content.UnitTypes` → 单位实体类;资源目录 → `Sounds` / `Tex` / `Icon` |
| 每天自动构建 | [Anuken/MindustryBuilds](https://github.com/Anuken/MindustryBuilds) 每次 commit 自动出包(最新 build 27965) |
| 贡献者 | 374 人,但绝大部分提交来自 Anuke 本人 |

## 安装与最小使用

### 直接玩(推荐,零门槛)

| 平台 | 拿包地址 |
|---|---|
| 桌面 / Android / 服务端 | <https://anuke.itch.io/mindustry> — 自愿付费 |
| Android | <https://play.google.com/store/apps/details?id=io.anuke.mindustry> — 免费 |
| F-Droid | <https://f-droid.org/packages/io.anuke.mindustry> — 免费(版本略滞后) |
| iOS | App Store 搜 Mindustry — $1.99 |

### 自己编译(**必须先装 JDK 17**)

```bash
git clone https://github.com/Anuken/Mindustry
cd Mindustry

# macOS / Linux:首次可能需要授权
chmod +x ./gradlew

./gradlew desktop:run      # 直接跑
./gradlew desktop:dist    # 打包 -> desktop/build/libs/Mindustry.jar
./gradlew server:dist     # 服务端 -> server/build/libs/server-release.jar
./gradlew tools:pack      # 精灵图打包
```

Android 端需要 Android SDK command-line tools、`ANDROID_HOME` 环境变量,产出未签名 APK:

```bash
./gradlew android:assembleDebug    # -> android/build/outputs/apk
```

> Gradle 首次构建要下载大量依赖,`-Xmx8192m` 已在 `gradle.properties` 里配好,耐心等。

## 版本节奏

| 里程碑 | 时间 | 说明 |
|---|---|---|
| 立项 | 2017-04-30 | GitHub 仓库创建 |
| v3.x | 2017–2018 | 早期迭代(itch devlog 仍有记录,2019-02 后迁到 GitHub) |
| Steam 上线 | **2019-09-26** | 至今持续更新,**6 年 11 个月**仍在发版本 |
| v7 → v8 | **2026-04-15** | 大版本更名,`build.gradle` 中 `versionNumber = '8'` |
| v160.7 | 2026-10-08 | 当前最新,近一个月发了 5 个版本(160.2 → 160.7) |

版本号命名是 `v<主版本>.<迭代号>`,即 **160 = v8 的第 160 次迭代**。

## 商业模型拆解 —— 为什么这套打法有效

```
        免费层(GPL 源码 + 免费构建)          付费层(Steam 买断)
                 │                                    │
    itch.io 自愿付费 / Play / F-Droid          $9.99 → 常促 $3.99
                 │                                    │
                 └────── 同一份游戏二进制 ────────────┘
                                    │
                    付费点全部在「社交与创作」,不在「数值」
                    · 成就 87 个      · 创意工坊地图/蓝图
                    · 无缝联机        · Steam Cloud 存档同步
                    · 地图浏览
```

**四条可复用的设计决策:**

1. **付费墙修在「社会性」上,不修在「可玩性」上** —— 核心游戏逻辑完全一致,单机体验零缺失,避免了「阉割单机骗钱」的差评。
2. **零 DLC** —— 创意工坊本身已经承载了 UGC 变现(作者可自愿给打赏),再叠 DLC 只会稀释口碑。**这是 Steam 上罕见的干净做法。**
3. **iOS 单独定价 $1.99** —— iOS 用户支付意愿与转化都低于 PC,用低价位换曝光,而不是用 $9.99 把人挡在门外。
4. **GPL-3.0 而非更宽松的 License** —— 主动放弃商业闭源 fork 的可能性,换取 mod 生态、fork 贡献、移植(Flathub / 各类安卓商店)与长期社区讨论度。

**变现效率对照(第三方估算,Gamalytic 2026-10-08):**

| 指标 | 值 |
|---|---|
| 累计销量 | **1.3M 份**(区间 886.5K – 1.8M) |
| **毛收入** | **$6.3M**(区间 $4.2M – $8.4M) |
| 平均客单价(反推) | ≈ $4.8 / 份 —— 远低于 $9.99 标价,说明**促销日贡献了大部分销量** |
| 平均游玩时长 | 27.2 小时 |
| 好评率 | 96% |
| 日均在线 | 924.6(近 7 天仍卖出 4.4K 份) |
| 关注者 | 47.6K |

> ⚠️ 销量/收入均为**第三方推算**(Gamalytic、SteamSpy),Valve 从不公开真实数字,存在系统性误差。SteamSpy 给出的是宽区间 1M–2M。写对外材料时应标注「估算」。

## 风险与坑点

| 坑 | 说明 |
|---|---|
| **JDK 版本锁死** | README 明确写「必须 JDK 17,其他版本不行」,用 JDK 21 直接编译失败 |
| **`mindustry.gen` 包不存在** | 这是构建时生成的,源码树里找不到,也不该手改 |
| **F-Droid 版本滞后** | 当前 `8-fdroid-160.5`,落后主线 160.7,地图数也被裁到 16+ |
| **SteamDB 拉黑** | 调研时 steamdb.info 直接返回「You have been banned on SteamDB」,只能改用 SteamSpy / Gamalytic |
| **Steam 商店页有 Cookie / 年龄门** | 直接 curl 抓到的是 age gate 页面而非商品数据,需走 `api/appdetails` |
| **App ID 极易记错** | 正确的是 **1127400**,不是 1129490(后者 API 返回 `success:false`) |
| **GPL-3.0 传染性** | 二次分发必须同样开源,且 Play / App Store 的闭源分发方式与 GPL 精神存在张力(F-Droid 与 itch.io 才是合规姿势) |

## 跟我们的关系

- **掌机场景直接可用** —— 归到 `misc/OS-gaming-console/` 分类下:Steam 已验证跨平台 + 支持家庭共享,Steam Deck 友好;itch.io 提供 17 MB 独立 server,可在家用小主机或软路由上开私服。
- **可作「独立开发者变现方案」的对照样本** —— 如果之后要给任何小体量项目定变现模型,这份笔记的四条决策(社交付费墙 / 零 DLC / 移动端低价 / 开源换生态)是可直接复用的框架,尤其在**拒绝在游戏里塞广告和内购**这一点上,它用 630 万美元证明了可行。
- **技术参考价值有限** —— 主体是 Java + 自研 arc 引擎,和我们的前端 / Python 技术栈不重叠;有价值的是 **`mindustry.gen` 构建期代码生成**(注解 → 网络包 / 实体类)这个思路,如果以后做联机游戏可以回看。

## 参考链接

| 类型 | 链接 |
|---|---|
| 仓库 | <https://github.com/Anuken/Mindustry> |
| 每天自动构建 | <https://github.com/Anuken/MindustryBuilds/releases> |
| 引擎 arc | <https://github.com/Anuken/Arc> |
| 官网 / Javadoc | <https://mindustrygame.github.io> · <https://mindustrygame.github.io/docs/> |
| 社区 Wiki | <https://mindustrygame.github.io/wiki> |
| itch.io(免费) | <https://anuke.itch.io/mindustry> |
| Steam(appid **1127400**) | <https://store.steampowered.com/app/1127400/Mindustry/> |
| Google Play | <https://play.google.com/store/apps/details?id=io.anuke.mindustry> |
| F-Droid | <https://f-droid.org/packages/io.anuke.mindustry> |
| Flathub(Arch) | <https://flathub.org/apps/details/com.github.Anuken.Mindustry> |
| 第三方估算 | <https://steamspy.com/app/1127400> · <https://gamalytic.com/game/1127400> |
