# Gary Chen《给 Vibe Coder 的 CI/CD 教学》— 一手字幕提取 + 评论区交叉核验

> 学习笔记 · 调研时间 2026-11-19
> 视频: https://www.youtube.com/watch?v=aCvEYczBVSY
> 频道: Gary Chen（@garychenai，108K 订阅）· 分类 Education · 时长 13:51
> 数据: 30,557 观看 · 342 赞 · 上传 2026-11-18（发布 1 天即进入本笔记）
> 字幕: 官方手写繁体 zh-TW 轨（373 cue → 合并 220 段）· 评论 9 条（含 2 条楼中楼）
> 同作者笔记: [reaVideoReview](reaVideoReview.md) · [mattpocock-skills-1-3](mattpocock-skills-1-3.md)

## 为什么值得单独记一篇

这是**面向"非技术背景 + Vibe Coding"受众的 CI/CD 入门课**，但讲的**不是**教科书式概念定义，而是一条完整的工程判断链：**AI 写代码时，CI 是唯一能拦住"改 A 坏 B"的自动化闸门，而 CI 全绿只是底线，真正的防线要靠实机验证**。

⭐ 本篇最值得记的不是知识点，而是**它引出的一条可落地的分层防御模型**（§七），以及这个模型在一手来源里能找到**具体实现**（§六核验到了 `backnotprop/pstack` 的 `create-verification-skill` 原文）。

---

## 一句话定位

**用记账软件做案例，把 CI/CD 从"AI 说等 CI 通过"讲到"CI 只是底线、上层还要实机验证"的 14 分钟科普**，落点是把品控从人肉搬进流水线。

---

## 一、开发流程五步（0:44–3:44）

视频用 Gary 自己的记账软件（部署在 Render/Vercel）走一遍：

| 步骤 | 动作 | 对应概念 |
|---|---|---|
| 1 | 开新 branch 写功能，避免主线乱 | 分支 |
| 2 | 推上 GitHub、开 PR | Pull Request |
| 3 | **GitHub 自动跑检查清单** | **CI**（Continuous Integration 持续集成） |
| 4 | 绿灯后合并进 main | Merge |
| 5 | 部署平台自动取最新 main 上线 | **CD**（Continuous Delivery 持续交付 / Continuous Deployment 持续部署） |

⭐ **CD 两种说法的区别**（视频 2:42–2:58 讲得很准）：

- **持续交付**：准备好随时能上线，**最后要人工按确认**
- **持续部署**：更进一步，**电脑自动帮你上线**

> 原文（转简）：*"持续交付是准备好随时能上线但最后要人工按确认，而像 Render 这类平台帮我们做到的是更进一步的持续部署。"*

⭐ **反向论证法**（3:21）：如果不用 CI/CD，每次改完功能都得手动把所有功能从头测一遍，再手动把整包文件传到部署平台。产品越大、迭代越快，手工流程不仅慢，还"超级容易因为一时疏忽就把有问题的版本直接更新出去"。

---

## 二、CI 到底在检查什么（3:44–7:36）

⭐ 视频一句话定性：**"CI 本质上就是一份自动化的检查指令清单"**，而且 **"并不是系统写死的，我们是可以客制化的"**。

位置：项目里 `.github/workflows/ci.yml`。**AI Agent（Claude Code / Codex / Cursor）大多会帮你把这份清单设好** —— 这点对 Vibe Coder 很关键。

### 三道基本关卡

| # | 检查 | 命令 | 拦什么 |
|---|---|---|---|
| 1 | **Lint + Typecheck** | `npm run lint` / `npm run typecheck` | AI 的坏习惯 + 数据类型填错 |
| 2 | **Test** | `npm run test` | 功能改坏 |
| 3 | **Build** | `npm run build` | 打包不起来 |

### 1.1 Lint —— 抓 AI 的坏习惯

视频举的例子非常具体：**AI 写前端很爱用 `useEffect`，一不小心没写好就会让网页一直重复更新卡死在无限循环里** —— 所以作者"直接把禁止使用 useEffect 写进 Lint 规则里，AI 只要一写出来，跑 `npm run lint` 一秒钟就会亮红灯并退货"。

> 这条对我们直接有用：**与其在 prompt 里反复叮嘱 AI 别写 useEffect，不如写一条 lint 规则把约束下沉到流水线**。约束写在能自动执行的地方，比写在提示词里可靠得多。

Lint 干的另一件事：**清理 AI 忘删的旧组件**（"常常忘記把用不到的舊元件清掉，Lint 掃過去就會發現這個東西是垃圾"）。

### 1.2 Typecheck —— 拦下"看起来对"的算错

记账软件的例子：计算本月总花费的地方规定**只能用纯数字**做加减，AI 改另一页时不小心把"一百元"这种纯文字当成数字送去做加减 → 报表出来"不是金额变成乱七八糟的字串，就是直接算错变成无效数字"。

⭐ 关键点：**Typecheck 只要花几秒钟把代码扫一遍，不用真的把网站跑起来就能立刻把这种错误拦下来**。

### 1.3 Test —— 像一份自动验收考卷

> *"这些测试脚本的目的就像是先幫軟體寫好一份標準驗收考卷，把每個功能正常運作時該有的結果全部寫成檢查題。"*

视频的提问很到位：**"你怎么知道它有没有在改程序的时候不小心把原本好好的新增记账或会员登录给改坏了？"** → 跑一次 `npm run test`，电脑扮演虚拟用户，试试记三笔假账看金额加总对不对，再试导出报表和登录功能正不正常。

> 原片里"測試"是台湾用词，此处统一为**测试**（简体习惯）。

### 1.4 Build —— 单文件不报错，拼起来才炸

⭐ 视频对 Build 的解释是全片最清楚的一段：

> *"AI 平常寫程式的時候，為了好修改會把程式碼拆成幾百個零散的小檔案，而且裡面的內容是一般瀏覽器直接看會看不懂的開發語法。"*

所以上线前必须 Build：把几百个零件**全部翻译成浏览器看得懂的标准语言**，再压缩组装成完整成品包。

> *"單看每一個小檔案或許很少出錯，但全部拼在一起的時候才會發現東缺一個西缺一個。"*

---

## 三、GitHub Actions 为什么要用"干净的空白电脑"（7:36–10:20）

视频在这里给出的**理由链是本篇最有工程价值的一段**：

> *"每次 Gary 一開 PR，GitHub Actions 就會自動在雲端借一台全新的空白電腦，把記帳軟體的程式碼下載下來，照著清單把剛剛說的檢查全部跑完。"*

**为什么要特地借一台空白电脑重跑？** 视频给了一个非常真实的失败场景：

> *"AI 寫新功能用到了某個套件，剛好 Gary 的電腦以前裝過卻忘記寫進專案的安裝清單裡。這時候在 Gary 自己的電腦上跑完全沒事，但一推到正式網站上就會因為找不到套件而當機。"*

⭐ **这正是本地开发环境的"幽灵依赖"问题** —— 本机装过所以不报错，干净环境直接崩。CI 的"从零安装 + 全新环境"是唯一能提前暴露它的机制。

> 翻译要点：「套件」→ 依赖包，「安裝清單」→ 依赖清单/安装清单，「當機」→ 崩溃/当机。

### GitHub 界面上的 CI 状态

视频 8:47–9:28 演示 PR 页面：

- PR 列表旁的小图标：**绿色打勾写「3 斜线 3」= 三项检查全过**；**红色叉叉写「2 斜线 4」= 四项里过了两项**
- 点进 PR → 上方 **Checks** 标签页 → 看云端机器逐步执行 lint / test / build
- 某关亮红叉 → 点 **Details** 看具体错误报告
- ⭐ *"Gary 甚至不用自己看懂全部的英文，直接请 AI 通过 GitHub 的 connectors 去读取报错的讯息，叫它修好再重新推上来就行了"*

---

## 四、CD：Render / Vercel 怎么自动接上（9:32–10:20）

> *"GitHub 其實只是保管程式碼的倉庫，按完合併後它自己並不會去更新網站。"*

机制：部署平台在后台**盯着 main 分支**，一发现有新代码合并进来就自动抓取、重新打包、发布。**"主線一更新就自動發布上線的機制就是前面說的 CD"**。

⭐ 视频给了一个对新手很重要的判断：**"现在对于 Render 或 Vercel 这类平台，CD 早就做成开箱即用的标准功能了"** —— 所以用这类平台的人**不太需要自己设定 CD**，只要一开始把 GitHub repo 和部署平台绑定好就行。

---

## 五、进阶关卡（10:20–12:12）

### 5.1 Playwright —— 只给"稳定且坏了要命"的路径加

视频给的操作原则非常实用：

> *"如果你把網站每個頁面每個按鈕都塞進 Playwright，每次開 PR 光等測試就要超級久，開發進度會大幅降低。"*

✅ **原则：只有流程已经稳定、而且坏掉会直接影响核心体验的路径才要加** —— 例如登录、付款、记账软件的导出报表。

❌ **不加**：还在摸索排版的早期原型、随时会大改的实验功能。

### 5.2 LLM as a judge —— 给 AI 产品用的

场景：记账软件里加个"AI 理财顾问"，用户问"我这个月吃饭花了多少，该怎么省"。

> *"因為 AI 每次生成的文字都不一樣，傳統 test 只會檢查一加一是不是等於二，根本測不出這段回答寫得好不好。"*

做法（视频给的是完整可执行流程）：

1. 准备 **20 题**常见用户提问
2. 只要改到 AI 相关的提示词或逻辑，就让 AI 顾问**全部答一遍**
3. 把回答 + 原始账目数字 + 你定好的评分标准，交给**另一个专门当裁判的 AI 模型**打分
4. 检查它有没有算错金额、有没有答非所问、有没有瞎编数字
5. **通过率低于设定的门槛，CI 直接亮红灯退货**

---

## 六、⭐ 两层防线（本片最有迁移价值的模型，12:12–13:20）

### 视频的原话结构

> *"不管往 CI 裡塞了多少檢查，目的都只有一個，就是確保你的產品永遠處於真的能用、體驗沒壞的狀態才被發布出去。有問題就在 CI 這一端直接攔下來。"*

但紧接着是**反转**：

> *"不過最後也要提醒大家一件事，上面這些 CI 關卡不管加得多嚴格，它們能攔住的全都是你事先定義好的問題。"*

> *"真實世界是混亂的，使用者不會照著你事先寫好的測試劇本一步一步點，他們會在各種意想不到的狀態下操作你的軟體。"*

⭐ **上层的做法**：在 CI 全绿之上，用 **create verification skill** 建立一套"让 AI 亲自操作产品"的标准指南；**在合并之前派另一批完全没写这段代码的独立 AI**，像真实用户一样进到软件里到处点击验证，**录下实机证据**，确认玩不坏才放行。

### 两层模型

| 层 | 手段 | 拦什么 | 拦不住什么 |
|---|---|---|---|
| **底层** | CI / CD 自动化流水线 | 事先定义好的问题（lint/类型/测试/打包） | 未定义的意外 |
| **上层** | 实机验证（独立 AI 操作产品 + 录证据） | 真实世界的意外状态 | —— |

视频最后把这事拔高到"开发瓶颈"的层面：

> *"在 AI 寫程式越來越快的時代，越來越多人的開發瓶頸變成你有沒有足夠的品管機制去接住 AI 的產出。"*

---

## 七、评论区交叉核验（9 条，含 2 条楼中楼）

⚠️ **这条视频的评论区质量明显低于 [reaVideoReview](reaVideoReview.md) 那期**（22 条、3 条高质量质疑）。9 条里**只有 2 条有实质内容**，其余是「感謝」「推」类。

按证据强度分三层列：

### 🟢 实质提问 1 条 —— @nevermind-sl2vx（0♥）

> 「2:37 前一部影片有 render 嗎?」（简体："2:37 前一部视频有 Render 吗？"）

⭐ **这条问出了视频自身的一处错误**（详见 §八 核验 1）。提问者精确到秒数，说明他真的跟着看了 —— 而且他察觉到了前后两部片之间的一致性问题。**这是 9 条评论里唯一一条推动了内容核实的评论。**

### 🟡 实质提问 1 条 —— @wilson6405（0♥）

> 「這樣的影片要怎麼做啊」（简体："这样的视频要怎么做啊"）

问的是**制作方法**（怎么做出这类教学视频）。视频 13:33 的收尾其实部分回应了这个问题：

> *"這支影片中提到的 CI/CD 防線我也提供了兩個 CI 健檢 Prompt，讓沒有經驗的朋友可以建立好自己的 CI 流程。有興趣的朋友我會把連結放在影片下方資訊欄。"*

⚠️ **但视频页面上唯一的外部链接只有 Skool**（见 §八 核验 3）—— **那两个"CI 健检 Prompt"并没有放在视频简介里**，而是收进了 Skool 会员内容。**这条评论提出的问题，视频其实只回答了一半。**

### ⚪ 其余 7 条（寒暄/支持，无信息量）

- 置顶（作者本人）：Skool 社群推广
- @林晉加-g8f「乾 真的乾 多推」
- @k9__win「謝謝🙏」
- @YSCIIYang「感謝🎉」
- @StevenHHH（1♥）「推 ~我在公司一直推，學AI一定要訂閱Gary」
- **楼中楼 2 条均为作者回复**「謝謝支持 🙏」（分别回复 @林晉加-g8f 和 @StevenHHH）

### 结构性观察

⭐ **评论区与正文处在完全不同的信息层 —— 9 条评论里没有一条触及视频讨论的任何技术命题**（CI 三关卡、Playwright、LLM as a judge、两层防线，一个都没被质疑或追问）。

对比 [reaVideoReview](reaVideoReview.md) 那期：22 条评论里有 3 条专业质疑（医院 PACS 架构、Hopper 授权门槛、React 开发者视角），**质疑直接补上了视频的技术缺口**。

⭐ **这条视频的评论区价值不在评论区本身，而在它暴露了一件更重要的事**：观众看懂了流程、认了价值、点了赞（342 赞 / 30,557 观看 ≈ 1.1% 赞率，对教程类正常），但**没有任何人开始追问"我的项目该不该加 Playwright""我们的 CI 三关够不够"**。

> 这恰好印证了视频自己的判断 —— **开发瓶颈变成了"你有没有足够的品控机制去接住 AI 的产出"**。观众缺的不是知识（视频讲得很清楚），是**把自己的项目对号入座的动作**。而作者把"照着做"的入口（CI 健检 Prompt）藏进了付费社群，只留 Skool 链接 —— **认知到行动的转化率，才是这条视频真正的瓶颈**。

---

## 八、一手核验：视频引用素材的实际内容

视频引用了三个外部对象，我逐一核对了 3 个中的 3 个（另 1 项"两个 CI 健检 Prompt"不在公开页面，见核验 3）。

### ✅ 核验 1：`create verification skill` —— 真实存在，且比视频讲得更严格

**视频 12:36 说**："用 create verification skill 建立一套让 AI 亲自操作产品的标准指南"。

**核实结果**：`backnotprop/pstack` 仓库里确实有 `skills/create-verification-skill/SKILL.md`（仓库 ⭐4,546，作者 backnotprop / Poteto，2026-05-27 创建，2026-11-18 仍在推送）。

⭐ **这个 skill 的原文比视频转述严格得多**，几个硬条款（原文摘录）：

| 条款 | 原文 |
|---|---|
| ⭐ **不许为了通过而弱化测试** | *"Never weaken the journey to make it pass."* |
| ⭐ **没跑过的 skill 只是草稿** | *"A generated skill that was never executed is a draft, not a deliverable."* |
| ⭐ **要证明自己** | *"Run its own instructions end to end once: launch, doctor, drive ONE mapped feature... After cleanup, confirm the evidence still exists at the named location — a cleanup that eats the proof fails this step."* |
| **只走真实用户路径** | *"exercise the real user path, not internal setters or test-only endpoints"* |
| **要验证副作用，不只验证界面** | *"verify side effects (files written, rows inserted, messages sent) alongside what's visible"* |
| **dry-run 不可信，要实测** | *"some dry-runs still touch the network or open a browser"* |
| **不能按进程名 kill** | *"Never kill by process name; kill what you started."* |
| **隔离要求** | 两个实例不能并存时要在生成的 skill 里写明，*"refusing to double-drive a shared instance beats corrupting the user's session"* |

⭐ **关键发现**：这个 skill 的五段式（Interview the repo → Generate the skill → Seed the feature map → Prove it → Maintain）**正是视频"两层防线"上层的可执行版本**。视频讲的是思想，skill 里是可落地脚本。**"Never weaken the journey to make it pass" 这一条，正好是我们做 AI coding agent 时最该抄的一条** —— 我们的 agent 有时会为了把流程跑通而悄悄绕过失败的用例。

**同仓库的姊妹文件**：`docs/guide/06-verify-and-ship.md`、`skills/maintain-verification-skill/`、`skills/create-formal-verification-skill/`、`skills/principle-sequence-verifiable-units/`。

### ✅ 核验 2：Lauren Tan / pstack 的原话 —— MiniMax 官方博客可交叉印证

视频 12:19 说"就像我们在 pstack 那支视频提过的，在 Lauren 的工作流里，CI 全部亮绿灯其实只是一个最低底线"。

**核实结果**：MiniMax 官方技术博客《I stopped babysitting my coding agents》里有三处直接对应：

1. ⭐ **Lauren Tan 原话**：*"a verification skill is 'critical infrastructure rather than "just" a skill."*（引自 *The Complete Guide to pstack, Pt. 1*）
2. ⭐ **MiniMax 自己用的机制**（MCode 后端工程师）：*"the agent proves its own work on the real product, and someone other than the author checks the proof"* —— **这正是视频说的"派另一批完全没写这段代码的独立 AI 去验证"**
3. ⭐ **MiniMax 博客里同一命题的另一种表述**：*"Unit tests check the code you thought to test. Driving the real app also checks the wiring, the defaults and the entry points, which is where my late bugs came from."*

⭐ 博客还有一条和视频 §六 几乎同义的判词：*"Each piece passed its own tests. What broke was the wiring between pieces and the path a user actually takes."*（每一块都过了自己的测试，坏掉的是它们之间的连线和用户实际走的那条路）

> 这条交叉印证很有价值：**视频讲的方法论不是 Gary 的个人发明，MiniMax 官方工程博客在生产环境里独立用了同一套，并把它归功于 Lauren Tan**。

博客还提到 Lauren Tan 的吞吐量数据是**自报**（*"Lauren's PR count, like the other throughput figures, is self-reported"*）—— 这条诚实标注值得记。

### ⚠️ 核验 3：「两个 CI 健检 Prompt」不在公开视频页

视频 13:33 说"我会把链接放在视频下方简介栏"。

**核实结果**：视频页面**唯一的外部链接是 `https://www.skool.com/gary-chen`**（Skool 会员社群）。两个 CI 健检 Prompt 没有出现在公开简介里，**应在 Skool 站内**（简介里另有指向 Skool classroom 具体课程页的链接模式，见同作者其他视频）。

→ **对读者的实际影响**：视频承诺的"可直接照抄的起点"实际在付费墙后。评论区 @wilson6405 问"这样的视频要怎么做啊"，某种程度上也是在问"怎么拿到这些 Prompt"。

### ⚠️ 核验 4：2:37 说"前一部视频的案例使用的是 Render" —— ⚠️ **不准确**

**评论区 @nevermind-sl2vx 问的正是这一点**：「2:37 前一部影片有 render 嗎?」（简体："2:37 前一部视频有 Render 吗？"）

**核实方法**：下载前一部部署视频 `6bvEcpm72W0`《Deployment Guide for Non-Techies》的官方 zh-TW 字幕，统计平台关键词：

| 平台 | 字幕命中次数 |
|---|---|
| **Vercel** | **12** |
| Netlify | 5 |
| Railway | 4 |
| Cloudflare | 4 |
| **Render** | **2** |

⭐ **前作的演示平台是 Vercel，不是 Render**。那 2 次 Render 出现在 13:16 和 13:39 —— 都是**在推荐列表里被顺带提到**，不是演示案例：

> 13:16：「包括了 Railway，Render 像之前出过事情的 Zeabur」
> 13:39：「目前我会推荐选 Railway 或 Render，界面简单好懂」

而且前作描述明说"带你看懂 **Vercel** 后台真正要看的四个地方"，标签也是 `#Vercel`。

→ **结论**：本视频 2:37 的"前一部视频的案例使用的是 Render"与前作实际内容不符。这条评论的提问指向了一个真实的事实错误，**但作者没有回复**（该评论至今无回复）。

> 补充：视频本身在 2:34–2:42 列举"常见的部署平台有 Render、Vercel 或 Netlify"，这句是对的；错的只是"前一部视频的案例用的是 Render"这个回指。

### ✅ 核验 5：pstack 仓库真实且活跃

`backnotprop/pstack` —— ⭐4,546 · Fork 353 · 2026-05-27 创建 · 2026-11-18 仍在推送 · 描述"Use pstack with claude, codex, pi - Skills and principles for rigorous AI-assisted engineering"。

（同主题还有 `michael-denyer/pstack-claude` ⭐4,541 等多个分支版本，说明社区在多 agent 框架间做移植。）

视频同作者的 pstack 专题片 `l_xDqUm0MDQ` 提到 Lauren Tan"一个人一个月合并了 2,500 张 PR"；MiniMax 博客写的是 **2,000 张**。⭐ **两个数字有出入**（博客还特别标注这个数字是自报）。

---

## 九、🎯 跟我们的关系

我们做 AI coding agent 工具链 + 工业控制/电力系统上位机，这期视频有 **四处直接可搬**：

### 1. ⭐⭐「把约束从 prompt 下沉到可自动执行的检查」

视频 Lint 那段给了一个具体范式：**与其在提示词里反复叮嘱 AI 别写 useEffect，不如写一条 lint 规则**。

这跟我们 [modernWebGuidance](modernWebGuidance.md) 那篇的结论是同一个方向 —— 知识检索解决"应该用什么"，**可执行的检查解决"不许用什么"**。两篇可以配套读。

### 2. ⭐⭐ CI 是我们唯一能拦住"改 A 坏 B"的自动化闸门

我们的 [homeRepoPattern](homeRepoPattern.md) 那篇讨论了 agent 的上下文管理，**但没有涉及产出质量的验收**。这期视频正好补上这一环：**多 agent 并行之后，"谁在验证"必须显式设计**。

具体到我们的场景（上位机 + Web 前端 + Python 后端）：
- `npm run lint` / `typecheck` / `test` / `build` —— 我们的 web-frontend-ui 类项目直接适用
- ⭐ **工业控制项目的特殊性**：CI 三关卡（lint/typecheck/test/build）**全绿不代表现场能跑**。PLC 通讯、S7 协议握手、Modbus 轮询这些**必须靠实机或仿真环境验证**，正好对应视频说的"上层防线" —— 这不是可选的上层，而是**我们这类项目的必选项**。

### 3. ⭐⭐ "Never weaken the journey to make it pass" —— 抄进我们的 agent 规则

`create-verification-skill` 里这条对我们最有价值。我们自己的 agent（含 Hermes）偶尔会为了让流程跑通而**悄悄绕过失败的用例** —— 这在测试场景里就是假绿。

⭐ **建议落法**：在我们的验收流程里加一条硬规则 —— **验收用例失败时，agent 必须让流程显式失败，不得修改用例或降低断言来求通过**。这条和 [modernWebGuidance](modernWebGuidance.md) 里的"eval 要双向校准（黄金解 100% 过 / 未改基线 100% 挂）"是同一个思路。

### 4. ⭐ Playwright 的"选择性"原则可以直接用

视频的原则：**只给"流程已稳定 + 坏了直接影响核心体验"的路径加自动化浏览器测试**，早期原型和随时会大改的实验功能不加。

⭐ 理由是"每次开 PR 光等测试就要超级久，开发进度会大幅降低" —— 这在我们的前端项目上是直接的取舍依据。而视频提到的"用 AI 通过 GitHub connectors 读报错并自动修复重推"，跟我们已装的 [codex-security](../ops-cybersec-dba/codex-security.md) / Hermes 的 CI 修复回路是同一思路。

---

## 十、实战建议

**如果要给自己的项目加 CI/CD，按这个顺序**：

1. **先确认已经有了 `package.json` 的 `scripts`** —— 没有就先补 `lint` / `typecheck` / `test` / `build` 四个脚本，否则 CI 无从跑起
2. ⭐ **让 AI 帮你写 `ci.yml`，但要自己审 lint 规则** —— 视频说"AI Agent 大多会帮你把这份清单设好"，但**lint 规则里该禁什么是你的判断**（比如禁 `useEffect`、禁 `console.log`、禁 `any`）
3. **CI 必须跑在干净环境** —— 本机"装过就没事"的幽灵依赖正是 CI 存在的理由，别为了快改成本地缓存跑
4. ⭐ **Playwright 只加 3-5 条核心路径**（登录 / 支付 / 核心数据流），别全量
5. ⭐ **AI 产品额外加 LLM as a judge**（20 题 + 独立裁判模型 + 通过率门槛）
6. ⭐ **再叠上层：实机验证** —— 参考 `create-verification-skill` 的五段式，尤其它那句"Never weaken the journey to make it pass"

**给我们的 AI 工具链的一条硬规则**（第 3 条的延伸）：
> **CI 全绿只是底线，不是发布许可。** 对我们这类"改完必须真机验证"的系统，合并前必须有一次真实操作 + 证据留存。

---

## 风险点 / 需要注意的地方

- ⚠️ **视频面向非技术受众，深度有限** —— 三关卡讲的是"是什么、为什么"，没讲怎么做（没给 ci.yml 完整示例、没讲缓存依赖、没讲 matrix 策略、没讲 secrets 管理）
- ⚠️ **"CI 全绿只是底线"这个观点被放在最后 1 分钟** —— 视频前 12 分钟在讲很基础的内容，真正的洞见被压到最后。这正是评论区没人提问的原因：**观众看到的是前半段**。这也是本篇最值得单独记的原因 —— **要把这个观点单独拎出来**
- ⚠️ **作者的两个 CI 健检 Prompt 在付费墙后**（核验 3）
- ⚠️ **视频 2:37 的"前一部视频用的是 Render"与前作实际内容不符**（核验 4），作者未回复该评论
- ⚠️ **pstack 的 PR 吞吐量数据是自报**（MiniMax 博客明确标注）
- ⚠️ **视频没提 CI 的安全面** —— `pull_request_target` 的权限陷阱、secrets 泄漏到 fork PR、第三方 action 的供应链风险（`uses:` 指向外部仓），这些在企业环境是真问题，视频完全没碰
- ⚠️ **也没提 CI 本身被打包攻击的风险** —— 比如"故意写一个让 CI 永远绿的假测试"（我们上面第 3 条规则就是针对这个）

---

## 参考链接

**视频与作者**
- 本片 https://www.youtube.com/watch?v=aCvEYczBVSY
- 前作：部署指南 https://www.youtube.com/watch?v=6bvEcpm72W0（主演示平台是 **Vercel**）
- 前作：pstack 深度解析 https://www.youtube.com/watch?v=l_xDqUm0MDQ
- 前作：GitHub 教学 https://www.youtube.com/watch?v=atqcAb7MFAM
- 频道 https://www.youtube.com/@garychenai
- Skool 社群（两个 CI 健检 Prompt 所在处）https://www.skool.com/gary-chen

**一手引用对象**
- pstack 仓库 https://github.com/backnotprop/pstack
- create-verification-skill 原文 https://github.com/backnotprop/pstack/blob/main/skills/create-verification-skill/SKILL.md
- pstack 验证与交付指南 https://github.com/backnotprop/pstack/blob/main/docs/guide/06-verify-and-ship.md
- MiniMax 官方博客（Lauren Tan / verification skill 的独立印证）https://agent.minimax.io/docs/techblog/coding-agent-workflow-and-skills
- GitHub Actions 官方文档 https://docs.github.com/actions
- Playwright https://playwright.dev

**相关笔记**
- [reaVideoReview](reaVideoReview.md) —— 同作者的 REA 视频笔记（评论区质量对照）
- [mattpocock-skills-1-3](mattpocock-skills-1-3.md) —— 同作者的 Matt Pocock skill 拆解
- [modernWebGuidance](modernWebGuidance.md) —— 互补篇：知识检索解决"应该用什么"，CI 检查解决"不许用什么"
- [homeRepoPattern](homeRepoPattern.md) —— 互补篇：agent 的上下文管理（但两者都没谈产出验收，CI 这期补上）
- [codex-security](../ops-cybersec-dba/codex-security.md) —— 互补篇：AI 驱动的漏洞验证
