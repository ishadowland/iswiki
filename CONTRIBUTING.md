# iswiki 维护规范

> 学习笔记库的写作 / 提交 / 协作规范
> 完整 skill 流程见: [note-taking/iswiki-writing](https://github.com/ishadowland/hermes-agent) (位于 coder profile 的 skills/note-taking/iswiki-writing/SKILL.md)

## 1. 目录结构(2026-09-11)

```
iswiki/
├── README.md                       # 根索引
├── ai-vibecoding-agents/          # 🤖 AI agent / 编排
├── ops-cybersec-dba/              # 🛠️ Linux 运维 / 安全 / DBA
├── web-frontend-ui/               # 🌐 Web 前端 / UI / 前端可观测
├── developer-productivity/         # ⚡ 开发者生产力
├── misc/                           # 📌 Misc(含 OS-gaming-console 子目录)
└── assets/                         # 🖼️ 插图目录(按 doc 名分子目录)
    └── <topic-name>/               #   - 01-keyword.webp
                                    #   - 02-keyword.webp
```

**新 doc 必须放对应分类下**(不是 root)。

## 2. 端到端写作流程(7 步)

```
[源 URL]
  ↓
1. fetch + 抓数据(gh api / curl)
  ↓
2. 提取章节结构(分析 5-15 个章节)
  ↓
3. 提取插图(下载 + 视觉验证 + WebP 压缩)
  ↓
4. 写 Markdown 主文档(嵌入插图到合适章节)
  ↓
5. 更新 README.md 索引
  ↓
6. git commit + push(retry 3-5 次绕开 GitHub firewall)
  ↓
7. 验证 + 通知
```

## 3. 写文档 8 大原则

1. **去除营销话术** —「效率提升 85%」之类没来源的数字不要写
2. **技术原理必含** — 不能只是 feature list,要讲为什么这样设计
3. **跟同类对比** — 跟相关项目/技术对比,展现相对位置
4. **ASCII 图优先** — 流程图 / 架构图用 ASCII 画,零成本
5. **插图放合适章节** — 不是堆顶部,而是在最相关章节内引用
6. **TL;DR 必含** — 给决策者 1 句话
7. **可借鉴元素** — 提取对作者自己的项目有启发的点
8. **相关 iswiki 交叉引用** — 链接到已存在的相关 doc

## 4. 插图处理规则

### 4.1 必须有的图

- ✅ 官方仓库的 teaser / overview(主题相关)
- ✅ 关键功能截图
- ✅ 对比图(方法 A vs 方法 B)
- ✅ 架构图(可用 ASCII 替代)

### 4.2 不要的图

- ❌ 跟主题**不符的场景**(如 3DGS 论文里的公园自行车对变电站没用)
- ❌ 营销图(产品宣传 / 客户 demo)
- ❌ 低分辨率截图
- ❌ 包含私人信息的截图

### 4.3 命名规范

```
<序号>-<场景关键词>.<ext>

# 好例子:
01-overview.webp       ← 总览
02-skeleton-only.webp  ← 只看骨骼
03-femur-detail.webp    ← 选中 femur + 详情

# 坏例子:
diagram1.png           ← 太泛
image_final_v2.jpg     ← 含版本号
```

### 4.4 格式选择

| 格式 | 何时用 | 体积 |
|---|---|---|
| **WebP (quality 85)** | 优先选择 | ~30% smaller than PNG |
| PNG | 原始高质量(可选压缩后转 WebP) | 大 |
| JPG | 真实照片(WebP 优先) | - |
| ASCII | 流程图 / 架构图 / 对比 | 0(代码内) |

### 4.5 视觉验证(必须)

每张图都用 `vision_analyze` 验证:
- 是不是跟主题相关?
- 内容是什么?(caption)
- 放哪个章节?

**如果图不相关 → 删掉**。

## 5. 文档模板

```markdown
# <项目名> — <一句话定位>

> 学习笔记 · 调研时间 <YYYY-MM-DD>
> GitHub: <URL> · 官网: <URL> · 文档: <URL>
> License: <LICENSE> · 语言: <Lang> · ⭐ <N> · 最近提交 <日期>

## 0.5 配图速览(可选)

| 场景 | 截图 |
|---|---|
| 总览 | ![](assets/<topic>/01-overview.webp) |
| ... | ... |

## 1. 一句话定位
...

## 2. 核心数据
| 字段 | 值 |
...

## 3. 核心架构 + ASCII 图
```

## 6. 提交规范

### 6.1 commit message 格式

```
docs: add <topic> (<简短描述>)

<2-3 行摘要:来源 + 核心要点 + 配图>

Highlights:
- ⭐ <N>
- <关键 feature 1>
- <关键 feature 2>
- 配图 N 张(<asset 路径>)

参考:
- <URL>
```

### 6.2 push 失败重试

GitHub 在公司网络下 TLS handshake 经常 timeout,**必须 retry 3-5 次**:

```bash
for i in 1 2 3 4 5; do
  output=$(git push origin main 2>&1)
  echo "Attempt $i: $output"
  if echo "$output" | grep -q "main -> main"; then
    echo "✓ Pushed"
    break
  fi
  sleep 30
done
```

## 7. README.md 索引更新

新 doc 必须在 README.md 加一行:

```markdown
- [doc-name](doc-name.md) — <一句话描述>(<⭐ N> ⭐, <关键事实>)
```

**位置**:插在对应分类目录下(参考现有 5 个分类)。

## 8. 评估 checklist

每篇 iswiki doc 提交前自检:

- [ ] 1+ 张相关插图(原文 / ASCII / 官方仓库)
- [ ] 图片放在最相关章节,不是堆顶部
- [ ] 每张图有 takeaway / caption
- [ ] 文件格式优先 WebP
- [ ] assets/<topic>/ 目录结构化
- [ ] 命名规范(`01-<keyword>.webp`)
- [ ] README.md 索引更新
- [ ] commit message 格式正确
- [ ] push 成功(显示 `main -> main`)
- [ ] 远程验证(gh api)

## 9. 跨 agent 协作

多个 agent 可能同时写 iswiki:

- **冲突避免**:用 `git fetch origin` 确认本地 = 远端,再开新 doc
- **分类一致**:doc 必须放对分类,放错会被后续 reviewer 移动
- **配图协作**:一人写主文档,另一人加配图(如 commit 2c7992b humanAtlas)
- **命名空间**:插图 assets/<doc-name>/,避免 doc 名冲突

## 10. 相关资源

- **Hermes skill**: `note-taking/iswiki-writing/SKILL.md`(完整流程)
- **已有 pattern 参考**:
  - humanAtlas(2026-09-11)— 10 张 WebP 图,assets/humanAtlas/
  - 3dgs-substation(2026-09-11)— 1 张官方图 + 5 个 ASCII 图
- **提交历史**: `git log --oneline --reverse` 查看所有 doc 提交
