# iswiki — 技术调研笔记

> 学习笔记库 · 长期积累的项目 / 工具 / 运维 / 安全 / 3D / AI 调研
> 按主题分类,每个目录有自己的 README.md 索引
> **共 48 个文档,9 个分类**

---

## 目录导航

### 🤖 [ai-coding-agents/](ai-coding-agents/) — AI Coding Agents / 编排
AI coding agent 工具 / 编排框架 / skill 集 / 多 agent 协作平台(12 个文档)

### 🎨 [3d-web-visualization/](3d-web-visualization/) — 3D / Web 可视化 / 渲染
Three.js / WebGPU / AI 生成 3D / 艺术化场景 / 美术风格(9 个文档)

### 🔒 [security-pentest/](security-pentest/) — 安全 / 渗透 / 漏洞
安全任务路由 / 渗透测试工具 / 漏洞研究 / 安全频道(5 个文档)

### 🛠️ [ops-linux-sysadmin/](ops-linux-sysadmin/) — Linux / 运维 / 故障排查
Linux 故障排查 / 数据恢复 / 性能 triage / WAF / 杂项运维(9 个文档)

### 🍎 [macos-ai-tools/](macos-ai-tools/) — macOS 上 AI 工具
macOS 原生 AI 工具(MLX / Swift / 会议笔记 / Agent 档案馆)(2 个文档)

### 🌐 [web-frontend-ui/](web-frontend-ui/) — Web 前端 / UI 库
Web 前端组件库 / 互动教室 / 地图 / 3D 编辑器(3 个文档)

### 🎬 [media-pipeline/](media-pipeline/) — 媒体 / 视频 / 多媒体
视频生成 prompt / 视觉处理 / 多媒体监控 / AI 模型(4 个文档)

### ⚡ [developer-productivity/](developer-productivity/) — 开发者生产力
开发者日常工具 / 提效库 / 数字过渡 / 体验优化(1 个文档)

### 🎮 [leaf-mlp1/](leaf-mlp1/) — Leaf / Miniloong 掌机二次开发
MLP1 掌机 + UMRK workspace + 部署编排器 + 自动化测试(1 个文档)

### 📌 [personal-misc/](personal-misc/) — 个人 / 杂项
个人项目 / 杂项 / 待重新分类(1 个文档)

---

## 📋 维护说明

### 命名规范
- **.md 文件**:英文 + kebab-case(如 `artemis-redradman.md`)
- **目录**:英文 + kebab-case(如 `3d-web-visualization/`)
- **每个目录都有 README.md**:作为该目录的索引

### 调研流程
1. 拿到新需求 / 项目 URL
2. 选合适的分类目录(或新建一个)
3. 写 `git fetch origin + rebase` + 同步本地
4. 写调研 + README 索引更新
5. `git commit + push`(retry 3-5 次绕开 GitHub firewall)

### 跨分类文件
- **reverse-skill.md**:虽然有"安全"字眼,核心是 AI agent 编排 → 归 ai-coding-agents
- **img2threejs.md**:虽然是 3D,但由 AI agent 编排 → 归 ai-coding-agents
- **lobeHub.md**:既是 Agent 平台又有 Web UI,但 Agent 平台性质更强 → 归 ai-coding-agents

---

## 🔗 相关项目

- **iswiki 主仓**: <https://github.com/ishadowland/iswiki>
- **liuyin**(作者): <https://github.com/ishadowland>

---

## 📊 统计

| 分类 | 文档数 |
|---|---|
| 🤖 ai-coding-agents | 12 |
| 🎨 3d-web-visualization | 9 |
| 🛠️ ops-linux-sysadmin | 9 |
| 🔒 security-pentest | 5 |
| 🎬 media-pipeline | 4 |
| 🌐 web-frontend-ui | 3 |
| 🍎 macos-ai-tools | 2 |
| ⚡ developer-productivity | 1 |
| 🎮 leaf-mlp1 | 1 |
| 📌 personal-misc | 1 |
| **总计** | **47** |

(47 个被分类的 doc + 1 个根 README.md)
