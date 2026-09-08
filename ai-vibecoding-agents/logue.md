# Logue — 隐私优先的 macOS AI Meeting Notes + 写作助手

> 学习笔记 · 调研时间 2026-08-11
> 仓库: https://github.com/bitwize-ai/Logue · 官网: https://bitwize.ai
> License: MIT · 语言: Swift 5.9 + SwiftUI + AppKit (99.5%) · ⭐ 145 · 🍴 11 · 版本 v1.0.1（2026-08-02）
> 平台: macOS 26.0+ (Tahoe) · Apple Silicon (M1+) · 构建: Xcode 26+ + XcodeGen

## 一句话定位

**macOS 上完全本地的 AI 会议笔记 + 写作助手**——录音、转写、说话人分离、摘要、Word 风格 AI 写作编辑器、Agentic 聊天，**全部跑在 Apple Silicon 的 MLX 推理上**，数据默认不出本机。

区别于 Whisper+GPT 这类云端方案：核心模型、推理、转写、embedding、说话人分离全部 on-device MLX；只有三类网络出站：模型下载、Sparkle 更新检查、用户**主动开启**的功能（web search / 外部 AI provider）。

## 三块核心能力

| 模块 | 干啥的 |
|---|---|
| **Meeting Intelligence** | 实时录 + 转写 + 说话人分离 → Smart Minutes（决策 / 主题 / 行动项） + AI 书签 + 下次会议预读 |
| **AI Writing Editor** | 基于 Textual 的 SwiftUI 编辑器，60+ 写作模式（语法 / 语气 / 改写 / fact-check / PII 检测 / 表格 / `[[wiki links]]` / 属性面板 / Saved Views / Inbox） |
| **Ask Logue** | 基于 LangGraph-Swift 的 Agent 聊天，可做多步研究、操作文档 + 会议、流式 token + Mermaid / Math 渲染 |

## 录音管线（钟点会议能跑通的关键设计）

这是个 hear the hard way 才学下来的设计，README 写得很坦白：

```
AudioRecorder (mic, AVAudioPCMBuffer)
  + SystemAudioCapture (ScreenCaptureKit, CMSampleBuffer)
  ──────────────────────────────
  ↓ BufferConverter
  AudioTimelineMixer         ← 所有源按 16 kHz 时间轴混音（非按到达时间）
  ↓
  SpeechTranscriberEngine    ← Apple SpeechAnalyzer (macOS 26+ SpeechTranscriber)
  ↓
  DiarizationManager         ← FluidAudio Sortformer（流式主路径 + batch 回退）
  + DiarizationManager+LongRecording  ← 长录音：边读音频文件边处理，不杀进程
  ↓
  RecordingSessionManager    ← 状态机: .idle / .starting / .recording / .stopping
```

两条硬规则（都踩过坑）：
1. **后处理 batch 只能覆盖它实际听过的区段**。整段替换会拿残缺文件干掉一小时的正确 live transcript——1.0.0 时通过 `TranscriptReplacement` 修
2. **落盘音频就是会议时间线**。`CaptureSegmentTimeline` 记录每个 source 的有效区间，被 mute/晚入会缩；按 source 推断时间戳是错的（设备时钟每次 toggle 都重置），必须靠 `persistRecordingAudio` 报告，**不要事后推导**

## LLM 层

- `LLMEngine`（actor）—— 全局推理入口，**所有调用必须走 `complete()` / `completeStream()`**。通过 `inferenceGate` 串行化（Swift actor 是 reentrant 的，单纯 actor 方法在 await 边界会被并发）
- `LLMEngineStatus`（@MainActor @Observable）—— `isBusy` flag，UI 用 `.disabled(...)` 屏蔽同时触发 AI 的按钮
- `ModelManager`—— 模型下载 / 激活 / endpoint 扫描（拆 +Download / +Discovery / +HuggingFace）
- `LLMClient`—— 可选外部 provider（OpenAI / Anthropic 兼容 / OpenRouter / Ollama / LM Studio），key 存在 Keychain，**默认关**

外部 LLM 调用前必须 XML 包裹用户内容（`<transcript>` / `<content>` / `<categories>`），长度上限按 `maxKVSize - outputTokens - promptOverhead` 截，不靠 `try?` 吞 JSON 解析失败。

## 数据层 — 两种存储模式

| 模式 | 默认 | 适用 |
|---|---|---|
| **加密 JSON**（AES-256-GCM） | ✅ | 会议、转写、音频、文档、回收站 |
| **Plain Markdown**（`~/Logue/` 下的 `.md`） | ❌（opt-in） | 文档；让 git / 外部编辑器 / 其他 agent 直接改 |

文档可以在两类存储之间切换，会议**永远加密**。Plain Markdown 模式的设计原则（每条都踩过坑）：

- **文件 = 文档**，没有复制、没有同步。扫描只读不写（写会触发 fs 事件 → 又扫 → 又写 = 死循环）。唯一例外：手动 drop 文件时写入 `_logue_id`
- **空间 ↔ 文件夹**靠 `_logue_space_id` 双向解析，不要从名字推路径——`/Work` 拼出来后拼不回原文件夹
- **消失检测**：`vanishedSpaceIDs` 必须两路都确认（identity index + 路径）；读不到 `_space.md` ≠ 该文件夹被删了
- **删除用 `trashItem` 不用 `removeItem`**——决策错了的代价是去废纸篓翻，不是丢文字
- **歧义不赌**：两个文件争一个文档 → 该文档零改动；两个文件夹争一个空间 → 留命名匹配的那个
- **mount 失败 = 静默不动**：移动硬盘没插 / sync 没完成 ≠ 删除一切

导入 Obsidian / Logseq 等 vault：子目录自动变 sub-space（按名匹配，重复导入不会产 `Projects (2)`）；frontmatter `tags:` / `created:` 解析；隐藏条目（`.obsidian` / `.trash` / `.git`）跳过。

## 依赖矩阵（确切版本）

| 依赖 | 来源 | 作用 |
|---|---|---|
| `mlx-swift-lm`（MLXLLM + MLXLMCommon） | SPM | MLX 推理 |
| `swift-transformers-mlx` | SPM | Tokenizer / 模型管线 |
| `swift-hf-api-mlx` | SPM | Hugging Face 下载 / hub cache |
| `LangGraph-Swift` | `Vendor/LangGraph-Swift` 子模块 | Agent 图 (`WritingAgentGraph`) |
| `swift-markdown` | `Vendor/swift-markdown` 子模块 | Markdown 解析 |
| `FluidAudio` | SPM ≥ 0.13.6 | 说话人分离（Sortformer 流式 + batch 回退） |
| `Textual` | SPM ≥ 0.3.1 | 富文本渲染 |
| `Sparkle` | SPM ≥ 2.9.1 | App 内自动更新（GitHub appcast，EdDSA 签名） |
| Apple `Speech.framework` | SDK | `SpeechTranscriber`（macOS 26+） |

构建前一次性： `xcodebuild -downloadComponent MetalToolchain`（MLX 需要）

## 安全 / 签名 / 分发（重点）

**App Sandbox 必须关闭**——这是 1.0.1 修的核心 bug。沙箱化进程拿不到 Accessibility API 客户端身份，macOS 不会列在「隐私与安全 → 辅助功能」里，**用户根本加不了它**。结果：⌘⌃I 内联助手 / 全局热键 / Command Center / 文本替换全部静默失效。shipped as issue #22。

Logue 走的是 **Developer ID + 公证 + GitHub Releases + Sparkle**（不走 Mac App Store），所以沙箱本来就不要求。**Hardened Runtime 保留**。`LogueTests/ReleaseEntitlementsTests.swift` 有 CI guard 防止再开。

- Sparkle EdDSA 私钥只在 GitHub Action secret `SPARKLE_PRIVATE_KEY` 里，repo 内只存 `SUPublicEDKey`
- 外部 API key 只走 Keychain（非敏感配置走 `UserDefaults`）
- 用户输入 URL 必须 HTTPS（localhost/127.0.0.1 除外）
- 注入 LLM 的字符串全部 sanitize + 长度截断 + 去控制字符
- 路径要 `.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)` 防 traversal
- Debug / Release 用不同 entitlements 文件（Debug 多 iCloud）

## 1.0.0 → 1.0.1 踩过的真坑（CHANGELOG 直引）

- **#22**：Accessibility 列表里压根没有 Logue → sandbox 关了
- **#31**：两个说话人重名 → `Dictionary(uniqueKeysWithValues:)` trap → 应用闪退，已坏会议迁移修复
- **#11**：Ask Logue 浮岛 ⌘⌃I 只能重开不能关，Esc / 点外部只在某些时候生效；关 App 是唯一出路
- **Diarization alignment**：残缺 batch 文件删掉一小时 live transcript
- **#10 / #39**：没有 quick open、没文档宽度、保存的视图 / inbox、`[[wiki]]` 链接、属性面板都是 1.0.1 一次性补的

## 测试

- **Swift Testing**（`@Suite` / `@Test` / `#expect`）——**不是 XCTest**
- 94 个 `@Test`，9 个文件，全在 `LogueTests/LLMIntegration/`
- 跑真模型推理（不在 mock 层糊弄）。Grammar 套件 10 分钟超时，其他 5 分钟
- `LLMTestHarness.swift` 提供 `LenientSuggestionItem` / `repairTruncatedJSON()` / `stripMarkdownFences()` 容纳模型小毛刺

## 代码规范（被 Review 强制）

- SwiftLint 严格，无 force unwrap / force cast（CF bridge 除外）；函数 ≤60 行、文件 ≤ 800 行、圈复杂度 ≤ 15
- 大类必须拆 extension 文件：`MeetingStore` 拆 8 份、`ModelManager` 拆 3 份
- 所有延时进 `AppConstants.Delays`，禁止裸 `Task.sleep(for: .seconds(N))`
- Swift actor reentrant：`inferenceGate` 串行化模式，所有推理必须经过 gate
- 错误禁用 `try?`（`Task.sleep` 的 cancellation 除外），全部 `do/catch` + log
- LLM 输出**回查源文档**——vocabulary `original` / suggestion `original` 必须在文档里真存在（case-insensitive），否则丢弃

## 项目结构

```
Logue/
├── Engine/         # LLMEngine / LLMEngineStatus / 录音管线 / 重试 / 时序混合
├── Services/       # RecordingSessionManager / EncryptionManager / DocumentStorage
├── Views/          # Meeting workspace / Writing editor / Ask Logue chat / Settings
├── App/            # AppConstants 等
├── Resources/      # Info.plist / entitlements / 资源
LogueTests/         # 94 LLM integration tests
Vendor/             # LangGraph-Swift, swift-markdown (submodules)
docs/               # RELEASE_SETUP, SPARKLE_UPDATE_FLOW, dev-setup, specs/
scripts/            # 维护脚本
```

## 跑起来

```bash
git clone --recurse-submodules https://github.com/bitwize-ai/Logue.git
cd Logue
xcodebuild -downloadComponent MetalToolchain     # 一次性
brew install xcodegen swiftformat swiftlint
xcodegen generate
xcodebuild build -project Logue.xcodeproj -scheme Logue \
  -destination 'platform=macOS' \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
open Logue.xcodeproj
```

要发自己签名的版本需要 GitHub secret：`APPLE_TEAM_ID` / `APPLE_CERTIFICATE_BASE64` / `APPLE_CERTIFICATE_PASSWORD` / `APPLE_ID` / `APPLE_APP_PASSWORD` / `SPARKLE_PRIVATE_KEY`，**全部走环境变量，repo 不存**。

## 评估（对这个项目）

**值得抄的**：
- 录音管线 / 文件夹双重身份映射 / batch pass 必须自证覆盖区段——都是真踩过坑的设计，写得很坦白
- LLM 推理 `inferenceGate` 串行化方案；LLM 输出回查源文档防幻觉
- 加密和 markdown 两种存储可以**双向切换**，不绑死用户
- 强制 SwiftLint，函数 / 文件 / 圈复杂度硬上限

**值得警惕的**：
- 整个项目**预设关闭 App Sandbox**，靠 **Developer ID + 公证 + Sparkle** 分发。如果未来要上 Mac App Store 就要重做
- 依赖全是最新版本（MLX / Swift 5.9 / macOS 26 / Xcode 26），**比当前多数 mac 还早**
- LLM 推理是单线程串行（`inferenceGate`），并发 AI 操作会全排队
- 1.0.1 才修 Accessibility 列表注册的 bug，意味着之前所有 release 的 cross-app 功能**都是坏的**

**相关 / 可对比**：
- 会议笔记：Otter.ai（云端）、MacWhisperer（本地 Whisper）
- AI 写作编辑器：Obsidian + Copilot / Logseq
- 本地 LLM 栈：Ollama / LM Studio / MLX
- 同类 on-device 架构：WhisperX 流式、Lightning MLX
