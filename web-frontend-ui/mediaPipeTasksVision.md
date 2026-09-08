# @mediapipe/tasks-vision — Google MediaPipe Vision Tasks JS SDK

> 学习笔记 · 调研时间 2026-08-12
> 仓库: https://github.com/google-ai-edge/mediapipe · 官网: https://developers.google.com/mediapipe
> npm: https://www.npmjs.com/package/@mediapipe/tasks-vision
> License: Apache-2.0 · 语言: TypeScript / C++(底层) · ⭐ 36.5k(主仓,2026-08-12;用户口头提的 17k+ 应为早期或子仓数)

## 一句话定位

Google MediaPipe 推出的**端侧(on-device)视觉任务 SDK**,把预训练模型打包成 15 个开箱即用的 Web API(人脸/手势/姿态/目标检测/分类/分割/嵌入/交互式分割等),WASM + GPU 加速,数据不出本地。

## 三种使用方式

| 方式 | 入口 | 适用场景 |
|---|---|---|
| **Web / JS** | `@mediapipe/tasks-vision` npm 包(本研究重点) | H5、Web App、PWA、Node 跑实验 |
| **Python** | `mediapipe` PyPI 包(同名不同仓,Tasks Vision 模块) | 桌面脚本、Jupyter、原型验证 |
| **Native Mobile** | Maven / CocoaPods(`com.google.mediapipe:tasks-vision` 等) | Android/iOS APP 内嵌 |

## 核心组件

### 1. MediaPipe Solutions 体系定位

```
MediaPipe Solutions(高层,开箱即用)
├── MediaPipe Tasks ←——— 本研究对象
│   ├── @mediapipe/tasks-vision  (Web/JS)
│   ├── @mediapipe/tasks-text
│   ├── @mediapipe/tasks-audio
│   ├── @mediapipe/tasks-genai
│   └── Python / Android / iOS SDK
├── MediaPipe Models(预训练 .tflite)
├── MediaPipe Model Maker(自定义微调)
└── MediaPipe Studio(浏览器可视化)

MediaPipe Framework(底层,Graph + Calculator)
└── C++ / Android / iOS
```

### 2. Vision Tasks API 清单(15 个)

从 `mediapipe/tasks/web/vision/index.ts` 导出的全部 Symbol:

| API | 模型/任务 | 典型用途 |
|---|---|---|
| `FaceDetector` | 人脸检测(框) | 人脸计数、ROI 提取 |
| `FaceLandmarker` | 478 个关键点 + blendshape | 美颜、AR 贴纸、表情驱动 |
| `GestureRecognizer` | 手势分类(预定义 + 自定义) | 隔空操控、手语 |
| `HandLandmarker` | 21 个手部关键点 | AR、手指绘画 |
| `HolisticLandmarker` | 脸 + 手 + 姿态联合 | 全身驱动、虚拟主播 |
| `ImageClassifier` | 图像分类(支持 EfficientNet/MobileNet) | 内容审核、标签 |
| `ImageEmbedder` | 图像特征向量 | 以图搜图、聚类 |
| `ImageSegmenter` | 语义/类别分割 | 背景替换、特效 |
| `InteractiveSegmenter` | 点击/框选交互分割 | PS 一键抠图 |
| `InteractiveSegmenterLegacy` | 旧版 | 兼容老项目 |
| `ObjectDetector` | 目标检测(EfficientDet 等) | 物体计数、巡检 |
| `PoseLandmarker` | 33 个身体关键点 | 健身动作评估 |
| `MPImage` / `MPMask` | 数据结构 | 跨 API 传图 |
| `FilesetResolver` | 模型加载器 | 加载 .task 文件 |
| `DrawingUtils` | 画关键点辅助 | 可视化 |

### 3. 关键技术栈

| 维度 | 选型 |
|---|---|
| **运行时** | WebAssembly + WebGL/WebGPU 加速 |
| **模型格式** | `.task`(MediaPipe Tasks 专用,内含 TFLite + 元数据) |
| **bundle 大小** | unpackedSize ≈ **37 MB**(含 WASM + .task 模型下载) |
| **依赖** | 0 runtime deps(npm `dependencies: {}`),纯静态资源 |
| **types** | `vision.d.ts` 自带,IDE 友好 |
| **离线可用** | ✅ 完全本地推理,数据不上传 |

## 安装与最小使用

### Web / JS — 最小示例(HandLandmarker)

```bash
npm install @mediapipe/tasks-vision
```

```typescript
import {
  HandLandmarker,
  FilesetResolver,
  DrawingUtils
} from "@mediapipe/tasks-vision";

// 1. 加载 WASM 资源
const vision = await FilesetResolver.forVisionTasks(
  "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@1.0.1/wasm"
);

// 2. 创建 HandLandmarker(加载模型)
const handLandmarker = await HandLandmarker.createFromOptions(vision, {
  baseOptions: {
    modelAssetPath:
      "https://storage.googleapis.com/mediapipe-models/hand_landmarker/hand_landmarker/float16/1/hand_landmarker.task",
    delegate: "GPU"  // GPU 加速,CPU fallback
  },
  runningMode: "VIDEO",  // IMAGE / VIDEO / LIVE_STREAM
  numHands: 2
});

// 3. 推理
const video = document.querySelector("video");
const results = handLandmarker.detectForVideo(
  video,
  performance.now()
);

// 4. 画关键点
const cvs = document.querySelector("canvas");
const ctx = cvs.getContext("2d");
const drawer = new DrawingUtils(ctx);
for (const landmarks of results.landmarks) {
  drawer.drawConnectors(landmarks, HandLandmarker.HAND_CONNECTIONS, {
    color: "#00FF00", lineWidth: 3
  });
  drawer.drawLandmarks(landmarks, { color: "#FF0000", radius: 2 });
}
```

### Python — 最小示例

```bash
pip install mediapipe
```

```python
import mediapipe as mp

BaseOptions = mp.tasks.BaseOptions
HandLandmarker = mp.tasks.vision.HandLandmarker
HandLandmarkerOptions = mp.tasks.vision.HandLandmarkerOptions
VisionRunningMode = mp.tasks.vision.RunningMode

options = HandLandmarkerOptions(
    base_options=BaseOptions(
        model_asset_path="hand_landmarker.task"
    ),
    running_mode=VisionRunningMode.IMAGE,
    num_hands=2,
)

with HandLandmarker.create_from_options(options) as landmarker:
    mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=numpy_frame)
    result = landmarker.detect(mp_image)
    for hand in result.hand_landmarks:
        print(hand)  # 21 个关键点(x, y, z normalized)
```

### 关键 API 模式

```typescript
// 三种 runningMode 决定 API 形态
runningMode: "IMAGE"        → detect(image: MPImage)             // 单帧
runningMode: "VIDEO"        → detectForVideo(video, timestampMs)  // 视频流(需时间戳)
runningMode: "LIVE_STREAM"  → detectForVideo(video, timestampMs)
                            + setResultListener(callback)         // 持续回调
```

## 跟我们的关系(用户工作相关)

| 关联点 | 潜在用途 |
|---|---|
| **私活 / H5 项目** | Vue/uniapp H5 嵌入 Vision Tasks,做人脸登录、手势小游戏、Cocos 游戏的辅助交互 |
| **WAF / 安全场景** | 客户端验证码(姿态/手势验证)、行为风控(头转向、眨眼)、图片内容审核(NSFW 检测走 `ImageClassifier`) |
| **Cocos Creator 3.x** | 平台层(`platform/`)可挂这套 SDK,实现"摄像头玩肉鸽"这类二期需求 |
| **巡检 / 离线工具** | 后台/工控现场无网环境,本地 TFLite 推理,离线视频分析 |
| **CLI 工具** | Node.js 跑批量图片分类/分割,构建内容审核 pipeline |

## 配套生态

| 工具 | 用途 |
|---|---|
| **MediaPipe Studio** | 浏览器可视化工具,可视化 .task 模型推理结果、对比 benchmark |
| **MediaPipe Model Maker** | 在 Colab / 本地用少量数据微调分类器/检测器 |
| **Task API 文档** | https://developers.google.com/mediapipe/solutions/vision |

## 隐私注意(从 README 摘录)

> When you use MediaPipe Tasks, processing of the input data takes place **on device**, and MediaPipe does not send that input data to Google servers.

⚠️ 但 MediaPipe Tasks APIs **会上报性能/利用率指标**(匿名 metric)给 Google。上线前要在用户隐私协议里告知并获取同意。

## 版本节奏

- v1.0.0 稳定版:**2026-07-28**(主仓 tag,MediaPipe v1.0 大版本)
- 当前 npm stable:**v1.0.1**(2026-08-11 RC 后发布)
- RC 节奏密集:每天一个 RC(1.0.1-rc.20260807 → rc.20260811),说明还在快速迭代
- 共 573 个 npm 版本(alpha 时代从 1668420867 时间戳开始)

## 参考链接

- 主仓: https://github.com/google-ai-edge/mediapipe
- 文档站: https://developers.google.com/mediapipe/solutions/vision
- npm: https://www.npmjs.com/package/@mediapipe/tasks-vision
- API 参考: https://developers.google.com/mediapipe/reference/js/tasks-vision
- Studio: https://developers.google.com/mediapipe/solutions/studio
- 隐私声明: https://goo.gle/mediapipe-privacy
- Awesome MediaPipe: https://mediapipe.page.link/awesome-mediapipe