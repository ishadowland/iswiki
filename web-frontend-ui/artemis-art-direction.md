# Artemis 美术风格深度学习笔记

> 学习笔记 · 2026-08-25
> 项目: [redradman/artemis](https://github.com/redradman/artemis)
> 原文: [iswiki artemis-redradman.md](artemis-redradman.md)
> 状态: source code 读了 materials.ts / Wire.tsx / CinematicShell.tsx / CelestialBodies.tsx / tokens.css

## 一句话总结

**Artemis 的美术风格 = 工程蓝图 × 太空电影 × 琥珀橙焦点色**。三种 visual modes(Blueprint / Space / Cinematic)共享一个 **line-art + warm cream** 的骨架,通过**色温**和**琥珀 #e8a23b 焦点色**做 mode 区分,不靠纹理/贴图。**线条粗细 + opacity 阶梯**承担信息密度,而不是材质本身的复杂度。

## 12 大 art direction 原则

### 1. **Pure black + warm cream 配色**(不要纯白)

```css
--color-bg: #000000;          /* 不是 #0a0a0a,是真正的纯黑 */
--color-fg: #f0ebe0;          /* 不是 #ffffff,是 warm cream */
```

→ 纯黑 + 暖白给 3D 场景**电影感**,避免显示器偏蓝的"OS 感"

### 2. **单一焦点色 (Amber #e8a23b)** — 信息编码

```
--color-accent: #e8a23b;      /* 主焦点色 */
--color-accent-dim: rgba(232, 162, 59, 0.55);  /* 弱焦点色 */
--color-accent-wash: rgba(232, 162, 59, 0.09); /* 极淡背景色 */
--color-accent-glow: rgba(232, 162, 59, 0.5);  /* glow 效果 */
```

→ 琥珀色用于:选中组件 / thrust plumes / separation motors /entry plasma。**全场景只有一个焦点色**,视觉密度低

### 3. **线框为主,贴图为辅**(Wireframe-first)

```ts
// Wire.tsx — 每个 part 都画 lineSegments
<lineSegments geometry={edges} material={accent ? mats.accent : mats.main} />
{wireframe && <lineSegments geometry={wireframe} material={mats.mesh} />}
```

→ 用 `THREE.EdgesGeometry` + `LineSegments` 渲染每个 mesh 的边线框,**不用 PBR materials**

### 4. **3 主题共用同一白+琥珀对**(Space + Cinematic)

```ts
const PALETTES = {
  space:      { line: 0xffffff, active: 0xe8a23b },
  cinematic:  { line: 0xffffff, active: 0xe8a23b },  // 同一对!
  blueprint:  { line: 0xdceafe, active: 0x8fd2ff },  // cyanotype
};
```

→ Space 和 Cinematic **色相同**,区别在 **lighting + background + atmosphere**

### 5. **Blueprint 是 cyanotype,不是 "blue"**

```
Blueprint:
  line:    #dceafe (paper cyan)
  active:  #8fd2ff (sky cyan)
Space + Cinematic:
  line:    #ffffff (white)
  active:  #e8a23b (amber)
```

→ Blueprint = **晒图纸风格**(青色 + 浅米黄背景),不是真的 "蓝"

### 6. **3 种 tone(opacity 阶梯)** 做选中状态

```ts
// materials.ts
export const wireMain      = opacity: 0.85, white
export const wireMainActive = opacity: 1.0,  amber
export const wireMainDim    = opacity: 0.14, white
```

→ 选中 part → opacity 1.0 + 琥珀
→  其他 parts → opacity 0.14 (fade out 6x)
→ 默认 → opacity 0.85 + 白

### 7. **Material mutate in place**(性能优化)

```ts
export function applyWirePalette(mode) {
  const p = PALETTES[mode]
  wireMain.color.setHex(p.line)        // 改 .color,不重新 new
  wireMesh.color.setHex(p.line)
  // ... 11 个 material 全 mutate
}
```

→ 切换 mode 时**不重新分配材质**,所有 part 下一帧自动用新颜色

### 8. **MeshPhongMaterial + warm cream** (Cinematic 模式独有)

```ts
const hullMat = new THREE.MeshPhongMaterial({
  color: 0xf1ead9,       // warm cream
  shininess: 18,
  specular: 0x2a2620,   // soft warm specular
})
const hullDarkMat = new THREE.MeshPhongMaterial({
  color: 0xc6bba4,      // muted warm
  shininess: 10,
})
const nozzleMat = new THREE.MeshPhongMaterial({
  color: 0x887d6b,      // metallic warm
  shininess: 32,
})
```

→ Cinematic 模式**有 PBR 光照 + 暖色**,其他模式纯线框

### 9. **World-space 天体**(不在 Rocket group 内)

```ts
const MOON_POSITION = [180, 70, -240]   // 远 + 偏移
const EARTH_POSITION = [-220, -40, -320] // 反方向,更远
```

→ 月球 / 地球 **不在 Rocket group 内**——这样 banking 不会拖动它们

### 10. **Visibility 跟 mission time 联动**

```ts
function moonVisibility(t) {
  if (t < 0.6 || t > 0.9) return 0  // T+0-60% 不显示
  // ...linear fade in/out
}
```

→ 月球只在 **trans-lunar coast + return** 阶段显示,跟 mission narrative 同步

### 11. **JetBrains Mono + wide letter-spacing**

```css
--font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
--tracking-tight: 2.5px;
--tracking-normal: 3px;
--tracking-wide: 8px;
--tracking-01: 0.12em; /* -07: 0.35em */
```

→ Mono 字体 + **letter-spacing 0.12-0.35em** = 工程图/技术文档 feel

### 12. **Type scale 最小 11px(克制)**

```css
--text-7: 11px;
--text-8: 11px;
--text-9: 12px;
/* ... */
```

→ 不用 tiny text 强迫用户眯眼

## 3 主题对比 (汇总)

| 维度 | Blueprint | Space | Cinematic |
|---|---|---|---|
| **线条色** | `#dceafe` paper cyan | `#ffffff` white | `#ffffff` white |
| **Active 色** | `#8fd2ff` sky cyan | `#e8a23b` amber | `#e8a23b` amber |
| **Background** | (默认黑) | `#000000` | `#000000` |
| **Ship body** | 纯线框 | 纯线框 | **MeshPhongMaterial 暖白** |
| **Lighting** | Flat | 微妙 space light | **3-point key/fill** |
| **天体** | 不显示 | Moon + Earth | Moon + Earth + glow |
| **氛围** | 工程图 | 真实太空 | 戏剧化电影 |
| **default mode** | ✅ | | |
| **使用场景** | 默认 / 学术 | 沉浸 | 演示 / Marketing |

## 4 大视觉技巧可学(给任何 3D 项目)

### A. **"single accent color" 原则**

```
全场景用白色 (default) + 单一焦点色 (selected) + 极淡白 (dimmed)
不用多种颜色,避免信息过载
```

### B. **Wireframe-first 然后添加 PBR**

```
第一步: 全线框 (Blueprint) — 验证 3D 结构
第二步: 加 PBR mesh (Cinematic) — 验证 lighting
第三步: 加环境 (Space) — 验证 atmosphere
```

→ 渐进增加复杂度,**总有一个 mode 是 fallback**

### C. **Material mutate in place**

```ts
// 不要每次 mode switch new Material()
PALETTES[mode].forEach((c, i) => sharedMaterials[i].color.setHex(c))
```

### D. **Mission time → visibility 联动**

不是所有天体都一直显示 — 跟时间轴同步 fade in/out,**让 narrative 自然发生**

## 5 大学习资源

1. **直接读 [materials.ts](https://raw.githubusercontent.com/redradman/artemis/main/src/scenes/ArtemisII/materials.ts)** —— 全部 design token 都在
2. **直接读 [tokens.css](https://raw.githubusercontent.com/redradman/artemis/main/src/styles/tokens.css)** —— CSS 变量化
3. **直接读 [Wire.tsx](https://raw.githubusercontent.com/redradman/artemis/main/src/scenes/ArtemisII/geometry/Wire.tsx)** —— 8 行核心 wireframe 模式
4. **直接读 [CinematicShell.tsx](https://raw.githubusercontent.com/redradman/artemis/main/src/scenes/ArtemisII/effects/CinematicShell.tsx)** —— Phong lighting 模式
5. **直接读 [CelestialBodies.tsx](https://raw.githubusercontent.com/redradman/artemis/main/src/scenes/ArtemisII/effects/CelestialBodies.tsx)** —— time → visibility 联动

## 给自己的 3 个 takeaway

| # | 学习点 | 怎么用 |
|---|---|---|
| 1 | **单一焦点色 + opacity 阶梯** 表达 selection | | 任何 interactive 3D / 2D viewer |
| 2 | **Material mutate in place** 切换 mode | | 任何 multi-theme / multi-mode UI |
| 3 | **Pure black + warm cream** 配色 (避免显示器偏蓝) | | 任何 dark-theme 3D / 影视化界面 |

## 🎯 TL;DR — 5 个关键词

> **Pure Black + Warm Cream + Amber + Wireframe + Time-driven**

5 个元素到位,你就 get Artemis 美术风格的 80%。

## 跟 iswiki 其他 Three.js 项目对比

| 工具 | 美术风格 | 跟 Artemis 区别 |
|---|---|---|
| [kage](kage.md) | **Poetic pixel art** + 4 warm/cool palette | kage 是 Phaser 像素 art,Artemis 是 3D engineering |
| artemis-redradman | **Engineering blueprint + cinematic wireframe** | 本次研究 |

→ **kage 偏 craft + art**,**Artemis 偏 data + engineering**
