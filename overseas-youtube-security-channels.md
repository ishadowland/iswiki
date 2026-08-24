# 海外优质网络安全 YouTube 学习频道调研

> 学习笔记 · 调研时间 2026-08-24
> 信息图来源: 微信公众号「张总说网安」《海外优质学习频道》
> 副标题: 适合不同阶段的网络安全学习者
> 8 个频道 · 2×4 卡片布局 · 中文分类标签

## 一句话定位

**覆盖网络安全学习 4 阶段的 8 个海外 YouTube 频道合集**:从零基础 NetworkChuck → 实战 IppSec → 二进制 LiveOverflow。**适合不同阶段(入门/工具/实战/高级研究)**的学习者,**按顺序学** = 完整 cybersecurity 自学路径。

## 8 频道 4×2 矩阵 (从原图)

| 阶段 | 频道 | 分类 | 内容 |
|---|---|---|---|
| **入门** | The Cyber Mentor | 渗透测试 / Ethical Hacking | Heath Adams 创办,**最经典的 pentesting 入门课** |
| **入门** | NetworkChuck | 网络基础 / Linux / 黑客工具 | **最友好 IT 入门**,咖啡 + 表情包风格 |
| **入门+** | (NetworkChuck 重复) | 同上 | ⚠️ **图里重复一次**(制图失误) |
| **工具** | Null Byte | 黑客技术 / 安全工具 | **信息安全教育平台**,Arch Linux 系 |
| **硬件** | "Hohn Hammond" ⚠️ | 硬件安全 / 渗透测试 | ⚠️ **拼写错误**,应作 **John Hammond** |
| **CTF/分析** | **John Hammond** | CTF挑战 / 恶意软件分析 | **Hunt 平台创始人**,CTF 实战 + malware reverse |
| **实战** | **IppSec** | HackTheBox 实战讲解 | **HTB 机器 walkthrough 之王**,每台机器一视频 |
| **高级** | **LiveOverflow** | 二进制安全 / 逆向工程 | **最深入 binary security**,pwn + 漏洞分析 |

> ⚠️ 原图有两处错误:
> 1. **NetworkChuck 重复**(第2行第1列 与 第2行第2列)
> 2. **"Hohn Hammond" 是 John Hammond 笔误**(漏了 J)

## 每个频道深度分析

### 1. The Cyber Mentor (Heath Adams)
- **YouTube**: <https://www.youtube.com/@TCMSecurityAcademy> 或 @TheCyberMentor
- **核心内容**:
  - **Ethical Hacking 完整路径** (20+ 小时课程)
  - **Practical Ethical Hacking** 系列
  - **Buffer Overflow 教程**
  - **Python for Pentesters**
  - **Web App Pentesting** (OWASP Top 10 实操)
- **配套网站**: <https://tcmschool.com> (TCM Security Academy) — 提供付费证书
- **适合**: **零基础 → 入门 pentester**
- **特点**: **节奏适中** + **真实验室** + **Offsec/PJWT/OSCP 考试导向**
- **替代**:John Hammond (基础部分)

### 2. NetworkChuck (Chuck Keith)
- **YouTube**: <https://www.youtube.com/@NetworkChuck>
- **核心内容**:
  - **IT 入门** (零基础友好)
  - **Linux 教程** (初学者到中级)
  - **网络基础** (CCNA 级别)
  - **黑客工具入门** (Nmap / Wireshark / Burp)
  - **Cloud / Linux + Cloud 集成**
- **适合**: **完全的零基础** (没碰过 Linux / 网络的人)
- **特点**: **幽默 + 表情包 + 咖啡 + 短小** (5-15 min/视频)
- **不限于安全**: 也教 Python / 云计算 / 职业建议

### 3. Null Byte (Arch Linux 系)
- **YouTube**: <https://www.youtube.com/@NullByte> (前 Prime Videos)
- **核心内容**:
  - **Kali Linux 教程**
  - **信息收集 / 漏洞扫描 / 提权**
  - **Anonsploit / DeepWeb 主题**(偏 underground 视角)
  - **Python scripting for hackers**
- **配套网站**: <https://null-byte.wonderhowto.com>
- **适合**: **NetworkChuck 之后的工具实战**
- **特点**: **脚本化 + step-by-step** + 包含完整 lab setup

### 4. John Hammond ⚠️ (原图误作 "Hohn Hammond")
- **YouTube**: <https://www.youtube.com/@_JohnHammond>
- **核心内容**:
  - **CTF 实战 walkthrough** (每周 1-2 个)
  - **Hunt** 平台 (<https://huntr.com>) 创始人 — bug bounty
  - **恶意软件分析** (静态 + 动态)
  - **Job hunting in cybersecurity** 系列(求职建议)
  - **真实案例** (勒索软件 / 事件响应)
- **适合**: **CTF 入门 / Bug bounty 准备 / 职业转型**
- **特点**: **真实 bug bounty 报告 + CTF 视频** + 适合**快速了解行业现状**
- **配套 GitHub**: <https://github.com/JohnHammond>

### 5. IppSec (Heath Adams 也看过他)
- **YouTube**: <https://www.youtube.com/@ippsec>
- **核心内容**:
  - **HackTheBox 机器 walkthrough** (每台退役机器一视频)
  - **从零开始解释 exploit chain** + **ret2libc / rop / kerberoast 详解**
  - **Active Directory 渗透**
  - **OSCP 准备**
- **适合**: **掌握基础后 + 想准备 OSCP / CPTS / HTB CPTS**
- **特点**:
  - **每视频 20-60 分钟,单台机器完整 walkthrough**
  - **脚本 + 命令** 实时显示
  - **300+ 视频,几乎覆盖所有 retired HTB 机器**
  - 视频索引按难度排序
- **必看**:HTB Easy → Medium 完整跟一遍

### 6. LiveOverflow
- **YouTube**: <https://www.youtube.com/@LiveOverflow>
- **核心内容**:
  - **二进制安全 / 漏洞分析** 深入专题
  - **Pwn / 内存破坏 / ROP / kernel**
  - **现代 web 漏洞** (browser pwn, 浏览器安全)
  - **The Heap Series** (heap exploitation 经典)
  - **Fuzzing / vulnerability research**
- **适合**: **高级研究 / 想成为 0day researcher / 安全研究员**
- **特点**:
  - **高质量长篇分析**(20-60 min/视频)
  - **可视化**(手写板 + 图解)
  - **贴近学术研究**

## 7 大学习阶段路径 (推荐顺序)

```
阶段 0: 基础 IT (1-2 月)
  └─ NetworkChuck (Linux + 网络基础)
        │
        ▼
阶段 1: 渗透测试入门 (2-3 月)
  ├─ The Cyber Mentor "Practical Ethical Hacking"
  └─ 配套 TryHackMe / HackTheBox Easy 房间
        │
        ▼
阶段 2: 工具 + 实战 (3-4 月)
  ├─ Null Byte (工具 + 脚本)
  ├─ John Hammond (CTF 实战)
  └─ HackTheBox Medium 房间
        │
        ▼
阶段 3: 实战深入 (3-6 月)
  ├─ IppSec (跟着他的 HTB walkthrough)
  ├─ OSCP / eCPPT / CPTS 准备
  └─ 参加 CTF (PicoCTF / HTB CPTS / NCL)
        │
        ▼
阶段 4: 高级研究 (持续)
  ├─ LiveOverflow (二进制 / pwn)
  └─ 选方向: web / mobile / cloud / reverse
        │
        ▼
阶段 5: 实战输出
  ├─ Bug bounty (HackerOne / Bugcrowd)
  ├─ 写 blog (技术沉淀)
  └─ 申请工作 / 认证
```

## 7 大学习思路 / 建议

### 1. **不要按顺序看完所有频道**
- NetworkChuck (基础) → TCM (pentest 入门) → Null Byte / Hammond (工具) → IppSec (HTB) → LiveOverflow (高级)
- 每个频道**先看 1-2 个播放列表**,**判断自己当前阶段**

### 2. **配套实战平台 (光看不动手 = 0)**
| 平台 | 类型 | 何时用 |
|---|---|---|
| **TryHackMe** | 引导式房间 | 阶段 0-1 (零基础) |
| **HackTheBox** | 实战机器 | 阶段 2+ |
| **PicoCTF** | CTF 入门 | 阶段 1-2 (CTF 入门) |
| **NCL** | 美式 CTF | 阶段 1-2 (校园赛) |
| **HackTheBox CPTS** | 认证 | 阶段 3 (中级认证) |
| **Offsec OSCP** | 认证金标准 | 阶段 3+ |
| **HackerOne / Bugcrowd** | 漏洞悬赏 | 阶段 3+ (赚钱 + 学) |

### 3. **中文学习者友好度排序**
1. **NetworkChuck** — 简短 + 表情包,中文字幕可机翻
2. **John Hammond** — 说话清晰 + 中文字幕可用
3. **IppSec** — 命令行多,中文字幕可用
4. **Null Byte** — 节奏中,中文字幕一般
5. **The Cyber Mentor** — 长篇,需专注
6. **LiveOverflow** — 概念深,**最难入门**,需英语基础

### 4. **认证 vs 学习路径**
- **看视频 + 实践 + 认证** 三件套
- 推荐顺序:
  - **CompTIA Security+** (基础) → **eJPT** (eLearnSecurity) → **CPTS** (HTB) → **OSCP** (Offsec)
  - 或: **PicoCTF + HTB CPTS + OSCP**
- 视频帮理解,**认证逼实战**

### 5. **资源协同效应 (用一张图说明)**
```
       ┌──────────────┐
       │   理论输入     │ ← LiveOverflow (高级) / TCM (入门)
       └──────┬───────┘
              ↓
       ┌──────────────┐
       │   工具实操     │ ← Null Byte / IppSec (命令演示)
       └──────┬───────┘
              ↓
       ┌──────────────┐
       │   实战环境     │ ← TryHackMe / HTB / PicoCTF
       └──────┬───────┘
              ↓
       ┌──────────────┐
       │   输出闭环     │ ← Bug bounty / Blog / 认证
       └──────────────┘
```

### 6. **每周时间分配 (在职 / 转型 / 学生)**
| 身份 | 视频学 | 实战 | 认证 | 输出 |
|---|---|---|---|---|
| **在职** | 3h | 5h | - | 2h |
| **转型** | 5h | 10h | 5h | 1h |
| **学生** | 6h | 8h | 6h | 2h |

### 7. **免费 vs 付费资源**
- ✅ **全部免费**: YouTube + TryHackMe 免费房间 + HTB 退役机器 + PicoCTF
- 💰 **付费**:
  - **HTB Academy** ($14/月) — **CPTS 备考** 必入
  - **Offsec Learn** ($239/年) — **OSCP** 必入
  - **Practical Ethical Hacking 完整版** (TCM, 约 $30) — 配套 lab

## 5 大补充 (没在原图但是必备)

1. **中文频道**(顺便推荐):
   - **IppSec 中文翻译**:B 站搬运
   - **玄机实验室 CTF** 系列
   - **安全客 / 先知社区** (中文技术 blog)
   - **Tombkeeper / 云舒** (中文安全大 V)

2. **英文补充资源**:
   - **PortSwigger Web Security Academy** (免费 + Web 渗透权威)
   - **OWASP WebGoat** (Web 漏洞演练)
   - **Cryptopals** (密码学挑战)
   - **CryptoHack** (密码学 CTF)
   - **OverTheWire** (Wargames, Bandit 入门)
   - **Exploit Education** (Phoenix 漏洞训练)

3. **必读书籍**:
   - **"Hacking: The Art of Exploitation"** (Jon Erickson) — 经典
   - **"The Web Application Hacker's Handbook"** (Stuttard) — Web 渗透圣经
   - **"Practical Malware Analysis"** (Sikorski) — 恶意软件分析入门
   - **"Effective C"** (Seacord) — 理解 binary / 漏洞的底层
   - **"Network Security Assessment"** (McNab) — 网络评估
   - **"Reversing: Secrets of Reverse Engineering"** (Eilam) — 逆向工程入门

4. **必关注的 Subreddit / Forum**:
   - **r/netsec** — 网络安全新闻
   - **r/ReverseEngineering** — 逆向
   - **r/netsecstudents** — 学生问题
   - **r/ExploitDev** — 漏洞利用开发
   - **Hacker News** — 行业动态

5. **必用的 free tools**:
   - **Burp Suite Community Edition** (Web 渗透)
   - **Wireshark** (流量分析)
   - **Ghidra** (逆向)
   - **CyberChef** (编码 / 解码)
   - **OWASP ZAP** (Web 扫描)
   - **Hashcat** (密码破解)

## 4 大常见误区 (学习者)

### 误区 1: "看完所有视频就懂了"
- **错** — 视频是被动接收,**实战平台才学得到**
- **解决**: 60% 时间给实战,40% 视频

### 误区 2: "学完所有 topic 才能开始"
- **错** — **T 型**学,先一竖 (pentesting) → 实战 → 再一横 (其他方向)
- **解决**: **先选 OSCP 路径,再补其他**

### 误区 3: "CTF 排名 = 真实能力"
- **错** — CTF 是技术练习,**bug bounty / 实战才看综合能力**
- **解决**: CTF 练技术 + blog 练表达 + 项目练协作

### 误区 4: "只看英文不看中文"
- **错** — 早期中文能加速,**后期必须转英文**(顶级资源都英文)
- **解决**: 入门中文,中级双语,高级纯英文

## 7 大推荐路线 (按身份)

### 路线 1: 学生 (CS 背景,想就业)
1. **NetworkChuck** (Linux + 网络) — 1 月
2. **The Cyber Mentor** "Practical Ethical Hacking" — 2 月
3. **TryHackMe** Easy-Medium 房间 — 3 月
4. **IppSec** 跟 30+ HTB 视频 — 3 月
5. **PicoCTF** 完赛 + 1 个 CTF 赛 — 1 月
6. **HTB CPTS** 准备 + 考 — 3 月
7. **OSCP** 准备 + 考 — 3 月
8. **Bug bounty** 上 HackerOne 提交第一个 — 持续

### 路线 2: 在职 (软件工程师, 想转安全)
- **跳过网络基础**(你已懂)
- **跳过 Linux 基础**(DevOps 经验足够)
- **从 The Cyber Mentor 开始** 直接
- **重点**: Web 渗透 + bug bounty (高 ROI)

### 路线 3: 在职 (运维 / 网络,想转安全)
- **从 NetworkChuck** 巩固基础
- **重点**: 蓝队 / SIEM / IR / SOC (运维经验直接复用)
- **认证**: CompTIA CySA+ / Splunk / Elastic

### 路线 4: 学生 (想读研 / 研究)
- **从 LiveOverflow** 早期
- **基础**: C / 汇编 / OS
- **读论文**: USENIX Security / IEEE S&P / ACM CCS
- **重点**: 0day research / 学术 publication

## 10 大高效学习 Tips

1. **Pomodoro** (25 min 视频 / 5 min 笔记) → 4 循环 → 长休息
2. **同时看 1-2 个频道**,**不要订阅 8 个都看**
3. **Notion / Obsidian 笔记**: 视频 URL + 关键 takeaway + 自己的话翻译
4. **每视频 1 张 Anki 卡片** (命令 / 概念)
5. **每周 1 个 HackTheBox 房间** (持续实战)
6. **每 3 月 1 个里程碑** (eJPT / CPTS / OSCP)
7. **找 1 个 study buddy** (互相讲)
8. **Twitter / X 关注安全大 V** (了解动态)
9. **写 blog 总结** (逼自己讲清楚)
10. **加入 Discord / Slack 社区** (求助 + 互动)

## 类似 / 对比项目

| 类型 | 中文 | 英文 |
|---|---|---|
| **视频入门** | 玄机实验室 / 安全客视频 | NetworkChuck / TCM |
| **CTF 实战** | NCL / XCTF / 强网杯 | HackTheBox / TryHackMe |
| **理论** | 看雪论坛 | LiveOverflow / Phrack |
| **新闻** | 安全客 / FreeBuf | Hacker News / r/netsec |
| **认证** | CISP / CISP-PTE | OSCP / eJPT / CPTS |

## 4 大相关 iswiki 工具

| 工具 | 关系 |
|---|---|
| [anthropic-cybersecurity-skills](anthropic-cybersecurity-skills.md) | 🟢 817 攻防技能库(可用作学习 + 实战参考) |
| [codex-security](codex-security.md) | 🟢 项目级安全扫描 |
| [wafKnowledgeBase](wafKnowledgeBase.md) | ⚪ 防御 WAF |
| [mattpocock-skills](mattpocock-skills.md) | ⚪ 软件工程非安全 |

## 🎯 TL;DR

**8 个频道 + 4 阶段路径 + 1 个核心原则**:

> **看视频 40% / 实战 60%** — **实战是唯一学得会安全的途径**。

**Top 3 必看**(按 ROI 排序):
1. **NetworkChuck** (零基础友好 + 幽默)
2. **IppSec** (HTB walkthrough 之王)
3. **The Cyber Mentor** (pentest 入门黄金标准)

**Top 3 实战平台**:
1. **TryHackMe** (引导式)
2. **HackTheBox** (实战)
3. **PicoCTF** (免费 + 友好)

**Top 3 认证路线**:
1. **eJPT** (eLearnSecurity Junior Penetration Tester) — 入门认证
2. **HTB CPTS** (Certified Penetration Testing Specialist) — 实战认证
3. **OSCP** (Offensive Security Certified Professional) — 金标准

== **原图 2 处错误**:
1. **NetworkChuck 重复** — 制图笔误
2. **"Hohn Hammond" 拼写错误** — 应作 **John Hammond**(@_JohnHammond)