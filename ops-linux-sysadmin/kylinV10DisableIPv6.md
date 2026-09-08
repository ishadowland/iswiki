# KylinV10DisableIPv6 — 麒麟 V10 ARM 版彻底禁用 IPv6 操作指南

> 学习笔记 · 操作手册 · 2026-09-08
> 适用环境: Kylin Linux Advanced Server V10 (Halberd) – aarch64 (ARM 架构)
> 目标: 从内核层彻底禁用 IPv6 协议栈,使 `netstat` 不再显示 `tcp6` 套接字,`ip a` 无任何 IPv6 地址
> License: N/A (内部运维 SOP)

## 一句话定位

麒麟 V10 ARM 版服务器通过修改 GRUB 内核参数 `ipv6.disable=1`,在协议栈层彻底关掉 IPv6 的最小操作流程,5 步到位 + 3 条验证命令 + 3 个常见问题兜底。

## 为什么需要这条 SOP

- **业务触发**: 部署了第三方安全/合规探针,探针的检测规则要求「IPv6 必须关闭」,否则会上报告警(误报为不合规或潜在暴露面)。禁用 IPv6 是为了**满足探针的合规基线**,不是单纯为了排障清爽
- 麒麟 V10 (aarch64) 默认启用 IPv6 协议栈,`netstat -tulnp` 总有 `tcp6` / `udp6` 套接字,即便业务只用 IPv4 也会触发探针告警
- 内网(尤其传统金融 / 政企)只走 IPv4,IPv6 在网关上无路由,保留协议栈等于白送攻击面
- ARM 版 `/etc/default/grub` + `update-grub` 路径不一定可用,必须直接改 `/boot/efi/EFI/kylin/grub.cfg`
- 这台机器曾因「修改 grub 导致启动失败」和「多网卡同 IP」两次翻车,本笔记把这两类踩坑都收口

> **给第三方探针方的话**: 「禁用 IPv6 是合规要求,非配置缺失,告警可收敛」 — 沟通时直接引用本节作为依据。

## 操作流程 (5 步)

### 1️⃣ 备份 GRUB 配置

```bash
sudo cp /boot/efi/EFI/kylin/grub.cfg /boot/efi/EFI/kylin/grub.cfg.bak
```

操作失误导致无法启动时,用此备份恢复。

### 2️⃣ 编辑 GRUB 配置

```bash
sudo vim /boot/efi/EFI/kylin/grub.cfg
```

### 3️⃣ 修改内核启动参数

找到所有 `linux` 或 `linuxefi` 开头的行(每个 `menuentry` 下有一行,**包括 rescue 条目**),在行尾追加 `ipv6.disable=1`。

**修改前**:

```
linux /vmlinuz-4.19.90-89.24.v2401.ky10.aarch64 root=/dev/mapper/klas-root ro ... audit=0
```

**修改后**(注意 `audit=0` 后有空格):

```
linux /vmlinuz-4.19.90-89.24.v2401.ky10.aarch64 root=/dev/mapper/klas-root ro ... audit=0 ipv6.disable=1
```

> ⚠️ 必须修改所有内核启动项(包括 rescue),否则未修改的入口仍会启用 IPv6。

### 4️⃣ 重启

```bash
sudo reboot
```

### 5️⃣ 三条命令验证 (均应无输出)

```bash
# TCP6 / UDP6 套接字应为空
netstat -tulnp | grep tcp6

# 所有 IPv6 地址应消失 (含 lo 的 ::1)
ip a | grep inet6

# IPv6 内核模块应未加载
lsmod | grep ipv6
```

三条都无输出 = 禁用成功。

## 常见问题兜底

### Q1: 修改后系统无法启动

**UEFI 引导菜单手动恢复:**
1. 开机按 `Esc` 或 `F8` 进 GRUB 菜单
2. 选中启动项,按 `e` 进入编辑
3. 手动删除 `ipv6.disable=1`
4. `Ctrl+X` 或 `F10` 启动

**急救模式回滚:**

```bash
sudo cp /boot/efi/EFI/kylin/grub.cfg.bak /boot/efi/EFI/kylin/grub.cfg
```

### Q2: 修改后网络不通

- 检查是否有**多网卡配置相同 IP**(本案例踩过)→ 删除冲突网卡的 IP + 错误路由
- 检查 `/etc/sysconfig/network-scripts/ifcfg-*`,只保留正确的网卡配置
- `ip a` 确认只有预期的 IPv4 地址

### Q3: 系统更新内核后修改会丢失吗

- 内核更新会重新生成 `grub.cfg`,`ipv6.disable=1` 丢失,需再次手工加
- 尝试过 `/etc/default/grub` + `update-grub`,ARM 版不一定支持
- **建议**: 写一个 ansible / shell playbook,内核更新后自动 patch grub.cfg(本笔记留作 TODO)

## 关键参数速查

| 项 | 值 | 说明 |
|---|---|---|
| GRUB 配置路径 | `/boot/efi/EFI/kylin/grub.cfg` | ARM UEFI 路径 |
| 内核参数 | `ipv6.disable=1` | 完全禁用 IPv6 协议栈 |
| 验证命令 | `netstat -tulnp \| grep tcp6` | 应无输出 |
| 验证命令 | `ip a \| grep inet6` | 应无输出(含 `::1`) |
| 验证命令 | `lsmod \| grep ipv6` | 应无输出 |
| 备份后缀 | `.bak` | 手动 cp,不依赖版本管理 |

## 跟我们的关系

- 这是**生产服务器**(麒麟 V10 ARM)反复踩坑后沉淀的 SOP,不是通用 Linux 教程
- 两次翻车都收口到本笔记:① grub 改错启动失败 ② 多网卡同 IP 网络不通
- 后续每次内核更新,运维走「重新 patch grub.cfg → 重启 → 三条命令验证」流程
- 如果引入配置管理(Ansible / Salt),把第 1 3 步做成 playbook,Q3 自动解决

## TODO / 待办

- [ ] 写 ansible playbook 自动 patch grub.cfg(应对 Q3)
- [ ] 探索 `/etc/default/grub` + 自定义 `grub2-mkconfig` 在 ARM 版是否可用
- [ ] 验证 `ipv6.disable=1` 对 `ip6tables` / nftables 行为的影响

## 参考链接

- 麒麟软件官网: https://www.kylinos.cn/
- Linux 内核参数 `ipv6.disable`: https://www.kernel.org/doc/html/latest/networking/ipv6.html
- GRUB2 手册: https://www.gnu.org/software/grub/manual/grub/
