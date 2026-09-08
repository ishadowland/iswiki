# Linux 多内核禁用 IPv6 — 完整 SOP

> 学习笔记 · 调研时间 2026-09-05
> 场景: 多内核引导(`/boot/grub/grub.cfg` 有多个 menuentry)
> 目标: 给所有 `audit=0` 的内核项加 `ipv6.disable=1`

---

## 1. 背景与原理

### 1.1 为什么是「多个内核」

```
典型 Linux 机器的内核引导菜单:

menuentry 'Ubuntu 22.04, Linux 6.5.0-26-generic' ...
menuentry 'Ubuntu 22.04, Linux 6.5.0-26-generic (recovery mode)' ...
menuentry 'Ubuntu 22.04, Linux 6.5.0-15-generic' ...           ← 旧版本
menuentry 'Ubuntu 22.04, Linux 6.5.0-15-generic (recovery mode)' ...
menuentry 'Ubuntu 22.04, with Linux 6.5.0-26-generic (upstart)' ...
menuentry 'Ubuntu 22.04, with Linux 6.5.0-26-generic (systemd)' ...
```

每个 `menuentry` 都是**独立的启动项**,可以独立配置。

### 1.2 为什么是 `audit=0`

- `audit=0` = 禁用 Linux audit 子系统(审计日志)
- 这个标记**只在生产稳定内核** / 旧 fallback 内核上出现(运维刻意加的)
- ==**识别方法**:**所有 `audit=0` 标记的 menuentry = 已审过的稳定内核,都应该加 IPv6 disable**

### 1.3 理论上「只改最新内核」 vs 实际「全加」

| 方案 | 风险 |
|---|---|
| **只改最新内核** | 如果旧内核被引导(fallback / 旧版本),IPv6 又来了 |
| **给所有 audit=0 加**(推荐) | 100% 覆盖,无遗漏,运维保险 |

==**生产环境做法**:**给所有 audit=0 的 menuentry 都加 `ipv6.disable=1`** — 5 秒成本,换来确定性。

## 2. 完整 4 步 SOP

### Step 1: 找到所有 audit=0 的内核项

```bash
# 查看当前 GRUB 配置(UEFI / BIOS 路径不同)
sudo cat /boot/grub/grub.cfg              # BIOS + ext4
sudo cat /boot/grub2/grub.cfg             # CentOS / RHEL BIOS
sudo cat /boot/efi/EFI/ubuntu/grub.cfg    # UEFI
```

或者直接 grep:

```bash
# 找到所有 audit=0 的 menuentry
sudo awk '/^menuentry/,/^}/' /boot/grub/grub.cfg | grep -B 5 "audit=0"
```

输出示例:

```
menuentry 'Ubuntu, with Linux 6.5.0-26-generic' --class ubuntu {
        ...
        linux   /boot/vmlinuz-6.5.0-26-generic root=UUID=xxx ro audit=0 ipv6.disable=1
        ...
}
menuentry 'Ubuntu, with Linux 6.5.0-15-generic' --class ubuntu {
        ...
        linux   /boot/vmlinuz-6.5.0-15-generic root=UUID=xxx ro audit=0 ipv6.disable=1
        ...
}
```

### Step 2: 备份 grub.cfg

```bash
# 备份原文件,出错可回滚
sudo cp /boot/grub/grub.cfg /boot/grub/grub.cfg.bak.$(date +%Y%m%d-%H%M%S)
```

### Step 3: 给所有 audit=0 项加 ipv6.disable=1

```bash
# 用 sed 替换:找到 audit=0 行,在末尾加 ipv6.disable=1
# 注意:这一行可能在 linux 命令里,不是 grep 单行

# 方法 A:一行 audit=0 + linux 命令模式
sudo sed -i '/audit=0/ s|$| ipv6.disable=1|' /boot/grub/grub.cfg

# 方法 B:更稳健 — 只替换 linux 行(避免改了其它 audit=0 出现位置)
sudo sed -i '/^[[:space:]]*linux.*audit=0/ s|$| ipv6.disable=1|' /boot/grub/grub.cfg

# 方法 C:防御性 — 避免重复添加
sudo sed -i '/^[[:space:]]*linux.*audit=0/ s| ipv6.disable=1||g; /^[[:space:]]*linux.*audit=0/ s|$| ipv6.disable=1|' /boot/grub/grub.cfg
```

### Step 4: 验证

```bash
# 验证 1:每个 audit=0 行都跟 ipv6.disable=1
sudo awk '/^[[:space:]]*linux/ && /audit=0/ && !/ipv6.disable=1/' /boot/grub/grub.cfg

# 应该没输出 (如果有,说明还有未处理的项)

# 验证 2:看修改后的对比
sudo diff /boot/grub/grub.cfg.bak.* /boot/grub/grub.cfg

# 验证 3:重启,检查 IPv6 已禁用
ip -6 addr show
# 应该显示 IPv6 接口全无或全 disabled

cat /proc/cmdline | grep -o "ipv6.disable=1"
# 应该输出 ipv6.disable=1
```

## 3. 完整脚本(可直接用)

```bash
#!/usr/bin/env bash
# disable-ipv6-all-kernels.sh
# 给所有 audit=0 的内核项加 ipv6.disable=1
# 用法: sudo ./disable-ipv6-all-kernels.sh

set -euo pipefail

# 1. 找 grub.cfg 路径
GRUB_CFG=$(find /boot -name grub.cfg 2>/dev/null | head -1)
if [[ -z "$GRUB_CFG" ]]; then
  echo "ERROR: grub.cfg not found"
  exit 1
fi
echo "Found grub config: $GRUB_CFG"

# 2. 备份
BAK="${GRUB_CFG}.bak.$(date +%Y%m%d-%H%M%S)"
cp "$GRUB_CFG" "$BAK"
echo "Backup: $BAK"

# 3. 处理所有 audit=0 的 linux 行
sed -i '/^[[:space:]]*linux.*audit=0/{
    s/ ipv6.disable=1//g       # 先去掉已有的(防止重复)
    s/$/ ipv6.disable=1/       # 再加一次
}' "$GRUB_CFG"

# 4. 验证
echo ""
echo "=== 验证 ==="
REMAINING=$(awk '/^[[:space:]]*linux/ && /audit=0/ && !/ipv6.disable=1/' "$GRUB_CFG")
if [[ -n "$REMAINING" ]]; then
  echo "✗ 以下项未加 ipv6.disable=1:"
  echo "$REMAINING"
  exit 1
else
  echo "✓ 所有 audit=0 项已加 ipv6.disable=1"
fi

# 5. 显示修改
echo ""
echo "=== 改动 diff ==="
diff "$BAK" "$GRUB_CFG" || true

echo ""
echo "请执行 sudo reboot,然后检查:"
echo "  ip -6 addr show        # IPv6 接口应空"
echo "  cat /proc/cmdline      # 应含 ipv6.disable=1"
```

## 4. 等价方法(用 grub-mkconfig 重新生成)

### 4.1 Debian/Ubuntu

```bash
# 1. 编辑 /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash audit=0 ipv6.disable=1"
GRUB_CMDLINE_LINUX="audit=0 ipv6.disable=1"

# 2. 重新生成 grub.cfg
sudo update-grub
# 或者 sudo grub-mkconfig -o /boot/grub/grub.cfg
```

### 4.2 CentOS / RHEL

```bash
# 1. 编辑 /etc/default/grub
GRUB_CMDLINE_LINUX="audit=0 ipv6.disable=1 rhgb quiet"

# 2. 重新生成
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

==**注意**:`/etc/default/grub` 改完之后必须重新生成 grub.cfg,否则不生效。手工改 grub.cfg 在系统升级或 `update-grub` 后会被覆盖。

## 5. 5 大 IPv6 禁用方法(对比)

| 方法 | 范围 | 持久性 | 推荐度 |
|---|---|---|---|
| **GRUB 参数 `ipv6.disable=1`** | **整个内核** | **重启持久** | **⭐⭐⭐⭐⭐ 推荐** |
| `sysctl net.ipv6.conf.all.disable_ipv6=1` | runtime | 不持久 | ⭐⭐ 临时调试 |
| `/etc/sysctl.d/99-disable-ipv6.conf` | runtime | 重启持久 | ⭐⭐⭐ 需要 runtime 关闭 |
| `modprobe -r ipv6` | module | 不持久 | ⭐ 不推荐(破坏依赖) |
| 防火墙禁用 IPv6 流量 | 流量层 | 持久 | ⭐⭐⭐⭐ 不阻止栈,但阻止流量 |

==**推荐**:GRUB 参数(最彻底),+ sysctl.conf 双保险。

### 5.1 双保险配置

```bash
# 1. GRUB 参数(已经做完)
audit=0 ipv6.disable=1

# 2. sysctl.d 持久化(运行时 + 重启)
echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee /etc/sysctl.d/99-disable-ipv6.conf

# 3. 立即生效
sudo sysctl --system
```

## 6. 4 大验证命令

```bash
# 1. IPv6 接口应空
ip -6 addr show

# 2. 内核启动参数
cat /proc/cmdline

# 3. sysctl 检查
sysctl net.ipv6.conf.all.disable_ipv6
# 应输出: net.ipv6.conf.all.disable_ipv6 = 1

# 4. 网络栈是否还有 IPv6 socket
ss -A inet6
# 应该几乎为空(可能 ::1 localhost,但 IPv4 应该工作)
```

## 7. 5 大坑 + 解决

| 坑 | 症状 | 解决 |
|---|---|---|
| **改完没重启** | 配置不生效 | `sudo reboot` |
| **update-grub 覆盖手工** | 配置消失 | 改 `/etc/default/grub` + 重新生成 |
| **grub.cfg 不在标准路径** | 找不到 | UEFI: `/boot/efi/EFI/<distro>/grub.cfg` |
| **audit=0 在 linux 行外** | sed 不匹配 | 用 grep 验证 audit=0 都在 linux 行 |
| **某些应用硬要 IPv6** | curl / apt 报错 | `--inet4-only` 强制 IPv4,或保留 loopback IPv6 |

### 7.1 保留 loopback IPv6 的细节

```bash
# 有些服务依赖 ::1(localhost IPv6)
# 可以只关外部接口,保留 loopback
echo "net.ipv6.conf.lo.disable_ipv6 = 0" | sudo tee -a /etc/sysctl.d/99-disable-ipv6.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.d/99-disable-ipv6.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.d/99-disable-ipv6.conf
```

## 8. 5 大可迁移到 fire-side / OPC

| fire-side 应用 | 迁移 |
|---|---|
| **多 agent 多 slot 配置** | 跟多内核类似,每个 slot 都要独立配置 |
| **「保险起见全加」** 哲学 | 不只是改一个,要全部都加,避免遗漏 |
| **sed / awk 处理** | 跟 OPC tools 的「批量处理」一致 |
| **备份原配置再改** | 类比 recovery-sop 的「先备份现场」 |
| **验证不只一次** | 改完 + 重启后 + 启动时,3 重验证 |

==**核心哲学**:**「保险起见」永远比「理论上足够」重要** — 5 秒成本,换来确定性。

## 9. TL;DR

==**一句话**:**给所有 `audit=0` 的 menuentry 都加 `ipv6.disable=1`**,5 秒成本,换来 100% IPv6 覆盖。

==**完整 SOP**:
1. **找到 grub.cfg**(BIOS: `/boot/grub/grub.cfg`,UEFI: `/boot/efi/EFI/.../grub.cfg`)
2. **备份**:`sudo cp grub.cfg grub.cfg.bak.<时间戳>`
3. **批量修改**:`sudo sed -i '/^[[:space:]]*linux.*audit=0/ s/$/ ipv6.disable=1/' /boot/grub/grub.cfg`
4. **验证**:`awk '/^[[:space:]]*linux/ && /audit=0/ && !/ipv6.disable=1/'` 应无输出
5. **重启**:`sudo reboot`,然后 `ip -6 addr show` 应空

==**最值得学的 1 点**:**「保险起见给所有 audit=0 加」** — 跟 recovery-sop 的「先备份现场」哲学一致,**5 秒成本换确定性**,运维永远不该省这一步。
