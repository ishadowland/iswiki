# Linux 权限调试 — `chmod 777` 还是 Permission denied 的 6 层访问链

> 学习笔记 · 调研时间 2026-08-31
> 来源: 微信公众号「赵楠的成长日记」 — *chmod 777 翻车了:权限拉满还是 Permission denied*
> URL: <https://mp.weixin.qq.com/s/GLUf-o1_WhvDnvwoLOA0xA>

---

## 1. 一句话定位

`Permission denied` 这一句报错背后有 **6 层访问链判断**(身份 → 路径 → 文件权限 → 挂载策略 → SELinux/MAC → 远端存储/隔离)。**`chmod 777` 只改第一层("传统权限位"),无法修复其它 5 层**,反而**抹掉了故障线索**,让下次同类问题更难排查。

## 2. 6 层访问链(完整定位思路)

```
谁在访问  →  路径能否逐级穿过  →  文件权限是否允许当前动作
  →  挂载策略是否允许执行或写入  →  SELinux/MAC 是否允许
    →  远端存储/容器 namespace 是否有额外判断
```

> **记住这条链,chmod 777 没有解决的问题就不再玄学。**

## 3. 7 大根因(完整定位思路 + 实操命令)

### 3.1 身份错配 — 终端 root ≠ 服务进程身份

**症状**:终端 `chmod 777` 成功,服务启动还是 `Permission denied`。

**根因**:服务进程以低权限用户运行(Nginx/www-data、Tomcat/tomcat、Java/appuser、postgres/postgres),不共享终端 root 的权限。

**定位思路**:

```bash
# 1. 终端身份
id
# uid=501(liuyin) gid=20(staff) ...

# 2. 目标进程身份
ps -o pid,user,group,comm -p 1234
# PID USER   GROUP  COMM
# 1234 appuser appgroup python

# 3. systemd 服务的运行用户
systemctl show your-service -p User -p Group

# 4. 用服务账号验证真实动作
sudo -u appuser -- test -r /srv/app/config.yaml && echo readable
sudo -u appuser -- test -w /srv/app/upload && echo writable
sudo -u appuser -- test -x /srv/app/deploy.sh && echo executable
```

**修复**:`chown appuser:appgroup /srv/app/deploy.sh`,而不是 `chmod 777`。

### 3.2 父目录权限堵路 — 文件 777 也没用

**症状**:`deploy.sh` 已经 `chmod 777`,但还是 `Permission denied`。

**根因**:Linux 解析 `/srv/app/releases/current/deploy.sh` 时,从根目录逐级找 `srv / app / releases / current / deploy.sh`。**路径中任意一级目录缺少 x 权限(搜索权限),内核都会返回 EACCES**,根本走不到文件面前。

**定位思路**:

```bash
# 方法 1:逐级 ls -ld(效率低,易漏符号链接)
ls -ld / /srv /srv/app /srv/app/releases /srv/app/releases/current
# dr-xr-xr-x   root root  /
# dr-x------   root root  /srv        <-- 这一级其他用户过不去!

# 方法 2:用 namei 一次展开整条路径
namei -l /srv/app/releases/current/deploy.sh
# dr-xr-xr-x  root  root  /
# dr-xr-xr-x  root  root  srv
# drwx------  root  root  app        <-- bug 在这里
# drwxr-xr-x  app   app   releases
# drwxr-xr-x  app   app   current
# -rwxrwxrwx  app   app   deploy.sh

# 能否删除文件?取决于父目录的 w + x,不取决于文件本身的 w
```

**修复**:`chmod o+x /srv/app`(给父目录加执行权限),而不是改文件。

### 3.3 挂载点 noexec — 文件 x 位仍在但无法执行

**症状**:`cat /data/tools/check.sh` 成功,`bash /data/tools/check.sh` 成功,`./check.sh` 失败。

**根因**:挂载选项 `noexec` 在**文件系统层**拒绝执行,即使文件有 x 位。

**定位思路**:

```bash
findmnt -T /data/tools/check.sh -o TARGET,SOURCE,FSTYPE,OPTIONS
# TARGET          SOURCE     FSTYPE  OPTIONS
# /data/tools     /dev/sda1  ext4    rw,noexec   <-- bug 在这里

# 找到所有 noexec 挂载点
mount | grep noexec
# /tmp on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)
# /dev/shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec)
# /home on /home type ext4 (rw,nosuid,nodev,noexec)
```

**修复**:`/tmp`、可移动介质、共享目录常 noexec。**不要 remount 成 exec**(扩大可执行范围),而是把受信任程序放到允许执行的文件系统(`/opt`、`/usr/local/bin`)。

### 3.4 SELinux MAC 拒绝 — rwx 全开还是 EACCES

**症状**:rwx 全开 + 父目录都能穿过 + 挂载是 exec,还是 `Permission denied`。

**根因**:SELinux 是**强制访问控制 (MAC)**,独立于 rwx。需要**进程域 + 文件标签 + 策略规则**都匹配。

**定位思路**:

```bash
# 1. 看 SELinux 状态
getenforce
# Enforcing

# 2. 看对象标签
ls -Zd /srv/app /srv/app/deploy.sh
# drwxr-xr-x. root root unconfined_u:object_r:default_t:s0 /srv/app
# -rwxrwxrwx. root root unconfined_u:object_r:default_t:s0 /srv/app/deploy.sh

# 3. 查 AVC 拒绝日志(需要 auditd)
sudo ausearch -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -ts recent
# type=AVC msg=audit(1693500000.123:456): avc: denied { execute } for ...
#    scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0

# 4. 给自定义目录打标签(Web 内容搬到 /srv/myweb 场景)
sudo semanage fcontext -a -t httpd_sys_content_t '/srv/myweb(/.*)?'
sudo restorecon -Rv /srv/myweb
```

**修复**:**不要 setenforce 0 关 SELinux**(保护一起消失)。先检查标签是否错误,再检查服务是否用了非标准目录/端口,最后才考虑策略调整。`chcon` 是临时,生产用 `semanage fcontext + restorecon`。

### 3.5 NFS/CIFS root_squash — 客户端 root 不是服务端 root

**症状**:本地 `chmod 777` 成功,但 NFS mount 后服务端还是 `Permission denied`。

**根因**:Linux NFS 服务默认 **root_squash** — 客户端 UID 0 被映射为 `nobody` (UID 65534),客户端 root 看不到自己写的文件。

**定位思路**:

```bash
# 1. 确认路径是 NFS
findmnt -T /data/project -o TARGET,SOURCE,FSTYPE,OPTIONS
# /data/project  nfs-server:/export/project  nfs  rw,vers=4

# 2. 看客户端身份
id
# uid=0(root)

# 3. 服务端查看实际导出配置
ls -ln /data/project
sudo exportfs -v
# /export/project  nfs-server(rw,sync,root_squash,no_subtree_check)

# 4. 测试 root_squash 效果
sudo -u nobody touch /data/project/testfile  # 用 nobody 试
ls -ln /data/project/testfile
# -rw-r--r-- 65534 65534 testfile  <-- 客户端 root 被映射成 65534
```

**修复**:**不要改成 no_root_squash**(扩大远端 root 控制能力)。改成统一身份映射 + 明确目录属主 + 访问组。生产推荐 `nfsv4` + `idmapd` 集中身份。

### 3.6 容器 mount namespace — 宿主机 ≠ 容器内

**症状**:宿主机 `ls -l /srv/app` 看文件可写,容器内还是 `Permission denied`。

**根因**:容器和 systemd service 有独立 mount namespace。**同一个 `/srv/app`,宿主机和进程内部可能对应不同挂载,甚至一边可写,另一边只读**。

**定位思路**:

```bash
# 1. 宿主机视角(可能正常)
ls -l /srv/app

# 2. 进入目标进程的 mount namespace 重新检查
sudo nsenter -t 1234 -m -- findmnt -T /srv/app -o TARGET,SOURCE,FSTYPE,OPTIONS

# 3. 容器场景:同时核对容器内用户、绑定挂载、SELinux 标签
docker exec <container> id
docker exec <container> ls -la /srv/app
docker inspect <container> | jq '.[0].Mounts'

# 4. 容器内查看 SELinux 标签(经常与宿主机不同)
docker exec <container> ls -Zd /srv/app
```

**修复**:在 Dockerfile/compose 里**显式声明挂载**(避免隐式继承)。容器 root ≠ 宿主机 root,需要 namespace-aware 排查。

### 3.7 (补充) ACL + xattr + capabilities + seccomp

**症状**:所有上面 6 项都正常,还报 `EACCES`。

**根因**:

| 维度 | 检查 |
|---|---|
| **POSIX ACL** | `getfacl file`(用户/组/other 之外的 ACL) |
| **File capabilities** | `getcap file`(root 都不一定能用) |
| **xattr** | `getfattr -d file`(SELinux/AppArmor 标签) |
| **seccomp** | 进程 syscall filter |
| **cgroups** | 资源限制也可导致 EACCES |

**定位思路**:

```bash
getfacl -p /path/to/file
# user::rwx
# group::r--
# other::---
# mask::rwx

getcap /path/to/binary
# /usr/bin/ping cap_net_raw+ep  <-- cap_net_raw 允许 ping

getfattr -d -m - file
# security.selinux="..."

# 看进程被 seccomp filter 拦截的 syscall
grep -i seccomp /var/log/audit/audit.log
```

## 4. 推荐排查顺序(read-only 操作)

权限报错出现后,**先保留现场,别急着递归执行 `chmod -R 777`**。下面这组检查大多是**只读操作**,足够定位到具体层级:

```bash
# 1. 当前身份和目标进程身份
id
ps -o pid,user,group,comm -p 1234

# 2. 展开整条路径的权限
namei -l /srv/app/deploy.sh

# 3. 查看目标文件和扩展访问控制信息
stat /srv/app/deploy.sh
getfacl -p /srv/app/deploy.sh

# 4. 查看文件系统和挂载策略
findmnt -T /srv/app/deploy.sh -o TARGET,SOURCE,FSTYPE,OPTIONS

# 5. SELinux/MAC 拒绝
getenforce
ls -Zd /srv/app /srv/app/deploy.sh
sudo ausearch -m AVC,USER_AVC -ts recent

# 6. 远端存储(如果是 NFS)
findmnt -T /data -t nfs -o OPTIONS
sudo exportfs -v  # 服务端

# 7. 容器 namespace
sudo nsenter -t PID -m -- findmnt -T /path

# 8. capabilities / xattr
getcap /path/to/binary
getfattr -d -m - /path/to/file
```

> **每次只验证一层。证据指向哪里,就修哪里。**

## 5. 6 大"为什么 chmod 777 没用"的具体原因

| chmod 777 期望效果 | 实际被阻挡层 | 修复 |
|---|---|---|
| **可执行** | 父目录无 x | `chmod +x` 父目录 |
| 可执行 | 挂载 `noexec` | 移动到 exec 文件系统 |
| 可执行 | SELinux MAC | 改标签或策略 |
| 可执行 | 进程无 capability | setcap 或 sudo |
| **可读/写** | 进程身份错 | chown 或 setuid |
| 读/写 | ACL 拒绝 | `setfacl` 或 ACL 继承 |

## 6. 核心哲学

> **我更愿意把权限修复看成一次访问链校准。让正确的进程,以正确的身份,在正确的路径和策略下,获得刚好够用的权限。这个结果比"暂时不报错"可靠得多。**

### chmod 777 的两大副作用

1. **不解决根因**:Permission denied 还有 5 层可能阻挡
2. **抹掉故障线索**:原本清晰的权限边界被改乱后,即使恢复也很难确认刚才究竟是哪条权限起作用。**下一次迁移、扩容或安全检查,问题还会回来**。

### 推荐替代

- **最小权限原则**:让进程只能访问它必须的对象
- **分层修复**:每层证据指向哪里,就修哪里
- **保留证据**:`chmod 777` 前先 `audit2why < /var/log/audit/audit.log` (SELinux)
- **验证再应用**:每次只验证一层,用只读命令(避免进一步破坏)

## 7. 跟 iswiki 已有内容的关系

- **[redis](redis.md)** — 同样讲 Linux 内核/系统层,但偏应用层
- **[tilores](tilores.md)** — 搜索 relevance,不涉及 OS 权限
- **(无 linux-permissions)** — **新类别:运维故障排查**

## 8. 5 大可迁移到 substation-blueprint 的工程方法

1. **分层验证**:每层只做只读操作,避免连锁影响 — substation-blueprint 调试 3D 性能时也可以用 (FPS 检查 / scene complexity / texture size 分层)
2. **保留现场**:发生故障时**先 snapshot 当前状态**,再开始改 — 适用任何 debugging workflow
3. **优先用 `namei` 这类一次性展开工具**:避免逐级 `ls -ld` 漏掉符号链接
4. **文档化"为什么这样改"**:不要只写"chmod 777"(虽然这次文章是反例) — 真正的修复应该带 `chmod o+x /srv/app  # parent dir was blocking traversal` 这种注释
5. **build-time enforce + runtime check**:
   - Linux `enforce` (MAC): 系统级强制
   - substation-blueprint: CI 强制 bundle size + 视觉 feedback
   - **关键 lesson**: **预防 > 修复**

## 9. 5 大相关引用

- **Linux man pages**:
  - `man 7 path_resolution` — 路径解析
  - `man 8 mount` / `man 5 fstab` — 挂载选项
  - `man 5 selinux` / `man 8 semanage-fcontext` — SELinux
  - `man 5 exports` — NFS exports
- **Red Hat SELinux 用户指南**: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/
- **NFS 文档**: `man exports(5)`, `man nfs(5)`
- **Linux Capabilities**: `man 7 capabilities`
- **作者其他文章**:
  - 多网卡服务器"能进不能出"
  - 服务器还有内存却 OOMKilled
  - SSH 登录权限异常
  - 服务启动后无法访问的故障层级

## 10. TL;DR

`chmod 777` 在 Linux 上**只能改文件本身的传统权限位**,但**访问链有 6+ 层**(身份 → 路径 → 文件权限 → 挂载策略 → SELinux/MAC → 远端/容器 namespace → ACL/cap/xattr)。每层都有自己的检查,**rwx 通过 ≠ 真的能访问**。

**正确排查顺序**:先 `id / ps -o pid,user,group,comm -p PID`(身份)→ `namei -l PATH`(路径) → `stat / getfacl`(文件+ACL)→ `findmnt`(挂载)→ `ausearch -m AVC`(SELinux) → `nsenter`(namespace)。**每次只验证一层,证据指向哪里就修哪里**。

**终极建议**:**把权限修复看成"访问链校准"** — 让正确的进程,以正确的身份,在正确的路径和策略下,获得刚好够用的权限。**比"暂时不报错"可靠得多**。

== **Best takeaway**: 下次遇到 Permission denied,先问自己一句——**当前这次拒绝,究竟发生在身份、路径、挂载、SELinux,还是远端存储?**
