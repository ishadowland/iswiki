#!/usr/bin/env bash
# check_miner.sh v1.0 - Linux 挖矿痕迹只读自查
# 运行建议：sudo bash check_miner.sh
# 安全声明：只读取本机信息；不发起网络连接，不向外部发送数据，不修改系统文件。
# 局限性：只能发现常见痕迹，查不出所有隐藏型 rootkit；全部 OK 不等于未被入侵。

set -u
export LC_ALL=C

FAMILY="unknown"
AUTH_LOG=""
SSHD_UNIT="sshd"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }
danger() { printf '[危] %s | %s\n' "$1" "$2"; }
warn() { printf '[疑] %s | %s\n' "$1" "$2"; }
ok() { printf '[OK] %s | %s\n' "$1" "$2"; }

os_id=""
os_pretty="unknown"
if [ -r /etc/os-release ]; then
    os_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')"
    os_pretty="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | tr -d '"')"
fi
case "$os_id" in
    rhel|centos|rocky|almalinux|fedora|amzn|ol)
        FAMILY="rhel"; AUTH_LOG="/var/log/secure"; SSHD_UNIT="sshd" ;;
    debian|ubuntu|linuxmint)
        FAMILY="debian"; AUTH_LOG="/var/log/auth.log"; SSHD_UNIT="ssh" ;;
    *)
        if [ -f /etc/redhat-release ]; then
            FAMILY="rhel"; AUTH_LOG="/var/log/secure"; SSHD_UNIT="sshd"
        elif [ -f /etc/debian_version ]; then
            FAMILY="debian"; AUTH_LOG="/var/log/auth.log"; SSHD_UNIT="ssh"
        fi
        ;;
esac

check_processes() {
    section "1/7 CPU 与进程血统"
    if ! have ps; then warn "进程" "缺少 ps，跳过本项"; return; fi
    ps-eo pid,ppid,user,%cpu,comm,etime,args --sort=-%cpu 2>/dev/null | head -n16

    local high fake kproc max_gap i p1 p2 gap
    high="$(ps -eo pid,ppid,%cpu,comm,args 2>/dev/null | awk 'NR>1 && $3>=150 {print}' | head -n 10)"
    if [ -n "$high" ]; then
        warn "高CPU" "以下进程平均CPU达到150%以上，需确认是否属于业务"
        printf '%s\n'"$high"
    else
        ok "高CPU" "未看到平均CPU达到150%以上的进程"
    fi

    fake="$(ps -eo pid,ppid,comm,args 2>/dev/null | grep -Ei 'kinsing|sysupdate|networkservice|systemd-update|kdevtmpfsi|watchdogs' | grep -v grep | head -n 10)"
    if [ -n "$fake" ]; then danger "可疑进程名" "$fake"; else ok "可疑进程名" "未命中常见挖矿家族进程名"; fi

    kproc="$(ps -eo pid,ppid,comm,args 2>/dev/null | awk 'NR>1 && $3 ~ /^kworker/ && $2 != 2 {print}' | head -n 10)"
    if [ -n "$kproc" ]; then
        danger "kworker血统" "以下kworker的PPID不是2，请检查/proc/PID/exe"
        printf '%s\n' "$kproc"
    else
        ok "kworker血统" "未发现PPID异常的kworker"
    fi

    max_gap=0
    i=1
    while [ "$i" -le 3 ]; do
        p1="$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')"
        p2="$(ps -e 2>/dev/null | awk 'NR>1 {n++} END {print n+0}')"
        gap=$((p1 - p2)); [ "$gap" -lt 0 ] && gap=$((-gap))
        [ "$gap" -gt "$max_gap" ] && max_gap="$gap"
        i=$((i + 1)); [ "$i" -le 3 ] && sleep 1
    done
    if [ "$max_gap" -gt 5 ]; then
        warn "进程计数采样" "三次采样最大差值为 $max_gap；容器和短生命周期进程也会干扰，请复核"
    else
        ok "进程计数采样" "三次计数差未超过5；仅是弱线索，不能据此排除隐藏进程"
    fi
}

check_cron() {
    section "2/7 定时任务与 systemd 持久化"
    local paths p hits rc
    paths=""
    for p in /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
        [ -e "$p" ] && paths="$paths $p"
    done
    if [ -n "$paths" ]; then
        hits="$(grep -RInE '(curl|wget).*(bash|sh)|base64[[:space:]]+-d|/dev/tcp|nohup' $paths 2>&1)"
        rc=$?
        if [ "$rc" -gt 1 ]; then
            warn "计划任务" "部分路径读取失败，结果不完整"
            printf '%s\n' "$hits" | head -n 30
        elif [ "$rc" -eq 0 ]; then
            warn "计划任务" "发现需人工核对的下载执行或常驻特征，关键词也可能是正常业务"
            printf '%s\n' "$hits" | head -n 30
        else
            ok "计划任务" "已读路径未发现指定特征；仍需人工核对任务内容"
        fi
    else
        warn "计划任务" "没有读取到cron路径，可能权限不足"
    fi
    if have systemctl; then
        systemctl list-timers --all --no-pager 2>/dev/null | head -n 20
        systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -n 30
        warn "systemd" "以上timer和enabled服务需按业务白名单人工核对"
    else
        warn "systemd" "缺少systemctl，跳过timer和enabled服务清单"
    fi
}

check_startup() {
    section "3/7 登录与启动触发器"
    local hits rc unread p user home f
    local -a targets=()
    unread=0
    for p in /etc/profile /etc/bashrc /etc/rc.local /etc/rc.d/rc.local /etc/profile.d/*; do
        [ -e "$p" ] || continue
        if [ -r "$p" ]; then targets+=("$p"); else unread=1; fi
    done
    if [ -r /etc/passwd ]; then
        while IFS=: read -r user _ _ _ _ home _; do
            [ -n "$home" ] || continue
            for p in "$home/.bashrc" "$home/.bash_profile"; do
                [ -e "$p" ] || continue
                if [ -r "$p" ]; then targets+=("$p"); else unread=1; fi
            done
        done < /etc/passwd
    else
        unread=1
    fi
    [ "$unread" -eq 1 ] && warn "启动脚本" "存在不可读文件或无法枚举家目录，结果不完整"
    if [ "${#targets[@]}" -gt 0 ]; then
        hits="$(grep -nE 'curl|wget|base64|nohup|/dev/tcp' "${targets[@]}" 2>&1)"
        rc=$?
        if [ "$rc" -gt 1 ]; then
            warn "启动脚本" "部分文件读取失败，结果不完整"
            printf '%s\n' "$hits" | head -n 30
        elif [ "$rc" -eq 0 ]; then
            warn "启动脚本" "发现需人工核对的下载执行或常驻特征，关键词也可能是正常业务"
            printf '%s\n' "$hits" | head -n 30
        elif [ "$unread" -eq 0 ]; then
            ok "启动脚本" "已读文件未发现指定特征"
        fi
    elif [ "$unread" -eq 0 ]; then
        warn "启动脚本" "没有可检查的启动文件"
    fi
    for f in /etc/rc.local /etc/rc.d/rc.local; do
        [ -e "$f" ] && ls -l "$f"
    done
}

inspect_key_file() {
    local f="$1" count meta rc
    [ -e "$f" ] || return 0
    KEY_FOUND=$((KEY_FOUND + 1))
    if [ ! -r "$f" ]; then
        warn "授权公钥" "$f 存在但不可读，需要root核对"
        return 0
    fi
    count="$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$f" 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        warn "授权公钥" "$f 读取失败：$count"
        return 0
    fi
    meta="$(stat -c '%U %a' "$f" 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        warn "授权公钥" "$f 有$count条，但属主和权限读取失败：$meta"
    else
        warn "授权公钥" "$f 有$count条（属主/权限：$meta），请逐条人工确认"
    fi
}

check_ssh() {
    section "4/7 SSH 后门与爆破痕迹"
    local cfg akf top brute_log config_read token user home path candidate
    cfg=""
    akf=".ssh/authorized_keys .ssh/authorized_keys2"
    config_read=0
    if have sshd && [ "$(id -u)" -eq 0 ]; then
        cfg="$(sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|authorizedkeysfile) ')"
        if [ -n "$cfg" ]; then
            config_read=1
            printf '%s\n' "$cfg"
            akf="$(printf '%s\n' "$cfg" | awk '$1=="authorizedkeysfile" {$1=""; sub(/^ /,""); print; exit}')"
            [ -n "$akf" ] || akf=".ssh/authorized_keys .ssh/authorized_keys2"
            printf '%s\n' "$cfg" | grep-q '^permitrootlogin yes' && danger "SSH配置" "允许root直接登录"
            printf '%s\n' "$cfg" | grep-q '^passwordauthentication yes' && warn "SSH配置" "允许密码登录，公网暴露时风险较高"
            if [ -r /etc/ssh/sshd_config ] && grep -qE '^[[:space:]]*Match[[:space:]]' /etc/ssh/sshd_config; then
                warn "SSH配置" "主配置含Match块；不带-C的sshd -T不能代表所有连接的最终配置"
            fi
        else
            warn "SSH配置" "sshd -T未返回配置；可能是版本低于6.8或执行失败"
        fi
    else
        warn "SSH配置" "需要root及sshd -T（OpenSSH 6.8+）才能读取全局生效配置"
    fi

    KEY_FOUND=0
    if [ "$akf" = "none" ]; then
        warn "授权公钥" "AuthorizedKeysFile为none，请确认是否管理员明确配置"
    else
        for token in $akf; do
            case "$token" in
                /*)
                    case "$token" in *%h*|*%u*) ;; *) inspect_key_file "$token" ;; esac
                    ;;
            esac
        done
        if [ -r /etc/passwd ]; then
            while IFS=: read -r user _ _ _ _ home _; do
                [ -n "$home" ] && [ -d "$home" ] || continue
                for token in $akf; do
                    case "$token" in
                        /*)
                            case "$token" in *%h*|*%u*) ;; *) continue ;; esac
                            ;;
                    esac
                    path="${token//%h/$home}"
                    path="${path//%u/$user}"
                    case "$path" in
                        /*) candidate="$path" ;;
                        *) candidate="$home/$path" ;;
                    esac
                    inspect_key_file "$candidate"
                done
            done < /etc/passwd
        else
            warn "授权公钥" "/etc/passwd不可读，无法按用户家目录检查"
        fi
        if [ "$KEY_FOUND" -eq 0 ]; then
            if [ "$config_read" -eq 1 ]; then
                ok "授权公钥" "按全局AuthorizedKeysFile及可读取家目录未发现；Match条件和不可读路径仍需复核"
            else
                warn "授权公钥" "默认路径未发现；未能读取sshd配置，自定义AuthorizedKeysFile未排除"
            fi
        fi
    fi

    brute_log=""
    if [ -n "$AUTH_LOG" ] && [ -r "$AUTH_LOG" ]; then
        brute_log="$AUTH_LOG"
    elif [ -r /var/log/secure ]; then
        brute_log="/var/log/secure"
    elif [ -r /var/log/auth.log ]; then
        brute_log="/var/log/auth.log"
    fi
    if [ -n "$brute_log" ]; then
        top="$(grep 'Failed password' "$brute_log" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="from"){print $(i+1);break}}' | sort | uniq -c | sort -nr | head -n 10)"
    elif have journalctl; then
        top="$(journalctl -u "$SSHD_UNIT" --since "7 days ago" --no-pager 2>/dev/null | grep 'Failed password' | awk '{for(i=1;i<NF;i++) if($i=="from"){print $(i+1);break}}' | sort | uniq -c | sort -nr | head -n 10)"
    else
        top=""
    fi
    if [ -n "$top" ]; then
        warn "SSH爆破" "以下来源地址出现失败登录，次数不等同于入侵成功"
        printf '%s\n'"$top"
    else
        warn "SSH爆破" "未获得失败登录统计；可能是无记录、日志轮转、权限不足或未开启日志"
    fi
}

check_network() {
    section "5/7 外连与解析配置"
    local conns ports ss_rc
    if have ss; then
        conns="$(ss -tunap state established 2>&1)"
        ss_rc=$?
        if [ "$ss_rc" -ne 0 ]; then
            warn "外连" "ss执行失败，无法判断：$conns"
        else
            printf '%s\n' "$conns" | head -n 40
            ports="$(printf '%s\n' "$conns" | grep -E ':(3333|5555|7777|8888|9999|14444|45700)([[:space:]]|$)' | head -n 20)"
            if [ -n "$ports" ]; then warn "矿池端口线索" "$ports"; else ok "矿池端口线索" "已建立连接中未命中常见端口；不等于没有外连"; fi
        fi
    elif have netstat; then
        netstat -tunap 2>/dev/null | head -n 40
        warn "外连" "当前使用netstat兜底，请人工核对ESTABLISHED连接"
    else
        warn "外连" "缺少ss和netstat，跳过本项"
    fi
    printf '%s\n' '--- /etc/resolv.conf ---'
    sed -n '1,30p' /etc/resolv.conf 2>/dev/null
    printf '%s\n' '--- /etc/hosts ---'
    sed -n '1,40p' /etc/hosts 2>/dev/null
    warn "解析配置" "请核对DNS及hosts静态条目是否均由自己配置"
}

check_temp() {
    section "6/7 临时目录与文件属性"
    local paths p hits f flags rc
    paths=""
    for p in /tmp /var/tmp /dev/shm; do [ -d "$p" ] && paths="$paths $p"; done
    if [ -z "$paths" ]; then warn "临时目录" "目录不存在或不可读"; return; fi
    hits="$(find $paths -xdev -type f -perm /111 -mtime -7 -print 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        warn "临时目录" "部分路径读取失败，结果不完整"
        printf '%s\n' "$hits" | head -n 40
    elif [ -n "$hits" ]; then
        warn "临时目录可执行文件" "以下为7天内改动且带任一执行位的文件，请结合业务核对"
        printf '%s\n' "$hits" | head -n 40
        if have lsattr; then
            printf '%s\n' "$hits" | head -n 40 | while IFS= read -r f; do
                flags="$(lsattr "$f" 2>/dev/null | awk '{print $1}')"
                case "$flags" in *i*) danger "文件免疫位" "$f 带immutable标志" ;; esac
            done
        fi
    else
        ok "临时目录可执行文件" "已读目录未发现7天内改动且带执行位的文件"
    fi
}

check_accounts_integrity() {
    section "7/7 账号、加载器与命令完整性"
    local uid0 root_members primary_gid0 empty_pw out verify_ran verify_status
    if [ -r /etc/passwd ] && [ -r /etc/group ]; then
        uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)"
        printf 'UID 0账号：%s\n' "$uid0"
        if [ "$(printf '%s\n' "$uid0" | awk '$1!="root"')" ]; then danger "UID 0" "存在root以外的UID 0账号"; else ok "UID 0" "只有root"; fi

        root_members="$(awk -F: '$3==0 {print $4}' /etc/group 2>/dev/null)"
        primary_gid0="$(awk -F: '$4==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)"
        [ -n "$root_members" ] && warn "root组成员" "$root_members"
        [ -n "$primary_gid0" ] && warn "主组为0" "$primary_gid0"
        [ -z "$root_members" ] && [ -z "$primary_gid0" ] && ok "GID 0" "未发现额外成员"
    else
        warn "账号文件" "/etc/passwd或/etc/group不可读，UID/GID检查未完成"
    fi

    if [ -r /etc/shadow ]; then
        empty_pw="$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null)"
        if [ -n "$empty_pw" ]; then danger "空密码账号" "$empty_pw"; else ok "空密码账号" "未发现"; fi
    else
        warn "空密码账号" "无法读取/etc/shadow，需要root"
    fi

    if [ -s /etc/ld.so.preload ]; then
        warn "LD_PRELOAD" "/etc/ld.so.preload存在且非空；若非管理员明确配置则高度可疑"
        sed -n '1,20p' /etc/ld.so.preload
    elif [ -e /etc/ld.so.preload ]; then
        warn "LD_PRELOAD" "文件存在但为空，请确认来源"
    else
        ok "LD_PRELOAD" "/etc/ld.so.preload不存在，符合常见系统状态"
    fi

    verify_ran=0
    verify_status=0
    out=""
    if [ "$FAMILY"="rhel" ] && have rpm; then
        out="$(rpm -Vf /usr/bin/ps 2>&1)"; verify_status=$?; verify_ran=1
    elif [ "$FAMILY"="debian" ] && have dpkg; then
        out="$(dpkg -V procps 2>&1)"; verify_status=$?; verify_ran=1
    elif have rpm; then
        out="$(rpm -Vf /usr/bin/ps 2>&1)"; verify_status=$?; verify_ran=1
    elif have dpkg; then
        out="$(dpkg -V procps 2>&1)"; verify_status=$?; verify_ran=1
    fi
    if [ "$verify_ran" -eq 0 ]; then
        warn "命令校验" "缺少rpm/dpkg，无法校验procps"
    elif [ "$verify_status" -ne 0 ]; then
        warn "命令校验" "校验执行失败(rc=$verify_status)，不能判定通过"
        [ -n "$out" ] && printf '%s\n' "$out"
    elif [ -n "$out" ]; then
        warn "命令校验" "procps相关文件有差异；成功执行且无输出才代表通过"
        printf '%s\n' "$out"
    else
        ok "命令校验" "procps校验成功且无输出，未发现包文件差异"
    fi
}

printf '===== Linux挖矿痕迹只读自查 v1.0 =====\n'
printf '主机：%s\n时间：%s\n系统：%s\n' "$(hostname 2>/dev/null)" "$(date '+%F %T' 2>/dev/null)" "$os_pretty"
printf '%s\n' '提示：报告可能包含内网地址、用户名、进程参数或cron中的敏感信息，公开分享前请先脱敏。'
if [ "$(id -u)" -ne 0 ]; then
    warn "权限" "当前不是root，部分项目会漏检；建议使用sudo重新运行"
fi

check_processes
check_cron
check_startup
check_ssh
check_network
check_temp
check_accounts_integrity

section "人工处置建议"
printf '%s\n' '1. 发现[危]或[疑]后，先把日志、连接、任务和样本留到本机之外。'
printf '%s\n' '2. 按“断持久化 -> 封出口 -> 收兵 -> 换锁”处理，顺序不要反。'
printf '%s\n' '3. 本脚本只读，不自动处置；脚本全部OK只表示覆盖项未见异常。'
printf '%s\n' '4. 怀疑rootkit、数据泄露或需要合规上报时，请离线取证并联系专业应急团队。'
