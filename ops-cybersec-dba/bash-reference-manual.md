# Bash Reference Manual — 核心知识体系

> 学习笔记 · 调研时间 2026-09-12
> 来源: <https://www.gnu.org/software/bash/manual/bash.pdf>(PDF 官方手册)
> 备用来源:
> - <https://tiswww.case.edu/php/chet/bash/bashref.html>(HTML mirror,Chet Ramey 维护)
> - <https://git.savannah.gnu.org/cgit/bash.git/plain/doc/bashref.texi>(Texinfo 源码)
> - <https://man7.org/linux/man-pages/man1/bash.1.html>(Linux man-pages)
> Bash 当前版本: 5.2.x(本文基于 Bash 5 系列)
> 作者: Chet Ramey (Case Western Reserve University)
> 许可: GNU Free Documentation License v1.3+

---

## 0. 一句话定位

**Bash 是 GNU 项目的 Bourne-Again SHell** — POSIX 兼容的 shell,扩展了 Bourne shell 的语法,加入数组、关联数组、`[[ ]]`、`(( ))`、`<<< here-string`、`{1..10}` brace expansion、命令替换 `$()`、进程替换 `<()` 等现代化特性。

== **核心哲学**:**「POSIX 超集 + 大量扩展 + 严格模式开关 `bash --posix`」**

---

## 1. 手册全景(10 章 + 4 附录)

### 1.1 10 大章节

| 章节 | 主题 | 关键内容 |
|---|---|---|
| 1 | Introduction | 什么是 Bash / 什么是 shell |
| 2 | Definitions | POSIX 术语(reserved word / metacharacter 等) |
| 3 | **Basic Shell Features** | 语法 / 命令 / 函数 / 参数 / 展开 / 重定向 / 执行 / 脚本 |
| 4 | **Shell Builtin Commands** | Bourne / Bash / 修改行为 / Special builtins |
| 5 | **Shell Variables** | Bourne / Bash 变量 |
| 6 | **Bash Features** | 调用 / 启动文件 / 交互 / 条件表达式 / 算术 / 别名 / 数组 / 目录栈 / 提示符 / 受限 shell / POSIX / 兼容模式 |
| 7 | Job Control | 作业控制基础 + 内建命令 |
| 8 | Command Line Editing | Readline + vi / emacs 模式 |
| 9 | Using History Interactively | 历史命令(`history` + `fc`)|
| 10 | Installing Bash | 编译 / 配置 / 测试 |

### 1.2 4 个附录

| 附录 | 内容 |
|---|---|
| A | Reporting Bugs (如何报告 bug,给 `bug-bash@gnu.org`)|
| B | **Major Differences From The Bourne Shell** (跟 sh 的关键差异)|
| C | GNU Free Documentation License |
| D | Indexes (概念 / 变量 / 内建命令 3 个索引) |

---

## 2. 第 3 章:Basic Shell Features(核心中的核心)

== 这是 Bash 的「操作语义」基础,任何 Bash 用户都必须理解。

### 2.1 Shell Syntax — 语法元素

Bash 输入按**8 类 token** 解析:

| Token | 例子 | 说明 |
|---|---|---|
| reserved word | `if` `while` `for` `function` | 关键字 |
| word | `cat` `file.txt` `$var` | 普通词 |
| operator | `|` `&&` `>` `<<` | 操作符 |
| name | `var=1` 左边的 var | 变量名 |
| redirection | `>file` `<&3` | 重定向 |
| comment | `# 注释` | `#` 开头 |
| newline | `;` 或换行 | 命令分隔符 |
| quoting | `"..."` `'...'` | 引号 |

### 2.2 Shell Commands — 4 类命令

```bash
# 1. 简单命令
ls -la

# 2. 管道
cat file | grep pattern

# 3. 列表(用 ; / && / || / & 分隔)
cd /tmp && ls || echo failed &

# 4. 复合命令((if/for/while/case/函数/子 shell/算术/条件/分组))
if [[ -f $file ]]; then ...; fi
for i in {1..10}; do echo $i; done
```

### 2.3 Shell Functions — 函数

```bash
# 定义
myfunc() {
    local var=$1      # 局部变量
    echo "$var"
    return 0          # 返回值 0-255
}

# 调用
myfunc "world"
echo $?              # 上一个命令的退出码

# 函数 vs 脚本:
# - 函数在当前 shell 进程内执行(变量共享)
# - 脚本 fork 子进程执行(变量隔离)
```

### 2.4 Shell Parameters — 4 类参数

| 类型 | 例子 | 说明 |
|---|---|---|
| **变量** | `var=value` | 最常见 |
| **位置参数** | `$1` `$2` `$@` `$#` | 脚本参数 |
| **特殊参数** | `$?` `$$` `$!` `$0` | shell 内部状态 |
| **数组** | `arr=(a b c)` `arr[0]=x` `arr[@]` | 一维数组(Bash 4+ 支持关联数组) |

```bash
# 数组
arr=(apple banana cherry)
echo "${arr[0]}"      # apple
echo "${arr[@]}"      # 全部元素(推荐写法)
echo "${#arr[@]}"     # 元素个数

# 关联数组(Bash 4+)
declare -A map
map[foo]=bar
echo "${map[foo]}"    # bar

# 间接引用(不推荐,易出错)
var="hello"
ref=var
echo "${!ref}"        # hello
```

### 2.5 Shell Expansions — 8 大展开(关键!)

== **Bash 按顺序执行 8 类展开**:

```
1. brace expansion  {}    → 最早展开
2. tilde expansion  ~    → 家目录
3. parameter / variable expansion  $  ${}
4. command substitution  $()  ``
5. arithmetic expansion  $(())
6. word splitting        (只在未加引号时)
7. filename expansion(globbing)  * ? [...]
8. quote removal
```

#### 2.5.1 Brace expansion `{}`

```bash
echo {a,b,c}          # a b c
echo {1..5}           # 1 2 3 4 5
echo {01..10..2}      # 01 03 05 07 09(步长)
echo {a..c}{1..3}     # a1 a2 a3 b1 b2 b3 c1 c2 c3(笛卡尔积)
mkdir -p project/{src,test,doc}/{core,utils}
# 一次建 6 个目录
```

#### 2.5.2 Parameter expansion `${}`

== 这是 Bash 最强大的特性,参数展开有几十种修饰符:

| 修饰符 | 作用 | 例子 |
|---|---|---|
| `${var:-default}` | var 空则用 default | `${name:-Anonymous}` |
| `${var:=default}` | var 空则赋值为 default | `${name:=Guest}` |
| `${var:+alt}` | var 非空则用 alt,否则空 | `${debug:+echo "DEBUG=$debug"}` |
| `${var:?msg}` | var 空则报错退出 | `${file:?path required}` |
| `${#var}` | 字符串长度 | `${#str}` |
| `${var:offset:len}` | 子串 | `${str:0:5}` |
| `${var#pattern}` | 去掉最短前缀 | `${file##*/}`(去路径)|
| `${var%pattern}` | 去掉最短后缀 | `${file%.*}`(去扩展名)|
| `${var/old/new}` | 替换第一个 | `${path/\/usr/\/local}` |
| `${var//old/new}` | 替换全部 | `${text// /_}` |
| `${var^^}` | 转大写 | `${input^^}` |
| `${var,,}` | 转小写 | `${input,,}` |
| `${!prefix*}` | 列出 prefix 开头的变量名 | `${!BASH*}` |

#### 2.5.3 Command substitution `$()` vs ``

```bash
# 两者等价,$() 更推荐(可嵌套)
files=$(ls)
date1=$(date +%Y-%m-%d)
nested=$(echo "$(whoami)@$(hostname)")
```

#### 2.5.4 Arithmetic expansion `$(())`

```bash
echo $((2 + 3 * 4))      # 14
((count++))               # 命令形式(无 $)
echo $((a > b ? 1 : 0))   # 三目
```

### 2.6 Redirections — 13 类重定向(关键!)

| 语法 | 含义 | 备注 |
|---|---|---|
| `> file` | 覆盖写入 stdout | 创建/截断文件 |
| `>> file` | 追加写入 stdout | 不截断 |
| `< file` | 从 file 读 stdin | |
| `<<EOF` ... `EOF` | here-document | 多行 stdin |
| `<<< "str"` | here-string | 单行 stdin(Bash) |
| `2> file` | 重定向 stderr | 跟 stdout 独立 |
| `2>&1` | stderr → stdout | **顺序很重要** |
| `&> file` | 同时重定向 stdout + stderr | Bash 简写 |
| `> file 2>&1` | **先重定向 stdout,再 dup stderr** | 标准做法 |
| `> file 2>&1`(顺序反) | stdout 去终端,stderr 去 file | **陷阱!** |
| `<&3` | 从 fd 3 读 | |
| `>&3` | 写到 fd 3 | |
| `&|`(管道) | 启动子进程 | |
| `<(cmd)` | process substitution | file 实际是 cmd 的 stdout |
| `>(cmd)` | process substitution | file 实际是 cmd 的 stdin |

```bash
# 经典陷阱:重定向顺序
cmd > file 2>&1      # ✅ stdout → file,stderr → file(都到 file)
cmd 2>&1 > file      # ❌ stderr → 终端(stdout),stdout → file
```

### 2.7 Executing Commands — 命令执行

== Bash 执行外部命令的查找顺序:

1. **函数**(function)
2. **内建命令**(builtin)
3. **hash 表**(已查找过的外部命令)
4. **PATH 查找**(按 `$PATH` 目录顺序)

```bash
type cd            # cd is a shell builtin
type ls            # ls is /bin/ls
type -a python3    # 所有匹配(函数 + builtin + 路径)

# 修改 PATH
PATH=/usr/local/bin:$PATH
hash -r            # 清空 hash 表(改了 PATH 后)
```

### 2.8 Shell Scripts — 脚本最佳实践

```bash
#!/usr/bin/env bash
# ↑ 用 env 而非 /bin/bash(兼容 BSD/macOS)

set -euo pipefail
# -e:任何命令失败立即退出
# -u:未定义变量报错
# -o pipefail:管道任一环节失败都算失败

# 注意:macOS Bash 3.2 不支持 ${EPOCHSECONDS},Bash 4+ 支持
# 注意:set -e 在函数 + if/&& 中行为不同(陷阱)
```

---

## 3. 第 4 章:Shell Builtin Commands(80+ 内建命令)

### 3.1 内建命令 vs 外部命令

| 类型 | 例子 | 区别 |
|---|---|---|
| **内建** | `cd` `echo` `read` `set` `export` | shell 内置实现,不 fork |
| **外部** | `ls` `cat` `grep` `awk` | 单独的二进制文件,需要 fork + exec |

== **为什么需要内建**:`cd` 必须修改当前 shell 的工作目录,**fork 子进程改不了父进程的 cwd**。

### 3.2 常用内建命令速查

| 类别 | 命令 | 作用 |
|---|---|---|
| **文件 / 目录** | `cd` `pwd` `pushd` `popd` `dirs` | 目录切换 |
| **变量** | `set` `unset` `export` `local` `declare` `typeset` | 变量管理 |
| **I/O** | `echo` `printf` `read` `readline` `mapfile` `source` | 输入输出 |
| **流程控制** | `if` `for` `while` `until` `case` `select` `break` `continue` `return` `exit` | 控制流 |
| **作业** | `jobs` `fg` `bg` `wait` `kill` `disown` | 作业控制 |
| **历史** | `history` `fc` | 命令历史 |
| **别名** | `alias` `unalias` | 别名 |
| **shell 行为** | `shopt` `set` `ulimit` `umask` `trap` `times` | 修改行为 |
| **特殊** | `:` `.` `[` `[[` `exec` `eval` `source` | shell 自身 |

### 3.3 4 个「行为修改」内建(关键)

```bash
# set -o / +o  :打开 / 关闭 shell 选项
set -e           # errexit   :命令失败立即退出
set -u           # nounset   :未定义变量报错
set -o pipefail  #           :管道任一环节失败都算失败
set -x           # xtrace    :执行前打印命令(调试)

# shopt -s / -u :shell 选项
shopt -s autocd        # 输入目录名直接 cd
shopt -s globstar      # ** 递归匹配
shopt -s dotglob       # * 匹配 . 开头的隐藏文件
shopt -s nocaseglob    # 大小写不敏感
```

---

## 4. 第 5 章:Shell Variables(变量完整参考)

### 4.1 Bourne Shell 变量(标准 POSIX)

| 变量 | 作用 |
|---|---|
| `HOME` | 用户主目录 |
| `PATH` | 命令搜索路径(`:` 分隔) |
| `IFS` | 内部字段分隔符(默认空格 / Tab / 换行)|
| `PS1` / `PS2` / `PS4` | 提示符 |
| `OPTARG` / `OPTIND` / `OPTERR` | getopts 解析 |
| `LANG` / `LC_*` | 本地化 |

### 4.2 Bash 特有变量(常用)

| 变量 | 作用 | 例子 |
|---|---|---|
| `BASH_VERSION` | Bash 版本 | `5.2.21(1)-release` |
| `BASH_SOURCE[0]` | 当前脚本路径 | |
| `BASH_LINENO[0]` | 调用行号 | |
| `BASH_COMMAND` | 当前命令 | |
| `BASHPID` | 当前 Bash 进程 PID | |
| `FUNCNAME[0]` | 当前函数名 | |
| `GROUPS` | 用户所属组 | |
| `HOSTNAME` | 主机名 | |
| `OSTYPE` | OS 类型(`linux-gnu` 等)| |
| `MACHTYPE` | CPU 架构(`x86_64-pc-linux-gnu`) | |
| `RANDOM` | 每次读都是新随机数 0-32767 | `$RANDOM` |
| `SECONDS` | shell 启动至今秒数 | |
| `LINENO` | 当前行号(脚本里)| |
| `PWD` / `OLDPWD` | 当前 / 上一个目录 | |
| `SHLVL` | shell 嵌套深度 | |
| `UID` / `EUID` | 用户 ID | |
| `PPID` | 父进程 PID | |
| `EPOCHSECONDS` | Unix epoch 秒(Bash 4+) | `$(date +%s)` |
| `EPOCHREALTIME` | Unix epoch + 微秒 | |

### 4.3 位置参数 + 特殊参数

```bash
$0       # 脚本自身路径
$1..$9   # 第 1-9 个参数
${10}    # 第 10+ 个参数(用大括号)
$#       # 参数个数
$@       # 全部参数,每个独立 quoting("$@" 保留)
$*       # 全部参数,IFS 第一个字符 join("$*" 不推荐)
$$       # 当前 shell PID
$!       # 上一个后台进程 PID
$?       # 上一个命令退出码(0=成功)
$-       # 当前选项(set -x 中会有 "x")
```

== **陷阱:`$@` vs `$*` 在 for 循环里行为不同**:

```bash
# "$@" 推荐:每个参数独立 quoting
for arg in "$@"; do
    echo "[$arg]"
done

# "$*" 不推荐:所有参数合并成一个字符串
for arg in "$*"; do
    echo "[$arg]"   # 只有一次循环,整个 "$*"
done
```

---

## 5. 第 6 章:Bash Features(Bash 特有高级特性)

### 5.1 Invoking Bash — 调用选项

```bash
bash [options] [file [args]]

# 常用选项
bash -c 'echo hello'      # 执行字符串命令
bash -i                   # 交互式 shell
bash -l                   # 登录 shell(读 /etc/profile,~/.bash_profile 等)
bash --noprofile          # 不读启动文件
bash --norc               # 不读 ~/.bashrc
bash -x script.sh         # 调试:执行前打印每条命令
bash -v script.sh         # 详细:执行时打印读入的命令
bash -e script.sh         # 任何命令失败立即退出
bash --posix              # 严格 POSIX 模式
bash --restricted         # 受限 shell(rbash,不能 cd 等)
```

### 5.2 Bash Startup Files — 启动文件读取顺序

== **Login shell**:
```
/etc/profile        ← 系统级
   ↓
~/.bash_profile     ← 用户级(优先)
或 ~/.bash_login     ← 备选
或 ~/.profile        ← 兜底
   ↓
~/.bashrc           ← 交互式 shell 才读
```

== **Non-login interactive shell**:
```
/etc/bash.bashrc
~/.bashrc
```

== **Non-interactive**:
```
$BASH_ENV 指向的文件
```

### 5.3 Interactive Shells — 交互模式行为

- 显示提示符
- 读 `~/.inputrc`(Readline 配置)
- 命令历史(默认 `~/.bash_history`)
- 别名展开
- 作业控制(默认开)
- 命令补补(programmable completion)

### 5.4 Conditional Expressions — 条件表达式

== **核心区分**:`[ ... ]` (test 命令) vs `[[ ... ]]` (Bash 关键字)

| 类别 | `[` | `[[` |
|---|---|---|
| **文件** | `[ -f file ]` | `[[ -f file ]]` |
| **字符串** | `[ -z "$s" ]` `[ "$a" = "$b" ]` | `[[ -z $s ]]` `[[ $a == $b ]]` |
| **数值** | `[ "$a" -eq "$b" ]` | `(( a == b ))` 或 `[[ $a -eq $b ]]` |
| **复合** | `[ ! -f file ]` `[ -f f ] && [ -d d ]` | `[[ ! -f file ]]` `[[ -f f && -d d ]]` |
| **模式匹配** | ❌(需 case) | `[[ $str == *.txt ]]` `[[ $str =~ regex ]]` |

```bash
# 文件测试
[[ -f file.txt ]]         # 普通文件存在
[[ -d /tmp ]]             # 目录存在
[[ -e file ]]             # 存在(任何类型)
[[ -r file ]]             # 可读
[[ -w file ]]             # 可写
[[ -x file ]]             # 可执行
[[ -L link ]]             # 符号链接
[[ -s file ]]             # 非空(大小 > 0)
[[ file1 -nt file2 ]]     # file1 比 file2 新
[[ file1 -ot file2 ]]     # file1 比 file2 旧

# 字符串
[[ -z $s ]]               # 空字符串
[[ -n $s ]]               # 非空
[[ $a == $b ]]            # 相等(== 是 Bash 扩展,POSIX 用 =)
[[ $a != $b ]]            # 不等
[[ $a < $b ]]             # 字典序(需转义 \<)
[[ $a == pattern* ]]      # 通配符匹配
[[ $a =~ regex ]]         # 正则匹配(Bash 3.2+)

# 数值(在 (()) 里)
(( a == b ))
(( a > b ))
(( a + b > 100 ))
```

### 5.5 Shell Arithmetic — 算术展开

```bash
# 算术展开
echo $(( 2 + 3 * 4 ))         # 14
echo $(( a << 2 ))            # 左移
echo $(( a & b ))             # 按位与
echo $(( a | b ))             # 按位或
echo $(( a ^ b ))             # 按位异或
echo $(( ~a ))                # 按位反
echo $(( a > b ? 1 : 0 ))     # 三目

# 算术命令(无 $,赋值)
(( count++ ))
(( sum += 5 ))
(( total = a * b + c ))

# 不同进制
echo $(( 16#FF ))             # 255(十六进制)
echo $(( 8#77 ))              # 63(八进制)
echo $(( 2#1010 ))            # 10(二进制)

# 整数变量声明
declare -i count=10          # 整数变量
let "count += 1"             # 等价于 (( count++ ))
```

### 5.6 Arrays — 数组(关键)

```bash
# 一维数组
arr=(apple banana cherry)
arr[3]=date

# 访问
echo "${arr[0]}"             # apple
echo "${arr[@]}"             # 所有元素(推荐)
echo "${arr[*]}"             # 所有元素(用 IFS join)
echo "${#arr[@]}"            # 元素个数
echo "${!arr[@]}"            # 所有下标(下标不连续时有用)

# 切片
echo "${arr[@]:1:2}"         # banana cherry(下标 1 起的 2 个)

# 操作
arr+=(grape)                 # 追加
unset arr[2]                 # 删除 cherry
arr=("${arr[@]/cherry/}")   # 删除 cherry

# 遍历
for fruit in "${arr[@]}"; do
    echo "$fruit"
done

# 关联数组(Bash 4+)
declare -A map
map[red]="#ff0000"
map[green]="#00ff00"
echo "${map[red]}"           # #ff0000
echo "${!map[@]}"            # red green
```

### 5.7 The Directory Stack — 目录栈

```bash
pushd /tmp                   # 压栈并 cd
pushd ~/projects

dirs                        # 查看栈

popd                         # 出栈并 cd
popd

# 用途:脚本里临时 cd 后回原位置
pushd /some/path > /dev/null
# do stuff
popd > /dev/null
```

### 5.8 Controlling the Prompt — PS1 自定义

```bash
# 常用转义
\a     # bell
\d     # 日期(Wed Aug 12)
\h     # 主机名
\H     # 完整主机名
\n     # 换行
\s     # shell 名(bash)
\t     # 时间 24h(HH:MM:SS)
\T     # 时间 12h(HH:MM:SS)
\@     # 时间 ampm
\u     # 用户名
\w     # 当前目录(完整路径)
\W     # 当前目录(基名)
\$     # # (root) 或 $ (普通用户)
\!     # 历史编号
\#     # 命令编号
\j     # 后台作业数

# 颜色(ANSI 转义)
\[\033[01;32m\]\u\[\033[00m\]@\[\033[01;34m\]\h\[\033[00m\]:\w\$
```

### 5.9 The Restricted Shell — 受限模式

```bash
# 限制:不能 cd,不能设 PATH,不能用 > 等重定向,不能执行带 / 的命令
# 用于权限最小化场景
rbash
```

### 5.10 Bash and POSIX — POSIX 模式

```bash
# 启动 POSIX 模式(去除 Bash 特有行为)
bash --posix

# 或在脚本里临时切换
set -o posix

# Bash 默认 POSIX 兼容,POSIX 模式更严格
# 主要差异:
# - 不展开 !(pattern) (Bash 历史扩展)
# - 不展开 {...}
# - [[ ]] 改成 [ ]
```

### 5.11 Shell Compatibility Mode — 兼容模式

```bash
# Bash 模拟 sh / ksh / csh 的行为
bash --compat32   # Bash 3.2 兼容(某些第三方工具需要)
emulate sh       # 在函数里模拟 sh(像 zsh 的 emulate)

# shopt 选项
shopt -s compat32
```

---

## 6. 第 7 章:Job Control(作业控制)

### 6.1 概念

| 术语 | 含义 |
|---|---|
| **作业**(job) | 一个或一组管道(由 shell 管理的进程组) |
| **前台作业** | 占据终端,等它结束 shell 才接受输入 |
| **后台作业** | 在后台运行,shell 可以继续接受输入 |

### 6.2 操作

```bash
cmd &              # 后台启动
jobs              # 列出当前 shell 的作业
fg %1             # 把作业 1 拉到前台
bg %1             # 把暂停的作业 1 继续在后台运行
Ctrl-Z            # 暂停当前前台作业(发 SIGTSTP)
kill %1           # 发信号给作业
wait %1           # 等待作业结束
disown %1         # 从 jobs 列表移除(但进程继续)
```

### 6.3 作业控制 vs nohup

```bash
nohup cmd &        # 不受 hangup 信号影响(登出后继续)
# 等价于:
cmd & disown
# + nohup 重定向输出到 nohup.out
```

---

## 7. 第 8 章:Command Line Editing(Readline)

### 7.1 两种编辑模式

```bash
set -o emacs   # 默认(Emacs 快捷键)
set -o vi      # VI 快捷键
```

### 7.2 常用快捷键(Emacs 模式)

| 快捷键 | 作用 |
|---|---|
| `Ctrl-A` | 跳到行首 |
| `Ctrl-E` | 跳到行尾 |
| `Ctrl-B` / `Ctrl-F` | 左 / 右移一个字符 |
| `Alt-B` / `Alt-F` | 左 / 右移一个词 |
| `Ctrl-U` | 删除到行首 |
| `Ctrl-K` | 删除到行尾 |
| `Ctrl-W` | 删除前一个词 |
| `Ctrl-D` | 删除当前字符(或 EOF) |
| `Ctrl-Y` | 粘贴(从 kill ring)|
| `Ctrl-L` | 清屏 |
| `Ctrl-R` | 反向搜索历史 |
| `Ctrl-S` | 正向搜索历史 |
| `Ctrl-P` / `Ctrl-N` | 上一条 / 下一条历史 |
| `Tab` | 自动补补 |
| `Alt-.` | 插入上一个命令的最后一个参数 |

### 7.3 Readline 配置:`~/.inputrc`

```ini
# ~/.inputrc 例子
set editing-mode vi
set completion-ignore-case on
set show-all-if-ambiguous on
"\C-x\C-e": edit-and-execute-command
```

---

## 8. 第 9 章:Using History Interactively

### 8.1 历史展开(默认开,`histexpand`)

```bash
!!       # 上一条命令
!$       # 上一条命令的最后一个参数
!^       # 上一条命令的第一个参数
!*       # 上一条命令的所有参数
!n       # 历史第 n 条命令
!string  # 以 string 开头的最近命令
!?string # 包含 string 的最近命令
^old^new^ # 上一条命令替换
!!:s/old/new/  # 上一条命令 sed 替换
```

### 8.2 配置历史

```bash
HISTFILE=~/.bash_history
HISTFILESIZE=2000      # 文件最多 2000 行
HISTSIZE=1000          # 内存中保留 1000 条
HISTCONTROL=ignoredups:ignorespace  # 忽略重复 + 空格开头的
HISTIGNORE="ls:cd:clear:exit"       # 不记录的命令

# 写入时间戳
HISTTIMEFORMAT="%F %T "
```

### 8.3 `history` 与 `fc` 内建

```bash
history            # 显示所有历史
history 10         # 显示最近 10 条
history -c         # 清空历史
history -d 100     # 删除第 100 条
history -a         # 追加到 HISTFILE
history -w         # 覆盖 HISTFILE

fc -l              # 等价于 history
fc 100 110         # 编辑命令 100-110 然后执行
fc -e vi 100       # 用 vi 编辑第 100 条
```

---

## 9. 第 10 章:Installing Bash

### 9.1 编译步骤

```bash
git clone https://git.savannah.gnu.org/git/bash.git
cd bash
./configure --prefix=/usr/local
make
make test          # 跑测试套件
sudo make install
```

### 9.2 重要 configure 选项

```bash
--with-bash-malloc           # 用 Bash 自带 malloc(性能更好)
--with-installed-readline    # 用系统 readline(否则用内置)
--enable-net-redirections    # 启用 /dev/tcp/host/port
--enable-progcomp           # 启用 programmable completion
--enable-usg-econf           # 启用 /etc/conf.d
--disable-nls               # 禁用国际化
```

### 9.3 版本差异

| 版本 | 重要特性 |
|---|---|
| Bash 2.0 | 基本 POSIX 兼容 |
| Bash 3.0 | 关联数组 + 通配符 |
| **Bash 4.0** | **关联数组** `declare -A` + `case ;;&` |
| **Bash 5.0** | **EPOCHSECONDS** + 改进变量 |
| Bash 5.2 | `wait -p` + 改进 coproc |

== **macOS 默认 Bash 3.2**(因为 GPLv3 vs Apple 商业协议问题),生产脚本推荐装 Bash 5+。

---

## 10. 附录 B:Bash vs Bourne Shell(关键差异)

| 特性 | Bourne Shell (sh) | Bash |
|---|---|---|
| 数组 | ❌ | ✅ |
| `{1..10}` brace expansion | ❌ | ✅ |
| `[[ ... ]]` 条件 | ❌ | ✅ |
| `(( ... ))` 算术 | ❌ | ✅ |
| `<<<` here-string | ❌ | ✅ |
| `${var//...}` 全部替换 | ❌ | ✅ |
| 关联数组 | ❌ | ✅ |
| 进程替换 `<()` `>()` | ❌ | ✅ |
| `[[ =~ ]]` 正则 | ❌ | ✅ |
| `case ;;&` | ❌ | ✅ |
| `coproc` | ❌ | ✅ |
| 调试 `set -x` | ✅ | ✅ |
| `trap` | ✅ | ✅ |

---

## 11. 12 大常见陷阱(实际工作会踩的)

### 11.1 忘记 quote

```bash
# ❌ 错误
if [ $var == "hello" ]; then
# 当 var 为空或含空格时:[: argument expected

# ✅ 正确
if [[ "$var" == "hello" ]]; then
# 或用 [[ ]] 自动处理空
if [[ $var == "hello" ]]; then
```

### 11.2 重定向顺序

```bash
# ❌ 错误顺序
cmd > file 2>&1
# stdout → file,stderr → stdout(最终到 file)— OK 但其实正确

# ❌ 错误顺序(陷阱)
cmd 2>&1 > file
# stderr → 当前 stdout(终端),stdout → file— stderr 不在 file
```

### 11.3 `for` 循环加引号

```bash
# ❌ 不加引号 — word splitting
for f in $files; do
    echo "$f"   # 文件名有空格会拆开
done

# ✅ 加引号 — 保留整体
for f in "$files"; do
    echo "$f"
done

# ✅ 数组推荐
arr=("$files")   # 数组
for f in "${arr[@]}"; do
    echo "$f"
done
```

### 11.4 `set -e` + `if`

```bash
# 陷阱:在 if 条件里 set -e 不会触发(故意为之)
set -e
if cmd; then     # cmd 失败 → if 失败 → set -e 不触发
    echo "ok"
fi

# 在 && 链里也类似
cmd && echo "ok"  # cmd 失败 → set -e 不触发(整链短路)
```

### 11.5 `cat file | while read line` 不修改原 shell 变量

```bash
# ❌ 陷阱:管道里的 while 在子 shell
count=0
cat file | while read line; do
    count=$((count + 1))  # 修改的是子 shell 的 count
done
echo $count  # 还是 0!

# ✅ 解决方法 1:避免管道
while read line; do
    count=$((count + 1))
done < file   # 重定向进 while(同进程)

# ✅ 解决方法 2:用 lastpipe(需开启)
shopt -s lastpipe
count=0
cat file | while read line; do
    count=$((count + 1))
done
echo $count  # 正确
```

### 11.6 `$RANDOM` 在同一行多次读

```bash
echo $RANDOM $RANDOM $RANDOM  # 每次读都是新随机数!
# 想要 3 个不同:echo $((RANDOM)) $((RANDOM)) $((RANDOM))
```

### 11.7 Bash 3.2 vs 5.x 兼容

```bash
# macOS 默认 Bash 3.2(2007),很多新特性没有:
# - ${EPOCHSECONDS} (Bash 5+)
# - ${var,,}  (Bash 4+)
# - declare -A 关联数组 (Bash 4+)
# - BASH_SOURCE 数组下标行为(Bash 4.4 fix)
```

### 11.8 `kill` 信号编号 vs 名字

```bash
kill 9       # SIGKILL
kill -9      # 同上
kill -SIGKILL
kill -l      # 列出所有信号
```

### 11.9 `[[ ]]` vs `[ ]` 行为差异

```bash
# [[ ]] 是 Bash 关键字,功能更强大:
# - 通配符:[[ $a == *.txt ]]  ✅
# - 正则:[[ $a =~ ^[0-9]+$ ]]  ✅
# - 不需要引号:[[ -n $a ]] 而非 [[ -n "$a ]]
# - 支持 && 和 ||:[[ $a && $b ]]

# [ ] 是 test 命令,POSIX 标准
# - 严格字符串比较:[ "$a" = "$b" ]
```

### 11.10 `set -u` + 数组空

```bash
set -u
arr=()
echo "${arr[0]}"  # bash: arr[0]: unbound variable
# 解:echo "${arr[0]:-}"  # 提供默认值
```

### 11.11 历史扩展陷阱

```bash
# bash 把 ! 当历史扩展
echo "Hello!"            # 通常 OK
echo 'Hello!'            # 单引号 OK
echo Hello!world         # 试图找历史命令 !world

# 关闭:在脚本里 set +H
# 或在命令行:set +o histexpand
```

### 11.12 `read` 不写也退出

```bash
# 输入终止(EOF)时 read 默认返回 1,导致 set -e 退出
set -e
while read line; do
    echo "$line"
done < file   # 文件结尾 EOF → read 返回 1 → set -e 触发
# 解:cat file | while read ...; do ...; done
# 或:while IFS= read -r line; do ...; done < file
#   -r 保留反斜杠
#   IFS= 不去前导 / 尾随空格
```

---

## 12. Bash vs 其他 Shell

| Shell | 优势 | 劣势 |
|---|---|---|
| **sh** (POSIX) | 标准、可移植、无依赖 | 功能弱 |
| **Bash** | POSIX + 大量扩展 | macOS 默认是 3.2 |
| **Zsh** | 交互体验最好、`zsh-completions` | 配置复杂(oh-my-zsh) |
| **Fish** | 用户友好、自动建议 | 语法不兼容 sh |
| **Dash** | 小、启动快、POSIX | 仅 POSIX,无扩展 |
| **Ash/BusyBox** | 嵌入式系统 | 功能极简 |

== **生产脚本推荐**:用 **Bash 5+**(明确 shebang `#!/usr/bin/env bash`),避免 sh 的功能太弱 + Zsh 的兼容性差。

---

## 13. 5 大常见 Bash使用场景

### 13.1 系统管理

```bash
# 服务管理
systemctl status nginx
journalctl -u nginx -f

# 进程
ps aux | grep nginx
pgrep nginx
kill $(pgrep nginx)
```

### 13.2 DevOps 脚本

```bash
# 部署脚本模板
#!/usr/bin/env bash
set -euo pipefail
trap 'echo "Failed at line $LINENO"' ERR

REPO=$1
BRANCH=${2:-main}
DEPLOY_DIR=/opt/$REPO

cd $REPO
git fetch origin $BRANCH
git reset --hard origin/$BRANCH

cd $DEPLOY_DIR
./build.sh
systemctl restart $REPO
```

### 13.3 数据处理

```bash
# 文本处理三剑客
grep pattern file.txt          # 搜索
sed -i 's/old/new/g' file.txt  # 替换
awk '{print $1}' file.txt      # 字段处理

# Bash 内置
while IFS=, read -r col1 col2 col3; do
    echo "$col1: $col2"
done < data.csv
```

### 13.4 CI/CD 流水线

```bash
# GitHub Actions / GitLab CI 都是 bash
- name: Build
  run: |
    make
    make test
```

### 13.5 系统初始化 / 启动脚本

```bash
# systemd 服务
[Service]
ExecStart=/usr/local/bin/myservice
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

---

## 14. 跟作者已有项目的关联

| 项目 | 关联 |
|---|---|
| **[opc.md](opc.md)** | Bash 写 OpenOPC shell scripts + 安装脚本 |
| **[fireside-sprint1.md](../ai-vibecoding-agents/fireside-sprint1.md)** | Bash 测试脚本 + 部署脚本 |
| **[substation-blueprint.md](../web-frontend-ui/)** | Bash 部署到 GitHub Pages |
| **[recovery-sop.md](recovery-sop.md)** | Bash 数据恢复 SOP(用 grep/awk/sed) |
| **[disable-ipv6-multi-kernel.md](disable-ipv6-multi-kernel.md)** | sed 修改 grub.cfg |
| **[ops-linux-sysadmin](../../)** | 各种 Linux 运维脚本 |
| **[remote-obd-usb-over-ip.md](remote-obd-usb-over-ip.md)** | Bash 跑 systemd + FRP |

== **核心洞察**:**Bash 是「Linux 运维的编程语言」** — 比 Python 更轻量,比 sh 功能强,几乎所有服务器操作都有 Bash 影子。

---

## 15. 5 大最佳实践

### 15.1 顶部 5 行必备

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
# ↑ -e:错误退出
#   -u:未定义变量报错
#   -o pipefail:管道错误传播
#   IFS 改掉(避免 word splitting 陷阱)
```

### 15.2 写函数而非复制粘贴

```bash
# ❌ 重复代码
log_info() { echo "[INFO] $(date +%T) $*"; }
log_error() { echo "[ERROR] $(date +%T) $*"; }
log_debug() { echo "[DEBUG] $(date +%T) $*"; }

# ✅ 带日志级别 + 颜色
log() {
    local level=$1
    shift
    local color
    case $level in
        INFO)  color='\033[0;32m' ;;  # green
        WARN)  color='\033[0;33m' ;;  # yellow
        ERROR) color='\033[0;31m' ;;  # red
        *)     color='\033[0m' ;;
    esac
    printf "${color}[%s] %s\033[0m\n" "$level" "$*"
}
log INFO "Starting..."
log ERROR "Failed!"
```

### 15.3 用 `[[ ]]` 不用 `[ ]`

```bash
# 推荐用 [[ ]]
[[ -f $file && -r $file ]] && echo "readable file"
[[ $a =~ ^[0-9]+$ ]] && echo "is number"
```

### 15.4 引号包裹变量

```bash
echo "$var"               # 而不是 echo $var
[[ "$var" == "x" ]]       # 而不是 [[ $var == x ]]
```

### 15.5 避免全局状态污染

```bash
# 函数内尽量 local
myfunc() {
    local tmp=$(mktemp)
    # ...
    rm -f "$tmp"
}

# 用 subshell 隔离
(
    cd /tmp
    work_stuff
)

# 用 trap 清理
trap 'rm -rf "$tmpdir"' EXIT
```

---

## 16. 引用与参考

- **Bash PDF 官方手册**: <https://www.gnu.org/software/bash/manual/bash.pdf>
- **HTML mirror(Chet Ramey 维护)**: <https://tiswww.case.edu/php/chet/bash/bashref.html>
- **Texinfo 源码**: <https://git.savannah.gnu.org/cgit/bash.git/plain/doc/bashref.texi>
- **Linux man-page**: <https://man7.org/linux/man-pages/man1/bash.1.html>
- **Bash Git 仓库**: <https://git.savannah.gnu.org/cgit/bash.git>
- **Bash FAQ**: <https://mywiki.wooledge.org/BashFAQ>
- **Bash Pitfalls**: <https://mywiki.wooledge.org/BashPitfalls>
- **Google Shell Style Guide**: <https://google.github.io/styleguide/shellguide.html>
- **Defensive Bash Programming**: <https://www.kfirlavi.com/blog/2012/11/14/defensive-bash-programming/>

## 17. TL;DR — 给 Bash 使用者的 1 句话

> **Bash 是 POSIX 超集** — 有 8 大展开、13 类重定向、80+ 内建命令、关联数组、Bash 特有的 `[[ ]]` `(( ))` `<<<` `<()` 等。**生产必装 Bash 5+**,**脚本顶部必加 `set -euo pipefail + IFS=$'\n\t'`**,**变量必加引号**,**用 `[[ ]]` 不用 `[ ]`**。

== **最后**:**Bash 4+ 有 EPOCHSECONDS + 关联数组,Bash 5+ 有 wait -p**,**用 Bash 5+ 写生产脚本最稳**。