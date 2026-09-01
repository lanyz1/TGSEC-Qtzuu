---
name: disk-forensics-evasion
description: "磁盘取证与反磁盘取证方法论。理解蓝队如何从磁盘恢复删除文件、提取时间线、分析文件系统 artifact，以及红队如何进行反取证（安全删除、时间戳篡改、痕迹清除）。当需要规避磁盘取证或进行磁盘分析时使用"
metadata:
  tags: "disk,forensics,anti-forensics,timestomp,file-recovery,MFT,NTFS,ext4,artifact,磁盘取证,反取证,时间戳"
  category: "dfir"
  mitre_attack: "T1070,T1070.004,T1070.006,T1036.006,T1564.001"
---

# 磁盘取证与反磁盘取证

> **双面视角**：蓝队从磁盘中恢复证据 → 红队确保证据不可恢复

## ⛔ 深入参考

- Windows NTFS artifact 详解与清除方法 → [references/ntfs-artifacts.md](references/ntfs-artifacts.md)
- Linux ext4 取证与反取证 → [references/linux-disk-forensics.md](references/linux-disk-forensics.md)

---

## Part A: 蓝队视角 — 磁盘取证

### Phase 1: 证据获取

```bash
# 使用 dcfldd 完整镜像（含哈希校验）
dcfldd if=/dev/sdb of=/evidence/disk.dd \
  hash=sha256 hashlog=/evidence/disk.sha256 \
  bs=4096 conv=noerror,sync

# 使用 E01 格式（压缩+分片）
ewfacquire /dev/sdb -t /evidence/disk \
  -c deflate -S 2G -e "Case INC-2025"

# 验证完整性
sha256sum /evidence/disk.dd
```

### Phase 2: 文件系统分析决策树

```
文件系统类型？
├─ NTFS (Windows) → MFT分析 / USN Journal / $LogFile
├─ ext4 (Linux) → inode / journal / superblock
├─ APFS (macOS) → diskutil / apfs_parser
└─ FAT32 (USB) → 简单文件表 / 簇分析
```

### Phase 3: Windows NTFS 关键 Artifact

| Artifact | 位置 | 内容 |
|----------|------|------|
| $MFT | 卷根 | 每个文件的元数据（时间戳、大小、路径） |
| $UsnJrnl | $Extend\ | 文件变更日志（创建/删除/重命名） |
| $LogFile | 卷根 | NTFS 事务日志 |
| Prefetch | C:\Windows\Prefetch\ | 程序执行记录（最后8次执行时间） |
| Amcache | C:\Windows\AppCompat\ | 程序首次执行+SHA1 |
| Shimcache | 注册表 | 程序兼容性缓存 |
| LNK 文件 | Recent\ | 最近访问文件记录 |
| Jump Lists | CustomDestinations\ | 任务栏程序历史 |
| $Recycle.Bin | 卷根 | 回收站（$I=元数据 $R=内容） |
| VSS | System Volume Information | 卷影副本（历史快照） |

```bash
# Sleuth Kit 分析
fls -r -p /evidence/disk.dd        # 递归列出文件（含已删除）
icat /evidence/disk.dd <inode>     # 按 inode 提取文件内容
tsk_recover -r /evidence/disk.dd /output/  # 恢复已删除文件

# MFT 解析
python3 analyzeMFT.py -f \$MFT -o mft_output.csv

# 时间线生成
log2timeline.py /evidence/timeline.plaso /evidence/disk.dd
psort.py -o l2tcsv /evidence/timeline.plaso > timeline.csv
```

### Phase 4: Linux ext4 关键 Artifact

| Artifact | 内容 |
|----------|------|
| /var/log/ | 系统日志（auth.log, syslog, wtmp, btmp） |
| .bash_history | 命令历史 |
| /tmp/ | 临时文件（攻击者常用目录） |
| crontab | 持久化计划任务 |
| /etc/passwd + shadow | 新增账户 |
| journal (ext4) | 文件系统操作日志 |
| inode timestamps | atime/mtime/ctime/crtime |

---

## Part B: 红队视角 — 反磁盘取证

### 策略 1: 安全删除（不可恢复）

```bash
# ⛔ 普通 rm 只删除 MFT 条目，数据仍在磁盘！

# Linux 安全删除
shred -vfz -n 3 target_file      # 多次覆写+零填充
srm -sz target_file               # 安全删除

# Windows 安全删除
cipher /w:C:\path\                # 覆写可用空间
sdelete -p 3 target_file          # Sysinternals 安全删除

# 内存文件系统操作（不触盘）
# Linux: 在 /dev/shm 或 tmpfs 操作
mkdir /dev/shm/.work && cd /dev/shm/.work
# Windows: 使用 Named Pipe / 内存 mapped file
```

### 策略 2: 时间戳篡改 (Timestomping / T1070.006)

```bash
# Linux: touch 修改 atime/mtime
touch -t 202301011200.00 malware.elf    # 伪装成旧文件
touch -r /bin/ls malware.elf            # 匹配合法文件时间

# Windows: PowerShell
$(Get-Item file.exe).CreationTime = "01/01/2023 12:00:00"
$(Get-Item file.exe).LastWriteTime = "01/01/2023 12:00:00"
$(Get-Item file.exe).LastAccessTime = "01/01/2023 12:00:00"

# ⛔ 注意：NTFS 有 4 组时间戳！
# $STANDARD_INFORMATION 的时间 → 上面的方法可改
# $FILE_NAME 的时间 → 只能通过 NTFS 底层操作修改
# 蓝队对比两组时间差异 → 发现 timestomping
```

### 策略 3: Artifact 清除清单

```
Windows 操作后清除：
├─ Prefetch → 删除 C:\Windows\Prefetch\TOOLNAME-*.pf
├─ Amcache → 删除注册表条目（需要 SYSTEM 权限）
├─ Shimcache → 内存中缓存，重启前修改注册表
├─ USN Journal → fsutil usn deletejournal /d C:
├─ Event Log → wevtutil cl Security/System/Application
├─ Recent/LNK → 删除 %APPDATA%\Microsoft\Windows\Recent\*
├─ Jump Lists → 删除 CustomDestinations\*
├─ $Recycle.Bin → 已手动删除就不进回收站
└─ Thumbcache → 删除 %LocalAppData%\Microsoft\Windows\Explorer\thumbcache*

Linux 操作后清除：
├─ .bash_history → unset HISTFILE 或 export HISTSIZE=0
├─ /var/log/ → 精准修改（不要清空，会被发现）
├─ wtmp/btmp → utmpdump → 编辑 → utmpdump -r
├─ auth.log → sed -i 删除特定行
├─ journal → journalctl --vacuum-time=1h
└─ /tmp/ 文件 → shred 后删除
```

### 策略 4: 最佳实践 — 从一开始减少痕迹

```
OPSEC 最优方案（预防 > 清除）：
├─ 工具不落盘 → 内存执行（反射加载/fileless）
├─ 使用 RAM 磁盘 → /dev/shm 或 tmpfs
├─ 操作前 unset HISTFILE → 不记录命令
├─ 使用 LOLBins → 不引入新文件
├─ 通过管道传输 → curl | python 不落盘
├─ 加密落盘文件 → 即使被发现也无法分析
└─ 最短驻留时间 → 用完即删
```

## 对照表：取证技术 vs 红队对策

| 蓝队手段 | 红队暴露 | 红队对策 |
|----------|---------|---------|
| 文件恢复（icat/tsk_recover） | rm 后数据仍在 | shred/sdelete 覆写 |
| 时间线分析（plaso） | 操作时间异常 | timestomping |
| MFT 分析 | $FN时间戳未改 | 底层 NTFS 操作或不落盘 |
| USN Journal | 文件操作记录 | 删除 USN Journal |
| Prefetch 分析 | 工具执行记录 | 删除 .pf 或不用独立 EXE |
| 卷影副本 | 历史文件快照 | vssadmin delete shadows |
| 日志分析 | 登录/操作记录 | 精确日志行删除（非清空） |
