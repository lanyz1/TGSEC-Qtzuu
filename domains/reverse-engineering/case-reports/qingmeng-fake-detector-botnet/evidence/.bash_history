bash go.sh
go run xiazai.go
bash go.sh
go run xiazai.go
source ~/.bashrc
go version
go run xiazai.go
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
systemctl stop oracle-cloud-agent
systemctl disable oracle-cloud-agent
systemctl stop oracle-cloud-agent-updater
systemctl disable oracle-cloud-agent-updater
systemctl stop firewalld.service
systemctl disable firewalld.service
rm -rf /etc/iptables && reboot
screen -m
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
screen -m
kill 15220
screen -r
cd web
unzip web.zip
y
rm -f bpjk
ls
screen -d
screen -r
screen -m
screen -r
screen -r 706402
top
screen -r 706402
screen -r
screen -r 706402
screen -r 
screen -m
kill 3585546
top
screen -r
screen -r 706402
screen -r
screen -r 1373
ls
python3 mg.py
source myenv/bin/activate
python3 mg.py
go run ccmg.go
python3 mg.py
apt install python3-venv -y
python3 -m venv myenv
source myenv/bin/activate
python3 mg.py
pip install dnslib
python3 mg.py
pip install flask
python3 mg.py
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
python3 mg.py
go run ccmg.go
curl -s "https://api.telegram.org/bot<7642554965:AAEpE_TFnLzzEnD2MeeNZV20z6D5_kyfDXg>/getUpdates"
curl -s "https://api.telegram.org/bot7642554965:AAEpE_TFnLzzEnD2MeeNZV20z6D5_kyfDXg/getUpdates"
go run ccmg.go
screen -r
screen -r 706402
screen -r
screen -r3544870
screen -r 3544870
kill 3544870
screen -r
screen -r 706402
kill 706402
screen -r
go run ccmg.go
screen -d
screen -m
iptables --version
screen -r
screen -r 124165
screen -r
screen -d
screen -r 124165
iptables -I INPUT -p tcp --dport 8080 -s 66.154.107.251 -j DROP
iptables -I INPUT -p tcp --dport 8080 -s 142.171.77.234 -j DROP
iptables -I INPUT -p tcp --dport 8080 -s 49.79.43.58 -j DROP
screen -r
screen -r 124165
curl -X POST "https://api.telegram.org/bot7642554965:AAEpE_TFnLzzEnD2MeeNZV20z6D5_kyfDXg/sendMessage" -H "Content-Type: application/json" -d '{
  "chat_id": 7210850213,
  "text": "这是一条测试消息"
}'
go run ccmg.go
kill 124165
screen -m
kill 246448
screen -r
screen -r 202609
go runiazai.go
go run xiazai.go
cd web
unzip web.zip
apt install unzip -y
unzip web.zip
cd ~
go run xiazai.go
unzip web.zip
cd web
unzip web.zip
cd ~
go run xiazai.go
screen -r
ls
screen -m
screen -r
cd web
rm -f linux_*
screen -r
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o xiazai xiazai.go
ls
bash jxby.sh
screen -m
screen -r
screen -r 402500
bash jxby.sh
screen -r
screen -r 1112011
screen -r
screen -r 402500
mipsel-linux-gnu-gcc -fcommon udp.c -o mipsel -static
apt install gcc-mipsel-linux-gnu
mipsel-linux-gnu-gcc -fcommon udp.c -o mipsel -static
bash jxby.sh
wget https://musl.cc/riscv32-linux-musl-cross.tgz
reboot
ping baidu.com
screen -m
screen -r
screen -m
screen -r
screen -r 1337
cd web
mv linux_mipsel linux_mpsel
screen -r
screen -r 1337
bash jxby.sh
./toolchain/sh4/bin/sh4-linux-musl-gcc -static -v -o test udp.c -pthread
wget https://toolchains.bootlin.com/downloads/releases/toolchains/sh4/tarball/sh4--musl--stable-2024.02-1.tar.bz2
tar -xjf sh4--musl--stable-2024.02-1.tar.bz2
# 解压后，工具链在 sh4--musl--stable-2024.02-1/ 目录下，bin 内有 sh4-linux-musl-gcc
export PATH=$PWD/sh4--musl--stable-2024.02-1/bin:$PATH
sh4-linux-musl-gcc -static -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread
tar -xjf sh4--musl--stable-2024.02-1.tar.bz2
wget https://toolchains.bootlin.com/downloads/releases/toolchains/sh-sh4aeb/tarballs/sh-sh4aeb--musl--stable-2025.08-1.tar.bz2
git clone https://github.com/richfelker/musl-cross-make.git
cd musl-cross-make
echo "TARGET = sh4-linux-musl" >> config.mak
make -j$(nproc)
export PATH=$PWD/output/bin:$PATH
sh4-linux-musl-gcc -static -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread
cd ~
sh4-linux-musl-gcc -sta
tic -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread
sh4-linux-musl-gcc -static -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread
export PATH=$PWD/output/bin:$PATH
sh4-linux-musl-gcc -static -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread
sh4-linux-musl-gcc --version
# 1. 进入 musl-cross-make 目录
cd ~/musl-cross-make
# 2. 确认已经配置过目标（如果未配置，执行这行）
echo "TARGET = sh4-linux-musl" >> config.mak
# 3. 开始编译工具链（需要较长时间，请耐心等待）
make -j$(nproc)
# 4. 编译完成后，将工具链加入 PATH
export PATH=$PWD/output/bin:$PATH
# 5. 验证编译器是否可用
sh4-linux-musl-gcc --version
# 6. 如果显示版本信息，则可以编译你的程序（确保 udp.c 在当前目录或指定路径）
sh4-linux-musl-gcc -static -s -O2 -D_GNU_SOURCE -o linux_sh4 udp.c -pthread
ls -l output/bin/
cd ~/musl-cross-make
make -j$(nproc)
cd ~/musl-cross-make
make -j$(nproc)
go run xiazai.go
bash mn.sh
reboot
sceen -m
screen -S xz
bash mn.sh
# 将 chroot 内 /root/linux_mipsel 复制到当前目录
sudo cp ./rootfs-mipsel/root/linux_mipsel ./
sudo chroot ./rootfs-mipsel /usr/bin/qemu-mipsel-static /bin/bash
# 在主机上执行（不要在 chroot 内）
sudo cp udp.c ./rootfs-mipsel/root/
sudo chroot ./rootfs-mipsel /usr/bin/qemu-mipsel-static /bin/bash
# 在主机上执行（不要在 chroot 内）
sudo cp udp.c ./rootfs-mipsel/root/
sudo cp ./rootfs-mipsel/root/linux_mipsel ./
# 确保您的主机上有更新后的 udp.c
sudo cp udp.c ./rootfs-mipsel/root/
# 1. 杀死主进程和所有子进程（递归）
pkill -9 -f linux_mipsel
# 2. 清理僵尸进程
sudo kill -9 $(pgrep -f linux_mipsel) 2>/dev/null
# 方法三完整命令（可直接复制粘贴）
pkill -9 -f linux_mipsel
sudo kill -9 $(pgrep -f linux_mipsel) 2>/dev/null
# 1. 杀掉所有 QEMU 模拟器进程
sudo pkill -9 qemu-mipsel-static
# 1. 杀掉所有 QEMU 模拟器进程
sudo pkill -9 qemu-mipsel-static
# 1. 杀掉所有 QEMU 模拟器进程
sudo pkill -9 qemu-mipsel-static
# 1. 查找所有 mipsel 客户端进程
ps aux | grep linux_mipsel | grep -v grep
# 2. 强制杀死（假设进程 PID 是 12345）
sudo kill -9 12345
sudo reboot
./xiazai
qemu-mipsel-static ./linux_mipsel
reboot
# 杀掉所有相关进程（包括伪装名称的）
sudo pkill -9 -f "linux_mipsel|qemu-mipsel"
#
sudo lsof | grep linux_mipsel | awk '{print $2}' | sort -u | xargs sudo kill -9
bash -c '
pkill -f udpclient
pkill -f /var/tmp/.sysbak
chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/rc.local /etc/init.d/udpclient /etc/inittab /etc/profile 2>/dev/null
rm -f /usr/bin/udpclient /var/tmp/.sysbak /tmp/.cronudp /tmp/udp_shell.log
sed -i "/udpclient/d" /etc/rc.local
crontab -l 2>/dev/null | grep -v udpclient | crontab - 2>/dev/null
update-rc.d udpclient remove 2>/dev/null
chkconfig --del udpclient 2>/dev/null
rm -f /etc/init.d/udpclient
sed -i "/udpclient/d" /etc/inittab
sed -i "/\/usr\/bin\/udpclient/d" /etc/profile
echo "✅ 清理完成！"
'
sudo bash -c '
# 1. 用 pkill 直接杀掉
pkill -9 -f "linux_mipsel|qemu-mipsel-static" 2>/dev/null

# 2. 通过 /proc 扫描所有进程，杀死所有执行文件或命令行包含关键字的
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
    if [ -L "/proc/$pid/exe" ]; then
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr "\0" " ")
        if [[ "$exe" == *"linux_mipsel"* ]] || [[ "$exe" == *"qemu-mipsel"* ]] || [[ "$cmd" == *"linux_mipsel"* ]] || [[ "$cmd" == *"qemu-mipsel"* ]]; then
            kill -9 $pid 2>/dev/null
        fi
    fi
done

# 3. 清理僵尸（可选）
wait 2>/dev/null

# 4. 确认剩余
ps aux | grep -E "linux_mipsel|qemu-mipsel" | grep -v grep || echo "✅ 已全部清理"
'
reboot
bash jxby.sh
#!/bin/bash
# =============================================================
# 宿主机彻底清理 MIPS 客户端（包括所有持久化痕迹）
# 请在宿主机（非 chroot）以 root 权限运行
# =============================================================
set -e
echo "🔍 开始清理客户端..."
# 1. 强制杀死所有相关进程（包括伪装进程名）
echo "💀 杀死进程..."
pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak" 2>/dev/null || true
# 通过 /proc 扫描所有进程（精确匹配执行文件路径）
for pid in $(ls /proc | grep -E '^[0-9]+$' 2>/dev/null); do     if [ -L "/proc/$pid/exe" ]; then         exe=$(readlink "/proc/$pid/exe" 2>/dev/null);         cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ');         if [[ "$exe" == *"linux_mipsel"* ]] || [[ "$exe" == *"udpclient"* ]] ||            [[ "$exe" == *".sysbak"* ]] || [[ "$cmd" == *"linux_mipsel"* ]] ||            [[ "$cmd" == *"udpclient"* ]] || [[ "$cmd" == *".sysbak"* ]]; then             kill -9 $pid 2>/dev/null || true;         fi;     fi; done
# 查找所有包含 "udpclient" 或 ".sysbak" 的文件
find / -type f -name "*udpclient*" 2>/dev/null
find / -type f -name "*.sysbak*" 2>/dev/null
# 查找所有可能的自启动脚本
grep -r "udpclient" /etc/ 2>/dev/null
grep -r ".sysbak" /etc/ 2>/dev/null
# 1. 杀死所有相关进程
sudo pkill -9 -f "udpclient|.sysbak|linux_mipsel" 2>/dev/null
reboot
# 1. 移除不可变属性（否则无法删除）
sudo chattr -i /usr/bin/udpclient /var/tmp/.sysbak 2>/dev/null
sudo pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak"
# 移除不可变属性
sudo chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/init.d/udpclient 2>/dev/null
ls -d ./rootfs-mipsel
sudo chroot ./rootfs-mipsel /usr/bin/qemu-mipsel-static /bin/bash
./xiazai
screen -m
# 1. 移除不可变属性（否则无法删除）
sudo chattr -i /usr/bin/udpclient /var/tmp/.sysbak 2>/dev/null
sudo reboot
sudo pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak"
# 移除不可变属性
sudo chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/init.d/udpclient 2>/dev/null
sudo reboot
#!/bin/bash
# ============================================================
# 彻底清除 MIPS 客户端（所有进程、文件、自启动）
# 在宿主机（非 chroot）以 root 权限运行
# ============================================================
set -e
echo "🔍 开始全面清理..."
# 1. 杀死所有相关进程（包括伪装进程名和 QEMU）
echo "💀 杀死进程..."
pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak" 2>/dev/null || true
# 通过 /proc 扫描所有进程（精确匹配执行文件路径）
for pid in $(ls /proc | grep -E '^[0-9]+$' 2>/dev/null); do     if [ -L "/proc/$pid/exe" ]; then         exe=$(readlink "/proc/$pid/exe" 2>/dev/null);         cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ');         if [[ "$exe" == *"linux_mipsel"* ]] || [[ "$exe" == *"udpclient"* ]] ||            [[ "$exe" == *".sysbak"* ]] || [[ "$cmd" == *"linux_mipsel"* ]] ||            [[ "$cmd" == *"udpclient"* ]] || [[ "$cmd" == *".sysbak"* ]]; then             kill -9 $pid 2>/dev/null || true;         fi;     fi; done
# 查找所有包含关键字“udpclient”的文件
find / -type f -name "*udpclient*" 2>/dev/null
# 查找所有可能的自启动配置（排除 /proc 和 /sys）
grep -r "udpclient" /etc/ /var/spool/cron/ 2>/dev/null
# 1. 强制杀死所有相关进程（包括伪装名和 QEMU）
sudo pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak" 2>/dev/null
./xiazai
screen -m
# 1. 强制杀死所有相关进程（包括伪装名和 QEMU）
sudo pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak" 2>/dev/null
# 扫描所有用户的 crontab
for user in $(cut -f1 -d: /etc/passwd); do     sudo crontab -u $user -l 2>/dev/null | grep udpclient && echo "找到 $user 的 crontab"; done
# 检查 systemd timers
sudo systemctl list-timers --all | grep udpclient
# 检查 /etc/cron.d/ 和 /etc/cron.daily/ 等
grep -r udpclient /etc/cron* 2>/dev/null
sudo crontab -l | grep -v udpclient | sudo crontab -
# 1. 清除 root 的 crontab
sudo crontab -l | grep -v udpclient | sudo crontab -
# 2. 杀死所有残留进程
sudo pkill -9 -f "udpclient|linux_mipsel|qemu-mipsel-static|.sysbak" 2>/dev/null
sudo reboot
bash -c '
pkill -f udpclient
pkill -f /var/tmp/.sysbak
chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/rc.local /etc/init.d/udpclient /etc/inittab /etc/profile 2>/dev/null
rm -f /usr/bin/udpclient /var/tmp/.sysbak /tmp/.cronudp /tmp/udp_shell.log
sed -i "/udpclient/d" /etc/rc.local
crontab -l 2>/dev/null | grep -v udpclient | crontab - 2>/dev/null
update-rc.d udpclient remove 2>/dev/null
chkconfig --del udpclient 2>/dev/null
rm -f /etc/init.d/udpclient
sed -i "/udpclient/d" /etc/inittab
sed -i "/\/usr\/bin\/udpclient/d" /etc/profile
echo "✅ 清理完成！"
'
# 1. 强制杀死所有相关进程（包括伪装名和 QEMU）
sudo pkill -9 -f "linux_mipsel|qemu-mipsel-static|udpclient|.sysbak" 2>/dev/null
# 1. 清除 root 的 crontab
sudo crontab -l | grep -v udpclient | sudo crontab -
# 2. 杀死所有残留进程
sudo pkill -9 -f "udpclient|linux_mipsel|qemu-mipsel-static|.sysbak" 2>/dev/null
sudo reboot
# 清除 root 的 crontab（@reboot 任务）
sudo crontab -l 2>/dev/null | grep -v udpclient | sudo crontab - 2>/dev/null
# 清除其他用户的 crontab（如果有）
for user in $(cut -f1 -d: /etc/passwd); do     sudo crontab -u "$user" -l 2>/dev/null | grep -v udpclient | sudo crontab -u "$user" - 2>/dev/null; done
# 禁用 systemd 服务（如果有）
sudo systemctl stop udpclient 2>/dev/null
# 移除不可变属性
sudo chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/init.d/udpclient 2>/dev/null
# 先杀掉所有相关进程（包括可能伪装名称的）
sudo pkill -9 -f "udpclient|linux_mipsel|qemu-mipsel-static|.sysbak" 2>/dev/null
# 创建空文件占位，并设置不可变，防止被覆盖
sudo touch /usr/bin/udpclient
sudo reboot
#!/bin/bash
set -e
echo "🔪 开始终极阻断..."
# 1. 强制杀死所有可能相关的进程（包括看门狗）
for signal in 9 15; do     pkill -$signal -f "udpclient|linux_mipsel|qemu-mipsel-static|.sysbak" 2>/dev/null || true;     pkill -$signal -f "kworker|ksoftirqd|watchdog" 2>/dev/null || true  # 误杀风险，但系统会重启这些内核线程，没关系
done
# 2. 去除所有不可变属性
chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/init.d/udpclient /etc/rc.local /etc/profile /etc/inittab 2>/dev/null || true
# 3. 删除所有找到的副本（包括 chroot、/tmp 等）
find / -name "*udpclient*" -type f -exec rm -f {} \; 2>/dev/null
find / -name "*.sysbak*" -type f -exec rm -f {} \; 2>/dev/null
# 4. 彻底清除所有自启动（全部禁用）
systemctl stop udpclient 2>/dev/null || true
systemctl disable udpclient 2>/dev/null || true
rm -f /etc/systemd/system/udpclient.service /run/systemd/generator.late/udpclient.service
update-rc.d udpclient remove 2>/dev/null || true
chkconfig --del udpclient 2>/dev/null || true
#!/bin/bash
set -e
echo "🔪 开始终极阻断..."
# 1. 强制杀死所有可能相关的进程（包括看门狗）
for signal in 9 15; do     pkill -$signal -f "udpclient|linux_mipsel|qemu-mipsel-static|.sysbak" 2>/dev/null || true;     pkill -$signal -f "kworker|ksoftirqd|watchdog" 2>/dev/null || true  # 误杀风险，但系统会重启这些内核线程，没关系
done
# 2. 去除所有不可变属性
chattr -i /usr/bin/udpclient /var/tmp/.sysbak /etc/init.d/udpclient /etc/rc.local /etc/profile /etc/inittab 2>/dev/null || true
# 3. 删除所有找到的副本（包括 chroot、/tmp 等）
find / -name "*udpclient*" -type f -exec rm -f {} \; 2>/dev/null
find / -name "*.sysbak*" -type f -exec rm -f {} \; 2>/dev/null
# 4. 彻底清除所有自启动（全部禁用）
systemctl stop udpclient 2>/dev/null || true
systemctl disable udpclient 2>/dev/null || true
rm -f /etc/systemd/system/udpclient.service /run/systemd/generator.late/udpclient.service
update-rc.d udpclient remove 2>/dev/null || true
chkconfig --del udpclient 2>/dev/null || true
sed -i '/udpclient/d' /etc/rc.local /etc/profile /etc/inittab /etc/crontab 2>/dev/null
./xiazai
screen -m
# 如果之前挂载了 proc、sys、dev，需要先卸载
sudo umount -l ./rootfs-mipsel/proc 2>/dev/null
sudo rm -rf ./rootfs-mipsel
# 如果之前挂载了 proc、sys、dev，需要先卸载
sudo umount -l ./rootfs-mipsel/proc 2>/dev/null
sudo rm -rf ./rootfs-mipsel
rm -f ./linux_mipsel   # 删除之前编译的二进制
screen -r
screen -m
bash jxby.sh
# 删除整个 toolchain 目录（重新下载 Bootlin 版本）
rm -rf ./toolchain
bash jxby.sh
reboot
bash jxby.sh
screen -S xz
screen -S by
cd wb
cd web
rm -f linux*
ls
screen -r xz
screen -r
screen -r by
screen -r xz
screen -r by
screen -r xz
cd web
mv linux_x86_64 linux_amd64
screen -r
screen -r xz
