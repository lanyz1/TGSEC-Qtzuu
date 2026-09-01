---
name: c2-beacon-analysis
description: "C2 Beacon 配置提取与分析。当捕获到 Cobalt Strike/Sliver/Havoc 等 C2 框架的 Beacon 样本、内存 dump、或网络流量时使用。提取 C2 地址、通信协议、Malleable Profile、Watermark 等关键情报。红队视角：了解蓝队如何从 Beacon 提取 IOC 以改进 C2 OPSEC"
metadata:
  tags: "c2,beacon,cobalt strike,sliver,havoc,malleable,watermark,配置提取,C2分析,threat hunting"
  category: "malware"
  mitre_attack: "T1071.001,T1573,T1095,T1572,T1090"
---

# C2 Beacon 配置提取与分析

> **红队价值**：了解 Beacon 泄露哪些配置信息 → 定制 Malleable Profile → 加强 C2 OPSEC

## ⛔ 深入参考

- CS Beacon 手动解密与 TLV 解析 → [references/cs-beacon-decrypt.md](references/cs-beacon-decrypt.md)
- Sliver/Havoc/Mythic Implant 分析 → [references/modern-c2-analysis.md](references/modern-c2-analysis.md)

---

## Phase 1: Beacon 类型识别

```
捕获的样本类型？
├─ PE/DLL 文件 → Phase 2（配置提取）
├─ Shellcode → Phase 2（需先识别 stage）
├─ 内存 dump → Phase 3（内存扫描）
├─ PCAP 流量 → Phase 4（流量解码）
└─ 进程 dump（MiniDump）→ Phase 3
```

**快速识别 C2 框架：**
```bash
# YARA 扫描识别框架
yara -r c2_rules.yar sample.bin

# 字符串特征
strings sample.bin | grep -iE "(beacon|sleeptime|jitter|watermark|pipe)"   # CS
strings sample.bin | grep -iE "(sliver|implant|mtls|wg)"                   # Sliver
strings sample.bin | grep -iE "(havoc|demon|teamserver)"                   # Havoc
```

## Phase 2: Cobalt Strike Beacon 配置提取

### 自动提取（首选）

```python
from dissect.cobaltstrike.beacon import BeaconConfig
import json

configs = list(BeaconConfig.from_path("beacon.bin"))
for cfg in configs:
    settings = cfg.as_dict()
    # 关键字段
    print(f"C2 Server:   {settings.get('SETTING_DOMAINS')}")
    print(f"Port:        {settings.get('SETTING_PORT')}")
    print(f"Sleep:       {settings.get('SETTING_SLEEPTIME')}ms")
    print(f"Jitter:      {settings.get('SETTING_JITTER')}%")
    print(f"User-Agent:  {settings.get('SETTING_USERAGENT')}")
    print(f"Watermark:   {settings.get('SETTING_WATERMARK')}")
    print(f"SpawnTo x64: {settings.get('SETTING_SPAWNTO_X64')}")
    print(f"PipeName:    {settings.get('SETTING_PIPENAME')}")
    print(f"BeaconType:  {settings.get('SETTING_BEACONTYPE')}")  # 0=HTTP,1=HTTPS,8=DNS
```

### 手动解密（自动工具失败时）

```python
import struct

def decrypt_cs_config(data):
    """手动 XOR 解密 CS Beacon 配置"""
    # CS4: XOR key 0x2e, CS3: XOR key 0x69
    for xor_key in [0x2e, 0x69]:
        # 搜索加密后的 magic: 0x0001 0x0002 (BeaconType, Short)
        magic = bytes([0x00 ^ xor_key, 0x01 ^ xor_key,
                       0x00 ^ xor_key, 0x02 ^ xor_key])
        offset = data.find(magic)
        if offset != -1:
            config_blob = bytes([b ^ xor_key for b in data[offset:offset+4096]])
            return parse_tlv(config_blob)
    return None

def parse_tlv(data):
    """解析 TLV 格式配置"""
    FIELDS = {1:"BeaconType", 2:"Port", 3:"SleepTime", 5:"Jitter",
              8:"C2Server", 9:"UserAgent", 10:"PostURI", 26:"Watermark",
              36:"PipeName", 54:"SpawnTo_x64", 55:"SpawnTo_x86"}
    results = {}
    pos = 0
    while pos + 6 <= len(data):
        ftype = struct.unpack(">H", data[pos:pos+2])[0]
        dtype = struct.unpack(">H", data[pos+2:pos+4])[0]
        flen = struct.unpack(">H", data[pos+4:pos+6])[0]
        if ftype == 0: break
        val = data[pos+6:pos+6+flen]
        name = FIELDS.get(ftype, f"0x{ftype:04x}")
        if dtype == 3:  # string
            results[name] = val.rstrip(b'\x00').decode(errors='replace')
        elif dtype == 2:  # int
            results[name] = struct.unpack(">I", val[:4])[0]
        elif dtype == 1:  # short
            results[name] = struct.unpack(">H", val[:2])[0]
        pos += 6 + flen
    return results
```

## Phase 3: 内存扫描提取

```bash
# Volatility3 扫描进程内存
vol3 -f memory.dmp windows.memmap --pid <PID> --dump
# 对 dump 出的文件用 Phase 2 方法提取

# 1768.py (JPCERT) — 专门的 CS config 扫描
python3 1768.py -f memory.dmp

# CobaltStrikeParser 扫描内存
python3 parse_beacon_config.py memory.dmp
```

## Phase 4: 网络流量分析

```
从 Beacon 配置推导网络签名：
├─ HTTP(S) Beacon → URI 路径 + UA + Host Header + 心跳间隔
├─ DNS Beacon → DNS 查询模式 + 子域名编码方式
├─ SMB Beacon → Named Pipe 名称
└─ TCP Beacon → 端口 + 协议特征
```

**生成检测签名示例：**
```
# Suricata
alert http any any -> any any (msg:"CS Beacon URI";
  content:"/api/v1/check"; http_uri;
  content:"Mozilla/5.0"; http_user_agent;
  threshold:type both, track by_src, count 5, seconds 300;
  sid:1000001; rev:1;)
```

## Phase 5: 红队 OPSEC 反思

分析结果 → 你的 C2 应该避免以下暴露：

| 暴露点 | 对策 |
|--------|------|
| 默认 Watermark | 用合法 license 或 patch 掉 |
| 固定 User-Agent | Malleable Profile 随机化 |
| 固定 URI 路径 | 模仿真实业务 API |
| 默认 Named Pipe `\\.\pipe\msagent_*` | 自定义管道名 |
| 默认 SpawnTo `rundll32.exe` | 改为 `svchost.exe` 或其他合法进程 |
| 固定 Sleep+Jitter | 增加 Jitter 到 30%+ |
| XOR key 已知(0x2e/0x69) | 使用 Sleep Mask + 堆加密 |

## 工具速查

| 工具 | 用途 |
|------|------|
| dissect.cobaltstrike | Python CS 配置解析 |
| CobaltStrikeParser (S1) | CS Beacon 配置提取 |
| 1768.py (JPCERT) | CS 扫描器 |
| BeaconEye | 内存实时扫描 CS Beacon |
| Volatility3 | 内存取证 |
| YARA | 签名匹配 |
