# CS Beacon 手动解密与 TLV 解析参考

## Cobalt Strike 配置结构

### 内存布局

```
Beacon PE/Shellcode 内存布局：
┌──────────────────────────┐
│  MZ Header (PE)          │
├──────────────────────────┤
│  .text (代码段)           │
├──────────────────────────┤
│  .rdata (只读数据)        │
├──────────────────────────┤
│  .data (配置 blob 在此)   │  ← XOR 加密的 TLV 配置
├──────────────────────────┤
│  .reloc                  │
└──────────────────────────┘
```

### XOR 解密规则

| CS 版本 | XOR Key | 配置大小 | Magic 位置 |
|---------|---------|---------|-----------|
| CS 3.x | 0x69 | 4096 bytes | .data 节内 |
| CS 4.0-4.3 | 0x2e | 4096 bytes | .data 节内 |
| CS 4.4+ | 0x2e | 4096 bytes | .data 节内，可能有多个 |

### 完整 TLV 字段映射表

```python
CS_SETTINGS = {
    0x0001: ("BeaconType", "short"),      # 0=HTTP, 1=HTTPS, 2=SMB, 4=TCP, 8=DNS
    0x0002: ("Port", "short"),
    0x0003: ("SleepTime", "int"),          # 毫秒
    0x0004: ("MaxGetSize", "int"),
    0x0005: ("Jitter", "short"),           # 百分比 0-99
    0x0006: ("MaxDNS", "short"),
    0x0007: ("PublicKey", "blob"),          # RSA Public Key
    0x0008: ("C2Server", "str"),           # 逗号分隔的域名/IP
    0x0009: ("UserAgent", "str"),
    0x000a: ("PostURI", "str"),
    0x000b: ("Malleable_C2_Instructions", "blob"),
    0x000c: ("HttpGet_Metadata", "blob"),
    0x000d: ("SpawnTo_x86", "str"),        # 默认 %windir%\\syswow64\\rundll32.exe
    0x000e: ("SpawnTo_x64", "str"),        # 默认 %windir%\\sysnative\\rundll32.exe
    0x000f: ("CryptoScheme", "short"),
    0x001a: ("Watermark", "int"),          # License 标识
    0x001b: ("CleanupDisk", "short"),
    0x001c: ("CleanupMemory", "short"),
    0x001d: ("HostHeader", "str"),
    0x0020: ("ObfuscateSectionsInfo", "blob"),
    0x0023: ("ProcInject_MinAllocSize", "int"),
    0x0024: ("PipeName", "str"),
    0x0025: ("Year", "short"),
    0x0026: ("Month", "short"),
    0x0027: ("Day", "short"),
    0x0028: ("DNS_Idle", "int"),
    0x0029: ("DNS_Sleep", "int"),
    0x002a: ("SSH_Host", "str"),
    0x002b: ("SSH_Port", "short"),
    0x002c: ("SSH_Username", "str"),
    0x002d: ("SSH_Password", "str"),
    0x002e: ("HttpGet_Verb", "str"),
    0x002f: ("HttpPost_Verb", "str"),
    0x0030: ("HttpPostChunk", "int"),
    0x0031: ("Spawnto_x86", "str"),
    0x0032: ("Spawnto_x64", "str"),
    0x0033: ("CryptoScheme2", "short"),
    0x0034: ("ProxyHostname", "str"),
    0x0035: ("ProxyUsername", "str"),
    0x0036: ("ProxyPassword", "str"),
    0x0037: ("ProxyType", "short"),        # 1=SOCKS4, 2=SOCKS5, 3=HTTP
    0x0038: ("Deprecated38", "short"),
    0x0039: ("KillDate", "int"),           # YYYYMMDD 格式
    0x003a: ("TextSectionEnd", "short"),
    0x003b: ("ObfuscateSections", "blob"),
    0x003d: ("ProcInject_StartRWX", "short"),
    0x003e: ("ProcInject_UseRWX", "short"),
    0x003f: ("ProcInject_MinAllocSize2", "int"),
    0x0040: ("ProcInject_Transform_x86", "blob"),
    0x0041: ("ProcInject_Transform_x64", "blob"),
    0x0042: ("UsesCookies", "short"),
    0x0043: ("ProcInject_Execute", "blob"),
    0x0044: ("ProcInject_AllocationMethod", "short"),  # 0=VirtualAllocEx, 1=NtMapViewOfSection
    0x0045: ("ProcInject_Stub", "blob"),
    0x0046: ("HostHeader", "str"),
}
```

### 完整解析脚本

```python
#!/usr/bin/env python3
"""
CS Beacon 配置完整解析器
支持 PE、Shellcode、内存 dump
"""
import struct
import sys
import json

CS_SETTINGS = {
    1: ("BeaconType", "short"),
    2: ("Port", "short"),
    3: ("SleepTime", "int"),
    4: ("MaxGetSize", "int"),
    5: ("Jitter", "short"),
    6: ("MaxDNS", "short"),
    7: ("PublicKey", "blob"),
    8: ("C2Server", "str"),
    9: ("UserAgent", "str"),
    10: ("PostURI", "str"),
    13: ("SpawnTo_x86", "str"),
    14: ("SpawnTo_x64", "str"),
    26: ("Watermark", "int"),
    29: ("HostHeader", "str"),
    36: ("PipeName", "str"),
    37: ("Year", "short"),
    38: ("Month", "short"),
    39: ("Day", "short"),
    46: ("HttpGet_Verb", "str"),
    47: ("HttpPost_Verb", "str"),
    50: ("ProxyHostname", "str"),
    57: ("KillDate", "int"),
}

BEACON_TYPES = {0: "HTTP", 1: "HTTPS", 2: "SMB", 4: "TCP", 8: "DNS", 16: "HTTPS (bind)"}

def find_config(data):
    """在二进制数据中搜索 CS 配置 blob"""
    for xor_key in [0x2e, 0x69]:
        # 配置开头: type=0x0001(BeaconType) + dtype=0x0001(short) + len=0x0002
        magic = bytes([
            0x00 ^ xor_key, 0x01 ^ xor_key,  # type = 1
            0x00 ^ xor_key, 0x01 ^ xor_key,  # dtype = short
            0x00 ^ xor_key, 0x02 ^ xor_key,  # len = 2
        ])
        offset = data.find(magic)
        if offset != -1:
            return offset, xor_key
    return None, None

def decrypt_config(data, offset, xor_key, size=4096):
    """XOR 解密配置 blob"""
    encrypted = data[offset:offset + size]
    return bytes([b ^ xor_key for b in encrypted])

def parse_config(decrypted):
    """解析 TLV 配置"""
    results = {}
    pos = 0
    while pos + 6 <= len(decrypted):
        field_type = struct.unpack(">H", decrypted[pos:pos+2])[0]
        data_type = struct.unpack(">H", decrypted[pos+2:pos+4])[0]
        field_len = struct.unpack(">H", decrypted[pos+4:pos+6])[0]

        if field_type == 0:
            break

        value_data = decrypted[pos+6:pos+6+field_len]

        # 解析值
        if data_type == 1:  # short
            value = struct.unpack(">H", value_data[:2])[0]
        elif data_type == 2:  # int
            value = struct.unpack(">I", value_data[:4])[0]
        elif data_type == 3:  # str/blob
            value = value_data.rstrip(b'\x00').decode('utf-8', errors='replace')
        else:
            value = value_data.hex()

        # 查找字段名
        field_info = CS_SETTINGS.get(field_type)
        if field_info:
            name = field_info[0]
        else:
            name = f"Unknown_0x{field_type:04x}"

        results[name] = value
        pos += 6 + field_len

    return results

def analyze_config(config):
    """分析配置并生成 IOC 报告"""
    report = {
        "beacon_type": BEACON_TYPES.get(config.get("BeaconType", -1), "Unknown"),
        "c2_servers": [],
        "port": config.get("Port"),
        "sleep_ms": config.get("SleepTime"),
        "jitter_pct": config.get("Jitter"),
        "user_agent": config.get("UserAgent", ""),
        "watermark": config.get("Watermark"),
        "spawn_to": {
            "x86": config.get("SpawnTo_x86", ""),
            "x64": config.get("SpawnTo_x64", "")
        },
        "named_pipe": config.get("PipeName", ""),
        "kill_date": config.get("KillDate"),
        "host_header": config.get("HostHeader", ""),
        "http_verbs": {
            "get": config.get("HttpGet_Verb", "GET"),
            "post": config.get("HttpPost_Verb", "POST")
        },
        "proxy": config.get("ProxyHostname", ""),
    }

    # 解析 C2 server 列表
    c2 = config.get("C2Server", "")
    if c2:
        for entry in c2.split(","):
            entry = entry.strip().rstrip("/")
            if entry:
                report["c2_servers"].append(entry)

    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <beacon_file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    offset, xor_key = find_config(data)
    if offset is None:
        print("[-] No CS config found")
        sys.exit(1)

    print(f"[+] Config at offset 0x{offset:x}, XOR key: 0x{xor_key:02x}")
    decrypted = decrypt_config(data, offset, xor_key)
    config = parse_config(decrypted)
    report = analyze_config(config)
    print(json.dumps(report, indent=2, ensure_ascii=False))
```

## Watermark 情报价值

```
Watermark 是 4 字节整数，嵌入每个 license 生成的 Beacon：
├─ 合法 license → 唯一 Watermark → 可追踪到购买者
├─ 破解版 → 固定 Watermark（如 0, 305419896, 666666）
├─ 同一 Watermark 出现在多个事件中 → 可能同一攻击者

已知破解版 Watermark：
├─ 0 → 最常见破解版
├─ 305419896 (0x12345678) → 某个流传广泛的破解
├─ 666666 → 中文社区常见破解
└─ 其他: 查询 MalwareBazaar/VirusTotal 的 Beacon 数据库
```

## 内存中扫描 Beacon 的方法

```bash
# 方法 1: Volatility3 + YARA
cat > cs_beacon.yar << 'EOF'
rule CobaltStrike_Beacon_Encoded {
    strings:
        $config_v4 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 }
        $xor_v4 = { 2e 2f 2e 2f 2e 2c }
        $xor_v3 = { 69 68 69 68 69 6b }
    condition:
        any of them
}
EOF
vol3 -f memory.dmp yarascan.YaraScan --yara-file cs_beacon.yar

# 方法 2: 1768.py (JPCERT)
python3 1768.py memory.dmp

# 方法 3: BeaconHunter (CobaltStrikeParser)
python3 parse_beacon_config.py --dump memory.dmp

# 方法 4: 手动搜索配置 magic
python3 -c "
import mmap, sys
with open(sys.argv[1], 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for key in [0x2e, 0x69]:
        magic = bytes([0x00^key, 0x01^key, 0x00^key, 0x01^key, 0x00^key, 0x02^key])
        pos = 0
        while True:
            pos = mm.find(magic, pos)
            if pos == -1: break
            print(f'[+] Possible config at 0x{pos:x} (XOR: 0x{key:02x})')
            pos += 1
" memory.dmp
```
