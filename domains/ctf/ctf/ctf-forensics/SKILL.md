---
name: ctf-forensics
description: "CTF 数字取证与信号分析技术。当挑战提供磁盘镜像(.dd/.E01)、内存 dump(.raw/.vmem)、网络抓包(.pcap/.pcapng)、隐写图片/音频、Windows 事件日志(.evtx)时使用。覆盖 Volatility 内存分析、Wireshark 流量还原、binwalk 隐写提取、文件系统恢复等取证全链路"
metadata:
  tags: "ctf,forensics,取证,volatility,pcap,steganography,隐写,磁盘,内存,网络"
  category: "ctf"
---

# CTF 数字取证

## 深入参考

以下参考资料**按需加载**，根据识别出的具体方向选择对应文件：

- 磁盘/内存取证（Volatility/VM/VMDK/分区恢复/勒索软件） → [references/disk-and-memory.md](references/disk-and-memory.md)
- 磁盘恢复（LUKS/BTRFS/XFS/RAID5/反雕刻） → [references/disk-recovery.md](references/disk-recovery.md)
- Windows 取证（注册表/SAM/事件日志/WMI/Amcache） → [references/windows.md](references/windows.md)
- Linux/应用取证（Docker/Git/浏览器/KeePass） → [references/linux-forensics.md](references/linux-forensics.md)
- 网络取证基础（tcpdump/TLS解密/SMB3/USB音频） → [references/network.md](references/network.md)
- 高级网络取证（时序编码/NTLMv2/TCP隐蔽通道/DNS隐写） → [references/network-advanced.md](references/network-advanced.md)
- 通用隐写术（PDF/SVG/PNG/文件叠加/终端图形） → [references/steganography.md](references/steganography.md)
- 图像隐写术（JPEG DQT/BMP位平面/F5检测/调色板） → [references/stego-image.md](references/stego-image.md)
- 高级隐写术（FFT/DTMF/音频/视频帧/JPEG XL） → [references/stego-advanced.md](references/stego-advanced.md)
- 高级隐写术2（视频帧累积/反转音频/多层PNG/EXIF链） → [references/stego-advanced-2.md](references/stego-advanced-2.md)
- 高级磁盘取证（删除分区恢复/ZFS/LVM Thin/APFS快照） → [references/disk-advanced.md](references/disk-advanced.md)
- 外设捕获分析（USB HID鼠标绘图/键盘捕获解码/蓝牙） → [references/peripheral-capture.md](references/peripheral-capture.md)
- 硬件信号（VGA/HDMI/DisplayPort/功率侧信道/键盘声学） → [references/signals-and-hardware.md](references/signals-and-hardware.md)
- 3D 打印取证（PrusaSlicer/G-code/QOIF） → [references/3d-printing.md](references/3d-printing.md)

---

## 分类决策树

```
拿到取证题？
├─ 文件分析
│  ├─ file/exiftool/binwalk → 识别格式与嵌入文件
│  ├─ 图片 → steghide/zsteg/stegsolve → [references/stego-image.md](references/stego-image.md)
│  ├─ 音频 → 频谱图/DTMF/SSTV → [references/stego-advanced.md](references/stego-advanced.md)
│  └─ PDF → 元数据/隐藏文本/多层 → [references/steganography.md](references/steganography.md)
├─ 磁盘/内存镜像
│  ├─ .dd/.img → mount -o loop,ro → fls/photorec
│  ├─ .ova/.vmdk → tar xf → 7z 提取
│  ├─ 内存 → Volatility3 (pslist/filescan/dumpfiles)
│  └─ RAID/ZFS/BTRFS → [references/disk-recovery.md](references/disk-recovery.md)
├─ 网络流量 (.pcap)
│  ├─ HTTP → tshark --export-objects
│  ├─ TLS → SSLKEYLOGFILE / 弱RSA密钥
│  ├─ SMB → 密钥解密 / NTLMv2 提取
│  └─ DNS → 隐蔽通道 / 尾字节编码
├─ Windows 事件日志 → [references/windows.md](references/windows.md)
├─ 硬件信号 → [references/signals-and-hardware.md](references/signals-and-hardware.md)
└─ 区块链 → mempool.space API / 剥离链追踪
```

## 快速启动命令

```bash
# 文件分析
file suspicious && exiftool suspicious && binwalk suspicious
strings -n 8 suspicious | grep -iE "flag|ctf"

# 磁盘取证
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd && photorec image.dd

# 内存取证 (Volatility 3)
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --physaddr ADDR

# 网络流量
tshark -r capture.pcap -Y "http" --export-objects http,/tmp/out
```

## 隐写速查

| 格式 | 工具 | 说明 |
|------|------|------|
| JPEG | steghide / F5 检测 | DQT表/DCT系数比 |
| PNG/BMP | zsteg / stegsolve | 位平面/调色板/LSB |
| 音频 | multimon-ng / sox | DTMF/频谱/反转 |
| 视频 | 帧累积/逐帧差分 | 闪烁隐藏QR |
| PDF | exiftool + binwalk | 元数据/注释/EOF后数据 |

## Windows 关键事件 ID

| ID | 含义 |
|----|------|
| 1102 | 审计日志清除 |
| 4720 | 用户创建 |
| 4781 | 账户重命名 |
| 21 (TSLocal) | RDP 登录成功 |

## Windows 事件日志
- EVTX 分析关注时间戳（TimeCreated / SystemTime）排序关键事件
