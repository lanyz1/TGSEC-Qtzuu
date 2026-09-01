---
name: firmware-analysis
description: "固件安全分析方法论。涵盖固件获取（从设备/下载/UART/JTAG）、固件解包与文件系统提取（binwalk/firmware-mod-kit）、静态分析（硬编码凭据/加密密钥/后门）、动态分析（QEMU 模拟）、漏洞挖掘、固件修改与重打包。当 Agent 需要分析嵌入式设备固件、提取固件中的敏感信息、或进行 IoT 设备安全评估时触发。"
metadata:
  tags: "firmware,固件分析,binwalk,qemu,iot安全,uart,jtag,嵌入式"
  category: "hardware"
---

# 固件安全分析方法论

> **核心流程**：获取固件 → 解包提取文件系统 → 静态分析敏感信息 → 动态模拟运行 → 漏洞挖掘 → 固件修改重打包

## 深入参考

- 固件分析完整技术细节与工具参考 → [references/firmware-analysis-techniques.md](references/firmware-analysis-techniques.md)

---

## Phase 1: 固件获取

```
固件获取途径决策树：
├─ 厂商官网下载（支持页/FTP/CDN）
│  └─ Google dork: site:vendor.com filetype:bin OR filetype:img "firmware"
├─ 云存储扫描
│  └─ S3Scanner / GrayhatWarfare 搜索厂商名+firmware
├─ 设备直接提取
│  ├─ UART 串口连接
│  │  ├─ 识别 TX/RX/GND 引脚（万用表/逻辑分析仪）
│  │  └─ picocom -b 115200 /dev/ttyUSB0
│  ├─ JTAG/SWD 调试接口
│  │  └─ OpenOCD 连接读取 flash
│  ├─ SPI Flash 芯片直读
│  │  └─ SOIC-8 夹具 + flashrom
│  └─ eMMC 直读（ISP 焊点）
├─ 中间人截获更新包
│  └─ 设置代理拦截 OTA 更新请求
├─ 移动应用提取
│  └─ apktool d vendor-app.apk → assets/firmware/
└─ 从 bootloader dump
   └─ U-Boot: md.b / nand read / sf read
```

### 从 SPI Flash 直接读取

```bash
# 使用 CH341A 编程器 + SOIC-8 夹具
flashrom -p ch341a_spi -r flash.bin

# 验证读取一致性（读两次比较）
flashrom -p ch341a_spi -r flash2.bin
md5sum flash.bin flash2.bin
```

### 通过 UART 获取 Shell

```bash
# 连接 UART（常见波特率: 115200, 9600, 57600）
picocom -b 115200 /dev/ttyUSB0

# 如果 UART 只有日志输出（RX 被忽略），编辑 U-Boot env 强制 shell
# 1. dump flash → 2. 修改 bootargs 加入 init=/bin/sh → 3. 重算 CRC32 → 4. 回写
```

### 从移动应用提取固件

```bash
apktool d vendor-app.apk -o vendor-app
ls vendor-app/assets/firmware/
# 常见路径: assets/fw/, res/raw/, assets/firmware/
```

## Phase 2: 解包与文件系统提取

```
固件解包决策树：
├─ binwalk 自动提取（首选）
│  └─ binwalk -ev firmware.bin
├─ binwalk 识别但提取失败
│  ├─ 手动 dd 切割 + 对应工具解压
│  │  ├─ squashfs → unsquashfs
│  │  ├─ jffs2 → jefferson
│  │  ├─ cramfs → cramfsck
│  │  ├─ cpio → cpio -ivd
│  │  ├─ ubifs → ubireader_extract_images
│  │  └─ yaffs2 → unyaffs
│  └─ firmware-mod-kit 辅助
├─ 固件加密
│  ├─ 检查熵值: binwalk -E firmware.bin
│  │  ├─ 高熵 → 可能加密或压缩
│  │  └─ 低熵 → 未加密
│  ├─ 寻找解密密钥（bootloader/旧版本固件/逆向加密逻辑）
│  └─ 某些厂商用 AES-CBC + 硬编码 key/IV
└─ 完全未知格式 → hexdump 分析 magic bytes
```

### binwalk 标准流程

```bash
# 初步分析（不提取，仅识别）
binwalk firmware.bin

# 熵分析判断是否加密
binwalk -E firmware.bin

# 自动递归提取
binwalk -ev firmware.bin

# 提取结果通常在 _firmware.bin.extracted/ 目录
ls _firmware.bin.extracted/
```

### 手动文件系统提取

```bash
# 查找文件系统偏移
binwalk firmware.bin | grep -i "squashfs\|jffs2\|cramfs\|ubifs"

# 用 dd 切割（示例: squashfs 在偏移 0x1A0094）
dd if=firmware.bin bs=1 skip=$((0x1A0094)) of=rootfs.squashfs

# 解压 squashfs
unsquashfs rootfs.squashfs
ls squashfs-root/

# 解压 jffs2
jefferson rootfs.jffs2 -d jffs2-root

# 解压 cpio
cpio -ivd --no-absolute-filenames -F rootfs.cpio

# 解压 ubifs
ubireader_extract_images -u UBI -s <start_offset> firmware.bin
```

### 基础文件信息收集

```bash
file firmware.bin
strings -n8 firmware.bin
strings -tx firmware.bin | head -50
hexdump -C -n 512 firmware.bin
fdisk -lu firmware.bin
```

## Phase 3: 静态分析

```
静态分析重点目标：
├─ 硬编码凭据
│  ├─ /etc/shadow, /etc/passwd
│  ├─ grep -r "password\|passwd\|secret\|key" etc/
│  └─ 配置文件中的默认账户密码
├─ 加密材料
│  ├─ SSL 证书与私钥: etc/ssl/, *.pem, *.key
│  ├─ SSH 密钥: etc/ssh/ssh_host_*
│  └─ API 密钥 / Token
├─ 后门与调试接口
│  ├─ telnetd / dropbear 配置
│  ├─ 隐藏的 CGI 端点
│  └─ 调试用 web shell
├─ 网络服务配置
│  ├─ Web 服务器配置（lighttpd/uhttpd/mini_httpd）
│  ├─ MQTT 凭据与 broker 地址
│  └─ 云平台 API endpoint
├─ 启动脚本分析
│  ├─ /etc/init.d/, /etc/rc.d/
│  └─ 服务启动顺序与权限
└─ 二进制安全检查
   └─ checksec --file=<binary>
```

### 凭据与敏感信息搜索

```bash
# 进入提取的文件系统
cd squashfs-root/

# 检查用户凭据
cat etc/shadow 2>/dev/null
cat etc/passwd

# 搜索硬编码密码
grep -rn "password\|passwd\|secret\|api_key\|token" etc/ --include="*.conf" --include="*.cfg"
grep -rn "password\|passwd" usr/lib/ --include="*.lua" --include="*.sh"

# 搜索 SSL/SSH 密钥
find . -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "ssh_host_*"

# 搜索 URL 和 IP 地址
grep -rn "http://\|https://\|ftp://" . --include="*.conf" --include="*.sh" --include="*.lua"
grep -rEn "\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b" etc/

# 搜索 base64 编码内容（可能隐藏凭据）
grep -rn "^[A-Za-z0-9+/=]\{20,\}$" etc/
```

### 自动化分析工具

```bash
# Firmwalker - 自动搜索敏感信息
./firmwalker.sh squashfs-root/

# EMBA - 综合固件安全分析
sudo ./emba -f firmware.bin -l ./logs

# LinPEAS（在模拟环境中运行）
# 拷贝到模拟的文件系统中执行
```

### 二进制保护检查

```bash
# 检查所有 ELF 二进制的安全编译选项
find squashfs-root/ -executable -type f -exec file {} \; | grep ELF
checksec --file=squashfs-root/usr/bin/httpd
checksec --file=squashfs-root/usr/sbin/dropbear
```

### 云凭据与 MQTT 配置提取

```bash
# 搜索 MQTT 配置
grep -rn "mqtt\|broker\|mosquitto" etc/ usr/ --include="*.conf" --include="*.json"

# 搜索云端点 URL 与 token 派生逻辑
grep -rn "/pf/\|deviceId\|STATIC_KEY" usr/bin/ usr/lib/
strings usr/bin/cloud_agent | grep -i "mqtt\|api\|token\|key\|secret"
```

## Phase 4: 动态分析（QEMU 模拟）

```
动态分析决策树：
├─ 单个二进制模拟
│  ├─ 确认架构: file <binary>
│  ├─ MIPS big-endian → qemu-mips
│  ├─ MIPS little-endian → qemu-mipsel
│  ├─ ARM → qemu-arm
│  ├─ ARM64 → qemu-aarch64
│  └─ 需要 chroot 或 --root 指向文件系统
├─ 全系统模拟
│  ├─ Firmadyne（自动化，推荐）
│  ├─ Firmware Analysis Toolkit（基于 Firmadyne）
│  └─ 手动 QEMU system 模拟
└─ 真实设备动态调试
   ├─ gdbserver 远程调试
   └─ Frida hook
```

### 单个二进制模拟

```bash
# 安装 QEMU 用户态模拟器
sudo apt-get install qemu-user-static

# 确认目标架构
file squashfs-root/bin/busybox

# MIPS 模拟（以提取的文件系统为根）
sudo chroot squashfs-root /usr/bin/qemu-mips-static /bin/busybox ls

# ARM 模拟
sudo chroot squashfs-root /usr/bin/qemu-arm-static /usr/sbin/httpd

# 带 strace 的模拟（观察系统调用）
qemu-mips-static -strace ./squashfs-root/usr/bin/target_binary
```

### 全系统模拟（Firmadyne）

```bash
# Firmadyne 流程
# 1. 提取固件文件系统
python3 ./sources/extractor/extractor.py -b <brand> -sql <psql_ip> -np -nk firmware.bin images/

# 2. 识别架构
python3 ./scripts/getArch.sh images/<image_id>.tar.gz

# 3. 创建 QEMU 镜像
python3 ./scripts/makeImage.sh <image_id>

# 4. 推断网络配置
python3 ./scripts/inferNetwork.sh <image_id>

# 5. 启动模拟
python3 ./scratch/<image_id>/run.sh
```

### 远程调试

```bash
# 在设备/模拟环境中启动 gdbserver
gdbserver :1234 /usr/bin/target_daemon

# 在主机上连接
gdb-multiarch /path/to/target_daemon
# (gdb) target remote <device-ip>:1234
# (gdb) set architecture mips
# (gdb) continue
```

## Phase 5: 漏洞挖掘

```
常见固件漏洞类型：
├─ 命令注入
│  ├─ Web CGI 参数未过滤
│  ├─ 系统调用拼接用户输入
│  └─ grep -rn "system\|popen\|exec\|eval" --include="*.c" --include="*.lua"
├─ 缓冲区溢出
│  ├─ strcpy/sprintf/gets 等不安全函数
│  ├─ 嵌入式系统通常缺少保护（no ASLR/NX/Canary）
│  └─ checksec 确认保护状态
├─ 认证绕过
│  ├─ 硬编码凭据
│  ├─ 后门账户
│  └─ session 管理缺陷
├─ 信息泄露
│  ├─ 未授权 API 端点
│  ├─ 调试信息暴露
│  └─ 配置文件可访问
├─ 降级攻击
│  ├─ 无版本号校验的签名更新机制
│  ├─ 旧版签名固件仍可刷入
│  └─ 绕过安全补丁
├─ MQTT/云凭据泄露
│  ├─ 硬编码 STATIC_KEY 派生 token
│  ├─ 明文 MQTT 凭据
│  └─ 弱 topic ACL 允许跨设备访问
└─ uClibc 堆利用（嵌入式 Linux 特有）
   ├─ fastbin 合并时的 fake chunk
   ├─ non-PIE 下 .data/.bss 地址稳定
   └─ /proc/self/mem 写入 shellcode
```

### Web 服务漏洞测试

```bash
# 识别 Web 服务
nmap -sV -p 80,443,8080,8443 <device-ip>

# 抓取所有 CGI 端点
curl -s http://<device-ip>/ | grep -oP 'action="[^"]*"|href="[^"]*"'
find squashfs-root/www/ -name "*.cgi" -o -name "*.asp" -o -name "*.lua"

# 命令注入测试（静态分析后定向测试）
# 分析 CGI 二进制中 system() 调用的参数来源
strings squashfs-root/usr/bin/httpd | grep "system\|popen\|/bin/sh"
```

### 更新机制审计

```bash
# 检查更新逻辑：是否验证版本号？
strings squashfs-root/usr/bin/upgrade_manager | grep -i "version\|rollback\|verify\|sign"

# 是否存在反降级计数器？
grep -rn "anti.rollback\|version.check\|monotonic" squashfs-root/etc/ squashfs-root/usr/
```

## Phase 6: 固件修改与重打包

```
固件修改流程：
├─ 修改文件系统内容
│  ├─ 添加 SSH 公钥到 /root/.ssh/authorized_keys
│  ├─ 修改 /etc/shadow（添加已知密码的用户）
│  ├─ 植入 reverse shell 或 busybox
│  └─ 修改启动脚本添加持久化后门
├─ 重打包文件系统
│  ├─ squashfs: mksquashfs <dir> rootfs.squashfs -comp xz
│  ├─ jffs2: mkfs.jffs2 -d <dir> -o rootfs.jffs2
│  └─ cramfs: mkcramfs <dir> rootfs.cramfs
├─ 重组固件镜像
│  ├─ dd 拼接各分区
│  ├─ firmware-mod-kit 自动重打包
│  └─ 更新 CRC/校验和（如果有）
└─ 刷入设备
   ├─ Web UI 上传
   ├─ TFTP/串口刷入
   └─ flashrom 直接写入 SPI
```

### 重打包示例

```bash
# 修改文件系统后重打包 squashfs
# 注意匹配原始压缩算法和块大小
mksquashfs squashfs-root/ new_rootfs.squashfs -comp xz -b 131072

# 用 firmware-mod-kit 重打包
./build-firmware.sh <extraction_dir>

# 手动拼接固件
dd if=header.bin of=modified_firmware.bin bs=1
dd if=new_rootfs.squashfs of=modified_firmware.bin bs=1 seek=<offset> conv=notrunc

# 重算 CRC（如果固件头包含校验和）
# 需要逆向分析固件头格式确定 CRC 算法和位置
```

## 工具速查

| 工具 | 用途 |
|------|------|
| binwalk | 固件识别与提取 |
| firmware-mod-kit | 解包/重打包 |
| flashrom | SPI Flash 读写 |
| OpenOCD | JTAG 调试 |
| QEMU | 二进制/系统模拟 |
| Firmadyne | 自动化全系统模拟 |
| Ghidra / radare2 | 二进制逆向分析 |
| gdbserver + gdb-multiarch | 远程调试 |
| checksec | 二进制保护检查 |
| EMBA | 综合固件安全分析 |
| Firmwalker | 敏感信息搜索 |
| picocom / minicom | 串口通信 |

## 练习靶场

| 项目 | 说明 |
|------|------|
| OWASP IoTGoat | IoT 固件漏洞练习 |
| DVRF | Damn Vulnerable Router Firmware |
| DVAR | Damn Vulnerable ARM Router |
| ARM-X | ARM 固件模拟框架 |
| DVID | Damn Vulnerable IoT Device |
