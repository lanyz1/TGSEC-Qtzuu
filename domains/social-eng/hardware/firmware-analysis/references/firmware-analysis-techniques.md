# 固件分析技术详细参考

## 固件基础概念

固件是存储在设备永久存储器中的基础软件，管理硬件组件与用户交互软件之间的通信。设备上电后首先加载固件，随后启动操作系统。对固件的审查和修改是识别安全漏洞的关键步骤。

## 信息收集（OSINT 阶段）

分析前需收集的设备信息：

- CPU 架构与运行的操作系统
- Bootloader 详细信息
- 硬件布局与数据手册（datasheet）
- 代码库规模与源码位置
- 外部库及许可证类型
- 更新历史与监管认证
- 架构图与流程图
- 已有安全评估与已知漏洞

可用的 OSINT 与静态分析工具：

- Coverity Scan (https://scan.coverity.com) - 免费静态分析
- Semmle LGTM - 代码质量分析

## 固件获取方法详解

### 常规获取途径

| 途径 | 说明 |
|------|------|
| 厂商直接提供 | 联系开发者/制造商获取 |
| 根据说明编译 | 从源码构建 |
| 官方支持站下载 | 厂商支持页面 |
| Google dork | `site:vendor.com filetype:bin "firmware" "update"` |
| 云存储扫描 | S3Scanner 扫描公开 bucket |
| 中间人截获 | 拦截 OTA 更新流量 |
| 设备硬件提取 | UART/JTAG/SPI/PICit |
| 网络嗅探 | 监听设备更新请求 |
| 硬编码端点 | 固件中的更新 URL |
| Bootloader dump | U-Boot shell 命令 |
| 芯片拆焊直读 | 最后手段，需要专业设备 |

### UART 只读日志时强制获取 Shell

当 UART 的 RX 被忽略（只有日志输出）时，可通过离线编辑 U-Boot 环境变量获取 shell：

```bash
# 1. 使用 SOIC-8 夹具 + 编程器读取 SPI Flash（3.3V）
flashrom -p ch341a_spi -r flash.bin

# 2. 定位 U-Boot env 分区
# 编辑 bootargs 加入 init=/bin/sh
# 重新计算 U-Boot env 的 CRC32

# 3. 仅回写 env 分区并重启
# shell 应出现在 UART 输出上
```

### 从移动应用提取固件

许多厂商将完整固件镜像打包在手机伴侣应用中，用于蓝牙/WiFi OTA 更新：

```bash
apktool d vendor-app.apk -o vendor-app
ls vendor-app/assets/firmware/
# 常见路径: assets/fw/, res/raw/, assets/firmware/
```

## 文件系统提取详解

### binwalk 自动提取

```bash
binwalk -ev firmware.bin
# 结果目录以文件系统类型命名:
# squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs
```

### 手动提取（binwalk 签名不匹配时）

当 binwalk 无法自动识别文件系统 magic bytes 时，需要手动操作：

```bash
# 查找文件系统偏移
binwalk DIR850L_REVB.bin
# 输出示例:
# 1704084  0x1A0094  Squashfs filesystem, little endian, version 4.0, compression:lzma

# dd 切割文件系统
dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
# 或使用十六进制偏移
dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs
```

### 各文件系统类型解压命令

| 文件系统 | 解压命令 |
|----------|----------|
| squashfs | `unsquashfs dir.squashfs` |
| cpio | `cpio -ivd --no-absolute-filenames -F <bin>` |
| jffs2 | `jefferson rootfsfile.jffs2` |
| ubifs (NAND) | `ubireader_extract_images -u UBI -s <offset> <bin>` |
| yaffs2 | `unyaffs image.yaffs2` |
| cramfs | `cramfsck -x <output_dir> image.cramfs` |

## 文件系统安全分析

### 关键检查位置

| 路径/项目 | 检查内容 |
|-----------|----------|
| etc/shadow, etc/passwd | 用户凭据、默认密码 |
| etc/ssl/ | SSL 证书和私钥 |
| etc/ssh/ | SSH host 密钥 |
| etc/init.d/, etc/rc.d/ | 启动脚本、服务配置 |
| 配置文件 (*.conf, *.cfg) | 硬编码凭据、API 端点 |
| Web 目录 | CGI 脚本、管理界面 |
| 二进制文件 | 不安全函数、后门 |

### 自动化分析工具

| 工具 | 说明 |
|------|------|
| LinPEAS | 权限提升路径与敏感信息搜索 |
| Firmwalker | 固件敏感信息自动搜索 |
| FACT | Firmware Analysis and Comparison Tool，综合分析 |
| FwAnalyzer | 固件安全策略检查 |
| ByteSweep | 自动化固件安全扫描 |
| EMBA | 嵌入式固件静态/动态分析框架 |

### 编译二进制安全检查

使用 checksec.sh 检查 Unix 二进制保护状态（NX/ASLR/Canary/PIE/RELRO）。嵌入式系统的二进制通常缺少这些保护，使其更容易被利用。

## 云配置与 MQTT 凭据提取

### 基于 token 派生的云端点

许多 IoT 设备使用可预测的 URL 格式从云端获取配置：

```
https://<api-host>/pf/<deviceId>/<token>
```

其中 token 由设备本地计算，例如：`token = MD5(deviceId || STATIC_KEY)` 的大写十六进制表示。

### 提取流程

```bash
# 1. 从 UART 日志获取 deviceId
picocom -b 115200 /dev/ttyUSB0
# 寻找类似: Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>

# 2. 从固件逆向恢复 STATIC_KEY 和算法
# Ghidra/radare2 搜索 "/pf/" 路径或 MD5 调用

# 3. 派生 token
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'

# 4. 获取云配置（含 MQTT 凭据）
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# 常见字段: mqtt host/port, clientId, username, password, topic prefix

# 5. 使用 MQTT 凭据（在授权范围内）
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

## QEMU 模拟详解

### 架构识别与工具安装

```bash
# 安装 QEMU 全套
sudo apt-get install qemu qemu-user qemu-user-static \
  qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils

# 确认二进制架构
file ./squashfs-root/bin/busybox
# 输出示例: ELF 32-bit MSB executable, MIPS, MIPS32 version 1
```

### 架构对应的 QEMU 命令

| 架构 | 用户态模拟器 | 系统模拟器 |
|------|-------------|-----------|
| MIPS big-endian | qemu-mips | qemu-system-mips |
| MIPS little-endian | qemu-mipsel | qemu-system-mipsel |
| ARM | qemu-arm | qemu-system-arm |
| ARM64 | qemu-aarch64 | qemu-system-aarch64 |

### 全系统模拟工具

| 工具 | 说明 |
|------|------|
| Firmadyne | 自动化固件模拟，支持网络配置推断 |
| Firmware Analysis Toolkit | 基于 Firmadyne 的封装，简化流程 |
| ARM-X | ARM 固件模拟与漏洞研究框架 |

## 运行时分析技术

### 远程 GDB 调试

```bash
# 在目标设备上（拷贝静态链接的 gdbserver）
gdbserver :1234 /usr/bin/targetd

# 在主机上
gdb-multiarch /path/to/targetd
# (gdb) target remote <device-ip>:1234
```

### 常用运行时分析工具

- gdb-multiarch: 跨架构调试
- Frida: 动态插桩，hook 函数调用
- Ghidra: 设置断点、反编译分析
- strace/ltrace: 系统调用/库函数调用追踪
- fuzzing: 对暴露的服务进行模糊测试

## 固件降级攻击

### 攻击条件

当更新机制仅验证签名但不检查版本号或单调递增计数器时，攻击者可以刷入旧的（已签名的）含漏洞固件。

### 攻击流程

1. 获取旧版签名固件（厂商下载页/CDN/APK 内置/第三方存档）
2. 通过暴露的更新通道上传（Web UI/移动应用 API/USB/TFTP/MQTT）
3. 利用旧版本中已修补的漏洞（如命令注入）
4. 获取持久化后刷回新版或禁用更新

### 更新逻辑审计清单

- 更新端点的传输/认证是否充分保护？
- 设备是否在刷入前比较版本号或反降级计数器？
- 签名验证是否在安全启动链中完成？
- 用户态代码是否进行额外验证（分区表/型号检查）？
- 备份/恢复更新流程是否复用相同验证逻辑？

## uClibc 嵌入式堆利用

嵌入式 Linux 常用 uClibc 代替 glibc，其堆管理有特殊特性：

- **Fastbins + 合并**：uClibc 使用类似 glibc 的 fastbins，大分配触发 `__malloc_consolidate()`，fake chunk 需通过检查（合理 size, fd=0, 周围 chunk 标记为 in-use）
- **Non-PIE + ASLR**：主程序非 PIE 时 `.data/.bss` 地址固定，可将 fastbin 分配到函数指针表
- **NUL 字节截断**：JSON 解析中 `\x00` 可停止解析但保留后续攻击载荷
- **/proc/self/mem 写入 shellcode**：ROP 链调用 `open("/proc/self/mem")` + `lseek()` + `write()` 植入 shellcode

## 专用分析环境

| 操作系统 | 说明 |
|----------|------|
| AttifyOS | IoT 安全评估专用发行版，预装分析工具 |
| EmbedOS | 基于 Ubuntu 18.04 的嵌入式安全测试系统 |

## 参考资源

- Firmware Security Testing Methodology: https://scriptingxss.gitbook.io/firmware-security-testing-methodology/
- Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things (书籍)
- OWASP IoTGoat: https://github.com/OWASP/IoTGoat
- DVRF: https://github.com/praetorian-code/DVRF
- ARM-X: https://github.com/therealsaumil/armx
