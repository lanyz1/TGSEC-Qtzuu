---
name: pentest-reversing
description: "逆向工程：APK/IPA/EXE脱壳、加固检测、反编译、敏感信息提取——信号→动作速查表"
allowed-tools: Read,Grep,Glob,Bash
---

# Reverse Engineering

> 仅在根路由选择本目录后读取。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 目标为 APK/IPA/EXE/DLL/SO/固件或二进制补丁。

## 领域决策直觉

1. 先判断加固/混淆级别再选策略 —— 对梆梆/360/腾讯乐固需要专用脱壳机，对无加固直接反编译
2. 二进制补丁 Diff 是最高效的漏洞发现方式 —— 厂商修复了什么，攻击者就知道利用什么
3. 逆向不是最终目的 —— 目标是提取 API 端点、硬编码凭据、加密密钥、业务逻辑漏洞

---

## Android（APK/AAB）

### 加固检测与脱壳
- **信号**: APK 文件
- **假设**: 应用可能使用加固（梆梆/360/腾讯乐固/爱加密/顶象/NAGA/阿里聚安全）
- **验证**: `apkid` 检测加固类型 → 按加固选择脱壳工具：梆梆→FART 脱壳机 / 360→FRIDA-DEXDump / 腾讯乐固→Youpk / 通用→Frida .dump_dex() → 内存 dump 完整 DEX → `jadx` 反编译
- **证实**: 成功提取完整未加固 DEX 文件
- **升级**: DEX → 反编译 → 源码分析

### 敏感信息提取
- **信号**: 反编译后的代码
- **假设**: APK 中硬编码 API Key/Token/加密密钥/端点 URL
- **验证**: `grep -rE "AKIA|AIza|sk-|api_key|secret|token|password|private|BEGIN.*KEY" jadx_output/` → JNI so 库 `strings lib/*.so | grep -E "http|https|api|key|token"` → assets 文件遍历 → Firebase/Google Cloud 配置分析
- **证实**: 发现有效的 API Key 或硬编码凭据
- **升级**: 凭据验证 → 后端 API 访问 → 权限提升

### JNI/SO 层分析
- **信号**: 应用关键逻辑放在 native 层（.so 文件）
- **假设**: Native 层包含加密算法、签名检查、反调试逻辑
- **验证**: `readelf -a libnative.so` 符号表分析 → `Ghidra/IDA` 反汇编 → Frida hook JNI 函数（Java_* 前缀）→ 动态调试 `android_server` + IDA remote debug
- **证实**: 定位到加密函数和密钥生成逻辑
- **升级**: 加密算法还原 → API 请求签名伪造 → 未授权访问

### 网络流量拦截与 API 提取
- **信号**: 应用使用 HTTPS 通信，需提取完整 API 端点
- **假设**: 可通过证书固定绕过/代理配置提取 HTTP 流量
- **验证**: Frida script 绕过 SSL Pinning → mitmproxy/Burp 代理捕获 → 提取全部 API 端点 + 请求体格式 + 鉴权 header 模式 → 移动端 API 通常直连后端绕过 CDN/WAF
- **证实**: 提取完整 API 文档等效信息
- **升级**: 直连后端 API → 绕过 WAF → 漏洞探测

---

## iOS（IPA）

### 砸壳（Decrypt IPA）
- **信号**: App Store 下载的加密 IPA
- **假设**: FairPlay 加密的二进制可通过砸壳获取未加密版本
- **验证**: 越狱设备 → `bfdecrypt`/`Clutch`/`frida-ios-dump` 砸壳 → 导出未加密 IPA → 提取 Mach-O 可执行文件
- **证实**: class-dump 可正常解析 Objective-C 类结构
- **升级**: 类结构分析 → 方法 hook → 逻辑审计

### Keychain/UserDefaults 敏感数据提取
- **信号**: iOS 应用使用 Keychain 或 UserDefaults 存储敏感数据
- **假设**: 越狱后可 dump Keychain 和 UserDefaults
- **验证**: `Keychain-Dumper` dump 全部 Keychain 条目 → `plutil` 解析 UserDefaults plist → 提取保存的 Token/密码/API Key
- **证实**: 提取到有效的认证 Token
- **升级**: Token → API 访问 → 未授权操作

---

## Windows（EXE/DLL）

### .NET 反编译/反混淆
- **信号**: .NET PE 文件（mscoree/mscorlib 引用）
- **假设**: .NET 程序集可反编译，混淆可用去混淆工具处理
- **验证**: `Detect It Easy` 识别混淆器类型（ConfuserEx/Obfuscar/Agile.NET）→ `de4dot` 去混淆 → `dnSpy/dnSpyEx` 反编译 + 动态调试 → IL 修改 + 重新打包
- **证实**: 反编译出可读的 C# 源码
- **升级**: 源码审计 → 逻辑分析 → 漏洞发现/凭据提取

### 二进制补丁 Diff 反推漏洞
- **信号**: 有产品补丁前后的二进制文件（.exe/.dll/.sys）
- **假设**: 补丁 Diff 可反推被修复的漏洞
- **验证**: Ghidriff 通过 Ghidra ProgramAPI 做新旧二进制函数级 Diff → 8 种匹配器链逐级匹配 → AutoPiff 用 58 条 YAML 规则编码漏洞修复语义模式 + 反编译可达性追踪评分 → 自动从 Microsoft symbol server 下载补丁前后二进制
- **证实**: 定位到被修复的函数和具体修改点
- **升级**: 漏洞根因分析 → PoC 构建 → 利用

### Native 二进制逆向（C/C++/Rust）
- **信号**: 非 .NET 的 Windows PE 文件或 Linux ELF
- **假设**: 二进制包含可审计的算法、密钥或协议实现
- **验证**: Ghidra/IDA Pro 反汇编 → x64dbg/windbg 动态调试 → Frida hook 关键函数 → 符号恢复（如适用）→ 交叉引用追踪敏感 API（CryptEncrypt/SendRequest/recv）
- **证实**: 定位到关键逻辑（加密/网络/认证）
- **升级**: 算法还原 → 协议分析 → 加密破解

---

## 固件/IoT

### 固件提取与解包
- **信号**: 路由器/摄像头/IoT 设备固件文件（.bin/.img/.ubi/.squashfs）
- **假设**: 固件包含文件系统、配置文件、硬编码凭据
- **验证**: `binwalk -Me firmware.bin` 自动提取 → `unsquashfs` 解包文件系统 → `strings` 搜索关键字 → 寻找 /etc/shadow /etc/passwd 配置文件
- **证实**: 成功提取可读的文件系统
- **升级**: 文件系统审计 → 后门/硬编码凭据发现 → 设备控制

### U-Boot/Bootloader 分析
- **信号**: 设备使用 U-Boot 引导且串口/UART 可访问
- **假设**: Bootloader 可能包含未文档化的后门命令或中断引导进入 shell
- **验证**: UART 连接 → 启动时按键中断 U-Boot → 修改 bootargs 参数（init=/bin/sh）→ 单用户模式获取 root shell
- **证实**: 获得 root shell 访问
- **升级**: 完整文件系统访问 → 固件逆向 → 持久化后门
