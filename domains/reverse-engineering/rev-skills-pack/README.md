# rev-skills 原子技能包（融合 2026-09-17）

来源：`dslsdzc/rev-skills`（Apache-2.0 / CC-BY-4.0，122 个技能）。
**这是独立包**，不覆盖本机 `reverse-skill` 路由包；同名以本地为准。

- 技能数：**122**（网关 13 + 原子 109）
- 文件数：**276**，参考资料 **154**，合计 **2.31 MB**
- 结构：入口 `re-analyze` → 大类网关 → 原子技能；每技能自带 SKILL.md + references

## 用法（不依赖 Hermes）

```text
1. 先读 re-analyze/SKILL.md（输入判定 → 环境探测 probe.sh → 任务识别 triage.md）
2. 按目标类型进对应网关 SKILL.md
3. 网关选择树 → 打开具体原子技能 SKILL.md
4. 缺工具读技能内「工具准备」章节，不猜路径
```

## 入口 + 网关（13）

| 网关 | 简介 | 参考 |
|---|---|---|
| `re-analyze` | 逆向分析唯一入口。流程：环境探测(probe.sh) → 偏好询问(分析目标/反编译器/深度/报告/平台) → 任务识别(triage.md) → 编排调用大类网关 | 11 |
| `re-anti-analysis` | 反分析对抗网关。编排：壳识别 → 简单壳脱壳 → 强壳脱壳 → 反混淆。 子技能：[[re-packer-id]] [[re-unpack-simple]] [[re-unpack-advan… | 0 |
| `re-binary-core` | 软件逆向核心网关（公共底座）。编排：初勘 → 格式解析 → 反编译 → 调试/跟踪 → 内存。 子技能：[[re-address-space]] [[re-triage]] [[re-form… | 0 |
| `re-cracking` | 软件破解网关。编排：带壳先脱壳 → 授权定位 → 补丁/注册机。 子技能：[[re-license]] [[re-patching]] [[re-keygen]] [[re-drm]] | 0 |
| `re-ctf` | CTF 实践网关。编排：题型识别 → 简单题直接 [[re-binary-core]] → 需自动化 [[re-angr]]/[[re-z3]] → 混淆 [[re-deobfuscate]]… | 0 |
| `re-feedback` | 经验反馈元网关。三源收集（会话复盘/文章扫描/手动输入）→ 蒸馏脱敏 → 归域 → 三档处理（发表 issue/本地入库/不入库） | 3 |
| `re-firmware` | 固件/嵌入式/硬件分析网关。编排：提取 → rootfs → 仿真 → 硬件接口。 子技能：[[re-fw-extract]] [[re-fw-rootfs]] [[re-fw-emulate… | 0 |
| `re-forensics` | 内存取证/威胁情报网关。编排：转储来源 → 内存取证 → 线索提取 → 情报关联。 子技能：[[re-mem-forensics]] [[re-disk-forensics]] [[re-ti… | 0 |
| `re-malware` | 恶意软件分析网关。编排：默认沙箱 → 静态初勘 → 行为分析 → C2/协议 → IOC/报告。 子技能：[[re-sandbox]] [[re-behavior]] [[re-ioc]] [… | 0 |
| `re-managed` | 托管代码逆向网关。编排：识别运行时 → 反编译 → 去混淆 → 恶意场景转 [[re-malware]]。 子技能：[[re-dotnet]] [[re-java]] [[re-script-… | 0 |
| `re-mobile` | 移动应用分析网关。编排：APK 静态 → iOS → 动态 Frida → 原生库。 子技能：[[re-apk]] [[re-ios]] [[re-frida]] [[re-frida-scr… | 1 |
| `re-protocol` | 协议逆向网关。编排：捕获 → 加密识别 → 密钥 → 解密 → 状态机重建。 子技能：[[re-netcap]] [[re-crypto-id]] [[re-crypto-keys]] [[r… | 0 |
| `re-vuln` | 漏洞挖掘网关。编排：目标与输入面识别 → 覆盖率引导 fuzzing → 崩溃分析 → 逆向定位 → 报告。 子技能：[[re-fuzzing]] [[re-crash-triage]] [[… | 0 |

## 原子技能（109）

| 技能 | 简介 | 参考 |
|---|---|---|
| `re-address-space` | 地址空间换算统一处理：PIE/ASLR 基址确定、RVA/VA 转换、loader offset（固件加载地址 vs 链接地址）、 跨工具地址对齐（Ghidra/angr/frida/gdb） | 0 |
| `re-ai-attack` | AI 模型安全评估与取证（行为层）：extraction assessment（API 黑盒提取评估）、 fingerprint verification（行为指纹与归属验证）、privacy… | 3 |
| `re-ai-model` | AI 模型文件逆向与静态分析：ONNX/PyTorch/Safetensors/TFLite 格式解析、 网络结构还原、权重提取、文件级水印分析（权重 pattern/metadata/ten… | 0 |
| `re-ai-triage` | AI 模型分析第一入口（分流器）：识别输入形态——模型文件走文件层逆向（re-ai-model）、 仅有 API 走行为层评估（re-ai-attack）、恶意行为走恶意分析 | 0 |
| `re-android-crypto` | Android 加密体系审计（crypto audit）：AndroidKeyStore 密钥体系分析（别名/算法/用途/硬件背书）、 Cipher/KeyInfo 审计、加密调用点 hook… | 0 |
| `re-android-native` | Android 原生库 JNI 逆向：so 提取、JNI 注册还原、Native 逻辑分析 | 2 |
| `re-angr` | angr 符号执行：符号化输入、求解 | 2 |
| `re-anti-cheat` | 反作弊对抗分析：EAC/BattlEye 驱动、内存校验、检测机制还原 | 0 |
| `re-apk` | APK 静态分析：jadx/apktool、manifest、smali、加固识别 | 2 |
| `re-arm` | ARM 架构逆向（非 Android）：Cortex-M/A 向量表、Thumb/ARM 切换、AAPCS 调用约定、位置相关代码重定位、MMIO 外设寄存器交叉 | 0 |
| `re-attribution` | 威胁归因方法论：钻石模型、基础设施图谱、置信度分级与归因报告 | 2 |
| `re-automotive` | 汽车逆向：CAN 总线、ECU 固件、AUTOSAR Classic（RTE/runnable/BSW）与 Adaptive（执行管理/清单） | 2 |
| `re-behavior` | 恶意行为分析：持久化、注入、进程树、文件/注册表、ATT&CK 映射 | 0 |
| `re-binaryninja` | Binary Ninja 工作流：MLIL、脚本 API | 2 |
| `re-blockchain` | EVM 智能合约逆向：字节码反编译、漏洞分析 | 0 |
| `re-browser-ext` | 浏览器扩展逆向：权限清单、恶意行为定位、混淆还原、上架审查绕过面 | 2 |
| `re-console` | 现代主机与复古平台逆向：Switch NSO/NPDM 容器与加密分区、PS4/PS5 ORBIS 结构、SDK 库指纹；复古 ROM 头/卡带格式/存档与 Cheat 码 | 0 |
| `re-cpp-abi` | 现代 C++ 二进制逆向：RTTI/异常/虚表恢复、ABI 识别、mangling 解码 | 0 |
| `re-crash-triage` | 崩溃/漏洞样本分析：确定性复现、ASAN/UBSAN 报告解读、输入最小化 (afl-tmin/cmin)、gdb 回溯定位、rr 录制重放、PoC 产出 | 0 |
| `re-crypto-decrypt` | 加密数据还原：定位解密函数、写解密脚本 | 0 |
| `re-crypto-id` | 加密算法识别：常量表指纹、自定义加密模式 | 0 |
| `re-crypto-keys` | 密钥与口令提取：硬编码、内存搜索、资源 | 0 |
| `re-deobfuscate` | 反混淆：花指令、控制流平坦化、字符串加密 | 0 |
| `re-disk-forensics` | 磁盘/文件系统取证：删除恢复、时间线、可疑文件定位 | 0 |
| `re-doc-malware` | 恶意文档分析：PDF/Office 武器化、宏链、文档漏洞利用、载荷提取 | 2 |
| `re-dotnet` | .NET CIL 逆向：dnSpy/ILSpy 反编译、de4dot 去混淆、ConfuserEx | 0 |
| `re-drm` | DRM 分析：PlayReady/Widevine 实现、许可证流程、解密器还原 | 2 |
| `re-ebpf` | eBPF 程序逆向与对抗分析：BPF-64 指令集、progs/maps 关联、bpftool 反汇编、跟踪取证/恶意样本/EDR 对抗三用途 | 0 |
| `re-electron` | Electron 桌面应用逆向：asar 解包、主/渲染进程 JS、V8 字节码（.jsc）边界、CDP 动态调试、反调试对抗 | 0 |
| `re-emulation` | 模拟执行：Unicorn/Qiling 框架 | 2 |
| `re-evasion` | 检测规避/EDR 对抗分析：AMSI/ETW 绕过、无文件、lolbin 链 | 0 |
| `re-exploit` | 利用开发：ROP 链构造、堆利用 | 0 |
| `re-fileless` | 无文件恶意软件：内存执行、持久化、PowerShell 链 | 0 |
| `re-flutter` | Flutter/Dart AOT 逆向：libapp.so 快照分区解析、符号还原、Dart VM 动态分析 | 0 |
| `re-format-elf` | ELF 格式解析：ehdr/phdr/shdr、GOT/PLT、init_array、符号恢复 | 2 |
| `re-format-macho` | Mach-O 格式解析：mach_header、LC_*、segment、dyld 信息 | 2 |
| `re-format-pe` | PE 格式解析：DOS/NT 头、节表、导入导出、TLS 回调、Rich Header、证书表 | 0 |
| `re-fp-runtime` | 函数式语言运行时逆向（Haskell/OCaml）：闭包/堆对象模型、调用约定、数据流优先策略 | 2 |
| `re-frida` | Frida 动态插桩（桌面+移动统一） | 1 |
| `re-frida-script-author` | Frida 脚本生成方法论：目标特征 → 模板选择 → 改写 → 验证。独立于执行插桩（re-frida） | 2 |
| `re-fuzzing` | 覆盖率引导模糊测试：AFL++/libFuzzer/honggfuzz、插桩与语料初始化、 afl-fuzz 运行参数、覆盖率(afl-cov)、字典/结构化输入 | 0 |
| `re-fw-emulate` | 固件仿真：QEMU 用户态/全系统 | 2 |
| `re-fw-extract` | 固件提取与解包：binwalk/unblob、magic 扫描、字节序 | 0 |
| `re-fw-rootfs` | 固件文件系统分析：rootfs、配置、密钥、启动脚本 | 0 |
| `re-game` | 游戏逆向：Unity/Unreal、Cheat Engine、Lua 脚本引擎、图形 Shader | 0 |
| `re-gdb` | GDB/pwndbg/gef 调试：attach、断点、内存读写 | 2 |
| `re-ghidra` | Ghidra 工作流：导入→自动分析→反编译→脚本化 | 2 |
| `re-go` | Go 二进制逆向：符号保留、字符串表、goroutine | 0 |
| `re-hardware-io` | 硬件接口：JTAG/UART/flash 读取 | 2 |
| `re-harmonyos` | 鸿蒙（HarmonyOS）应用逆向：hap/hsp/har 包结构、ArkTS 字节码（.abc、ArkCompiler）分析 | 0 |
| `re-hunting` | 威胁狩猎方法论：假设驱动、遥测源选择、基线对比与验证闭环 | 2 |
| `re-hw-chip` | 物理层硬件逆向：去封装、裸片分析、探针与 FIB、PCB 电路分析、硬件木马检测 | 0 |
| `re-hybrid-app` | Flutter/React Native 混合应用逆向 | 0 |
| `re-hypervisor` | 虚拟化逆向：VT-x/SVM、hypervisor 检测、VMCS/EPT 分析， 以及 Xen / QNX Hypervisor / Jailhouse / ACRN / Bao / Hyp… | 9 |
| `re-ics` | 工控协议逆向：Modbus/DNP3/OPC UA | 0 |
| `re-ida` | IDA 工作流：导入→FLIRT→Hex-Rays→idapython | 2 |
| `re-imports` | 导入导出表与库指纹：IAT/EAT、DLL/so 指纹、FLIRT 思路 | 0 |
| `re-ioc` | IOC 提取与 YARA 规则、报告结构 | 0 |
| `re-ios` | iOS 应用分析：Mach-O、class-dump、越狱环境 | 2 |
| `re-ios-jb` | iOS 越狱逆向环境：越狱检测识别与绕过、tweak 分析与开发 | 0 |
| `re-iot-proto` | 物联网协议：MQTT/CoAP/BLE/Zigbee；BLE 链路层（广播解析/配对加密）与 NFC/智能卡（ISO14443/APDU/MIFARE） | 0 |
| `re-java` | Java 字节码逆向：CFR/JD-GUI、jar 解包、Java 加固 | 0 |
| `re-javacard` | Java Card / SIM 卡 applet 逆向：CAP 文件组件解析（规范 12 组件）、CAP 字节码（Java 子集）还原、AID 与安装参数、process(APDU) 分派 | 0 |
| `re-kernel` | 内核逆向（跨平台）：Windows 驱动（.sys/IRP/SSDT）、Linux 内核模块（.ko/ET_REL/LKM/rootkit）、 macOS KEXT 与 System Exte… | 23 |
| `re-keygen` | 注册机算法还原 | 2 |
| `re-license` | 授权验证逻辑分析：注册校验定位 | 2 |
| `re-lldb` | lldb 调试（macOS/iOS）：attach、expr、image | 2 |
| `re-loader` | 加载器/投放器分析：多层下载、内存加载、模块拼接 | 0 |
| `re-macos` | macOS 原生应用逆向：App Bundle/签名公证、entitlements、沙箱与 TCC、钥匙串与 Secure Enclave | 2 |
| `re-mem-forensics` | Volatility 3 内存取证：进程/内核对象/网络/凭据线索 | 0 |
| `re-memdump` | 内存转储与提取：默认转储优先(gcore)，直读特例 | 2 |
| `re-mips` | MIPS 架构逆向与路由器固件分析方法论：延迟槽、$gp 调用约定、大小端判断、httpd 定位 | 0 |
| `re-mobile-forensics` | 移动设备取证：Android/iOS 备份解析、应用数据提取、删除恢复与时间线 | 2 |
| `re-mobile-pack` | Android 加固脱壳专项：乐固/360/梆梆/爱加密、DEX 恢复 | 0 |
| `re-netcap` | 网络流量捕获：tcpdump/Wireshark/抓包 | 2 |
| `re-nim` | Nim 编译产物逆向：运行时识别、NimString 结构、异常与 GC 路径 | 2 |
| `re-packer-id` | 壳与混淆器识别：签名/节名/EP/熵 | 0 |
| `re-patching` | 补丁制作：字节级 patch、指令重写 | 0 |
| `re-plugin-dev` | Ghidra/IDA 插件开发：脚本→插件工程化 | 0 |
| `re-proto-rev` | 协议状态机重建：Scapy 解析、消息结构 | 0 |
| `re-pwn` | CTF pwn 入门：栈溢出、格式化字符串、ret2libc | 0 |
| `re-python` | Python 打包/混淆样本分析：PyInstaller/PyArmor/Nuitka/Cython 解包、pyc 版本识别与反编译 | 2 |
| `re-radare2` | rizin/radare2 工作流：命令行分析、pdf、V 模式 | 2 |
| `re-ransomware` | 勒索软件分析：加密识别、勒索信、解密恢复思路 | 0 |
| `re-riscv` | RISC-V 架构逆向：RV32/RV64、压缩指令（RVC）、gp 相对寻址、ABI 与 ecall 系统调用约定、工具链指纹 | 0 |
| `re-rtos` | RTOS 结构分析：FreeRTOS/ThreadX/Zephyr/RT-Thread/VxWorks/QNX/RTEMS/NuttX/eCos/µC-OS/SYS-BIOS/SAFERTOS… | 14 |
| `re-rust` | Rust 二进制逆向：符号、monomorphization、所有权模式 | 0 |
| `re-sample-acquire` | 样本现场采集（从现象到可用样本）：目标没有独立进程、样本不落盘时，以「异常执行内存 + 到达该内存的执行上下文」为核心定位载体并运行时提取。 覆盖四种观测模型：Windows（VAD/线程/E… | 4 |
| `re-sandbox` | 沙箱环境搭建（动态分析强制前置） | 2 |
| `re-script-deob` | 脚本/宏去混淆：PowerShell、VBA、JavaScript | 0 |
| `re-sdr` | 射频逆向：信号采集、频谱分析、解调、帧同步与协议恢复、重放 | 2 |
| `re-shellcode` | Shellcode 分析：提取、解码循环、模拟执行 | 0 |
| `re-stego` | 隐写术检测与提取：文件尾附加、图片 LSB、音频与其他载体、提取验证 | 2 |
| `re-swift` | Swift 二进制逆向：mangling 解码、协议 witness table、闭包捕获、ObjC 互操作 | 2 |
| `re-tee` | TEE/TrustZone 逆向：OP-TEE 架构、可信应用（Trusted App）、secure storage、SMC 接口与设备密钥 | 2 |
| `re-ti` | 威胁情报查询与关联：VT/Any.run/hybrid-analysis、MISP | 2 |
| `re-tls` | TLS/加密流量深度：指纹、密钥导出、TLS 1.3 | 0 |
| `re-tracing` | 系统调用/函数调用跟踪：strace/ltrace/dtruss | 2 |
| `re-triage` | 文件初步勘察：file/哈希(sha256/md5)/熵/strings/架构识别 | 0 |
| `re-uefi` | UEFI/BIOS 固件：SEC/PEI/DXE/BDS 阶段判定、DXE 驱动、UEFI 模块、bootkit | 1 |
| `re-unpack-advanced` | 强壳脱壳：VMProtect/Themida | 0 |
| `re-unpack-simple` | 压缩壳脱壳：UPX/ASPack/FSG | 0 |
| `re-variant` | 二进制变体/补丁对比：函数匹配、N-day 补丁 diff、变体溯源与相似度分析 | 2 |
| `re-wasm` | WASM 逆向：格式解析、wasm2wat、浏览器侧 | 0 |
| `re-whitebox` | 白盒加密分析：白盒实现识别、密钥提取 | 0 |
| `re-windbg` | WinDbg 调试（Windows 用户态+内核） | 2 |
| `re-x64dbg` | x64dbg 调试（Windows）：attach、断点、Scylla | 2 |
| `re-z3` | Z3 约束求解：建模、密钥/flag 推导 | 0 |
| `re-zig` | Zig 编译产物逆向：产物识别、comptime 展开、panic/错误处理路径、C ABI 边界 | 2 |

## 相对本机的增量面

本地 `reverse-skill` 缺失或明显更浅：`re-kernel` `re-rtos` `re-hypervisor` `re-tee` `re-javacard` `re-ebpf` `re-uefi` `re-automotive` `re-ics` `re-sdr` `re-console` `re-game` `re-flutter` `re-hybrid-app` `re-electron` `re-wasm` `re-whitebox` `re-drm` `re-anti-cheat` `re-memdump` `re-netcap` `re-stego` `re-crash-triage` `re-fp-runtime` `re-ai-model` `re-nim` `re-zig` `re-riscv` `re-mips` `re-arm` `re-hw-chip` `re-fw-*` `re-mobile-*` `re-ios-jb`

## 投毒甄别

入库前已核：无 npm `postinstall/preinstall/prepare` 钩子；JS 无混淆、无 `curl|bash`、无挖矿/回连；
唯一外连 `bin/wxsource.mjs` → `https://bbs.kanxue.com`（看雪论坛，取素材）。
唯一 shell `re-analyze/references/probe.sh` = `uname/free/command -v` 环境探测。**结论：干净。**

---
@TGSEC社区 · @TGSEC-Qtzuu 整理