---
name: reverse-engineering
description: >-
  逆向工程专家手册。涵盖AI辅助逆向、移动应用逆向、二进制分析与漏洞挖掘、固件逆向、反混淆与反反调试、WebAssembly逆向、加密协议逆向、硬件侧信道攻击。使用场景：二进制分析、APK/IPA逆向、固件提取与分析、混淆代码还原、WASM模块分析、TLS/SSH协议审计、侧信道攻击与故障注入。
---

# SKILL: 逆向工程 — 专家攻击手册

> **AI LOAD INSTRUCTION**: 2026年逆向工程全栈技术。覆盖AI辅助逆向(GhidrAssist/GEPETTO/VulChatGPT/Binary Ninja Sidekick/HELIOS)、移动应用逆向(Frida/Objection/JADX)、二进制分析(angr/SysFuSS/Bangr)、固件逆向(SWD/JTAG/SPI嗅探/CH341A)、反混淆(Squanchy/SiMBA++/wasm2c)、WebAssembly逆向(WABT/SeeWasm)、加密协议逆向(CryptoLyzer/CryptoBap/侧信道形式化分析)、硬件逆向(ChipWhisperer/DPA/电压毛刺)。核心CVE：CVE-2026-3142(OpenSSL HollowByte)、CVE-2026-33697(Attested TLS)、CVE-2026-0947(MCP证书链绕过)。

## 0. RELATED ROUTING

使用本文件进行逆向工程分析。同时加载：

- [mobile-app-security-testing](../mobile-app-security-testing/SKILL.md) — 移动应用安全测试方法论（逆向是其中的核心分析手段）
- [secure-code-review](../secure-code-review/SKILL.md) — 源码级安全审计（与二进制逆向互补）
- [vulnerability-assessment](../vulnerability-assessment/SKILL.md) — 漏洞评估流程（逆向发现后的影响评估）
- [container-security-testing](../container-security-testing/SKILL.md) — 容器镜像逆向分析
- [sinian-omnipotent](../sinian-omnipotent/SKILL.md) — 全能技能集 Part XI 逆向工程融合层

---

## 1. AI辅助逆向工程 — 2026核心战场

2026年AI辅助逆向已从实验阶段进入生产实用阶段。LLM与反编译器的深度集成形成语义增强、代码解释和漏洞检测三大应用类别。

### 1.1 Ghidra AI插件生态

**GhidrAssist** — 将Ghidra直接连接到LLM API（OpenAI/Anthropic/Ollama本地模型），对当前选中函数进行上下文分析。核心优势：不将整个二进制反编译结果灌入提示词，而是构建聚焦查询——包含目标函数、直接调用者/被调用者、相关字符串引用。

```bash
# 安装GhidrAssist
git clone https://github.com/unkmc/GhidrAssist.git
cp -r GhidrAssist $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
# 重启Ghidra → File > Install Extensions启用
```

**GEPETTO** — 最早的生产级Ghidra AI插件，专注函数解释和批量重命名。可将 `FUN_00401000` 标签转化为 `decrypt_config_buffer` 或 `parse_c2_response` 等有意义名称。对常见模式（文件I/O、网络操作、加密例程）准确率超80%。

**VulChatGPT** — 扩展GEPETTO概念，专注漏洞识别。分析反编译函数中的常见漏洞模式（缓冲区溢出、整数溢出、UAF、格式化字符串、竞态条件），生成结构化报告：漏洞类型、受影响行、严重程度估计、利用难度。分析2000个函数的二进制时，自动首轮标记50个最可疑函数可节省数天人工审查。

**PyGhidra** — 允许以Python库方式运行Ghidra分析引擎无需启动GUI，对构建自动化管道具有变革性意义：

```python
# PyGhidra自动化分析管道
import pyghidra
from pyghidra import GhidraProject

with GhidraProject.open("target_binary") as project:
    program = project.program
    fm = program.getFunctionManager()
    
    # 遍历所有函数，自动重命名
    for func in fm.getFunctions(True):
        if func.getName().startswith("FUN_"):
            decompiled = project.decompile(func)
            # 发送给LLM分析
            analysis = llm_analyze(decompiled)
            if analysis.confidence > 0.8:
                func.setName(analysis.suggested_name)
```

### 1.2 Binary Ninja Sidekick

Vector 35将AI功能直接集成到平台。Sidekick提供上下文感知的交互式聊天界面，知道当前查看的函数、当前选择的内容、已执行的分析。Binary Ninja的类型传播引擎直接馈入AI上下文，模型不仅看到原始反编译代码，还看到恢复的类型、结构和枚举值：

```python
# Binary Ninja Sidekick自动化脚本
from binaryninja import BinaryViewType
bv = BinaryViewType.get_view_of_file("/path/to/binary")
for func in bv.functions:
    if func.name.startswith("sub_"):
        analysis = bv.query_sidekick(
            f"Analyze function at {hex(func.start)} and suggest a name"
        )
        if analysis.confidence > 0.8:
            func.name = analysis.suggested_name
```

### 1.3 IDA Pro AI集成

**BinaryAI** — 使用基于嵌入的相似性搜索，将函数与已知开源代码数据库匹配。计算函数控制流图和数据流模式的向量嵌入，在索引语料库中搜索相似函数。擅长识别静态链接的库函数（zlib、OpenSSL、SQLite）。

**IDAssist** — IDA Pro插件，将LLM驱动的分析直接集成到IDA界面，支持可配置的LLM提供商、语义知识图谱、RAG文档搜索。基于Python和PySide6构建，作为可停靠面板在IDA Pro 9.0+中运行。

**DAILA** — 反编译器无关的AI交互插件，基于BinSync库LibBS抽象反编译器差异。支持IDA、Ghidra、Binja和angr-management。集成两种AI系统：OpenAI和VarBERT。

### 1.4 HELIOS — 学术前沿(NDSS 2026)

**HELIOS**（Hierarchical Graph Abstraction for Structure-Aware LLM Decompilation）提出层次化图抽象方法。第一阶段使用Ghidra无头分析器提取丰富制品：反编译器的C/C-like伪代码、控制流图、数据流信息。设计工具无关，可基于其他分析框架实现。

### 1.5 基础工具链

```python
# Capstone反汇编 + Unicorn仿真 + Keystone汇编
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

# 反汇编
CODE = b"\x55\x48\x89\xe5\x48\x83\xec\x10\x89\x7d\xfc"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for insn in md.disasm(CODE, 0x1000):
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

# Unicorn仿真执行
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000, 0x1000)
uc.mem_write(0x1000, CODE)
uc.emu_start(0x1000, 0x1000 + len(CODE))
```

### 1.6 AI逆向工具对比

| 工具 | 平台 | 核心能力 | LLM支持 | 适用场景 |
|---|---|---|---|---|
| GhidrAssist | Ghidra | 函数上下文分析 | OpenAI/Anthropic/Ollama | 通用逆向分析 |
| GEPETTO | Ghidra | 批量函数解释重命名 | OpenAI | 大型二进制快速标注 |
| VulChatGPT | Ghidra | 漏洞模式识别 | OpenAI | 漏洞挖掘加速 |
| Sidekick | Binary Ninja | 交互式AI对话+类型感知 | 内置 | 精细化分析 |
| BinaryAI | IDA Pro | 函数相似性搜索(嵌入) | 专有模型 | 库函数识别 |
| IDAssist | IDA Pro 9.0+ | 语义知识图谱+RAG | 多提供商 | 复杂目标分析 |
| DAILA | IDA/Ghidra/Binja/angr | 跨平台AI交互 | OpenAI/VarBERT | 多工具工作流 |
| PyGhidra | Python(无头) | 自动化管道 | 可选 | CI/CD集成 |

---

## 2. 移动应用逆向 — Android & iOS

### 2.1 2026年十大移动渗透测试工具

| 类别 | 工具 | 平台 | 主要用途 |
|---|---|---|---|
| 动态运行时分析 | **Frida** | Android & iOS | 运行时插桩、Hook、绕过安全控制 |
| 静态分析和逆向 | **Ghidra** | Android & iOS | 底层二进制分析、固件和库逆向 |
| 静态分析和逆向 | **JADX** | Android | APK反编译为类Java源码 |
| 网络流量分析 | **mitmproxy** | Android & iOS | 交互式HTTP/S/WebSocket拦截 |
| 网络流量分析 | **Wireshark** | Android & iOS | 数据包级网络捕获 |
| 自动化和编排 | **OXO** | Android & iOS | 协调多个移动安全工具 |
| 自动漏洞扫描 | **Nuclei** | Android & iOS | 模板驱动CVE/配置错误扫描 |

### 2.2 Android逆向流程

```bash
# 1. APK解包与反编译
apktool d target.apk -o target_decoded
jadx -d target_jadx target.apk

# 2. 查找敏感信息
grep -rn "api_key\|secret\|password\|token" target_jadx/sources/
grep -rn "http://\|https://" target_jadx/sources/ | grep -v "schemas.android"

# 3. Native库分析
# JNI函数命名: Java_<package>_<ClassName>_<methodName>
# 例: Java_com_target_app_auth_NativeAuth_verifyToken
file lib/arm64-v8a/*.so
# 用Ghidra打开.so文件，搜索Java_前缀函数

# 4. Smali修补（绕过验证）
# 修改Smali代码: 将方法返回值改为true
# 原始: const/4 v0, 0x0  (false)
# 修改: const/4 v0, 0x1  (true)
apktool b target_decoded -o target_patched.apk
# 签名
apksigner sign --ks debug.keystore target_patched.apk
```

### 2.3 Frida运行时插桩

```javascript
// Frida脚本：绕过Root检测
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[+] RootBeer.isRooted() bypassed');
        return false;
    };
});

// 绕过SSL Pinning
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.Builder.implementation = function() {
        console.log('[+] SSL Pinning bypassed');
        return this.certificatePinner(null);
    };
});

// Hook加密函数捕获明文
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        console.log('[+] Cipher.doFinal captured:');
        console.log('  Input: ' + bytesToHex(input));
        console.log('  Output: ' + bytesToHex(result));
        return result;
    };
});
```

### 2.4 Objection一键绕过

```bash
# 启动Objection
objection -g com.target.app explore

# Android绕过
android root disable           # 绕过Root检测
android sslpinning disable     # 绕过SSL Pinning
android keystore list          # 列出KeyStore条目
android hooking list classes   # 列出已加载类
android hooking watch class_method com.target.Auth.verify --dump-args --dump-return

# iOS绕过
ios jailbreak disable          # 绕过越狱检测
ios sslpinning disable         # 绕过SSL Pinning
ios keychain dump              # 导出Keychain
ios hooking watch class_method TargetAuth:verifyToken:
```

### 2.5 iOS逆向

```bash
# 1. 从IPA提取二进制
unzip target.ipa -d target_extracted
cd target_extracted/Payload/Target.app/

# 2. class-dump导出头文件
class-dump -H Target -o Target_headers/

# 3. 查找敏感方法
grep -rn "password\|secret\|token\|auth\|verify" Target_headers/

# 4. Frida Hook Objective-C方法
frida -U -f com.target.app -l hook.js --no-pause
```

```javascript
// iOS Frida脚本：Hook认证方法
ObjC.classes.TargetAuth['- verifyToken:'].implementation = function(token) {
    console.log('[+] verifyToken called with: ' + token);
    return 1; // 强制返回成功
};
```

---

## 3. 二进制分析与漏洞挖掘

### 3.1 AI驱动的二进制安全认知引擎

传统二进制安全分析面临"不可能三角"：速度（Fuzzing快速覆盖路径）、深度（符号执行求解深层约束）与广度（大规模测试目标）无法兼顾。AI驱动方案通过认知引擎演进突破这一瓶颈。

### 3.2 SysFuSS — 系统级固件模糊测试

**SysFuSS**（System-Level Firmware Fuzzing with Selective Symbolic Execution）是混合固件验证框架，克服传统模糊测试在复杂系统级固件中检测漏洞的局限。固件运行在最高特权级别，其漏洞异常危险。SysFuSS通过集成系统级选择性符号执行解决覆盖率平台期问题。

### 3.3 Bangr — Binary Ninja + angr集成

NDSS BAR 2026发表的**Bangr**插件将angr的符号执行能力集成到Binary Ninja中，桥接静态分析和符号执行工具：

```python
# Bangr: 在Binary Ninja中使用angr符号执行
import angr
import binaryninja as bn

# 从Binary Ninja加载angr项目
bv = bn.BinaryViewType.get_view_of_file("target.bin")
proj = angr.Project("target.bin")

# 找到目标函数
target_func = bv.get_function_at(0x401000)
# 使用angr符号执行探索路径
state = proj.factory.blank_state(addr=0x401000)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401200, avoid=0x401300)

if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.posix.dumps(0)
    print(f"[+] Input reaching target: {solution}")
```

### 3.4 静态分析增强的模糊测试

通过静态二进制分析将黑盒模糊测试转变为覆盖率驱动的过程：

```python
# 使用angr进行静态分析增强AFL模糊测试
import angr

proj = angr.Project("target.bin", auto_load_libs=False)
cfg = proj.analyses.CFGFast()

# 识别高风险函数
high_risk_funcs = []
for func in cfg.functions.values():
    if func.name and any(kw in func.name.lower() for kw in 
        ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'memcpy']):
        high_risk_funcs.append(func)

# 生成AFL种子输入针对高风险函数
for func in high_risk_funcs:
    # 使用符号执行生成到达漏洞函数的输入
    state = proj.factory.blank_state(addr=func.addr)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=func.addr + func.size)
    # 导出种子到AFL种子目录
```

### 3.5 漏洞模式快速识别

```python
# 使用Ghidra无头分析识别漏洞模式
# @category: Security
# 运行: analyzeHeadless . Project -scriptPath . -postScript vuln_scan.py

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType

fm = currentProgram.getFunctionManager()
vuln_patterns = {
    'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'],
    'format_string': ['printf', 'fprintf', 'syslog', 'snprintf'],
    'integer_overflow': ['malloc', 'calloc', 'realloc', 'alloca'],
    'use_after_free': ['free', 'delete'],
    'command_injection': ['system', 'popen', 'exec', 'execve']
}

for func in fm.getFunctions(True):
    name = func.getName()
    for vuln_type, patterns in vuln_patterns.items():
        if name in patterns:
            print(f"[!] {vuln_type}: {name} at {func.getEntryPoint()}")
            # 获取交叉引用
            refs = getReferencesTo(func.getEntryPoint())
            for ref in refs:
                print(f"    Called from: {ref.getFromAddress()}")
```

---

## 4. 固件逆向工程

### 4.1 固件提取技术

**SWD和JTAG（前门攻击）** — 如果调试端口在生产环境中保持激活，使用Segger J-Link或OpenOCD可在几秒内转储整个闪存：

```bash
# OpenOCD转储ARM固件
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg \
    -c "init" \
    -c "halt" \
    -c "flash read_bank 0 firmware_dump.bin 0 0x100000" \
    -c "shutdown"
```

**Flash转储（脱焊方法）** — 对使用外部SPI/I2C闪存芯片的系统，使用热风返修台脱焊芯片，放入CH341A读取器：

```bash
# 使用CH341A和flashrom读取SPI闪存
flashrom -p ch341a_spi -r firmware_dump.bin
```

**SPI嗅探（传输中拦截）** — 对BGA封装闪存，使用逻辑分析仪（Saleae）连接MCU和闪存芯片之间的走线，在设备重启时捕获固件加载过程：

```text
SPI嗅探连接:
  逻辑分析仪CH1 → SPI CLK
  逻辑分析仪CH2 → SPI MOSI (MCU→Flash)
  逻辑分析仪CH3 → SPI MISO (Flash→MCU)
  逻辑分析仪CH4 → SPI CS

触发条件: CS下降沿(开始传输)
捕获: 完整固件从Flash加载到MCU RAM的数据
```

### 4.2 固件分析工具链

| 工具 | 特点 | 适用场景 |
|---|---|---|
| **Ghidra** | 自动反编译ARM/MIPS/x86为C-like伪代码 | 通用固件逆向 |
| **IDA Pro** | 冷门微控制器处理器模块支持 | 特殊架构固件 |
| **Binary Ninja** | 极快UI和强大IL | 快速分析 |
| **Radare2/Cutter** | 命令行驱动，脚本化 | CI/CD管道集成 |
| **binwalk** | 固件提取和特征扫描 | 固件解包 |

```bash
# binwalk固件提取
binwalk -e firmware.bin
# 递归提取嵌套文件系统
binwalk -eM firmware.bin
# 扫描加密签名
binwalk -S firmware.bin

# 在提取的文件系统中查找敏感信息
find _firmware.bin.extracted/ -type f -name "*.conf" -o -name "*.cfg" -o -name "*.key"
grep -rn "password\|admin\|root\|secret" _firmware.bin.extracted/
# 查找硬编码凭据
strings _firmware.bin.extracted/squashfs-root/bin/httpd | grep -i "pass\|key\|token"
```

### 4.3 硬件调试工具

| 工具 | 功能 | 价格区间 |
|---|---|---|
| 逻辑分析仪(Saleae) | 抓取UART/SPI通信信号 | $500+ |
| OpenOCD | JTAG接口调试ARM芯片 | 开源 |
| Bus Pirate | 万能硬件调试(I2C/SPI等) | $30-50 |
| JTAGulator | 发现和识别JTAG接口 | $50-70 |
| Glasgow Interface Explorer | 多协议硬件接口 | $100+ |
| ChipWhisperer | 侧信道分析和故障注入 | $300+ |

### 4.4 嵌入式设备调试复活

通过在RDP（读取保护）检查期间进行glitch来重新启用调试：

```text
调试复活流程:
  1. 在启动期间捕获功耗轨迹
  2. 识别安全检查时序(功耗轨迹中的特征模式)
  3. 配置glitch参数:
     - 宽度: 10-50ns
     - 偏移: 相对于时钟边沿的精确位置
     - 重复: 迭代直到成功绕过
  4. 通过调试接口提取固件

所需设备: ChipWhisperer/类似glitch平台 + 示波器 + 目标板修改(电容移除)
```

---

## 5. 反混淆与反反调试

### 5.1 WASM反混淆工具链

BlackHat Asia 2025发表的系统性方法，将LLVM工具链用于WebAssembly反混淆：

**混淆工具识别**:
| 混淆器 | 特征技术 |
|---|---|
| O-LLVM | 指令替换、控制流平坦化、虚假控制流 |
| Hikari | 函数调用混淆、函数包装、字符串加密 |
| Polaris | 别名访问、间接调用、线性MBA |
| Wasmixer | WebAssembly专用混淆 |

**反混淆工具链**:

```bash
# Squanchy — 自动化WASM反混淆
# 将Wasm提升到LLVM IR → 优化 → 提取干净模块
git clone https://github.com/pgarba/Squanchy.git
cd Squanchy
python3 squanchy.py --input obfuscated.wasm --output clean.wasm

# SiMBA++ — 简化MBA表达式
python3 simba.py --input obfuscated.ll --output simplified.ll

# GAMBA — 非线性MBA求解
python3 gamba.py --input simplified.ll --output solved.ll

# SOUPER — 超级优化器(解析不透明谓词)
souper -z3solver input.ll -o output.ll
```

**实际案例**: hCaptcha的中型混淆函数可在<1-2分钟内简化，展开控制流并内联函数。

### 5.2 传统二进制反混淆

```python
# 使用angr进行控制流反平坦化
import angr

proj = angr.Project("obfuscated.bin", auto_load_libs=False)
cfg = proj.analyses.CFGFast()

# 识别控制流平坦化的调度器
for func in cfg.functions.values():
    if func.block_count > 50:  # 平坦化后基本块数量激增
        # 分析调度器模式: switch-case分发
        blocks = list(func.blocks)
        # 查找分发器基本块(大量条件跳转)
        for block in blocks:
            if len(block.vex.constant_jump_targets) > 10:
                print(f"[+] Likely dispatcher at {hex(block.addr)}")
                # 使用符号执行重建原始控制流
```

### 5.3 反反调试技术

```python
# 绕过ptrace反调试(Linux)
import ctypes
libc = ctypes.CDLL('libc.so.6')

# 方法1: LD_PRELOAD覆盖ptrace
# preload.c
"""
long ptrace(int request, int pid, void *addr, void *data) {
    return 0;  // 始终返回成功
}
"""
# gcc -shared -fPIC -o anti_anti_debug.so preload.c
# LD_PRELOAD=./anti_anti_debug.so ./target

# 方法2: Frida Hook ptrace
# frida脚本
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onEnter: function(args) {
        console.log('[+] ptrace called, faking success');
    },
    onLeave: function(retval) {
        retval.replace(0);  // 返回0(成功)
    }
});

# 方法3: 修改/proc/self/status
# Frida脚本: 覆盖TracerPid
Interceptor.attach(Module.findExportByName(null, 'fopen'), {
    onLeave: function(retval) {
        // 重写/proc/self/status内容
    }
});
```

### 5.4 动态密钥捕获

针对运行时生成AES密钥链的动态密钥混淆：

```javascript
// Frida: 捕获运行时AES密钥
Java.perform(function() {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        if (algo === 'AES') {
            console.log('[+] AES Key captured: ' + bytesToHex(key));
        }
        return this.$init(key, algo);
    };
    
    // 捕获动态密钥生成
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function() {
        var key = this.generateKey();
        var encoded = key.getEncoded();
        console.log('[+] Dynamic key generated: ' + bytesToHex(encoded));
        return key;
    };
});
```

---

## 6. WebAssembly逆向

### 6.1 WASM二进制分析特性

WebAssembly二进制格式是结构化、可验证的栈式虚拟机表示——在可分析性上显著优于原生机器码。每个WASM模块暴露类型化的导入/导出表、声明的函数计数、可读的数据段。

### 6.2 WASM工具链

| 工具 | 功能 |
|---|---|
| WABT (WebAssembly Binary Toolkit) | 标准二进制工具包(wasm2wat/wat2wasm/wasm-objdump) |
| wasm-tools | 现代Wasm工具集 |
| Ghidra (Wasm插件) | 查看反编译的Wasm |
| JEB Pro | 商业Wasm分析工具 |
| wasm2c | 将Wasm提升到C(有良好定义的运行时) |
| WAMRC | WebAssembly Micro Runtime AOT编译器 |
| SeeWasm | WASM符号执行工具 |

```bash
# WASM逆向基础流程
# 1. 提取WASM模块
wasm-objdump -x module.wasm        # 查看节信息
wasm2wat module.wasm -o module.wat # 转换为WAT文本格式

# 2. 导出函数分析
wasm-objdump -x module.wasm | grep "Export"
# 查看导出函数名和类型签名

# 3. 使用wasm2c提升到C
wasm2c module.wasm -o module.c
# 生成的C代码可读性更好，便于分析

# 4. 使用SeeWasm符号执行
seewasm -m module.wasm -func export_function_name
```

### 6.3 WASM逆向军备竞赛(2026)

到2026年，主要反机器人平台的Wasm逻辑已被安全研究社区完整记录：

| 平台 | 逆向状态 | 影响 |
|---|---|---|
| Cloudflare Turnstile | token生成逻辑已完整文档化 | 存在生成有效token的Python库 |
| DataDome | sensor data格式已知 | 可伪造有效请求 |
| Akamai BotManager | cookie生成已被复制 | 绕过反机器人检测 |
| Solver-as-a-service | 每次收费<$0.00 | 自动化绕过即服务 |

---

## 7. 加密协议逆向

### 7.1 2026年关键CVE

**CVE-2026-3142（OpenSSL HollowByte）** — 2026年7月14日由Cryptographic Integrity Labs披露。一个精确11字节的TLS Client Hello数据包可迫使OpenSSL无限期分配和持有服务器内存——无需认证、无需会话协商。72小时内出现PoC代码。CVSS高危。

**CVE-2026-33697（Attested TLS Intra-handshake.fail）** — CVSS 7.5。在IETF 126会议披露。影响Attested TLS，以TLS 1.3为传输、AI代理为动机用例。使用ProVerif形式化工具发现。

**CVE-2026-0947（MCP证书链校验绕过）** — 高危逻辑缺陷。漏洞源于对证书签名算法与公钥类型匹配关系的宽松校验，攻击者可构造包含混合签名算法的证书链实施绕过。

```bash
# CVE-2026-0947 快速检测: 3行OpenSSL命令定位受影响节点
openssl s_client -connect target:443 -cert mixed_sig_cert.pem 2>&1 | \
  grep -E "verify return|Certificate chain"
# 如果返回verify OK但使用了混合签名算法 → 受影响
```

### 7.2 CryptoLyzer — 加密协议分析器

```bash
# CryptoLyzer 1.4.0 — 全面加密协议分析
pip install cryptolyzer

# TLS分析
cryptolyze tls target.com 443
# SSH分析
cryptolyze ssh target.com 22
# 检测400+密码套件包括GOST和后量子算法

# JA3指纹生成
cryptolyze tls target.com 443 --ja3
# HASSH指纹生成
cryptolyze ssh target.com 22 --hassh

# 批量扫描
cryptolyze tls target.com 443 --json | jq '.ciphers[] | select(.key_exchange == "RSA")'
# 检测弱密钥交换
```

### 7.3 自动化侧信道分析(CCS 2026)

从真实二进制中提取协议相关模型，在显式泄漏契约下分析：

```text
分析流程:
  1. 从选定二进制区域开始
  2. 将机器码提升到中间表示(BIR - Binary Intermediate Representation)
  3. 注入泄漏契约(定义哪些指令泄漏信息)
  4. 符号执行获取事件/观察轨迹
  5. 转换为Sapic+模型
  6. 使用Tamarin/ProVerif/DeepSec分析

框架: CryptoBap + HolBA (使用HOL4定理证明器和L3规范语言)

案例: WhatsApp Desktop
  - 首次从二进制中提取Sesame会话管理和双棘轮机制形式化模型
  - 证明前向安全性
  - 发现新隐私攻击: 利用会话建立期间指令缓存侧信道
    推断两个用户是否有过联系(社交图谱推断)
```

### 7.4 TLS协议审计

```bash
# 全面TLS配置审计
# 1. 使用testssl.sh
testssl.sh --full target.com

# 2. 使用nmap NSE脚本
nmap --script ssl-enum-ciphers,ssl-cert,ssl-known-key,ssl-poodle,ssl-heartbleed target.com

# 3. 使用sslyze
sslyze --regular --certinfo --robot target.com

# 4. 检测降级攻击
nmap --script ssl-ccs-injection,ssl-drown target.com

# 5. CryptoLyzer后量子算法检测
cryptolyze tls target.com 443 --all-versions
# 检查是否支持后量子密码套件(Kyber/Dilithium)
```

---

## 8. 硬件逆向 — 侧信道攻击与故障注入

### 8.1 功耗分析攻击

每次CPU执行指令——特别是加密操作——都会消耗微小功率。通过高灵敏度探头连接MCU电源轨并用示波器监控功耗：

**简单功耗分析(SPA)** — 直接观察功耗轨迹中的操作特征：

```python
# ChipWhisperer SPA分析
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)

# 捕获功耗轨迹
scope.adc.samples = 24000
trace = cw.capture_trace(scope, target, plaintext, key)

# 分析功耗轨迹识别AES轮操作
import numpy as np
import matplotlib.pyplot as plt

plt.plot(trace.wave)
plt.title('SPA: AES Power Trace')
plt.xlabel('Sample')
plt.ylabel('Power')
plt.show()
# 可观察到10轮AES的功耗峰值模式
```

**差分功耗分析(DPA)** — 对数千条功耗轨迹的统计分析直接从硅片提取加密密钥：

```python
# DPA攻击AES-128
# 1. 捕获N条功耗轨迹(不同明文,相同密钥)
# 2. 对每个密钥假设,计算中间值(如S-box输出)
# 3. 根据中间值某bit将轨迹分为两组
# 4. 计算两组功耗均值之差
# 5. 正确密钥假设产生最大差分峰值

import numpy as np

traces = np.load('traces.npy')        # N x T 功耗矩阵
plaintexts = np.load('plaintexts.npy') # N x 16 明文数组

sbox = np.array([...])  # AES S-box

for key_byte in range(16):
    max_corr = 0
    best_key = 0
    for k in range(256):
        # 计算中间值
        intermediate = sbox[plaintexts[:, key_byte] ^ k]
        # 取LSB作为分组依据
        group0 = traces[intermediate & 1 == 0]
        group1 = traces[intermediate & 1 == 1]
        # 差分均值
        diff = np.abs(np.mean(group0, axis=0) - np.mean(group1, axis=0))
        if np.max(diff) > max_corr:
            max_corr = np.max(diff)
            best_key = k
    print(f"Key byte {key_byte}: 0x{best_key:02x} (corr={max_corr:.4f})")
```

### 8.2 故障注入 — 电压毛刺

在CPU执行关键指令时瞬间降低电压，使CPU恰好在一个时钟周期内逻辑失效：

```text
电压毛刺攻击Secure Boot绕过:
  目标: if (firmware_signature_valid == TRUE) { boot(); }
  
  1. 监控目标功耗确定安全检查时序
  2. 在签名验证指令执行时注入电压毛刺
  3. 毛刺宽度: 10-50ns (恰好使比较器跳过)
  4. CPU跳过安全检查 → 执行未签名固件

  ChipWhisperer配置:
    scope.glitch.clk_src = 'target'
    scope.glitch.offset = 31234   # 精确时钟偏移
    scope.glitch.width = 15        # 毛刺宽度(个时钟周期)
    scope.glitch.repeat = 1
    scope.glitch.trigger_src = 'manual'
```

### 8.3 硬件逆向工具全景

| 工具 | 类型 | 功能 |
|---|---|---|
| ChipWhisperer | 开源 | 侧信道分析+故障注入平台 |
| lascar (Ledger Donjon) | 开源 | 侧信道分析库 |
| Riscure Inspector | 商用 | 专业侧信道分析 |
| JTAGulator | 开源硬件 | 发现和识别JTAG接口 |
| Glasgow Interface Explorer | 开源硬件 | 多协议硬件接口 |
| Saleae Logic Analyzer | 商用 | 逻辑分析(协议嗅探) |

### 8.4 防御技术(逆向工程对抗)

```c
// 常量时间内存比较 — 防止时序侧信道
uint8_t secure_memcmp_constant_time(const uint8_t *a, const uint8_t *b, size_t length) {
    uint8_t result = 0;
    for (size_t i = 0; i < length; i++) {
        result |= (a[i] ^ b[i]);
    }
    return result;  // 0=匹配, 非0=不匹配
}
```

**动态引脚复用** — 不仅依赖eFuse禁用JTAG(glitch有时可绕过eFuse)，而是在启动时立即将SWD/JTAG引脚复用为关键高频IO功能。如果攻击者试图保持引脚用于调试，设备功能性地自毁。

**主动PCB屏蔽** — 在PCB外层和BGA芯片正下方布设包含高频心跳信号的连续紧密编织走线网格。如果攻击者试图钻孔或切割PCB，网格断裂，心跳停止，MCU立即清零安全密钥库。

**蜜罐函数** — 创建看似加密例程的复杂数学密集型虚拟函数，大量引用 `AES_KEY_GEN_START` 等字符串。攻击者花费数周逆向这些"蜜罐"代码，而实际逻辑在别处以混淆的内联汇编执行。

---

## 9. 2026逆向工程技术矩阵

| 领域 | 核心技术 | 关键工具 | 2026新进展 |
|---|---|---|---|
| AI辅助逆向 | LLM函数分析/重命名/漏洞识别 | GhidrAssist/VulChatGPT/Sidekick | HELIOS层次化图抽象 |
| 移动逆向 | 运行时插桩/Hook/绕过 | Frida/Objection/JADX | OXO编排+AI辅助 |
| 二进制分析 | 符号执行/模糊测试/静态分析 | angr/SysFuSS/Bangr | AI认知引擎突破不可能三角 |
| 固件逆向 | 调试端口/Flash转储/SPI嗅探 | OpenOCD/CH341A/binwalk | 调试复活glitch技术 |
| 反混淆 | 控制流反平坦化/MBA简化 | Squanchy/SiMBA++/wasm2c | LLVM工具链系统化反混淆 |
| WASM逆向 | 二进制提取/符号执行 | WABT/SeeWasm/wasm2c | 反机器人平台完整逆向 |
| 加密协议 | 形式化验证/侧信道分析 | CryptoLyzer/CryptoBap/Tamarin | 二进制提取形式化模型(CCS 2026) |
| 硬件逆向 | DPA/电压毛刺/EM分析 | ChipWhisperer/lascar | WhatsApp侧信道社交图谱推断 |

---

## 10. 测试检查清单

```
AI辅助逆向 (§1)
□ 安装GhidrAssist/GEPETTO/VulChatGPT到Ghidra
□ 使用PyGhidra构建自动化分析管道
□ 测试Binary Ninja Sidekick的交互式AI分析
□ 使用BinaryAI进行函数相似性搜索识别库函数
□ 用VulChatGPT自动标记可疑函数进行漏洞分类

移动应用逆向 (§2)
□ 使用JADX反编译APK并搜索硬编码凭据
□ 用Frida Hook Root检测/SSL Pinning/加密函数
□ 使用Objection一键绕过安全控制
□ 分析Native库(.so)中的JNI函数
□ iOS: class-dump导出头文件+Frida Hook Objective-C方法

二进制分析 (§3)
□ 使用angr进行符号执行探索路径
□ 用静态分析增强AFL模糊测试(覆盖率驱动)
□ 识别高风险函数(strcpy/sprintf/system等)及其交叉引用
□ 测试SysFuSS系统级固件模糊测试
□ 用Bangr在Binary Ninja中集成angr符号执行

固件逆向 (§4)
□ 使用binwalk提取固件文件系统
□ 测试SWD/JTAG调试端口是否激活(OpenOCD)
□ 脱焊SPI Flash + CH341A读取固件
□ SPI嗅探捕获固件加载过程(逻辑分析仪)
□ 使用Ghidra分析ARM/MIPS固件二进制

反混淆 (§5)
□ 使用Squanchy反混淆WASM模块
□ 用SiMBA++/GAMBA简化MBA表达式
□ 使用angr进行控制流反平坦化
□ 绕过ptrace反调试(LD_PRELOAD/Frida Hook)
□ 捕获运行时动态AES密钥生成

WASM逆向 (§6)
□ 使用wasm-objdump查看模块节信息
□ wasm2wat转换为可读WAT文本格式
□ wasm2c提升到C进行深入分析
□ 测试SeeWasm符号执行
□ 检查WASM模块是否包含反机器人逻辑

加密协议逆向 (§7)
□ 使用CryptoLyzer分析TLS/SSH配置
□ 检测CVE-2026-3142(OpenSSL HollowByte)
□ 检测CVE-2026-0947(MCP证书链绕过)
□ 使用testssl.sh全面TLS审计
□ 测试后量子密码套件支持(Kyber/Dilithium)

硬件逆向 (§8)
□ 使用ChipWhisperer进行SPA/DPA攻击AES
□ 测试电压毛刺绕过Secure Boot
□ 使用JTAGulator发现JTAG接口
□ 用Saleae逻辑分析仪嗅探UART/SPI通信
□ 验证常量时间比较防御是否正确实现
```

---

## 11. OLLVM 混淆逆向 — 控制流恢复与MBA化简

> **2026核心战场**：OLLVM（Obfuscator-LLVM）及其变体（Arkari/Pluto/Hikari/Goron）是当前最主流的编译级混淆方案。2026年D810-ng持续更新至v0.6.6，AI辅助去混淆成为研究热点（BinDeObfBench基准发布），同时混淆器主动对抗去混淆工具（Pluto的Trap Angr）。

### 11.1 OLLVM 三大混淆技术原理

| 混淆技术 | 标识 | 原理 | 复杂度倍增 |
|----------|------|------|------------|
| **控制流平坦化 (FLA/CFF)** | `-mllvm -fla` | 将自然分支结构拆解为中央调度器(switch-case/if-chain状态机)路由 | 与BCF组合时x86放大4.18倍，ARM放大5.50倍 |
| **虚假控制流 (BCF)** | `-mllvm -bcf` | 插入不透明谓词(`x*(x+1)%2==0`)恒真条件分支+不可达代码 | 单独使用增加30-50%代码量 |
| **指令替换 (SUB)** | `-mllvm -sub` | 将标准算术替换为MBA表达式(`a+b → (a^b)+2*(a&b)`) | 增加指令数3-5倍 |

### 11.2 控制流平坦化去混淆

#### 方法A: 符号执行去平坦化（deflat.py / angr）

```bash
# deflat.py — 基于angr的经典去平坦化工具
# 原理: 识别调度器基本块→对每个真实基本块符号执行→求解状态变量→重建控制流
python3 deflat.py -f target_x8664_flat --addr 0x400530

# debogus.py — 移除虚假控制流
# 原理: 将不透明谓词x*(x+1)%2替换为0→恒真条件自动成立→移除假分支
python3 debogus.py -f target_x86_bogus --addr 0x80483e0

# 批量处理多函数
python3 multi.py -f target_binary --function-list funcs.txt
```

```python
# deflat.py 核心原理实现
import angr

proj = angr.Project("obfuscated.bin", auto_load_libs=False)
cfg = proj.analyses.CFGFast()

# 步骤1: 识别调度器基本块(大量条件跳转的目标)
for func in cfg.functions.values():
    if func.block_count < 50:
        continue  # 平坦化后基本块数量激增
    
    # 查找主调度器: switch-case分发模式
    dispatcher_block = None
    for block in func.blocks:
        # 调度器特征: 大量条件跳转目标
        targets = block.vex.constant_jump_targets
        if len(targets) > 10:
            dispatcher_block = block
            break
    
    if not dispatcher_block:
        continue
    
    # 步骤2: 识别状态变量(调度器比较的变量)
    state_var = identify_state_variable(dispatcher_block)
    
    # 步骤3: 对每个真实基本块执行符号执行
    real_blocks = identify_real_blocks(func, dispatcher_block)
    for rb in real_blocks:
        # 求解: 从入口到该基本块的状态变量值
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=rb.addr)
        
        if simgr.found:
            found_state = simgr.found[0]
            state_value = found_state.solver.eval(state_var)
            
            # 步骤4: 确定该基本块的后继
            successors = list(found_state.step().successors)
            for succ in successors:
                next_state = succ.solver.eval(state_var)
                # patch: 在基本块末尾直接跳转到后继(跳过调度器)
                patch_jump(rb.addr, next_block_addr)
```

#### 方法B: Miasm符号执行去平坦化（ollvm-unflattener v2.0）

```bash
# ollvm-unflattener — 基于Miasm的去平坦化(2025年v2.0)
# 支持Windows/Linux x86/x64，可生成去混淆后的可执行文件

# 单函数去混淆
python unflattener -i ./CFF.bin -o ./deob_CFF.bin -t 0x80491A0

# 跟踪所有调用进行递归去混淆(BFS遍历调用图)
python unflattener -i ./CFF_full.bin -o ./deob_CFF_full.bin -t 0x8049E00 -a

# 依赖: miasm, graphviz, keystone-engine
pip install miasm graphviz keystone-engine
```

#### 方法C: IDA Microcode去平坦化（D810-ng v0.6.6）

```python
# D810-ng配置: 专门针对OLLVM的去平坦化规则
# 配置文件: default_unflattening_ollvm.json

# D810-ng反平坦化器矩阵:
# ┌──────────────────────────┬──────────────┬──────────────────────────────┐
# │ 反平坦化器               │ 目标混淆器    │ 描述                          │
# ├──────────────────────────┼──────────────┼──────────────────────────────┤
# │ Unflattener              │ O-LLVM       │ switch/if-chain调度器+状态变量│
# │ UnflattenerSwitchCase    │ Tigress      │ Tigress m_jtbl调度器          │
# │ UnflattenerTigressIndirect│ Tigress     │ Tigress m_ijmp间接跳转         │
# │ HodurUnflattener         │ Hodur(PlugX) │ 嵌套while(1)状态机            │
# │ BadWhileLoop             │ Approov      │ while(v8!=C)状态常量0xF6xxx   │
# │ UnflattenControlFlowRule │ 通用(实验性) │ 基于路径模拟的CFG去平坦化     │
# └──────────────────────────┴──────────────┴──────────────────────────────┘

# 安装D810-ng
# pip3 install d810-ng[speedups]
# python -m d810.speedups.install
# 仅支持IDA v9+ 和 Python 3.10+
```

### 11.3 MBA表达式化简去混淆

#### D810-ng MBA规则系统

```python
# D810-ng DSL规则定义: MBA表达式化简
from d810.mba.dsl import Var
from d810.mba.rules import VerifiableRule

x, y = Var("x_0"), Var("x_1")

# OLLVM指令替换模式化简
class Add_OllvmRule_1(VerifiableRule):
    PATTERN = (x ^ y) + 2 * (x & y)       # OLLVM的a+b混淆形式
    REPLACEMENT = x + y
    DESCRIPTION = "Simplify OLLVM add substitution"

class Xor_HackersDelightRule_1(VerifiableRule):
    PATTERN = (x | y) - (x & y)           # Hacker's Delight恒等式
    REPLACEMENT = x ^ y
    DESCRIPTION = "Simplify (x|y)-(x&y) to x^y"

# Z3自动验证规则等价性
# verify_rule()通过Z3证明PATTERN和REPLACEMENT等价
# 如果验证失败，Z3返回反例
# 支持Z3和egglog双后端
```

#### MBA化简模式速查表

```
# OLLVM常见MBA变换及其化简:

加法:  a + b
  → (a ^ b) + 2 * (a & y)          [OLLVM标准]
  → 2 * (a | b) - (a ^ b)          [Hacker's Delight]
  → (a & b) + (a | b)              [Hacker's Delight]
  → -(-a - b)                      [双重取反]

减法:  a - b
  → (a ^ b) - 2 * (~a & b)         [OLLVM变体]
  → 2 * (a & ~b) - (a ^ b)         [Hacker's Delight]

异或:  a ^ b
  → (a | y) - (a & b)              [Hacker's Delight]
  → (a + b) - 2 * (a & b)          [OLLVM变体]
  → (~a & b) | (a & ~b)            [布尔展开]

与:    a & b
  → (a + b - (a | b))              [算术等价]
  → ~(~a | ~b)                     [德摩根]

或:    a | b
  → (a & b) + (a ^ b)              [分解]
  → ~(~a & ~b)                     [德摩根]
```

#### SiMBA++ + ML混合去混淆

```python
# 2026: ML辅助MBA模式识别
from sympy import symbols, simplify
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# 步骤1: 从二进制提取MBA表达式
mba_expressions = extract_mba_from_binary("obfuscated.bin")

# 步骤2: ML分类器识别MBA模式
# 训练数据: 已知MBA变换的AST特征
clf = RandomForestClassifier(n_estimators=100)
clf.load("mba_pattern_model.pkl")  # 预训练模型

for expr in mba_expressions:
    features = extract_ast_features(expr)
    pattern_type = clf.predict([features])[0]
    
    # 步骤3: SiMBA++符号化简
    simplified = simba_simplify(expr, pattern_type)
    print(f"原始: {expr}")
    print(f"化简: {simplified}")

# 步骤4: Z3验证化简正确性
from z3 import *
for expr, simplified in zip(mba_expressions, simplified_exprs):
    x, y = BitVecs('x y', 32)
    s = Solver()
    s.add(expr != simplified)
    if s.check() == unsat:
        print("[+] 验证通过: 表达式等价")
    else:
        print("[-] 验证失败: 表达式不等价!")
```

### 11.4 OLLVM变体识别与对抗

```
2026年活跃OLLVM变体:

1. Arkari (LLVM 22.x, 2026年6月最新):
   ├── 基于Goron改进，最活跃的OLLVM变体
   ├── 间接跳转加密: -mllvm -irobf-indbr
   ├── 间接函数调用加密: -mllvm -irobf-icall
   ├── 间接全局变量引用加密: -mllvm -irobf-indgv
   ├── C字符串加密: -mllvm -irobf-cse
   ├── 整数常量加密: -mllvm -irobf-cie
   ├── 浮点常量加密: -mllvm -irobf-cfe
   └── 配置文件: -mllvm -arkari-cfg="path"

2. Pluto-Obfuscator (LLVM 12.0.1):
   ├── 增强型控制流平坦化: -mllvm -fla-ex (强烈推荐)
   ├── 全局变量加密: -mllvm -gle (强烈推荐)
   ├── 增强MBA混淆: -mllvm -mba (5系数多项式)
   ├── 随机控制流: -mllvm -rcf
   ├── 变量替换: -mllvm -vsb
   └── Trap Angr: -mllvm -trap-angr (★专门对抗angr符号执行)

3. Hikari (OLLVM扩展):
   ├── AntiClassDump: 反类转储
   ├── FunctionCallObfuscate: 函数调用混淆
   ├── FunctionWrapper: 函数包装
   ├── IndirectBranching: 间接分支
   └── StringEncryption: 字符串加密

4. 推荐组合(Pluto FullProtection):
   ./clang++ -mllvm -mba -mllvm -mba-prob=50 \
              -mllvm -fla-ex -mllvm -gle test.cpp -o test

对抗Trap Angr的策略:
  ├── 约束简化: 自定义angr exploration策略
  ├── 钩子函数: 自定义syscall/库函数行为
  ├── 路径剪枝: 提前剪枝不可达路径
  ├── 混合方法: 符号执行+具体执行混合
  └── 动态绕过: 运行时检测并patch陷阱指令
```

### 11.5 AI/LLM辅助OLLVM去混淆

```python
# 2026: BinDeObfBench基准测试发现
# 推理模型(DeepSeek-R1)在Level-6混淆下保持62.89%语义保真度
# 标准模型(ChatDEOB)仅58.30%，ReCopilot仅54.62%

# AI去混淆工作流
def ai_deobfuscate(decompiled_code, obfuscation_level):
    """LLM辅助去混淆"""
    
    # 步骤1: 混淆类型识别(ALMOND零样本检测)
    obfuscation_type = almnd_detect(decompiled_code)
    # 支持检测: OLLVM/Hikari/Tigress/Pluto
    
    # 步骤2: 分阶段去混淆
    # 阶段A: MBA化简(交给D810-ng/Z3)
    simplified = d810_simplify(decompiled_code)
    
    # 阶段B: 控制流恢复(交给deflat.py/angr)
    de flattened = deflat(simplified)
    
    # 阶段C: LLM语义恢复
    prompt = f"""
    以下代码经过OLLVM混淆(FLA+BCF+SUB, Level {obfuscation_level})，
    已经过D810和deflat预处理。请恢复原始代码逻辑:
    1. 识别并移除残留的不透明谓词
    2. 恢复原始变量名和函数名
    3. 简化冗余逻辑
    4. 重建可读的控制流结构
    
    预处理后的代码:
    {de_flattened}
    """
    recovered = llm_analyze(prompt)
    
    # 步骤3: 验证语义等价性
    is_equivalent = z3_verify_equivalence(decompiled_code, recovered)
    
    return recovered if is_equivalent else None

# 关键发现(2026 Promon报告):
# - 三重混淆(SUB+FLA+BCF)下x86最佳AI成功率20-36%，ARM仅8.5%
# - 反编译器质量影响巨大: Claude Opus 4.5从伪代码50% vs 从汇编24%
# - AI在干净代码上也有内置错误率: 无模型超过86%
# - 顶级模型(Claude 4.5/DeepSeek/Gemini 3)即使在最大混淆下仍有意义
```

---

## 12. UPX 脱壳与反脱壳对抗

> **2026 UPX 5.x新特性**：`memfd_create`支持SELinux Enforcing模式、`--unmap-all-pages`避免依赖`/proc/self/exe`、两步解压缩、RISC-V 64位支持(5.1.0)。攻击者通过修改UPX头部规避`upx -d`，需要多层脱壳策略。

### 12.1 标准UPX脱壳

```bash
# 标准UPX脱壳(格式公开可逆)
upx -d packed_binary.exe -o unpacked.exe

# UPX使用NRV2B/NRV2D/NRV2E或LZMA算法
# 压缩数据存储在UPX0/UPX1节中，解压器算法固定

# 批量脱壳
for f in samples/*.exe; do
    upx -d "$f" -o "${f%.exe}_unpacked.exe" 2>/dev/null
done

# ELF UPX脱壳
upx -d packed_elf -o unpacked_elf
```

### 12.2 修改UPX检测与修复

```
攻击者常见UPX头部篡改手法:
  1. 清空/修改AddressOfEntryPoint → 设为0，破坏静态分析
  2. 修改节名 → UPX0/UPX1重命名为随机字符串
  3. 修改UPX!魔术标记 → upx -d报错"file is modified/hacked/currupt"
  4. 修改校验和与版本字段 → 标准upx -d拒绝解压

检测修改UPX的方法:
  ┌─────────────────────────────────────────────────────┐
  │ 1. DIE(Detect It Easy)扫描                          │
  │    diec -a sample.exe                               │
  │    输出: UPX / 未知(被修改)                          │
  │                                                     │
  │ 2. 熵分析(pescanner.py)                             │
  │    节熵 >7.0 → 压缩/加密                            │
  │    原生x86代码熵值: 5.5-6.5                         │
  │                                                     │
  │ 3. UPX!标记计数验证                                 │
  │    PE/ELF要求 ≥ 2个UPX!标记(对应UPX0/UPX1)          │
  │   少于2个 → 被篡改                                  │
  │                                                     │
  │ 4. 节名模式检查                                      │
  │    搜索UPX0/UPX1或变体(如UPX., .UPX, 随机6字符)    │
  └─────────────────────────────────────────────────────┘

修复被修改UPX的步骤:
  1. 用010 Editor打开，定位UPX!标记位置
  2. 恢复被篡改的UPX!标记(搜索0x55505821)
  3. 恢复节名为UPX0/UPX1
  4. 恢复AddressOfEntryPoint到UPX1节内
  5. 再次执行 upx -d
```

### 12.3 动态脱壳 — OEP定位与内存转储

```python
# UPX动态脱壳: 当upx -d失败时的递进策略
# 工具: x64dbg + Scylla

"""
动态脱壳流程:
  1. x64dbg加载样本(不要运行)
  2. 在VirtualAlloc/VirtualProtect上下断点
     → UPX stub分配内存解压时会调用这些API
  3. 运行到断点后，在.text节下内存执行断点(hardware breakpoint on execution)
  4. 继续运行，当执行跳转到解压后代码时即到达OEP
  5. 用Scylla/OllyDumpEx dump内存
  6. Scylla重建IAT:
     a. IAT Autosearch → 自动搜索IAT位置
     b. Get Imports → 获取导入表
     c. Fix Dump → 指向dump文件，生成_SCY后缀修复文件
"""

# 模拟执行脱壳(Unipacker — 基于Unicorn)
# pip install unipacker
from unipacker.api import UnipackerAPI

# 自动脱壳: 模拟执行→检测解压完成→dump内存
api = UnipackerAPI("packed.exe")
api.unpack()  # 自动检测section hop或W+X转移
# Unipacker dump触发条件:
# 1. Section hop: 执行跳转到运行时写入的不同节
# 2. Write+Execute: 运行时写入区域变为可执行且执行进入
# 3. 壳特定逻辑(ASPack内置)

# Qiling脱壳(支持64位，Unipacker不支持PE32+)
from qiling import Qiling

ql = Qiling(["packed.exe"], rootfs="x8664_windows")
ql.run(timeout=180)  # 超时后从基址dump
# 从镜像基址dump SizeOfImage大小内存
# 注意: IAT未修复，需后续Scylla处理
```

### 12.4 UPX 5.x新特性对抗

```
UPX 5.x关键对抗机制:

1. memfd_create + SELinux兼容 (5.0.0):
   ├── 解压不写临时文件到磁盘，使用匿名内存文件
   ├── 基于文件系统监控的脱壳沙箱看不到中间产物
   └── 对抗: 内存dump(进程内存中直接提取)

2. --unmap-all-pages:
   ├── 完全避免读取/proc/self/exe
   └── 对抗: 监控/proc/self/mem或使用ptrace附加

3. 两步解压缩:
   ├── 解压流程拆分，per-PT_LOAD段独立处理
   └── 对抗: 更耐心的OEP等待+多次内存断点

4. RISC-V 64位支持 (5.1.0):
   ├── 新增linux/riscv64格式
   └── 对抗: 使用QEMU user-mode模拟RISC-V环境

5. MIPS r3000共享库 (5.1.1):
   └── 对抗: QEMU MIPS模拟环境
```

---

## 13. 商业壳逆向 — VMP/Themida/Enigma

### 13.1 壳识别与难度分级

```bash
# Detect It Easy (DIE) — 当前最主流壳识别工具
# GitHub 10,200+ stars, 支持400+ packers
diec -a packed.exe

# 输出示例:
# VMProtect 3.x
# Themida 2.x
# Enigma Protector
# ASPack 2.x
# MPRESS
# NSPack
# PECompact
```

| 壳 | 难度 | 脱壳技术 | 自动化可行性 |
|----|------|----------|--------------|
| **UPX** | 简单 | `upx -d` 或 OEP+dump | 完全自动化 |
| **MPRESS** | 容易 | OEP+dump+IAT修复 | CAPE自动化 |
| **ASPack** | 中等 | 模拟+dump(Unipacker内置) | Unipacker自动化 |
| **Themida** | 困难 | VM分析+dump，LZSS算法识别 | 部分(模拟启发式) |
| **VMProtect** | 专家级 | VM字节码分析 | 困难(64位需Qiling超时dump) |
| **Enigma** | 困难 | 迭代脱壳(常与.NET混淆层叠) | 部分 |

### 13.2 VMProtect 3.6逆向

```
VMProtect 3.6 (2026)核心机制:
  ├── 完整代码虚拟化: 原始代码→自定义VM字节码
  ├── 滚动密钥寄存器(VKEY): 每条操作码用唯一密钥解密
  │   └── handler1用EDI中的密钥解密opcode1
  │       → 密钥经唯一变异 → handler2解密opcode2 → ...
  ├── 纯静态分析无法解密操作码流(必须动态执行)
  └── 64位: 需Qiling+Windows rootfs超时dump

VMP脱壳策略:
  32位:
  ├── Unipacker(Unicorn模拟) + section hop/W+X启发式dump
  └── 工具: Oreans UnVirtualizer(稳定性差但可完整还原)
  
  64位:
  ├── Qiling + Windows rootfs
  ├── ql.run(timeout=...) → 从基址dump SizeOfImage
  └── IAT未修复 → 需Scylla后续处理

  学术方法:
  └── DevMP: 虚拟指令提取(ACM 2026)
      ├── 自动提取VM handler语义
      ├── 重建原始控制流
      └── 适用于商业代码虚拟化混淆器
```

### 13.3 Themida逆向

```python
# Themida脱壳三步法
"""
Themida核心机制:
  - LZSS压缩 + 控制流平坦化(CFF)
  - 中央dispatcher替换自然控制结构
  - 状态变量选择下一个执行块

脱壳步骤:
  1. DIE确认壳 → 010 Editor查看EP数据 → 确定加密数据
  2. x64dbg断在EP → 反汇编解压代码 → 识别LZSS算法
     - LZSS特征: 滑动窗口+look-ahead buffer
     - 搜索LZSS解压循环模式
  3. 跟踪到OEP → dump + IAT修复(Scylla)

关键: 不运行程序直接解Themida加密代码段
  - 定位LZSS解压例程
  - 离线执行解压(无需在调试器中运行完整壳)
  - 适用于: 已知LZSS算法参数的情况
"""
```

### 13.4 多层壳迭代脱壳

```python
# 多层壳脱壳流水线(2026: anpa1200/Unpacker)
# pip install 1200km-unpacker

# 一条命令完成 detect → unpack → validate
# unpacker /path/to/sample.exe -o ./unpacked --timeout 180

# 典型三层壳结构:
# 商业crypter(MaaS) → 中间loader → 内部packer → 最终payload

# 脱壳器调度策略:
unpacker_dispatch = {
    'UPX': 'native_unpack',        # upx -d, 无模拟
    'ASPack': 'unipacker',          # Unicorn模拟从EP运行
    'Themida_32': 'unipacker',      # 模拟+启发式dump
    'VMProtect_32': 'unipacker',    # 模拟+启发式dump  
    'VMProtect_64': 'qiling',       # Qiling+rootfs, 超时dump
    'MPRESS': 'stub',               # 检测但未实现
    'Enigma': 'manual',             # 手动x64dbg+de4dot
    'unknown': 'qiling_generic',    # 通用Qiling模拟
}

# orcastor/unpack (Go库) — 多层递归脱壳
# unpack unpack -depth 10 packed.exe
# 自动检测每一层壳类型，逐层脱壳
# 支持层叠: ASPack → UPX，从外向内逐层剥离
```

### 13.5 反调试与反虚拟机对抗

```python
# 2026壳的反DBI(动态二进制插桩)检测

# 1. Frida检测绕过
# 壳检测: 内存扫描frida-agent.so、/data/local/tmp文件、库完整性校验
# 绕过:
Interceptor.attach(Module.findExportByName(null, 'fopen'), {
    onLeave: function(retval) {
        // 隐藏/proc/self/maps中的frida相关条目
    }
});

# 2. 反虚拟机检测绕过
anti_vm_checks = {
    '注册表': 'HKLM\\SOFTWARE\\VMware等hypervisor键',
    '虚拟驱动': 'vmhgfs.sys, VBoxGuest.sys文件存在性',
    '集成进程': 'vmtoolsd.exe, VBoxService.exe进程存在',
    'CPUID': '返回hypervisor名称到EBX/ECX/EDX',
    'I/O端口': 'VMware通信通道I/O端口0x5658',
}

# 模拟器(Unicorn/Qiling)不暴露真实hypervisor特征
# → 可绕过CPUID检测
# → 但复杂系统交互模拟不完整

# 3. 2026新兴对抗技术
emerging_anti_analysis = {
    '滚动XOR/AES-128-CTR字符串混淆': '字符串动态解密，静态不可见',
    '加盐SHA-1 API解析': '不使用标准IAT，哈希动态解析API',
    'Local Hollowing + AES': '自注入hollowing，永不写盘(RedSun技术)',
    'AMSI Ghosting': '绕过AMSI检测机制',
}
```

### 13.6 内存转储与IAT重建

```
脱壳后内存转储工具链:

  ┌──────────────────────────────────────────────────────┐
  │                    脱壳后处理                          │
  ├───────────────┬──────────────────────────────────────┤
  │   内存Dump     │  IAT重建                              │
  ├───────────────┼──────────────────────────────────────┤
  │ Scylla        │ Scylla (标准)                        │
  │ OllyDumpEx    │  - IAT Autosearch                    │
  │ PE-sieve      │  - Get Imports                       │
  │ hollows_hunter│  - Fix Dump → _SCY文件               │
  │ revdump       │ revdump (对齐dump+IAT重建)           │
  │               │ ImpREC (异常计数法)                   │
  └───────────────┴──────────────────────────────────────┘

验证脱壳成功:
  1. Ghidra/IDA中正确识别函数和字符串
  2. 熵值降低(如ASPack案例: 6.25→2.38, 文件33KB→176KB)
  3. 沙箱执行验证行为一致性
  4. 比较动态API调用与重建IAT导入
```

---

## 14. 压缩逆向 — gzip/LZMA/Zstd/LZ4

> **2026关键发现**：安全工具对GZip/zlib检测覆盖全面，但对Zstandard/LZ4/LZString/Brotli几乎"零检测覆盖"。攻击者从GZip切换到Zstd即可获得对所有依赖魔数检测工具的即时规避（KlaroSkope 2026年2月研究）。

### 14.1 压缩格式魔数速查表

| 格式 | 魔数字节 | 熵值范围 | 安全工具检测覆盖 | 关键结构特征 |
|------|---------|----------|-----------------|----------

---

## 15. .NET 反混淆与脱壳 — ConfuserEx/Eazfuscator/dnGuard/.NET Reactor

### 15.1 .NET 混淆技术全景

.NET 因元数据丰富、IL 字节码易反编译,成为混淆保护重灾区。主流混淆技术:

- **符号重命名**:将类/方法/字段名替换为零宽字符或 `a`/`b`。ConfuserEx 支持可重用名(Reusable)与不可重用名(Non-Reusable),后者逆向更难。
- **控制流混淆**:线性 IL 转为状态机或跳转表,插入垃圾指令。ConfuserEx 用 switch 扁平化,Eazfuscator.NET 用不可约循环。
- **字符串加密**:明文字符串替换为 `decryptor(int token)` 调用,运行时反射还原。ConfuserEx 用 XOR/AES,密钥与 MethodDef token 绑定。
- **防篡改/防调试**:ConfuserEx 的 Anti-Tamper 通过 MD5 校验方法体完整性;Anti-Debug 调用 `IsDebuggerPresent`、检测 `PEB.BeingDebugged`。
- **代码虚拟化**:.NET Reactor 的 Necrobit/JEOPARDY 将方法体替换为 native stub + 自定义 VM 指令,由 native 解释器执行。
- **元数据损坏**:破坏 `#Strings`/`#US` 堆偏移,使 dnSpy/ILSpy 反编译失败但 CLR 仍能加载(dnlib 需设 `MetadataFlags` 修复)。

2026 年趋势:.NET 8/9 的 NativeAOT 将 IL 直接编译为原生机器码,产出不含元数据的本地可执行,传统 dnSpy/ILSpy 完全失效,需 IDA Pro/Ghidra 配合调用约定推断。但 AOT 不支持运行时反射,商业软件仍以 CoreCLR + 混淆为主流。

| 保护器 | 符号重命名 | 控制流混淆 | 字符串加密 | 防篡改 | 代码虚拟化 | 元数据损坏 | 典型特征 |
|--------|-----------|-----------|-----------|--------|-----------|-----------|----------|
| **ConfuserEx 2.0** | 强(Unicode) | switch 扁平化 | XOR+token | MD5 校验 | 否 | 否 | 开源、`[ConfuserEx]` 属性 |
| **Eazfuscator.NET** | 强 | 不可约循环 | AES | 弱 | 否 | 否 | 商业、配置简洁 |
| **.NET Reactor** | 中 | 中 | 强 | 强 | Necrobit/JEOPARDY | 是 | license.rptc |
| **dnGuard** | 中 | 中 | 中 | 强 | native VM | 是 | native wrapper |
| **Babel.NET** | 强 | switch | XOR | 强 | 否 | 部分 | 商业 |
| **SmartAssembly** | 中 | 中 | XOR | 强 | 否 | 否 | Red Gate |

### 15.2 ConfuserEx 逆向

**de4dot 通用反混淆器**是 .NET 逆向标准起点,内置 30+ 种保护器特征识别,自动还原符号、解密字符串、简化控制流:

```bash
de4dot target.exe                  # 自动检测保护器类型,输出 target-cleaned.exe
de4dot -p confuserex target.exe    # 手动指定类型:confuser/eazfuscator/reactor/smartassembly
de4dot --symbolmap map.xml target.exe   # 生成符号映射文件,便于交叉引用
```

**字符串解密**有两条路径:de4dot 内联模拟(拷贝解密方法体模拟执行)与基于 dnlib 的手动提取(适用于 de4dot 未识别的自定义解密器):

```csharp
// dnlib 字符串解密示例:定位解密方法并内联还原
using dnlib.DotNet;
using dnlib.DotNet.Emit;

var module = ModuleDefMD.Load("target.exe",
    new ModuleCreationOptions { MetadataOptions = new MetadataOptions(false) });

// 标记疑似解密方法(特征:静态、接收 int token、返回 string)
var decryptors = module.Types.SelectMany(t => t.Methods)
    .Where(m => m.IsStatic && m.MethodSig.RetType.FullName == "System.String"
        && m.Parameters.Count == 1 && m.Parameters[0].Type.FullName == "System.Int32")
    .ToList();

foreach (var type in module.Types)
    foreach (var method in type.Methods)
        if (method.HasBody)
            foreach (var instr in method.Body.Instructions)
                if (instr.OpCode == OpCodes.Call && decryptors.Contains(instr.Operand))
                {
                    var prev = instr.Previous;
                    if (prev?.OpCode == OpCodes.Ldc_I4)
                    {
                        int token = prev.GetLdcI4Value();
                        string plain = InvokeDecryptor(instr.Operand as MethodDef, token);
                        instr.OpCode = OpCodes.Ldstr;   // 替换为明文 ldstr
                        instr.Operand = plain;
                        prev.OpCode = OpCodes.Nop;
                    }
                }
module.Write("target-decrypted.exe", new ModuleWriterOptions(module) { WritePdb = true });
```

**控制流反混淆**:ConfuserEx 的 switch 扁平化可被 de4dot 模式匹配还原(识别 `switch(num)` + 数字映射表)。**Anti-Tamper 绕过**:de4dot `--keep-types` 移除 anti-tamper 模块,或手动 patch `ModuleInitializer` 跳过校验调用。

### 15.3 .NET Reactor 代码虚拟化对抗

.NET Reactor 的 **Necrobit** 将方法体替换为 native stub,真实 IL 加密存储在资源段,运行时由 native 代码解密并交予 JIT。标准反编译器只看到空壳。

对抗路径:
1. **Reactor Slayer / devirtualizer**:开源工具针对早期版本,定位加密资源并调用内置解密器还原 IL;对 Reactor 7.x+ 效果有限。
2. **内存 dump 法**:在 dnSpy 调试器中运行,在目标方法首次被调用后(IL 已解密并交给 JIT),于 `clr.dll!compileMethod` 下断点,dump `CORINFO_METHOD_INFO` 中 ILCode 指针指向的内存。
3. **JEOPARDY 绕过**:JEOPARDY 将 IL 转为自定义虚拟指令集,需逆向解释器逻辑,建立虚拟 opcode 到 CIL 的映射表(类似 VMProtect 脚本分析),可借助 ReactorDeobfuscator 结合动态 trace。

Reactor 版本识别要点:`.rsrc` 节含 `RT_RCDATA` 资源名为 `ReactOr` 或数字 ID;导入表含 `mscoree.dll` 的 `_CorExeMain`;license 文件 `license.rptc` 可用于版本判定。对 Reactor 9.x+ 的 Necrobit,需在 `clr!JIT_MethodBarrierComp` 回调后 dump,此时 IL 已解密。

### 15.4 dnGuard 与 x64 native 保护

**dnGuard** 将整个 .NET 程序集封装在 native loader 中(EXE 入口为机器码),运行时解密并加载到内存,CLR 通过 hosting API 启动。程序集仅在内存中以明文存在短暂时间。

对抗核心:Hook `mscorlib` 的 JIT 编译入口拦截 IL 编译,从而拿到所有方法的明文 IL:
- **Hook mscorjit.dll!compileMethod**:JIT 编译每个方法时,`ICorJitCompiler::compileMethod` 接收 IL,在此处 dump 即可获取全部 IL。
- **MegaDumper / extremeDumper / Process Hacker**:运行后扫描内存 `.NET MetaData` magic(PE 头 + `BSJB` 元数据签名),dump 出完整 assembly,再修复 PE 头与元数据偏移。

```bash
extremeDumper.exe          # GUI,选目标进程右键 dump .NET modules
MegaDumper.exe /dump:pid=1234 /out:C:\dumps
MetaFix.exe dumped.dll     # 修复 dump 后损坏的元数据偏移
```

### 15.5 实战脱壳工作流

| 步骤 | 任务 | 工具 | 关键技巧 |
|------|------|------|----------|
| 1 | 识别保护器 | Detect It Easy、PEiD | 检查 PE 节名、字符串特征、导入表 |
| 2 | 选择工具 | 依据 15.1 表格 | ConfuserEx→de4dot;Reactor→Reactor Slayer;dnGuard→MegaDumper |
| 3 | 静态反混淆 | de4dot、ConfuserEx.Protections | `de4dot -p` 指定类型,生成 cleaned 文件 |
| 4 | 动态 dump | dnSpy 调试器、MegaDumper | 在 `compileMethod` 断点或内存扫描 BSJB |
| 5 | IL 修复 | MetaFix、dnlib | 修复元数据偏移、还原 `#Strings`/`#US` 堆 |
| 6 | 反编译 | dnSpy、ILSpy、dotPeek | dnSpy 支持调试与编辑;ILSpy 命令行批量 |
| 7 | 还原符号 | de4dot symbolmap、手动 | 利用字符串引用、调用图辅助命名 |

---

## 16. Java/Android 加固脱壳 — ProGuard/Allatori/360加固/腾讯乐固/爱加密

### 16.1 Java 字节码混淆技术

Java 字节码与 Android DEX 同样富含元数据,反编译极易还原源码,混淆与加固成为标配:

- **ProGuard**:Oracle 系开源混淆器,提供 shrink(压缩)、optimization(优化)、obfuscation(重命名为 `a`/`b`/`c`)、preverification(预校验 StackMapTable)。不加密字符串、不做控制流混淆,是最基础的保护层。
- **Allatori**:商业混淆器,增加字符串加密(XOR)、控制流混淆(假分支)、水印(类名/字段名嵌入版权)。解密器特征明显(静态方法 + int 参数)。
- **Zelix KlassMaster (ZKM)**:业界最强 Java 混淆器,支持控制流扁平化(方法体转 switch 状态机)、字符串加密(多重 XOR + 变换)、引用混淆(改变类继承结构),使 CFR/Procyon 反编译输出大量 `goto`。

| 混淆器 | 重命名 | 控制流 | 字符串加密 | 水印 | 成本 |
|--------|--------|--------|-----------|------|------|
| **ProGuard** | 强 | 否 | 否 | 否 | 免费 |
| **Allatori** | 强 | 弱 | XOR | 是 | 商业 |
| **Zelix KlassMaster** | 强 | 强(扁平化) | 多重 | 是 | 商业 |
| **DashO** | 强 | 中 | AES | 是 | 商业 |

### 16.2 国产 Android 加固壳全景(2026)

国产加固占据国内 90% 以上市场,技术从 DEX 整体加密发展到函数抽取、VMP 虚拟化:

| 加固壳 | 厂商 | 特征文件 | 核心技术 | 脱壳难度 | 主流脱壳工具 |
|--------|------|---------|---------|----------|------------|
| **360加固** | 奇虎 | `libjiagu.so` | DEX 整体加密 + 函数抽取 | 中 | BlackDex、FART、Youpk |
| **腾讯乐固** | 腾讯 | `libshell.so` | DEX 函数抽取(指令抽取) | 中 | BlackDex、FartAttack |
| **爱加密** | 爱加密 | `libijmdata.so` | DEX 加密 + SO VMP | 中高 | BlackDex、frida-dexdump |
| **百度加固** | 百度 | `libbaiduprotect.so` | DEX 加密 + 反调试 | 中 | BlackDex、FART |
| **阿里聚安全** | 阿里 | `libsgmainso-6.0.x.so` | DEX 加密 + SO 加固 | 中高 | Youpk、frida-dexdump |
| **梆梆安全/Bangcle** | 梆梆 | `libsecexe.so` | DEX 整体加密 + **VMP 虚拟化** | 高 | Youpk、定制 ROM |
| **娜迦/Nagain** | 娜迦 | `libnagain.so` | DEX 加密 + SO 壳 | 中 | BlackDex、FART |

技术分类:**DEX 整体加密**(360/百度/阿里)将 classes.dex 加密存储于 SO 或 assets,运行时解密到内存;**DEX 函数抽取**(腾讯乐固早期)保留 DEX 结构但抽取每个方法的指令体,运行时在 `dvmDexFileOpenPartial` 前还原;**VMP 虚拟化**(梆梆)将关键 Java 方法体替换为 native 解释器调用,Java 层仅留 native 桩。

### 16.3 DEX 脱壳核心技术

**内存 dump 脱壳法**是最通用的方案:DEX 无论怎么加密,最终必须在内存中以明文交给 ART/Dalvik 加载,在 DexFile 构造后从内存 dump 即可。

**Frida DEX dump** 扫描内存中的 DEX magic(`dex\n035\0`)定位并 dump:

```javascript
// frida DexDump 通用脱壳脚本核心(基于 frida-dexdump)
Java.perform(function() {
    var dexFiles = [];
    var dexMagic = '64 65 78 0a 30 33 35 00'; // "dex\n035\0"
    // 遍历所有可读内存区域,搜索 DEX magic
    Process.enumerateRanges('r--').forEach(function(range) {
        try {
            Memory.scanSync(range.base, range.size, dexMagic)
                .forEach(function(match) {
                    // 读取 DEX header 中 file_size(偏移 0x20, 4 字节)
                    var dexSize = match.address.add(0x20).readUInt();
                    if (dexSize > 0 && dexSize < 100 * 1024 * 1024) {
                        var dexData = match.address.readByteArray(dexSize);
                        dexFiles.push({addr: match.address, size: dexSize, data: dexData});
                        console.log('[+] DEX at ' + match.address + ' size=' + dexSize);
                    }
                });
        } catch (e) { /* ignore unreadable */ }
    });
    dexFiles.forEach(function(d, i) {  // 写入文件
        var f = new File('/data/data/' + pkg + '/dump_' + i + '.dex', 'wb');
        f.write(d.data); f.close();
    });
});
```

```bash
frida-dexdump -U -f com.target.app -o ./dump_dir   # 一键脱壳,输出 dump_dir/*.dex
```

- **BlackDex**:免 Root 脱壳工具,通过自身作为独立进程注入目标(利用 `app_process` 重打包),在 ART 加载 DEX 后 dump,适用于无 Root 设备。
- **FART**:基于定制 AOSP ROM,在 `art/method.cc` 的 `Execute` 入口主动调用所有类方法(强制触发指令还原),再 dump 内存中的 DEX。对函数抽取型壳(腾讯乐固)效果极好。
- **Youpk**:基于 Unikboot 的定制 ROM,在 ART 层 hook `DexFile::OpenMemory`,在 DEX 加载且指令还原后 dump,并修复 DEX header 中的 checksum/signature。

### 16.4 VMP 壳对抗

**梆梆 VMP** 将 Java 方法体替换为 native 解释器调用:原 `access_flags` 中 `ACC_NATIVE` 被置位,实际逻辑由 `libsecexe.so` 中的虚拟机执行自定义指令集。

**识别 VMP 化方法**:方法声明非 native 但方法体仅含 native 桩或空指令(`0x0140`);反编译后方法体为单条 `invoke-static` 调用某 native 函数;SO 中存在大段 switch-case 解释器(VM dispatch loop)。

**半自动还原**:Hook native 解释器 `interpret` 入口,记录每条虚拟指令执行前后 ART 虚拟寄存器(vreg)与 PC 变化,建立 `vopcode -> bytecode` 映射表,将解释器 trace 重构为 DEX 指令序列:

```javascript
// Hook 梆梆 VM 解释器入口,trace 虚拟指令
Interceptor.attach(Module.findExportByName('libsecexe.so', 'vm_interpret'), {
    onEnter: function(args) {
        this.pc = args[1].toInt32();  // 虚拟 PC
        console.log('[VM] pc=' + this.pc);
    },
    onLeave: function(retval) { /* 记录 PC 序列,离线分析 */ }
});
```

### 16.5 ProGuard/Allatori 反混淆

**反编译器对比**:CFR 控制流还原能强(支持 Java 8+ lambda);Procyon 泛型还原准确;JD-GUI 速度快但对复杂控制流易出错;Vineflower(Fern 续作)质量稳定。

**字符串解密**:Allatori 的字符串解密器是静态方法(名为 `_m...`),接收 `int` 返回 `String`,定位后可批量反射调用还原,将 `invokestatic` 替换为 `ldc` 明文。

**反映射恢复**:ProGuard 生成 `mapping.txt`(发布时通常删除),可通过 **Soot 框架**分析调用图与字符串引用,结合已知库 API 签名匹配半自动恢复类名。例如混淆类 `a.b.c` 频繁调用 `android.app.Activity` 方法,可推断其继承自 `Activity` 并重命名。

```bash
# CFR 命令行批量反编译
java -jar cfr.jar target.jar --outputdir ./out --comments false
# Procyon 命令行
java -jar procyon-decompiler.jar -jar target.jar -o ./out
# Vineflower(质量较高,支持新语法)
java -jar vineflower.jar target.jar -dout=./out
```

---

## 17. 反调试技术深度对抗 — PEB/VEH/时序/硬件断点/DBI 检测

### 17.1 Windows 反调试技术矩阵

| 技术 | 检测方法 | 绕过方法 |
|------|---------|----------|
| **IsDebuggerPresent** | 读取 `PEB.BeingDebugged`(偏移 0x2) | patch PEB.BeingDebugged=0;ScyllaHide 自动 |
| **CheckRemoteDebuggerPresent** | 调用 `NtQueryInformationProcess(ProcessDebugPort)` | Hook NtQueryInformationProcess 返回 0 |
| **PEB.NtGlobalFlag** | 检测 `FLG_HEAP_ENABLE_TAIL_CHECK \| FLG_HEAP_ENABLE_FREE_CHECK`(0x70) | patch NtGlobalFlag=0 |
| **NtQueryInformationProcess** | `ProcessDebugPort=0x07`、`ProcessDebugFlags=0x1F`、`ProcessDebugObjectHandle=0x1E` | Hook 全部返回清洁值 |
| **DebugActiveProcess 自检** | 对自身 pid 调用,失败=被调试 | Hook 返回失败 |
| **时序检测** | `RDTSC`/`GetTickCount`/`QueryPerformanceCounter` 比较差值 | Hook RDTSC 返回固定差 |
| **硬件断点检测** | `GetThreadContext` 读取 DR0-DR7,非零=被设 HW BP | SetThreadContext 清除 DR0-DR3 |
| **软件断点检测** | 扫描代码段 `0xCC`(INT3)字节 | 使用 HW BP 替代;扫描时动态还原 |
| **父进程检查** | 期望父进程为 `explorer.exe`,非则报调试 | PEB 父 pid 伪造;parent spoofing |
| **NtSetInformationThread** | `HideThreadFromDebugger=0x11` 隐藏线程 | Hook 忽略调用 |
| **NtClose 句柄陷阱** | 传入无效句柄触发 `STATUS_INVALID_HANDLE` | VEH 中处理该异常 |

### 17.2 反反调试技术

**ScyllaHide** 是 x64dbg/OllyDbg 反反调试插件,在目标进程启动时注入并 Hook `ntdll.dll`、`kernelbase.dll` 中的反调试 API:

```ini
# ScyllaHide 配置(x64dbg 启动时自动加载)
[NtQueryInformationProcess] Hook=1
; ProcessDebugPort 返回 0;ProcessDebugFlags 返回 1;ProcessDebugObjectHandle 返回 NULL
[PEB] BeingDebugged=0;NtGlobalFlag=0;HeapFlags=0;HeapForceFlags=0
[NtSetInformationThread] HideThreadFromDebugger=0   ; 忽略线程隐藏请求
[NtClose] FilterInvalidHandle=1                     ; 屏蔽句柄陷阱异常
```

**Hook NtQueryInformationProcess** 返回清洁值(用户态 inline hook):

```cpp
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
pNtQueryInformationProcess origNtQIP;

NTSTATUS NTAPI HookNtQueryInformationProcess(
    HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG rlen) {
    NTSTATUS st = origNtQIP(h, cls, buf, len, rlen);
    if (st == 0) {  // STATUS_SUCCESS
        switch (cls) {
            case 7:    *(DWORD*)buf = 0; break;       // ProcessDebugPort
            case 0x1F: *(DWORD*)buf = 1; break;       // ProcessDebugFlags
            case 0x1E: *(HANDLE*)buf = NULL; break;   // ProcessDebugObjectHandle
        }
    }
    return st;
}
```

**时序绕过**:Hook `RDTSC`/`RDTSCP` 返回线性递增值使差值恒定(x64dbg 的 RDTSC 命令、ScyllaHide 的 Timing 模块)。**硬件断点清除**:检测到 DR 寄存器非零时,通过 `SetThreadContext` 清除 DR0-DR3 与 DR7:

```cpp
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
ctx.Dr7 = 0;
SetThreadContext(hThread, &ctx);
```

**TitanHide** 提供内核级隐藏(驱动),可绕过用户态 hook 检测——目标若检测 ntdll 是否被 patch,TitanHide 在内核态过滤 `NtQueryInformationProcess`、`NtSetInformationThread`,patch `EPROCESS`/`PEB`。

### 17.3 Linux/macOS 反调试对抗

**Linux ptrace 自附加**:目标调用 `ptrace(PTRACE_TRACEME, 0, 0, 0)`,已被调试则返回 -1(errno=EPERM),程序据此退出:

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { _exit(1); }  // 已被调试则退出
```

绕过:`LD_PRELOAD` hook `ptrace` 返回 0;目标静态链接时需 binary patch。

**/proc/self/status TracerPid 检测**:读取 `TracerPid:` 字段,非 0 即被调试。绕过:hook `open`/`read` 当路径含 `/proc/self/status` 时篡改返回内容。**inotify 监控**:目标对 `/proc/self/status` 建 watch,反检测到监控则判定为调试环境,需 hook `inotify_add_watch`。

**macOS PT_DENY_ATTACH**:通过 `sysctl` 的 `PT_DENY_ATTACH`(31)拒绝调试器附加,附加则进程被 SIGTRAP 终止。绕过:Hook `sysctl` 当 `CTL_KERN + KERN_PROC` 时清除 `P_FLAG` 中的调试标志。

**Frida 检测**:扫描 `/proc/self/maps` 中 `frida-agent`、`frida-gadget` 映射;检测线程名 `gum-js-loop`、`gmain`、`pool-frida`。

### 17.4 DBI 框架检测与绕过(2026)

动态二进制插桩(DBI)框架留下独特指纹:

- **Frida 检测**:TCP 端口 27042 扫描(frida-server 默认监听);`/proc/self/maps` 中 `frida-agent.so` 映射;D-Bus 协议探测(向 27042 发送 `AUTH` 字节,返回 `REJECT` 即 frida);检测 `gum-js-loop` 线程名;扫描内存中 `frida:rpc`、`gum` 字符串。
- **DynamoRIO 检测**:检查代码缓存特征(DR 将原始代码复制到独立 cache,存在 `dynamorio` 字符串与基本块重定位痕迹);检测 `ntdll.dll` 中 DR 注入的 hook stub。
- **QBDI 检测**:基于指令执行计数偏差——QBDI 模拟执行时 `RDTSC` 与真实 CPU 偏差巨大,目标比较两次 `RDTSC` 间执行的指令数即可判定。

**绕过策略**:frida-gadget 重命名为普通库名(如 `libtest.so`)并改 config.js 模块名;`frida-server -l 0.0.0.0:1337` 改用非默认端口;用 **Stalker 替代 Interceptor**(Stalker 不修改函数前 5 字节,对 INT3 扫描与 hook 检测免疫);DynamoRIO 用 `-stealth` 模式或进程外(out-of-process)模式减少特征。

```bash
# 修改 frida-server 默认端口与名称
cp frida-server frida-server-renamed
./frida-server-renamed -l 0.0.0.0:1337   # 改用非默认端口 1337
# frida 客户端连接:frida -H 127.0.0.1:1337 com.target.app
```

### 17.5 VEH(向量异常处理)反调试

`AddVectoredExceptionHandler` 注册的异常处理器优先级高于调试器。程序故意触发异常(INT3=0xCC、INT 2D、除零、非法指令),若被调试器接管则 VEH 不执行,据此判断是否被调试:

```cpp
LONG WINAPI VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        // VEH 触发 = 未被调试,跳过 INT3
        ep->ContextRecord->Eip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

AddVectoredExceptionHandler(1, VehHandler);
__asm int 0x2d;   // 触发异常:被调试器接管则 VEH 不执行,程序通过全局标志判断
```

**绕过**:在 x64dbg/WinDbg 中配置 **"Pass exception to program"**(异常选项中将 `0x80000003`、`0x80000004` 设为 continue passing),使异常优先交予 VEH;或直接 patch 触发异常的指令为 NOP。

### 17.6 2026 新兴反调试技术

- **eBPF-based debugging detection**(Linux 6.x):程序通过 eBPF 挂载 `tracepoint/sched/sched_process_exec`、`raw_syscalls`,监控 `ptrace`、`process_vm_readv` 调用,即便用户态 hook 也无法绕过(内核态监控)。绕过需内核态 patch 或禁用非特权 eBPF(特权 eBPF 仍生效)。
- **Intel CET shadow stack**:控制流强制技术维护影子栈,若调试器通过 ROP/异常篡改返回地址,影子栈校验失败触发 `#CP` 异常。调试器需正确同步影子栈(2026 新版 gdb/WinDbg 已支持),否则被检测。
- **Hypervisor-enforced debugging detection**:基于 Hypervisor(Hyper-V、KVM)的调试在 VMExit 留下时序特征,目标通过 `RDTSC` 测量指令间延迟(VMExit 耗时数万周期)检测。需 Hook `RDTSC` 或使用硬件直通。
- **TPM-based attestation**:程序请求 TPM 远程证明,PCR(Platform Configuration Register)报告是否含调试器特征(已签名驱动、被 patch 的内核)。绕过需伪造 TPM 证明或物理替换 TPM。
- **AI-driven behavioral analysis**:通过机器学习模型分析进程行为(系统调用序列、内存访问模式、线程调度间隔),识别调试器/沙箱的"非人类"特征。2026 年已有商业 EDR 集成,逆向需模拟真实用户行为(随机化输入、引入人类节奏延迟),或对模型本身进行对抗样本攻击。

---

## 18. 动态二进制插桩(DBI) — DynamoRIO/Intel PIN/Frida/QBDI

动态二进制插桩(Dynamic Binary Instrumentation, DBI)是逆向工程与恶意软件分析的核心技术,通过在二进制运行时注入分析代码,实现对指令流、内存访问、控制流的细粒度监控。相比静态调试,DBI无需源码且可在生产环境部署,是绕过反调试、提取解密数据、收集覆盖率的关键手段。

### 18.1 DBI框架对比矩阵

| 特性 | DynamoRIO | Intel PIN | Frida | QBDI |
|------|-----------|-----------|-------|------|
| 支持架构 | x86/x64/ARM/ARM64 | x86/x64/ARM64 | x86/x64/ARM/ARM64/MIPS/RISC-V | x86/x64/ARM/ARM64 |
| 插桩方式 | code cache翻译 | JIT code cache | JS Agent + gum | 独立DBI引擎 |
| 性能开销 | 低(2-10x) | 中(3-20x) | 中(5-50x,Stalker高) | 低(1.5-5x) |
| 跨平台支持 | Linux/Windows/macOS/Android | Linux/Windows/macOS | 全平台(含iOS) | Linux/Windows/macOS/Android/iOS |
| 隐蔽性 | 中(可被PEB/线程检测) | 低(PIN3.x易检测) | 低(JS引擎特征明显) | 高(无外部依赖) |
| 脚本化 | C/C++ client | C/C++/Python | JavaScript/TypeScript | Python/JS(QBDIPreload) |
| 适用场景 | 覆盖率/缓存分析/脱壳 | 恶意软件分析/性能 | 移动端/API hook | 移动端/反检测场景 |

选型建议: 桌面端深度分析用DynamoRIO,快速原型与移动端用Frida,反检测要求高的移动端场景用QBDI,PIN适合传统Windows恶意软件分析生态。

### 18.2 DynamoRIO实战

DynamoRIO采用code cache机制: 将原始代码块翻译复制到独立代码缓存区执行,在翻译过程中插入分析代码。核心概念包括basic block(单入单出指令序列)、trace(热点basic block链)、code cache(翻译后代码存放区)。

编写自定义client实现基本块计数:

```c
// DynamoRIO basic block计数器
#include "dr_api.h"

static uint64 bb_count = 0;

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag,
    instrlist_t *bb, bool for_trace, bool translating) {
    bb_count++;
    return DR_EMIT_DEFAULT;
}

static void event_exit(void) {
    dr_fprintf(STDERR, "Total basic blocks executed: %" PRIu64 "\n", bb_count);
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_register_bb_event(event_basic_block);
    dr_register_exit_event(event_exit);
}
```

编译与运行: `drrun -c libbbcount.so -- ./target`。drcov是DynamoRIO自带的覆盖率工具,生成BB覆盖率文件供lighthouse或IDA Coverage可视化:

```bash
drrun -t drcov -- ./target          # 生成target.cov.*文件
drcov2lcov -dir . -o coverage.info   # 转换为lcov格式
```

drcachesim用于缓存模拟分析,可统计L1/L2/LLC命中率与伪共享: `drrun -t drcachesim -- ./target`。taint_indirect示例展示间接跳转污点追踪,通过在`indbr`指令处插入回调,追踪寄存器来源,辅助挖掘JOP/COP gadget链。DynamoRIO的drmgr扩展模块支持多client协作,drutil提供内存访问与控制流插桩工具函数,drwrap实现函数包装(类似Frida Interceptor)。

### 18.3 Intel PIN实战

PIN通过JIT编译将插桩代码与原始指令混合,在code cache中执行。其插桩粒度分为指令级(INS)、基本块级(BBL)、镜像级(IMG)、跟踪级(TRACE)。

指令级插桩示例:

```cpp
// PIN指令计数器
#include "pin.H"

static UINT64 icount = 0;

VOID docount() { icount++; }

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IPOINT_END);
}

VOID Fini(INT32 code, VOID *v) {
    fprintf(stderr, "Total instructions: %" PRIu64 "\n", icount);
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```

运行: `pin -t inscount0.so -- ./target`。PIN的RTN(Routine)API支持按符号插桩,IMG API可枚举加载模块。相比DynamoRIO,PIN优势在于Windows生态成熟、API文档完善、社区工具丰富(如Intel SDE指令集模拟);劣势是性能开销略高、PIN自身特征明显(如pinvm.dll、__pin_*符号)易被反调试检测。恶意软件分析中,PIN常用于追踪API调用序列、提取解密后的字符串、记录内存写入以定位C2配置解密例程。可通过`PIN_SpawnChildProcess`分析多进程恶意软件,结合`CallbackGuard`处理TLS回调与早期执行代码。

### 18.4 Frida高级插桩

Frida基于gum引擎,通过Gum.Interceptor实现函数级hook(API hook),Gum.Stalker实现基本块级追踪(code coverage/taint)。两者适用场景不同: Interceptor适合API监控与参数篡改,Stalker适合细粒度覆盖率收集与控制流分析。

Stalker代码覆盖率收集:

```javascript
// Frida Stalker覆盖率收集
var tid = Process.getCurrentThreadId();
var blocks = new Set();
Stalker.follow(tid, {
    events: { compile: true },
    onReceive: function(events) {
        var parsed = Stalker.parse(events);
        parsed.forEach(function(event) {
            blocks.add(event[1].toString(16));
        });
    }
});

// 导出覆盖率到文件
function dumpCoverage() {
    var cov = Array.from(blocks).join('\n');
    var f = new File("/data/local/tmp/cov.txt", "w");
    f.write(cov);
    f.close();
}
setInterval(dumpCoverage, 5000);
```

Frida C模块允许在JS上下文中编写Native函数,绕过JS引擎开销并提升隐蔽性。C模块以字符串形式嵌入,编译为机器码后注入目标进程:

```javascript
var cm = new CModule(`
#include <gum/guminterceptor.h>
extern void on_enter(GumInvocationContext * ic) {
    // 纯C实现,无JS回调开销
    void * arg0 = gum_invocation_context_get_nth_argument(ic, 0);
}
`);
Interceptor.replace(Module.getExportByName(null, 'open'), cm.on_enter);
```

Frida反检测技巧: 避免使用`frida-server`(端口27042易被扫描),改用`frida-gadget`注入so或`frida-compile`打包单文件脚本;重命名agent线程;hook `dlopen`/`pthread_create`隐藏自身;使用`frida-il2cpp-bridge`分析Unity游戏。对frida检测脚本(检查/maps、/proc/self/status、端口扫描)可针对性绕过。

### 18.5 QBDI — 轻量级DBI

QBDI(QuarkslaB Dynamic Instrumentation)是轻量级DBI框架,无需内核驱动或ptrace,以静态库形式注入目标进程,隐蔽性极高。其核心是独立DBI引擎,不依赖外部框架,适用于反检测严格的移动端分析。

独立运行模式: QBDI直接接管目标进程执行,通过`QBDI::VM`对象管理执行上下文与插桩回调。Frida-QBDI联合模式(通过frida-qbdi插件)将QBDI作为Frida的代码分析后端,兼顾Frida的便捷API与QBDI的低检测特征:

```javascript
// Frida-QBDI联合: 用QBDI做Stalker替代
var qbdi = new QBDI();
qbdi.addInstructionCallback(function(vm, gpr, fpr) {
    var pc = vm.getGPRState().pc;
    // 高性能覆盖率收集,无Stalker特征
    return VMAction.CONTINUE;
});
qbdi.run(currentThread);
```

iOS越狱检测绕过是QBDI典型场景: 越狱检测常通过`fork`、`access("/Applications/Cydia.app")`、`dyld`环境变量检查实现,QBDI可hook这些调用并伪造返回值,且因无frida-server特征而难以被检测。QBDI的CallbackGuard处理信号与异常,确保插桩过程稳定。QBDI还支持Python绑定,便于编写自动化分析脚本。

---

## 19. 模拟执行框架 — Qiling/Unicorn/QEMU-user

模拟执行框架通过软件模拟CPU指令集与(可选)操作系统层,在非原生环境运行目标二进制,是跨架构分析、恶意软件沙箱、脱壳的关键基础设施。相比动态调试,模拟执行无调试器痕迹、可精确控制内存与系统调用,适合反检测与自动化场景。

### 19.1 模拟执行框架对比

| 框架 | 底层引擎 | 支持架构 | 系统调用模拟 | 文件系统模拟 | 适用场景 |
|------|----------|----------|--------------|--------------|----------|
| Unicorn | QEMU(精简) | x86/x64/ARM/ARM64/MIPS/PPC/RISC-V | 无(纯CPU) | 无 | shellcode分析/解密例程 |
| Qiling | Unicorn | 同Unicorn | 完整(Linux/Win/macOS) | 完整(rootfs) | 恶意软件沙箱/跨架构/脱壳 |
| QEMU-user | QEMU | 全架构 | 部分(用户态) | 部分(路径映射) | 跨架构调试/fuzzing |
| Manticore | 自研 | x86/x64/EVM | 符号化 | 符号化 | 符号执行/智能合约 |

Unicorn是纯CPU级模拟器,无OS层,适合指令级分析;Qiling在Unicorn之上构建OS模拟层,提供系统调用、文件系统、网络栈模拟;QEMU-user是QEMU的用户态模式,支持gdbstub;Manticore融合符号执行与模拟。

### 19.2 Qiling框架实战

Qiling架构: Qiling = Unicorn(CPU模拟) + OS模拟层(syscall handler + 文件系统 + 注册表 + 网络栈)。支持Windows PE、Linux ELF、macOS Mach-O跨架构执行,内置rootfs提供模拟环境。

运行Windows PE并Hook API:

```python
from qiling import Qiling

# 运行Windows恶意软件
ql = Qiling(["malware.exe"], "/path/to/rootfs")
ql.run()

# Hook Windows API
@ql.hook_api("kernel32.dll!CreateFileW")
def hook_create_file(ql, address, params):
    print(f"CreateFileW: {params['lpFileName']}")
    # 修改参数或返回值
    return 0  # 返回INVALID_HANDLE_VALUE

# Hook注册表操作,模拟持久化
@ql.hook_api("advapi32.dll!RegSetValueExA")
def hook_reg_set(ql, address, params):
    print(f"RegSetValue: {params['lpValueName']} = {params['lpData']}")
```

运行Linux ELF跨架构执行: `ql = Qiling(["arm_binary"], "rootfs/arm_linux", arch="arm")`。Qiling自动识别ELF头并设置正确的架构与模式。运行macOS Mach-O需提供对应rootfs与dyld。Qiling沙箱分析恶意软件: 拦截文件创建/写入、注册表修改、网络连接(C2回连),将行为记录到JSON报告。`ql.os.stats`输出系统调用统计,`ql.fs`可挂载自定义文件系统。Qiling的`on_syscall`钩子可重写任意系统调用语义,实现蜜罐式响应。

### 19.3 Unicorn Engine深度应用

Unicorn提供纯CPU指令级模拟,无OS开销,适合shellcode分析、解密例程还原、漏洞利用开发。

模拟执行shellcode:

```python
from unicorn import *
from unicorn.x86_const import *

# 模拟执行shellcode
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, b"\x48\x31\xc0\x48\xff\xc0\x90\x90")  # xor rax,rax; inc rax; nop; nop
mu.reg_write(UC_X86_REG_RSP, 0x1000 + 0x800)

# Hook每条指令
def hook_code(uc, address, size, user_data):
    print(f"Executing: 0x{address:x}, size={size}")

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(0x1000, 0x1008)
print(f"RAX = {mu.reg_read(UC_X86_REG_RAX):#x}")
```

模拟执行解密例程: 加载恶意软件中的解密函数shellcode到模拟内存,设置寄存器(密钥指针、密文地址),执行后dump解密结果。结合`UC_HOOK_MEM_READ`/`UC_HOOK_MEM_WRITE`追踪内存访问,定位解密输出缓冲区。Unicorn支持上下文保存/恢复(`context_save`/`context_restore`),可用于分支探索。与angr配合时,Unicorn作为concrete executor执行具体路径,angr处理符号约束,实现混合符号执行(hybrid execution),显著缓解路径爆炸。

### 19.4 QEMU-user模式

QEMU-user模式在用户态翻译执行异架构二进制,无需完整系统镜像,是跨架构fuzzing与调试的标配。

```bash
qemu-arm ./binary                    # 运行ARM二进制
qemu-mips ./binary                   # 运行MIPS二进制
qemu-aarch64 -g 1234 ./binary        # 启动GDB stub等待连接
# GDB连接: target remote :1234
```

GDB stub支持断点、单步、内存读写,配合`gdb-multiarch`调试异架构程序。结合Frida: `frida -U -f qemu-arm -- ./binary`,在QEMU翻译层之上做API hook。QEMU-user的`-strace`输出系统调用日志,`-L`指定sysroot路径映射。2026年QEMU 9.x新特性: RISC-V模拟完善(支持RVV向量扩展)、ARM SME/MPAM支持、TCG插件框架增强(`-plugin`可加载覆盖率/内存分析插件,替代传统DBI)。QEMU-user常用于IoT固件分析,结合FirmAE或firmware-analysis-toolkit运行提取的squashfs根文件系统中的二进制。

### 19.5 模拟执行脱壳应用

模拟执行脱壳利用壳代码在模拟环境中自解密的特性,无需对抗反调试,即可获取原始代码。

```python
# Qiling自动脱壳通用模式
ql = Qiling(["packed.exe"], "rootfs")

# 等待OEP: 监控section hop
def check_oep(ql):
    pc = ql.reg.arch_pc
    # 检测执行从壳代码跳转到原始代码段
    if is_original_code_section(pc):
        ql.mem.dump(pc, original_size, "unpacked.bin")
        ql.emu_stop()

ql.hook_code(check_oep)
ql.run()
```

UPX脱壳: UPX在解压后跳转到OEP,可通过监控`jmp`/`ret`目标地址是否落在原始代码段(.text)判断OEP。ASPack等压缩壳通过异常处理(SEH)转移控制流,需模拟异常分发逻辑。VMProtect/Themida等虚拟化壳需先还原VM handler再提取原始指令,模拟执行可辅助VM dispatcher分析。模拟执行+内存dump = 通用脱壳方案: 记录所有内存写入,在OEP处dump整个可执行段。对比动态调试脱壳,模拟执行更隐蔽(无调试器痕迹、无硬件断点特征、可伪造反调试API返回值),但需处理壳的反模拟检测(如时间戳检查、特定CPUID模拟差异)。Qiling的`ql.os.exit_code`与异常回调可处理壳触发的故意崩溃。

---

## 20. 符号执行与污点分析深度应用 — angr/KLEE/Manticore/Triton/QSYM

符号执行将程序输入标记为符号变量,通过约束求解探索所有可达路径,是自动化漏洞挖掘、CTF求解、反混淆的利器。污点分析追踪数据流传播,识别受外部输入影响的代码区域。两者结合形成强大的程序分析能力。

### 20.1 符号执行原理与挑战

符号执行 vs 具体执行: 具体执行单一输入产生单一路径,符号执行用符号变量表示输入,通过路径约束(path constraint)探索所有可行路径,核心挑战是路径爆炸(path explosion)——分支数随输入位宽指数增长。

静态符号执行(如KLEE早期)从入口纯符号探索;动态符号执行(concolic execution,如SAGE/DART)先具体执行一条路径,再翻转分支约束求解新输入,缓解路径爆炸。约束求解器: Z3(SMT,微软)、STP、Boolector、CVC5,性能差异显著,Z3最通用。2026年挑战与进展: 路径爆炸缓解采用状态合并(state merging,用λ表达式合并分支)、冗余路径剪枝(verbatim技术避免重复探索等价路径);预计算约束缓存(constraint caching);增量求解(incremental solving)复用求解器状态。混合执行(concolic + fuzzing)成为主流,符号执行仅处理模糊测试难以突破的复杂约束。

### 20.2 angr符号执行框架

angr是Python符号执行框架,核心概念: Project(二进制加载与架构)、State(执行状态,含寄存器/内存/约束)、SimEngine(执行引擎)、SimulationManager(状态集合管理)。

```python
import angr

proj = angr.Project("./target", auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# 探索到达特定地址的路径
simgr.explore(find=0x400800, avoid=0x400900)

if simgr.found:
    found = simgr.found[0]
    # 求解输入
    solution = found.posix.dumps(0)  # stdin
    print(f"Solution: {solution}")
```

管理器操作: `step()`推进一个基本块,`explore(find, avoid)`自动探索至目标,`prune()`剪除不可满足状态,`merge()`合并等价状态。Hook函数简化分析: `proj.hook_symbol('strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())`用SimProcedure替代复杂库函数;自定义hook返回固定值(如`strcmp`恒返回0)绕过校验。约束求解: `state.solver.eval(expr)`求解符号表达式,`state.solver.BVV`构造位向量,`state.solver.If`构造条件表达式。angr的`Claripy`后端可切换Z3/STP。实战技巧: 用`state.options.add(angr.options.LAZY_SOLVES)`延迟求解提升性能,`Veritesting`模式自动合并路径缓解爆炸。

### 20.3 KLEE — LLVM符号执行

KLEE基于LLVM bitcode执行符号分析,需先用clang将源码编译为LLVM IR: `clang -emit-llvm -c target.c -o target.bc`。KLEE对IR做符号执行,生成KTest测试用例。

```bash
# KLEE符号执行
klee -libc=uclibc -posix-runtime target.bc
# 输出test*.ktest用例
ktest-tool klee-last/test000001.ktest
```

KTest文件包含触发各路径的输入数据,可直接作为AFL种子。KLEE的`klee_make_symbolic`标记符号变量,`klee_assume`添加路径约束。2026年KLEE对LLVM 15+支持完善,新增对新LLVM IR特性的符号语义。与AFL配合: KLEE探索深度路径生成高质量种子 → AFL变异扩展,形成KLEE-AFL混合fuzzing,显著提升覆盖率与漏洞发现率。KLEE-Net模块支持网络协议符号执行。

### 20.4 Manticore — 多范式符号执行

Manticore支持多目标: x86/x64/ARM二进制符号执行、EVM字节码符号执行(智能合约漏洞挖掘)。其优势是统一的符号执行API跨平台。

```python
from manticore.eth import ManticoreEVM

m = ManticoreEVM()
with open('contract.sol') as f:
    source_code = f.read()

user_account = m.create_account(balance=1000)
contract_account = m.solidity_create_contract(source_code, owner=user_account)

# 符号执行所有公开函数
symbolic_data = m.make_symbolic_buffer(320)
contract_account.fallback(data=symbolic_data)

# 检测整数溢出/重入漏洞
for state in m.running_states:
    # 检查balance异常状态
    pass

m.finalize()  # 生成报告
```

Manticore for smart contracts自动检测整数溢出、重入攻击、未授权访问。二进制分析模式下,`manticore ./binary`自动探索路径并生成触发各分支的输入。Manticore的插件系统支持自定义检测器(detector)。

### 20.5 Triton — 动态符号执行与污点分析

Triton结合DBI(基于Pin)的具体执行与符号执行,实现concolic analysis,适合分析混淆代码与自动求解约束。

```python
from triton import TritonContext, ARCH, Instruction

ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)

# 设置符号变量
ctx.setConcreteRegisterValue(ctx.registers.rax, 0x41414141)
ctx.symbolizeRegister(ctx.registers.rax, 'input')

# 执行指令并追踪污点
inst = Instruction(b"\x48\x01\xc0")  # add rax, rax
ctx.processing(inst)

# 获取符号表达式
rax_sym = ctx.getSymbolicExpressionFromId(ctx.getSymbolicRegisterId(ctx.registers.rax))
print(f"RAX = {rax_sym.getAst()}")
# 输出: RAX = (input_0 + input_0)
```

Triton的污点传播引擎自动追踪符号变量在寄存器与内存间的流动,`getTaintedRegister`/`isMemoryTainted`查询污点状态。应用: 自动化绕过license check——标记用户输入为符号,执行license校验例程,在比较指令处收集路径约束,用Z3求解满足"校验通过"的输入;反混淆VMProtect时追踪VM handler的数据流,还原虚拟化指令语义。Triton支持AST快照与SMT简化,降低求解开销。

### 20.6 QSYM — 混合模糊测试

QSYM = 符号执行 + 模糊测试,符号执行仅用于求解模糊测试难以突破的复杂约束(如magic number比较、checksum校验),避免纯符号执行的路径爆炸。

```bash
# Symcc编译: 在编译时插入符号执行指令
symcc --stat-syms ./target.c -o target_sym

# 配合AFL运行: concolic execution辅助fuzzing
afl-fuzz -i input/ -o output/ -- ./target_sym @@
```

QSYM采用乐观求解(optimistic solving)与约束切片(constraint slicing)仅保留关键约束,大幅提升求解速度。与AFL配合: QSYM作为AFL的辅助引擎,当AFL卡在magic number时触发符号执行求解。2026年进展: SymCm——在LLVM编译器级插桩,性能比传统DBI方式提升10x,符号执行开销接近零;SyME将符号执行并行化,多核扩展求解。Symcc编译的二进制在运行时自动记录路径约束并生成新种子,与AFL++的`-c symcc`集成。

### 20.7 符号执行实战场景

自动化CTF flag求解: angr解决简单crackme——标记输入为符号,`explore(find=打印"Correct"地址, avoid=打印"Wrong"地址)`,求解到达成功分支的输入。适用于校验逻辑简单的逆向题,对复杂VM或魔改加密仍需手动分析。

漏洞利用自动生成: 求解触发crash的输入——将网络输入标记为符号,在crash点收集路径约束与内存约束,用Z3求解满足缓冲区溢出条件的输入。angr的`explore(find=crash_addr)`配合`state.solver`可自动生成PoC。

协议fuzzing: 符号执行生成协议测试用例——对协议解析器符号执行,在状态机分支处求解满足各分支的协议数据,生成覆盖所有解析路径的fuzzing种子,显著优于纯随机变异。

反混淆: 符号执行还原OLLVM控制流平坦化——识别dispatcher(分发器)基本块,对每个真实basic block标记符号执行上下文,通过约束求解恢复原始控制流图;angr的`Veritesting`与DDG(数据依赖图)辅助还原。Triton的污点追踪可识别opaque predicate(恒真/恒假条件)并化简,还原混淆逻辑。对VMProtect虚拟化,符号执行配合污点分析可自动推导VM handler语义,重建原始指令。

---

## 21. 二进制差分与补丁分析 — Diaphora/BinDiff/DarunGrim

### 21.1 二进制差分技术原理

二进制差分(Binary Diffing)是逆向工程中用于对比两个二进制文件差异的核心技术,其根本目标是在剥离符号表、经历编译器优化与地址重排后,仍然能够识别出"逻辑等价"或"高度相似"的代码块。差分的结果常用于补丁逆向(定位 CVE 修复点)、恶意软件变种溯源、固件版本对比以及漏洞 1day 分析。

- **Basic Block Matching(基本块匹配)**:基本块是差分的最小单元,匹配策略包含三层。第一层是 hash 匹配,对基本块内指令字节序列(或归一化后的助记符序列)计算哈希,如 MD5/SHA-1/FNV,哈希相同则视为同构;第二层是结构匹配,在哈希失效时比较指令数量、操作数类型、跳转目标数等拓扑特征;第三层是松弛匹配,允许少量指令差异(如立即数变化),用于检测补丁修改的微小变化。
- **Function Matching(函数匹配)**:在基本块匹配之上进行函数级对齐。CFG 同构是比较两个函数的控制流图是否同构(忽略节点地址);名称匹配利用导出表、PDB 残留符号、RTTI 类名进行精确匹配;调用图匹配(Call Graph Matching)将函数作为节点、调用关系作为边,在全局调用图上做近似同构匹配,从而定位"调用结构相似但内部略有改动"的函数。
- **Algorithm categories**:graph isomorphism(图同构,BinDiff 采用的 Bellman-Ford 变种与 Hungarian 算法组合)、hash-based(DarunGrim 的指令指纹)、symbolic execution-based(对基本块做符号执行后比较约束求解结果,精度高但开销大)。业界主流工具多以图同构 + 哈希混合策略,在精度与速度间取得平衡。
- **应用场景**:补丁差异分析(Patch Tuesday 逆向还原 CVE)、恶意软件变种分析(同族不同版本的 C2 协议演变)、固件版本对比(IoT 路由器固件差异定位新漏洞)、1day 漏洞利用开发(已知 CVE 但无 PoC 时,通过差分还原漏洞触发路径)。

### 21.2 工具对比矩阵

| 工具 | IDA集成 | 跨平台 | 算法 | 免费开源 | 2026维护状态 |
|------|---------|--------|------|----------|--------------|
| BinDiff (Google→Zynamics) | 原生插件 | Linux/macOS/Windows | Graph isomorphism + Hungarian | 非开源(免费) | 活跃,Ghidra/Binary Ninja 支持 |
| Diaphora | IDA 脚本 | 全平台(依赖 IDA) | 多算法混合(Best/Partial/Unreliable) | 开源(GPLv3) | 活跃,社区驱动 |
| DarunGrim | IDA 插件 | Windows 优先 | 指纹哈希 + CFG | 开源 | 维护缓慢 |
| TurboDiff | IDA 插件 | Windows | Corelan 团队,匹配策略偏补丁 | 免费 | 基本停更 |
| BinSlayer | 独立 | Linux | 基于 NetworkX 图匹配 | 开源 | 学术原型 |
| BinDiff 2 (Ghidra fork) | Ghidra | 全平台 | 同 BinDiff 内核 | 开源 | 2026 社区维护 |

选型建议:常规补丁逆向首选 BinDiff(精度高、IDA 集成好);需要自动化批处理或自定义匹配策略时选 Diaphora;学术研究或定制图算法可用 BinSlayer;纯 Ghidra 工作流可考虑 BinDiff 2 社区版。

### 21.3 BinDiff实战 — 补丁差异分析

```bash
# BinDiff命令行使用
bindiff --primary=original.exe --secondary=patched.exe --output_dir=results/

# BinDiff导出: 比较结果可视化
# 在IDA Pro中:
# 1. File → BinDiff → Diff Database
# 2. 选择原始二进制和补丁二进制
# 3. 查看匹配/不匹配的函数
# 4. 重点分析 "unreliable match" 和 "no match" 的函数
```

BinDiff 的工作流是"先建库再比对"。对每个二进制先用 `binexport` 工具(或 IDA 插件)导出 `.BinExport` 数据库,包含函数、基本块、指令、调用图结构;再用 `bindiff` 比较两个数据库,生成 `.BinDiff` 结果文件。比较结果分为四类:**Matched**(高可信同构)、**Reliable Match**(部分指令差异)、**Unreliable Match**(仅结构相似)、**No Match**(新增/删除函数)。

分析补丁时的核心策略:先按相似度排序,跳过完全匹配的函数(占 90% 以上),聚焦 Unreliable Match 与 No Match 函数。在 IDA 中双击结果项可同步显示两个版本的 CFG 并排视图,修改的基本块会高亮。**从补丁还原漏洞的关键逻辑**:补丁通常只修改漏洞触发路径上的少量代码,因此差分定位的修改点即为漏洞点;通过对比修改前后的边界检查、长度校验、指针运算,可推断出原始漏洞类型(越界读写、整数溢出、UAF 等)。

2026 年趋势:Microsoft Patch Tuesday 逆向已高度自动化,开源项目(如 PatchDiffFlow、DiffDump)结合 BinDiff 结果与 LLM 自动生成漏洞类型推测报告,将单个 CVE 的逆向时间从数小时压缩到分钟级。

### 21.4 Diaphora实战

Diaphora 是目前最活跃的开源差分工具,以 IDA Python 脚本形式分发,支持 SQLite 数据库导出与多种匹配策略。

```bash
# IDA中执行Diaphora脚本
# 1. 打开original.exe, 执行Diaphora → Export Database
# 2. 打开patched.exe, 执行Diaphora → Export Database  
# 3. 执行Diaphora → Diff Database 选择两个.dsqlite文件
# 4. 查看Best Match/Partial Match/Unreliable Match/No Match
```

匹配结果分类与含义:
- **Best Match**:高可信度匹配,通常名称、CFG、调用关系三者一致,可视为完全相同的函数,跳过即可。
- **Partial Match**:CFG 相似但非同构,存在指令增删或基本块重排,需人工核对差异指令,这类函数往往是补丁修改的目标。
- **Unreliable Match**:仅调用结构或粗粒度特征相似,可信度低,需结合上下文判断是否为对应函数。
- **No Match**:新增或删除的函数,是补丁引入新功能或删除旧逻辑的关键证据。

Diaphora 支持导出 JSON/CSV 结果,便于自动化分析。典型脚本流程:批量导出多个补丁版本的 `.dsqlite`,用 Python 脚本循环比对,提取所有 Partial/No Match 函数名,生成差异清单。对于无符号二进制,Diaphora 的"Best Match by MD Index"能基于函数调用图拓扑指纹进行匹配,有效缓解符号缺失问题。

### 21.5 恶意软件变种分析

同族恶意软件不同版本间的差分是威胁情报生产的核心手段。典型流程:收集同族样本(按 YARA 族规则或家族名聚类)→ 对核心模块逐版本差分 → 提取功能变化。重点关注四类变化:**核心功能变化**(如新增勒索加密模块、删除传播模块)、**反检测代码新增**(如新增沙箱检测、反调试、反 hook)、**C2 通信协议演变**(如加密算法升级、协议字段调整、域名生成算法 DGA 变更)、**持久化机制调整**(如注册表键变更、计划任务格式变化)。

自动化批处理示例:用 Diaphora 导出每个版本的数据库,编写脚本两两比对,生成"功能演进时间线",可直观看到某家族从简单 RAT 逐步加入挖矿、勒索、横向移动模块的演化路径。对于加壳样本,需先脱壳(Unicorn 模拟脱壳或 dump 内存)再进行差分,否则哈希与 CFG 会被混淆层破坏。

### 21.6 2026趋势: AI辅助二进制差分

- **CodeBERT/CodeT5 用于函数语义相似度比较**:将反编译伪代码视为自然语言,用预训练代码模型编码函数语义向量,计算余弦相似度,弥补纯图匹配在变量重命名、循环展开等变换下的失效。
- **Gemini/Claude 用于差异代码片段的自然语言解释**:将差分定位的修改基本块反编译后送入 LLM,自动生成"该修改将缓冲区长度检查从 `len > 256` 改为 `len >= 256`,修复了 off-by-one 越界写"等自然语言说明。
- **自动 CVE 映射**:差分结果与已知漏洞模式库(如 CVE 描述向量化)匹配,自动推测补丁对应的 CVE 编号,实现"给两个二进制,输出候选 CVE 列表"。

---

## 22. iOS 应用脱壳与逆向 — frida-ios-dump/Clutch/dumpdecrypted

### 22.1 iOS应用保护机制

iOS 应用逆向的第一道关卡是 Apple 的 FairPlay DRM。FairPlay 是 Apple 应用于 App Store 分发应用的 DRM 系统,对应用的 Mach-O 主二进制中的 `__TEXT` 段进行加密,加密密钥与设备 Apple ID 账户绑定,只有授权设备才能解密执行。加密层级为:**FairPlay 加密层 → Mach-O 加载层 → 代码执行层**,内核在 `exec_mach_imgact` 阶段调用 `cape->crproc` 完成 FairPlay 解密后才会跳转入口。

**脱壳原理**基于一个根本事实:解密后的代码必须以明文形式驻留在内存中才能被 CPU 执行,因此在运行时从进程内存中 dump 出 `__TEXT` 段即可获得解密后的二进制。具体做法是定位 Mach-O header,读取 `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` load command 获取加密段的文件偏移与大小,从内存中读取解密后的数据,再回填到原始 Mach-O 文件对应位置,即可生成脱壳后的 IPA。

2026 年 iOS 18/19 新增了**代码签名完整性检查**:内核在 page-in 时校验每个代码页的 SHA-256 哈希(硬编码在 `fairplay` 模块),单纯修改磁盘上的二进制会触发签名失败;此外 `AMFI` 引入了运行时 `proc_jailbreak` 标志检测,对越狱环境做了更严格的限制。这意味着传统脱壳工具必须适配新的内存布局与签名校验路径。

### 22.2 脱壳工具与方法

| 工具 | 原理 | 需要越狱 | 2026状态 |
|------|------|----------|----------|
| frida-ios-dump | Frida hook + 内存 dump | 是 | 活跃,主流首选 |
| Clutch | 直接调用 fairplay 解密接口 | 是 | 维护缓慢 |
| dumpdecrypted | 注入 dylib,dump 解密后 Mach-O | 是 | 老牌但仍可用 |
| FlexDecrypt | 通过 Frida 从内存提取 | 是 | 基本停更 |
| Azul | 基于 KFD 漏洞的免越狱脱壳 | 否 | 2026 新兴 |
| CrackerXI | 在线脱壳服务(需上传 IPA) | 否 | 服务可用 |

### 22.3 frida-ios-dump实战

frida-ios-dump 是当前最主流的脱壳工具,基于 Frida 运行时插桩,工作流清晰、自动化程度高。

```bash
# 1. 安装frida-ios-dump
pip3 install frida-tools
git clone https://github.com/AloneMonkey/frida-ios-dump

# 2. 列出已安装应用
python3 dump.py -l
# 输出: [pid] [bundle_id] [name]

# 3. 脱壳指定应用
python3 dump.py com.example.app
# 自动完成: 解密 → dump → 生成IPA

# 原理:
# a. Frida attach到目标进程
# b. 调用dlopen/dlsym定位Mach-O header
# c. 读取LC_ENCRYPTION_INFO获取加密段
# d. 调用mprotect修改权限, 读取解密后的内存
# e. 重建Mach-O: 用解密数据替换加密段
# f. 打包为IPA
```

脱壳流程的关键点:frida-server 必须以 root 运行在越狱设备上,且设备的 frida-server 版本要与主机 frida-tools 匹配(2026 年推荐 frida 17.x)。dump 时应用必须处于运行状态(已通过 FairPlay 解密),`dump.py -l` 列出的 `[pid]` 为 0 表示应用未启动,需先手动启动应用再执行 dump。生成的 IPA 可直接用 `class-dump-z`、`Hopper`、`Ghidra` 进行后续静态分析。

### 22.4 dumpdecrypted实战

```bash
# 1. 编译dumpdecrypted.dylib
git clone https://github.com/stefanesser/dumpdecrypted
cd dumpdecrypted && make

# 2. 设置DYLD_INSERT_LIBRARIES注入
# 在目标应用启动时注入:
cp dumpdecrypted.dylib /Library/MobileSubstrate/DynamicLibraries/

# 3. 启动应用, dylib自动dump
# 输出: /var/mobile/Documents/com.example.app.decrypted

# 原理: 
# - 在dylib构造函数中hook dlopen
# - 检测主二进制加载完成
# - 通过LC_ENCRYPTION_INFO确定加密段
# - 读取解密后的内存并写入文件
```

dumpdecrypted 的优势是不依赖 Frida,纯 dylib 注入方式更隐蔽,适合 Frida 被应用检测的场景;劣势是必须通过 `DYLD_INSERT_LIBRARIES` 或 MobileSubstrate 加载,iOS 9 之后系统对 `DYLD_INSERT_LIBRARIES` 有限制(受 `CS_HARD`、`CS_KILL`、`get-task-allow` 影响),实际多用 MobileSubstrate/Tweak 形式注入。

### 22.5 iOS逆向分析工具链

- **class-dump-z**:从 Mach-O 提取 Objective-C 类信息(类名、方法、属性、ivar),生成头文件,是 ObjC 应用逆向的第一步。
- **Hopper Disassembler**:macOS 原生反汇编器,反编译质量高,对 ARM64 支持优秀,适合交互式分析。
- **Ghidra + iRET**:Ghidra 开源免费且支持 iOS 二进制,iRET(iOS Reverse Engineering Toolkit)集成常用脚本。
- **objection**:基于 Frida 的运行时插桩框架,提供高层 iOS 探查 API。

```bash
# objection iOS分析
objection -g "com.example.app" explore

# 转储Keychain
ios keychain dump

# 监控方法调用
ios hooking watch class_method

# 绕过越狱检测
ios jailbreak disable
```

objection 还支持 `ios cookies get`、`ios nsuserdefaults get`、`ios pasteboard monitor` 等命令,覆盖了 iOS 应用数据存储探查的绝大多数场景。

### 22.6 iOS反逆向对抗(2026)

应用层反逆向日益严格,主要检测手段与绕过方法如下:
- **Jailbreak detection**:检查文件路径 `/Cydia`、`/Applications/Cydia.app`、`/private/var/lib/apt`、`/usr/sbin/sshd`;检查能否写入 `/private/`;`fork()` 测试(沙箱内 fork 失败)。绕过:Liberty Lite/Bypass、A-Bypass、Choicy(tweak 选择器,选择性加载 tweak)。
- **Frida detection**:扫描进程列表查找 `frida-server`;扫描默认端口 27042(D-Bus);检测 `frida-agent` 在内存中的特征字符串;检测 `gum-js-loop` 线程。绕过:修改 frida-server 名称、改用 `frida-gadget` 静态嵌入、使用 `objection` 的 anti-anti-frida 模式。
- **Code signing verification**:`SecCodeCheckValidity` 自校验签名,检测重签名;`dtfabric` 校验 entitlement。绕过:Hook `SecCodeCheckValidity` 强制返回 0。
- **Symlink-based jailbreak detection**:`lstat` 检查 `/Applications`、`/Library/Ringtones` 是否为符号链接(越狱后常为 symlink)。绕过:Hook `lstat` 返回正常值。
- **2026 越狱生态**:RootHide jailbreak(隐藏 root,反检测强)与 Dopamine(公开 root,功能全)并存;KFD-based 内核漏洞(iOS 16-17)成为免越狱利用新方向,Azul 脱壳工具即基于 KFD。

### 22.7 Swift逆向挑战

Swift 的引入显著增加了逆向难度:
- **方法名 mangling**:Swift 编译后方法名经过 name mangling,如 `_TtC4App11ViewController`(App 模块的 ViewController 类)、`_TFC4App11ViewController5hellofS0_FT_T_`(实例方法 hello)。反汇编时需用 `swift-demangle` 还原:`swift-demangle _TtC4App11ViewController` 输出 `App.ViewController`。
- **Protocol Witness Table**:Swift 协议通过 witness table 实现动态分发,逆向时需解析 witness table 结构才能确定实际调用的方法,比 ObjC 的 `objc_msgSend` 更复杂。
- **Swift ABI 稳定性**:Swift 5 起 ABI 稳定,不同版本编译的库可互操作,但逆向工具需适配稳定的 ABI 调用约定(`swift::ABI`、`swift_retain`/`swift_release` 引用计数)。
- **2026 Swift 6.0 并发模型**:`actor` 类型的方法调度通过 `swift::runJob`、`swift_task_switch` 实现,异步方法被编译为状态机(`async/await` 展开为 `swift::AsyncContext`),逆向时需识别状态机结构才能还原控制流。`swift-demangle` 已支持 actor 与 concurrency 相关符号。

---

## 23. 恶意软件动态分析 — 沙箱对抗/API监控/YARA规则

### 23.1 恶意软件分析方法论

恶意软件分析是逆向工程的重要分支,目标是提取 IoC、还原行为逻辑、生成检测规则。方法论上分为三类:
- **静态分析**:不执行样本,分析 PE 结构(节区、导入表、资源)、字符串提取(URL、API、互斥体名)、YARA 规则匹配、熵值计算判断是否加壳、反汇编关键函数。优点安全快速,缺点被加壳/混淆样本难以穿透。
- **动态分析**:在隔离沙箱中执行样本,监控 API 调用、文件/注册表/网络行为。优点能穿透简单混淆,缺点触发率有限(样本可能有反沙箱逻辑)。
- **混合分析**:符号执行 + 动态执行,用符号执行探索路径约束,动态执行覆盖具体行为,如 Driller、QSYM。适合分析有复杂条件分支的恶意逻辑。

**分析流程**:样本优先级排序(基于来源、文件类型、沙箱初筛结果)→ 静态特征提取(PE 信息、字符串、YARA)→ 动态行为监控(沙箱 + API hook)→ 行为报告(文件/注册表/网络/进程操作时间线)→ 检测规则产出(YARA/Sigma/Snort)。

### 23.2 沙箱环境搭建

Cuckoo Sandbox 是最经典的开源恶意软件分析沙箱,基于虚拟机 + agent 模式。

```bash
# Cuckoo安装与配置
pip install cuckoo
cuckoo init
# 配置virtualbox隔离网络
# 配置分析agent (Windows VM中的agent.py)

# 提交样本分析
cuckoo submit sample.exe
# 提交URL分析
cuckoo submit --url http://malicious.com
```

Cuckoo 的工作流:主机调度 → 启动干净 VM 快照 → VM 内 agent.py 接收样本并执行 → 行为监控(基于 API hook 注入分析 DLL)→ 网络流量通过 inetsim/fakenet 转发 → 分析完成回滚快照 → 生成 JSON 行为报告与 PCAP。Cuckoo 已基本停更,2026 年主流替代方案:

- **DRAKVUF**:基于 Xen 的硬件级沙箱,无需 VM 内 agent,通过 Xen altp2m 内存事件实现无侵入式 API 监控,隐蔽性极高,可检测反 agent 类恶意软件。
- **Joe Sandbox**:商业沙箱,云端分析,支持多平台(Windows/Linux/macOS/Android),报告详尽。
- **Any.run**:交互式云沙箱,支持分析师手动操作样本(点击、输入),大幅提高触发率,适合分析需要用户交互的恶意软件。

### 23.3 API监控与行为分析

动态分析的核心是 API 监控,通过 hook 关键 API 还原恶意行为。常用工具:**API Monitor**(Windows GUI 工具,实时监控 API 调用与参数)、**Process Monitor**(文件/注册表/进程/网络活动监控)、**Wireshark + FakeNet**(网络流量捕获与模拟 DNS/HTTP 响应)。

关键 API 监控列表:

| API类别 | 关键API | 恶意行为 |
|---------|---------|----------|
| 进程注入 | CreateRemoteThread, NtMapViewOfSection, QueueUserAPC | 进程空洞化、APC 注入、反射式 DLL 注入 |
| 文件操作 | CreateFile, WriteFile, MoveFile | 勒索软件批量加密、文件释放 |
| 注册表 | RegSetValue, RegCreateKey | 持久化(Run 键)、配置存储 |
| 网络 | WSAStartup, connect, InternetOpen, WinHttpSendRequest | C2 通信、数据回传 |
| 加密 | CryptEncrypt, BCryptEncrypt, CryptGenKey | 勒索加密、C2 流量加密 |
| 内存 | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | 跨进程代码注入 |
| 服务 | CreateService, StartService | 服务持久化、提权 |
| 计划任务 | NetScheduleJobAdd, ITaskService | 计划任务持久化 |

监控时应同时记录调用栈,便于关联 API 调用到具体代码模块。

### 23.4 沙箱对抗技术与绕过

恶意软件广泛使用沙箱检测以规避自动分析。常见检测手段:
- **硬件指纹**:CPU 核心数 < 4、内存 < 4GB、硬盘 < 60GB 视为虚拟机;检查 `CPUID` 的 hypervisor bit;检查 BIOS 字符串中的 `VMware`/`VirtualBox`/`QEMU`。
- **用户交互检测**:启动后等待鼠标移动、剪贴板变化、窗口焦点切换,长时间无交互则判定为沙箱。
- **时间延迟**:`Sleep(大数值)`(如 600 秒)等待沙箱超时退出;`GetTickCount` 反 timing 检测;`rdtsc` 测量指令间隔判断是否被插桩。
- **进程检测**:遍历进程查找 `vmtoolsd.exe`、`vboxservice.exe`、`xenservice.exe`、`cuckoo.exe`、`python.exe`(Cuckoo agent)。
- **MAC 地址**:`08:00:27`(VirtualBox OUI)、`00:05:69`/`00:0C:29`/`00:50:56`(VMware OUI)、`00:15:5D`(Hyper-V)。
- **时间戳**:检查 PE 编译时间与当前运行时间差值,异常大可能为沙箱重置环境。

绕过技术(分析侧):
- 修改沙箱配置使其更真实:增加 CPU 核心、安装常用软件(Office、浏览器)、注入真实用户活动模拟(鼠标抖动脚本)。
- Hook `Sleep` 函数加速执行(Cuckoo 的 `sleep_skipper` 模块),将 `Sleep(N)` 直接返回。
- 使用 DRAKVUF(无 agent)避免进程检测,因 Xen 事件监控不注入任何分析模块。
- NVIDIA GPU 指纹模拟(2026):某些高级样本检测 GPU 型号,沙箱需模拟真实 GPU EDID。

### 23.5 YARA规则编写

YARA 是恶意软件特征匹配的事实标准,规则由 meta、strings、condition 三段构成。

```yara
rule Ransomware_2026_Generic {
    meta:
        description = "Generic 2026 ransomware detection"
        author = "analyst"
        date = "2026-07"
    
    strings:
        // 加密相关API
        $api1 = "BCryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        // 持久化注册表键
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        // C2通信特征
        $c2 = { 63 6f 6e 6e 65 63 74 00 ?? ?? ?? ?? 68 74 74 70 }
        // 勒索信特征
        $note = "YOUR FILES ARE ENCRYPTED" nocase
        
    condition:
        // PE文件且匹配多个特征
        uint16(0) == 0x5A4D and
        ($api1 or $api2) and
        $reg1 and
        ($c2 or $note) and
        filesize < 5MB
}

// 2026: AI生成YARA规则
// 使用LLM从恶意软件分析报告中自动提取IoC并生成YARA规则
// 工具: YaraForge, Loki (YARA-based IOC scanner)
```

YARA 规则编写要点:strings 段善用 `ascii`、`wide`(UTF-16,Windows 常用)、`nocase`、`xor`(变异字符串)、hex 与 regex;condition 段合理组合,避免过松(误报)或过紧(漏报),推荐用 `and` 串联多类特征(文件类型 + 行为特征 + 字符串)。`filesize` 限制可加速扫描并排除大文件误报。

2026 年趋势:LLM 辅助 YARA 生成。YaraForge 从 ThreatFox、MalwareBazaar 等威胁情报源自动提取 IoC 生成规则;Loki 基于 YARA 的 IOC 扫描器集成社区规则库;部分团队用 GPT-4/Claude 阅读分析报告自动产出候选 YARA 规则,人工审校后入库。

### 23.6 2026恶意软件趋势

- **AI 辅助恶意软件**:LLM 生成多态代码(每次编译变量名、控制流不同)、自动化规避代码生成、钓鱼邮件文本生成。
- **Living-off-the-Land (LotL)**:大量使用系统自带工具(WMI、PowerShell、`certutil`、`mshta`、`rundll32` 等 LOLBins),无文件落地,传统特征检测难以覆盖。
- **无文件恶意软件**:PowerShell + .NET assembly 内存加载(Assembly.Load),通过 `System.Management.Automation` 直接调用,内存执行后不落盘。
- **Linux IoT 恶意软件**:Mirai 变种持续演进,ARM/MIPS 架构 DDoS botnet,利用弱口令与 N-day 漏洞传播,2026 年出现针对 RISC-V 设备的变种。
- **macOS 恶意软件**:针对 M1/M2 ARM64 芯片原生编译,Shadowhammer 变种窃取 Keychain,XCSSET 变种感染 Xcode 项目。
- **eBPF rootkit**:Linux 6.x 内核利用 eBPF 程序隐藏进程/文件/网络连接,绕过传统内核模块检测,需 eBPF verifier 漏洞或 root 权限加载。

---

## 24. DRM与许可证保护逆向 — keygen/许可证验证patch/硬件指纹

### 24.1 DRM保护技术全景

| 保护类型 | 技术 | 逆向难度 | 常见应用 |
|----------|------|----------|----------|
| 许可证文件 | RSA/ECDSA 签名验证 | 高(需私钥) | 商业软件、JetBrains 系列 |
| 硬件指纹 | CPU ID + MAC + 硬盘序列号 → 机器码绑定 | 中 | 单机软件、专业 CAD |
| 在线激活 | 请求服务器验证,返回激活令牌 | 高(需模拟服务器) | Adobe、Windows、游戏 |
| USB Dongle | 硬件加密狗(Feitian、SafeNet),代码与 Dongle 交互 | 高(需硬件) | 工业软件、财务软件 |
| 代码虚拟化 | VMP/Themida 保护验证逻辑 | 极高 | 游戏、专业软件 |
| White-box crypto | AES 密钥嵌入代码,无法直接提取 | 极高 | DRM、流媒体保护 |

### 24.2 许可证验证逆向方法论

通用方法论分三步:
1. **定位验证函数**:通过字符串引用(搜索 "License invalid"、"Trial expired"、"Register" 等)、API 调用模式(`RegQueryValue`、`CreateFile` 读许可证文件、`CryptVerifySignature`)、交叉引用定位验证入口。IDA 中可结合 F5 伪代码快速理解逻辑。
2. **分析验证逻辑**:判断比较方式(明文比较、哈希比较、签名验证)、密钥来源(硬编码、文件、服务器)、是否在线请求。签名验证类需关注公钥位置与签名算法(RSA-PKCS#1、ECDSA);硬件指纹类需追踪机器码生成函数。
3. **选择攻击策略**:
   - **Patch**:修改验证函数返回值(jump patch 或返回值 patch),最简单但易被完整性校验检测。
   - **Keygen**:还原密钥/序列号生成算法,编写注册机,最彻底但难度最高(需完全逆向算法)。
   - **Hook**:运行时 Hook 验证函数返回 true,不需修改磁盘文件,适合带完整性校验的目标。
   - **服务器模拟**:针对在线激活,搭建假激活服务器返回有效响应。

### 24.3 Keygen编写实战

以一个典型许可证验证为例,逆向分析发现算法后编写注册机。

```python
# 典型许可证验证: name → serial 验证
# 逆向分析发现算法:
# 1. name转换为ASCII
# 2. 每个字符乘以位置(i+1)
# 3. 求和后异或固定magic: 0xDEADBEEF
# 4. 转为十六进制字符串

def generate_serial(name):
    """根据逆向分析结果编写注册机"""
    ascii_values = [ord(c) for c in name]
    total = sum(v * (i + 1) for i, v in enumerate(ascii_values))
    serial = total ^ 0xDEADBEEF
    return f"{serial:08X}"

# 验证: generate_serial("admin") → "A1B2C3D4"
```

Keygen 编写要点:必须完整还原算法的每一步(包括字节序、大小端、有符号/无符号),一个细节错误就会导致生成的序列号无效。逆向时常通过动态调试(在比较函数处下断点)观察实际计算中间值,与自己的实现逐字节比对。对于涉及自定义哈希或加密的算法,建议用 Unicorn 模拟执行原始函数验证注册机正确性。

### 24.4 Patch验证函数

Patch 是最直接的绕过方式,核心是定位关键跳转并修改。

```assembly
; 原始验证函数:
; mov eax, [ebp+8]     ; 加载验证结果
; test eax, eax
; jz  fail             ; 如果验证失败则跳转
; ... 成功路径

; Patch方案1: NOP掉条件跳转
; jz fail → nop nop (90 90)
; 6字节: 0F 84 xx xx xx xx → 90 90 90 90 90 90

; Patch方案2: 修改返回值
; mov eax, [ebp+8]
; test eax, eax
; jz fail
; → 改为:
; mov eax, 1           ; 直接返回成功
; ret
; B8 01 00 00 00 C3

; Patch方案3: 入口直接返回true
; push ebp; mov ebp, esp
; → 改为:
; mov eax, 1; ret
; B8 01 00 00 00 C3
```

搜索关键跳转技巧:x64dbg 中用"搜索 → 条件跳转"列出所有 `jz/jnz/jne` 指令;跟踪验证函数时关注比较指令后的条件跳转。IDA 中 F5 查看伪代码,定位 `if (!check_license()) return false;` 这类关键判断,反向定位到汇编跳转。Patch 后需注意完整性校验(CRC32、数字签名),许多软件会校验自身代码段哈希,此时需同时 patch 校验函数或改用 Hook 方案。

### 24.5 硬件指纹绕过

硬件指纹通过组合 CPU ID、MAC 地址、硬盘序列号、卷序列号、主板序列号生成机器码,绑定许可证。绕过思路是分析指纹生成函数,Hook 相关 API 返回伪造值。

- **分析指纹生成**:Hook `GetVolumeInformation`(卷序列号)、`GetAdaptersInfo`(MAC)、`DeviceIoControl`(硬盘序列号,IOCTL `IOCTL_STORAGE_QUERY_PROPERTY`)、`__cpuid`(CPU ID)。
- **模拟硬件指纹**:拦截 API 返回伪造值。

```javascript
// Frida Hook硬件指纹API
Interceptor.attach(Module.getExportByName('kernel32.dll', 'GetVolumeInformationA'), {
    onLeave: function(retval) {
        // 伪造卷序列号
        var serialPtr = this.context.esp.add(0x14); // 参数位置
        serialPtr.writeU32(0x12345678); // 伪造的序列号
    }
});
```

- **虚拟机指纹**:修改 VM BIOS 序列号(VMware `.vmx` 文件 `serial` 字段)、MAC 地址(`ethernet0.address`)。
- **2026 TPM 2.0 远程证明绕过**:Windows 11 强制 TPM 2.0,部分软件通过 TPM 远程证明绑定设备。绕过方式是使用 vTPM(虚拟 TPM)模拟,或在 hypervisor 层拦截 TPM 命令返回伪造的 PCR 值与签名。

### 24.6 在线激活服务器模拟

在线激活类保护需抓包分析激活协议,搭建假服务器返回有效响应。

```python
# Flask模拟激活服务器
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/activate', methods=['POST'])
def activate():
    machine_id = request.json.get('machine_id')
    # 返回有效激活响应(逆向分析获得的格式)
    return jsonify({
        'status': 'success',
        'license_key': 'VALID-KEY-' + machine_id[:8],
        'expires': '2099-12-31',
        'signature': '...'  # 可能需要提取的签名
    })

# 使用: 修改hosts文件将激活服务器指向本地
# 127.0.0.1 activate.vendor.com
```

实施步骤:抓包(Burp/mitmproxy)分析激活请求与响应格式 → 用 Flask/Node 搭建模拟服务器 → 修改 `hosts` 文件将激活域名指向本地 → 若响应含签名则需逆向签名验证逻辑,可能需提取客户端公钥对应的伪造私钥(若签名验证在客户端,且公钥可替换则更简单)。SSL Pinning 绕过:若激活使用 HTTPS 且客户端校验证书,需用 Frida Hook `SecTrustEvaluate`/`SSLHandshake` 或替换客户端内置 CA 证书。2026 年云激活服务多采用 OAuth/JWT token,逆向时需分析 token 签名算法(JWT 的 HS256/RS256),伪造签名需获取共享密钥或私钥。

### 24.7 USB Dongle模拟

USB Dongle(加密狗)通过硬件存储密钥,软件运行时与 Dongle 交互验证。逆向策略:
- **提取 Dongle 固件**:用逻辑分析仪(如 Saleae)抓取 USB 通信,记录请求-响应对;或用 USBPcap 在软件运行时抓包,分析 Dongle 协议。
- **软件模拟 Dongle**:编写虚拟 USB 设备驱动(Windows 用 WinUSB/libusb,或基于 usbip 框架),在驱动层响应软件的 Dongle 请求,返回抓取的合法响应。
- **工具**:USBPcap 抓包分析、`qemu` USB passthrough 将物理 Dongle 透传到虚拟机、`usbip` 跨网络共享 Dongle。
- **2026 趋势**:USB Dongle + Cloud 双重验证,本地 Dongle 校验通过后还需云端二次验证;逆向需同时模拟 Dongle 响应与云端请求,难度提升。部分厂商改用 SDKey/TF Card 形态的智能卡 Dongle,协议更复杂。

### 24.8 White-box密码学对抗

White-box 密码学将密钥嵌入在查找表中,即使在白盒环境(攻击者完全控制执行)下也无法直接提取密钥,常用于 DRM 与支付保护。以 White-box AES 为例,密钥被编码进 T-table 与外部编码,直接逆向查找表无法还原密钥。

攻击方法:
- **Differential Computation Analysis (DCA)**:类似硬件侧信道的 DPA,对白盒实现执行大量已知明文,记录中间值,用相关性分析恢复密钥字节,适用于未做足够混淆的白盒实现。
- **Differential Fault Analysis (DFA)**:在白盒执行中注入故障(如翻转中间状态字节),通过故障输出与正常输出的差异恢复密钥,经典攻击可在 2 组故障下恢复 AES-128 密钥。
- **BGE attack**:针对 Chow 等人提出的白盒 AES 实现的代数攻击,利用 T-table 的代数结构还原密钥,对原始 Chow 实现有效。
- **工具**:SideTrail(侧信道分析框架)、WhibOx contest winners(历届白盒密码竞赛的攻击代码)。

2026 年趋势:NIST 推进 White-box 密码学标准化(结合 PQC 后量子密码),新标准强调抗 DCA/DFA 能力;但学术界持续发现对标准化候选方案的攻击,White-box 与攻击者的博弈仍在持续。对逆向工程师而言,面对 White-box 保护的目标,DCA/DFA 仍是首选低成本攻击手段。

---

## 25. NEXT ROUTING

| 发现 | 下一步技能 |
|---|---|
| 移动应用中发现漏洞 | [mobile-app-security-testing](../mobile-app-security-testing/SKILL.md) |
| 二进制中发现漏洞需评估影响 | [vulnerability-assessment](../vulnerability-assessment/SKILL.md) |
| 逆向发现加密弱点 | [jwt-oauth-token-attacks](../jwt-oauth-token-attacks/SKILL.md) |
| 固件中发现命令注入 | [cmdi-command-injection](../cmdi-command-injection/SKILL.md) |
| 逆向发现反序列化漏洞 | [deserialization-insecure](../deserialization-insecure/SKILL.md) |
| .NET/Java应用脱壳后发现漏洞 | [mobile-app-security-testing](../mobile-app-security-testing/SKILL.md) |
| 恶意软件分析需应急响应 | [incident-response](../incident-response/SKILL.md) |
| 符号执行发现漏洞需评估 | [vulnerability-assessment](../vulnerability-assessment/SKILL.md) |
| DRM逆向发现认证绕过 | [authbypass-authentication-flaws](../authbypass-authentication-flaws/SKILL.md) |
| 需要全栈融合攻击 | [sinian-omnipotent](../sinian-omnipotent/SKILL.md) |
