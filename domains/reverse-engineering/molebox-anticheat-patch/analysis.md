# PatchDLL — MoleBox 反作弊补丁 技术要点

- 目标形态: 32 位 Windows 程序, MoleBox 加壳(自带解密外壳), 反作弊逻辑要到 OEP 外壳解密后才在内存中可见
- 关键偏移(与版本强相关, 换版本需重新定位): 服务端 OEP = `base + 0x86AA1FE`; 客户端 OEP = `base + 0x04F431FE`; 反作弊 call = `MoleBoxBase + 0x99B6C`; MoleBox 基址全局变量 = `0x00400000 + 0x86B59B0`(仅 Loader2 轮询使用)
- 补丁动作(两条路线一致): 解锁目标页为 RWX → 原地写入 5 字节 `0x90`(NOP) 覆盖反作弊 call → 恢复页属性
- 路线一 `patch.dll`(静态输入表绑定): `DllMain` → `InitMemoryPatch()` 在原程序 `hGame + 0x86AA1FE` 处写 `E9` 相对 JMP 挂到裸函数 `MyOepHook`; 裸函数内 `pushad` 保现场, 从 EAX 取 MoleBox 基址, 直接经堆栈传参调 `VirtualProtect`(不调 C 函数以免破坏寄存器), 写完 NOP 后 `popad` + 执行被覆盖的 `push eax` + `jmp g_HookReturnAddress` 回原流程
- 路线一源码细节: `InitMemoryPatch()` 中 `hookAddress = 0xE9;` 按字面是把常量赋给指针变量本身(注释意图为写 jmp 操作码, 疑为漏写解引用 `*hookAddress = 0xE9;`); 其后 `*(DWORD*)(hookAddress + 1)` 将解引用 0xEA — 按此原文编译运行会出现异常; 调试器路线(Loader.cpp)不涉及该代码
- 路线二 `Loader.exe`(调试器, 不注入): `CreateProcessA("game.exe", ..., DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED)` 挂起拉起目标, 找不到回退 `explorers.exe`; `NtQueryInformationProcess(ProcessBasicInformation)` 拿 PEB → 读 `PEB + 8` 取镜像基址(兼容 ASLR, 失败回退 0x00400000)
- 硬件断点: `Dr0 = OEP1`, `Dr1 = OEP2`, `Dr7 = 0x00000005`(0x1 开 DR0、0x4 开 DR1 本地执行断点); 不修改目标内存任何字节, 加壳程序的内存扫描查不出来
- 命中 `EXCEPTION_SINGLE_STEP` 且地址等于任一 OEP → `GetThreadContext(CONTEXT_FULL)` 从 EAX 取 MoleBox 基址 → `VirtualProtectEx` + `WriteProcessMemory` 写 5 个 NOP → 清空 `Dr0/Dr1/Dr7` → `DebugActiveProcessStop` 平滑脱附不卡死进程
- Loader2(纯外部轮询存档): `Sleep(0)` 死等 OEP 处解密出 `0x50`(push eax) → 死等全局基址变量变为非零 → 等反作弊 call 处解密出 `0xE8`(call) 的瞬间写 NOP; 不用调试器、不注入 DLL, 时序全靠抢
- Loader3(控制台版存档): 单硬件断点 + 只针对客户端 OEP `0x00400000 + 0x4F431FE`
- 编译: 必须 32 位工具链(`vcvars32.bat`); 参数 `/MT /O1 /GS- /source-charset:utf-8 /D _WIN32_WINNT=0x0601 /D WINVER=0x0601`, 链接 `/NXCOMPAT:NO /SAFESEH:NO` 避免注入老程序被拦; 脚本内 VS 路径为本机硬编码(`E:\Program Files\...`), 换机需改
- 日志: 默认静默, 加 `-l` 经 `OutputDebugStringA` 输出(DebugView 查看); 备注: 硬件断点仅 DR0–DR3 四个, 本项目已占用 DR0/DR1

@TGSEC社区 · @TGSEC-Qtzuu 整理
