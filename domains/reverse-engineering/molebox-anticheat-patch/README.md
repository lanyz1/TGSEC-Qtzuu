# PatchDLL

针对 **MoleBox 加壳**的目标程序，在其 OEP（原始入口点）处挂钩，把位于 `MoleBoxBase + 0x99B6C` 的
**反作弊 call 抹成 5 个 NOP**，让该反作弊逻辑永远没有机会执行。

> 背景：这个"反作弊"在触发时会对本机做出破坏性惩罚（删除盘符、篡改系统时间等），
> 因此本项目的目的只是**阻止它跑起来**，属于本地逆向研究性质的自保手段，不针对任何服务器数据。

## 两条技术路线

仓库里同时保留了两套实现，思路不同，可以互相印证。

### 路线一：DLL 注入 —— `AntiCheatPatch.c` → `patch.dll`

由外部工具（如 Stud_PE）把 `patch.dll` 绑定进目标程序的静态输入表，加载后走 `DllMain`：

1. `InitMemoryPatch()` 在原程序 `hGame + 0x86AA1FE` 处原地写入 `E9` 相对跳转，挂钩到裸函数 `MyOepHook`；
   同时记下 `g_HookReturnAddress = hookAddress + 1`，用于之后补回被覆盖掉的原始指令。
2. `MyOepHook` 用 `__declspec(naked)` 严格保证寄存器与堆栈平衡：
   - `pushad` 备份全部通用寄存器；
   - 此时 `EAX` 里已经是解密完毕的 MoleBox 真实基址，`mov esi, eax; add esi, 0x99B6C` 算出反作弊 call 的绝对地址；
   - **在裸函数内直接通过堆栈传参调用 `VirtualProtect`**（不调 C 函数，避免破坏寄存器环境），把该页改成 `PAGE_EXECUTE_READWRITE`；
   - 原地写 5 个 `0x90`（NOP）；
   - `popad` 恢复寄存器，执行原本被覆盖的机器码 `push eax`（`0x50`），再 `jmp g_HookReturnAddress` 跳回原程序。
3. 另外导出一个空函数 `__declspec(dllexport) void __cdecl InitAntiCheatPatch()`，
   **纯粹作为占位导出**，供 Stud_PE 做静态输入表绑定用。

### 路线二：调试器加载 —— `Loader.cpp` → `Loader.exe`

**完全不注入任何 DLL**，因此没有模块特征可供扫描：

1. `CreateProcessA("game.exe", ..., DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, ...)` 以挂起状态拉起目标，
   找不到时回退到 `explorers.exe`；Loader 自己成为顶级调试器。
2. `GetProcessImageBase()` 用 `NtQueryInformationProcess` 拿到 PEB 地址，再 `ReadProcessMemory` 读 `PEB + 8`
   得到真实镜像基址（**兼容 ASLR**，读失败时退回默认 `0x00400000`）。
3. 给主线程设置 **DR0 / DR1 双硬件执行断点**，分别指向两个 OEP：
   - `oepAddress1 = base + 0x86AA1FE`（服务端）
   - `oepAddress2 = base + 0x04F431FE`（客户端）
   - `Dr7 = 0x00000005`（`0x1` 开启 DR0 本地执行断点，`0x4` 开启 DR1）

   硬件断点不修改目标内存任何字节，加壳程序的内存扫描查不出来。
4. `ResumeThread` 后进入 `WaitForDebugEvent` 循环，命中 `EXCEPTION_SINGLE_STEP` 且地址等于任一 OEP 时：
   - `OpenThread` + `GetThreadContext(CONTEXT_FULL)` 抓下断那一刻的寄存器，**从 `EAX` 取出 MoleBox 基址**；
   - 算出 `targetAntiCheatCall = moleBoxBase + 0x99B6C`；
   - `VirtualProtectEx` 解锁 → `WriteProcessMemory` 写入 5 个 `0x90` → 恢复原页属性；
   - **过河拆桥**：清空 `Dr0`/`Dr1`/`Dr7`，让主线程恢复纯净状态；
   - `DebugActiveProcessStop` 平滑脱离调试关系，不卡死目标进程。

### 另外两份早期实现（保留作思路存档）

| 文件 | 思路 |
|---|---|
| `Loader2.cpp` | 纯外部轮询：`Sleep(0)` 死等 OEP 处解密出 `0x50`（`push eax`），再死等全局基址变量 `0x00400000 + 0x86B59B0` 变为非零拿到 MoleBox 基址，最后等反作弊 call 处解密出 `0xE8` 的瞬间写 NOP。不用调试器、不注入 DLL，但时序全靠抢。 |
| `Loader3.cpp` | 调试器 + 单个硬件断点的控制台版，只针对客户端 OEP `0x00400000 + 0x4F431FE`。 |

## 关键偏移一览

| 名称 | 表达式 | 说明 |
|---|---|---|
| 服务端 OEP | `base + 0x86AA1FE` | 挂钩点，此处原指令为 `push eax`（`0x50`） |
| 客户端 OEP | `base + 0x04F431FE` | 挂钩点，同上 |
| 反作弊 call | `MoleBoxBase + 0x99B6C` | 被 5 个 NOP 覆盖的目标 |
| 全局基址变量 | `0x00400000 + 0x86B59B0` | 外壳把 MoleBox 基址写进这里的全局指针（仅 Loader2 用） |

> 这些偏移与具体版本强相关，换版本必须重新定位。

## 编译

两份脚本都**必须用 32 位工具链**（`vcvars32.bat`），目标是 x86。

```bat
build.bat    :: 生成 patch.dll
loader.bat   :: 生成 Loader.exe
```

实际使用的编译参数：

```bat
cl.exe /MT /O1 /GS- /source-charset:utf-8 /D _WIN32_WINNT=0x0601 /D WINVER=0x0601 ^
       AntiCheatPatch.c /link /SUBSYSTEM:WINDOWS /OUT:patch.dll /NXCOMPAT:NO /SAFESEH:NO
```

几个参数是有意为之：

- `/MT` 静态链接 CRT，目标机不需要额外运行库；
- `/O1` 体积优先；`/GS-` 关闭栈保护（裸函数里不能有 cookie 检查）；
- `/D _WIN32_WINNT=0x0601` 兼容到 Windows 7；
- `/NXCOMPAT:NO`、`/SAFESEH:NO` 关闭 PE 的 DEP / SEH 标记，避免注入到老程序时被拦。

脚本里 VS 路径是**本机硬编码**的，换机器要改：

```bat
call "E:\Program Files\Microsoft Visual Studio\VC\Auxiliary\Build\vcvars32.bat"
```

## 使用

1. 把 `Loader.exe`（或 `patch.dll` + Stud_PE 绑定好的目标程序）与目标 exe 放在同一目录；
2. 直接运行 `Loader.exe`。默认静默，加 `-l` 参数会通过 `OutputDebugStringA` 输出日志
   （用 DebugView 之类的工具查看），例如：
   - `[AntiCheat-Loader] Base = 0x........ | OEP1 = 0x........ | OEP2 = 0x........`
   - `[AntiCheat-Patch] MATCH: Hit OEP Hardware Breakpoint at 0x........`
   - `[AntiCheat-Loader] Anti-cheat bypassed. Loader closing smoothly.`

## 目录说明

| 文件 | 说明 |
|---|---|
| `AntiCheatPatch.c` | patch.dll 源码（DLL 注入路线） |
| `Loader.cpp` | Loader.exe 源码（调试器 + 双硬件断点，GUI 子系统） |
| `Loader2.cpp` / `Loader3.cpp` | 早期实现存档 |
| `build.bat` / `loader.bat` | 编译脚本 |
| `patch.dll` | 已编译产物 |
| `Loader.exe` | 由 `Loader.cpp` 编译（已核对：GUI 子系统且含 `AntiCheat-Loader` 字符串） |
| `Game_Loader.exe` / `Server_Loader.exe` | 更早的控制台版本产物，分别对应客户端与服务端两个 OEP；源码对应关系已不可考，仅作存档 |
| `AntiCheatPatch.lib` / `.exp` | 早期直接编译留下的导入库与导出文件 |

## 注意事项

- 仅供本地逆向研究与自保使用；请自行确认是否符合目标软件的使用条款。
- 硬件断点只有 4 个（DR0~DR3），本项目已占用 DR0/DR1。
- `patch.dll` 路线依赖 Stud_PE 做静态输入表绑定，属于**改文件**；`Loader.exe` 路线不改文件、不留模块，
  隐蔽性更好，两者按需选用。
