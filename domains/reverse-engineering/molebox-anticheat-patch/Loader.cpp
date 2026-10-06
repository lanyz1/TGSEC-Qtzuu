#include <windows.h>
#include <winternl.h>
#include <stdio.h>
 // 声明未公开的内核调试寄存器标志，用于精确控制硬件断点
 // (winnt.h 已定义，这里用 ifndef 避免重定义警告)
 #ifndef CONTEXT_DEBUG_REGISTERS
 #define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L)
 #endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// 动态获取游戏在内存中的真实加载基址 (兼容 ASLR)
DWORD GetProcessImageBase(HANDLE hProcess) {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) return 0x00400000;

    pfnNtQueryInformationProcess NtQueryInfoProc = 
        (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProc) return 0x00400000;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;
    if (NtQueryInfoProc(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) >= 0) {
        DWORD pebAddress = (DWORD)pbi.PebBaseAddress;
        DWORD imageBaseAddress = 0;
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddress + 8), &imageBaseAddress, 4, &bytesRead)) {
            return imageBaseAddress;
        }
    }
    return 0x00400000;
}

void SafeLog(bool bSilent, const char* message) {
    if (!bSilent) {
        OutputDebugStringA(message);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    bool bSilent = true; 
    if (strstr(lpCmdLine, "-l") != NULL) {
        bSilent = false; 
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    SafeLog(bSilent, "[AntiCheat-Loader] Launching process in suspended debug mode...");

    // 1. 以调试模式 + 挂起状态拉起目标程序
    if (!CreateProcessA("game.exe", NULL, NULL, NULL, FALSE, 
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        if (!CreateProcessA("explorers.exe", NULL, NULL, NULL, FALSE, 
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        	SafeLog(bSilent, "[AntiCheat-Loader] Cannot find exe!");
        	return -1;
        }
    }

    // 2. 动态自适应 ASLR 基址
    DWORD gameBaseAddress = GetProcessImageBase(pi.hProcess);
    
    // 【核心微调：计算两个不同的 OEP 目标挂钩点】
    DWORD oepAddress1 = gameBaseAddress + 0x86AA1FE; // 第一个程序的 OEP
    DWORD oepAddress2 = gameBaseAddress + 0x04F431FE; // 第二个程序的 OEP

    char logBuf[256];
    sprintf_s(logBuf, sizeof(logBuf), "[AntiCheat-Loader] Base = 0x%08X | OEP1 = 0x%08X | OEP2 = 0x%08X", gameBaseAddress, oepAddress1, oepAddress2);
    SafeLog(bSilent, logBuf);

    // 3. 【高阶技术：同时激活 DR0 和 DR1 双硬件断点】
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(pi.hThread, &ctx);
    
    ctx.Dr0 = oepAddress1;  // 断点 1
    ctx.Dr1 = oepAddress2;  // 断点 2
    
    // Dr7 控制寄存器配置：
    // 0x00000001 (开启 DR0 本地执行断点) | 0x00000004 (开启 DR1 本地执行断点) = 0x00000005
    ctx.Dr7 = 0x00000005;              
    
    SetThreadContext(pi.hThread, &ctx);

    // 4. 恢复线程，进入双重雷达侦听循环
    ResumeThread(pi.hThread);

    DEBUG_EVENT dbgEvent;
    bool bPatchSuccess = false;

    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_RECORD extRec = dbgEvent.u.Exception.ExceptionRecord;

            // 5. 命中硬件单步断点异常
            if (extRec.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                DWORD hitAddress = (DWORD)extRec.ExceptionAddress;

                // 【分支甄别】：判断到底是哪一个程序的 OEP 被踩中了
                if (hitAddress == oepAddress1 || hitAddress == oepAddress2) {
                    
                    sprintf_s(logBuf, sizeof(logBuf), "[AntiCheat-Patch] MATCH: Hit OEP Hardware Breakpoint at 0x%08X", hitAddress);
                    SafeLog(bSilent, logBuf);

                    // 原地断下，抓取触发线程的句柄与上下文
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dbgEvent.dwThreadId);
                    CONTEXT threadCtx;
                    threadCtx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread, &threadCtx);

                    // 6. 无论是哪个 OEP，此时 EAX 里一定都存着热气腾腾的 MoleBox 基址
                    DWORD moleBoxBase = threadCtx.Eax;
                    
                    // 反作弊偏移保持不变量 (MoleBox基址 + 0x99B6C)
                    DWORD targetAntiCheatCall = moleBoxBase + 0x99B6C;

                    // 7. 强行解除内存属性锁定并抹除为 5 个 NOP
                    DWORD oldProtect;
                    VirtualProtectEx(pi.hProcess, (LPVOID)targetAntiCheatCall, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

                    BYTE nopBytes[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
                    WriteProcessMemory(pi.hProcess, (LPVOID)targetAntiCheatCall, nopBytes, 5, NULL);

                    VirtualProtectEx(pi.hProcess, (LPVOID)targetAntiCheatCall, 5, oldProtect, &oldProtect);

                    // 8. 过河拆桥：彻底清空所有硬件调试寄存器，恢复纯净状态
                    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    threadCtx.Dr0 = 0;
                    threadCtx.Dr1 = 0;
                    threadCtx.Dr7 = 0; 
                    SetThreadContext(hThread, &threadCtx);
                    CloseHandle(hThread);

                    bPatchSuccess = true;
                }
            }
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);

        // 打补丁成功后，平滑脱离控制权
        if (bPatchSuccess) {
            DebugActiveProcessStop(pi.dwProcessId); 
            break;
        }
    }

    SafeLog(bSilent, "[AntiCheat-Loader] Anti-cheat bypassed. Loader closing smoothly.");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}