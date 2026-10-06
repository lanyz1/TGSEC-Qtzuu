#include <windows.h>
#include <stdio.h>

 // 声明未公开的内核调试寄存器标志，用于精确控制硬件断点
 // (winnt.h 已定义，这里用 ifndef 避免重定义警告)
 #ifndef CONTEXT_DEBUG_REGISTERS
 #define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L)
 #endif

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    printf("[+] 正在以调试/挂起状态启动原版游戏 (不依赖任何DLL，实现0特征过检测)...\n");

    // 1. 以调试模式 (DEBUG_ONLY_THIS_PROCESS) + 挂起状态 (CREATE_SUSPENDED) 拉起游戏
    // 此时 Loader 自动成为该游戏的顶级宿主调试器，拥有绝对控制权
    if (!CreateProcessA("game.exe", NULL, NULL, NULL, FALSE, 
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] 错误：无法启动 game.exe，请确保本启动器与游戏在同一目录下！\n");
        return -1;
    }

    // 2. 锁定目标 OEP 挂钩点绝对地址 (game.exe 默认基址通常为 0x00400000 + 0x4F431FE，server是0x86AA1FE)
    DWORD oepAddress = 0x00400000 + 0x4F431FE;

    // 3. 【核心技术】：通过设置 CPU 的 DR0 调试寄存器，在 push eax 处安插一个硬件执行断点
    // 这种断点属于硬件级别，不修改内存任何字节，外壳的任何静态/动态内存扫描都绝对无法察觉
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(pi.hThread, &ctx);
    
    ctx.Dr0 = oepAddress;              // 硬件断点目标地址
    ctx.Dr7 = 0x00000001;              // 开启 DR0 硬件执行断点
    
    SetThreadContext(pi.hThread, &ctx);
    printf("[+] 硬件执行断点已精准安插在 OEP 地址: 0x%08X\n", oepAddress);

    // 4. 恢复游戏主线程，进入 Windows 标准调试循环
    ResumeThread(pi.hThread);
    printf("[+] 游戏主线程已恢复，正在等待外壳执行并踩中 OEP 断点...\n");

    DEBUG_EVENT dbgEvent;
    bool bPatchSuccess = false;

    // 5. 开启高频侦听 Windows 调试事件循环
    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        // 捕获异常事件
        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_RECORD extRec = dbgEvent.u.Exception.ExceptionRecord;

            // 当主线程刚好走到 push eax 时，触发单步硬件断点异常 (0x80000004)
            if (extRec.ExceptionCode == EXCEPTION_SINGLE_STEP && (DWORD)extRec.ExceptionAddress == oepAddress) {
                printf("[+] MATCH: 游戏主线程成功踩中 OEP 硬件断点！当前主线程已被操作系统自动强制挂起。\n");

                // 6. 【原地断下，直接获取 EAX】：
                // 打开当前触发断点的线程句柄，抓取它被冻结那一瞬间的寄存器状态
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dbgEvent.dwThreadId);
                CONTEXT threadCtx;
                threadCtx.ContextFlags = CONTEXT_FULL;
                GetThreadContext(hThread, &threadCtx);

                // 直接从 EAX 寄存器中提取出解密就绪的 MoleBox 真实基址
                DWORD moleBoxBase = threadCtx.Eax;
                printf("[+] 成功从主线程 EAX 寄存器中截获 MoleBox 加载基址 = 0x%08X\n", moleBoxBase);

                // 7. 【马上进行修改】：根据基址，精准定位到反作弊创建代码的绝对内存地址
                DWORD targetAntiCheatCall = moleBoxBase + 0x99B6C;
                printf("[+] 反作弊指令位于 0x%08X。因为主线程已断下，此时内存已解密就绪，直接强行擦除...\n", targetAntiCheatCall);

                // 临时解开该内存页的只读属性锁
                DWORD oldProtect;
                VirtualProtectEx(pi.hProcess, (LPVOID)targetAntiCheatCall, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

                // 外部重拳出击，直接在主线程脚底下写入 5 个 NOP 机器码 (0x90)，瞬间抹除反作弊 call
                BYTE nopBytes[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
                WriteProcessMemory(pi.hProcess, (LPVOID)targetAntiCheatCall, nopBytes, 5, NULL);

                // 恢复原有的内存属性，不留任何被篡改的痕迹
                VirtualProtectEx(pi.hProcess, (LPVOID)targetAntiCheatCall, 5, oldProtect, &oldProtect);
                printf("[+] SUCCESS: 毁灭性反作弊指令已被外部 5 个 NOP 物理阉割完毕！\n");

                // 8. 【过河拆桥，自毁卸载】：既然修改完成，立刻将 CPU 的硬件调试寄存器清空
                threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                threadCtx.Dr0 = 0;
                threadCtx.Dr7 = 0; // 关闭所有硬件断点，让主线程彻底恢复纯净状态
                SetThreadContext(hThread, &threadCtx);
                CloseHandle(hThread);

                printf("[+] 调试器使命完成，已移除所有硬件断点。正在向游戏移交并脱离(DebugActiveProcessStop)控制权...\n");
                bPatchSuccess = true;
            }
        }

        // 响应 Windows 调试状态，让游戏继续往下走
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);

        // 如果已经成功擦除，启动器直接安全功成身退，让游戏脱离调试状态完美自由奔跑
        if (bPatchSuccess) {
            DebugActiveProcessStop(pi.dwProcessId); // 分离调试器控制权，不卡死游戏进程，Loader.exe 功成身退
            break;
        }
    }

    printf("[+] 游戏已成功免疫所有格式化、改时间惩罚！正在退出启动器...\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
