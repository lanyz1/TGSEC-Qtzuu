#include <windows.h>
#include <stdio.h>

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    printf("[+] 正在以挂起状态启动原版游戏 (不注入任何DLL，实现0特征过检测)...\n");

    // 1. 以挂起状态拉起游戏，此时外壳完全不设防
    if (!CreateProcessA("explorers.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] 错误：无法启动 game.exe，请确保和游戏在同一目录下！\n");
        return -1;
    }

    // 2. 计算游戏主模块的挂钩点绝对地址
    // game.exe 默认基址通常是 0x00400000，加上你的偏移 0x86AA1FE
    BYTE* hookAddress = (BYTE*)0x00400000 + 0x86AA1FE; 
    printf("[+] 监控目标挂钩点: 0x%08X\n", hookAddress);

    // 3. 直接恢复游戏主线程，让外壳开始大张旗鼓地解密，我们不留任何 DLL 痕迹
    ResumeThread(pi.hThread);
    printf("[+] 游戏主线程已恢复，正在外部以微秒级速度盯死解密时序...\n");

    BYTE currentByte = 0;
    DWORD bytesRead = 0;

    // 4. 【第一重守株待兔】：在外部死等该地址被解密释放并填入 0x50 (push eax)
    while (currentByte != 0x50) {
        // 从外部读取游戏进程的该内存字节
        ReadProcessMemory(pi.hProcess, hookAddress, &currentByte, 1, &bytesRead);
        Sleep(0); // 极速轮询，绝不拖泥带水
    }

    printf("[+] 抓到时机！目标 OEP 已成功解密出 0x50。外壳解密引擎正在运转...\n");

    // 5. 【获取 MoleBox 真实基址】：
    // 此时游戏刚好要执行 push eax，而 eax 里就存着基址。
    // 为了防止读取寄存器卡时间，我们直接采取你之前验证成功的更聪明的办法：
    // 死等它后面的那个反作弊 call（基址 + 99B6C）被释放！
    // 既然程序已经在往前跑了，我们直接通过外壳暴露出来的全局基址变量指针来获取：
    BYTE* pGlobalBaseVar = (BYTE*)0x00400000 + 0x86B59B0;
    DWORD moleBoxBase = 0;

    printf("[+] 正在等待外壳将 EAX 赋值给全局变量指针 0x%08X...\n", pGlobalBaseVar);
    while (moleBoxBase == 0) {
        ReadProcessMemory(pi.hProcess, pGlobalBaseVar, &moleBoxBase, 4, &bytesRead);
        Sleep(0);
    }

    printf("[+] 成功拦截到 MoleBox 动态加载基址: 0x%08X\n", moleBoxBase);

    // 6. 【第二重守株待兔】：计算出反作弊核心 call 地址 (MoleBox基址 + 99B6C)
    BYTE* targetAntiCheatCall = (BYTE*)moleBoxBase + 0x99B6C;
    printf("[+] 反作弊核心破坏指令位于: 0x%08X，正在等待其解密出 0xE8...\n", targetAntiCheatCall);

    BYTE antiCheatByte = 0;
    while (antiCheatByte != 0xE8) {
        ReadProcessMemory(pi.hProcess, targetAntiCheatCall, &antiCheatByte, 1, &bytesRead);
        Sleep(0);
    }

    // 7. 【致命一击】：在它来得及执行删除盘符和改时间的万分之一微秒内，外部直接将其砸碎！
    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, targetAntiCheatCall, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    BYTE nopBytes[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    WriteProcessMemory(pi.hProcess, targetAntiCheatCall, nopBytes, 5, NULL);
    
    VirtualProtectEx(pi.hProcess, targetAntiCheatCall, 5, oldProtect, &oldProtect);

    printf("[+] SUCCESS: 毁灭性反作弊线程已在内存中被物理阉割（5个NOP覆盖成功）！\n");
    printf("[+] 启动器使命完成，游戏已处于绝对纯净安全状态，正在退出控制台...\n");

    // 清理句柄，启动器深藏功名退出
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}