#include <windows.h>

DWORD g_HookReturnAddress = 0;
#define PAGE_EXECUTE_READWRITE 0x40

// 核心占位导出函数：供 Stud_PE 静态输入表绑定
__declspec(dllexport) void __cdecl InitAntiCheatPatch() {
    // Keep it blank for Stud_PE
}

// 裸函数：拦截 push eax (使用汇编严格保证寄存器与堆栈平衡)
__declspec(naked) void MyOepHook() {
    __asm {
        pushad                  // 1. 备份所有通用寄存器

        // 此时 EAX 里面已经是热气腾腾的 MoleBox 真实基址了
        // 我们直接利用主线程的最高特权，计算出反作弊 call 的绝对地址并存入 ESI
        mov esi, eax
        add esi, 0x99B6C

        // 2. 模拟调用 VirtualProtect(esi, 5, PAGE_EXECUTE_READWRITE, esp-4) 解锁目标内存写权限
        // 在裸函数内，我们通过堆栈直接传参，不调用 C++ 函数，防止破坏寄存器环境
        push esp                // 参数 4：提供一个合法的堆栈地址接收旧权限
        push PAGE_EXECUTE_READWRITE // 参数 3：新属性 (0x40)
        push 5                 // 参数 2：大小 (5 字节)
        push esi               // 参数 1：目标内存起始地址
        call dword ptr [VirtualProtect] // 强行破锁！

        // 3. 施展致命一击：主线程亲自在原地写入 5 个 NOP
        mov byte ptr [esi], 0x90
        mov byte ptr [esi+1], 0x90
        mov byte ptr [esi+2], 0x90
        mov byte ptr [esi+3], 0x90
        mov byte ptr [esi+4], 0x90

        popad                   // 4. 恢复所有通用寄存器
        
        push eax                // 5. 执行原本被 Hook 覆盖掉的游戏原始机器码 (50)
        jmp g_HookReturnAddress // 6. 顺延跳回原程序继续执行
    }
}

// 补丁初始化逻辑 (快进快出，写完 Hook 立刻释放 LoaderLock)
void InitMemoryPatch() {
    HMODULE hGame = GetModuleHandleA(NULL);
    BYTE* hookAddress = (BYTE*)hGame + 0x86AA1FE;
    g_HookReturnAddress = (DWORD)hookAddress + 1;

    // 强行在原地写下我们的 jmp 挂钩
    DWORD oldProtect;
    if (VirtualProtect(hookAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        DWORD relativeOffset = (DWORD)MyOepHook - (DWORD)hookAddress - 5;
        hookAddress = 0xE9; // jmp 机器码
        *(DWORD*)(hookAddress + 1) = relativeOffset;
        VirtualProtect(hookAddress, 5, oldProtect, &oldProtect);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitMemoryPatch();
    }
    return TRUE;
}
