## Appendix B: Win32 App Isolation

A new lightweight sandbox for traditional Win32 desktop applications. Unlike AppContainer (which requires UWP packaging), Win32 App Isolation allows any `.exe` to run in a restricted sandbox with capability-based access control.

### Detecting Win32 App Isolation

```c
// win32_app_isolation_detect.c - Detect isolated Win32 applications
// Compile: cl src\win32_app_isolation_detect.c /Fe:bin\win32_app_isolation_detect.exe advapi32.lib

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

/*
Win32 App Isolation Detection:
══════════════════════════════

Isolated Win32 apps run with special token properties:
1. AppContainer-like SID (unique per app)
2. Security attributes marking them as "isolatedWin32"
3. Reduced integrity level
4. Virtualized file system and registry views

Detection approach:
- Check for AppContainer SID on the process token
- Look for "isolatedWin32" security attributes
- Check if the process has a virtualized registry root
- Examine the token's capabilities list
*/

// Custom structure definitions for security attributes
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _MY_TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
    ULONG64 Version;
    MY_UNICODE_STRING Name;
} MY_TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PMY_TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _MY_TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
    PVOID pValue;
    ULONG ValueLength;
} MY_TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PMY_TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _MY_TOKEN_SECURITY_ATTRIBUTE_V1 {
    MY_UNICODE_STRING Name;
    USHORT ValueType;
    USHORT Reserved;
    ULONG Flags;
    ULONG ValueCount;
    union {
        PLONG64 pInt64;
        PULONG64 pUint64;
        PMY_UNICODE_STRING pString;
        PMY_TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        PMY_TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;
} MY_TOKEN_SECURITY_ATTRIBUTE_V1, *PMY_TOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _MY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
    USHORT Version;
    USHORT Reserved;
    ULONG AttributeCount;
    union {
        PMY_TOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
    } Attribute;
} MY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PMY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION;

#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID 0x00
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64 0x01
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64 0x02
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING 0x03
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN 0x04
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_SID 0x05
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN 0x06
#define MY_TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING 0x10

// Function pointer for GetProcessMitigationPolicy
typedef BOOL (WINAPI *PFN_GetProcessMitigationPolicy)(
    HANDLE hProcess,
    int MitigationPolicy,
    PVOID lpBuffer,
    SIZE_T dwLength
);

BOOL CheckWin32kLockdown(HANDLE hProcess) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;

    PFN_GetProcessMitigationPolicy pfnGetProcessMitigationPolicy =
        (PFN_GetProcessMitigationPolicy)GetProcAddress(hKernel32, "GetProcessMitigationPolicy");

    if (!pfnGetProcessMitigationPolicy) return FALSE;

    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = {0};
    if (pfnGetProcessMitigationPolicy(hProcess, ProcessSystemCallDisablePolicy,
                                      &policy, sizeof(policy))) {
        return policy.DisallowWin32kSystemCalls;
    }

    return FALSE;
}

BOOL GetTokenCapabilitiesDetailed(HANDLE hProcess, DWORD *pCapCount, PWSTR **ppCapNames) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenCapabilities, NULL, 0, &dwSize);

    if (dwSize == 0) {
        CloseHandle(hToken);
        return FALSE;
    }

    PTOKEN_GROUPS pCapabilities = (PTOKEN_GROUPS)malloc(dwSize);
    if (!pCapabilities) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL result = FALSE;
    if (GetTokenInformation(hToken, TokenCapabilities, pCapabilities, dwSize, &dwSize)) {
        *pCapCount = pCapabilities->GroupCount;

        if (ppCapNames && pCapabilities->GroupCount > 0) {
            *ppCapNames = (PWSTR*)malloc(sizeof(PWSTR) * pCapabilities->GroupCount);
            if (*ppCapNames) {
                for (DWORD i = 0; i < pCapabilities->GroupCount; i++) {
                    ConvertSidToStringSidW(pCapabilities->Groups[i].Sid, &(*ppCapNames)[i]);
                }
            }
        }
        result = TRUE;
    }

    free(pCapabilities);
    CloseHandle(hToken);
    return result;
}

BOOL GetProcessIntegrityLevel(HANDLE hProcess, DWORD *pIntegrityLevel) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);

    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)malloc(dwSize);
    if (!pTIL) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL result = FALSE;
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
        *pIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
        result = TRUE;
    }

    free(pTIL);
    CloseHandle(hToken);
    return result;
}

BOOL GetAppContainerSid(HANDLE hProcess, PWSTR *ppSidString) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenAppContainerSid, NULL, 0, &dwSize);

    if (dwSize == 0) {
        CloseHandle(hToken);
        return FALSE;
    }

    PTOKEN_APPCONTAINER_INFORMATION pAppContainer = (PTOKEN_APPCONTAINER_INFORMATION)malloc(dwSize);
    if (!pAppContainer) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL result = FALSE;
    if (GetTokenInformation(hToken, TokenAppContainerSid, pAppContainer, dwSize, &dwSize)) {
        if (pAppContainer->TokenAppContainer) {
            ConvertSidToStringSidW(pAppContainer->TokenAppContainer, ppSidString);
            result = TRUE;
        }
    }

    free(pAppContainer);
    CloseHandle(hToken);
    return result;
}

BOOL GetTokenCapabilities(HANDLE hProcess, DWORD *pCapCount) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenCapabilities, NULL, 0, &dwSize);

    if (dwSize == 0) {
        CloseHandle(hToken);
        return FALSE;
    }

    PTOKEN_GROUPS pCapabilities = (PTOKEN_GROUPS)malloc(dwSize);
    if (!pCapabilities) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL result = FALSE;
    if (GetTokenInformation(hToken, TokenCapabilities, pCapabilities, dwSize, &dwSize)) {
        *pCapCount = pCapabilities->GroupCount;
        result = TRUE;
    }

    free(pCapabilities);
    CloseHandle(hToken);
    return result;
}

BOOL IsProcessIsolatedWin32(HANDLE hProcess, BOOL verbose) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    // Check 1: Is this an AppContainer token?
    DWORD isAppContainer = 0;
    DWORD size = sizeof(isAppContainer);
    if (!GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, size, &size)) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (!isAppContainer) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (verbose) {
        printf("  [+] AppContainer: YES\n");

        // Get integrity level
        DWORD integrityLevel = 0;
        if (GetProcessIntegrityLevel(hProcess, &integrityLevel)) {
            printf("  [+] Integrity Level: 0x%X ", integrityLevel);
            if (integrityLevel < SECURITY_MANDATORY_LOW_RID) {
                printf("(Untrusted)\n");
            } else if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
                printf("(Low)\n");
            } else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                printf("(Medium)\n");
            } else {
                printf("(High/System)\n");
            }
        }

        // Get AppContainer SID
        PWSTR sidString = NULL;
        if (GetAppContainerSid(hProcess, &sidString)) {
            printf("  [+] AppContainer SID: %S\n", sidString);
            LocalFree(sidString);
        }

        // Get capabilities count
        DWORD capCount = 0;
        if (GetTokenCapabilities(hProcess, &capCount)) {
            printf("  [+] Capabilities: %d\n", capCount);
        }
    }

    // Check 2: Query security attributes for "isolatedWin32" markers
    DWORD attrSize = 0;
    GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)73, NULL, 0, &attrSize); // TokenSecurityAttributes = 73

    BOOL hasIsolationAttrs = FALSE;
    if (attrSize > 0) {
        PVOID attrBuf = malloc(attrSize);
        if (attrBuf && GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)73,
                                attrBuf, attrSize, &attrSize)) {
            PMY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION pAttrs =
                (PMY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)attrBuf;

            if (verbose && pAttrs->AttributeCount > 0) {
                printf("  [+] Security Attributes:\n");
            }

            for (DWORD i = 0; i < pAttrs->AttributeCount; i++) {
                PMY_TOKEN_SECURITY_ATTRIBUTE_V1 attr = &pAttrs->Attribute.pAttributeV1[i];

                if (attr->Name.Buffer) {
                    if (verbose) {
                        printf("      - %S\n", attr->Name.Buffer);
                    }

                    // Check for Win32 App Isolation markers
                    if (wcsstr(attr->Name.Buffer, L"WIN://SYSAPPID") ||
                        wcsstr(attr->Name.Buffer, L"WIN://PKG") ||
                        wcsstr(attr->Name.Buffer, L"WIN://NOALLAPPPKG")) {
                        hasIsolationAttrs = TRUE;
                    }
                }
            }
        }
        if (attrBuf) free(attrBuf);
    }

    CloseHandle(hToken);
    return isAppContainer && hasIsolationAttrs;
}

BOOL GetPackageFamilyName(HANDLE hProcess, PWSTR *ppPackageName) {
    typedef LONG (WINAPI *PFN_GetPackageFamilyName)(HANDLE, UINT32*, PWSTR);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;

    PFN_GetPackageFamilyName pfnGetPackageFamilyName =
        (PFN_GetPackageFamilyName)GetProcAddress(hKernel32, "GetPackageFamilyName");

    if (!pfnGetPackageFamilyName) return FALSE;

    UINT32 length = 0;
    LONG result = pfnGetPackageFamilyName(hProcess, &length, NULL);

    if (result != ERROR_INSUFFICIENT_BUFFER || length == 0) {
        return FALSE;
    }

    *ppPackageName = (PWSTR)malloc(length * sizeof(WCHAR));
    if (!*ppPackageName) return FALSE;

    result = pfnGetPackageFamilyName(hProcess, &length, *ppPackageName);
    if (result != ERROR_SUCCESS) {
        free(*ppPackageName);
        *ppPackageName = NULL;
        return FALSE;
    }

    return TRUE;
}

typedef struct _ISOLATION_INFO {
    BOOL isAppContainer;
    BOOL hasIsolationAttrs;
    BOOL hasWin32kLockdown;
    BOOL hasPackageIdentity;
    DWORD integrityLevel;
    DWORD capabilityCount;
    PWSTR appContainerSid;
    PWSTR packageFamilyName;
    PWSTR *capabilityNames;
    WCHAR **securityAttributes;
    DWORD securityAttributeCount;
} ISOLATION_INFO, *PISOLATION_INFO;

void FreeIsolationInfo(PISOLATION_INFO pInfo) {
    if (!pInfo) return;

    if (pInfo->appContainerSid) {
        LocalFree(pInfo->appContainerSid);
    }

    if (pInfo->packageFamilyName) {
        free(pInfo->packageFamilyName);
    }

    if (pInfo->capabilityNames) {
        for (DWORD i = 0; i < pInfo->capabilityCount; i++) {
            if (pInfo->capabilityNames[i]) {
                LocalFree(pInfo->capabilityNames[i]);
            }
        }
        free(pInfo->capabilityNames);
    }

    if (pInfo->securityAttributes) {
        for (DWORD i = 0; i < pInfo->securityAttributeCount; i++) {
            if (pInfo->securityAttributes[i]) {
                free(pInfo->securityAttributes[i]);
            }
        }
        free(pInfo->securityAttributes);
    }
}

BOOL AnalyzeProcessIsolation(HANDLE hProcess, PISOLATION_INFO pInfo) {
    ZeroMemory(pInfo, sizeof(ISOLATION_INFO));

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    // Check 1: Is this an AppContainer token?
    DWORD isAppContainer = 0;
    DWORD size = sizeof(isAppContainer);
    if (GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, size, &size)) {
        pInfo->isAppContainer = isAppContainer;
    }

    if (!pInfo->isAppContainer) {
        CloseHandle(hToken);
        return FALSE;
    }

    // Check 2: Get integrity level
    GetProcessIntegrityLevel(hProcess, &pInfo->integrityLevel);

    // Check 3: Get AppContainer SID
    GetAppContainerSid(hProcess, &pInfo->appContainerSid);

    // Check 4: Get capabilities
    GetTokenCapabilitiesDetailed(hProcess, &pInfo->capabilityCount, &pInfo->capabilityNames);

    // Check 5: Check Win32k lockdown
    pInfo->hasWin32kLockdown = CheckWin32kLockdown(hProcess);

    // Check 6: Get package family name
    pInfo->hasPackageIdentity = GetPackageFamilyName(hProcess, &pInfo->packageFamilyName);

    // Check 7: Query security attributes for "isolatedWin32" markers
    DWORD attrSize = 0;
    GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)73, NULL, 0, &attrSize);

    if (attrSize > 0) {
        PVOID attrBuf = malloc(attrSize);
        if (attrBuf && GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)73, attrBuf, attrSize, &attrSize)) {
            PMY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION pAttrs = (PMY_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)attrBuf;

            if (pAttrs->AttributeCount > 0) {
                pInfo->securityAttributes = (WCHAR**)malloc(sizeof(WCHAR*) * pAttrs->AttributeCount);
                pInfo->securityAttributeCount = pAttrs->AttributeCount;

                for (DWORD i = 0; i < pAttrs->AttributeCount; i++) {
                    PMY_TOKEN_SECURITY_ATTRIBUTE_V1 attr = &pAttrs->Attribute.pAttributeV1[i];

                    if (attr->Name.Buffer && attr->Name.Length > 0) {
                        size_t bufLen = attr->Name.Length + sizeof(WCHAR);
                        pInfo->securityAttributes[i] = (WCHAR*)malloc(bufLen);
                        if (pInfo->securityAttributes[i]) {
                            wcsncpy_s(pInfo->securityAttributes[i], bufLen / sizeof(WCHAR),
                                     attr->Name.Buffer, attr->Name.Length / sizeof(WCHAR));
                        }

                        // Check for Win32 App Isolation markers
                        if (wcsstr(attr->Name.Buffer, L"WIN://SYSAPPID") ||
                            wcsstr(attr->Name.Buffer, L"WIN://PKG") ||
                            wcsstr(attr->Name.Buffer, L"WIN://NOALLAPPPKG")) {
                            pInfo->hasIsolationAttrs = TRUE;
                        }
                    } else {
                        pInfo->securityAttributes[i] = NULL;
                    }
                }
            }
        }
        if (attrBuf) free(attrBuf);
    }

    CloseHandle(hToken);
    return TRUE;
}

void PrintIsolationInfo(const char *processName, DWORD pid, PISOLATION_INFO pInfo) {
    printf("\n|================================================================|\n");
    printf("| Process: %-50s |\n", processName);
    printf("| PID: %-56d |\n", pid);
    printf("|=================================================================|\n");

    printf("| AppContainer:        %-37s |\n", pInfo->isAppContainer ? "YES" : "NO");
    printf("| Isolation Attributes: %-36s |\n", pInfo->hasIsolationAttrs ? "YES" : "NO");
    printf("| Win32k Lockdown:     %-37s |\n", pInfo->hasWin32kLockdown ? "YES" : "NO");
    printf("| Package Identity:    %-37s |\n", pInfo->hasPackageIdentity ? "YES" : "NO");

    printf("| Integrity Level:     0x%04X ", pInfo->integrityLevel);
    if (pInfo->integrityLevel < SECURITY_MANDATORY_LOW_RID) {
        printf("%-28s |\n", "(Untrusted)");
    } else if (pInfo->integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
        printf("%-28s |\n", "(Low)");
    } else if (pInfo->integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        printf("%-28s |\n", "(Medium)");
    } else {
        printf("%-28s |\n", "(High/System)");
    }

    printf("| Capabilities:        %-37d |\n", pInfo->capabilityCount);

    if (pInfo->appContainerSid) {
        printf("|===============================================================|\n");
        printf("| AppContainer SID:                                             |\n");
        wprintf(L"|   %s", pInfo->appContainerSid);
        int sidLen = wcslen(pInfo->appContainerSid);
        for (int i = sidLen + 4; i < 63; i++) printf(" ");
        printf("|\n");
    }

    if (pInfo->packageFamilyName) {
        printf("|===============================================================|\n");
        printf("| Package Family Name:                                          |\n");
        wprintf(L"|   %s", pInfo->packageFamilyName);
        int pkgLen = wcslen(pInfo->packageFamilyName);
        for (int i = pkgLen + 4; i < 63; i++) printf(" ");
        printf("|\n");
    }

    if (pInfo->capabilityCount > 0 && pInfo->capabilityNames) {
        printf("|===============================================================|\n");
        printf("| Capabilities (first 5):                                       |\n");
        for (DWORD i = 0; i < pInfo->capabilityCount && i < 5; i++) {
            if (pInfo->capabilityNames[i]) {
                wprintf(L"|   %d. %s", i+1, pInfo->capabilityNames[i]);
                int capLen = wcslen(pInfo->capabilityNames[i]);
                for (int j = capLen + 6; j < 63; j++) printf(" ");
                printf("|\n");
            }
        }
        if (pInfo->capabilityCount > 5) {
            printf("|   ... and %d more                                            ",
                   pInfo->capabilityCount - 5);
            int numLen = (pInfo->capabilityCount - 5 >= 10) ? 2 : 1;
            for (int i = numLen + 14; i < 59; i++) printf(" ");
            printf("|\n");
        }
    }

    if (pInfo->securityAttributeCount > 0 && pInfo->securityAttributes) {
        printf("|===============================================================|\n");
        printf("| Security Attributes (first 8):                                |\n");
        for (DWORD i = 0; i < pInfo->securityAttributeCount && i < 8; i++) {
            if (pInfo->securityAttributes[i]) {
                wprintf(L"|   • %s", pInfo->securityAttributes[i]);
                int attrLen = wcslen(pInfo->securityAttributes[i]);
                for (int j = attrLen + 5; j < 63; j++) printf(" ");
                printf("|\n");
            }
        }
        if (pInfo->securityAttributeCount > 8) {
            printf("|   ... and %d more                                            ",
                   pInfo->securityAttributeCount - 8);
            int numLen = (pInfo->securityAttributeCount - 8 >= 10) ? 2 : 1;
            for (int i = numLen + 14; i < 59; i++) printf(" ");
            printf("|\n");
        }
    }

    printf("|===============================================================|\n");

    // Determine isolation level
    if (pInfo->hasIsolationAttrs && pInfo->hasWin32kLockdown) {
        printf("\n>>> STRONG ISOLATION: Win32 App Isolation with Win32k Lockdown <<<\n");
    } else if (pInfo->hasIsolationAttrs) {
        printf("\n>>> MODERATE ISOLATION: Win32 App Isolation <<<\n");
    } else if (pInfo->isAppContainer) {
        printf("\n>>> BASIC ISOLATION: AppContainer (UWP/MSIX) <<<\n");
    }
}

void ScanForIsolatedAppsEnhanced(BOOL showAll) {
    printf("===============================================================\n");
    printf("  Win32 App Isolation - Comprehensive Process Scan\n");
    printf("===============================================================\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot (Error: %d)\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    int isolated_count = 0;
    int appcontainer_count = 0;
    int strong_isolation_count = 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            ISOLATION_INFO info;
            if (AnalyzeProcessIsolation(hProc, &info)) {
                appcontainer_count++;

                if (info.hasIsolationAttrs) {
                    isolated_count++;
                    if (info.hasWin32kLockdown) {
                        strong_isolation_count++;
                    }
                    PrintIsolationInfo(pe.szExeFile, pe.th32ProcessID, &info);
                } else if (showAll) {
                    // Show all AppContainer processes even if not isolated
                    PrintIsolationInfo(pe.szExeFile, pe.th32ProcessID, &info);
                }

                FreeIsolationInfo(&info);
            }

            CloseHandle(hProc);
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    printf("\n==============================================================\n");
    printf("  Scan Summary\n");
    printf("==============================================================\n");
    printf("  Total AppContainer processes:     %d\n", appcontainer_count);
    printf("  Isolated Win32 processes:         %d\n", isolated_count);
    printf("  Strong isolation (Win32k locked): %d\n", strong_isolation_count);
    printf("==============================================================\n");

    if (isolated_count == 0 && appcontainer_count > 0) {
        printf("\n[i] Note: Found %d AppContainer processes but none with Win32 App\n", appcontainer_count);
        printf("    Isolation markers. This is expected on Windows < 11 24H2 or if\n");
        printf("    no isolated Win32 apps are currently running.\n");
        printf("\n[i] Run with '-v' flag to see details of all AppContainer processes.\n");
    }
}

void ScanForIsolatedApps() {
    printf("=== Win32 App Isolation - Process Scan ===\n\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot\n");
        return;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    int isolated_count = 0;
    int appcontainer_count = 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hToken;
            if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                DWORD isAppContainer = 0;
                DWORD size = sizeof(isAppContainer);

                if (GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, size, &size)) {
                    if (isAppContainer) {
                        appcontainer_count++;
                        printf("\n[APPCONTAINER] %s (PID %d)\n", pe.szExeFile, pe.th32ProcessID);

                        if (IsProcessIsolatedWin32(hProc, TRUE)) {
                            printf("  >>> ISOLATED WIN32 APP <<<\n");
                            isolated_count++;
                        }
                    }
                }
                CloseHandle(hToken);
            }

            CloseHandle(hProc);
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    printf("\n[*] Found %d AppContainer processes\n", appcontainer_count);
    printf("[*] Found %d isolated Win32 processes\n", isolated_count);
}

int main(int argc, char *argv[]) {
    BOOL verbose = FALSE;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = TRUE;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -v, --verbose    Show all AppContainer processes (not just isolated)\n");
            printf("  -h, --help       Show this help message\n\n");
            printf("Description:\n");
            printf("  Scans for Win32 App Isolation processes on Windows 11 24H2+.\n");
            printf("  By default, only shows processes with isolation markers.\n");
            printf("  Use -v to see all AppContainer processes.\n\n");
            return 0;
        }
    }

    printf("\n");
    printf("|===============================================================|\n");
    printf("|                                                               |\n");
    printf("|         Win32 App Isolation Detection & Analysis              |\n");
    printf("|                                                               |\n");
    printf("|===============================================================|\n");
    printf("\n");

    ScanForIsolatedAppsEnhanced(verbose);
    return 0;
}
```

