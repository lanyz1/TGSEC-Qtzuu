// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "browser_terminator.hpp"
#include "../sys/internal_api.hpp"
#include <algorithm>
#include <queue>

namespace Injector {

    BrowserTerminator::BrowserTerminator(const Core::Console& console) 
        : m_console(console) {}

    std::vector<ProcessEntry> BrowserTerminator::EnumerateProcesses(const std::wstring& targetExeName) const {
        std::vector<ProcessEntry> results;
        Core::UniqueHandle hCurrentProc;
        HANDLE nextProcHandle = nullptr;

        // Use NtGetNextProcess syscall to enumerate all processes
        while (NtGetNextProcess_syscall(
            hCurrentProc.get(), 
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
            0, 0, &nextProcHandle) == STATUS_SUCCESS) {
            
            Core::UniqueHandle hNextProc(nextProcHandle);
            hCurrentProc = std::move(hNextProc);

            // Get process image file name
            std::vector<BYTE> buffer(sizeof(UNICODE_STRING_SYSCALLS) + MAX_PATH * 2);
            auto imageName = reinterpret_cast<PUNICODE_STRING_SYSCALLS>(buffer.data());
            
            NTSTATUS status = NtQueryInformationProcess_syscall(
                hCurrentProc.get(), 
                ProcessImageFileName, 
                imageName, 
                static_cast<ULONG>(buffer.size()), 
                nullptr);
            
            if (status != STATUS_SUCCESS || imageName->Length == 0) {
                continue;
            }

            std::wstring imagePath(imageName->Buffer, imageName->Length / sizeof(wchar_t));
            std::filesystem::path p(imagePath);
            std::wstring fileName = p.filename().wstring();

            // Case-insensitive comparison
            if (_wcsicmp(fileName.c_str(), targetExeName.c_str()) != 0) {
                continue;
            }

            // Get process basic information (PID, parent PID)
            PROCESS_BASIC_INFORMATION pbi{};
            status = NtQueryInformationProcess_syscall(
                hCurrentProc.get(), 
                ProcessBasicInformation, 
                &pbi, 
                sizeof(pbi), 
                nullptr);
            
            if (status != STATUS_SUCCESS) {
                continue;
            }

            ProcessEntry entry{};
            entry.pid = static_cast<DWORD>(pbi.UniqueProcessId);
            entry.parentPid = static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
            entry.imageName = fileName;
            entry.isMainProcess = true;

            // Try to read command line
            entry.commandLine = GetProcessCommandLine(hCurrentProc.get());

            results.push_back(std::move(entry));
        }

        return results;
    }

    std::wstring BrowserTerminator::GetProcessImageName(HANDLE hProcess) const {
        std::vector<BYTE> buffer(sizeof(UNICODE_STRING_SYSCALLS) + MAX_PATH * 2);
        auto imageName = reinterpret_cast<PUNICODE_STRING_SYSCALLS>(buffer.data());
        
        if (NtQueryInformationProcess_syscall(hProcess, ProcessImageFileName, 
            imageName, static_cast<ULONG>(buffer.size()), nullptr) != STATUS_SUCCESS) {
            return L"";
        }

        if (imageName->Length == 0) return L"";
        
        std::wstring path(imageName->Buffer, imageName->Length / sizeof(wchar_t));
        return std::filesystem::path(path).filename().wstring();
    }

    std::wstring BrowserTerminator::GetProcessCommandLine(HANDLE hProcess) const {
        PROCESS_BASIC_INFORMATION pbi{};
        if (NtQueryInformationProcess_syscall(hProcess, ProcessBasicInformation, 
            &pbi, sizeof(pbi), nullptr) != STATUS_SUCCESS) {
            return L"";
        }

        if (!pbi.PebBaseAddress) return L"";

        // Read PEB
        PEB peb{};
        if (NtReadVirtualMemory_syscall(hProcess, pbi.PebBaseAddress, 
            &peb, sizeof(peb), nullptr) != STATUS_SUCCESS) {
            return L"";
        }

        // Read process parameters
        RTL_USER_PROCESS_PARAMETERS params{};
        if (NtReadVirtualMemory_syscall(hProcess, peb.ProcessParameters, 
            &params, sizeof(params), nullptr) != STATUS_SUCCESS) {
            return L"";
        }

        if (params.CommandLine.Length == 0) return L"";

        // Read command line string
        std::vector<wchar_t> cmdLine(params.CommandLine.Length / sizeof(wchar_t) + 1, 0);
        if (NtReadVirtualMemory_syscall(hProcess, params.CommandLine.Buffer, 
            cmdLine.data(), params.CommandLine.Length, nullptr) != STATUS_SUCCESS) {
            return L"";
        }

        return std::wstring(cmdLine.data());
    }

    Core::UniqueHandle BrowserTerminator::OpenProcessHandle(DWORD pid, ACCESS_MASK access) const {
        HANDLE hProcess = nullptr;
        OBJECT_ATTRIBUTES objAttr{};
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
        
        CLIENT_ID clientId{};
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
        clientId.UniqueThread = nullptr;

        if (NtOpenProcess_syscall(&hProcess, access, &objAttr, &clientId) != STATUS_SUCCESS) {
            return nullptr;
        }

        return Core::UniqueHandle(hProcess);
    }

    std::set<DWORD> BrowserTerminator::BuildProcessTree(
        const std::vector<ProcessEntry>& processes, DWORD rootPid) const {
        
        std::set<DWORD> tree;
        std::queue<DWORD> toProcess;
        toProcess.push(rootPid);

        while (!toProcess.empty()) {
            DWORD currentPid = toProcess.front();
            toProcess.pop();

            if (tree.count(currentPid) > 0) continue;
            tree.insert(currentPid);

            // Find all children of current process
            for (const auto& proc : processes) {
                if (proc.parentPid == currentPid && tree.count(proc.pid) == 0) {
                    toProcess.push(proc.pid);
                }
            }
        }

        return tree;
    }

    bool BrowserTerminator::WaitForProcessExit(HANDLE hProcess, DWORD timeoutMs) const {
        return WaitForSingleObject(hProcess, timeoutMs) == WAIT_OBJECT_0;
    }

    // Callback structure for EnumWindows
    struct EnumWindowsData {
        DWORD targetPid;
        std::vector<HWND> windows;
    };

    static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        auto* data = reinterpret_cast<EnumWindowsData*>(lParam);
        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);
        
        if (windowPid == data->targetPid) {
            data->windows.push_back(hwnd);
        }
        return TRUE;
    }

    bool BrowserTerminator::SendGracefulTermination(DWORD pid, DWORD timeoutMs) {
        // Find all windows belonging to this process
        EnumWindowsData data{};
        data.targetPid = pid;
        EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&data));

        if (data.windows.empty()) {
            return false; // No windows to close
        }

        // Send WM_CLOSE to all windows
        for (HWND hwnd : data.windows) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }

        // Wait for process to exit
        auto hProcess = OpenProcessHandle(pid, SYNCHRONIZE | PROCESS_QUERY_INFORMATION);
        if (!hProcess) {
            return true; // Process may have already exited
        }

        return WaitForProcessExit(hProcess.get(), timeoutMs);
    }

    bool BrowserTerminator::TerminateProcess(DWORD pid, const TerminationOptions& opts) {
        // Direct forceful termination using NtTerminateProcess syscall
        auto hProcess = OpenProcessHandle(pid, PROCESS_TERMINATE | SYNCHRONIZE);
        if (!hProcess) {
            // Process may have already exited
            return true;
        }

        NTSTATUS status = NtTerminateProcess_syscall(hProcess.get(), 0);
        
        if (status != STATUS_SUCCESS) {
            return false;
        }

        // Wait for process to fully exit
        if (opts.waitForExit) {
            WaitForProcessExit(hProcess.get(), opts.exitWaitTimeoutMs);
        }

        return true;
    }

    std::vector<ProcessEntry> BrowserTerminator::GetRunningProcesses(const std::wstring& exeName) const {
        return EnumerateProcesses(exeName);
    }

    bool BrowserTerminator::IsBrowserRunning(const std::wstring& exeName) const {
        auto processes = EnumerateProcesses(exeName);
        return !processes.empty();
    }

    TerminationStats BrowserTerminator::KillByExeName(
        const std::wstring& exeName, const TerminationOptions& opts) {
        
        TerminationStats stats{};

        // Enumerate all processes with the target executable name
        auto processes = EnumerateProcesses(exeName);
        stats.processesFound = static_cast<int>(processes.size());

        if (processes.empty()) {
            return stats;
        }

        // If terminating children, we need to enumerate ALL processes to find the tree
        std::vector<ProcessEntry> allProcesses;
        if (opts.terminateChildren) {
            // Get all browser-related processes (main + children)
            // Children might have different names (e.g., helper processes)
            Core::UniqueHandle hCurrentProc;
            HANDLE nextProcHandle = nullptr;

            while (NtGetNextProcess_syscall(
                hCurrentProc.get(),
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                0, 0, &nextProcHandle) == STATUS_SUCCESS) {
                
                Core::UniqueHandle hNextProc(nextProcHandle);
                hCurrentProc = std::move(hNextProc);

                PROCESS_BASIC_INFORMATION pbi{};
                if (NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessBasicInformation,
                    &pbi, sizeof(pbi), nullptr) != STATUS_SUCCESS) {
                    continue;
                }

                ProcessEntry entry{};
                entry.pid = static_cast<DWORD>(pbi.UniqueProcessId);
                entry.parentPid = static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
                entry.imageName = GetProcessImageName(hCurrentProc.get());
                entry.isMainProcess = (_wcsicmp(entry.imageName.c_str(), exeName.c_str()) == 0);
                
                allProcesses.push_back(std::move(entry));
            }
        }

        // Build set of PIDs to terminate (including children if requested)
        std::set<DWORD> pidsToTerminate;
        
        for (const auto& proc : processes) {
            if (opts.terminateChildren && !allProcesses.empty()) {
                auto tree = BuildProcessTree(allProcesses, proc.pid);
                for (DWORD pid : tree) {
                    pidsToTerminate.insert(pid);
                }
            } else {
                pidsToTerminate.insert(proc.pid);
            }
        }

        stats.childProcesses = static_cast<int>(pidsToTerminate.size()) - stats.processesFound;
        if (stats.childProcesses < 0) stats.childProcesses = 0;

        // Terminate processes in reverse order (children first, then parents)
        // This helps ensure clean shutdown
        std::vector<DWORD> sortedPids(pidsToTerminate.begin(), pidsToTerminate.end());
        
        // Sort by whether they're main processes (children first)
        std::sort(sortedPids.begin(), sortedPids.end(), [&](DWORD a, DWORD b) {
            bool aIsMain = std::any_of(processes.begin(), processes.end(), 
                [a](const ProcessEntry& e) { return e.pid == a; });
            bool bIsMain = std::any_of(processes.begin(), processes.end(), 
                [b](const ProcessEntry& e) { return e.pid == b; });
            return !aIsMain && bIsMain; // Children before parents
        });

        for (DWORD pid : sortedPids) {
            if (TerminateProcess(pid, opts)) {
                stats.processesTerminated++;
                stats.terminatedPids.push_back(pid);
            } else {
                stats.processesFailed++;
            }
        }

        return stats;
    }


}
