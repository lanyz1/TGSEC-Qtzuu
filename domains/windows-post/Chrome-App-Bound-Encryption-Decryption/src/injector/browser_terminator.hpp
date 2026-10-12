// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "../core/console.hpp"
#include "browser_discovery.hpp"
#include <vector>
#include <string>
#include <set>
#include <functional>

namespace Injector {

    // Statistics for termination operations
    struct TerminationStats {
        int processesFound = 0;
        int processesTerminated = 0;
        int processesFailed = 0;
        int childProcesses = 0;
        std::vector<DWORD> terminatedPids;  // PIDs that were successfully terminated
    };

    // Process information structure for internal tracking
    struct ProcessEntry {
        DWORD pid;
        DWORD parentPid;
        std::wstring imageName;
        std::wstring commandLine;
        bool isMainProcess;
    };

    // Termination options
    struct TerminationOptions {
        bool terminateChildren = true;       // Also terminate child processes
        bool waitForExit = true;             // Wait for processes to fully exit
        DWORD exitWaitTimeoutMs = 2000;     // Timeout waiting for exit
    };

    class BrowserTerminator {
    public:
        explicit BrowserTerminator(const Core::Console& console);
        ~BrowserTerminator() = default;

        // Non-copyable
        BrowserTerminator(const BrowserTerminator&) = delete;
        BrowserTerminator& operator=(const BrowserTerminator&) = delete;

        // Kill processes by executable name
        TerminationStats KillByExeName(const std::wstring& exeName, const TerminationOptions& opts = {});

        // Check if any processes with given exe name are running
        bool IsBrowserRunning(const std::wstring& exeName) const;

        // Get list of running browser processes
        std::vector<ProcessEntry> GetRunningProcesses(const std::wstring& exeName) const;

    private:
        // Process enumeration using NtGetNextProcess syscall
        std::vector<ProcessEntry> EnumerateProcesses(const std::wstring& targetExeName) const;

        // Build process tree (find all children recursively)
        std::set<DWORD> BuildProcessTree(const std::vector<ProcessEntry>& processes, DWORD rootPid) const;

        // Terminate a single process by PID
        bool TerminateProcess(DWORD pid, const TerminationOptions& opts);

        // Open process handle with syscall
        Core::UniqueHandle OpenProcessHandle(DWORD pid, ACCESS_MASK access) const;

        // Read process command line
        std::wstring GetProcessCommandLine(HANDLE hProcess) const;

        // Get process image name
        std::wstring GetProcessImageName(HANDLE hProcess) const;

        // Wait for process to exit
        bool WaitForProcessExit(HANDLE hProcess, DWORD timeoutMs) const;

        // Send graceful termination signal (WM_CLOSE to windows)
        bool SendGracefulTermination(DWORD pid, DWORD timeoutMs);

        const Core::Console& m_console;
    };

}
