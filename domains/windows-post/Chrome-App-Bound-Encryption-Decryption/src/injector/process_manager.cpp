// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "process_manager.hpp"
#include "../sys/internal_api.hpp"
#include <iostream>

namespace Injector {

    ProcessManager::ProcessManager(const BrowserInfo& browser) : m_browser(browser) {}

    ProcessManager::~ProcessManager() {
        // Ensure cleanup if not explicitly terminated
        if (m_hProcess) Terminate();
    }

    void ProcessManager::CreateSuspended() {
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (!CreateProcessW(m_browser.fullPath.c_str(), nullptr, nullptr, nullptr,
                            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            throw std::runtime_error("CreateProcessW failed: " + std::to_string(GetLastError()));
        }

        m_hProcess.reset(pi.hProcess);
        m_hThread.reset(pi.hThread);
        m_pid = pi.dwProcessId;

        CheckArchitecture();
    }

    void ProcessManager::Terminate() {
        if (m_hProcess) {
            NtTerminateProcess_syscall(m_hProcess.get(), 0);
            WaitForSingleObject(m_hProcess.get(), 2000);
            m_hProcess.reset(); // Release handle
        }
    }

    void ProcessManager::CheckArchitecture() {
        // Read PE header directly from executable - IsWow64Process2 doesn't work correctly
        // for x64 processes running under emulation on ARM64 Windows (returns 0 for processArch)
        HANDLE hFile = CreateFileW(m_browser.fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to open executable for architecture check");
        }

        IMAGE_DOS_HEADER dosHeader{};
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            CloseHandle(hFile);
            throw std::runtime_error("Invalid PE: bad DOS signature");
        }

        SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN);
        DWORD ntSig = 0;
        ReadFile(hFile, &ntSig, sizeof(ntSig), &bytesRead, nullptr);
        if (ntSig != IMAGE_NT_SIGNATURE) {
            CloseHandle(hFile);
            throw std::runtime_error("Invalid PE: bad NT signature");
        }

        IMAGE_FILE_HEADER fileHeader{};
        ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, nullptr);
        CloseHandle(hFile);

        m_arch = fileHeader.Machine;

        // Architecture names for human-readable errors
        auto GetArchName = [](USHORT arch) -> std::string {
            switch (arch) {
                case 0x8664: return "x64 (AMD64)";
                case 0xAA64: return "ARM64";
                case 0x014C: return "x86 (i386)";
                case 0x01C4: return "ARM (Thumb-2)";
                default: return "Unknown (0x" + std::to_string(arch) + ")";
            }
        };

        // Injector is x64 or ARM64 (native)
#if defined(_M_X64)
        constexpr USHORT injectorArch = 0x8664; // AMD64
        constexpr const char* injectorArchName = "x64";
#elif defined(_M_ARM64)
        constexpr USHORT injectorArch = 0xAA64; // ARM64
        constexpr const char* injectorArchName = "ARM64";
#else
        constexpr USHORT injectorArch = 0;
        constexpr const char* injectorArchName = "Unknown";
#endif

        if (m_arch != injectorArch) {
            std::string error = "Architecture mismatch!\n";
            error += "  Injector: " + std::string(injectorArchName) + "\n";
            error += "  Target:   " + GetArchName(m_arch) + "\n";
            error += "  Solution: Use chromelevator_" + std::string(m_arch == 0xAA64 ? "arm64" : "x64") + ".exe";
            throw std::runtime_error(error);
        }
    }

}
