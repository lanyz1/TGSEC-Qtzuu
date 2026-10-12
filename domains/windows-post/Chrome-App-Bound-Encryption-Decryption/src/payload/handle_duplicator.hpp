// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "../sys/internal_api.hpp"
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <set>
#include <map>

namespace Payload {

    class HandleDuplicator {
    public:
        // Result of a duplication attempt
        struct DuplicatedHandle {
            Core::UniqueHandle handle;
            DWORD sourcePid;
            ULONG_PTR originalHandle;
            std::wstring objectName;
        };

        // Callback for logging (optional)
        using LogCallback = std::function<void(const std::string&)>;

        explicit HandleDuplicator(LogCallback logger = nullptr);
        ~HandleDuplicator() = default;

        // Non-copyable, moveable
        HandleDuplicator(const HandleDuplicator&) = delete;
        HandleDuplicator& operator=(const HandleDuplicator&) = delete;
        HandleDuplicator(HandleDuplicator&&) = default;
        HandleDuplicator& operator=(HandleDuplicator&&) = default;

        // Find and duplicate handles to the specified file path
        // Returns all successfully duplicated handles (there may be multiple)
        [[nodiscard]] std::vector<DuplicatedHandle> DuplicateFileHandles(
            const std::filesystem::path& targetPath);

        // Read entire file contents using a duplicated handle
        [[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileViaHandle(HANDLE hFile);

        // Copy locked file to a temporary location
        // Returns the path to the temp file, or nullopt on failure
        [[nodiscard]] std::optional<std::filesystem::path> CopyLockedFile(
            const std::filesystem::path& sourcePath,
            const std::filesystem::path& destDir);

        // Check if a file is accessible (can be opened normally)
        [[nodiscard]] static bool IsFileAccessible(const std::filesystem::path& path);

    private:
        LogCallback m_logger;

        // Internal helper methods
        void Log(const std::string& msg);
        
        // Get the object name for a handle (resolves to NT path)
        [[nodiscard]] std::optional<std::wstring> GetObjectName(HANDLE hObject);
        
        // Convert DOS path to NT path for comparison
        [[nodiscard]] std::wstring DosPathToNtPath(const std::filesystem::path& dosPath);
        
        // Open a process for handle duplication
        [[nodiscard]] Core::UniqueHandle OpenProcessForDuplication(DWORD pid);
        
        // Get file size via handle
        [[nodiscard]] std::optional<LONGLONG> GetFileSizeViaHandle(HANDLE hFile);
        
        // Get all PIDs of browser processes (same executable name)
        [[nodiscard]] std::vector<DWORD> GetBrowserProcessPids();
    };

}
