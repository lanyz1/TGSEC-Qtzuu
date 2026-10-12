// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "browser_discovery.hpp"
#include "../sys/internal_api.hpp"
#include <algorithm>
#include <map>

#pragma comment(lib, "version.lib")

namespace Injector {

    namespace {
        const std::map<std::wstring, std::pair<std::wstring, std::string>> g_browserMap = {
            {L"chrome", {L"chrome.exe", "Chrome"}},
            {L"chrome-beta", {L"chrome.exe", "Chrome Beta"}},
            {L"edge", {L"msedge.exe", "Edge"}},
            {L"brave", {L"brave.exe", "Brave"}},
            {L"avast", {L"AvastBrowser.exe", "Avast"}}
        };
    }

    std::vector<BrowserInfo> BrowserDiscovery::FindAll() {
        std::vector<BrowserInfo> results;
        for (const auto& [type, info] : g_browserMap) {
            auto path = ResolvePath(type, info.first);
            if (!path.empty()) {
                results.push_back({type, info.first, path, info.second, GetFileVersion(path)});
            }
        }
        return results;
    }

    std::optional<BrowserInfo> BrowserDiscovery::FindSpecific(const std::wstring& type) {
        std::wstring lowerType = type;
        std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::towlower);

        auto it = g_browserMap.find(lowerType);
        if (it == g_browserMap.end()) return std::nullopt;

        auto path = ResolvePath(lowerType, it->second.first);
        if (path.empty()) return std::nullopt;

        return BrowserInfo{lowerType, it->second.first, path, it->second.second, GetFileVersion(path)};
    }

    static bool ValidatePathForBrowser(const std::wstring& path, const std::wstring& browserType) {
        std::wstring lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (browserType == L"chrome") {
            return lowerPath.find(L"\\google\\chrome\\") != std::wstring::npos &&
                   lowerPath.find(L"\\google\\chrome beta\\") == std::wstring::npos;
        } else if (browserType == L"chrome-beta") {
            return lowerPath.find(L"\\google\\chrome beta\\") != std::wstring::npos;
        }
        return true;
    }

    std::wstring BrowserDiscovery::ResolvePath(const std::wstring& browserType, const std::wstring& exeName) {
        if (browserType != L"chrome" && browserType != L"chrome-beta") {
            const std::wstring appPaths[] = {
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName,
                L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName
            };

            for (const auto& regPath : appPaths) {
                auto path = QueryRegistry(regPath);
                if (!path.empty() && std::filesystem::exists(path)) {
                    return path;
                }
            }
        }

        std::vector<std::pair<std::wstring, std::wstring>> altRegistry;

        if (browserType == L"chrome") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome\\shell\\open\\command", L""}
            };
        } else if (browserType == L"chrome-beta") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome Beta\\shell\\open\\command", L""}
            };
        } else if (browserType == L"edge") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Microsoft Edge\\shell\\open\\command", L""}
            };
        } else if (browserType == L"brave") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brave-Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brave-Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Brave\\shell\\open\\command", L""}
            };
        } else if (browserType == L"avast") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Avast Secure Browser\\shell\\open\\command", L""}
            };
        }

        for (const auto& [regKey, valueName] : altRegistry) {
            auto result = QueryRegistryValue(regKey, valueName);
            if (!result.empty()) {
                std::wstring fullPath;
                if (valueName == L"InstallLocation") {
                    fullPath = result + L"\\" + exeName;
                } else {
                    size_t start = (result[0] == L'"') ? 1 : 0;
                    size_t end = result.find(L'"', start);
                    if (end == std::wstring::npos) end = result.find(L' ', start);
                    if (end == std::wstring::npos) end = result.length();
                    fullPath = result.substr(start, end - start);
                }
                if (std::filesystem::exists(fullPath) && ValidatePathForBrowser(fullPath, browserType)) {
                    return fullPath;
                }
            }
        }

        return L"";
    }

    std::wstring BrowserDiscovery::QueryRegistryValue(const std::wstring& keyPath, const std::wstring& valueName) {
        std::vector<wchar_t> pathBuffer(keyPath.begin(), keyPath.end());
        pathBuffer.push_back(L'\0');

        UNICODE_STRING_SYSCALLS keyName;
        keyName.Buffer = pathBuffer.data();
        keyName.Length = static_cast<USHORT>(keyPath.length() * sizeof(wchar_t));
        keyName.MaximumLength = static_cast<USHORT>(pathBuffer.size() * sizeof(wchar_t));

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE hKey = nullptr;
        NTSTATUS status = NtOpenKey_syscall(&hKey, KEY_READ, &objAttr);
        if (status != 0) return L"";

        Core::UniqueHandle keyGuard(hKey);

        std::vector<wchar_t> valueBuffer(valueName.begin(), valueName.end());
        valueBuffer.push_back(L'\0');

        UNICODE_STRING_SYSCALLS valueNameStr;
        valueNameStr.Buffer = valueName.empty() ? nullptr : valueBuffer.data();
        valueNameStr.Length = static_cast<USHORT>(valueName.length() * sizeof(wchar_t));
        valueNameStr.MaximumLength = static_cast<USHORT>(valueBuffer.size() * sizeof(wchar_t));

        ULONG bufferSize = 4096;
        std::vector<BYTE> buffer(bufferSize);
        ULONG resultLength = 0;

        status = NtQueryValueKey_syscall(hKey, &valueNameStr, KeyValuePartialInformation,
                                         buffer.data(), bufferSize, &resultLength);

        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {
            buffer.resize(resultLength);
            bufferSize = resultLength;
            status = NtQueryValueKey_syscall(hKey, &valueNameStr, KeyValuePartialInformation,
                                             buffer.data(), bufferSize, &resultLength);
        }

        if (status != 0) return L"";

        auto kvpi = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer.data());
        if (kvpi->Type != 1 && kvpi->Type != 2) return L"";
        if (kvpi->DataLength < sizeof(wchar_t) * 2) return L"";

        size_t charCount = kvpi->DataLength / sizeof(wchar_t);
        std::wstring path(reinterpret_cast<wchar_t*>(kvpi->Data), charCount);
        while (!path.empty() && path.back() == L'\0') path.pop_back();

        if (path.empty()) return L"";

        if (kvpi->Type == 2) {
            std::vector<wchar_t> expanded(MAX_PATH * 2);
            DWORD size = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), static_cast<DWORD>(expanded.size()));
            if (size > 0 && size <= expanded.size()) {
                path = std::wstring(expanded.data());
            }
        }

        return path;
    }

    std::wstring BrowserDiscovery::QueryRegistry(const std::wstring& keyPath) {
        std::vector<wchar_t> pathBuffer(keyPath.begin(), keyPath.end());
        pathBuffer.push_back(L'\0');

        UNICODE_STRING_SYSCALLS keyName;
        keyName.Buffer = pathBuffer.data();
        keyName.Length = static_cast<USHORT>(keyPath.length() * sizeof(wchar_t));
        keyName.MaximumLength = static_cast<USHORT>(pathBuffer.size() * sizeof(wchar_t));

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE hKey = nullptr;
        NTSTATUS status = NtOpenKey_syscall(&hKey, KEY_READ, &objAttr);

        if (status != 0) return L"";

        Core::UniqueHandle keyGuard(hKey);

        UNICODE_STRING_SYSCALLS valueName = {0, 0, nullptr};
        ULONG bufferSize = 4096;
        std::vector<BYTE> buffer(bufferSize);
        ULONG resultLength = 0;

        status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                         buffer.data(), bufferSize, &resultLength);

        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {
            buffer.resize(resultLength);
            bufferSize = resultLength;
            status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                             buffer.data(), bufferSize, &resultLength);
        }

        if (status != 0) return L"";

        auto kvpi = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer.data());

        if (kvpi->Type != 1 && kvpi->Type != 2) return L"";
        if (kvpi->DataLength < sizeof(wchar_t) * 2) return L"";

        size_t charCount = kvpi->DataLength / sizeof(wchar_t);
        std::wstring path(reinterpret_cast<wchar_t*>(kvpi->Data), charCount);

        while (!path.empty() && path.back() == L'\0') path.pop_back();

        if (path.empty()) return L"";

        if (kvpi->Type == 2) {
            std::vector<wchar_t> expanded(MAX_PATH * 2);
            DWORD size = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), static_cast<DWORD>(expanded.size()));
            if (size > 0 && size <= expanded.size()) {
                path = std::wstring(expanded.data());
            }
        }

        return path;
    }

    std::string BrowserDiscovery::GetFileVersion(const std::wstring& filePath) {
        DWORD dummy = 0;
        DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
        if (size == 0) return "";

        std::vector<BYTE> buffer(size);
        if (!GetFileVersionInfoW(filePath.c_str(), 0, size, buffer.data())) return "";

        VS_FIXEDFILEINFO* fileInfo = nullptr;
        UINT len = 0;
        if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &len)) return "";
        if (len == 0 || fileInfo == nullptr) return "";

        return std::to_string(HIWORD(fileInfo->dwFileVersionMS)) + "." +
               std::to_string(LOWORD(fileInfo->dwFileVersionMS)) + "." +
               std::to_string(HIWORD(fileInfo->dwFileVersionLS)) + "." +
               std::to_string(LOWORD(fileInfo->dwFileVersionLS));
    }

}
