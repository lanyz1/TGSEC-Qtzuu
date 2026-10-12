// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <vector>
#include <string>
#include <optional>

namespace Injector {

    struct BrowserInfo {
        std::wstring type;
        std::wstring exeName;
        std::wstring fullPath;
        std::string displayName;
        std::string version;
    };

    class BrowserDiscovery {
    public:
        static std::vector<BrowserInfo> FindAll();
        static std::optional<BrowserInfo> FindSpecific(const std::wstring& type);

    private:
        static std::wstring ResolvePath(const std::wstring& browserType, const std::wstring& exeName);
        static std::wstring QueryRegistry(const std::wstring& keyPath);
        static std::wstring QueryRegistryValue(const std::wstring& keyPath, const std::wstring& valueName);
        static std::string GetFileVersion(const std::wstring& filePath);
    };

}
