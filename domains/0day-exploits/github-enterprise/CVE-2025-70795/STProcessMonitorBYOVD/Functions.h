#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>

BOOL EnableSeDebugPrivilege();
BOOL LoadDriver(LPCWSTR DriverName, LPCWSTR DriverPath);
BOOL UnloadDriver(LPCWSTR DriverName);
BOOL EnableSeTcbPrivilege();
std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName);