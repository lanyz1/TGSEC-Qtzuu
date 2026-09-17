#include <Windows.h> 
#include <tlhelp32.h> 
#include <vector> 
#include <string> 
#include <algorithm>
#include <iostream>

//If there're multiple processes with same name
std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName) {
	std::vector<DWORD> pids;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "[!]Invalid Snapshot handle value return" << std::endl;
		return pids;
	}

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(entry);
	if (Process32FirstW(hSnapshot, &entry)) {
		do {
			std::wstring exe(entry.szExeFile);
			std::wstring exeLower = exe;
			std::wstring nameLower = processName;
			std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), ::towlower);
			std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
			if (exeLower == nameLower) {
				pids.push_back(entry.th32ProcessID);
			}
		} while (Process32NextW(hSnapshot, &entry));
	}

	CloseHandle(hSnapshot);
	return pids;
}