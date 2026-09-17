#include <Windows.h>
#include <iostream>

BOOL LoadDriver(LPCWSTR DriverName, LPCWSTR DriverPath) {
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL) {
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Open SC Manager Failed" << std::endl;
		return FALSE;
	}

	SC_HANDLE schService = CreateServiceW(schSCManager, DriverName, DriverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, DriverPath, NULL, NULL, NULL, NULL, NULL);
	if (schService == NULL) {
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Create Driver Service Failed" << std::endl;
		return FALSE;
	}

	if (StartService(schService, 0, 0) == 0) {
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Start Driver Service Failed" << std::endl;
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	std::cout << "[+]Load Driver Success." << std::endl;
	return TRUE;
}

BOOL UnloadDriver(LPCWSTR DriverName) {
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL) {
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Open SC Manager Failed" << std::endl;
		return FALSE;
	}

	SC_HANDLE schService = OpenService(schSCManager, DriverName, SERVICE_ALL_ACCESS);
	if (schService == NULL) {
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Open Driver Service Failed" << std::endl;
		return FALSE;
	}

	SERVICE_STATUS status;
	if (QueryServiceStatus(schService, &status) == 0) {
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Query Service Status Failed" << std::endl;
		return FALSE;
	}
	if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING) {
		if (ControlService(schService, SERVICE_CONTROL_STOP, &status) == 0) {
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			std::cout << "[-]Service Stop Failed" << std::endl;
			return FALSE;
		}
	}
	if (DeleteService(schService) == 0) {
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		std::cout << "[-]Delete Driver Service Failed" << std::endl;
		return FALSE;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	std::cout << "[+]Unload Driver Success, Please reboot your PC for full unload!" << std::endl;
	return TRUE;
}