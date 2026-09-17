# STProcessMonitorBYOVD

Reference: https://bbs.kafan.cn/thread-2288675-1-1.html


Usage:

1. Place the vulnerable driver under the same directory of the exe. The version 11.11.4.0 (the older one) is with CVE-2025-70795 / CVE-2026-0828, compatible with the parameter /Kill; The version 11.26.18 (Updated) is compatible with parameter /Terminate.

2. /Init - Install the driver. /Kill - Use CVE-2025-70795 / CVE-2026-0828 to terminate processes. /Terminate - Use the updated driver to terminate processes. /Uninst - Unload the driver.


 Screenshots

Exploit CVE-2025-70795 / CVE-2026-0828 (Please notice that the '/Kill' operate is without any priviledge)
 <img width="1015" height="528" alt="屏幕截图 2026-02-14 200828" src="https://github.com/user-attachments/assets/e58fc75c-6b08-40a5-8168-b1890e8e79bb" />
<img width="758" height="470" alt="屏幕截图 2026-02-14 201224" src="https://github.com/user-attachments/assets/a4fc8777-d177-4015-9782-b73c105d70f0" />

The updated driver verifys if the control code is from an NT AUTHORITY\SYSTEM process, so we need to get at least Administrator priviledge to use the new driver.

<img width="1893" height="1019" alt="160139uqz99h29c96anwyg" src="https://github.com/user-attachments/assets/1c8d69d0-a186-4f66-8faf-a01d82339a26" />
<img width="747" height="374" alt="屏幕截图 2026-02-14 201729" src="https://github.com/user-attachments/assets/e2ce3486-619f-4237-bc4e-9b2fb20c34b1" />
