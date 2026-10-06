# S-inject 要点（自 README / SECURITY_AUDIT_GUIDE.md 提炼）

- 定位：DLL + Shellcode 的 Windows 注入免杀工具，仅罗列各类方法；完整 C++/CMake 源码在 GitHub（src/ include/ extern/，约 2500 行），本卡收录 README、v2.0 README 与自审指南。
- DLL 注入：远程线程、APC 队列、反射式注入（manual mapping，基于 stephenfewer/ReflectiveDLLInjection；2025-11-28 起支持任意 x64 DLL，新增 .pdata 异常处理映射）。
- Shellcode 注入：远程线程 / APC / 上下文注入（SetThreadContext + ResumeThread）；shellcode 用 base64 编码（字符串或文件）。
- 免杀：64 位 CreateRemoteThread 改为直接系统调用（SysWhispers3 / ParallelSyscall-RIFT 技术）；PoolParty 线程池注入（基于 SafeBreach-Labs/PoolParty，2026-2 起为 shellcode-only 不稳定版）。
- CLI：`-method <rmtdll|refdll|apcdll|net|rmtsc|apcsc|ctxsc|rmtfie|apcfile|ctxfile> -proc <进程名> -path <DLL路径|URL|base64 shellcode|文件路径> [-pid]`（方法列表与示例命令拼写不完全一致，原文如此）。
- 示例：`S-Inject.exe -method rmtfile -args "...\shellcode_x64.txt" -proc x64dbg`。
- net 方法：从用户提供的 http URL 拉取 DLL，不落地加载（需反射式注入格式的 DLL）。
- GUI：Dear ImGui + DirectX 11，Docking 布局；2026-5 起支持对选定进程自动测试 远程线程/APC/反射式 三种 DLL 注入。
- 编译：CMake x64（`cmake .. -G "Visual Studio 17 2022" -A x64` → `cmake --build . --config Release`）；GitHub Actions 支持手动触发构建 exe 产物。
- 自审结论（2026-05-18，全源码审查）：无 socket/C2、无持久化（注册表/计划任务/服务）、无数据外传、无混淆；唯一网络功能 = 用户指定 URL 的 DLL 下载。
- 内嵌引导 shellcode：`include/app/Injector.hpp` 的 bootshellcode[3568] 为 RDI 引导 shellcode（PE 解析→重定位→导入表→DllMain），无额外行为。

@TGSEC社区 · @TGSEC-Qtzuu 整理
