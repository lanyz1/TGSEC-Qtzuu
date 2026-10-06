# av-evasion-skills 要点（V5.2，自 README / SKILL.md 提炼）

- 定位：Shellcode 处理 + Windows Loader 免杀技巧的研究实现（作者 bluechips，V5.2，2026-08-10）；验证截图见源仓库文末，无完整测试矩阵/样本哈希，不能作为当前环境的免杀保证。
- 版本线：v4.1 行为伪装（WriteProcessMemory/HeapAlloc/函数指针调用）→ v5.0 绕 Hook（Indirect Syscall + Halo's Gate + ETW 补丁）→ v5.1 消特征（字符串编译期 XOR、.text Code Cave）→ v5.2 单文件（内嵌 payload 数据、IPv4 编译期 XOR 0x5A）。
- 处理链：shellcode-patch.py（同义等长指令替换，如 test rax,rax→or rax,rax）→ shellcode-encrypt.py（自定义密钥 XOR）→ shellcode-obfuscate-ipv4.py（伪装 IPv4 数组）→ gen_embed_data.py（生成 XOR 加密的 payload_data.h）。
- Loader 流程：PatchETW → 栈上解密内嵌密钥 → HeapAlloc + IPv4 手动反混淆 + XOR 解密 → SecureZeroMemory → LoadLibraryA(msimg32.dll，回退 dcomp.dll/dwmapi.dll) → 解析 .text 段 → Indirect Syscall 写入（回退 WriteProcessMemory）→ FlushInstructionCache → 清理 stub → 函数指针调用。
- Syscall stub 共 22 字节：`mov r10,rcx; mov eax,SSN; jmp [rip+0] + syscall;ret 地址`；存放于自身 .text padding（Code Cave，天然 RX，零额外可执行内存），用后恢复原始 padding。
- 编译：`gcc -mwindows -o loader.exe loader_v5.c -s`（GUI 无窗口、去符号、零额外链接库）。
- 注意：syscall number 随 Windows 版本变化，运行时经 Halo's Gate 动态解析；源仓库 scripts/ 下示例 shellcode tcp_windows_amd64.bin 为二进制，本卡未收录。

@TGSEC社区 · @TGSEC-Qtzuu 整理
