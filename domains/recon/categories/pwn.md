# PWN - 二进制漏洞与利用

> 来源：CTF实战 / CWE / HackTricks
> 条目前缀：KB-PWN | 覆盖：堆溢出、栈溢出、格式化字符串、整数溢出

---

### [KB-PWN-01] PHP zend_mm Off-by-one 堆溢出
- **类别**: PWN / 堆利用
- **信号**: `X-PHP-Version` header；debug 输出 input_len 或 strlen；自定义 .so PHP 扩展；`X-Alloc-Bins` header
- **原理**: PHP 扩展使用 `_emalloc(n)` 但写入 n+1 字节，null byte 溢出到相邻 heap slot 的 next_free_slot 指针 LSB。PHP 8.1 zend_mm allocator 中可导致 free list corruption。**仅当 N+1 == bin_size 时触发**（非所有边界）。
- **检测**: 对每个 bin 边界值发送 `len(u)+len(p)=bin_size-1` 的输入，观察响应体大小是否差 1 字节
- **利用**: 目标：覆盖 `return_value->u1.type_info` 从 `IS_FALSE(0x2)` 到 `IS_TRUE(0x3)`。路径：off-by-one → 破坏相邻 free slot LSB → free list corruption → chain → `_emalloc` 返回目标地址 → 写入 IS_TRUE。**关键发现**: PHP VM 栈由 zend_mm 堆分配，return_value 在堆上（非系统栈），理论可及。**核心阻塞**: 函数末尾 `movl $0x2, 0x8(%rbp)` 必定覆盖 return_value。**替代目标**: `sapi_module.ub_write` 函数指针。
- **相关 CVE**: CVE-2022-31626 — PHP mysqlnd heap buffer overflow 使用同类技术（POST 变量堆整形 + fake free slot + zend_string overlap）
- **修复**: 代码审计确保分配与实际写入匹配；使用安全内存分配 API；隐藏 debug 信息
- **参考**: CWE-122 / CWE-193 / Echoes of Heap 案例 (v1+v2) / CFandR-github/PHP-binary-bugs

### [KB-PWN-02] 栈缓冲区溢出 (Stack Buffer Overflow)
- **类别**: PWN / 栈利用
- **信号**: C/C++ 程序使用 gets()/strcpy()/sprintf() 等不安全函数；输入长度超过缓冲区时程序崩溃 (SIGSEGV)
- **原理**: 局部变量在栈上分配固定大小，写入超长数据覆盖返回地址（RIP/EIP）。控制返回地址可劫持执行流实现 RCE。
- **检测**: 发送递增长度输入直到程序崩溃；dmesg 检查 segfault 地址；gdb 分析 core dump
- **利用**: EIP/RIP 覆盖 → ROP/JOP chain → ret2libc → system("/bin/sh")
- **防护**: Stack Canary、NX/DEP、ASLR、PIE、FORTIFY_SOURCE；安全函数 fgets/strncpy/snprintf
- **参考**: CWE-121 / MITRE ATT&CK T1068

### [KB-PWN-03] 格式化字符串漏洞 (Format String)
- **类别**: PWN / 格式化字符串
- **信号**: printf(user_input) 而非 printf("%s", user_input)；输入 `%x %x %x` 泄露栈内容
- **原理**: printf 系列函数的 format string 参数可被用户控制时，通过 `%n` 写入任意地址、`%x/%p` 泄露栈/内存内容。
- **检测**: 输入 `%p.%p.%p` 或 `%n` 观察程序崩溃或输出栈数据
- **利用**: `%x` 泄露 → 获取 libc 基址 → `%n` 写入 GOT 表 → 劫持函数指针
- **防护**: 编译选项 `-Wformat -Wformat-security`；永远使用 printf("%s", user_input)
- **参考**: CWE-134 / OWASP: Format String

### [KB-PWN-04] 整数溢出 (Integer Overflow)
- **类别**: PWN / 整数安全
- **信号**: 输入超大数值导致计算溢出；`malloc(size * count)` 中乘积溢出变小数
- **原理**: 有符号/无符号整数运算溢出或截断，导致分配小于预期的内存或绕过大小检查。
- **检测**: 输入边界值 (0, -1, INT_MAX, INT_MIN, UINT_MAX) 观察异常行为
- **利用**: `malloc(user_input * element_size)` → user_input 超大导致乘积溢出为小数 → heap overflow
- **防护**: 编译器 `-ftrapv` (有符号溢出陷阱)；使用安全整数库；运算前做溢出检查
- **参考**: CWE-190 / CWE-680 / CERT INT32-C

### [KB-PWN-05] Use-After-Free (UAF)
- **类别**: PWN / 堆利用
- **信号**: 对象释放后仍被引用；悬空指针导致崩溃或可利用
- **原理**: 内存被 free 后指针未置 NULL，后续使用该悬空指针访问已被重新分配的内存，导致类型混淆或控制流劫持。
- **检测**: AddressSanitizer (ASAN)；valgrind；代码审计重点关注 free 后未置 NULL 的指针
- **利用**: free victim object → alloc attacker-controlled data of same size → use dangling pointer → type confusion → RCE
- **防护**: free 后立即 ptr=NULL；智能指针 (C++ shared_ptr/unique_ptr)；ASAN 运行时检测
- **参考**: CWE-416 / OWASP: Memory Safety
