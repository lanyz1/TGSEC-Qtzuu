# 内核桥接五级降级链（bridge_universal）

> 来源：`native_bridge_universal.js`（494 行）逆向整理。同一份桥接层适配多种 exploit 框架，按优先级降级尝试，最终导出统一 API：`nativeExecShell` / `nativeReadFile` / `nativeListDir`（别名 `execShell` / `readFile` / `listFiles`）。

## 降级顺序

```
① callSymbol 类原语（原生符号调用框架）
② 已有 execShell 全局函数（其他框架注入）
③ obChTK 类提权对象（链E 体系）
④ p.read64/write64 或 fcall 通用内核 R/W（含符号解析）
⑤ XHR POST /shell（服务端 execSync 回退）
└─ 全部失败 → 强制 ⑤；再失败 → 占位函数（返回错误串，不崩）
```

每级成功标准：导出 `nativeExecShell` 且**自检通过**（见下）。

## ① callSymbol 类原语

条件：全局 `Native` 对象 + `Native.callSymbol` 函数 + `Native.mem`/`Native.memSize`。

| 能力 | 实现 |
|---|---|
| shell | `Native.callSymbol('popen', cmd)` |
| 读文件 | `open(path, 0)` → 循环 `read(fd, Native.mem, min(memSize, 0x4000))` → `Native.read(mem, n)` → Uint8Array 合并 → `close` |
| 列目录 | `popen('ls -1a "<path>" 2>/dev/null')` 按行拆分 |

细节：分块大小 `min(memSize, 16KB)`；合并用 `new Uint8Array(total)` + `set()`（修复 ArrayBuffer 拼接 bug）。

## ② 已有 execShell

条件：全局 `execShell` 为函数。直接复用，标注 bridgeType=`existing-execShell`。

## ③ obChTK 类提权对象

条件：全局 `obChTK`。两种形态：

| 形态 | 检测 | 能力 |
|---|---|---|
| 直接内核 R/W | `tk.Ki` 且 `tk.Hi` 为函数 | 内核读写原语 |
| shellcode 执行 | `tk.si` 为函数 | 执行 shellcode |

## ④ 通用内核 R/W / fcall

### 形态 A：p.read64/p.write64

条件：全局 `p` 有 `read64`+`write64`。直接使用。

### 形态 B：fcall

条件：全局 `fcall` 为函数（或 `p.fcall`）。核心机制：

**符号解析双通道**（`_getSym`）：
1. 动态解析：`func_resolve(name)`（若存在）
2. 静态符号表：全局 `_STATIC_SYMS_1583`（1,583 个符号的静态表，含 `_name` 前缀兼容）
3. 缓存：`_symCache` 命中即返回

**动态 dlsym 解析**（静态表缺失时）：
1. `dlopen('/usr/lib/libSystem.B.dylib', RTLD_LAZY=1)`，失败试 `/usr/lib/libc.dylib`
2. `dlsym(handle, name)` → 地址入缓存

**字符串→指针**（`_strToPtr`）：`malloc(len)` + `p.write8(buf+i, charCode)` 逐字节写 + NUL 结尾，结果缓存；`_bridgeFreeCStrings()` 用 `free` 批量释放。

**fcall 参数规范**：所有 Number 参数转 BigInt；`_fcallBridged` 时用 `p.fcall`，否则全局 `fcall`。

**execShell 三级策略**（fcall 模式）：
1. `popen(cmd, "r")` → `fread(buf, 1, 16384, fp)` → `p.read8` 逐字节读回 → `pclose`（注意：`free(buf)` 在 `pclose` **前**调用，存在 UAF 时序）
2. `system(cmd)` → 返回 ret 码
3. `posix_spawn(0, "/bin/sh", 0, 0, ["sh","-c",cmd], 0)` → 返回 ret 码

**readFile**：`open(path, 0)` → `malloc(≤64KB)` → `read(fd, buf, size)` → `p.read8` 逐字节读出 → `close` → `free`。

**listDir**：`execShell('ls -1a "<path>" 2>/dev/null')`。

## ⑤ XHR 服务端 shell（保底）

条件：`XMLHttpRequest` 存在。**同步**请求 `POST /shell`，body `{cmd}`，解析响应 `output` 字段。

```
readFile → execShell('cat "<path>" 2>/dev/null | head -c <max>')
listDir  → execShell('ls -1a "<path>" 2>/dev/null')
```

## 自检机制

fcall 模式安装后必须自检：`echo __BRIDGE_OK_<随机5位>__` → 输出含 `BRIDGE_OK_` 才算成功；失败则 `nativeBridgeReady=false` 并降级到 ⑤。

## 导出契约

| 全局 API | 签名 | 说明 |
|---|---|---|
| `nativeExecShell` | `(cmd) → string` | 任意命令执行 |
| `nativeReadFile` | `(path, maxBytes?) → string|null` | 读文件，默认 512KB |
| `nativeListDir` | `(path) → string[]` | 列目录 |
| `nativeBridgeReady` | boolean | 桥接可用标志 |
| `nativeBridgeType` | string | 生效级别标识（检测用） |
| `_universalBridgeOK` | boolean | 整体成功标志 |
| `execShell/readFile/listFiles` | 别名 | harvest 模块调用入口 |
