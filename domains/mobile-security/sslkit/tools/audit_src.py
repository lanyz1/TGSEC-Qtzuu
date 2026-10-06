import re
src = open('app/src/main/cpp/sslkit.c').read()

print("="*70)
print("【1】hook 回调里对 original 的所有调用点 —— 检查是否可能自递归")
print("="*70)
# 找所有 replacement 函数里调用 find_original 的地方
for m in re.finditer(r'static\s+\S+\s+(sslkit_\w+)\s*\(([^)]*)\)\s*\{', src):
    name = m.group(1)
    start = m.end()
    depth = 1; i = start
    while i < len(src) and depth > 0:
        if src[i] == '{': depth += 1
        elif src[i] == '}': depth -= 1
        i += 1
    body = src[start:i]
    if 'find_original' in body:
        print(f"  {name}: 调用 find_original -> 需确认指向 trampoline")

print()
print("="*70)
print("【2】original 赋值点 —— 是否可能等于被 hook 的地址")
print("="*70)
for m in re.finditer(r'g_hooks\[h\]\.original\s*=\s*([^;]+);', src):
    print(f"  line {src[:m.start()].count(chr(10))+1}: {m.group(1).strip()}")
for m in re.finditer(r'g_hooks\[i\]\.original\s*=\s*([^;]+);', src):
    print(f"  line {src[:m.start()].count(chr(10))+1}: {m.group(1).strip()}")

print()
print("="*70)
print("【3】write_abs_jump 调用点 —— 覆盖 16 字节，检查目标函数是否 <16 字节")
print("="*70)
for m in re.finditer(r'write_abs_jump\(', src):
    line = src[:m.start()].count(chr(10))+1
    ctx = src[max(0,m.start()-200):m.start()+100]
    print(f"  line {line}: ...{ctx[-120:].strip()[:110]}")

print()
print("="*70)
print("【4】必须互斥的路径检查")
print("="*70)
checks = [
    ("GOT hook 是否检查 g_hooks[h].hooked", r'if \(g_hooks\[h\]\.hooked\) break;'),
    ("inline hook 是否检查 g_hooks[h].hooked", r'if \(g_hooks\[h\]\.hooked\) break;'),
    ("trampoline 是否为 NULL 时跳过", r'if \(ih->trampoline == NULL\)'),
]
for label, pat in checks:
    n = len(re.findall(pat, src))
    print(f"  {'OK ' if n>0 else '!!!'} {label}: {n} 处")

print()
print("="*70)
print("【5】日志限流检查（避免 logcat 拖慢时序）")
print("="*70)
for m in re.finditer(r'LOGI\("SSL_CTX_set_custom_verify called[^"]*"', src):
    print(f"  {m.group()}")
    break
if re.search(r'\(n % 100\)', src):
    print("  OK 有 %100 限流")
else:
    print("  !!! 无日志限流")
