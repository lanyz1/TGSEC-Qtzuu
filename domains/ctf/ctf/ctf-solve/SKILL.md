---
name: ctf-solve
description: "CTF 综合解题编排器。当面对未知类型的 CTF 挑战、需要自动分析挑战类型并选择正确解题路径时使用。自动调度对应的专项 skill（pwn/crypto/web/reverse/forensics/osint/malware/misc），适合给定挑战文件或服务端点但不确定属于哪个类别的场景"
metadata:
  tags: "ctf,solve,编排,orchestrator,challenge,解题"
  category: "ctf"
---

# CTF 综合解题编排器

## Phase 1: 解题流程

### 1.1 侦察

```bash
file *                          # 识别文件类型
strings binary | grep -i flag   # 快速字符串搜索
xxd binary | head -20           # Hex 头部
binwalk -e firmware.bin         # 提取嵌入文件
checksec --file=binary          # 检查保护
nc host port                    # 连接远程服务
```

### 1.2 分类与 Skill 调度

**按文件类型：**

| 文件类型 | 分类 | 调度 Skill |
|----------|------|-----------|
| .pcap/.evtx/.raw/.dd | 取证 | ctf-forensics |
| ELF/PE + 远程服务 | Pwn | ctf-pwn |
| ELF/PE/APK/.pyc/WASM | 逆向 | ctf-reverse |
| .py/.sage + 数字 | 密码学 | ctf-crypto |
| Web URL/HTML/JS/PHP | Web | ctf-web-methodology |
| 图片/音频/PDF(无明显内容) | 隐写取证 | ctf-forensics |

**按关键词：**

| 关键词 | 分类 |
|--------|------|
| overflow/ROP/shellcode/heap | ctf-pwn |
| RSA/AES/cipher/lattice/LWE | ctf-crypto |
| XSS/SQLi/JWT/SSRF | ctf-web-methodology |
| disk image/memory dump/registry | ctf-forensics |
| find/locate/identify/who/where | ctf-osint |
| obfuscated/C2/malware/beacon | ctf-malware |
| jail/sandbox/encoding/game | ctf-misc |

### 1.3 卡住时转向

1. **重新分类** — 很多题跨分类（Web+Crypto, Forensics+Crypto, Reverse+Pwn）
2. **检查遗漏** — 隐藏文件、备用端口、响应头、注释、元数据
3. **简化** — 检查是否有更简单路径（默认凭据、已知CVE、逻辑漏洞）

**常见跨分类模式：**
- 取证 + 密码学：PCAP/磁盘中的加密数据
- Web + 逆向：WASM 或混淆 JS
- Web + 密码学：JWT 伪造、自定义签名
- 逆向 + Pwn：先逆向再利用
- OSINT + 隐写：社交媒体 Unicode 同形字

## Phase 2: 辅助信息

### 2.1 Flag 格式

常见：`flag{...}` / `CTF{...}` / 自定义前缀（`ENO{...}` / `HTB{...}`）

```bash
grep -rniE '(flag|ctf|eno|htb|pico)\{' .
strings output.bin | grep -iE '\{.*\}'
```

### 2.2 卡住时策略
- 回退侦察：robots.txt、.git、备份文件、目录扫描

### 2.3 文件类型识别
- SQLite 数据库文件：用 sqlite3 命令打开，.tables 查询表结构
