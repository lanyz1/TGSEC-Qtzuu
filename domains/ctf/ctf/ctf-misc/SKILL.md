---
name: ctf-misc
description: "CTF 杂项挑战技术。当遇到编码谜题、Python/Bash 沙箱逃逸、RF/SDR 信号、游戏/VM 逆向、K8s RBAC、浮点数技巧、Z3 约束求解、博弈论等不属于 pwn/crypto/web/reverse/forensics/osint 的 CTF 挑战时使用。先排除其他分类后再使用本技能"
metadata:
  tags: "ctf,misc,杂项,pyjail,bashjail,encoding,sdr,dns,game,z3"
  category: "ctf"
---

# CTF 杂项挑战

## 深入参考

以下参考资料**按需加载**，根据识别出的具体方向选择对应文件：

- Python 沙箱逃逸（受限字符/func_globals链/类属性持久化） → [references/pyjails.md](references/pyjails.md)
- Bash 沙箱/受限Shell逃逸 → [references/bashjails.md](references/bashjails.md)
- 编码与解码（QR/esolang/Verilog/BCD/Gray码/SMS PDU） → [references/encodings.md](references/encodings.md)
- RF/SDR 信号处理（QAM-16/载波恢复/定时同步） → [references/rf-sdr.md](references/rf-sdr.md)
- DNS 利用（ECS欺骗/NSEC遍历/IXFR/重绑定/隧道） → [references/dns.md](references/dns.md)
- 游戏与VM Part1（WASM/Roblox/PyInstaller/K8s/Z3/浮点） → [references/games-and-vms.md](references/games-and-vms.md)
- 游戏与VM Part2（ML权重/WebSocket/Flask/LoRA/De Bruijn） → [references/games-and-vms-2.md](references/games-and-vms-2.md)
- 游戏与VM Part3（memfd/博弈/ROM切换/Benford/BuildKit） → [references/games-and-vms-3.md](references/games-and-vms-3.md)
- Linux 提权（sudo通配符/NFS/SSH隧道/PostgreSQL RCE） → [references/linux-privesc.md](references/linux-privesc.md)
- 高级编码（Verilog HDL/Gray码/Manchester编码/BPF字节码） → [references/encodings-advanced.md](references/encodings-advanced.md)

---

## 分类决策树

```
Misc 题目？
├─ 编码/解码谜题
│  ├─ Base64/Hex/ROT13 → CyberChef 自动检测
│  ├─ QR 码 → zbarimg / 碎片重组
│  ├─ 二进制/莫尔斯/BCD → [references/encodings.md](references/encodings.md)
│  └─ 多层嵌套 → 循环解码直到明文
├─ 沙箱逃逸
│  ├─ Python jail → [references/pyjails.md](references/pyjails.md)
│  │  ├─ 受限字符 → repunit分解 / chr()构造
│  │  ├─ 禁import → __builtins__.__import__
│  │  └─ 受限exec → func_globals链 / MRO遍历
│  └─ Bash jail → [references/bashjails.md](references/bashjails.md)
├─ 游戏/交互
│  ├─ WASM → 内存patch / wasm2wat 修改
│  ├─ WebSocket → 拦截修改消息
│  ├─ 博弈论 → Nim/承诺方案 → [references/games-and-vms-3.md](references/games-and-vms-3.md)
│  └─ ML/AI → 权重扰动 / 碰撞 → [references/games-and-vms-2.md](references/games-and-vms-2.md)
├─ DNS → [references/dns.md](references/dns.md)
├─ RF/SDR → [references/rf-sdr.md](references/rf-sdr.md)
└─ Linux 提权 → [references/linux-privesc.md](references/linux-privesc.md)
```

## 通用技巧

```bash
# 文件识别
file mystery && xxd mystery | head
binwalk -e mystery

# 编码检测
echo "data" | base64 -d
python3 -c "import base64; print(base64.b85decode(b'...'))"

# Z3 约束求解
python3 -c "
from z3 import *
x = BitVec('x', 32)
s = Solver()
s.add(x * 0x1337 == 0xdeadbeef)
s.check(); print(s.model())
"
```

## Python Jail 速查

| 技术 | 场景 |
|------|------|
| `__builtins__.__import__` | import 被禁 |
| `().__class__.__bases__[0].__subclasses__()` | 获取所有子类 |
| `chr()` + `eval()` 构造 | 字符被限制 |
| `breakpoint()` → `os.system()` | Python 3.7+ |

## 编码速查

| 编码 | 特征 |
|------|------|
| Base64 | `A-Za-z0-9+/=` 结尾 |
| Base32 | `A-Z2-7=` 大写 |
| Hex | `0-9a-f` 偶数长度 |
| URL编码 | `%XX` 形式 |
| Unicode隐写 | 零宽字符 U+200B/U+200C |

## 多层编码
- 编写脚本 while 循环自动化批量解码，避免手动逐层解

## QR 码修复
- 注意方向：可能需要旋转、翻转、对齐校正
- QR 有纠错/容错机制，部分损坏也能解码
