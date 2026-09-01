---
name: ctf-flag-verification
description: "CTF/靶场 Flag 强制验证流程。当通过**任何方式**发现疑似 flag 字符串（含 flag{、FLAG{、ctf{ 等格式）时**必须立即**使用此 skill 验证，不要直接提交。防止因字符截断、编码错误、HTML 实体、base64 不完整解码、hex 截断等原因导致提交错误 flag。即使 flag 看起来完整，也可能存在隐藏字符或编码问题。覆盖 SQL 注入分段提取、命令执行输出截断、文件读取编码、Web 页面解析等所有 flag 提取场景。任何时候看到 flag{ 字样都应触发此 skill"
metadata:
  tags: "ctf,flag,验证,capture the flag,靶场,flag验证,sqli,rce,lfi,file-read,提交,flag{,疑似flag,flag格式,flag截断,编码还原,hex,base64解码,字符截断,HTML实体,提取验证"
  category: "ctf"
---

# CTF Flag 验证方法论

## 核心原则

**LLM 无法可靠地数 hex 字符或拼接长字符串。** 所有 flag 的提取、拼接、验证必须用程序（Python）完成，绝不手动拼接。

## 强制验证流程

### 1.1 提取 flag 时优先使用程序化方法

**SQL 注入（EXTRACTVALUE/UPDATEXML 分段提取）：**
- ❌ 不要手动复制各段然后在思考中拼接
- ✅ 写 Python 脚本自动发请求、自动分段、自动拼接（参考 sql-injection-methodology 中的 Python 模板）
- ✅ 优先用 UNION SELECT（无截断限制，一次拿完整 flag）

**命令执行（RCE / 命令注入）：**
- ⚠️ `cat /flag.txt` 输出可能含 trailing newline → 用 `flag.strip()` 去除
- ⚠️ 命令输出可能被 HTML 编码（`&lt;` → `<`）→ 用 Python `html.unescape()` 解码
- ⚠️ 如果回显被截断，改用 `base64 /flag.txt` 再解码

**文件读取（LFI / 任意文件读取）：**
- ⚠️ PHP `file_get_contents` 可能返回 base64 → 先解码
- ⚠️ 通过 php://filter 读取时：`php://filter/convert.base64-encode/resource=flag` → 必须 base64 解码
- ⚠️ 路径大小写敏感：`/flag.txt` ≠ `/Flag.txt` ≠ `/FLAG.txt`

**Web 页面解析：**
- Flag 可能在 HTML 注释 `<!-- flag{...} -->` 中
- Flag 可能在 HTML 属性 `data-flag="flag{...}"` 中
- Flag 可能在 JavaScript 变量 `var flag = "flag{...}"` 中
- 用 Python `re.search(r'flag\{[a-fA-F0-9_-]+\}', html_text)` 提取

### 1.2 长度验证

如果你通过 SQL `LENGTH()` 或其他方式获知了 flag 的预期长度，用 Python 验证：
```python
flag = "flag{...extracted...}"
expected_length = 70  # 从 LENGTH() 获得
assert len(flag) == expected_length, f"MISMATCH! {len(flag)} != {expected_length}"
```

### 1.3 格式验证

```python
import re
flag = "flag{...}"
assert re.match(r'^flag\{[a-fA-F0-9_-]+\}$', flag), f"Invalid format: {flag}"
assert flag.endswith('}'), "Missing } — flag 可能被截断"
```

### 1.4 验证失败的处理

1. **长度不匹配** → 重新提取。EXTRACTVALUE 改用 Python 自动脚本或 UNION SELECT
2. **格式不对** → 检查 HTML 编码、base64 编码、trailing whitespace
3. **多次失败** → 切换提取方法（EXTRACTVALUE → UNION → 盲注 → sqlmap --dump）

### 1.5 常见错误模式

| 错误 | 原因 | 解决 |
|------|------|------|
| Flag 少 1-2 字符 | EXTRACTVALUE 32 字符截断 + 手动拼接 | Python 自动提取脚本 |
| Flag 多 1-2 字符 | SUBSTRING 起始位置重叠 | 检查 SUBSTRING 参数 |
| Flag 中间有错字符 | LLM 误读 hex 字符 | Python re.search 提取 |
| Flag 含 HTML 实体 | `&amp;` 未解码 | `html.unescape()` |
| Flag 有换行/空格 | 命令输出含 whitespace | `.strip()` |
| Flag 格式不对 | 提取了错误数据 | 重新确认表名/文件路径 |

### 1.6 字符级验证问题
- Flag 中间丢失字符时，检查位置 29-32 区域，可能存在偏移错误导致遗漏字符
- HTML 实体还原：`&lt;` 变成 `<`，`&amp;` 变成 `&`，网页显示与源码不同，需解码还原
- 示例：`flag{a3b<c5d&e7f}` — 渲染后不同于源码，解码后才是正确 flag
