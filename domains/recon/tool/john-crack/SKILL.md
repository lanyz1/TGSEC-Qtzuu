---
name: john-crack
description: "使用 John the Ripper 进行离线密码破解。当需要破解哈希（MD5/SHA/NTLM/Kerberos/ZIP/RAR/PDF/SSH Key 等）时使用。John 支持自动检测哈希类型、字典攻击、规则变形、增量爆破，内置 *2john 工具链从各种格式提取哈希。任何涉及离线密码破解、哈希还原、密码审计的场景都应使用此技能"
metadata:
  tags: "john,crack,password,密码破解,哈希,hash,MD5,NTLM,Kerberos,字典攻击,规则,暴力破解"
  category: "tool"
---

# John the Ripper 离线密码破解方法论

John the Ripper 是最经典的离线密码破解工具。核心优势：**自动哈希识别** + **丰富规则引擎** + ***2john 提取工具链**。支持 200+ 哈希类型。

项目地址：https://github.com/openwall/john

## Phase 1: 基本破解

```bash
# 自动检测哈希类型并破解
john hashes.txt

# 指定哈希格式
john --format=Raw-MD5 hashes.txt
john --format=NT hashes.txt
john --format=Raw-SHA256 hashes.txt

# 字典攻击
john --wordlist=rockyou.txt hashes.txt

# 查看已破解的密码
john --show hashes.txt
```

## Phase 2: 规则变形攻击

```bash
# 字典 + 默认规则
john --wordlist=rockyou.txt --rules hashes.txt

# 字典 + best64 规则（最常用）
john --wordlist=rockyou.txt --rules=best64 hashes.txt

# 字典 + Jumbo 规则（更全面）
john --wordlist=rockyou.txt --rules=Jumbo hashes.txt

# 字典 + KoreLogic 规则（最复杂，最慢）
john --wordlist=rockyou.txt --rules=KoreLogic hashes.txt

# 列出可用规则
john --list=rules
```

## Phase 3: 哈希提取（*2john 工具链）

```bash
# ZIP 文件
zip2john secret.zip > zip_hash.txt
john zip_hash.txt

# RAR 文件
rar2john secret.rar > rar_hash.txt

# PDF 文件
pdf2john.pl secret.pdf > pdf_hash.txt

# SSH 私钥
ssh2john id_rsa > ssh_hash.txt

# KeePass 数据库
keepass2john database.kdbx > keepass_hash.txt

# Office 文档
office2john document.docx > office_hash.txt

# Kerberos TGS (Kerberoasting)
john --format=krb5tgs --wordlist=rockyou.txt tgs_hashes.txt

# Kerberos AS-REP (AS-REP Roasting)
john --format=krb5asrep --wordlist=rockyou.txt asrep_hashes.txt

# NTLM Hash
john --format=NT --wordlist=rockyou.txt ntlm_hashes.txt
```

## Phase 4: 增量和掩码攻击

```bash
# 增量模式（纯暴力，自动递增长度）
john --incremental hashes.txt

# 指定字符集
john --incremental=Digits hashes.txt     # 纯数字
john --incremental=Alnum hashes.txt      # 字母数字
john --incremental=ASCII hashes.txt      # 全 ASCII

# 掩码攻击（Hashcat 风格）
john --mask='?d?d?d?d?d?d' hashes.txt          # 6 位数字
john --mask='?u?l?l?l?d?d?d?s' hashes.txt      # 大写+小写x3+数字x3+特殊
```

## Phase 5: 实用技巧

```bash
# 恢复中断的破解
john --restore

# 查看当前进度
john --status

# 多核并行
john --fork=4 --wordlist=rockyou.txt hashes.txt

# 指定会话名称
john --session=my_crack --wordlist=rockyou.txt hashes.txt

# 只破解特定用户
john --users=admin hashes.txt
```

## 渗透测试常用场景

| 场景 | 命令 |
|------|------|
| NTLM 破解 | `john --format=NT --wordlist=rockyou.txt ntlm.txt` |
| Kerberoasting | `john --format=krb5tgs --wordlist=rockyou.txt tgs.txt` |
| SSH 密钥破解 | `ssh2john id_rsa > h.txt && john --wordlist=rockyou.txt h.txt` |
| ZIP 密码破解 | `zip2john file.zip > h.txt && john h.txt` |
| Linux shadow | `john --wordlist=rockyou.txt /tmp/shadow` |
| 字典+规则 | `john --wordlist=rockyou.txt --rules=best64 hashes.txt` |
