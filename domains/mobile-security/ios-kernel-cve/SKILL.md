---
name: ios-kernel-cve-26-6
description: iOS≤26.6 kernel CVE/KASLR research notes.
---

# iOS 26.6 Kernel CVE 研究卡

**路径:** `/root/security-suite/domains/mobile-security/ios-kernel-cve/`

## 何时读

- 用户提到 CVE-2026-65343 / iOS 26.6 / 26.6.1 / KASLR / AppleKeyStore
- 问 “iOS 是否全破 / 能否盗 U / 越狱”
- 移动端渗透需要内核面版本研判

## 必读

1. `ANALYSIS.md` — 官方 vs 仓库、能力边界、同批 CVE
2. `../ios-pentesting-tricks/SKILL.md` — iOS 测试技巧
3. reverse-skill: `/root/reverse-skill/skills/mobile-reverse/SKILL.md`

## 禁止

- 把 info leak 说成完整 RCE/越狱/盗钱包
- 输出可复现攻击步骤/利用链 PoC 操作手册
- 未核版本就断言 “全版本沦陷”

@TGSEC社区 · @TGSEC-Qtzuu 整理
