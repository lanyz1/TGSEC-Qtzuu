---
name: reverse-skill
description: "Use for APK/IPA/JS/binary reverse task routing."
version: 1.1.0
---

# reverse-skill 路由引擎

本地包: `/root/reverse-skill`  
对标路由设计: keyword → PRIMARY skill → ACTION REQUIRED → tool-index。

**为什么渗透时“调不到技能”：**  
旧 security 技能 description 全是虚词（needing/performing），系统提示 57 字截断后没有 APK/IPA/SQLi/Frida 等具体触发词。本技能 + 已重写的各伞形 description 用**具体产物/工具词**抢路由。

## When to Use

- APK / IPA / smali / jadx / apktool / Frida / Objection
- JS 逆向、webpack、前端加密、签名算法还原
- IDA / Ghidra / radare2 / 二进制 / pwn / 固件
- 用户说“逆向”“脱壳”“Hook”“协议还原”
- 与 `tgsec-suite` mobile/reverse 域交叉时先本技能定 PRIMARY

Don't use for: 纯 Web 注入/未授权 API（走 `hack-skills`/`web-sec`/`pentest-execution`）。

## ACTION REQUIRED（读完立刻执行）

1. `NOW`: 用下方快路径或脚本定 PRIMARY（禁止先瞎猜 jadx/frida 命令）
2. `NOW`: `read_file` PRIMARY 的 SKILL.md，执行其 ACTION REQUIRED
3. `NEXT`: 刷新/读取 tool-index；缺工具再 bootstrap
4. `ACT`: 按 PRIMARY 工作流逐步做

## 快路径（Linux）

```bash
bash /root/reverse-skill/skills/scripts/master-route.sh --hint "<用户原话>"
```

全矩阵: `/root/reverse-skill/skills/routing.md`  
规则源: `/root/reverse-skill/skills/config/routing.json`  
总览: `/root/reverse-skill/skills/MASTER-ROUTING.md`  
AI 引导: `/root/reverse-skill/README_AI.md` / `AGENTS.md`

tool-index 首次:

```bash
bash /root/reverse-skill/skills/scripts/refresh-tool-index.sh
```

## 高频 PRIMARY 速查

| 条件 | PRIMARY |
|------|--------|
| APK/smali/jadx/apktool | `apk-reverse/SKILL.md` |
| IPA/iOS/Objection/越狱检测 | `mobile-reverse/SKILL.md` |
| JS/webpack/前端加密 | `js-reverse/SKILL.md` |
| IDA 深挖 | `ida-reverse/SKILL.md` |
| Ghidra | `ghidra-reverse/SKILL.md` |
| pwn/ROP | `pwn-chain/SKILL.md` |
| 多阶段打穿 | `attack-chain/SKILL.md` |
| 未命中 | `reverse-engineering/SKILL.md` |

完整 43 条 priority：读 `MASTER-ROUTING.md` 或跑 `master-route.sh`。

## 与 TGSEC 域映射

| 任务 | reverse-skill | security-suite |
|------|---------------|----------------|
| APK | `apk-reverse` | `domains/mobile-security/apk-reverse` |
| iOS/IPA | `mobile-reverse` | `domains/mobile-security/` |
| iOS 26.6 内核 CVE/KASLR/盗U研判 | mobile-reverse + 分析卡 | `domains/mobile-security/ios-kernel-cve/ANALYSIS.md` |
| 移动 App 安全测试手册 | mobile-reverse | `domains/mobile-security/playbook-6000/mobile-app-security-testing/` |
| JS 加密 | `js-reverse` | mobile-security/js-reverse + recon |
| 二进制/PWN | ida/pwn-chain | binary-pwn + reverse-engineering |
| 多阶段 | attack-chain | pentest-execution + tgsec-suite |

## iOS 内核 CVE 批次（已融合）

`/root/security-suite/domains/mobile-security/ios-kernel-cve/`  
- `ANALYSIS.md` — CVE-2026-65343 官方 UAF/DoS vs 公开 OOB/KASLR 对照  
- **不是**完整越狱/盗 U 链；info leak ≠ RCE ≠ SE 密钥提取

## Pitfalls

- 只读本路由器不读 PRIMARY = 仍然不会做逆向
- 未授权目标禁止 ACT（scope 契约）
- 用户只说“渗透”：先 `pentest-execution`，按资产类型再分支到本技能

## Trigger matrix

详见 `references/skill-trigger-matrix.md`（全 security 伞形触发词表）。

## Verification

- [ ] `master-route.sh --hint "apk 加固"` → apk-reverse
- [ ] `master-route.sh --hint "CVE-2026-65343 iOS KASLR"` → mobile-reverse
- [ ] `skill_view(reverse-skill)` 可用
- [ ] ios-kernel-cve/ANALYSIS.md 存在
- [ ] PRIMARY SKILL.md 被打开

@TGSEC社区 · @TGSEC-Qtzuu 整理
