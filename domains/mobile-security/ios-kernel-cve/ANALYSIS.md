# iOS 26.6 Kernel Surface — CVE-2026-65343 批次分析

> @TGSEC社区 · @TGSEC-Qtzuu 整理  
> 用途: 移动端/内核研究知识卡，供渗透路由与版本研判。**非完整利用链，不可直接用于盗号/盗U。**

## 元数据

| 字段 | 值 |
|------|----|
| CVE | CVE-2026-65343 |
| 官方组件 | Kernel |
| 官方类型 | Use-After-Free (CWE-416) |
| 官方影响 | 远程攻击者可能导致系统异常终止 (DoS) |
| 公开仓库叙事 | AppleKeyStore OOB read → KASLR 指针泄露 |
| 受影响 | iOS/iPadOS < 26.6.1；macOS Tahoe < 26.6.2 |
| 修复 | iOS/iPadOS 26.6.1 (23G83)；macOS 26.6.2 |
| 同批相关 | CVE-2026-65349 Kernel OOB read（App 可读内核内存） |
| 公开参考 | Apple HT 148282；研究快照见 `references/` |

## 官方 vs 公开仓库（必须区分）

1. **Apple/NVD 原文**: Kernel UAF → unexpected system termination。不写 RCE、不写读用户数据、不写钱包。
2. **公开 GitHub 叙事**: `AppleKeyStore` / `_LibSer_SEPControl_Deserialize` 缺 `declared_length` 边界检查 → `copyout` 越界读邻接堆 → 扫 `0xfffffff0…` 算 KASLR slide。
3. **编号错配风险**: 仓库把 OOB-read/KASLR 故事挂在 65343 上；同批 **65349** 的官方 impact 才更接近 “read kernel memory”。研判时两者都要看，**以 Apple 公告为准**。

## 能力边界（攻击链位置）

```
[本卡覆盖]  信息泄露原语 / KASLR 研判 / 版本是否在补丁前
     ↓ 还缺
代码执行入口 → 沙盒逃逸 → 内核写/RCE → 绕过 PAC/PPL 等 → 数据面(Keychain/进程/SE)
     ↓
才可能谈持久化或资产相关影响
```

**结论铁律:**
- ≤26.6 存在已披露内核问题 ≠ “全版本被攻破”
- KASLR leak ≠ 越狱 ≠ 读 SE 私钥 ≠ 盗 U
- SE 私钥设计上不出 enclave；热钱包盗取需要完整用户态/内核链，本卡不提供

## 同批 26.6.1 高价值条目（路由用）

| CVE | 面 | 官方影响摘要 | 链上价值 |
|-----|----|--------------|----------|
| 65343 | Kernel UAF | remote unexpected termination | DoS / 稳定性 |
| 65349 | Kernel OOB read | app → terminate **or read kernel memory** | info leak |
| 65330 | Kernel | app → terminate or corrupt kernel memory | 内存破坏向 |
| 65346 | ImageIO int overflow | image → arbitrary code execution | 本地/文件面 ACE |
| 64788 | IOGPUFamily | web content → memory corruption | 浏览器/GPU 链 |
| 多条 WebKit | WebKit | crash / memory corruption | 浏览器入口 |

## 渗透时怎么用这张卡

1. 目标若声称 iOS 版本 → 先对版本号: `<26.6.1` 才讨论本批次。
2. 任务若是 “iOS 能不能打 / 盗 U / 越狱” → 读本卡 + `../ios-pentesting-tricks/` + reverse-skill `mobile-reverse`，**先泼冷水划边界再深挖**。
3. 任务若是 App 逆向 (IPA/APK) → 不要停在内核 CVE；走 `mobile-reverse` / `apk-reverse`。
4. 需要领域总库 → `tgsec-suite` → `domains/mobile-security/`。

## 目录

- `references/upstream-readme-snapshot.md` — 公开研究说明快照（只读）
- `poc-notes/file-inventory.txt` — 公开 PoC 文件清单（不内嵌利用步骤）
- `SKILL.md` — 本域 Hermes 触发入口（若注册）

## 时间线

- 2026-08-17: iOS 26.6.1 发布修复；Apple credits
- 2026-09-02~03: 公开研究仓库出现（OOB/KASLR 叙事）
