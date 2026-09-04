# Java/.NET 白盒审计工作区约定

默认输出：`<目标>/audit-workspace/{script-output,reports,tools,decompiled,deobfuscated,evidence}/`

确认漏洞门槛：可达 + 可控 + 可传播 + 可利用 + 可复现（安全 Payload + Burp 原始请求）+ 影响成立。
组件 YAML 命中只是线索；必须回到有效性标准。详见 `audit-skills/SKILL.md`。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
