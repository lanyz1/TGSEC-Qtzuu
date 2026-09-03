---
name: tgsec-suite
description: "Use for attack-surface domain knowledge matrix."
version: 1.1.0
---

# 安全知识库 · TGSEC 一体化导航

按攻击面组织的安全知识矩阵。本地: `/root/security-suite`  
总入口: `/root/security-suite/MASTER.md`  
6000 融合索引: `/root/security-suite/domains/FUSION-6000.md`

## 开打前强制

1. `skill_view(pentest-execution)` 活靶纪律
2. 本技能定攻击面 → `read_file domains/<面>/README.md`
3. 同面优先读: `playbook-6000/` → `hunter-6000/` → `src-methods/` → 其它
4. APK/IPA/逆向另开 `reverse-skill` + master-route.sh

## 主题域速查

| 域 | 何时 |
|----|------|
| recon | 子域/端口/组件情报/OSINT |
| web-injection | SQLi/XSS/SSRF/XXE/反序列化/Fastjson/Shiro/Log4j/Spring |
| web-attack | CSRF/走私/WAF/竞态/开放重定向 |
| auth-security | IDOR/JWT/OAuth/401-403 |
| file-vulns | 上传/LFI/路径穿越 |
| api-security | GraphQL/API 网关 |
| business-logic | 支付/逻辑/威胁建模 |
| mobile-security | APK/IPA/iOS CVE |
| cloud-security | 云/K8s/CI-CD/容器 |
| binary-pwn | fuzz/shellcode/exploit dev |
| redteam-framework | 状态机/多阶段/lyan 工作流 |
| malware-dfir | IR/vuln memory |
| 0day-exploits | 产品 RCE 库 |

## 6000RMB 包落点

- 各域 `playbook-6000/` — Skills20260809 测试手册
- 各域 `hunter-6000/` — hunter offensive skills
- `redteam-framework/pentest-lyan-workflow/` — 授权 Web 三阶段+威胁建模
- `recon/component-vuln-intel/` — 组件→联网 CVE/PoC
- `malware-dfir/vuln-hunter-memory/`
- `ctf/case-reports-6000/`
- clown 方法: 已有 `src-methods/`（重复哈希跳过）

## 5 步路由

1. 定阶段 2. 定域 3. 读 README 4. 进 playbook/hunter/src-methods 5. 交叉引用

@TGSEC社区 · @TGSEC-Qtzuu 整理
