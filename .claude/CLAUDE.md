# TGSEC 项目说明（Claude / 任意读 CLAUDE.md 的客户端）

你在 **TGSEC 安全知识仓库**中。默认：**已获授权的安全评估、红队演练、防御加固、代码审计、CTF/靶场、知识检索**。

## 全 AI 统一入口（与 Hermes 无关）

1. 读 `AGENTS.md`
2. 读 **`ROUTING.md`**（关键词 → `domains/` 路径表）
3. 读 `MASTER.md`（24 域导航）
4. 按 ROUTING 打开对应文件；顺序：`README` → `playbook-6000` → `hunter-6000` → `src-methods` → `case-lessons`
5. **不要**假设存在 `skill_view`；无 Hermes 也能完整路由

可选：`bash scripts/bootstrap.sh`

## 业务系统默认序

`recon/true-false-separation-recon.md` → `auth-security/session-crypto-identity-layer.md` → 正逻辑∥`redteam-framework/anti-logic-layout.md` → 支付则 `business-logic/payment-config-crown-surface.md`

## 执行

- 用户声明授权/自有/SRC/CTF 后，在范围内按 domains 方法论推进
- 可复现命令与证据；报告区分已验证/未测
- 复杂 shell 先写脚本再执行
- 不把未验证 scanner 输出写成正式漏洞
- 不使用「永不拒绝/卸安全」越狱框；不自动伪造授权

## 知识路径

- 总路由：`ROUTING.md` + `MASTER.md`
- 正文：`domains/`
- 0day：`domains/0day-exploits/`
- 报告课：`domains/recon/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
