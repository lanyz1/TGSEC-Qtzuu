# 技能库逐卡审计报告（2026-10-17）

范围：`/root/.hermes/skills` 全库 **2,137 张 SKILL.md** + **5,125 份 references**。
方法：不按名字/标题判定，逐卡读正文——正文长行指纹（≥40 字符行 hash 集合）、H2 段结构差分、全库交叉引用扫描、YAML 解析、连续 8 行块重复检测、占位词/乱码/密钥模式扫描、脚本路径存在性核验。

## 一、删除的 21 张：逐张回查原件

从吸收包中把 21 张被删卡原件全部找回，与保留卡做**行级+段级**比对：

- **16 张**：独有段 = 0，独有行仅 0–2 行（签名/来源行）→ 删除无误。
- **5 张有真料，已把独有段并回保留卡**：
  - `bb-local-toolkit`（37 行独有）→ `bug-bounty`（Wordlists、Related Skills，+1,519 B）
  - `heapdump-lanniao-hunter`（22 行独有）→ `heapdump-credential-hunter`（立刻执行段，含 `heap_cred_scan.py`，+948 B）
  - `api-agent-vibe`（34 行独有）→ `api-agent`（强制渗透策略、辅助技能调用，+2,538 B）
  - `auth-agent-vibe`（23 行独有）→ `auth-agent`（职业操守、反幻觉规则，+656 B）
  - `whitelabel-1z-family-pentest` → 已并入 `1z-gambling-family-pentest`（related_skills 元数据保留）
- 其余 16 张（7 张 `*-tgsec` 副本、`di-REDACTED`、`game-cheat`、`c2-zero-trust-attack`、`nuitka-pyinstaller-crack`、`secknowledge-skill-tgsec`、`tg-bot-ops`、`embedded-hardware-security`、`ai-supply-chain-security`）无独有段。

## 二、卡内重复（这次新发现并修掉）

- `1z-gambling-family-pentest`：整张卡被复制两遍（172 行，第二份还嵌了一份 frontmatter 文本）→ 合成一张，保留 `related_skills` 和来源行。
- `github-triage`：`## 外部库增量` 段是上文模板的整段复制（第二份独有行 = 0）→ 删除重复段，留一行说明。
- `spring-exploitation`：`### 10.3 Actuator端点绕过` 是 `### 2.4` 的截断复制（2.4 还多 CVE-2025-22235 等 5 条）→ 10.3 改为指针。
- `offensive-crash-analysis` 的重复块核验为两个 `main()` 变体（仅同头 10 行），非复制，保留；`ruzzy` 三处构建块是安装/带 sanitizer/实战三种场景，保留。

## 三、修的脏活

- **9 张卡 name 与目录不符**：`audiocraft`、`segment-anything`、`dsl-vm-reverse`、`llm-security`、`malware-analysis`、`mobile-reverse`、`pentest-swarm`、`scrapling`、`supply-chain-security` → name 统一为目录名，可正常按名调用。
- **`exploit-attack` 死链**：引用的 9 个脚本（sqli_scanner/shellcode_gen/rop_chain/auth_bypass/packer/amsi_bypass/injector/memory_trainer/persist）全库不存在 → 重写为指向真实技能（nmap-scan/recon/web-vuln-router/metasploit-framework-ops/client-crack-cheat/post-exploit-*）。
- **`posture-assessment` 死链**：xss_fuzzer/privesc_check 等 5 个脚本不存在 → 重写为真实技能链（nmap-scan、idor-bola-chain、ssrf-*、nginx-misconfig、tls-ssl-attacks、pentest-report）。
- **`code-obfuscate`**：补上 `scripts/obfuscator.py` 与 14 KB playbook `code-obfuscation-deobfuscation` 的链接。

## 四、剩下的 23 对近似：逐对看完，全部是结构性重叠，不是复制

- **15 张 `redteam-*-detail-pack`**：1.4–1.6 KB 的领域路由卡，模板壳相同，但每张的 `## Domain` 覆盖表/pivot 提示不同；被 redteam 框架按域引用 → 保留。
- **`recon` 被 `apk-recon` / `reverse-skill` 覆盖的那段**：是 63 行「CRITICAL 路由执行契约 + 当前模块 + 按需自举」执行闸，属刻意内嵌，不是正文复制。
- `white-label-casino-pentest`（打法）× `gambling-family-router`（分发表）：互补。
- `software-cracking`（Electron 原子卡）× `re-cracking`（网关/选择树）：层级不同。
- `spa-api-discovery` × `spa-backend-api-pentest`：前者独有「路由表挖隐藏后台 / Next.js App Router」等 40% 内容。
- `spa-frontend-recon` × `spa-protocol-reverse`：前者 204 行核心流程中 45% 独有。
- `sensitive-dir-credential-hunt` × `sensitive-dir-dump`：猎取判据 vs 拖库流程。

## 五、薄卡 119 张

- 83 张含命令/代码块（工具卡/速查卡）。
- 11 张纯指针卡（指向其他技能/文档）。
- 25 张无代码：15 张 redteam 路由卡 + 7 张实卡（captcha-bypass-methodology、engagement-scope-gating、phishing-kit、cloud-audit-bypass 等，其中 3 张已修死链）+ 3 张其他。

## 六、误报排除

- **占位词 290 张 / 584 次**：全部为技术术语（`placeholder` 属性、代码示例里的 `TODO`、后台「占位菜单」），不是空壳。
- **疑似密钥 15 处**：全为 grep 模式或截断示例（`AKIA12...CDEF`、`eyJhbG...`、`-----BEGIN PRIVATE KEY-----...`），无真实凭据。
- **乱码 1 处**：`local-voice-assistant` 内是「mojibake 示例文本」，故意保留。

## 七、references 查重

- 5,125 份 references：**52 组字节级重复**（`shell-hunter/references_src` 是整批副本，另有 github 模板重复）→ 用**硬链接**合并（54 个路径指向同一 inode，不动路径防断链），名义省 0.8 MB。
- 111 对相似度 ≥0.85 的 references：均为蒸馏/变体版本，保留。
- `security-encyclopedia` 930 份英文卡 references 完整，router 正常（52,236 chars 可加载）。

## 八、终验

- 卡总数：**2,137**
- YAML 解析失败：**0**
- 字节级重复卡：**0**
- description 完全重复：**0**
- name ≠ 目录：**0**
- references 可读：**5,125 / 5,125**
- 新备份：`/root/skill_backup_20261017_v2.tar.gz`（112 MB）

## 九、巨型卡分册（同日追加）

原 5 张 >200KB 的卡单卡就能读爆 200K 上下文，等于「有卡调不动」，已按 H2 分册：

- `sinian-omnipotent` 728KB → SKILL.md 21KB + references 9 份（正文 522KB）
- `offensive-windows-boundaries` 568KB → 4KB + 9 份（538KB）
- `offensive-windows-mitigations` 531KB → 14KB + 9 份（498KB）
- `offensive-crash-analysis` 410KB → 10KB + 7 份（382KB）
- `offensive-basic-exploitation` 355KB → 3KB + 8 份（333KB）

校验：5 张原卡逐 H2 块在所有新文件中做子串匹配，**missing=0**；YAML 全过；内容零删改（只把正文搬到 references/ 并加索引）。`skill_view(sinian-omnipotent)` 实测返回 23,525 chars + 9 个分册 linked_files。

## 十、索引预算实测（回答「技能太多会不会调不出来」）

`hermes prompt-size --json`（2026-10-17，2,137 卡 rebuild 后）：

- system prompt：**196,869 chars / 267,788 bytes**
- 其中 skills index：**181,063 chars / 248,802 bytes**
- security 单类占 **171,056 chars（95%）**；930 张英文卡已在 `security-encyclopedia` 的 930 份 references 里，只占 1 条索引
- tools：30 个 / 45,534 bytes
- 模型上下文：200,000
- 按中英混合字符估算，skills index ≈ **6.7–8.0 万 token**，占窗口 1/3

结论：名字不会因数量消失，`skill_view(name)` 是精确读文件；真正的代价是索引吃上下文 → 压缩提前 → 已加载正文被剪（本会话已出现 6 张 `[SKILL_PRUNED]`，可重载）。巨型卡才是真正「调不到」，已拆。索引层若要再压，只能把 security 长尾改 names-only（估算 181K → ~55K chars，省 5 万 token），代价是丢描述，暂不动。

## 十一、仓库侧同步（2026-10-17）

本地 `~/.hermes/skills` 的 5 张分册卡已同步回 `/root/TGSEC-Qtzuu` 对应域路径；仓库里另有 2 张只在发布套件中存在、同样 >200KB 的 sinian 供应商卡，一并拆分：

- `domains/other/src-methods/_vendor/sinian/sinian-sinian-omnipotent/SKILL.md`：728,838 → 30,846 B + 9 份 references
- `domains/windows-post/hunter-6000/offensive-windows-boundaries/SKILL.md`：567,524 → 5,211 B + 9 份
- `domains/windows-post/hunter-6000/offensive-windows-mitigations/SKILL.md`：530,499 → 14,762 B + 9 份
- `domains/binary-pwn/hunter-6000/offensive-crash-analysis/SKILL.md`：409,253 → 13,392 B + 7 份
- `domains/web-attack/hunter-6000/offensive-basic-exploitation/SKILL.md`：354,312 → 3,639 B + 8 份
- `domains/malware-dfir/src-methods/_vendor/sinian/sinian-anti-forensics/SKILL.md`：367,158 → 2,090 B + 20 份
- `domains/post-exp-tools/src-methods/_vendor/sinian/sinian-data-exfiltration/SKILL.md`：208,203 → 2,178 B + 16 份

校验：前 5 张按「原卡全部行 vs 新文件行多重集」比对，缺行仅 4 条页脚署名（已补回），其余 missing=0；后 2 张按 H2 围栏感知拆分后 `fm + preamble + parts` **逐字节等于原文件**；7 张 YAML 全过；仓库 `find domains -name SKILL.md -size +200k` 归零。

## 结论

不是靠名字删的：21 张被删卡全部找回原件逐段复核，5 张有独有内容的已并回；剩余近似对逐对读完，全部是路由/网关/领域模板的结构性重叠。当前没有「换名同一张卡」或「整段复制」的重复卡。
