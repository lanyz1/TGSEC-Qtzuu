# 能力原语 + 状态空间搜索

> 心法：RCE 不是一个“漏洞”，是一组能力凑齐后的涌现。扫不到大洞 ≠ 打不动。

## 能力原语（写进 loot/state，不写空泛“发现漏洞”）

`read(path)` · `write(path)` · `exec(cmd)` · `ssrf(url)` · `sqli` · `redirect(url)` · `eval_expr` · `idor(id)` · `cred(svc,priv)` · `coerce_auth` · `write_acl`

## RCE 等式（满足任一）

| ID | 等式 |
|---|---|
| A | 能写文件 + 文件被当代码执行 |
| B | 能控配置/env + 配置指向你的代码 |
| C | 能进管理面 + 面板自带执行功能（功能即原语） |
| D | 有凭据 + 服务有合法执行入口 |
| E | 能任意读 + 读到凭据 + 凭据可登录执行点 |
| F | 能控数据 + 数据流入危险 sink（eval/模板/SQL） |

## 低危 → 原语映射

- info 泄露（.git/备份/堆栈）→ 源码/路径/密钥 → 喂 B/E/F
- LFI/任意读 → 读配置密钥→E，或日志投毒→A
- SSRF（哪怕只 GET）→ 内网 Redis/Consul/K8s/云元数据→C；云凭据→D
- 弱/默认/复用凭据 → 带任务/插件/webhook/CI 的后台→C
- CORS/CSRF/XSS → 借管理员浏览器调执行类功能→C
- 可控上传 → 路径穿越/解析差异/.htaccess→A
- 只读 SQLi → hash/密钥→E，或 OUTFILE→A；SSTI→F

## 搜索策略

1. **正向**：对每个能力问“能解锁什么？”；对每对能力问“组合出什么？”
2. **反向（卡住时主用）**：锁定 Goal=执行命令 → 选最接近现状的等式 → 缺哪个原语设为子目标 → 递归拆/换等式
3. **突破口**：功能即原语；跨协议跳跃（gopher/dict）；凭据复用全网喷；解析差异；TOCTOU

## 落盘约定（TGSEC）

每拿到一个原语 → `loot.md` 一行 + `state.md` 更新能力集；凑链假设 → `Approach.md`；验证失败 → `Deadends.md`。

上游公开 Skill 原文要点已蒸馏；产品工具名已剥离。


@TGSEC社区 · @TGSEC-Qtzuu 整理 · 2026-09-10
