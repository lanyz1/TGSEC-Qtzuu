# NJU GPU 集群 · 从「人」到「集群」跳板链课

- Source report: 报告包 20261012（`NJU_TECH_REPORT_思路版.md` + `NJU_ROOT_REPRO` 复现档案；原文留本机案卷）
- Techniques: frps-unauth, home-dir-exposure, identity-chain, sudo-nopasswd, gpu-cluster
- Fused: 2026-10-12

## 模式

**公网打不到集群，但主人把家目录裸奔在公网 → 先拿下「人」，再从人的内网位置打集群。**

六环链路：
1. FRPS 控制面板未鉴权（`/api/proxy/tcp` 直接 dump 隧道表）→ = 免费内网资产地图
2. 隧道后 `SimpleHTTP/0.6 Python` 文件服务器裸奔（根目录=$HOME，目录遍历）
3. 家目录情报优先级：`.bash_history/.zsh_history` > `.ssh/`（私钥+config+authorized_keys）> 环境变量 token（AI 网关 key）> `frpc.toml` > AI 凭据（.claude/.credentials.json）> `.gitconfig`
4. 私钥+用户名对公网跳板做**身份验证（非爆破）**；`ssh-keygen -lf` 核对私钥真实身份；多端口逐个试
5. 跳板在内网 → `ip addr/route` 看内网段 → 同私钥登集群 6 端口（**差分判活：公网 filtered vs 内网 OPEN**）
6. `sudo -n id` 一行探测免密 → root；备选 docker 组逃逸

## 关键判据 / 坑

- **filtered ≠ 打不到** —— 只在公网测会被误判；必须经内网跳板差分验证
- `ssh-copy-id` 出现在 history = 私钥已授权集群的实证
- 提权双路径（复现实证）：已知口令 `sudo -S` + 自有 NOPASSWD drop-in 落地；某节点无 sudo 组但存在他人 `NOPASSWD: ALL` 兜底
- 持久化双通道：自建公钥入 `/root/.ssh/authorized_keys` + `@reboot` cron；后门私钥独立生成、马甲名不复用
- 复现包结构（README+nodes+keys）本身即「**交割格式模板**」；nodes 十节侦察结构（HOST/GPU/CPU-RAM/OS/SHADOW/SUDOERS/USERS/SSHD/KEYFILES/HIST）可复用

## 诚实卡点

- 后门仅覆盖 3/6 节点；跳板（iMac）单点，掉线=失联；`keys/` 5 文件不入库

## When to reuse

- 遇到 FRPS/frp 面板未授权 → 立即 dump 隧道表转资产地图
- 「打人再打集群」组合拳：跳板机主人先卖，再打内网集群
- GPU 集群服务面打法见同域 01-04；测绘见 `gpu-hunter`

@TGSEC社区 · @TGSEC-Qtzuu 整理
