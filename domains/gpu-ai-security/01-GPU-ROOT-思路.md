# 01 · GPU ROOT 获取思路

> 从「发现一台 GPU 机器」到「拿到 root shell」的完整方法论。
> 核心结论：**主战场在服务面，不在内核。**

---

## 一、三层猎场模型

```
第一层：资产测绘     ← 找出公网暴露的 GPU 机器（FOFA / Quake / Shodan / 内部扫描）
第二层：服务面突破   ← 未认证 RCE 全家桶（ComfyUI / GPUStack / Ray / Docker / Ollama / k8s / Redis）
第三层：本地提权     ← 容器逃逸 / 内核 CVE / 错误配置（仅当服务面给的是非 root 时）
```

---

## 二、第一层：资产测绘（定位 GPU 机器）

### 2.1 指纹思路

GPU 机器的可识别特征，按可靠性排序：

| 特征 | 说明 | 命中端口 |
|---|---|---|
| **AI 框架 banner** | ComfyUI / GPUStack / Ray Dashboard / Ollama / vLLM / SGLang | 8188 / 30003 / 8265 / 11434 / 8000 |
| **Jupyter** | Notebook / Lab 未授权（body 含 `/api/kernels`） | 8888 / 8889 |
| **Docker API** | 未认证 2375/2376（body 含 Docker + nvidia） | 2375 / 2376 |
| **K8s kubelet** | 10250 未认证（body 含 kubernetes + nvidia.com） | 10250 / 6443 |
| **GPU 字样** | body/title 含 NVIDIA / CUDA / A100 / H100 / L40S / Tesla | — |
| **训练平台** | MLflow / TensorBoard / Kubeflow / JupyterHub / W&B | 5000 / 6006 / — |
| **云 GPU 实例** | body 含 p3.2xlarge / gv100 / ecs.gn6v 等机型串 | — |

### 2.2 FOFA 语法模板（示例）

```
# GPU 核心指纹
("NVIDIA" || "CUDA" || "nvidia-smi" || "GeForce RTX" || "A100" || "H100" || "L40S" || "Tesla V100")
  && (port="22" || port="8888" || port="6006" || port="9090" || port="3000" || port="8501")

# 未授权 AI 平台
body="ComfyUI" || body="GPUStack" || body="Ray Dashboard" || title="Ollama"

# Docker GPU 容器 API
body="Docker" && body="nvidia" && (port="2375" || port="2376")
```

### 2.3 测绘纪律

- **多源交叉**：FOFA + Quake + Shodan 交叉验证，避免单源误报。
- **去重**：按 IP + 端口 + banner 哈希去重。
- **存活确认**：测绘结果必须**实际探测**（HTTP 状态 + 关键词），不能只信 FOFA 返回。
  > 血训：HTTP 200 ≠ 成功。SPA fallback、蜜罐、同源集群会产生大量假阳性。批量命中必须抽验。

---

## 三、第二层：服务面突破（主力战场）

### 3.1 未认证 AI 基建 RCE 全家桶

| 服务 | 端口 | 突破口 | 效果 |
|---|---|---|---|
| **ComfyUI** | 8188 | `/upload/image` 上传 + `StringFormat` 属性链 dlopen；或 pickle 上传 | 任意代码执行（服务常以 root 跑） |
| **GPUStack** | 30003 | `POST /v2/models` 恶意"模型" = 任意镜像 + run_command | 任意镜像 RCE，骗过显存调度拿 GPU |
| **Ray Dashboard** | 8265 | `POST /api/jobs/` 提交 job | 集群节点 root 执行 |
| **Docker API** | 2375/2376 | `/info` 免认证 → 建特权容器 `Binds:["/:/host"]` | 挂载宿主文件系统 = 直接写 root |
| **Ollama** | 11434 | `/api/pull` modelfile FROM 读文件；`/api` 模型盘点 | 文件读取 / 信息泄露 |
| **k8s kubelet** | 10250 | `/pods` 盘点 + 任意 pod exec | 容器内执行（未必宿主 root） |
| **Redis** | 6379 | 未认证 → `CONFIG SET dir/dbfilename` 写文件 | 写 authorized_keys / cron |
| **Jupyter** | 8888 | 未授权 notebook → 新建 terminal | 直接 shell |

### 3.2 ComfyUI 主链（实战验证，最具代表性）

```
1. 侦察: GET /internal/folder_paths → 拿上传路径；路径含 /root/ → 判定服务以 root 跑
2. 上传: POST /upload/image (type=temp/input/output) → 投放 .so / pickle
3. 触发: POST /prompt 提交恶意 workflow
   - StringFormat 属性链: str.format() 里用 {a.__class__.__init__.__globals__[...]} 逐级取到 ctypes.cdll，
     对上传的 .so 路径做 getitem → 触发 dlopen → constructor 执行
   - 或 pickle 投毒: 上传恶意 checkpoint，加载即反序列化执行
4. 回显: GET /view?filename=X&type=output|temp → 读命令输出
```

**关键点**：StringFormat 用的是 `str.format()` 而非 `eval()`，但属性链 + `__getitem__` 足以抵达 `ctypes.cdll[path]` 触发 dlopen。这是「看起来安全实则能执行」的经典。

### 3.3 Docker API 2375 主链（实战验证）

```
1. GET /info → 免认证确认
2. POST /containers/create → Binds:["/:/host"] + Privileged:true
3. POST /containers/{id}/start
4. 容器内写 /host/root/.ssh/authorized_keys → 宿主机 root 到手
5. DELETE /containers/{id}?force=1 → 自毁消痕
```

### 3.4 突破纪律

- **探测优先用 python socket timeout**，不要依赖 `timeout` 命令（部分沙盒/嵌入式环境 SIGALRM 不触发，会挂死）。
- **单 IP 多端口并行探测**，2 秒内判型，避免串行拖慢。
- **命中即验证**：不要看到 200 就宣布成功，必须有**命令回显实锤**。

---

## 四、第三层：本地提权（仅当服务面给的不是 root）

> 若服务面直接给 root（AI 平台常见），跳过本层。

### 4.1 容器逃逸（优先级最高）

| 路径 | 检测 | 利用 |
|---|---|---|
| docker.sock 挂载 | `ls /var/run/docker.sock` | 起特权容器挂宿主 |
| docker 组 | `id` 含 docker | 同上 |
| containerd.sock | `ls /run/containerd/containerd.sock` | ctr 起容器 |
| cgroup 可写 + SYS_ADMIN | `capsh --print` | cgroup release_agent 逃逸 |
| 特权容器 | `cat /proc/self/status` CapEff | 直接挂宿主 |

### 4.2 内核 CVE（辅助，诚实降级）

> **2025-2026 现实**：内核 6.6/6.8+ 公开稳定 LPE 近乎断档。**别把内核当主攻。**

| 武器 | 射程 | 备注 |
|---|---|---|
| CVE-2024-1086 (nf_tables) | 5.14 ≤ K < 6.6 | 需 CONFIG_NF_TABLES |
| CVE-2022-0847 DirtyPipe | 5.8–5.15 | 任意写 |
| CVE-2021-4034 PwnKit | 老机 pkexec | 通杀 |
| CVE-2021-3493 overlayfs | Ubuntu 20.04 | blasty 版 |

**工程要点**：
- 取货三态：`curl → wget → python3 urllib`（极简容器通杀）
- 无编译器自动装 gcc（apt/dnf/yum/apk）
- **不落盘执行**：`memfd_create` + `/proc/self/fd` 执行（syscall 号按架构：x86_64=319 / aarch64=279 / armv7l=385 / riscv64=226）
- 成功后自动播 SSH 公钥

### 4.3 错误配置（低成本路径）

- 弱口令 / 默认口令（AI 平台、数据库、管理后台）
- 泄露的 `.git` / `.env` / 备份文件
- 未授权管理 API（不只是 AI 框架，还有 K8s apiserver、etcd、Consul）

---

## 五、判穷与撤退

```
三查无果 → 判穷落盘（记录技术阻塞点，防重复推进）
系统性消毒 → 撤留 rearm（保留一条最低成本重入路径）
被察觉 → 静默 24–72h，评估可见度再决定
```

**判穷纪律**：
- 通道阻塞 ≠ 不存在。记录**技术阻塞点**（如「上传文件落虚拟 FS，dlopen 磁盘路径对不上」），下次可绕过。
- 判穷产物必须落盘，避免下次从零开始。

---

## 六、一句话铭记

> **AI 平台要么 root 跑、要么裸奔。你要找的不是内核 0day，是一台忘了关认证的 ComfyUI。**
