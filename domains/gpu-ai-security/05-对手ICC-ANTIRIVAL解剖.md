# GPU 挖矿劫持框架「ICC / antirival」— 技术分析报告

> 类型：对手解剖（反面教材 / 攻防技法拆解）
> 来源: 报告包 20261012（原文留本机案卷）· Fused 2026-10-12
> 对照: `04-对手MINER-HUNTER解剖-20260929.md`（不同团伙；战术对照见文末）
> 分析者：
> 说明：本文为纯技术分析，不含具体目标、IP、主机、凭据等信息。

---

## 一、总体架构

一套**长期运营、自动化、自愈型 GPU 挖矿劫持框架**。核心代号 `icc`，主伪装名 `nvpmgr`（冒充 NVIDIA 电源管理守护）。

三大组件：

```
1. boot.sh          — 主逻辑（拉起矿机 + 反竞争者 + key 固化）
2. guard.py         — 进程层杀毒（扫 /proc，kill 一切非己矿机）
3. antirival.rules  — 竞争者黑名单规则库（热加载）
```

四层持久化（这是它难以清除的核心）：

```
L1  systemd timer  : nvpmgr-heal.timer (约45秒/次) + zzantirival.timer  ← 真正的复活引擎
L2  cron.d         : zznvpmgr / zznvpmgrg / zznvpmgript / zzantirev    ← 每分钟
L3  root crontab   : 用户级冗余
L4  sshd key固化    : 每分钟重写作者键文件，只留自己
```

设计哲学：**每一层互为备份，任一层存活即可重建其余所有层。**

---

## 二、技术要点（可复用的攻防技法）

### 2.1 进程与路径伪装（反侦查）
- **进程名伪装**：矿机进程命名成 `nvidia-persistenced --pool ...`，模仿 NVIDIA 系统守护进程，混入 `ps` 输出难以分辨。
- **目录伪装**：框架目录藏于 `~/.local/share/<app>/.mgr/`，模仿正常应用数据目录。
- **载荷伪装**：备份文件命名为 `<cache>/.v3/gl_blob_<name>.dat`，模仿 Mesa 着色器缓存。
- **命名规避**：持久化文件用 `zz` 前缀（字典序末尾），逃避按名排序的人工审查；进程段名用 `svc-backup@local` 之类通用服务名。
- **二进制路径**：矿机藏在 `profiles/p<随机hex>/<miner-name>` 下，路径动态化。

### 2.2 反竞争者杀进程逻辑（guard.py 核心）

```python
OUR = re.compile(WALLET + '|' + WORKER + '|nvidia-persistenced --pool')
BAD = re.compile(r'krig-miner|xmrig|nbminer|lolminer|trex|srbminer|peakminer|'
                 r'miner2|kdevtmpfsi|kinsing|rig3748|rev_tunnel|rev_gate_key|'
                 r'/usr/local/bin/frpc', re.I)

# 遍历 /proc/*/cmdline：命中 OUR 跳过；命中 BAD（或 /tmp/python、stratum）→ kill -9
# 随后把常见落脚点文件覆写为 '#!/bin/sh\nexit 0\n'：
#   /tmp/python, /var/tmp/python, ~/.ssh/<tunnel>.sh, /usr/local/bin/frpc
```

**要点**：不只是杀进程，还**主动"污染"竞争者的落脚文件**（写成 no-op 脚本），让对手重启也白搭 —— 这是高级的"拒绝服务式反制"。`/proc` 扫描 + 正则匹配 = 无需安装任何依赖的纯 Python 实现。

### 2.3 竞争者指纹库（antirival.rules）— 最值得学习的情报化设计

```ini
gate_ip=<redacted>          # 拉黑特定来源 IP
[name_patterns]             # 按进程名 / 命令行特征识别竞争者
<miner-binary-names>        # 各种矿机二进制名
<tunnel-key-names>          # 竞争者隧道/密钥名
<fleet-tag>                 # 竞争者的"舰队"标识
<wallet-address>            # 竞争者的钱包地址
<worker-name>               # 竞争者的 worker 名
[paths]                     # 要污染的路径
[block_ips]                 # iptables 封禁列表
```

**要点**：指纹库能识别竞争者的**钱包、worker 名、脚本名、来源 IP**，并跨主机保持一致（同步）。这说明框架具备**持续监控 + 动态扩充 + 多主机同步**的完整"反制情报闭环"。而且它能**反向识别对手的钱包地址**，用于关联同一攻击者在其他机器上的活动。

### 2.4 密钥固化（持久化访问）

```bash
# 每分钟确保只有自己的 key 存在
grep -qxF 'OUR_KEY' authorized_keys || echo 'OUR_KEY' >> authorized_keys

# 主动删除竞争者的 key（按 comment / 来源 IP 定向过滤）
grep -v '<rival-comment>' authorized_keys | grep -v '<rival-ip>' > ak.clean
```

**要点**：**主动对抗** —— 不只保自己，还**定向删除**特定 comment/IP 的 key，把"持久化"做成"排他性持久化"。

### 2.5 矿机存活判定（boot.sh）

```bash
alive=0
if ps -ef | grep -- "--worker <worker>"; then
  u=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits \
      | awk '{s+=$1} END{print s}')
  [ "$u" -ge 40 ] && alive=1        # GPU 利用率 ≥40% 才算"活着"
fi
if [ "$alive" = 0 ]; then
  # 杀掉所有 GPU 计算进程 → 解包矿机 → nohup setsid 启动
  for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    kill -9 "$pid"
  done
fi
```

**要点**：用 **GPU 利用率做健康探针**（而非进程存在性），能识别"进程在但没干活"的假活；随后**强杀所有 GPU 计算进程**抢回算力 —— 不惜破坏机主正常业务（渲染/训练）。

### 2.6 证据留档（框架的取证意识）

```
evidence_<artifact>.<unix-ts>       # 保存竞争者每件入侵产物的样本
evidence_<unit>.service.<ts> -> /dev/null
```

**要点**：框架会**保存竞争者每次入侵的产物样本**（密钥、隧道二进制、systemd unit），文件名带 Unix 时间戳。说明它具备**取证 / 溯源意识**，可能用于反制或上报同一攻击者的其他活动。

---

## 三、为什么难清除（经验教训）

1. **只删 cron 无效** —— 真正的复活引擎是 **systemd timer**；删 cron 后 timer 会立刻重建 cron。
2. **只 kill 进程无效** —— systemd 的 `Restart=always` 会让它秒级复活。
3. **只删文件无效** —— 只要任一钩子存活，文件会被重建。
4. **正确清除顺序**（本役验证有效）：
   ```
   stop+disable+删 unit → systemctl daemon-reload → 删 cron
   → 多轮 kill 进程 → 删目录 → 重置键 → 静置复检
   ```
5. **必须静置复检**（≥60 秒，超过 timer 周期），否则会把"瞬时清除"误判为"已清除"。

---

## 四、框架画像推断

- **性质**：专业 GPU 挖矿劫持框架（非业余脚本）。
- **活跃持续性**：从规则库时间戳看属长期运营。
- **能力**：多主机同步、动态指纹、四层持久化、进程/路径伪装、GPU 级算力抢占、取证留档。
- **水平评价**：高于普通挖矿木马，持久化与反制设计接近 APT 水准（虽目的是挖矿获利）。
- **致命弱点**：复活链最终收敛到 **systemd timer 单点** —— 斩断它即全线崩溃。

---

## 五、可复用的技法总结

### 持久化
1. 用 **systemd timer** 而非 cron 作为主复活引擎（更隐蔽、更顽固）。
2. 多层冗余（timer → cron → crontab → 键固化），每层互为备份。
3. 持久化文件命名用字典序末尾前缀，规避人工审查。

### 隐蔽性
4. 进程名伪装成系统守护（模仿 `*-persistenced` 类）。
5. 目录伪装成应用数据 / 缓存路径（`~/.local/share/`、`~/.cache/`）。

### 反制
6. 落脚文件**"污染"而非仅删除**（写 no-op，让对手重启无效）。
7. **指纹库 + 跨主机同步**，实现竞争者的持续识别与情报闭环。
8. **反向识别竞争者钱包/worker/IP**，用于关联同一攻击者跨机活动。

### 算力抢占
9. **GPU 利用率健康探针**（比进程存活判定更准）。
10. 判定"假活"后**强杀全部 GPU 计算进程**抢回算力。

### 清除对手（防守方视角）
11. 先**斩断 systemd 根钩**，再清表层（cron/文件/进程）。
12. 必须 **静置复检**（超过复活周期）才算清除完成。

---

## 对照与复用（10-12 增补）

- 与 04（rig3748 系）对照：服务端规则下发 vs 热加载指纹库；四维检测 vs **GPU 利用率健康探针**；**均以 systemd 为复活根**。
- 可复用技法回流：落脚文件「no-op 污染」→ `venom-hydra` / `immortal-pact` 参考；利用率 ≥40% 健康探针 → `gpu-hunter`。
- 清除纪律（本役验证）：先斩 systemd 根钩 → daemon-reload → 删 cron → 多轮 kill → 删目录 → 重置键 → **静置复检 ≥60 秒**（超复活周期才算清除完成）。

@TGSEC社区 · @TGSEC-Qtzuu 整理
