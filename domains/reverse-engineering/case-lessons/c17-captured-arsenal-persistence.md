# C17 缴获包解剖：APK 授权爆破 + WebRTC 追踪 + UDS 微服务 C2

- Source: `C17_ARSENAL_REPORT_001_redacted.md`（原文留本机案卷，不入库）
- Techniques: apk, auth-crack, webrtc, uds, minecraft-c2, persistence
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

## 目标
- 非站点渗透：对 **3 个已缴获对手团伙、8 件武器实体、5 类持久化范式**做逆向与能力矩阵
- 甲团 = AI 服务牧场猎人；乙团 = 矿机猎人；丙团 = 三重持久化后门（APT 型）
- 受害方标识全部隐去，攻击者基础设施部分掩码

## 技术栈
- 甲团：Go 静态链接多架构 + UPX，mbedTLS，Tor `.onion` C2
- 乙团：Shell 主控 + XMRig 6.22.2 静态 ELF + 数据库配置中心原生机制
- 丙团：Shell/二进制混合，SSH `-R` + iptables REDIRECT
- 作案面：LiteLLM / QingLong / ComfyUI / OpenAI 兼容端点；PostgreSQL 集群 + etcd/Consul 配置中心

## 攻击链
甲团：扫描暴露 AI 服务 → LiteLLM `/mcp-rest/test/connection` 的 MCP stdio 命令执行（一条 HTTP 拿机器）/ QingLong 5700 未授权 / ComfyUI 8188 插件链 → 投 agent → cron `@reboot` + `*/5 pgrep` 自愈 + systemd 双份 → Tor C2 → MINER HUNTER 清剿同行

乙团：配置中心未授权写（2379/8500/8848）→ PG `archive_command` 注入 base64 shell（restart-only）→ 管理组件 `on_reload`/`on_restart` 回调 → cron 每分钟 `.khp` + `javab` + `.rguard` 三层常驻

丙团：已具 root → SSH 反向隧道 + 伪装心跳 + root 看门狗，长期驻留

## 可复用原语
1. **持久化三层冗余**：入口层 + 触发层 + 常驻层，任一层被清都不失效（三团伙独立收敛到同一解，可作为设计/检测基线）。
2. **触发源与载荷分离**：载荷 URL 十六进制存放，伪装成静态资源路径（`/img/cache`、`/assets/fonts/woff2`、`/wp-content/uploads`）；解码器四重降级 `python3→python→xxd→perl→sed`，多镜像抗封。
3. **配置中心 → 集群级原生机制 RCE**：etcd/Consul 未授权写 + `archive_command = bash -c 'echo <base64>'` + `archive_mode` 非预期开启 + `archive_timeout` 压至极小 ⇒ 一次写入全节点生效；**注意 restart-only 参数未重启则不引爆**。
4. **免出网 C2**：让载荷把状态写回管理组件自己的本机 API，再借配置中心复制汇总，网络层监控不可见。
5. **对手清剿判据（可直接用于 IR）**：伪内核线程名（`[kworker*`/`[kswapd*`/`[khugepaged*`）且核对 UID≠0；exe 含 `(deleted)` 且路径在 `/dev/shm`、`/var/tmp`、`/run`。
6. **无文件投递与静态对抗**：`memfd_create` 内存态执行；字符串 XOR 0x5A 混淆。
7. **主机排查清单**：crontab `@reboot` 与 `*/5 pgrep`、systemd system+user 双份 unit、`/tmp/.snt.lck`、PG_HOME 下 `.khp`/`.rguard`/`.ksmd_done`/`.java_cache`。
8. **反取证**：`systemctl disable` + 删 unit + `daemon-reload`，自清服务痕迹。

## 数据战果
- 8 件武器实体完整能力画像；5 类持久化范式；3 团伙 12 维能力矩阵
- 公开载荷：XMRig 6.22.2 linux-static-x64（SHA256 1 个）；自研管理器 MD5 1 个
- 我方已实战验证（非纸面）：配置中心未授权写 → 集群命令执行（`uid=postgres`）、镜像反杀、注入后完全回滚

## 缺口
- 乙团第 1 层（配置层）因 restart-only 长期“已布设未引爆”，实际未生效
- 丙团初始入口未知（分析时已具 root）
- 甲团 Tor C2 未接管，仅完成画像
- 无受害者侧横向范围数据

## 敏感物（类别+数量，不含值）
- 样本哈希 2 个（公开载荷 SHA256、自研管理器 MD5）
- 攻击者基础设施：C2 域名/IP/矿池地址已掩码，完整值仅存本地案卷
- 受害方标识（组织/域名/IP/国别）全部隐去

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/reverse-engineering/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
