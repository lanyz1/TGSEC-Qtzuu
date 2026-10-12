# 案例课：DarkSword / Coruna C2 + 同机 ThinkPHP 刷单盘

> 脱敏。来自授权主机沦陷报告提炼，无真实口令/收款地址。

## 模式

同机三件套：ThinkPHP 5.1 刷单/号商 + DarkSword Admin `:8888` + Coruna C2 `:8080`（iOS payload）。

### 高 ROI 链

```text
/manage 弱口 + XHR 头 → 双扩展上传 webshell
→ TP5.1 phar POP → FPM sendmail_path → www
→ PwnKit → root → 宝塔/MySQL/DarkSword/Coruna
```

或跳过刷单盘：

```text
Coruna /openapi.json → GET /api/payload/entry/..%2f..%2f..%2f...
→ 未授权任意文件/源码读 → 拖 backend → 控 C2
```

### 关键点

- Coruna：`%2f` 穿越；段数必须命中「跳过清单」分支
- DarkSword：默认口常见；HTML `#token`
- 刷单：`X-Requested-With` 影响登录 oracle
- **JackApple / `we.*` 投递面板**（xpjkk 族）：操作端 `/adminjack` 可极硬（无用户名 oracle）。真洞在 **设备数据面**——前端 `rce_loader.js`/`beacon.js` 硬编码 `DS_SHARED_SECRET`，Bearer 打 `/beacon` `/cmd/poll` `/exfil`；`/api/plugins/list` 常无鉴权。同机旁路（APK 统计、厂商 Lab `:8080` requireAuth:false）比喷面板更值钱。FOFA `body="rce_loader.js"` 挖同族。

### 修复

关 OpenAPI/payload 免鉴权；修 TP 上传与 phar；补 PwnKit；C2 与业务分机。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理


## 增补 2026-10-02 — Coruna-Lab farm 方法论 (L批吸收)
- **WAF 重放防护语义测穿**: 只拦"可解码 JSON"的 lab-session + x-xsrf-token 组合 (伪404); 垃圾值全穿透; cookie 名 `lab-session` 是开关 → 旧名 `coruna-lab-session` 致盲 WAF
- **CSRF 值链证明法**: 原样 cookie + unquote(XSRF) 头 → 过 CSRF 后 401 = 卡点在登录态; (419/401 二分器, logout 当零副作用 oracle)
- **锁定反制**: per-(username,IP) 速率型 → Tor IsolateSOCKSAuth 每请求换电路; /user/login 无锁; aiohttp 必须 allow_redirects=False
- **喷射负证据**: 5000万次零命中 → 勿再烧字典
- **分型**: Style-A(双面板)/Style-B; cookie 名分代; darksword chain; rce_worker 18.4→18.7
- 全文: 已撤出仓库（原文留本机案卷）

## 增补 2026-10-12 — 面板舰队规模化视图（报告包B）

- **4 面板 admin/admin123 接管**（Bearer JWT）：PRO（38 台）· C2_10324（~125 万设备，真伪未确认）· ADM_156（15）· ADM_3860（73）。注：与 10-02 的 `admin/999666333` 属**不同实例族**，勿互相覆盖
- 设备库/exfil 类别量级（只读实证）：keychain ~18.8-20.4 万 · sms ~34.9-44 万 · calls ~20.7-26.9 万 · contacts ~3 万 · browser ~7.9-8.9 万 · wifi ~2.2 万 · photos ~2.4-3k · files ~1 万 · wallet 容器 1770
- **iOS 26 模块族存在性**：`rce_worker_26 / rce_module_26 / kernel_priv_26 / pe_main`（双源出现）
- **PAC `:8080` 私服域名劫持面**；「:2000 console disabled vs :8000 开放」实例策略差异 → 找同族另一实例的启发
- **2FA setup secret 泄露且 enabled=false** → 可直接绑（另见 dream9527 课 F-03）
- 家族存活扫描：46 目标 / 29 个 HTTP 200；未接管约 10 个可跟进（`70.39.197.148:8000` · `154.12.17.101:8888` · `iosxq.top/admin` 等，详见案卷）
- 假矿机壳 `sum812m.site/usdt` C2 写接口可通（noop-write）；imToken AES-CTR 固定密钥泄露面
- 诚实卡点：joker admin 全 401 + 5/min 限流（Tor 喷 ~365 组未中）· C2 shared secret ≠ Admin JWT · 设备 OS 分布含 305k null（真伪未确认）

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
