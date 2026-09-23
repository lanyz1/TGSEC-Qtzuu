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
