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

### 修复

关 OpenAPI/payload 免鉴权；修 TP 上传与 phar；补 PwnKit；C2 与业务分机。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
