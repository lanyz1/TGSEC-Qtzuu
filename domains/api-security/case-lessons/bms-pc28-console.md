# 案例课：BMS / PC28 算法控制台

> 脱敏。FastAPI + 用户上传 `.py` 预测插件。

## 模式

低权用户可上传算法 → AST「沙箱」非真隔离 → 帧/字符串拼 builtins → root；再读占位 `BMS_SESSION_SECRET` 伪造站长会话；OKPAY HMAC 密钥同机可读。

### 指纹

`uvicorn app.main:app`、`/api/algorithms/upload`、`/okpay/callback`、OpenAPI 公网、SessionMiddleware。

### 检查清单

- [ ] traceback 是否回显给上传者？
- [ ] session secret 是否 change-me*？
- [ ] OKPAY 回调有无 IP 白名单/重放保护？

### 修复

容器+seccomp 真隔离；安装时强随机密钥；回调验签密钥进 KMS。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
