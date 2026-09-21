# 案例课：ChatNet + LskyPro + Cloudreve UGC 集群

> 脱敏。同开发者聊天/图床/网盘一条链打到云根 AK。

## 模式

```text
LskyPro is_admin=1 注册 → OSS AK
→ ChatNet /ajax/add-profile user_type=1 未授权建管
→ 拖用户/私聊；OSS 读写网盘
→ GetCallerIdentity=root → Cloud Assistant root
```

### 信号

- ChatNet：`/ajax/add-profile`、CSRF 注释掉
- Lsky：注册体可写管理员字段
- Cloudreve + 阿里云 OSS；AK 可能是主账号根钥

### 纪律

探路用空参数证明写簇可达；不改真超管密、不删生产。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
