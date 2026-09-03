# 案例课：EdgeOne/Bot 墙 + 开放注册过量权限 + 上传

> 脱敏。筛号/聚合 SaaS（RuoYi-Vue API + 多 CDN）常见组合。

## 链

```text
落地多子域（app/admin/api）指纹
→ API 前 TencentEdgeOne JS Challenge / Bot cookie
→ 静态逆向或复用已知解法拿 EO cookie
→ 开放 /register → common 角色菜单过多
→ 产品列表/定价/thirdSource 泄露
→ /common/upload 无类型或弱类型
→ Druid 等监控入口暴露（独立弱口令另测）
```

## 检查清单

- [ ] WAF cookie 是否可本地重放/脚本化
- [ ] Host 直连边缘 IP 是否绕过部分策略
- [ ] 注册默认角色权限是否最小化
- [ ] 产品/API 名/佣金/COS 路径是否对普通用户可见
- [ ] upload 后缀白名单；返回 path 是否 web 可达
- [ ] `/druid` `/actuator` 是否公网

## 报告点

区分：**配置/信息泄露 CRITICAL** vs **未拿到 admin 密码** 的诚实结论。  
thirdSource 说明平台可能只是调度方，库存不在本机。



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
