# 在野平台默认密钥与"渗透指挥平台"情报 (舰队战报摘录)

## OpenIM 默认 JWT 密钥
- `openIM123` 默认密钥 → 伪造 imAdmin → 68 群 / 4.5 万用户全量
- OpenIM 部署检查点: config 默认 secret / imAdmin token 伪造面

## "星环 XingRin" 渗透指挥平台 (在野元数据!)
- 读写 API **全无鉴权**: 68 目标 / 86 扫描史 — **攻击方的指挥平台自身裸奔**
- 教训: 打黑产/红队对手时优先找其"指挥/协作平台" — 元数据=全量目标+手法+扫描历史

## 其他摘录
- JeecgBoot RCE → MinIO Host 泄露 → Token 注入超管 (不改密码)
- 注册机 session_key 复活; WFP 支付签名 (SALT/APPKEY/CRC) 全逆向; 印章点选验证码破解; 假钱包工厂 93 域名分布式
