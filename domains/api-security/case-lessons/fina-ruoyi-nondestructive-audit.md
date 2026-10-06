# fina.icu 非破坏审计要点 (RuoYi 钱包生态)

**目标**: fina.icu 10+ 系统同 IP 154.9.25.34 (钱包后台/钱包API/用户端小程序/商户后台/游戏运维/接码平台/OSS)

## 发现 (F-01~F-09 摘要)
- **F-01 前端 _app.config.js 内联 RSA 私钥 + 密码加密开关=false** (明文传输面)
- F-02 测试/运维后台 (fttest/testmer/code) 公网直暴露, 加固弱于生产
- F-03 登录账号枚举 (文案差异: "账号不存在" vs "谷歌验证码不能为空")
- F-04 无图形验证码 + 锁定策略不统一 (3min vs 10min)
- F-05 CORS 反射任意 Origin (无 credentials); F-06 Swagger 公网; F-07 /prod-api/logout 未鉴权; F-08 多系统同 IP 无隔离

## "已排查清单" (对账模板)
JWT 默认密钥×20+ / alg=none / 畸形头 / XFF 伪造 / 白名单穿越 / 登录 SQLi / Druid / Actuator — 均未复现

## 教训
- SPA 审计第一站 = 运行时配置 (config.js/_app.config.js): 密钥/开关/内联私钥
- 评估型交付: 只读枚举 + 公开面审计 + "已排除清单"; 报告按 P0-P2 优先级
