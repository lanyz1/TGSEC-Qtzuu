# Electron jsc 字节码 → 签名 Oracle 重建 (SKYSCRM 案)

## 流程
1. Electron 22.3.27 客户端 → asar 解包 + jsc (bytenode) 字节码提取
2. 硬编码材料: AES 密钥/IV + CDN 签名盐 (API 端 + localStorage 两套)
3. 从 jsc 抽签名逻辑 → 补环境执行 → **重建 V8 签名 Oracle** (可对任意请求签名)
## 失败面 (记录防重复)
- JWT 篡改 / TP5 RCE / lang LFI / SSH 弱口令 / OSS 越权 — 全未果
## 教训
- 厚客户端 (Electron) 常是签名体系最弱点: asar+jsc 工具链 + 字符串提取
- 硬编码材料常分"静默两套" (前端一套/客户端一套), 全都要拿
