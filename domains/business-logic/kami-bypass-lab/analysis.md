# 卡密授权绕过靶场(第一课) — 源码要点

- 靶场形态: 单文件 `index.decrypted.html`(含完整 JS 应用, 4257 行, 已解密版) + 课程 README; 素材为"警笛/警报器"类 App 的授权门模拟
- 四大关卡(README): ①前端本地卡密校验绕过 ②服务端卡密校验绕过 ③12 小时时效限制突破 ④服务端资源下发鉴权欺骗
- 客户端授权门: `verifyLicenseStatus()` — 无 `localStorage.app_license_cdk` 直接 `showCdkLock(true)` 上锁; 有卡密则走 `executeAuthExchange(cdk, isActivate)`
- 校验/激活分支: 本地 `AndroidHardware.getToneConfig()` 是否已有 K_device 决定 `isActivate`(无 → activate, 由服务端下发全套 4 字段补齐缓存)
- 加密信道: `executeAuthExchange` 不走 fetch — 经原生桥 `AndroidHardware.sendSecureAuthAsync` 或 `cordova.exec("AndroidHardware", "sendSecureAuth", [cdk, devId, isActivate])` 交互, 回调收 base64 → `JSON.parse`; 页面文案称"RSA 安全加密通道"
- 时效逻辑: `GRACE_PERIOD_MS = 12 * 60 * 60 * 1000`; 响应非 200 或网络异常时走离线宽限 — 以 `app_first_offline_time` 起算, 超 12h 则 `isCdkAuthorized = false` + `showOfflineLimitModal(true)`
- 作废处理: 服务端返回 401/403/409 → 清空 `app_license_cdk` / `app_license_last_online` / `app_first_offline_time` 三键 + 重新上锁
- 设备指纹: `getOrCreateDeviceFingerprint()` 生成 `HWID-` 前缀的 `app_device_uuid_v1`(存 localStorage); `doActivateCdk()` 激活前强校验该前缀
- 资源/音效下发: 正版走 `AndroidHardware.getToneConfig()`(Java 层解密后返回 JSON → `SERVER_TONE_CONFIG`); `DEFAULT_TONE_CONFIG` 是留给破解环境的"陷阱参数"(全部 1600Hz 测试音, 源码注释明示"正版路径永远不会用到这个")
- 更新通道: `doManualCheckUpdate()` 无卡密时用占位串 `"CHECK_UPDATE_QUERY"` 请求; 版本号 `CURRENT_APP_VERSION_CODE = 20001` / `2.0.1`
- 相关函数: `applyAuthGate()`(授权门渲染) / `showOfflineLimitModal()` / `loadServerToneConfig()` / `refreshServerToneConfig()`

@TGSEC社区 · @TGSEC-Qtzuu 整理
