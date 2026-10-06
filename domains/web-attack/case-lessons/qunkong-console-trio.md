# 群控平台攻击面"三件套" — tingyu28 案 (抖音/小红书真机群控)

**目标**: tingyu28.vip 基础设施 (群控 console + 卡密授权 + FG 记账 + 订单机器人; 10 域名 9 IP)

## 三件套模式 (可复用)
1. **开放注册 → workspace IDOR**: 注册即建后台; `settings?workspace_id=ANY` 跨租户; 卡密 XHS-XXXX 格式泄露+任意配对成功
2. **无鉴权导出 API**: quchong `check_exist/save_selected/export_action=direct&exportType=full` → **867,627 条抖音用户记录**; source_lookup.php/xiaohongshu.php 裸奔; 前端硬编码导出密码
3. **移动端泄露**: releases/latest + /download/android (APK) 未授权; 前端 JS 全量泄露

## APK 侧
- xhs: top.xdwutuobang.xhsmobile (硬编码 URL / /api/v1/pairing-sessions/resolve / /ws/device; Keystore AES-GCM)
- dy: vip.tingyu.dy (AES256_GCM + Google Tink)

## 其他
- 卡密系统: OpenAPI 27 端点 + Ed25519 公钥泄露; /license/activate 产品枚举 oracle; admin 用户名枚举; FTP puredb 损坏
- 喷射 2600+ 次 0 命中 (Tor 轮换+ddddocr) → 强口令反例

## 教训
- 群控品类先打"导出型未授权 API" (`exportType=full` 类参数命中率极高)
- workspace_id / tenant 参数必测跨租户
