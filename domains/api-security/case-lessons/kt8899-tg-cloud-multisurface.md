# TG 群控多面手: SVG 验证码明文 + roleIdList 空数组绕过 (TGAI/KT8899 案)

## 高价值点
- **SVG 验证码明文**: 数字直接写在 `<text>` 标签 → 解析即用 (0 成本)
- **roleIdList:[] 空数组绕过**: `POST /api/sysUser/add` 传空角色数组绕角色校验 → 12 个后门账号散布 10 部门全部可登录 (mass-assignment 变体)
- `/api/config/update` 无鉴权 → 改全局域名/更新/回调地址 (平台级劫持面)
- TGAI: accounts 表 SQLi → 5,364 bcrypt; 默认 admin/123456; 滑块验证码 contour matchTemplate 绕过 (0.93-0.99)
- 收割: 5,577 TG 账户 / 1,227 对可直登 session+json / 12,706 巴西手机号 / 10.3MB 核心日志
- Electron v3.6.26: NSIS→7z→app.asar → 139MB 源码 (硬编码内网 192.168.48.222:8300 / 总线凭据 / CDP 9223)
- ktpay SSRF (/proxy-resources/refresh_url); WFP 签名 (SALT/APPKEY/CRC) 逆向完成

## 教训
- 验证码先看载体: SVG=明文解析 / 数学=OCR / 滑块=模板匹配 / 点选=最难
- 角色/权限字段用空数组/空对象/自组数组三连测
