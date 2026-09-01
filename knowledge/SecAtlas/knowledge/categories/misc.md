# MISC - 渗透技巧

---

## 2026-07-20

### [MISC-01] Express SPA: JS bundle 逆向必做 (搜 baseURL/api/fetch)
- **信号**: 见案例
- **原理**: Express SPA: JS bundle 逆向必做 (搜 baseURL/api/fetch)
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab
### [MISC-02] 万能密码 SQLi: username=' OR '1'='1 在 Node+SQLite 中有效
- **信号**: 见案例
- **原理**: 万能密码 SQLi: username=' OR '1'='1 在 Node+SQLite 中有效
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab
### [MISC-03] Boolean-based blind SQLi: 用登录成功/失败作为 Oracle
- **信号**: 见案例
- **原理**: Boolean-based blind SQLi: 用登录成功/失败作为 Oracle
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab
### [MISC-04] IDOR: RESTful /api/user/:id 常缺权限校验
- **信号**: 见案例
- **原理**: IDOR: RESTful /api/user/:id 常缺权限校验
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab

---

## 2026-07-21

### [MISC-05] echo $((2#...)) 在受限 shell 中绕过进制限制
- **信号**: 见案例
- **原理**: echo $((2#...)) 在受限 shell 中绕过进制限制
- **最小PoC**: 见案例 20260720-echoes-of-heap
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Echoes of Heap
### [MISC-06] .bak/.swp/.orig 文件是PHP源码泄露的经典入口
- **信号**: 见案例
- **原理**: .bak/.swp/.orig 文件是PHP源码泄露的经典入口
- **最小PoC**: 见案例 20260720-echoes-of-heap
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Echoes of Heap
### [MISC-07] RuoYi自定义表PUT端点可能绕过Spring Security认证
- **信号**: GET /prod-api/ → "RuoYi后台管理框架" + PUT端点返回200无Authorization头
- **原理**: RuoYi的SecurityConfig默认只拦截标准路径(/system/**等)，业务自定义Controller如未显式配置authenticated()则完全公开。攻击者无需凭证即可读写系统配置，包括支付密钥、汇率、钱包地址等
- **最小PoC**: `curl -X PUT https://target/prod-api/bet/system/setting/updateSysBasicInfo -d '{"usdtToCnyRate":10000}'` 返回success=True
- **绕过与变体**: 全量字段写入可能触发Java参数校验(报"系统繁忙")，需逐个字段修改绕过；Java/Spring缓存TTL约30分钟，修改后不会即时生效
- **修复**: SecurityConfig中对所有API路径添加authenticated()；敏感配置不通过前端接口返回
- **来源**: 案例: 博彩平台渗透 (2026-07-21)
### [MISC-08] 2captcha可识别RuoYi数学验证码但返回表达式文本需自行计算
- **信号**: 验证码图片160x60(JPEG) + captchaEnabled:true + 返回uuid
- **原理**: 2captcha识别RuoYi数学验证码后返回如"9-2=?"的表达式文本而非答案，需要在客户端eval计算。且'?'有时被误识别为数字(如"9-2=7")，需fallback处理
- **最小PoC**: `captcha2 solve-image --file captcha.jpg` → {"text":"9-2=?"} → eval("9-2") → 7
- **绕过与变体**: 成功率约60%；UUID有效期约5分钟；同一UUID可多次尝试
- **修复**: 升级为滑块/recaptcha；增加同UUID重试限制；增加图片噪点
- **来源**: 案例: 博彩平台渗透 (2026-07-21)
### [MISC-09] 博彩/灰产平台攻击面：汇率操纵+支付网关劫持+配置读写
- **信号**: Telegram Mini App + 博彩平台 + RuoYi + 有充值/提现功能
- **原理**: 博彩平台通常暴露以下攻击面：1)未授权配置读写(修改汇率/usdt地址/支付密钥)；2)支付网关回调验签(控制密钥可伪造回调)；3)充值订单金额可改(汇率字段非只读)；4)验证码绕过→注册账号→提现(需过人工审核)
- **最小PoC**: 改汇率10000倍→充5 USDT→到账50000内部币→提现申请→人工审核(阻断)
- **绕过与变体**: 后端缓存导致汇率修改不即时生效；提现人工审核是最终阻断点；可通过XSS/钓鱼获取管理员session绕过审核
- **修复**: 配置接口加认证；充值确认后金额字段设为只读；提现增加风控规则(异常金额/频率告警)
- **来源**: 案例: 博彩平台渗透 (2026-07-21)
### [MISC-10] ⚠️ 反模式：支付网关密钥在手但IP白名单卡死
- **信号**: 支付网关API返回"未授权"/"身份认证失败"，直连被拒或经过CDN(Cloudflare)
- **原理**: 即使拿到完整支付网关密钥(商户号+Token+Secret)，网关侧IP白名单仍会阻断外部调用。需要目标服务器IP(或被攻陷的同C段机器)作为代理
- **最小PoC**: 签名算法验证通过(三组测试向量全对)但API返回身份认证失败
- **绕过与变体**: SSRF打点(从目标服务器发出请求)；攻陷同网段机器做跳板；WebSocket劫持；DNS rebinding
- **修复**: 网关侧不下发密钥到业务系统；使用HMAC签名链路而非IP白名单
- **来源**: 案例: 博彩平台渗透 (2026-07-21)
### [MISC-11] ⚠️ 反模式：提现人工审核阻断自动化攻击链
- **信号**: 提现状态长时间pending + 驳回后余额回退 + 无自动审批逻辑
- **原理**: 博彩/支付平台通常对提现设置人工审核。即使完成汇率操纵放大余额，出金环节仍需管理员手动通过。自动化攻击链在此断裂
- **绕过与变体**: 社工钓鱼(改客服链接引流假客服套管理权限)；业务逻辑漏洞(提现金额<阈值自动通过)；竞态条件(审核中修改金额)；XSS劫持管理员Cookie后自动审批
- **修复**: 保留人工审核但增加风控规则(大额/高频异常告警)；审核操作需二次验证
- **来源**: 案例: 博彩平台渗透 (2026-07-21)
### [MISC-12] ⚠️ 能力缺口：无SSRF打点 + 无前端WebView测试 + 无持久化
- **信号**: 目标开放端口少(22/80/443)，无文件上传，无SSRF向量可利用
- **原理**: 本次渗透的三大缺口：1)缺少SSRF(无法利用目标IP调用支付网关)；2)未测Telegram Mini App前端(WebView XSS/postMessage/js bridge)；3)只依赖单一未授权PUT端点，被封即清零
- **绕过与变体**: SSRF→用同网段资产做代理；前端→逆向Mini App JS找bridge接口注入；持久化→写定时任务/WebShell/创建高权限账号
- **修复**: 缩减攻击面(关闭非必要端口/服务/CDN)；前端CSP + iframe沙箱；操作审计日志
- **来源**: 案例: 博彩平台渗透复盘 (2026-07-21)
