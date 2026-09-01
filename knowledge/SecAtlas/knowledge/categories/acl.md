# 访问控制与权限绕过 (ACL & Authorization Bypass)

> 来源：OWASP ASVS / PortSwigger / HackTricks
> 条目前缀：KB-ACL | 覆盖：水平越权、垂直越权、上下文绕过

---

### [KB-ACL-01] 水平越权 (Horizontal Privilege Escalation)
- **类别**: ACL / 水平越权
- **信号**: 修改请求中的资源标识符（用户ID/订单号/文件路径）后可访问他人资源；不同用户间响应内容无差异校验
- **原理**: 应用仅校验用户是否已登录，未校验请求资源的归属关系。攻击者替换资源标识符即可访问同权限级别的他人数据。
- **最小PoC**: GET /api/order/123 → 修改为 /api/order/124 → 返回他人订单详情
- **绕过与变体**: GUID 遍历（UUID 可被泄露后枚举）；多参数组合越权（userId + orderId 不同步）；API 版本切换绕过新版权限校验
- **修复**: 服务端校验 `resource.owner_id == session.user_id`；使用随机不可预测的资源标识符；每次资源访问做归属校验
- **参考**: CWE-639 / OWASP ASVS V4.1.1 / PortSwigger: IDOR

### [KB-ACL-02] 垂直越权 (Vertical Privilege Escalation)
- **类别**: ACL / 垂直越权
- **信号**: 普通用户可直接访问管理员端点；修改 role 参数可提权；未授权访问管理面板
- **原理**: 应用缺少角色校验或角色校验仅在前端实现。攻击者绕过前端路由守卫直接调用后端管理接口。
- **最小PoC**: GET /admin/users → 普通用户 session 返回管理员数据；修改 POST body 中 `role: user` → `role: admin`
- **绕过与变体**: 隐藏的管理路径 (/admin_new, /manager, /backup)；HTTP 方法绕过（GET /admin 403 但 POST /admin 200）；参数污染绕过角色校验
- **修复**: 每个管理端点独立校验角色；服务端强制访问控制；前端路由守卫仅为 UX 优化，不可作为安全边界
- **参考**: CWE-285 / OWASP ASVS V4.1.2 / PortSwigger: Access control

### [KB-ACL-03] 上下文绕过 (Context-Based Access Control Bypass)
- **类别**: ACL / 上下文绕过
- **信号**: 多步骤流程中某一步跳过权限校验；直接访问最终步骤绕过前置条件
- **原理**: 多步骤业务流程（结账/注册/审核）中，仅第一步做了权限校验，后续步骤假设用户已通过校验直接信任请求上下文。
- **最小PoC**: 跳过购物车步骤直接 POST /api/checkout/confirm → 以非授权价格结账
- **绕过与变体**: API 直接调用跳过 UI 流程；修改请求中的步骤标识；重放最终步骤请求
- **修复**: 每个步骤独立校验权限和前置状态；服务端维护流程状态机；不可信任客户端发送的步骤标识
- **参考**: CWE-863 / OWASP ASVS V4.1.3 / PortSwigger: Business logic

### [KB-ACL-04] CORS 配置错误
- **类别**: ACL / CORS
- **信号**: `Access-Control-Allow-Origin: *` 或反射 Origin 头；`Access-Control-Allow-Credentials: true` 配合宽松 Origin
- **原理**: CORS 配置不当允许任意域跨域读取敏感资源。若同时允许 Credentials，攻击者可利用已登录用户的 cookie 从恶意页面发起跨域请求窃取数据。
- **最小PoC**: 恶意页面 fetch('https://target.com/api/user', {credentials:'include'}) → 若 CORS 返回 `ACAO: attacker.com` + `ACAC: true` → 窃取用户数据
- **绕过与变体**: Origin 后缀匹配绕过 (attacker.target.com)；null Origin 允许（沙箱 iframe）；内网 IP 被允许为 Origin
- **修复**: 不使用 `ACAO: *` 配合 Credentials；Origin 精确白名单；敏感 API 禁用 CORS 或仅允许受信域
- **参考**: CWE-942 / OWASP CORS / PortSwigger: CORS

### [KB-ACL-05] 直接对象引用 (IDOR)
- **类别**: ACL / IDOR
- **信号**: RESTful /api/user/:id 自增ID可遍历；GET 参数含对象引用且可被替换
- **原理**: 见 IDOR 分类详情 (KB-IDOR)。核心：资源标识符暴露 + 缺失归属校验 = 越权访问。
- **参考**: CWE-639 / 详见 idor.md
