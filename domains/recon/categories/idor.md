# IDOR - 不安全的直接对象引用

> 来源：OWASP / PortSwigger / HackTricks
> 条目前缀：KB-IDOR | 与 ACL 互补：ACL 关注权限，IDOR 关注引用暴露

---

### [KB-IDOR-01] RESTful 自增 ID 枚举
- **类别**: IDOR / 枚举
- **信号**: `/api/user/:id` 或 `/api/users/:id` 端点；ID 为自增整数；GET 返回用户 JSON；JWT 中无用户范围限制
- **原理**: RESTful API 使用自增整数作为资源标识符，且服务端未校验请求者是否为资源所有者。攻击者遍历 ID 即可获取所有用户数据。
- **最小PoC**: GET /api/user/1 → /api/user/2 → ... → /api/user/100 → 获取全部用户信息
- **绕过与变体**: UUID 遍历（需先泄露 UUID）；批量请求（并发100+请求）；响应差异分析（403 vs 404 信息泄露）
- **修复**: 服务端校验 JWT user.id == :id；用 UUID 代替自增 ID；即使 404 也统一响应格式
- **参考**: CWE-639 / PortSwigger: IDOR / OWASP ASVS V4.1.1

### [KB-IDOR-02] 复合对象引用遍历
- **类别**: IDOR / 复合引用
- **信号**: 请求含多个对象标识符（userId + orderId + fileId）；仅校验部分组合
- **原理**: 应用校验了 userId 归属但未校验嵌套对象（orderId/fileId）归属。攻击者保持自己 userId 但替换内嵌对象引用访问他人资源。
- **最小PoC**: POST /api/user/me/order/123 → POST /api/user/me/order/124 → 访问他人订单
- **绕过与变体**: 批量操作中混入他人 ID；修改 body 中的 owner_id 字段
- **修复**: 每个对象标识符逐级校验归属；`user.orders.contains(order)` 而非仅校验 user
- **参考**: CWE-639 / OWASP WSTG-ATHZ-04

### [KB-IDOR-03] 文件路径 IDOR
- **类别**: IDOR / 文件引用
- **信号**: 文件下载/查看使用可预测的文件名或路径；如 `/download?file=report_123.pdf`
- **原理**: 文件资源通过可预测的路径或文件名访问，未校验文件所有者。攻击者修改文件名/路径即可访问他人文件。
- **最小PoC**: GET /download?file=invoice_2024_001.pdf → /download?file=invoice_2024_002.pdf
- **绕过与变体**: 路径遍历组合（/download?file=../user2/report.pdf）；时间戳预测（基于已知用户的创建时间推算）；Hash 碰撞（MD5(fileId) 可被彩虹表反查）
- **修复**: 文件访问通过服务端映射表（用户→文件列表）；随机文件名；使用临时签名 URL（过期+签名）
- **参考**: CWE-639 / OWASP File Upload Cheat Sheet
