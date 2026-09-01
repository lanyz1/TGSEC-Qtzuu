---
name: java-auth-config-audit
description: |
  Java 源码认证与配置安全审计。当在 Java 白盒审计中需要检测认证绕过、权限缺陷或安全配置问题时触发。
  覆盖 6 类风险: 认证绕过(Spring Security/Shiro Filter 链 URI 解析差异)、
  越权(IDOR/水平越权/垂直越权)、JWT 安全(算法混淆/密钥泄露/Claims 验证)、
  加密配置(弱算法/硬编码密钥/不安全随机数)、信息泄露(错误堆栈/Actuator/Debug 模式)、
  业务逻辑漏洞(竞争条件/金额篡改/流程绕过)。
metadata:
  tags: authentication bypass, authorization, idor, jwt, shiro, spring security, 认证绕过, 越权, 加密配置, 信息泄露, actuator, 业务逻辑, java source audit
  category: code-audit
---

# Java 认证与配置安全源码审计

Java 后端项目中认证、授权与安全配置是最高频的漏洞产出面。本 skill 提供 6 大类白盒审计的完整检测思路，适用于 Spring Boot/Spring Security、Apache Shiro 及自定义框架。

## 相关 Skill

- `java-framework-audit` — Spring/Struts/MyBatis 框架审计
- `java-injection-audit` — SQL/OGNL/EL 注入审计
- `java-serialization-audit` — 反序列化漏洞审计
- `idor-methodology` — 黑盒 IDOR 测试方法论

## 深入参考

- 6 类漏洞详细模式（危险代码/安全代码/EVID 证据）-> [references/auth-config-patterns.md](references/auth-config-patterns.md)

---

## 6 类风险速查表

| # | 类别 | 关键搜索入口 | 危害等级 |
|---|------|-------------|---------|
| 1 | 认证绕过 | `SecurityConfig`, `ShiroFilterFactory`, `doFilter` | 严重 |
| 2 | 越权 | DAO/Mapper 查询语句, `@PreAuthorize`, Controller 参数 | 高 |
| 3 | JWT 安全 | `Jwts.parser()`, `Algorithm.HMAC`, `SECRET_KEY` | 高 |
| 4 | 加密配置 | `MessageDigest`, `Cipher.getInstance`, `new Random()` | 高 |
| 5 | 信息泄露 | `application.yml` Actuator 配置, `@ExceptionHandler` | 中 |
| 6 | 业务逻辑 | 余额/库存操作, 状态机流转, 支付回调 | 高 |

---

## 1. 认证绕过审计要点

- **Spring Security**: 检查 `FilterChainProxy` 匹配规则，`AntPathRequestMatcher` 与 `MvcRequestMatcher` 差异（尾部斜杠/路径后缀）；`requestMatchers` 顺序——宽松规则 `permitAll()` 在前会覆盖后续拦截；`permitAll()` 是否过度开放（如 `/api/**`）
- **Shiro**: URI 解析差异导致绕过——`/admin/` vs `/admin` vs `/admin/..;/`；CVE-2020-1957 / CVE-2020-11989 / CVE-2020-13933 等 path normalization 系列绕过
- **自定义 Filter**: `doFilter()` 中 early return 导致后续 chain 未执行；白名单正则不严谨（如 `startsWith("/public")` 可被 `/publicevil` 匹配）

## 2. 越权审计要点

- **水平越权**: 接口仅校验登录态未校验资源归属——DAO 层 `WHERE id = #{orderId}` 缺少 `AND user_id = #{currentUserId}` 条件
- **垂直越权**: Controller/Service 方法缺少角色注解 `@PreAuthorize`/`@RequiresRoles`；枚举值（角色 ID）可猜解
- **IDOR**: 自增 ID 可遍历；UUID 是否真正不可预测；批量接口跳过单条权限检查

## 3. JWT 安全审计要点

- **算法混淆**: `alg: none` 绕过签名验证；RS256 -> HS256 攻击（用公钥作为 HMAC 密钥）
- **密钥硬编码**: 源码中 `SECRET_KEY = "xxx"` 或 `application.yml` 明文配置
- **Claims 校验缺失**: `exp`(过期)/`iss`(签发者)/`aud`(受众) 未验证导致 token 可跨环境复用
- **刷新机制**: `refresh_token` 长期有效且未绑定用户/设备，被盗后可无限刷新

## 4. 加密配置审计要点

- **弱算法**: `MD5`/`SHA1` 做密码哈希、`DES`/`RC4` 加密、`ECB` 模式（泄露数据模式）
- **正确做法**: 密码用 `bcrypt`/`scrypt`/`argon2`；对称加密用 `AES-GCM`/`AES-CBC+HMAC`
- **硬编码密钥/盐值**: `private static final String KEY = "..."` 或盐值写死在代码中
- **不安全随机**: `java.util.Random` 可预测，安全场景必须用 `SecureRandom`

## 5. 信息泄露审计要点

- **Actuator 端点暴露**: `/env`(环境变量/密码)、`/heapdump`(堆内存含密钥)、`/jolokia`(远程代码执行)
- **详细错误堆栈**: 全局异常处理器缺失，SQL 报错/类名/路径直接返回客户端
- **Debug 模式**: `server.error.include-stacktrace=always`、`spring.devtools` 未移除
- **敏感数据日志**: `log.info("用户密码: {}", password)` 或完整信用卡号写入日志文件

## 6. 业务逻辑审计要点

- **并发竞争**: 余额检查与扣款非原子操作（double-spending）；优惠券/积分重放
- **参数篡改**: 金额/数量/折扣由客户端传入且服务端未重新计算；订单金额可为负数
- **流程绕过**: 多步流程（注册-验证-设置密码）步骤间缺少状态校验，可直接跳到后续接口

---

## 检测清单

审计时逐项确认，每发现一项即记录 EVID 证据:

- [ ] Spring Security 配置链顺序问题或过度 `permitAll`
- [ ] Shiro `filterChainDefinitionMap` URI 解析差异绕过
- [ ] 自定义 Filter/Interceptor early return 或白名单绕过
- [ ] 数据查询是否绑定当前用户 ID（水平越权）
- [ ] 敏感接口是否有角色/权限注解（垂直越权）
- [ ] JWT 是否强制指定算法 + 密钥安全存储 + Claims 全验证
- [ ] 密码存储 bcrypt/scrypt/argon2; 对称加密 AES-GCM 且密钥不硬编码
- [ ] 随机数使用 SecureRandom
- [ ] Actuator 端点限制访问 + 认证保护
- [ ] 全局异常处理器吞掉堆栈; 生产关闭 debug/devtools; 日志无敏感数据
- [ ] 金额/库存操作原子性; 多步流程状态机校验
