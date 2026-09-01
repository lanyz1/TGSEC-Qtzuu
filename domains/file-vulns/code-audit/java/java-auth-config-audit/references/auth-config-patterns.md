---
name: auth-config-patterns
description: Java 认证与配置安全审计 — 6 类漏洞详细模式参考，含危险代码、安全代码与 EVID 证据模板。
metadata:
  tags: authentication bypass, authorization, idor, jwt, shiro, spring security, 加密配置, 信息泄露, actuator, 业务逻辑
  category: code-audit
---

# Java 认证与配置安全 — 6 类漏洞详细模式

每类含: 危险代码 / 安全代码 / EVID 证据模板。

---

## 1. 认证绕过

### 1.1 Spring Security — 规则顺序与匹配器差异

**危险代码 — antMatchers 顺序错误**:
```java
http.authorizeRequests()
    .antMatchers("/api/**").permitAll()           // 宽松规则在前
    .antMatchers("/api/admin/**").hasRole("ADMIN") // 永远不会执行
    .anyRequest().authenticated();
```
`/api/admin/deleteUser` 被第一条匹配到并 permitAll。

**危险代码 — antMatchers 尾部斜杠差异**:
```java
.antMatchers("/admin/panel").hasRole("ADMIN")
// 访问 /admin/panel/ (末尾斜杠) 可能绕过
```

**安全代码**:
```java
http.authorizeRequests()
    .mvcMatchers("/api/admin/**").hasRole("ADMIN")  // 严格规则在前
    .mvcMatchers("/api/user/**").hasRole("USER")
    .anyRequest().authenticated();  // mvcMatchers 自动处理尾部斜杠
```

### 1.2 Shiro — URI 解析差异绕过

**危险代码**: `filterChainDefinitionMap.put("/api/admin/**", "authc, roles[admin]");`
绕过: `/admin/config/`(CVE-2020-1957) | `/admin/..;/`(CVE-2020-11989) | `%252f`(CVE-2020-13933)

**安全代码**: 升级 Shiro >=1.11.0，启用 `invalidRequest` 全局过滤器。

### 1.3 自定义拦截器 — preHandle 缺陷

**危险代码**: `uri.startsWith("/public")` → `/publicXXX` 也被放行; `uri.contains("/health")` → `/a/health/../admin` 也被放行。

**安全代码**: URI 规范化 + 精确白名单 `Set.of("/public/login", "/health/check")` 匹配。

### EVID_AUTH_BYPASS
```
类型: 认证绕过 | 风险: 严重
文件: src/main/java/.../config/SecurityConfig.java:25-30
描述: antMatchers("/api/**").permitAll() 排在 hasRole("ADMIN") 之前，
     /api/admin/ 下所有端点可未认证访问。
修复: 严格规则移至宽松规则之前；使用 mvcMatchers 替代 antMatchers。
```

---

## 2. 越权

### 2.1 水平越权 — DAO 层缺少用户绑定

**危险代码**:
```java
// Controller — 未检查订单归属
@GetMapping("/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    return orderService.getById(orderId);
}
// Mapper — 缺少 AND user_id = #{currentUserId}
// SELECT * FROM orders WHERE id = #{orderId}
```

**安全代码 — 方案 A: Service 层校验归属** / **方案 B: `@PreAuthorize` + SpEL** / **方案 C: DAO 层 `WHERE id=? AND user_id=?`**

### 2.2 垂直越权 — 接口缺少角色注解

**危险代码**:
```java
@RestController @RequestMapping("/admin")
public class AdminController {
    @PostMapping("/deleteUser")  // 缺少 @PreAuthorize
    public Result deleteUser(@RequestParam Long userId) { ... }
}
```

**安全代码**: 类级别 `@PreAuthorize("hasRole('ADMIN')")` 兜底 + 方法级细粒度权限。

### EVID_AUTHZ
```
EVID_AUTHZ_001 | 类型: 水平越权 | 风险: 高
文件: OrderController.java:42 + OrderMapper.xml:18
描述: DAO 层 SQL 缺少 user_id 过滤，任何用户可遍历 orderId 获取他人订单。
修复: DAO 添加 AND user_id 条件或 Service 层归属校验。

EVID_AUTHZ_002 | 类型: 垂直越权 | 风险: 高
文件: AdminController.java:15-25
描述: 管理接口未配置角色注解，普通用户可直接调用。
修复: 类级别 @PreAuthorize("hasRole('ADMIN')")。
```

---

## 3. JWT 安全

### 3.1 算法混淆

**危险代码 — 未限定算法**:
```java
Claims claims = Jwts.parser()
    .setSigningKey(publicKey)   // RSA 公钥
    .parseClaimsJws(token).getBody();
// 攻击: alg RS256→HS256，用公钥作 HMAC 密钥签名 → 验证通过
// 攻击: alg→none，删除签名部分 → 老版本库可能通过
```

**安全代码 — jjwt**:
```java
JwtParser parser = Jwts.parserBuilder()
    .requireIssuer("myapp").requireAudience("myapp-api")
    .setSigningKey(secretKey).build();
// jjwt 0.12+ 默认拒绝 alg:none; RSA 场景需显式校验 header algorithm
```

**安全代码 — auth0-java-jwt**:
```java
Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, null);
JWTVerifier verifier = JWT.require(algorithm)
    .withIssuer("myapp").withAudience("myapp-api").acceptExpiresAt(0).build();
```

### 3.2 密钥硬编码

**危险代码**:
```java
private static final String SECRET_KEY = "mySecretKey123456";  // 硬编码
```

**安全代码**: 环境变量 `@Value("${JWT_SECRET}")` / Vault / KMS 动态获取。

### 3.3 Claims 校验缺失

**危险代码**: 未检查 exp/iss/aud → 过期 token 有效、跨系统 token 可用。

**安全代码**:
```java
Jwts.parserBuilder().setSigningKey(key)
    .requireIssuer("auth-server").requireAudience("order-service")
    .requireExpiration(new Date()).build()
    .parseClaimsJws(token).getBody();
```

### 3.4 刷新机制缺陷

**危险代码**: refresh_token 无过期 + 不绑定设备 → 被盗后可无限刷新。

**安全代码**: 过期校验 + 设备指纹绑定 + Rotation(刷新后旧 token 失效)，指纹不匹配时撤销所有令牌。

### EVID_JWT
```
EVID_JWT_001 | 类型: 算法混淆 | 风险: 严重
文件: JwtUtil.java:34
描述: JWT 解析未指定算法，RSA 公钥验签可被 HS256 攻击绕过。
修复: parserBuilder() + 显式验证 algorithm。

EVID_JWT_002 | 类型: 密钥硬编码 | 风险: 高
文件: JwtUtil.java:12
描述: SECRET_KEY 硬编码在源码中，获取源码即可伪造任意 JWT。
修复: 环境变量或 Vault/KMS。
```

---

## 4. 加密配置

### 4.1 弱哈希做密码存储

**危险代码**:
```java
MessageDigest.getInstance("MD5").digest(password.getBytes());   // 彩虹表秒破
MessageDigest md = MessageDigest.getInstance("SHA-1");
md.update("fixedSalt".getBytes());  // 盐值硬编码
```

**安全代码**:
```java
new BCryptPasswordEncoder(12);  // 或 SCrypt / Argon2
```

### 4.2 弱对称加密

**危险代码**:
```java
Cipher.getInstance("DES/ECB/PKCS5Padding");  // DES 56 位 + ECB 泄露模式
Cipher.getInstance("AES/ECB/PKCS5Padding");  // AES 用 ECB 仍不安全
Cipher.getInstance("RC4");                    // 统计偏差
```

**安全代码**:
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
// IV 与密文一起存储; 也可用 AES-CBC + HMAC (Encrypt-then-MAC)
```

### 4.3 硬编码密钥

**危险代码**:
```java
private static final String KEY = "aGVsbG93b3JsZDEyMzQ1Ng==";  // 密钥硬编码
private static final String IV  = "0000000000000000";            // 固定 IV
```

**安全代码**: `@Value("${encryption.key}")` 从配置中心/环境变量获取; IV 每次随机生成。

### 4.4 不安全随机数

**危险代码**:
```java
Random random = new Random();       // 线性同余，种子可预测
Random random = new Random(12345L); // 固定种子更危险
```

**安全代码**:
```java
SecureRandom secureRandom = new SecureRandom();
byte[] bytes = new byte[32];
secureRandom.nextBytes(bytes);
```

### EVID_CRYPTO
```
EVID_CRYPTO_001 | 类型: 弱密码哈希 | 风险: 高
文件: PasswordUtil.java:18
描述: MD5 无盐哈希密码，彩虹表秒破。
修复: BCryptPasswordEncoder(12) 或 Argon2。

EVID_CRYPTO_002 | 类型: 弱对称加密 | 风险: 高
文件: EncryptUtil.java:25
描述: DES/ECB/PKCS5Padding，密钥 56 位可暴力破解 + ECB 泄露模式。
修复: AES/GCM/NoPadding，密钥 256 位。

EVID_CRYPTO_003 | 类型: 不安全随机数 | 风险: 高
文件: TokenService.java:33
描述: java.util.Random 生成 token，输出可预测。
修复: 替换为 SecureRandom。
```

---

## 5. 信息泄露

### 5.1 Actuator 端点暴露

**危险代码 — application.yml**:
```yaml
management.endpoints.web.exposure.include: "*"
```

高危端点: `/actuator/env`(密码/Key) | `/actuator/heapdump`(堆内存) | `/actuator/jolokia`(RCE) | `/actuator/configprops` | `/actuator/mappings` | `/actuator/httptrace`(请求 Header/Cookie)

**安全代码**:
```yaml
management.endpoints.web.exposure.include: health,info,metrics
management.endpoints.web.base-path: /internal-monitor
```
```java
http.requestMatcher(EndpointRequest.toAnyEndpoint())
    .authorizeRequests().anyRequest().hasRole("ACTUATOR_ADMIN")
    .and().httpBasic();
```

### 5.2 错误堆栈返回客户端

**危险代码**: 缺少 `@RestControllerAdvice`，SQL 异常堆栈直接返回（泄露表名、SQL 语法）。

**安全代码**: `@RestControllerAdvice` + `@ExceptionHandler(Exception.class)` 吞掉堆栈，服务端 `log.error()` 记录，客户端仅返回 traceId + 通用错误信息。

### 5.3 Debug 模式

**危险代码**: `server.error.include-stacktrace: always` / `spring.devtools.restart.enabled: true`
**安全代码** (application-prod.yml): `include-stacktrace: never` / `include-message: never` / `devtools.restart.enabled: false`

### 5.4 敏感数据日志

**危险代码**: `log.info("password={}", password)` / `log.debug("card={}, cvv={}", ...)`
**安全代码**: 绝不记录密码; 信用卡号仅保留后四位。

### EVID_INFO
```
EVID_INFO_001 | 类型: Actuator 暴露 | 风险: 严重
文件: application.yml:45
描述: exposure.include="*"，/env 暴露密码，/heapdump 可下载堆内存。
修复: 限制端点 + 认证保护。

EVID_INFO_002 | 类型: 错误堆栈泄露 | 风险: 中
文件: 全局 (缺少 @RestControllerAdvice)
描述: SQL 异常堆栈返回客户端，泄露表名和 SQL 语法。
修复: 添加全局异常处理类。
```

---

## 6. 业务逻辑

### 6.1 并发竞争 — Double-Spending

**危险代码**:
```java
Account account = accountMapper.selectById(userId);    // 无锁查询
if (account.getBalance().compareTo(amount) < 0) return fail;
account.setBalance(account.getBalance().subtract(amount));  // 非原子
accountMapper.updateById(account);
// 并发: 余额 100，10 个请求同时读到 100 → 全部通过 → 余额 -900
```

**安全代码 — 方案 A: SELECT FOR UPDATE (悲观锁)**:
```java
Account account = accountMapper.selectByIdForUpdate(userId); // 行级锁
```

**安全代码 — 方案 B: 乐观锁**:
```sql
UPDATE accounts SET balance = balance - #{amount}, version = version + 1
WHERE user_id = #{userId} AND version = #{version} AND balance >= #{amount}
```

**安全代码 — 方案 C: Redis 分布式锁**:
```java
redisTemplate.opsForValue().setIfAbsent("lock:balance:" + userId, "1", Duration.ofSeconds(5));
```

### 6.2 参数篡改 — 金额/数量

**危险代码**:
```java
order.setPrice(request.getPrice());              // 客户端传入价格
order.setTotalAmount(request.getTotalAmount());   // 客户端传入总额
// 攻击: {"price":0.01, "totalAmount":0.01}
```

**安全代码**: 服务端从数据库获取商品价格，重新计算总额; 校验数量 > 0。

### 6.3 流程绕过 — 步骤间缺少状态校验

**危险代码**: 注册 step1/step2/step3 为独立接口，step3 无前置状态检查 → 攻击者跳过邮箱验证直接设置密码。

**安全代码**: 引入状态机 `INIT → INFO_SUBMITTED → EMAIL_VERIFIED → COMPLETED`，每步校验前置状态 + 有效时间窗口:
```java
if (reg.getStatus() != RegistrationStatus.EMAIL_VERIFIED) {
    return Result.fail("请先完成邮箱验证");
}
```

### EVID_LOGIC
```
EVID_LOGIC_001 | 类型: 并发竞争 | 风险: 严重
文件: AccountService.java:45-55
描述: 余额查询与扣款非原子，并发可超额扣款。
修复: SELECT FOR UPDATE 或乐观锁。

EVID_LOGIC_002 | 类型: 参数篡改 | 风险: 高
文件: OrderController.java:30-40
描述: 直接使用客户端传入 price/totalAmount，可篡改为极低价格。
修复: 服务端从数据库获取价格重新计算。

EVID_LOGIC_003 | 类型: 流程绕过 | 风险: 高
文件: RegisterController.java:50-55
描述: step3 未校验前置状态，可跳过邮箱验证。
修复: 状态机校验 status == EMAIL_VERIFIED。
```

---

## 审计搜索关键词速查

```
# 认证: SecurityConfig, WebSecurityConfigurerAdapter, HttpSecurity,
#       ShiroFilterFactoryBean, filterChainDefinitionMap,
#       HandlerInterceptor, preHandle, OncePerRequestFilter, doFilter
# 越权: selectById, @PathVariable, @PreAuthorize, @RequiresRoles
# JWT:  Jwts.parser, Algorithm.HMAC, SECRET_KEY, jwt.secret
# 加密: MessageDigest.getInstance, Cipher.getInstance, new Random()
# 泄露: management.endpoints.web.exposure, @ControllerAdvice, devtools
# 逻辑: balance, amount, price, FOR UPDATE, version, setIfAbsent, status
```
