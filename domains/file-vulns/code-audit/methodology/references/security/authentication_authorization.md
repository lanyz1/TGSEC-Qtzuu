# 认证与授权安全审计 (CWE-287/306/269/276/862/863)

> 覆盖 OWASP A01/A07 | 认证缺失/不当 | 授权缺失/不当 | 权限管理 | 默认权限
>
> 适用全语言通用规则 + 框架专项

---

## 目录

1. [CWE 映射与风险等级](#1-cwe-映射与风险等级)
2. [认证安全 (CWE-287/306)](#2-认证安全)
3. [授权安全 (CWE-862/863)](#3-授权安全)
4. [权限管理 (CWE-269)](#4-权限管理)
5. [默认权限 (CWE-276)](#5-默认权限)
6. [多语言检测规则](#6-多语言检测规则)
7. [框架专项检测](#7-框架专项检测)

---

## 1. CWE 映射与风险等级

| CWE | 名称 | CVSS基础 | OWASP | 典型场景 |
|-----|------|----------|-------|----------|
| CWE-287 | 认证不当 | 9.8 | A07 | 弱密码策略、会话固定 |
| CWE-306 | 关键功能缺少认证 | 9.8 | A07 | API未鉴权、管理接口暴露 |
| CWE-862 | 缺少授权 | 8.8 | A01 | 水平越权、IDOR |
| CWE-863 | 授权不当 | 8.8 | A01 | 垂直越权、权限提升 |
| CWE-269 | 权限管理不当 | 8.0 | A01 | 过度权限、权限残留 |
| CWE-276 | 默认权限不当 | 7.5 | A05 | 默认管理员、0777权限 |

---

## 2. 认证安全

### 2.1 CWE-306: 关键功能缺少认证

#### 危险模式
```java
// Java/Spring - 缺少认证的敏感接口
@RestController
public class AdminController {
    @GetMapping("/admin/users")        // 🔴 无 @PreAuthorize
    public List<User> getAllUsers() {
        return userService.findAll();
    }

    @PostMapping("/admin/config")      // 🔴 管理配置无认证
    public void updateConfig(@RequestBody Config config) {
        configService.update(config);
    }
}
```

```python
# Python/FastAPI - 缺少依赖注入认证
@app.get("/admin/users")  # 🔴 无 Depends(get_current_user)
async def get_users():
    return await User.all()

@app.delete("/api/records/{id}")  # 🔴 无认证
async def delete_record(id: int):
    await Record.filter(id=id).delete()
```

```javascript
// Node.js/Express - 缺少中间件
app.get('/admin/dashboard', (req, res) => {  // 🔴 无 authMiddleware
    res.json(getAdminData());
});

// Koa - 路由未保护
router.delete('/api/users/:id', async (ctx) => {  // 🔴 无认证
    await User.destroy({ where: { id: ctx.params.id } });
});
```

```go
// Go/Gin - 缺少中间件
r.GET("/admin/stats", func(c *gin.Context) {  // 🔴 无 AuthRequired()
    c.JSON(200, getStats())
})
```

```csharp
// .NET - 缺少 [Authorize]
[ApiController]
public class AdminController : ControllerBase {
    [HttpGet("admin/secrets")]  // 🔴 无 [Authorize]
    public IActionResult GetSecrets() => Ok(secrets);
}
```

```ruby
# Rails - 缺少 before_action
class AdminController < ApplicationController
  # 🔴 缺少 before_action :authenticate_admin!
  def index
    @users = User.all
  end
end
```

```rust
// Rust/Actix - 缺少中间件
web::resource("/admin/config")
    .route(web::get().to(get_config))  // 🔴 无 .wrap(Auth)
```

#### 快速检测命令
```bash
# 查找无认证保护的敏感路由
# Java/Spring
rg -n "@(Get|Post|Put|Delete|Patch)Mapping.*admin|@RequestMapping.*admin" --glob "*.java" | \
  xargs -I {} sh -c 'grep -B5 "{}" | grep -v "@PreAuthorize\|@Secured"'

# Python/FastAPI
rg -n "@app\.(get|post|put|delete).*admin" --glob "*.py" | \
  xargs -I {} sh -c 'grep -B3 "{}" | grep -v "Depends.*auth\|current_user"'

# Node.js
rg -n "app\.(get|post|put|delete).*admin|router\.(get|post)" --glob "*.js" --glob "*.ts"

# Go
rg -n '\.(GET|POST|PUT|DELETE)\("/admin' --glob "*.go"

# .NET
rg -n '\[Http(Get|Post|Put|Delete).*admin' --glob "*.cs" | \
  xargs -I {} sh -c 'grep -B3 "{}" | grep -v "\[Authorize\]"'
```

### 2.2 CWE-287: 认证不当

#### 弱密码策略
```java
// 🔴 无密码强度验证
public void register(String username, String password) {
    User user = new User(username, encoder.encode(password));
    userRepository.save(user);
}

// 🟢 安全: 密码策略验证
public void register(String username, String password) {
    if (!PasswordPolicy.isStrong(password)) {  // 长度、复杂度、常见密码检查
        throw new WeakPasswordException();
    }
    // 限制注册频率
    rateLimiter.checkLimit(getClientIP());
    User user = new User(username, encoder.encode(password));
    userRepository.save(user);
}
```

#### 会话固定攻击
```java
// 🔴 登录后未重新生成 Session ID
@PostMapping("/login")
public String login(HttpSession session, @RequestBody LoginRequest req) {
    if (authService.authenticate(req)) {
        session.setAttribute("user", req.getUsername());  // 🔴 Session ID 未变
        return "success";
    }
    return "failed";
}

// 🟢 安全: 重新生成 Session
@PostMapping("/login")
public String login(HttpServletRequest request, @RequestBody LoginRequest req) {
    if (authService.authenticate(req)) {
        request.getSession().invalidate();  // 销毁旧会话
        HttpSession newSession = request.getSession(true);  // 创建新会话
        newSession.setAttribute("user", req.getUsername());
        return "success";
    }
    return "failed";
}
```

#### 暴力破解防护缺失
```python
# 🔴 无登录限制
@app.post("/login")
async def login(credentials: Credentials):
    user = await User.get_or_none(username=credentials.username)
    if user and verify_password(credentials.password, user.password_hash):
        return {"token": create_token(user)}
    raise HTTPException(401, "Invalid credentials")

# 🟢 安全: 登录限制
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/login")
@limiter.limit("5/minute")  # 每分钟5次
async def login(request: Request, credentials: Credentials):
    # 检查账户锁定状态
    if await is_account_locked(credentials.username):
        raise HTTPException(423, "Account locked")

    user = await User.get_or_none(username=credentials.username)
    if user and verify_password(credentials.password, user.password_hash):
        await reset_failed_attempts(credentials.username)
        return {"token": create_token(user)}

    await increment_failed_attempts(credentials.username)
    raise HTTPException(401, "Invalid credentials")
```

---

## 3. 授权安全

### 3.1 CWE-862: 缺少授权 (水平越权/IDOR)

#### 危险模式
```java
// 🔴 直接使用用户输入的 ID，无所有权验证
@GetMapping("/api/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    return orderRepository.findById(orderId)  // 可访问任意订单
        .orElseThrow();
}

// 🟢 安全: 验证资源所有权
@GetMapping("/api/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId, @AuthenticationPrincipal User user) {
    Order order = orderRepository.findById(orderId).orElseThrow();
    if (!order.getUserId().equals(user.getId())) {
        throw new AccessDeniedException("Not your order");
    }
    return order;
}
```

```python
# 🔴 IDOR - 可修改任意用户
@app.put("/api/users/{user_id}")
async def update_user(user_id: int, data: UserUpdate):
    await User.filter(id=user_id).update(**data.dict())  # 无所有权检查

# 🟢 安全
@app.put("/api/users/{user_id}")
async def update_user(user_id: int, data: UserUpdate, current_user: User = Depends(get_current_user)):
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(403, "Forbidden")
    await User.filter(id=user_id).update(**data.dict())
```

```javascript
// 🔴 Node.js IDOR
app.get('/api/documents/:docId', async (req, res) => {
    const doc = await Document.findByPk(req.params.docId);  // 无所有权检查
    res.json(doc);
});

// 🟢 安全
app.get('/api/documents/:docId', authMiddleware, async (req, res) => {
    const doc = await Document.findOne({
        where: { id: req.params.docId, userId: req.user.id }  // 绑定用户
    });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
});
```

#### 检测命令
```bash
# 查找潜在 IDOR
# 参数直接用于数据库查询
rg -n "findById\(.*param|findByPk\(.*params|filter\(id=" --glob "*.{java,py,js,ts,go,rb}"

# 查找缺少所有权检查的模式
rg -n "\.findById\(|\.get\(.*id\)|\.filter\(.*=.*id\)" --glob "*.{java,py,js,ts}" | \
  grep -v "userId\|user_id\|owner\|current_user"
```

### 3.2 CWE-863: 授权不当 (垂直越权)

#### 危险模式
```java
// 🔴 仅前端控制，后端无角色检查
@PostMapping("/admin/promote")
public void promoteUser(@RequestBody PromoteRequest req) {
    userService.setRole(req.getUserId(), "ADMIN");  // 任何人可调用
}

// 🟢 安全: 后端角色验证
@PostMapping("/admin/promote")
@PreAuthorize("hasRole('SUPER_ADMIN')")  // 仅超级管理员
public void promoteUser(@RequestBody PromoteRequest req, @AuthenticationPrincipal User admin) {
    // 审计日志
    auditLog.record(admin.getId(), "PROMOTE_USER", req.getUserId());
    userService.setRole(req.getUserId(), "ADMIN");
}
```

```python
# 🔴 角色检查不完整
@app.delete("/api/posts/{post_id}")
async def delete_post(post_id: int, current_user: User = Depends(get_current_user)):
    post = await Post.get(id=post_id)
    if post.author_id == current_user.id:  # 🔴 缺少管理员判断
        await post.delete()
    else:
        raise HTTPException(403)

# 🟢 安全
@app.delete("/api/posts/{post_id}")
async def delete_post(post_id: int, current_user: User = Depends(get_current_user)):
    post = await Post.get(id=post_id)
    if post.author_id == current_user.id or current_user.role in ['admin', 'moderator']:
        await post.delete()
    else:
        raise HTTPException(403)
```

---

## 4. 权限管理 (CWE-269)

### 4.1 过度权限

```java
// 🔴 服务账号权限过大
@Bean
public DataSource dataSource() {
    return DataSourceBuilder.create()
        .username("root")          // 🔴 使用 root
        .password("password")
        .build();
}

// 🔴 API Token 权限过大
String apiKey = "[REDACTED]";  // 拥有所有权限

// 🟢 安全: 最小权限原则
@Bean
public DataSource dataSource() {
    return DataSourceBuilder.create()
        .username("app_readonly")  // 只读账号
        .password(secretManager.get("db_password"))
        .build();
}
```

### 4.2 权限残留

```java
// 🔴 用户降级后权限未清除
public void downgradeUser(Long userId) {
    User user = userRepository.findById(userId).get();
    user.setRole("BASIC");  // 🔴 缓存中的权限未清除
    userRepository.save(user);
}

// 🟢 安全: 清除所有权限缓存
public void downgradeUser(Long userId) {
    User user = userRepository.findById(userId).get();
    user.setRole("BASIC");
    userRepository.save(user);

    // 清除权限缓存
    permissionCache.evict(userId);
    // 使现有会话失效
    sessionRegistry.getAllSessions(user, false)
        .forEach(s -> s.expireNow());
}
```

---

## 5. 默认权限 (CWE-276)

### 5.1 默认管理员账户

```java
// 🔴 硬编码默认管理员
@PostConstruct
public void init() {
    if (userRepository.count() == 0) {
        User admin = new User("admin", encoder.encode("admin123"));  // 🔴
        admin.setRole("ADMIN");
        userRepository.save(admin);
    }
}

// 🟢 安全: 首次启动强制设置
@PostConstruct
public void init() {
    if (userRepository.count() == 0) {
        String randomPassword = generateSecurePassword();
        log.warn("Initial admin password (change immediately): {}", randomPassword);
        User admin = new User("admin", encoder.encode(randomPassword));
        admin.setMustChangePassword(true);  // 强制修改
        userRepository.save(admin);
    }
}
```

### 5.2 文件/目录默认权限

```python
# 🔴 过于宽松的权限
os.makedirs("/app/uploads", mode=0o777)  # 任何人可读写执行

with open("/app/config/secrets.json", "w") as f:  # 默认权限可能过宽
    f.write(json.dumps(secrets))

# 🟢 安全: 限制权限
os.makedirs("/app/uploads", mode=0o750)  # 所有者读写执行，组读执行

import stat
with open("/app/config/secrets.json", "w") as f:
    f.write(json.dumps(secrets))
os.chmod("/app/config/secrets.json", stat.S_IRUSR | stat.S_IWUSR)  # 600
```

```bash
# 检测不安全的文件权限
rg -n "chmod.*777|makedirs.*0o?777|umask.*0{3}" --glob "*.{py,rb,sh,go,java}"
rg -n "os\.chmod|File\.setWritable|Files\.setPosixFilePermissions" --glob "*.{py,java,go}"
```

### 5.3 数据库/服务默认配置

```yaml
# 🔴 Docker Compose 默认配置
services:
  mysql:
    environment:
      MYSQL_ROOT_PASSWORD: root  # 🔴 默认密码
      MYSQL_ALLOW_EMPTY_PASSWORD: "yes"  # 🔴 允许空密码

  redis:
    # 🔴 无密码，无绑定限制
    ports:
      - "6379:6379"
```

```yaml
# 🟢 安全配置
services:
  mysql:
    environment:
      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_root_password
      MYSQL_ROOT_HOST: localhost  # 限制 root 登录源
    secrets:
      - mysql_root_password

  redis:
    command: redis-server --requirepass ${REDIS_PASSWORD} --bind 127.0.0.1
```

---

## 6. 多语言检测规则

### 6.1 通用检测正则

```bash
# 认证缺失检测
# 敏感路由无认证注解/中间件
admin|manage|config|setting|internal|private|secret

# 授权缺失检测
# 直接使用参数查询无所有权验证
findById\(.*\)|get\(.*id\)|filter\(id=|where.*id.*=

# 权限过大检测
root|admin.*password|chmod.*777|0o777|grant.*all

# 默认凭据检测
password.*[:=].*["'](admin|root|123456|password|test)|default.*password
```

### 6.2 语言专项补充

| 语言 | 认证检测 | 授权检测 | 权限检测 |
|------|----------|----------|----------|
| Java | `@PreAuthorize\|@Secured\|@RolesAllowed` | `.findById.*Principal\|SecurityContext` | `DataSource.*root` |
| Python | `Depends.*auth\|login_required\|@permission` | `current_user\|request\.user` | `os\.chmod\|makedirs.*mode` |
| JS/TS | `authMiddleware\|isAuthenticated\|passport` | `req\.user\|ctx\.state\.user` | `fs\.chmod\|mode:` |
| Go | `AuthRequired\|JWTMiddleware` | `c\.Get\("user"\)` | `os\.Chmod\|FileMode` |
| .NET | `\[Authorize\]\|\[AllowAnonymous\]` | `User\.Identity\|ClaimsPrincipal` | `FileSystemAccessRule` |
| Ruby | `before_action.*authenticate\|devise` | `current_user\|authorize!` | `File\.chmod\|FileUtils` |
| Rust | `#\[authorize\]\|AuthMiddleware` | `Identity\|Claims` | `std::fs::set_permissions` |

---

## 7. 框架专项检测

### 7.1 Spring Security

```java
// 检查 SecurityConfig
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()  // 🔴 审计: 是否过于宽松
            )
            .csrf(csrf -> csrf.disable());  // 🔴 审计: CSRF 禁用原因
        return http.build();
    }
}
```

### 7.2 Django

```python
# settings.py
AUTHENTICATION_BACKENDS = [...]
LOGIN_URL = '/login/'
SESSION_COOKIE_SECURE = True  # 检查是否启用
CSRF_COOKIE_SECURE = True

# views.py
from django.contrib.auth.decorators import login_required, permission_required

@login_required
@permission_required('app.can_edit', raise_exception=True)
def edit_view(request):
    pass
```

### 7.3 Express/NestJS

```typescript
// NestJS Guards
@Controller('admin')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles('admin')
export class AdminController {
    // 检查是否所有敏感端点都有 Guards
}

// Express middleware chain
app.use('/admin', authMiddleware, roleMiddleware('admin'), adminRouter);
```

---

## 8. 审计清单

### 认证 (CWE-287/306)
- [ ] 所有敏感接口是否需要认证
- [ ] 密码策略是否足够强
- [ ] 是否有暴力破解防护
- [ ] 登录后是否重新生成 Session ID
- [ ] 多因素认证是否可绕过

### 授权 (CWE-862/863)
- [ ] 是否存在 IDOR (水平越权)
- [ ] 是否存在垂直越权
- [ ] 资源所有权是否在后端验证
- [ ] 角色/权限检查是否在后端实现

### 权限管理 (CWE-269)
- [ ] 服务账号是否遵循最小权限
- [ ] API Token 权限是否过大
- [ ] 用户降级后权限是否清除

### 默认权限 (CWE-276)
- [ ] 是否存在默认管理员密码
- [ ] 文件/目录权限是否过于宽松
- [ ] 数据库/服务是否使用默认配置
