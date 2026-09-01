# Laravel 安全审计模式

## Mass Assignment 审计

检查所有 Eloquent Model 的属性保护配置。

**高危模式**:
- `Model::create($request->all())` 或 `Model::update($request->all())` -- 未经过滤的请求数据直接赋值
- `$guarded = []` -- 空 guarded 数组等于全部字段可批量赋值
- `$fillable` 包含敏感字段如 `is_admin`、`role`、`balance`、`password`

**审计步骤**:
1. 全局搜索 `$request->all()` / `$request->input()` 传入 `create` / `update` / `fill` 的调用
2. 检查对应 Model 的 `$fillable` 和 `$guarded` 定义
3. 比对数据库 migration 中的实际字段，确认是否有敏感字段未受保护
4. 关注 `forceFill` / `forceCreate` -- 直接绕过 guarded 机制

## Blade XSS 审计

Laravel Blade 默认使用 `{{ }}` 进行 HTML 实体转义，`{!! !!}` 输出原始 HTML。

**搜索目标**:
- `{!! $variable !!}` -- 所有未转义输出，逐一确认数据来源是否可控
- `@php echo $var; @endphp` -- 内联 PHP 绕过模板转义
- 自定义 Blade Directive 中使用 `$expression` 未包裹 `e()` 函数
- `Js::from()` / `@json` 在 `<script>` 上下文中的使用是否正确

**风险场景**:
- 富文本内容渲染使用 `{!! $post->content !!}` 但存储时未过滤
- URL 参数通过 `{!! request('callback') !!}` 直接输出

## CSRF 例外审计

**检查 VerifyCsrfToken 中间件**:
- 定位 `app/Http/Middleware/VerifyCsrfToken.php`
- 审计 `$except` 数组中列出的路由，确认是否包含状态变更操作
- Webhook 接收路由排除 CSRF 合理，但需确认有替代验证（签名校验等）

**API 路由风险**:
- `routes/api.php` 默认不加载 `VerifyCsrfToken`，若同时使用 Session 认证则存在 CSRF 风险
- Sanctum SPA 认证场景需确认 CORS 配置 + Referer 验证

## Eloquent 注入审计

Eloquent ORM 参数化查询默认安全，但 Raw 表达式引入注入面。

**危险方法清单**:
- `whereRaw($sql)` -- 第一参数拼接用户输入
- `havingRaw($sql)` / `orderByRaw($sql)` / `groupByRaw($sql)`
- `DB::raw($expr)` 嵌入 `select` / `where` / `join`
- `DB::select(DB::raw("SELECT ... WHERE id = $id"))`

**审计方法**:
1. 搜索所有 `Raw` 后缀方法和 `DB::raw` 调用
2. 追踪第一参数中是否包含 `$request` / `$_GET` / `$_POST` 来源的变量
3. 确认是否使用了绑定参数: `whereRaw('price > ?', [$price])` 为安全写法

## 认证与授权审计

**Guard 配置**:
- `config/auth.php` -- 检查 guards / providers / passwords 配置
- 自定义 Guard 实现中 `validate` / `user` 方法的安全性
- 多 Guard 场景下路由是否指定了正确的 guard

**Policy / Gate**:
- 控制器中 `$this->authorize('action', $model)` 调用覆盖率
- Policy 类中 `before` 方法是否有短路逻辑（如 admin 跳过所有检查）
- `Gate::define` 闭包中权限判断逻辑是否可被绕过

**Token 管理**:
- Sanctum: `personalAccessTokens` 表 token 是否设置了 abilities 限制和过期时间
- Passport: OAuth scope 配置、token 生命周期、refresh token 轮换

## 调试与配置泄露

**APP_DEBUG 残留**:
- `.env` 中 `APP_DEBUG=true` 在生产环境暴露完整堆栈和环境变量
- 错误页面 Ignition 可能触发 RCE（CVE-2021-3129）

**.env 文件可达**:
- Web 根目录为 `public/`，但配置错误可能导致 `.env` 直接可下载
- 搜索 `.env.backup` / `.env.example` 中残留真实凭据

**调试工具路由**:
- `/_debugbar` -- Laravel Debugbar 默认路由
- `/telescope` -- Laravel Telescope 面板，暴露请求/SQL/日志
- 确认生产环境是否通过 `APP_ENV=production` 自动禁用

## 队列与事件审计

**Job 反序列化**:
- 队列 Job 类的 `handle` 方法接收的参数是否来自不可信来源
- Redis / Database 队列驱动中 payload 被篡改可触发反序列化链
- `SerializesModels` trait 会序列化 Model 标识符，重新获取时需注意权限

**Event 触发链**:
- `Event::dispatch` 传播链中是否有 Listener 执行敏感操作而缺乏独立鉴权
- Broadcast Event 是否泄露了不应公开的 Model 属性（检查 `broadcastWith`）
- Model Observer 中 `creating` / `updating` 事件回调是否引入副作用

## 文件与存储审计

**文件上传**:
- `$request->file()->store()` 是否验证了 MIME 类型和扩展名
- `Storage::disk('public')` 存储的文件是否可直接 Web 访问执行
- 文件名是否使用 `hashName()` 防止路径遍历和覆盖

**路径遍历**:
- `Storage::get($userInput)` / `Storage::download($userInput)` 未过滤 `../`
- `response()->file($path)` 中 `$path` 来源是否可控
