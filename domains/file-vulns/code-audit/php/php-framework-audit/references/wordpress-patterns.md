# WordPress 安全审计模式

## 插件与主题审计

WordPress 安全问题多数来自插件和主题，核心代码相对成熟。

**Action / Filter 钩子安全**:
- `add_action('wp_ajax_nopriv_*', $callback)` -- 未认证用户可触发的 AJAX 操作
- 审计所有 `wp_ajax_nopriv_` 钩子的回调函数，确认是否包含敏感操作
- `add_filter` 钩子中修改查询参数或输出内容时的注入风险
- `do_action` 动态钩子名: `do_action("plugin_{$action}")` 中 `$action` 可控

**Shortcode 回调注入**:
- `add_shortcode('tag', 'callback')` 中回调函数对 `$atts` 参数的处理
- Shortcode 属性值未转义直接输出到 HTML
- 嵌套 Shortcode 的解析顺序导致的注入

**插件生命周期**:
- `register_activation_hook` -- 插件激活时执行的代码
- `register_deactivation_hook` -- 插件停用时的清理是否完整
- 自动更新机制是否被篡改

## 数据库操作审计

**$wpdb 使用模式**:
- 危险: `$wpdb->query("DELETE FROM $table WHERE id = $id")`
- 安全: `$wpdb->query($wpdb->prepare("DELETE FROM $table WHERE id = %d", $id))`
- `$wpdb->prepare` 使用 `%s`(字符串)、`%d`(整数)、`%f`(浮点数) 占位符

**常见遗漏场景**:
- `$wpdb->get_results` / `get_row` / `get_var` 中直接拼接 SQL
- LIKE 查询: `$wpdb->prepare("... LIKE %s", '%' . $wpdb->esc_like($input) . '%')` 需双重处理
- `$wpdb->insert` / `update` / `delete` 方法本身安全，但自定义 SQL 需 prepare

**表名前缀**:
- 使用 `$wpdb->prefix` 而非硬编码 `wp_`
- 多站点环境下 `$wpdb->base_prefix` 与 `$wpdb->prefix` 的区别

## Nonce 验证审计

**表单提交**:
- 生成: `wp_nonce_field('action_name', 'nonce_field')`
- 验证: `wp_verify_nonce($_POST['nonce_field'], 'action_name')`
- 缺少 nonce 验证的表单处理函数存在 CSRF 风险

**AJAX 请求**:
- 前端: `ajax_object.nonce` 通过 `wp_localize_script` 传递
- 后端: `check_ajax_referer('action_name', 'nonce')` 验证
- `wp_ajax_` 回调中同时缺少 nonce 和 capability 检查为高危

**Nonce 生命周期**:
- 默认有效期 24 小时（两个 tick，各 12 小时）
- 自定义 nonce 生命周期: `nonce_life` filter
- Nonce 不等于认证 -- 已知 nonce 值的攻击者仍可在有效期内重放

## 权限检查审计

**current_user_can 调用完整性**:
- 所有管理操作入口必须调用 `current_user_can('capability')`
- 常用 capability: `manage_options`、`edit_posts`、`upload_files`、`delete_users`
- 自定义 capability 是否正确注册并分配给对应 role

**is_admin() 误用**:
- `is_admin()` 判断的是请求路径是否在管理后台，而非用户是否为管理员
- AJAX 请求 `is_admin()` 始终返回 true（因为走 `admin-ajax.php`）
- 正确判断管理员: `current_user_can('manage_options')`

**角色层级**:
- 默认角色: subscriber < contributor < author < editor < administrator
- 插件自定义角色的 capability 分配是否遵循最小权限原则
- `add_cap` / `remove_cap` 动态修改权限的调用点

## REST API 审计

**permission_callback 审计**:
- 危险: `'permission_callback' => '__return_true'` -- 任何人可访问
- 危险: 省略 `permission_callback` -- WordPress 5.5+ 会警告但仍执行
- 安全: `'permission_callback' => function() { return current_user_can('edit_posts'); }`

**参数验证**:
- `sanitize_callback` -- 输入清理回调，缺失则接收原始输入
- `validate_callback` -- 输入验证回调，返回 false 时请求被拒绝
- `args` 中每个参数应同时定义 sanitize 和 validate

**自定义端点风险**:
- `/wp-json/plugin/v1/` 命名空间下的自定义路由
- 批量操作端点中 ID 数组未验证导致的越权
- 文件操作端点缺少路径遍历防护

## 文件上传审计

**wp_handle_upload 配置**:
- `wp_handle_upload` 默认检查 MIME 类型和文件扩展名
- `upload_mimes` filter 可以添加或移除允许的 MIME 类型
- 插件通过 filter 添加 `.php`、`.svg` 等危险类型

**插件自定义上传**:
- 绕过 `wp_handle_upload` 直接使用 `move_uploaded_file` 的插件
- 上传目录: 非 `wp-content/uploads/` 的自定义路径是否有 Web 访问限制
- 文件名处理: `sanitize_file_name` 是否被调用，是否存在截断或双扩展名绕过

**SVG 上传风险**:
- SVG 文件本质是 XML，可嵌入 JavaScript 实现存储型 XSS
- 若允许 SVG 上传需确认是否经过 SVG Sanitizer 处理
- 检查 `upload_mimes` filter 中 `svg` / `svgz` 的添加
