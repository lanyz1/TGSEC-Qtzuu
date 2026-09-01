# ThinkPHP 安全审计模式

## 历史 RCE 模式

ThinkPHP 历史版本中存在多个高危 RCE 漏洞，审计时需首先确认框架版本。

**TP5.0.x RCE -- method 覆盖**:
- `Request::method()` 允许通过 `_method` 参数覆盖 HTTP 方法
- 攻击链: `_method=__construct` 配合 `filter` 参数实现任意函数调用
- 检查 `app/config.php` 中 `var_method` 配置是否仍为默认值

**TP5.1.x RCE -- 未过滤控制器名**:
- 路由未严格限制控制器名时，可通过 `\think\app/invokefunction` 调用任意方法
- 检查路由配置是否启用强制路由模式 `url_route_must`

**TP5.x Request 类链式调用**:
- `Request` 类 `__construct` 可通过请求参数覆盖内部属性
- `filter` 属性被覆盖后在 `input` 方法中作为回调执行

**版本确认方法**:
- `composer.lock` 中 `topthink/framework` 版本号
- `thinkphp/base.php` 或 `think/App.php` 中的 `VERSION` 常量

## 路由注入审计

**兼容模式风险**:
- `s=` 参数（PATH_INFO 兼容模式）直接映射到 `模块/控制器/方法`
- 未开启强制路由时，所有 public 方法均可通过 URL 直接访问
- 审计 `config/app.php` 中 `url_route_must` 和 `controller_suffix` 配置

**多应用模式绑定绕过**:
- `app_map` 配置不当允许访问未预期的应用模块
- `deny_app_list` 黑名单不完整导致管理模块暴露
- 自动多应用模式下通过 URL 切换应用绕过权限

**路由中间件缺失**:
- TP6 路由中间件需在路由定义中显式声明
- 全局中间件与路由中间件的执行顺序和覆盖关系
- `Route::group` 中间件是否覆盖了所有子路由

## 数据库注入审计

**where 条件注入**:
- `where` 方法接收数组时支持表达式: `['field', 'exp', Db::raw($input)]`
- `where($field, 'like', $input)` 中 `$input` 未过滤通配符
- `where($field, 'between', $input)` 中 `$input` 为数组时的注入

**聚合与排序注入**:
- `field($input)` / `order($input)` / `group($input)` 直接拼接
- `Db::raw()` 在查询构建器中的使用
- `buildSql` 子查询拼接

**批量操作风险**:
- `insertAll` / `saveAll` 中数组键名未过滤导致字段注入
- `where` 链式调用中混合字符串和数组条件

**安全写法对比**:
- 危险: `Db::query("SELECT * FROM user WHERE id = " . $id)`
- 安全: `Db::query("SELECT * FROM user WHERE id = ?", [$id])`
- 危险: `Db::name('user')->where($request->param())->find()`
- 安全: `Db::name('user')->where('id', $request->param('id'))->find()`

## 缓存文件写入

**漏洞原理**:
- TP5 文件缓存驱动将缓存内容序列化后写入 `runtime/cache/` 目录
- 缓存文件名基于 key 的 MD5 值，路径可预测
- 若缓存内容可控（如用户输入被缓存），可构造 PHP 代码写入

**审计步骤**:
1. 搜索 `Cache::set` / `cache()` 调用，追踪 value 参数来源
2. 确认缓存驱动类型: 文件驱动风险最高
3. 检查 `runtime/` 目录是否在 Web 可访问路径下
4. 确认缓存文件是否包含 PHP 执行防护（如 `<?php exit();` 前缀）

**利用条件**:
- 文件缓存驱动 + 缓存内容可控 + runtime 目录 Web 可达
- 绕过 `exit()` 前缀: 利用 php://filter 编码或换行截断

## 模板引擎注入

**think 模板危险标签**:
- `{php}code{/php}` -- 直接执行 PHP 代码（TP5 默认允许）
- `{:function($var)}` -- 变量函数调用，如 `{:system($cmd)}`
- 检查 `tpl_deny_php` 配置是否为 true（TP5.1+）
- 检查 `tpl_deny_func_list` 是否包含危险函数

**模板文件写入**:
- 若模板内容来自数据库或用户可编辑区域，存在 SSTI 风险
- CMS 类应用的模板编辑功能需重点关注

## 配置泄露审计

**.env 文件**:
- ThinkPHP 5.1+ 支持 `.env` 文件，存放于项目根目录
- 确认 Web Server 配置是否阻止对 `.env` 的直接访问
- `.env` 中通常包含数据库凭据、缓存密码、第三方 API Key

**runtime 目录**:
- `runtime/log/` -- 应用日志，可能包含 SQL 语句、用户数据、异常堆栈
- `runtime/cache/` -- 缓存文件
- `runtime/session/` -- Session 文件
- 确认 Web Server 是否阻止对 `runtime/` 目录的访问

**调试模式**:
- `app_debug` 配置或 `.env` 中 `APP_DEBUG = true`
- 调试模式暴露完整错误堆栈、SQL 查询、请求参数
- TP 调试面板 `app_trace` 配置
