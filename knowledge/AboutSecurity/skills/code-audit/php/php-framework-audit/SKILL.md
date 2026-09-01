---
name: php-framework-audit
description: |
  PHP 框架特定安全审计。当在 PHP 白盒审计中已识别目标使用特定框架、
  需要检查框架特有安全机制和常见配置缺陷时触发。
  覆盖 6 大框架: Laravel(Mass Assignment/Blade XSS/CSRF 例外)、
  ThinkPHP(RCE 历史漏洞/路由注入/缓存写入)、WordPress(插件漏洞/权限钩子/nonce 验证)、
  Symfony(Debug Bar/YAML 解析/安全投票器)、Yii2(RBAC/ActiveRecord 注入)、CodeIgniter(全局 XSS/CSRF Token)。
metadata:
  tags: laravel, thinkphp, wordpress, symfony, yii, codeigniter, 框架审计, mass assignment, blade xss, wp plugin, think rce
  category: code-audit
---

# PHP 框架特定安全审计
## 框架识别决策表

| 识别特征 | 框架 | 深入参考 |
|---|---|---|
| `composer.json` → `laravel/framework` | Laravel | [references/laravel-patterns.md](references/laravel-patterns.md) |
| `composer.json` → `topthink/framework` | ThinkPHP | [references/thinkphp-patterns.md](references/thinkphp-patterns.md) |
| 存在 `wp-content/` 目录或 `wp-config.php` | WordPress | [references/wordpress-patterns.md](references/wordpress-patterns.md) |
| `composer.json` → `symfony/framework-bundle` | Symfony | 本文简要覆盖 |
| `composer.json` → `yiisoft/yii2` | Yii2 | 本文简要覆盖 |
| `composer.json` → `codeigniter4/framework` | CodeIgniter | 本文简要覆盖 |

## Laravel 核心检查点

1. **Mass Assignment** -- `$fillable` / `$guarded` 是否正确配置，`Model::create($request->all())` 或 `update($request->all())` 是否存在未过滤字段
2. **Blade XSS** -- 搜索 `{!! !!}` 未转义输出、`@php` 指令内直接 echo、自定义 Blade Directive 未调用 `e()`
3. **CSRF 例外** -- `VerifyCsrfToken` 中间件 `$except` 数组是否包含敏感路由，API 路由组默认不含 CSRF 中间件
4. **Gate / Policy** -- 控制器方法是否调用 `$this->authorize()` 或 `Gate::allows()`，Policy 定义是否覆盖所有 CRUD
5. **Eloquent Raw** -- `whereRaw` / `havingRaw` / `orderByRaw` / `DB::raw` 中是否存在变量拼接
6. **签名 URL / 调试** -- `APP_DEBUG=true` 残留、`.env` Web 可达、Telescope / Debugbar 路由暴露

## ThinkPHP 核心检查点

1. **历史 RCE 路由** -- TP5.x `method()` 覆盖、`Request` 类 `__construct` 任意方法调用
2. **缓存文件写入** -- 缓存文件路径可预测 + 内容可控 → 写入 WebShell
3. **数据库 where 注入** -- `where` 数组条件中 `exp` / `like` / `between` 表达式注入、`Db::raw`
4. **Session 反序列化** -- TP6 session 序列化驱动可能触发 POP 链
5. **模板注入** -- `{php}` 标签、变量函数 `{:system()}`

## WordPress 核心检查点

1. **插件 action/filter** -- `wp_ajax_nopriv_*` 钩子暴露未认证操作、Shortcode 回调参数注入
2. **$wpdb->prepare 缺失** -- 直接拼接 SQL 到 `$wpdb->query()`
3. **nonce 验证** -- 表单处理 / AJAX handler 缺少 `wp_verify_nonce` / `check_admin_referer`
4. **REST API** -- `register_rest_route` 的 `permission_callback` 是否为 `__return_true` 或缺失
5. **文件上传** -- 插件自定义上传逻辑绕过 `wp_handle_upload` 的 MIME 检查

## Symfony 简要概述

- **Debug 模式** -- `APP_DEBUG=1` 泄露 Profiler / Web Debug Toolbar，暴露环境变量和 SQL
- **YAML 反序列化** -- 低版本 `Yaml::parse` 支持 `!!php/object` 标签导致对象注入
- **Security Voter** -- 自定义 Voter 逻辑缺陷或 `ACCESS_ABSTAIN` 误用导致越权

## Yii2 简要概述

- **RBAC 配置** -- `DbManager` 权限项分配不当、`checkAccess` 调用缺失导致垂直越权
- **ActiveRecord 注入** -- `findBySql` / `where` 条件字符串拼接、`orderBy` 未过滤

## CodeIgniter 简要概述

- **全局 XSS 过滤** -- CI3 `$config['global_xss_filtering']` 已弃用，CI4 需手动调用 `esc()`
- **CSRF Token** -- 配置 `CSRFProtection` 但排除路由过多、Token 重生策略不当

## 深入参考

- [Laravel 审计模式](references/laravel-patterns.md)
- [ThinkPHP 审计模式](references/thinkphp-patterns.md)
- [WordPress 审计模式](references/wordpress-patterns.md)
