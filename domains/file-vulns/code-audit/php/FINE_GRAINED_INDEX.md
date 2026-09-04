# PHP 细粒度白盒审计索引

来源：细粒度 PHP 审计 skill 包（路由映射 / tracer / 分类审计 / 框架专项）。

使用顺序：
1. `php-route-mapper` → `php-route-tracer`
2. `php-audit-pipeline`
3. 按漏洞类：`php-sql-audit` / `php-xss-audit` / `php-ssrf-audit` / `php-deser-audit` / `php-file-*-audit` …
4. 框架：`php-laravel-audit` / `php-thinkphp-audit` / `php-wordpress-audit` / `php-symfony-audit` / `php-yii-audit` / `php-codeigniter-audit`
5. 证据契约与链路：`php-exploit-chain-audit` / `shared/`

已有聚合层（`php-injection-audit` 等）保留；细粒度 skill 补全分类深度。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
