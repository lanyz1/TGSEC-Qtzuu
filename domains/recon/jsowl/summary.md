# Summary

- Product: `jsowl`
- Topic: `JsOwl — JS 信息收集与敏感信息扫描器`
- Path: `/root/security-suite/domains/recon/jsowl`
- Source: `yumulijiang/jsowl`
- Notes: Go 1.25+ 编写（JS AST 依赖 CGO）：正则（regexp2）+ Tree-sitter AST 双引擎，兼容 HaE 规则格式，提取 API/参数/路由与敏感信息；direct/browser/auto 三种采集模式，支持 --login 登录态扫描与 MCP Server；输出 JSON + 自包含交互式 HTML 报告（不脱敏）
- Ingest: `2026-10-06b`
