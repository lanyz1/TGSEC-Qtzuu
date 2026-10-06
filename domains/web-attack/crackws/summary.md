# Summary

- Product: `crackws`
- Topic: `crackws — WebSocket 渗透桥`
- Path: `/root/security-suite/domains/web-attack/crackws`
- Source: `guaidao2/crackws`
- Notes: 把 WebSocket 桥接成本地 HTTP，让 sqlmap/Burp/curl/nuclei 这些只会说 HTTP 的工具直接打 WebSocket；Go 单二进制、无第三方运行时依赖（仅编译期 yaml.v3），另带 recon/注入检测/fuzz/replay/REPL。
- Ingest: `2026-10-06b`
