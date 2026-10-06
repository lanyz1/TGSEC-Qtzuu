# Summary

- Product: `ai_bobao`
- Topic: `ai_bobao — AI 漏洞播报系统`
- Path: `/root/security-suite/domains/vuln-intel/ai_bobao-feed`
- Source: `wr0x00/ai_bobao`
- Notes: Python 3.11 + FastAPI + Vue3/Vite：多源聚合（Seebug/先知/Exploit-DB RSS）→ LLM 结构化（名称/简介/原理/攻击范围），缺失 PoC 时按公开思路自动补写 Python PoC → 可导出 nuclei v3 模板并支持上游 nuclei-templates 增量同步；文件式存储（无数据库依赖）
- Ingest: `2026-10-06b`
