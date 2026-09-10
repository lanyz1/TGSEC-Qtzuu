# 选吸增量片段（补现有 domains，不建平行伞）

## 组件联网情报节奏

识别框架/组件/版本后：**先联网情报再打**（对齐 `domains/recon/component-vuln-intel`）。  
序列：CVE 库 → 搜索引擎（含中文）→ 安全社区 → GitHub PoC → 资产引擎；结果一律 tentative，验证前不进高危报告。

## 源码狩猎增量

- `.git` dumper + 全历史敏感  
- 危险函数 / 硬编码密钥 grep  
- JS RC4+字符串数组解混淆流程  
- UniApp：`app-service.js` + 加密配置 + 插件清单  
- semgrep/CodeQL / trufflehog / patch diff / 依赖混淆与 CI 注入

摘录：
```
UniApp特征: app-service.js(业务逻辑,常800KB+混淆) + zlsioh.dat(加密配置,native .so解密) + dcloud_uniplugins.json(插件清单)
静态扫描: semgrep --config=auto 快扫 / CodeQL建库写query (taint求解+变体分析方法论见 `zero-day-discovery`)
Secrets深挖: trufflehog/gitleaks 扫git全历史+docker镜像层+npm/PyPI tarball+前端bundle(--only-verified区分死活密钥)
框架Patch Diff: clone前后版本 diff → 修了什么=漏洞在哪 | 依赖链: composer.json/npm audit/pip-audit
供应链/CI: 依赖混淆(内部包名抢注公共registry) | GHA命令注入${{github.event.issue.title}} | self-hosted runner接管 | .npmrc/.pypirc凭据
```

```

## Web 增量关注

- WebSocket/STOMP 客服会话存储型 XSS（agent 面板 innerHTML）链  
- CDN/反代/PATH_INFO/XFF 杂项绕过需实网验证，遵守 confirmation-gate

## AI/LLM 应用攻击面（交叉 llm-ai-security）

提示注入（直接/间接）· Agent 工具滥用 RCE · RAG 投毒 · MCP 供应链 · `torch.load` pickle RCE · 输出二次注入  

验证要看工具副作用（OOB/读文件），不是模型嘴上承认。


@TGSEC社区 · @TGSEC-Qtzuu 整理 · 2026-09-10
