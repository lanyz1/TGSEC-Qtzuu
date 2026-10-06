# ai_bobao — 关键事实（源: README / README.en）

- 流水线：RSS 源 → crawler → analyzer → store → translate；每轮先增量同步上游 nuclei-templates，再跑文章流水线，最后按 keep_days 清理过期条目；抓取与模板同步各自加锁，避免手动触发与定时任务（默认间隔 10 分钟）互撞
- LLM 配置：llm.base（OpenAI 兼容端点，不含 /v1）、llm.key、llm.model（默认 gpt-4o-mini）、llm.timeout；未配置 Key 时 AI 功能不可用；配置可被环境变量覆盖（前缀 AI_BAOBAO_）
- nuclei 双向通道：POST /api/vulns/{id}/nuclei 生成 nuclei v3 模板（allow_write 默认 false → 只读探测模板）；GET /api/nuclei/remote?limit=&severity= 预览上游、POST /api/nuclei/pull 拉取入库；模板汇总在 data/nuclei_tpl/，可直接 `nuclei -l` 执行
- 自助接入新源：POST /api/sources/discover 按 /feed、/rss、/rss.xml、/atom.xml 等常见路径探测 feed 并由 AI 判活；AI 不可用时退化为标题关键词匹配；JS 渲染站点探测不到，需手动找到 RSS 地址
- 存储：backend/data/vulns/{ID}/（meta.json + poc.py + nuclei.yaml）、nuclei_tpl/、nuclei_sync.json、nuclei_cache/；config.yaml 含明文密钥，已列入 .gitignore
- 控制面 API：/api/vulns（列表/详情/PoC 重生成/翻译）、/api/collect（手动抓取）、/api/translate/backfill（批量翻译）、/api/settings（读写配置，Key 脱敏）、/api/settings/test（LLM 连通性）、/api/sources CRUD
- 注意：源仓库 README.md 存在 3 处原文截断标记（`[...]`），本卡按原样保留

@TGSEC社区 · @TGSEC-Qtzuu 整理
