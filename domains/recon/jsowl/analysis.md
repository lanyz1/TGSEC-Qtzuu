# JsOwl — 关键事实（源: README + docs/）

- 双引擎匹配：规则经 regexp2（.NET 风格 NFA）编译，支持前瞻/后顾、反向引用、命名组，单次匹配限时 2 秒——灾难性回溯只截断该规则自身、不会挂死扫描；AST 用 Tree-sitter（构建必须启用 CGO）
- 规则加载优先级：`rules_file`（显式指定）> `config/rules.yml`（项目级，改后立即生效）> `~/.jsowl/rules.yaml`（用户级，首次运行播种）> 内嵌默认值；每条 HaE 规则 ID 形如 `hae.<组名>.<规则名>`，可在 `disabled` 中引用关闭
- 三种采集模式：direct（高速 HTTP）/ browser（Rod 驱动本地 Chrome 渲染）/ auto（默认，先 direct，按 SPA 信号自动升级浏览器）
- 登录态扫描（--login）：打开可见浏览器人工登录后整批目标串行扫描；强制 browser 模式、非 headless、目标并发 1，浏览器周期重启并自动迁移会话 Cookie（等待最长 5 分钟）
- 报告不脱敏：JSON / HTML / 纯文本均保留完整敏感值；`api绝对路径.txt`、`url.txt` 等纯清单可直接喂给 Burp、fuzz 工具或爬虫
- AI 辅助（--ai）：参数完整性与真实性复核、未知污点来源推断、敏感发现价值评级；支持 openai-chat / openai-responses / anthropic-messages / gemini-native 四种接口，请求上限由 max_requests 控制
- 生态：规则格式来自 HaE，浏览器自动化 Rod，AST 为 Tree-sitter，自动填表算法适配自 projectdiscovery/katana（MIT）

@TGSEC社区 · @TGSEC-Qtzuu 整理
