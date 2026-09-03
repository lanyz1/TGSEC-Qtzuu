# tgsec-demoAI Skills 技能包 v3.0

自动化AI渗透测试框架（tgsec-demoAI）的Skills包 - **深度攻防专家版**。

By:Tas9er

## 概述

基于 Eino ADK 的 tgsec-demoAI 框架通过统一工具调用 `skill("name")` 按需加载技能定义。所有技能包放置于 `$SKILLS_ROOT` 目录（默认同级目录），子目录名即技能名。

**v3.0 核心升级**：全部 24 个核心技能已从 v2.0 深度优化至 **v3.0（资深攻防专家版）**，在保留原攻击面全覆盖的基础上，新增高级对抗章节、AI 大模型结合维度（AI 攻击面/AI 辅助攻防/AI 安全）、2025-2026 最新漏洞情报（CVE 速查/攻击原语/EDR 对抗），并新增内网渗透与 CI/CD 攻击两个专项技能。

## 快速开始

```bash
# 查看所有可用技能
curl http://localhost:8888/api/skills

# 查看技能摘要
curl http://localhost:8888/api/skills/sql-injection-testing?depth=summary

# 加载完整技能定义
curl http://localhost:8888/api/skills/sql-injection-testing?depth=full

# 访问技能包内脚本/资源
curl http://localhost:8888/api/skills/tgsec-demo-eino-demo/scripts/check-env.sh
```

## 技能目录

### 核心漏洞测试技能（v3.0 深度优化）

| 技能名称 | 目录 | 版本 | 描述 |
|---------|------|------|------|
| SQL注入测试 | `sql-injection-testing/` | 3.0.0 | **v3.0**：15章，数据库全指纹（MySQL/MSSQL/Oracle/PG/NoSQL）+ WAF分层绕过 + sqlmap Tamper矩阵 + CVE-2025-1094 PostgreSQL编码错配 + 数据库AI函数（P2SQL/Vector）注入面 + Gopher全协议利用链 |
| XSS测试 | `xss-testing/` | 3.0.0 | **v3.0**：15章，反射/存储/DOM/mXSS/vXSS/Blind/Universal全类型 + DOMPurify绕过谱系 + DOM Clobbering + 20+注入上下文 + CSP绕过 + Trusted Types对抗 + Service Worker持久化 + AI应用XSS |
| SSRF测试 | `ssrf-testing/` | 3.0.0 | **v3.0**：16章，全协议payload库 + IMDSv2八种绕过 + 防护绕过矩阵 + IP编码/DNS重绑定/302跳转 + 5大云厂商元数据 + Gopher Redis/FastCGI/MySQL RCE链 + AI基础设施SSRF |
| 命令注入测试 | `command-injection-testing/` | 3.0.0 | **v3.0**：16章，Windows/Linux全连接符 + 空格/关键字绕过 + 无字母数字RCE + 解释器注入面（PHP/Node/Python/Java沙箱）+ 供应链命令注入 + disable_functions绕过 + 反弹Shell矩阵 + 容器云逃逸 |
| XXE注入测试 | `xxe-injection-testing/` | 3.0.0 | **v3.0**：16章，8大解析器默认配置风险 + 防护绕过矩阵 + XInclude深度 + OOB Blind XXE + CDATA + SAML绕过 + SVG/OOXML + 2025-2026 十九项CVE速查（Tika CVE-2025-66516等） |
| 文件上传测试 | `file-upload-testing/` | 3.0.0 | **v3.0**：14+种WAF绕过策略（后缀/C-D头/MIME/解析漏洞/魔术字节等）+ Godzilla 6语言免杀WebShell + 图片马/竞争条件/云存储 + AI应用文件处理面 + 组合利用链 |
| CSRF测试 | `csrf-testing/` | 3.0.0 | **v3.0**：16章，GET/POST/JSON/Flash/SOAP CSRF + SameSite跨浏览器差异绕过 + Token绕过矩阵 + OAuth授权码CSRF + CORS+CSRF链 + Service Worker劫持 + AI应用CSRF |
| IDOR测试 | `idor-testing/` | 3.0.0 | **v3.0**：BOLA/BFLA全覆盖 + Mass Assignment批量赋值 + GraphQL IDOR + UUID/Hashid预测 + 多租户/关系链IDOR + 自动化BOLA检测方法论 + AI对象级越权 |
| API安全测试 | `api-security-testing/` | 3.0.0 | **v3.0**：OWASP API Top 10 2023 + REST/GraphQL/gRPC/WebSocket/SSE/BFF + JWT算法混淆矩阵 + OAuth2.0/OIDC深度攻击 + API网关绕过 + LLM/AI API与MCP攻击面 + Webhook签名绕过 |
| 业务逻辑漏洞测试 | `business-logic-testing/` | 3.0.0 | **v3.0**：16章，OWASP BLA Top 10 2025 + 0元支付/竞态条件（Turbo Intruder）/优惠券滥用/验证码绕过 + 状态机漏洞 + LLM应用业务逻辑漏洞 |
| LDAP注入测试 | `ldap-injection-testing/` | 3.0.0 | **v3.0**：14章，认证绕过 + 盲注提取 + 通配符滥用横向接管 + RBCD联动 + JNDI注入RCE + 多目录服务器差异 + 通道绑定绕过 |
| XPath注入测试 | `xpath-injection-testing/` | 3.0.0 | **v3.0**：16章，认证绕过/盲注 + XSLT RCE + XPath 3.1新特性攻击面 + XQuery注入 + SAML XSW攻击 + 带外数据外带 |
| 反序列化漏洞测试 | `deserialization-testing/` | 3.0.0 | **v3.0**：16章，Java CC/CB/Fastjson/Shiro/WebLogic/JNDI全链 + Gadget挖掘方法论 + JEP 290绕过（CVE-2026-47065）+ PHP POP链 + Python pickle + .NET ViewState + AI框架反序列化面（LangChain/vLLM） |
| Fastjson利用 | `fastjson-exploitation/` | 3.0.0 | **v3.0**：1.2.22-1.2.83+全版本段AutoType绕过（L前缀/双写/方括号/Class缓存/expectClass）+ JNDI/BCEL/TemplatesImpl完整利用链 + 不出网利用 + WAF绕过 + 内存马 |
| Shiro利用 | `shiro-exploitation/` | 3.0.0 | **v3.0**：15章，CBC/GCM双模式 + Key爆破字典 + Gadget链选择 + Shiro-550/721 + CVE-2023-46749/CVE-2026-56091 + NoCC链 + 无DNSLog验证法 + 内存马注入 + WAF绕过 |
| Spring Framework利用 | `spring-exploitation/` | 3.0.0 | **v3.0**：16章，Spring4Shell + SpEL注入全家族 + Actuator利用（heapdump→云RCE完整链）+ Spring Security绕过 + Spring AI CVE-2026-22738(SpEL RCE 9.8) + 内存马七类型 + WAF绕过 |
| Log4Shell利用 | `log4shell-exploitation/` | 3.0.0 | **v3.0**：16章，CVE-2021-44228全链路 + 全变体家族 + 现代JDK绕过矩阵（TrustURLCodebase/BeanFactory/本地Gadget）+ JDK21 trustSerialData对抗 + 不出网利用 + 内存马 + WAF绕过 |
| 网络渗透测试 | `network-penetration-testing/` | 3.0.0 | **v3.0**：16章，红队攻击链规划与ATT&CK TTP映射 + 目标建模决策树 + 高级外网打点（钓鱼联动/供应链/云资产）+ 隧道C2 + BloodHound CE v8图分析 + AD域渗透（Kerberoast/DCSync/ADCS ESC1-16/Certighost/委派滥用/混合身份Golden SAML）+ EDR对抗 + 攻击模拟自动化 |

### 基础设施/环境技能（v3.0 深度优化）

| 技能名称 | 目录 | 版本 | 描述 |
|---------|------|------|------|
| 信息收集 | `information-gathering/` | 3.0.0 | **v3.0**：18章，CT/DNS历史/暗网情报 + 8层OSINT+主动探测 + 子域名枚举 + JS敏感信息 + 云资产发现 + WAF/CDN指纹 + AI风险评分模型 + 自动化编排 |
| 内网渗透测试 | `intranet-penetration-testing/` | 1.0.0 | **新增**：内网深度渗透全链路（本地收集/凭证窃取/隧道/提权/横向/域渗透/维持/清痕/免杀C2）+ AI大模型内网攻击面（Ollama/vLLM/向量库/RAG/MCP/Agent）+ AI辅助红队作战 |
| CI/CD与开发平台攻击 | `ci-cd-attack-testing/` | 1.0.0 | **新增**：DevOps供应链攻击链（代码托管/Git对象深挖/Jenkins CVE-2024-23897/GitHub Actions注入/GitLab CVE-2023-7028/依赖混淆/镜像投毒/ArgoCD CVE-2024-37152/开发者终端）+ 典型案例复盘（tj-actions CVE-2025-30066）+ AI辅助CI/CD攻击 |
| 漏洞评估 | `vulnerability-assessment/` | 3.0.0 | **v3.0**：13章，CVSS 4.0深度 + EPSS+KEV+VPT融合风险优先级 + PoC开发原则 + 漏洞全生命周期管理 + AI辅助漏洞评估 |
| 云安全审计 | `cloud-security-audit/` | 3.0.0 | **v3.0**：16章，AWS/Azure/GCP/阿里云全平台 + IAM深度攻击（策略混淆代理/OIDC信任滥用）+ 元数据SSRF（IMDSv2绕过）+ K8s攻击面 + Serverless + LLMjacking |
| 容器安全测试 | `container-security-testing/` | 3.0.0 | **v3.0**：17章，镜像供应链攻击 + runc三连CVE + 8+种容器逃逸（特权/Docker Socket/PID/CAP/nodes/proxy WebSocket提权）+ eBPF攻击面 + K8s渗透 + 云原生AI攻击面 |
| 移动应用测试 | `mobile-app-security-testing/` | 3.0.0 | **v3.0**：17章，Android/iOS双平台 + Frida对抗 + 脱壳对抗 + SSL Pinning绕过 + WebView安全 + 组件导出审计 + 跨平台框架漏洞 + 移动AI攻击面 |
| 安全代码审查 | `secure-code-review/` | 3.0.0 | **v3.0**：14章，6种语言漏洞模式 + 攻击面驱动审计方法论 + Source-Sink数据流追踪 + AI代码幻觉7大失效模式 + 供应链代码审计（Flooding Dropper 850+恶意包） |
| 应急响应 | `incident-response/` | 3.0.0 | **v3.0**：16章，NIST 800-61r3 + 事件分级矩阵 + Win/Linux取证 + Volatility 3内存分析 + 勒索软件专项 + 云容器事件响应 + 大模型安全事件响应 + MITRE ATT&CK重建 |
| 安全自动化 | `security-automation/` | 3.0.0 | **v3.0**：16章，DevSecOps全流程（SAST/DAST/SCA/IaC）+ SOAR深度 + Agentic AI安全自动化 + OPA策略即代码 + CIS Benchmark自动化 + 与tgsec-demo-eino-demo联动 |
| 安全意识培训 | `security-awareness-training/` | 3.0.0 | **v3.0**：14章，AI时代社工威胁升级 + 社会工程学攻防矩阵 + Evilginx2全链路仿真演练 + 钓鱼演练设计与评估 + Kirkpatrick四层评估 + OWASP Top 10安全编码培训 |

### 示例/模板技能

| 技能名称 | 目录 | 描述 |
|---------|------|------|
| Eino集成示例 | `tgsec-demo-eino-demo/` | 框架集成示例，包含checklist/脚本/参考文档/配置文件等完整结构 |

## 技能包结构

每个技能包遵循统一目录结构：

```
skill-name/
├── SKILL.md              # 必需：YAML Front Matter + Markdown正文
├── scripts/              # 可选：可执行脚本/payload/工具
├── references/           # 可选：参考文档
├── assets/               # 可选：静态资源
├── FORMS.md              # 可选：检查清单表格
└── REFERENCE.md          # 可选：API参考
```

### SKILL.md Front Matter 规范

```yaml
---
name: skill-name                    # 必需：与目录名完全一致
description: 技能描述（运行时列表展示）
version: 3.0.0                      # 可选：语义化版本号
---
```

## 开发指南

创建新技能或扩展现有技能：

1. 创建与 `name` 字段完全相同的子目录
2. 编写 `SKILL.md`，必需YAML Front Matter（name/description）
3. 使用标准Markdown编写方法论、Payload、工具命令
4. 复杂技能可添加 `scripts/` 目录存放可执行脚本/payload
5. 使用 ` ```bash ` 等fenced code block标注命令示例
6. 添加 `- [ ]` checkbox格式测试清单
7. 重启服务或刷新skills目录生效

### 技能开发原则

- **完整攻击面**：覆盖参数位置、协议、编码、所有注入点
- **WAF绕过层次化**：从编码→注释→空白符→关键字→语法→协议→语义逐层绕过
- **分版本定制**：针对数据库/中间件版本提供差异化Payload
- **工具可执行**：所有命令/Payload均可直接复制执行
- **高级利用链**：从探测→绕过→利用→数据外带→RCE/提权完整链路
- **AI大模型结合**：每个技能包含AI攻击面（LLM/Agent/MCP）或AI辅助攻防维度
- **最新情报**：融入2025-2026年最新CVE/攻击原语/工具链
- **合规声明**：每个技能末尾包含"注意事项"，强调授权测试要求

## 参考规范

Skills 包格式兼容 [agentskills.io 规范](https://agentskills.io/specification.md)，支持渐进加载、分块传输和按需资源访问。

## v3.0 优化亮点

### 批量深度优化（24个技能 v2.0 → v3.0）
- **结构升级**：每技能 13-18 章 + 注意事项，统一"概述→分章节→工具链→检查清单→修复建议→注意事项"范式
- **最新漏洞情报**：融入 2025-2026 高危 CVE（CVE-2025-1094 PG编码错配、Tika CVE-2025-66516、Spring AI CVE-2026-22738、JEP 290绕过 CVE-2026-47065、Shiro CVE-2026-56091、ADCS Certighost CVE-2026-54121、NTLM Reflection CVE-2025-33073等）
- **AI大模型维度**：AI攻击面（LLM/Agent/MCP/向量库/RAG）、AI辅助攻防（自动化编排/免杀增强/报告生成）、AI安全（幻觉失效模式/提示注入防御）
- **EDR对抗深化**：LOTL/无文件/内存执行、进程注入对抗、免杀C2、检测规避矩阵

### SQL注入（v3.0）
- CVE-2025-1094：PostgreSQL `_advance` 编码错配 SQLi 利用链
- NoSQL注入：`$ne`/`$regex`/`$where`/原型污染变体
- 数据库AI函数注入面：MSSQL OPENJSON/VECTOR_DISTANCE、Oracle 23ai AI_SQL_GENERATE、P2SQL语义函数
- 7级绕过层级模型 + sqlmap Tamper 70+组合矩阵

### 文件上传（v3.0）
- 14种WAF绕过策略完整分类
- Godzilla 6语言免杀WebShell完整连接参数
- 图片马/竞争条件/云存储/解析漏洞组合利用链
- AI应用文件处理攻击面（文件解析RCE/沙箱逃逸）

### SSRF（v3.0）
- IMDSv2 八种绕过方式（PUT跳转/X-Forwarded-For/云厂商差异等）
- SSRF防护绕过矩阵（DNS重绑定/302/协议降级/URL解析差异）
- Gopher全协议Payload库（Redis/FastCGI/MySQL/Memcached/SMTP）
- AI基础设施SSRF（模型API代理/向量库/推理服务）

### XSS（v3.0）
- DOMPurify 历史绕过谱系（mXSS/配置绕过/nodename）
- DOM Clobbering 高级变体（form/iframe/原型链）
- Service Worker 持久化 XSS + 缓存投毒
- AI应用XSS（LLM渲染输出/RAG内容投毒）

### 反序列化（v3.0）
- Gadget挖掘方法论（ObjectInputStream分析/链拼接）
- JEP 290 绕过（CVE-2026-47065）：多种反序列化过滤器绕过
- AI框架反序列化面：LangChain/vLLM/向量库 pickle 加载

### Spring（v3.0）
- heapdump → 云RCE 完整利用链（云凭证提取/AccessKey滥用）
- Spring AI CVE-2026-22738 SpEL RCE 利用细节
- 内存马七类型（Filter/Servlet/Controller/WebSocket/Listener/Agent/字节码）

### 网络渗透（v3.0）
- 红队攻击链10阶段 + MITRE ATT&CK TTP映射表
- BloodHound CE v8 OpenGraph 分析 + 核心Cypher查询
- ADCS ESC1-ESC16 全谱 + Certighost
- 混合身份攻击：Golden SAML / Entra Connect同步账户滥用

### 内网渗透（v1.0 新增）
- 内网全链路：本地收集/凭证窃取(mimikatz/LSASS/ntds.dit)/隐藏隧道(frp/Chisel/DNS/ICMP)/提权/横向/AD域渗透/维持/清痕/免杀C2
- AI大模型内网攻击面：Ollama(11434)/vLLM(8000)/向量库(Milvus/Qdrant)/MCP tools调用/RAG投毒/Agent滥用
- AI辅助红队作战：攻击路径分析/免杀增强/自动化编排

### CI/CD攻击（v1.0 新增）
- DevOps供应链攻击链：代码托管→CI系统→制品仓库→CD发布→云六层信任链
- Jenkins CVE-2024-23897(Groovy CLI任意文件读→RCE)、GitLab CVE-2023-7028(密码重置)、ArgoCD CVE-2024-37152、tj-actions CVE-2025-30066(secrets内存窃取)
- 依赖混淆攻击（Alex Birsan手法）+ 镜像投毒 + 开发者终端攻击
- AI辅助CI/CD攻击：代码审计/投毒生成/供应链情报

### 其他Skills v3.0增强亮点
- **应急响应**：NIST 800-61r3、Volatility 3深度、勒索软件专项、云容器事件响应、大模型安全事件响应
- **代码审计**：攻击面驱动方法论、AI幻觉7大失效模式、Flooding Dropper 850+恶意包供应链审计
- **移动安全**：Frida对抗、脱壳对抗、跨平台框架漏洞、移动AI攻击面
- **安全自动化**：SOAR深度、Agentic AI安全自动化、与Eino框架联动
- **安全意识**：AI时代社工威胁、Evilginx2仿真演练、Kirkpatrick四层评估
- **漏洞评估**：CVSS 4.0、EPSS+KEV+VPT融合
- **容器安全**：runc三连CVE、eBPF攻击面、云原生AI攻击面
- **云安全**：IAM策略混淆代理、OIDC信任滥用、LLMjacking

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
