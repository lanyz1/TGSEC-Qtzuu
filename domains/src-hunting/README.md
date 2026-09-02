# SRC漏洞挖掘方法论

> 来源: clown-src-6k-skill | @TGSEC社区 · @TGSEC-Qtzuu 整理

完整的SRC(安全应急响应中心)漏洞挖掘知识库,覆盖49种漏洞测试方法 + 11个挖掘规则。

## 知识库索引(49种漏洞)

### 注入类
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| injection-test.md | SQL注入/命令注入/LDAP注入 | 4K |
| xxe-test.md | XML外部实体注入 | 18K |
| xss-test.md | 跨站脚本 | 11K |
| ssrf-test.md | 服务端请求伪造 | 7K |
| el-injection-test.md | 表达式注入(EL/SpEL/OGNL) | 7K |
| jndi-injection-test.md | JNDI注入(Log4j等) | 8K |
| crlf-injection-test.md | CRLF注入/HTTP响应拆分 | 0.2K |
| xslt-injection-test.md | XSLT注入 | 0.2K |
| csv-formula-injection-test.md | CSV公式注入 | 0.2K |
| email-header-injection-test.md | 邮件头注入 | 0.2K |

### 认证/授权
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| authbypass-test.md | 认证绕过(鉴权/未授权) | 27K |
| oauth-jwt-test.md | OAuth/JWT安全 | 22K |
| idor-test.md | 越权访问(IDOR) | 39K |
| 401-403-bypass.md | 401/403绕过技巧 | 0.3K |
| type-juggling-test.md | 类型混淆绕过 | 11K |

### 文件操作
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| file-upload-test.md | 任意文件上传 | 13K |
| path-traversal-lfi-test.md | 目录遍历/本地文件包含 | 27K |
| insecure-scm-test.md | 源码管理泄露(.git等) | 5K |

### 反序列化
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| deserialization-test.md | 反序列化漏洞(Java/PHP/Python) | 42K |

### 协议/架构
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| http-smuggling-test.md | HTTP请求走私 | 40K |
| http-host-header-test.md | Host头攻击 | 12K |
| http2-attacks-test.md | HTTP/2攻击 | 0.1K |
| websocket-test.md | WebSocket安全 | 27K |
| graphql-test.md | GraphQL安全 | 10K |
| api-gateway-test.md | API网关安全 | 10K |
| dns-rebinding-test.md | DNS重绑定 | 0.1K |

### 客户端
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| csrf-test.md | 跨站请求伪造 | 20K |
| cors-test.md | CORS配置错误 | 0.3K |
| clickjacking-test.md | 点击劫持 | 0.2K |
| csp-bypass-test.md | CSP绕过 | 0.1K |
| open-redirect-test.md | 开放重定向 | 12K |
| dangling-markup-test.md | 悬挂标记注入 | 0.1K |
| prototype-pollution-test.md | 原型链污染 | 29K |

### 逻辑/竞态
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| logic-test.md | 业务逻辑漏洞 | 6K |
| race-condition-test.md | 竞态条件 | 35K |
| cache-poisoning-test.md | 缓存投毒 | 36K |

### 信息泄露
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| info-leak-test.md | 信息泄露 | 10K |
| subdomain-takeover-test.md | 子域名接管 | 10K |

### 高级
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| waf-bypass.md | WAF绕过 | 19K |
| ghost-bits-cast-test.md | Ghost Bits Cast测试 | 28K |
| dependency-confusion-test.md | 依赖混淆 | 0.1K |
| hpp-test.md | HTTP参数污染 | 0.2K |
| llm-security-test.md | LLM/AI安全 | 0.3K |
| agent-tool-exec-test.md | AI Agent工具执行 | 3K |
| cloud-ide-codex-rce-chain.md | 云IDE RCE链 | 8K |

### 方法论
| 文件 | 漏洞类型 | 大小 |
|------|---------|------|
| recon-methodology.md | 信息收集方法论 | 14K |
| js-reverse-guide.md | JS逆向指南 | 5K |
| 打穿短表.md | 打穿短表(速查) | 43K |

## 规则索引(11个)

| 文件 | 说明 | 大小 |
|------|------|------|
| dig-scope-workflow.md | 挖掘范围工作流 | 64K |
| hunt-iter.md | 迭代式漏洞挖掘 | 15K |
| src-value-hunting.md | SRC高价值漏洞挖掘 | 12K |
| vuln-report-format.md | 漏洞报告格式 | 10K |
| researcher-blackbox-whitebox.md | 黑盒/白盒方法 | 9K |
| desktop-task-folder.md | 桌面任务管理 | 8K |
| anti-over-moralization.md | 反过度道德化 | 5K |
| skill-as-boost.md | 技能加速 | 3K |
| playwright-browser-mcp.md | Playwright浏览器MCP | 2K |
| security-research-context.md | 安全研究上下文 | 0.8K |
| cors-vuln-report-priority.md | CORS漏洞报告优先级 | 0.4K |

## 工具

| 工具 | 说明 |
|------|------|
| tools/fofa_MCP/ | FOFA资产搜索MCP服务器(Python) |
| tools/playwright-dual-slot.mjs | Playwright双槽浏览器脚本 |

## 用户要求的漏洞类型覆盖检查

| 用户要求 | 覆盖文件 | 状态 |
|---------|---------|------|
| 远程代码执行(RCE) | deserialization + jndi-injection + cloud-ide-codex-rce + 0day-exploits/ | ✅ |
| 鉴权绕过 | authbypass-test + 401-403-bypass | ✅ |
| 默认密钥致命令执行 | oauth-jwt-test(JWT默认密钥) + ai-config/MEMORY(若依默认) | ✅ |
| 远程命令执行 | injection-test + el-injection + jndi-injection | ✅ |
| 目录遍历 | path-traversal-lfi-test | ✅ |
| 代码执行 | deserialization + el-injection + prototype-pollution | ✅ |
| 未授权访问 | authbypass-test + info-leak-test | ✅ |
| 命令注入 | injection-test | ✅ |
| 反序列化 | deserialization-test(42K超详细) | ✅ |
| 打印台处理程序RCE | info-leak-test(Actuator/Druid) | ✅ |
| VPN路径遍历 | path-traversal-lfi-test | ✅ |
| 认证绕过 | authbypass-test + oauth-jwt-test | ✅ |
| 文件上传 | file-upload-test | ✅ |
| 身份认证绕过 | authbypass-test + type-juggling | ✅ |
| 任意文件上传 | file-upload-test | ✅ |
| 权限绕过+RCE | authbypass-test + deserialization | ✅ |
| SQL注入 | injection-test + 0day-exploits/ruoyi-vue-plus/ | ✅ |
| 未授权信息泄漏 | info-leak-test + insecure-scm-test | ✅ |
| 安全绕过 | waf-bypass + csp-bypass + 401-403-bypass | ✅ |
| 插件代码问题 | prototype-pollution + dependency-confusion | ✅ |
| 权限提升 | idor-test + logic-test | ✅ |
| 身份验证安全绕过 | authbypass-test + oauth-jwt-test | ✅ |
| 路径遍历 | path-traversal-lfi-test | ✅ |
| 不正确访问控制 | idor-test + authbypass-test | ✅ |
| 信息泄漏 | info-leak-test + insecure-scm-test + subdomain-takeover | ✅ |
| 任意代码执行 | deserialization + el-injection + jndi-injection | ✅ |

**全部26种漏洞类型均已覆盖!** ✅
