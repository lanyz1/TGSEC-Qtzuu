# 证据合约系统

## 为什么需要证据合约

AI 进行源码审计时容易"看到危险函数就报漏洞"，忽略上游过滤、参数可控性、路径可达性，导致大量误报。证据合约系统强制要求每个漏洞结论附带完整数据流证明。

**核心原则**: 没有从 Source 到 Sink 的完整证据链，就不能将漏洞标记为"已确认可利用"。

## EVID_* 命名规则

格式: `EVID_{漏洞类型}_{证据维度}`。漏洞类型用大写缩写（SQL、CMD、XSS 等），证据维度描述该点证明的内容（EXEC_POINT=执行点、USER_PARAM=用户参数来源）。

## 各漏洞类型证据点定义

### SQL 注入（SQL）
| 证据点 | 含义 |
|--------|------|
| `EVID_SQL_EXEC_POINT` | SQL 语句的实际执行位置（类:方法:行号 + 调用链） |
| `EVID_SQL_STRING_CONSTRUCTION` | SQL 字符串的拼接/构造方式（字符串拼接 vs PreparedStatement vs MyBatis #{} vs ${}） |
| `EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT` | 用户输入进入 SQL 片段的完整路径（Controller 参数 → Service → DAO） |

### 命令注入（CMD）
| 证据点 | 含义 |
|--------|------|
| `EVID_CMD_EXEC_POINT` | 命令执行调用的位置（Runtime.exec / ProcessBuilder.start） |
| `EVID_CMD_COMMAND_STRING_CONSTRUCTION` | 命令字符串/参数数组的拼接方式 |
| `EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT` | 用户输入进入命令参数的路径 |

### SSRF
| 证据点 | 含义 |
|--------|------|
| `EVID_SSRF_URL_NORMALIZATION` | URL 的规范化/解析过程（是否经过 URL 类解析、是否存在重定向跟随） |
| `EVID_SSRF_FINAL_URL_HOST_PORT` | 最终请求的目标主机和端口 |
| `EVID_SSRF_DNSIP_AND_INNER_BLOCK` | DNS 解析结果及内网地址限制检查 |

### 文件操作（FILE）
| 证据点 | 含义 |
|--------|------|
| `EVID_FILE_WRAPPER_PREFIX` | 协议/路径前缀（file://、classpath:、jar: 等） |
| `EVID_FILE_RESOLVED_TARGET` | 最终解析的文件路径（经过 Path.normalize / canonicalize 后） |
| `EVID_FILE_PATH_TRAVERSAL_CHECK` | 路径穿越防护检查（是否过滤 `../`、是否校验 canonical path） |

### 文件上传（UPLOAD）
| 证据点 | 含义 |
|--------|------|
| `EVID_UPLOAD_DESTPATH` | 上传文件的存储目标路径 |
| `EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE` | 文件名和扩展名的解析与过滤逻辑（白名单/黑名单、Content-Type 校验） |
| `EVID_UPLOAD_ACCESSIBILITY_PROOF` | 上传文件是否可被 Web 直接访问执行（静态资源映射、Servlet 容器解析规则） |

### XSS
| 证据点 | 含义 |
|--------|------|
| `EVID_XSS_OUTPUT_POINT` | 输出到 HTML 的位置和上下文（JSP / Thymeleaf / FreeMarker 模板位置） |
| `EVID_XSS_USER_INPUT_INTO_OUTPUT` | 用户输入到达输出点的路径 |
| `EVID_XSS_ESCAPE_OR_RAW_CONTROL` | 转义/编码处理或 raw 输出控制（`<c:out>` vs `<%= %>`、`th:text` vs `th:utext`） |

### 反序列化（DESER）
| 证据点 | 含义 |
|--------|------|
| `EVID_DESER_CALLSITE` | 反序列化函数的调用位置（ObjectInputStream.readObject / JSON.parseObject / ObjectMapper.readValue） |
| `EVID_DESER_INPUT_SOURCE` | 反序列化数据的来源（HTTP body / RMI / JMX / MQ 消息） |
| `EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN` | 反序列化目标类型、魔术方法触发（readObject / readResolve / finalize）及可用 Gadget Chain |

### XXE
| 证据点 | 含义 |
|--------|------|
| `EVID_XXE_PARSER_CALL` | XML 解析器的调用位置和类型（DocumentBuilderFactory / SAXParser / XMLInputFactory） |
| `EVID_XXE_INPUT_SOURCE` | XML 数据的输入来源（用户上传 / API 请求体 / 配置文件） |
| `EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO` | 外部实体/DTD 加载配置状态及解析结果是否回显 |

### 认证授权（AUTH）
| 证据点 | 含义 |
|--------|------|
| `EVID_AUTH_PATH_PROTECTED_MATCH` | 路由与安全规则的匹配关系（antMatchers 规则、Shiro URL 配置） |
| `EVID_AUTH_TOKEN_DECODE_JUDGMENT` | Token/Session 的解码与校验逻辑（JWT 签名验证、Session 固定检查） |
| `EVID_AUTH_PERMISSION_CHECK_EXEC` | 权限校验的实际执行（`@PreAuthorize` / `hasRole` / 自定义注解是否生效） |

### 表达式注入（EXPR）
| 证据点 | 含义 |
|--------|------|
| `EVID_EXPR_EVAL_ENTRY` | 表达式引擎的调用入口（SpEL ExpressionParser / OGNL ValueStack / EL ELProcessor） |
| `EVID_EXPR_EXPR_CONTROL` | 用户输入对表达式内容的控制程度（完全可控 / 部分拼接 / 仅参数） |
| `EVID_EXPR_EXEC_CHAIN_ENTRY` | 表达式执行到危险操作（Runtime.exec / ClassLoader）的调用链 |

### 其他类型简表
| 类型 | 证据点 |
|------|--------|
| 重定向 (REDIR) | `EVID_REDIR_TARGET_URL`, `EVID_REDIR_USER_INPUT_INTO_URL`, `EVID_REDIR_VALIDATION_CHECK` |
| CSRF | `EVID_CSRF_STATE_CHANGE_ACTION`, `EVID_CSRF_TOKEN_ABSENCE`, `EVID_CSRF_IMPACT_SCOPE` |
| LDAP | `EVID_LDAP_QUERY_CALL`, `EVID_LDAP_FILTER_CONSTRUCTION`, `EVID_LDAP_USER_INPUT_INTO_FILTER` |

## 证据状态定义

| 标记 | 状态 | 含义 |
|------|------|------|
| ✅ | 已确认可利用 | Source→Sink 完整路径已追踪，过滤不充分或可绕过 |
| ⚠️ | 待验证 | 部分证据缺失（如无法确认过滤是否可绕过、反射调用打断追踪等） |
| 🔍 | 环境依赖 | 利用条件取决于运行环境（JDK 版本、容器配置、依赖版本） |

## 证据引用格式示例

完整 SQL 注入证据引用样例:
```
漏洞: SQL 注入 | 文件: com.example.dao.UserDAO | 严重度: High (Score: 2.55)

[EVID_SQL_EXEC_POINT]
  位置: UserDAO.java:87 | 调用: jdbcTemplate.query(sql, ...)

[EVID_SQL_STRING_CONSTRUCTION]
  位置: UserDAO.java:85-86
  代码: String sql = "SELECT * FROM users WHERE id = '" + id + "'"
  方式: 字符串直接拼接，未使用 PreparedStatement

[EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT]
  Source: UserController.java:23 — @RequestParam("id") String id
  传递: UserController.getUser(id) → UserService.findById(id) → UserDAO.queryById(id) → sql 拼接
  过滤: 无 | 结论: 用户输入直接拼入 SQL，可利用
```

## 证据缺失处理规则

| 缺失情况 | 处理方式 | 标记状态 |
|----------|----------|----------|
| Sink 存在但无法追溯 Source | 记录 Sink 位置，标注数据来源不明 | ⚠️ 待验证 |
| Source→Sink 路径中有反射/动态代理 | 记录已知部分，标注断点位置和反射目标 | ⚠️ 待验证 |
| 存在过滤但无法确认可否绕过 | 记录过滤逻辑，列出潜在绕过思路 | ⚠️ 待验证 |
| 完整路径已追踪且过滤不充分 | 提供全部 EVID_* 证据 | ✅ 已确认 |
| 完整路径已追踪且过滤充分 | 记录过滤方式，说明安全原因 | 安全 |

关键原则: "待验证"比"误报为已确认"的代价低得多。不确定时保守标记。

## Java 特有: trace 不可用时的降级策略

当仅有 .class 文件、无法获得完整源码时，允许以下降级:
- 反编译产物（CFR / Procyon）可替代源码作为证据来源，但须标注"反编译还原"
- 反编译丢失的局部变量名不影响数据流追踪，以参数位置（arg0, arg1）替代
- Lambda 表达式和内部类反编译可能失真，此类路径上的证据降级为 ⚠️ 待验证
- 若关键 Sink 位于第三方 JAR 且无法反编译（混淆/加密），记录 JAR 名称和方法签名，标记为 🔍 环境依赖

## 严重度评分公式

### 三维度评分

**可达性 R（Reachability, 0-3）**:
- 0 = 需管理员权限 + 特定配置才可触发
- 1 = 需普通用户认证后访问
- 2 = 未认证但需特定条件（特定 Content-Type、非默认路径）
- 3 = 未认证直接可达（公开接口、默认路径）

**影响范围 I（Impact, 0-3）**:
- 0 = 非敏感信息泄露（版本号、路径）
- 1 = 敏感信息泄露（配置文件、数据库凭据、用户数据）
- 2 = 数据篡改 / 部分系统控制（SQL 写入、任意文件写入受限目录）
- 3 = RCE / 完全系统控制（命令执行、反序列化 Gadget Chain）

**利用复杂度 C（Complexity, 0-3, 反向评分 — 越容易利用分越高）**:
- 0 = 需多步组合 + 竞态条件
- 1 = 需特定环境/版本 + 多步操作
- 2 = 简单构造 payload 即可利用
- 3 = 直接拼接 payload，无需额外条件

### 计算与映射

**加权公式**: `Score = R * 0.40 + I * 0.35 + C * 0.25`

**CVSS 3.1 近似映射**: `CVSS ≈ Score / 3.0 * 10.0`

| Score 范围 | CVSS 近似 | 等级 |
|-----------|-----------|------|
| 2.50 - 3.00 | 8.3 - 10.0 | Critical |
| 2.00 - 2.49 | 6.7 - 8.3 | High |
| 1.50 - 1.99 | 5.0 - 6.6 | Medium |
| < 1.50 | < 5.0 | Low |
