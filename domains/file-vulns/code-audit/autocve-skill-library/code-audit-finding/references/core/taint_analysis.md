# Taint Analysis Module

> 污点分析核心模块 - 用于追踪用户可控数据从输入到危险函数的完整路径

## 专项详细规则

| 漏洞类型 | 详细规则文件 | Sink 示例 |
|----------|--------------|-----------|
| 反序列化 Gadget | `languages/java_gadget_chains.md` | readObject, parseObject |
| JNDI 注入 | `languages/java_jndi_injection.md` | InitialContext.lookup |
| XXE | `languages/java_xxe.md` | DocumentBuilder.parse |
| Fastjson | `languages/java_fastjson.md` | JSON.parseObject |
| 通用 Sink/Source | `core/sinks_sources.md` | 完整规则库 |

## Overview

污点分析是代码审计的核心方法论，通过追踪不可信数据(污点)从进入系统到触发危险操作的完整流程，精确定位安全漏洞。

```
┌─────────────────────────────────────────────────────────────────┐
│                      Taint Analysis Flow                        │
│                                                                 │
│   Source ──→ Propagation ──→ Sanitizer? ──→ Sink               │
│   (污点源)    (传播路径)      (净化检查)     (汇聚点)            │
│                                                                 │
│   用户输入    变量赋值         过滤/转义      危险函数            │
│              函数参数          验证/编码      执行操作            │
│              返回值            白名单                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Taint Analysis Report Template

### 标准报告格式

```markdown
## [严重程度] 漏洞类型 - 文件名:行号

### 基本信息
| 属性 | 值 |
|------|-----|
| 漏洞类型 | SQL注入 / XSS / RCE / SSRF / ... |
| 严重程度 | Critical / High / Medium / Low |
| CWE编号 | CWE-89 / CWE-79 / CWE-78 / ... |
| 文件位置 | path/to/file.ext:行号 |
| 函数名称 | function_name() |

---

### Source (污点源)

**位置**: `file.ext:行号`

**类型**: [HTTP参数 / Cookie / Header / 文件读取 / 数据库 / 环境变量]

**代码**:
\`\`\`language
// 污点引入点代码
\`\`\`

**说明**: 描述为什么此处是污点源，数据如何进入系统

---

### Taint Propagation (污点传播路径)

\`\`\`
[步骤1] file.ext:行号
        代码: variable = source_input
        操作: 污点引入
        ↓
[步骤2] file.ext:行号
        代码: processed = transform(variable)
        操作: 污点传递 (未净化)
        ↓
[步骤3] file.ext:行号
        代码: result = build_query(processed)
        操作: 污点拼接
        ↓
[步骤4] file.ext:行号
        代码: execute(result)
        操作: 污点到达Sink
\`\`\`

**传播链摘要**:
- 总跨度: X 行代码 / X 个函数 / X 个文件
- 中间变量: var1 → var2 → var3 → sink参数
- 跨函数调用: funcA() → funcB() → funcC()

---

### Sink (汇聚点)

**位置**: `file.ext:行号`

**类型**: [SQL执行 / 命令执行 / 文件操作 / 网络请求 / 模板渲染 / 反序列化]

**代码**:
\`\`\`language
// 危险操作代码
\`\`\`

**危害**:
- 攻击者可实现: [具体危害描述]
- 影响范围: [数据泄露/服务器控制/用户影响]

---

### Taint Analysis (污点分析结论)

| 分析项 | 结果 |
|--------|------|
| 污点源可控性 | 完全可控 / 部分可控 / 需特定条件 |
| 存在净化措施 | 无 / 有但可绕过 / 有效净化 |
| 绕过可能性 | 高 / 中 / 低 |
| 利用复杂度 | 简单 / 中等 / 复杂 |
| 需要认证 | 是 / 否 |

**净化检查**:
- [ ] 输入验证: 无 / 白名单 / 黑名单 / 正则
- [ ] 编码转义: 无 / HTML实体 / URL编码 / SQL参数化
- [ ] 类型转换: 无 / 强制类型 / 长度限制

**攻击向量**:
\`\`\`
示例payload或攻击路径
\`\`\`

---

### PoC (概念验证)

**前置条件**: 描述利用需要的条件

**利用步骤**:
1. 步骤一
2. 步骤二
3. 步骤三

**Payload**:
\`\`\`
具体的攻击payload
\`\`\`

**预期结果**: 描述攻击成功后的现象

---

### 修复建议

**推荐方案**:
\`\`\`language
// 安全代码示例
\`\`\`

**替代方案**: 其他可行的修复方式

**修复原则**:
1. 原则一
2. 原则二

---

### 参考资料
- CWE: https://cwe.mitre.org/data/definitions/XXX.html
- OWASP: 相关链接
```

---

## Tracking Strategy (追踪策略)

### 函数级 vs 变量级追踪

> 参考: JavaSinkTracer 的设计理念

| 策略 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| **变量级追踪** | 精确、能识别净化点 | 易断链(反射/线程/回调) | 简单数据流 |
| **函数级追踪** | 稳定、不易断链 | 可能有误报 | 复杂调用关系 |

**推荐策略**: 先用函数级追踪建立调用链，再用变量级验证污点传播

### BFS反向追溯算法

```
算法: Sink到Source的广度优先搜索

输入: sink_method, call_graph, max_depth
输出: 所有到达Source的调用链

procedure TRACE_BACK(sink_method):
    queue = [(sink_method, [sink_method], 0)]  // (当前方法, 路径, 深度)
    visited = set()
    results = []

    while queue not empty:
        current, path, depth = queue.pop(0)

        if current in visited or depth > max_depth:
            continue
        visited.add(current)

        // 检查是否到达Source (外部入口点)
        if is_source_method(current):
            results.append(path)
            continue

        // 获取所有调用当前方法的caller
        for caller in get_callers(current, call_graph):
            // 过滤无参方法 (无法接收污点)
            if not has_parameters(caller):
                continue
            queue.append((caller, path + [caller], depth + 1))

    return results
```

---

## LSP-Enhanced Tracking (LSP增强追踪)

> v2.4.0 新增 - 利用语言服务协议实现精确的代码跳转和引用分析

### 为什么使用 LSP 而不是 Grep？

| 方法 | 搜索 `sanitize` | 结果 |
|------|-----------------|------|
| **Grep** | `grep "sanitize"` | 匹配字符串、注释、变量名 (噪音大) |
| **LSP** | `findReferences(sanitize)` | **仅返回实际代码引用** (精确) |

**核心优势**:
- **语义级分析**: 区分函数调用 vs 字符串匹配
- **跨文件追踪**: 自动解析 import/include 关系
- **多态感知**: 找到接口的所有实现类
- **调用链分析**: 获取完整的调用者/被调用者关系

### LSP 操作与审计场景映射

| LSP 操作 | 审计场景 | 使用示例 |
|----------|----------|----------|
| `goToDefinition` | **污点溯源** | 追踪变量来自哪里 |
| `findReferences` | **影响面分析** | 危险函数被哪些地方调用 |
| `goToImplementation` | **多态穿透** | 接口背后的实际实现 |
| `incomingCalls` | **攻击面映射** | 谁调用了 `executeQuery()` |
| `outgoingCalls` | **污点传播** | 该函数又调用了什么 |
| `documentSymbol` | **入口点枚举** | Controller 的所有方法 |
| `workspaceSymbol` | **全局搜索** | 找所有 `*Handler` 类 |

### 实战工作流：追踪 SQL 注入

```
场景: 发现 executeQuery(sql) 调用，追踪 sql 变量来源

Step 1: 定位 Sink
└─ 使用 Grep 找到: UserDao.java:45 - stmt.executeQuery(sql)

Step 2: LSP 变量溯源
└─ LSP goToDefinition(sql) → 跳转到 sql 变量定义
   └─ 发现: sql = buildQuery(userId) at line 42

Step 3: LSP 函数追踪
└─ LSP goToDefinition(buildQuery) → 跳转到函数定义
   └─ 发现: buildQuery() 在 QueryHelper.java:20

Step 4: LSP 调用链分析
└─ LSP incomingCalls(executeQuery) → 找到所有调用者
   └─ 发现 5 个调用点，2 个来自 Controller 层 (HTTP入口)

Step 5: 确认攻击路径
└─ Controller → Service → DAO → executeQuery()
└─ userId 来自 @RequestParam → 确认为 Source
```

### LSP 命令参考

```python
# 污点溯源 - 追踪变量定义
LSP goToDefinition(filePath, line, character)
# 返回: 变量/函数的定义位置

# 影响面分析 - 谁使用了这个符号
LSP findReferences(filePath, line, character)
# 返回: 所有引用位置列表

# 多态分析 - 接口的实现
LSP goToImplementation(filePath, line, character)
# 返回: 接口/抽象方法的所有实现

# 调用链 - 谁调用了这个函数
LSP incomingCalls(filePath, line, character)
# 返回: 所有调用当前函数的位置

# 污点传播 - 这个函数调用了什么
LSP outgoingCalls(filePath, line, character)
# 返回: 当前函数调用的所有函数

# 入口点枚举 - 列出文件中的所有符号
LSP documentSymbol(filePath, line, character)
# 返回: 类、方法、变量等符号列表

# 全局搜索 - 按名称搜索符号
LSP workspaceSymbol(filePath, line, character)
# 返回: 工作区内匹配的符号
```

### 常见审计模式

#### 模式 1: 危险函数调用点枚举

```
目标: 找到所有 Runtime.exec() 调用

1. Grep 快速定位一个调用点
2. LSP goToDefinition 跳转到 exec() 定义
3. LSP findReferences 获取所有调用点
4. 对每个调用点进行污点分析
```

#### 模式 2: 数据验证函数有效性

```
目标: 验证 sanitize() 是否被正确调用

1. LSP findReferences(sanitize) 找到所有调用点
2. 对比 LSP findReferences(dangerousSink) 的调用点
3. 检查是否每个 Sink 调用前都有 sanitize
```

#### 模式 3: 接口实现全覆盖

```
目标: 审计 UserService 接口的所有实现

1. LSP goToImplementation(UserService.getUser)
2. 返回: UserServiceImpl, AdminUserService, CacheUserService
3. 对每个实现进行独立审计 (可能有不同的漏洞)
```

### LSP 与 Grep 协同策略

```
┌─────────────────────────────────────────────────────────────┐
│                    审计追踪策略                              │
│                                                             │
│  Phase 1: Grep 广度搜索                                     │
│  ├─ 快速发现潜在危险点                                       │
│  └─ 适用于: 初始侦察、模式匹配                               │
│                                                             │
│  Phase 2: LSP 深度分析                                       │
│  ├─ 精确追踪数据流                                          │
│  ├─ 分析调用关系                                            │
│  └─ 适用于: 验证漏洞、追踪污点                               │
│                                                             │
│  原则: Grep 找广度，LSP 求深度                               │
└─────────────────────────────────────────────────────────────┘
```

### 注意事项

1. **LSP 需要语言服务器支持**: 确保目标语言的 LSP 服务器已配置
2. **行号从 1 开始**: LSP 使用 1-based 行号和列号
3. **异步等待**: 大型项目中 LSP 操作可能需要时间
4. **回退策略**: LSP 不可用时，使用 Grep + Read 组合

---

## Sink Slot Type Classification (Slot 类型分类)

> 借鉴自 Shannon 渗透测试工具的精细化分析方法

### 为什么需要 Slot 分类？

不同的 sink 位置需要不同的防护措施。**常见误区是认为"参数绑定可以防止所有 SQL 注入"**，
但参数绑定只能保护**值位置**，不能保护**标识符位置**。

### SQL Sink Slot 类型

| Slot Type | 代码特征 | 正确防护 | 无效防护 |
|-----------|----------|----------|----------|
| **SQL-val** | `WHERE col = ?` | 参数绑定 | - |
| **SQL-like** | `WHERE col LIKE ?` | 参数绑定 + 转义 `%_` | 仅参数绑定 |
| **SQL-num** | `LIMIT ?`, `OFFSET ?` | parseInt/类型转换 | 字符串绑定 |
| **SQL-enum** | `ORDER BY status` (固定值) | 白名单验证 | 参数绑定 |
| **SQL-ident** | `ORDER BY ${col}` (动态列名) | **白名单** | 参数绑定无效! |
| **SQL-table** | `FROM ${table}` (动态表名) | **白名单** | 参数绑定无效! |

### Command Injection Slot 类型

| Slot Type | 代码特征 | 正确防护 | 无效防护 |
|-----------|----------|----------|----------|
| **CMD-argument** | `cmd [arg1] [arg2]` | shell=False + 数组传参 | 黑名单过滤 |
| **CMD-part-of-string** | `"cmd ${input}"` | shlex.quote() / 白名单 | 简单转义 |

### File Operation Slot 类型

| Slot Type | 代码特征 | 正确防护 | 无效防护 |
|-----------|----------|----------|----------|
| **FILE-path** | 文件路径拼接 | resolve() + 边界检查 | `../` 黑名单 |
| **FILE-include** | 动态文件包含 | 白名单路径 | 协议过滤 |

### Template Slot 类型

| Slot Type | 代码特征 | 正确防护 | 无效防护 |
|-----------|----------|----------|----------|
| **TEMPLATE-content** | 模板内容渲染 | autoescape | - |
| **TEMPLATE-expr** | 模板表达式 `{{}}` | 沙箱 + 禁止危险方法 | 简单过滤 |

### Deserialization Slot 类型

| Slot Type | 代码特征 | 正确防护 | 无效防护 |
|-----------|----------|----------|----------|
| **DESERIALIZE-object** | 反序列化入口 | 可信来源 + HMAC 签名 | 类型黑名单 |

### 审计时的 Slot 检查流程

```
1. 识别 Sink 点
2. 确定 Slot 类型 (val/ident/argument/path/...)
3. 检查实际使用的防护措施
4. 验证防护措施是否匹配 Slot 类型
5. 不匹配 → 报告潜在漏洞
```

### 示例：SQL-ident Slot 漏洞

```java
// ❌ 危险: 参数绑定不能保护 ORDER BY 的列名
String col = request.getParameter("sort");
String sql = "SELECT * FROM users ORDER BY " + col;  // SQL-ident slot
PreparedStatement ps = conn.prepareStatement(sql);   // 参数绑定无法保护此处!

// ✅ 安全: 使用白名单
String col = request.getParameter("sort");
List<String> allowed = Arrays.asList("name", "created_at", "id");
if (!allowed.contains(col)) {
    col = "id";  // 默认安全值
}
String sql = "SELECT * FROM users ORDER BY " + col;
```

---

## Post-Sanitization Concat Detection (净化后拼接检测)

> 关键规则: 如果 concat 发生在 sanitization 之后，该净化措施可能无效

### 反模式定义

"净化后拼接"是指：数据经过净化函数处理后，在到达 sink 之前又与其他**未净化数据**拼接，
或者净化后的数据被重新拼接到危险上下文中。

### 检测流程

```
1. 定位 sanitizer 调用: escape(), htmlspecialchars(), parameterize()
2. 标记净化后的变量为 "sanitized"
3. 追踪该变量到 sink 的路径
4. 检查路径上是否有字符串拼接操作
5. 若拼接引入了未净化数据 → 报告漏洞
6. 若净化后数据拼接到不匹配的上下文 → 报告漏洞
```

### 危险模式示例

**模式 1: 净化后与未净化数据拼接**
```python
# user_id 被净化，但 table 未净化
user_id = escape_sql(request.args.get('id'))     # sanitized
table = request.args.get('table')                 # NOT sanitized!
query = f"SELECT * FROM {table} WHERE id = {user_id}"  # 危险!
```

**模式 2: 部分参数净化**
```python
name = escape_sql(request.form['name'])           # sanitized
sort = request.form['sort']                       # NOT sanitized!
query = f"SELECT * FROM users WHERE name = '{name}' ORDER BY {sort}"  # 危险!
```

**模式 3: 净化上下文不匹配**
```python
# HTML 转义后用于 JavaScript 上下文
user_input = html_escape(request.args.get('data'))  # HTML sanitized
script = f"<script>var data = '{user_input}';</script>"  # JS 上下文, HTML 转义无效!
```

**模式 4: 净化结果被二次处理**
```python
data = escape_sql(user_input)                     # sanitized
data = data.replace("'", "")                      # 后续处理可能破坏净化
query = f"SELECT * FROM users WHERE name = '{data}'"
```

### 审计检查点

- [ ] 追踪**所有**到达 sink 的变量，不仅仅是用户输入
- [ ] 检查每个拼接操作是否引入新的未净化数据
- [ ] 验证净化函数与 sink 上下文是否匹配
- [ ] 检查净化后是否有破坏性的二次处理
- [ ] 特别关注动态构建的 SQL/命令/模板字符串

### 报告格式

```yaml
vulnerability:
  type: "Post-Sanitization Concat"
  source: "request.args.get('table') @ app.py:10"
  sanitizer:
    location: "app.py:12"
    function: "escape_sql()"
    target: "user_id"
  post_sanitization_concat:
    location: "app.py:15"
    operation: "f-string concatenation"
    unsanitized_data: "table"
  sink:
    location: "app.py:16"
    function: "cursor.execute()"
  verdict: "vulnerable"
  reason: "未净化的 table 变量与净化后的 user_id 拼接进入 SQL 执行"
```

---

## Source & Sink Quick Reference

> 完整的 Source/Sink 定义请参考: `references/core/sinks_sources.md`

### 常见 Source (污点源)

| 语言 | 主要污点源 |
|------|-----------|
| Java | `request.getParameter()`, `@RequestParam`, `@RequestBody` |
| Python | `request.args`, `request.form`, `request.json` |
| Go | `r.URL.Query()`, `c.Query()`, `c.PostForm()` |
| PHP | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` |
| Node.js | `req.query`, `req.body`, `req.params` |

### 危险 Sink 分类

| 类型 | 严重程度 | 典型函数 |
|------|----------|----------|
| RCE | Critical | `exec()`, `system()`, `eval()` |
| 反序列化 | Critical | `readObject()`, `pickle.loads()`, `unserialize()` |
| SQL注入 | Critical | `executeQuery()`, `cursor.execute()`, `db.Query()` |
| SSRF | High | `URL.openConnection()`, `requests.get()`, `http.Get()` |
| XXE | High | `DocumentBuilder.parse()`, `SAXParser.parse()` |
| 路径遍历 | High | `new File()`, `open()`, `os.Open()` |
| XSS | Medium | `response.write()`, `echo`, `template.HTML()` |

### 快速查询正则

```regex
# 通用危险函数
exec|system|eval|popen|shell_exec|passthru

# 反序列化
ObjectInputStream|pickle\.load|unserialize|Yaml\.load|JSON\.parse

# SQL
execute|executeQuery|createQuery|db\.Query|cursor\.execute

# 文件操作
FileInputStream|FileOutputStream|file_get_contents|open\(|os\.Open
```

---

## Automated Taint Tracking (自动化污点追踪)

### 追踪算法

```
输入: 漏洞位置 (file:line)
输出: 完整污点分析报告

算法步骤:
1. 定位Sink
   - 读取指定行代码
   - 识别危险函数调用
   - 提取涉及的变量

2. 反向追踪 (Backward Tracking)
   - 从Sink变量开始
   - 逐行向上查找变量定义/赋值
   - 识别函数调用，进入函数体继续追踪
   - 记录每个传播节点

3. 识别Source
   - 追踪直到找到外部输入
   - 标记Source类型和位置

4. 正向验证 (Forward Validation)
   - 从Source开始正向遍历
   - 确认传播路径完整性
   - 检查是否存在净化操作

5. 生成报告
   - 整理Source/Sink/Propagation
   - 分析净化情况
   - 评估利用可能性
```

### 追踪操作指南

#### Step 1: 定位Sink点

```
给定: file.java:70 存在漏洞

操作:
1. Read file.java 获取第70行上下文
2. 识别危险函数: stmt.executeQuery(query)
3. 提取Sink变量: query
4. 记录Sink信息
```

#### Step 2: 反向数据流追踪

```
追踪变量: query

操作:
1. 在当前函数内向上搜索 query 的定义
2. 找到: String query = "SELECT * FROM users WHERE id=" + param (line 67)
3. 新增追踪变量: param
4. 继续向上搜索 param 的定义
5. 找到: String param = userId.trim() (line 52)
6. 新增追踪变量: userId
7. 继续向上搜索 userId 的定义
8. 找到: String userId = request.getParameter("id") (line 45)
9. 识别为Source: HTTP参数
```

#### Step 3: 跨函数追踪

```
场景: 变量来自函数调用

操作:
1. 识别函数调用: result = processInput(userInput)
2. 定位函数定义: processInput() in utils.java:120
3. 分析函数参数和返回值
4. 在函数体内继续追踪
5. 如果返回值包含污点，标记为传播
```

#### Step 4: 净化检查

```
在传播路径上检查:

1. 输入验证
   - 白名单验证: if (!allowed.contains(input)) return;
   - 正则匹配: if (!input.matches("^[a-zA-Z0-9]+$")) return;
   - 类型转换: int id = Integer.parseInt(input);

2. 编码/转义
   - HTML: StringEscapeUtils.escapeHtml4(input)
   - SQL: PreparedStatement 参数化
   - 命令: ProcessBuilder (非shell模式)
   - URL: URLEncoder.encode(input)

3. 安全API替换
   - 原生SQL → ORM参数化查询
   - Runtime.exec → ProcessBuilder
   - String拼接 → StringBuilder + 验证
```

### 工具辅助

#### 使用Grep追踪

```bash
# 查找变量定义
grep -n "variableName\s*=" file.ext

# 查找变量使用
grep -n "variableName" file.ext

# 查找函数定义
grep -n "def functionName\|function functionName\|func functionName" *.ext

# 查找函数调用
grep -rn "functionName(" --include="*.ext"
```

#### 使用LSP追踪

```
操作:
1. goToDefinition: 跳转到变量/函数定义
2. findReferences: 查找所有引用位置
3. hover: 获取类型信息
4. incomingCalls: 查找调用者
5. outgoingCalls: 查找被调用函数
```

---

## Function Context Analysis (函数上下文分析)

> 借鉴自 DeepAudit RAG 系统的 retrieve_function_context() 方法

### 概述

函数上下文分析是污点追踪的重要补充，通过分析函数的调用者(callers)和被调用者(callees)，
建立完整的调用关系图，识别污点传播的完整路径。

### 函数上下文追踪流程

```
┌─────────────────────────────────────────────────────────────────┐
│                  Function Context Analysis                       │
│                                                                 │
│   Step 1: 定位目标函数                                           │
│   ├─ 确定函数名称和所在文件                                       │
│   └─ 读取函数定义和签名                                          │
│                                                                 │
│   Step 2: 追踪调用者 (Callers) - 谁调用了这个函数?                │
│   ├─ grep -rn "function_name\s*\(" --include="*.ext"            │
│   ├─ 分析调用点的参数来源                                        │
│   └─ 递归追踪直到找到外部入口                                     │
│                                                                 │
│   Step 3: 追踪被调用者 (Callees) - 这个函数调用了谁?              │
│   ├─ 读取函数体，提取所有函数调用                                 │
│   ├─ 识别危险函数调用 (Sink)                                     │
│   └─ 分析参数如何传递给被调用函数                                 │
│                                                                 │
│   Step 4: 构建调用图                                             │
│   └─ 可视化完整的调用关系                                        │
└─────────────────────────────────────────────────────────────────┘
```

### 调用者追踪 (Caller Analysis)

**目标**: 找出所有调用目标函数的位置，追踪参数来源

```bash
# Step 1: 搜索直接调用
grep -rn "vulnerable_function\s*(" --include="*.py" --include="*.java" --include="*.js"

# Step 2: 搜索方法调用 (带对象前缀)
grep -rn "\.vulnerable_function\s*(" --include="*.py" --include="*.java"

# Step 3: 搜索导入/引用关系
grep -rn "from.*import.*vulnerable_function\|import.*vulnerable_function" --include="*.py"
grep -rn "require.*vulnerable_function\|import.*vulnerable_function" --include="*.js"
```

**分析要点**:
```
对每个调用点:
1. 调用参数是什么?
   - 硬编码常量 → 安全
   - 局部变量 → 继续追踪变量来源
   - 函数参数 → 继续追踪调用者
   - 用户输入 → 找到 Source!

2. 调用上下文是什么?
   - 在 Controller/Handler 中 → 可能是入口点
   - 在 Service/Util 中 → 继续追踪
   - 在测试代码中 → 通常可忽略
```

### 被调用者追踪 (Callee Analysis)

**目标**: 分析函数内部调用了哪些其他函数，是否到达危险 Sink

```
分析步骤:
1. 读取函数完整代码
2. 提取所有函数调用
3. 分类:
   ├─ 危险函数 (Sink) → 标记风险
   ├─ 数据处理函数 → 分析是否传递污点
   ├─ 验证函数 → 检查是否有效净化
   └─ 工具函数 → 递归分析
```

**示例**:
```python
def process_user_data(user_input):
    # Callee 1: 数据处理
    cleaned = sanitize(user_input)      # 需要分析 sanitize() 是否有效

    # Callee 2: 数据库操作
    query = build_query(cleaned)        # 需要分析 build_query() 是否安全

    # Callee 3: 执行查询 (Sink)
    result = db.execute(query)          # 危险! 如果 query 包含污点

    return result
```

### 调用图构建

```
可视化调用关系:

                    [HTTP Handler]
                          │
                          ▼
[caller_1] ──┬──► [target_function] ──┬──► [callee_1: validator]
             │                        │
[caller_2] ──┤                        ├──► [callee_2: transformer]
             │                        │
[caller_3] ──┘                        └──► [callee_3: db.execute] ← Sink!

调用链示例:
Controller.handleRequest()
    └──► UserService.processUser(userId)
            └──► UserMapper.selectUser(userId)
                    └──► SQL执行 (Sink)
```

### 跨文件函数追踪

```
场景: 函数定义和调用分散在多个文件

追踪策略:
1. 定位函数定义文件
   grep -rn "def function_name\|function function_name\|public.*function_name" --include="*.py" --include="*.js" --include="*.java"

2. 搜索所有调用点
   grep -rn "function_name\s*(" --include="*.py" --include="*.js" --include="*.java"

3. 分析导入关系
   - Python: from module import function
   - Java: import package.Class
   - JavaScript: require/import

4. 构建跨文件调用链
   file_a.py:10 → file_b.py:25 → file_c.py:42 → Sink
```

### 递归深度控制

```
参数配置:
- max_depth: 最大追踪深度 (推荐: 10)
- top_k: 每层返回的最大结果数 (推荐: 10)

深度控制策略:
1. 优先追踪高风险路径
2. 遇到循环调用时标记并跳过
3. 达到最大深度时停止并报告
4. 遇到框架/库函数时标记边界
```

### 上下文分析模板

```markdown
## 函数上下文分析报告

### 目标函数
- **名称**: function_name()
- **位置**: path/to/file.ext:line
- **签名**: def function_name(param1, param2)

### 调用者分析 (谁调用了这个函数)

| 调用位置 | 参数来源 | 风险评估 |
|----------|----------|----------|
| caller1.py:20 | 用户输入 request.args | 高风险 |
| caller2.py:45 | 内部常量 | 安全 |
| caller3.py:80 | 数据库查询结果 | 需验证 |

### 被调用者分析 (这个函数调用了谁)

| 被调用函数 | 调用位置 | 类型 | 风险 |
|------------|----------|------|------|
| sanitize() | line 5 | 净化函数 | 需验证有效性 |
| db.query() | line 12 | Sink | 高风险 |
| log.info() | line 15 | 日志 | 低风险 |

### 完整调用链

```
[Entry] request.args.get('id')
    ↓
[Caller] UserController.get_user(id) line:30
    ↓
[Target] UserService.find_by_id(id) line:15
    ↓
[Callee] db.query("SELECT * FROM users WHERE id=" + id) line:20  ← Sink!
```

### 风险结论
- 调用链存在从 Source 到 Sink 的污点传播
- 中间无有效净化措施
- 建议: 使用参数化查询
```

---

## Propagation Rules (传播规则)

### 污点传播情况

| 操作类型 | 传播规则 | 示例 |
|----------|----------|------|
| 赋值 | 污点传递 | `b = a` (a污点→b污点) |
| 字符串拼接 | 污点传递 | `c = a + b` (任一污点→c污点) |
| 函数参数 | 污点传递 | `func(a)` (a污点→参数污点) |
| 函数返回 | 条件传递 | 返回值是否包含参数污点 |
| 数组/对象 | 元素传递 | `arr[0] = a` (a污点→arr污点) |
| 类型转换 | 可能净化 | `int(a)` 可能抛异常净化 |
| 编码/转义 | 可能净化 | `escape(a)` 根据上下文判断 |

### 污点消除情况

| 消除方式 | 说明 | 示例 |
|----------|------|------|
| 常量替换 | 被常量覆盖 | `a = "fixed"` |
| 白名单验证 | 在允许列表中 | `if a in whitelist` |
| 类型强制转换 | 转为安全类型 | `int(a)` 非数字抛异常 |
| 适当的编码 | 针对Sink的编码 | SQL参数化、HTML实体 |
| 安全API | 使用安全替代 | PreparedStatement |

---

## Report Examples (报告示例)

### SQL注入示例

```markdown
## [Critical] SQL注入 - UserController.java:70

### 基本信息
| 属性 | 值 |
|------|-----|
| 漏洞类型 | SQL注入 |
| 严重程度 | Critical |
| CWE编号 | CWE-89 |
| 文件位置 | src/main/java/com/app/controller/UserController.java:70 |
| 函数名称 | getUserById() |

---

### Source (污点源)

**位置**: `UserController.java:45`

**类型**: HTTP请求参数

**代码**:
```java
String userId = request.getParameter("id");
```

**说明**: 用户通过URL参数直接控制userId值，无任何输入验证

---

### Taint Propagation (污点传播路径)

```
[1] UserController.java:45
    代码: String userId = request.getParameter("id")
    操作: 污点引入 - HTTP参数进入变量
    ↓
[2] UserController.java:52
    代码: String param = userId.trim()
    操作: 污点传递 - trim()不改变污点性质
    ↓
[3] UserController.java:67
    代码: String query = "SELECT * FROM users WHERE id=" + param
    操作: 污点拼接 - 污点数据拼接到SQL语句
    ↓
[4] UserController.java:70
    代码: ResultSet rs = stmt.executeQuery(query)
    操作: 污点到达Sink - 执行包含污点的SQL
```

**传播链摘要**:
- 总跨度: 25行代码 / 1个函数 / 1个文件
- 中间变量: userId → param → query
- 无跨函数调用

---

### Sink (汇聚点)

**位置**: `UserController.java:70`

**类型**: SQL执行 (Statement.executeQuery)

**代码**:
```java
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**危害**:
- 攻击者可实现: 任意SQL执行，包括数据查询、修改、删除
- 影响范围: 整个数据库，可能导致数据泄露、数据篡改、权限提升

---

### Taint Analysis (污点分析结论)

| 分析项 | 结果 |
|--------|------|
| 污点源可控性 | 完全可控 |
| 存在净化措施 | 无 |
| 绕过可能性 | 高 |
| 利用复杂度 | 简单 |
| 需要认证 | 否 |

**净化检查**:
- [x] 输入验证: 无
- [x] 编码转义: 无
- [x] 类型转换: 无 (trim()不是有效净化)

**攻击向量**:
```
GET /api/user?id=1' OR '1'='1
GET /api/user?id=1' UNION SELECT username,password,null FROM admin--
```

---

### PoC (概念验证)

**前置条件**: 无需认证，公开访问接口

**利用步骤**:
1. 访问 /api/user?id=1 确认正常功能
2. 访问 /api/user?id=1' 观察错误信息
3. 使用 UNION 注入获取其他表数据

**Payload**:
```
/api/user?id=1' UNION SELECT username,password,email FROM admin--
```

**预期结果**: 返回admin表中的用户名和密码

---

### 修复建议

**推荐方案**: 使用PreparedStatement参数化查询
```java
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

**替代方案**:
- 使用ORM框架 (MyBatis参数化、JPA)
- 输入验证 (仅允许数字)

**修复原则**:
1. 永远不要拼接SQL语句
2. 使用参数化查询或ORM
3. 对于动态表名/列名，使用白名单验证

---

### 参考资料
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
```

---

## Integration with Audit Workflow

### 触发时机

```
在标准审计流程中，当发现漏洞时:

1. 使用Grep/Glob定位危险模式
2. 发现潜在漏洞点 (Sink)
3. **触发污点分析**
4. 反向追踪到Source
5. 验证传播路径
6. 检查净化措施
7. 生成污点分析报告
```

### 命令触发

```
用户输入格式:
- "分析 file.java:70 的污点流"
- "追踪 path/to/file.py:123 的数据来源"
- "生成 src/handler.go:45 的污点报告"

自动识别:
- 文件路径
- 行号
- 启动污点追踪流程
```

---

## Best Practices

### 追踪原则

1. **完整性**: 追踪直到确认Source，不要中途停止
2. **准确性**: 每个传播节点都需要代码验证
3. **全面性**: 检查所有可能的传播路径
4. **实用性**: 关注可利用的路径，忽略理论风险

### 常见陷阱

1. **忽略间接传播**: 通过全局变量、数据库、文件的间接传播
2. **误判净化**: 某些"净化"操作可能被绕过
3. **跨请求污点**: 存储型漏洞的跨请求数据流
4. **框架魔法**: 框架自动绑定的隐式数据流

### 效率技巧

1. 先识别Sink类型，确定需要追踪的危险程度
2. 使用IDE/LSP的跳转功能加速追踪
3. 熟悉框架的数据绑定机制
4. 建立常见Source-Sink模式库

---

## References (参考资源)

### 工具参考

| 工具 | 语言 | 链接 |
|------|------|------|
| JavaSinkTracer | Java | [upstream-repo] |
| CodeQL | 多语言 | https://codeql.github.com/ |
| Semgrep | 多语言 | https://semgrep.dev/ |
| Gosec | Go | [upstream-repo] |
| Bandit | Python | [upstream-repo] |

### 理论参考

- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Taint Analysis Wikipedia](https://en.wikipedia.org/wiki/Taint_checking)

## 🚀 改进的传播路径分析 (基于RuoYi审计经验)

### 新增传播模式

#### 1. 注解驱动的数据过滤传播
```
HTTP请求 → Controller → @DataScope注解方法 → AOP切面处理 → SQL拼接 → ${}参数替换
```

**检测要点:**
- 扫描所有使用`@DataScope`注解的方法
- 追踪AOP切面中的SQL拼接逻辑
- 验证注解参数的可控性

#### 2. 框架特定的传播路径
```
HTTP请求 → Controller参数 → Service调用 → @DataScope处理 → Mapper执行
```

**检测要点:**
- 识别框架特定的数据流模式
- 检查权限注解的安全性
- 验证数据范围过滤的实现

### 增强的验证步骤

#### 注解处理安全性验证
- 确认`@DataScope`注解的参数来源
- 检查AOP切面中的输入过滤
- 验证权限验证逻辑的完整性

#### 方法调用链分析
- 追踪Service层方法间的参数传递
- 检查导出功能的数据流路径
- 验证间接调用的安全性

### 新增检测策略

```markdown
### 框架应用审计流程

1. **入口点识别**
   - 扫描所有Controller接口
   - 识别HTTP方法和路径映射

2. **传播路径追踪**
   - 追踪Service层方法调用
   - 识别注解驱动的数据过滤
   - 检查AOP切面处理逻辑

3. **汇聚点识别**
   - 检查Mapper.xml中的${}使用
   - 验证SQL语句的安全性
   - 确认参数化查询的正确性

4. **风险验证**
   - 确认数据流完整性
   - 评估实际可利用性
   - 提供具体修复建议
```

---

### 新增：文件操作污点追踪

#### 文件操作传播路径
```
HTTP请求 → @RequestParam/@PathVariable → 路径拼接 → 文件系统操作 → 敏感文件泄露
```

**关键检测节点:**
1. **Source**: `@RequestParam("fileName")`, `@PathVariable("file")`
2. **传播**: 路径拼接操作 (`basePath + fileName`)
3. **Sink**: `new File()`, `FileInputStream()`, `Paths.get()`

#### 文件上传传播路径
```
MultipartFile → 文件名获取 → 路径拼接 → 文件存储 → 服务器文件系统
```

#### 检测策略
```bash
# 文件操作污点追踪流程
# 1. 识别文件操作接口
grep -rn "@GetMapping.*file\|@PostMapping.*file" --include="*.java"

# 2. 追踪参数传递路径
grep -rn "fileName\|filePath\|path.*\+" --include="*.java"

# 3. 识别文件操作Sink点
grep -rn "new File\|FileInputStream\|FileOutputStream" --include="*.java"

# 4. 验证安全防护措施
grep -rn "contains.*\\.\\.\|normalize\|startsWith" --include="*.java"
```
