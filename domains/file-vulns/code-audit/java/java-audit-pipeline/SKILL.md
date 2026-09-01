---
name: java-audit-pipeline
description: |
  Java 白盒源码安全审计总方法论。当需要对 Java 项目进行完整的源码安全审计、
  或需要系统化的白盒漏洞挖掘流程时触发。
  覆盖 5 阶段审计流水线: 路由映射→权限建模→数据流追踪→分类漏洞审计→利用链组装。
  核心机制: 证据合约系统(EVID_*)防止 AI 幻觉误报，所有漏洞结论必须有数据流证据支撑。
metadata:
  tags: java audit, code audit, 代码审计, white box, 白盒, source code, 源码审计, pipeline, evidence contract, 证据合约, route mapping, data flow, sink, source, java security, spring, servlet, deserialization
  category: code-audit
---

# Java 白盒审计总方法论
白盒审计在源码层面发现漏洞，关注"代码为什么不安全"。发现漏洞后的实际利用技术（构造 payload、绕过 WAF、Gadget Chain 武器化）属于黑盒 exploit skill 范畴。Java 项目常以编译后的 .class / JAR / WAR 形式交付，需先完成反编译还原源码（详见 decompile-strategy.md）。

## 深入参考

- 证据合约系统与评分公式 → [references/evidence-contract.md](references/evidence-contract.md)
- Java 危险函数分类速查 → [references/sink-reference.md](references/sink-reference.md)
- CFR 反编译策略 → [references/decompile-strategy.md](references/decompile-strategy.md)
- Semgrep / SonarQube / CodeQL / Snyk 等 SAST 工具链 → [references/sast-toolchain.md](references/sast-toolchain.md)

---

## 审计 5 阶段概览

| 阶段 | 名称 | 核心任务 | 产出物 |
|------|------|----------|--------|
| P1 | 路由映射 | 解析所有入口点及其参数 | 路由清单 |
| P2 | 权限建模 | 分析认证/授权，标记裸露路由 | 权限矩阵 |
| P3 | 数据流追踪 | Source→Sink 完整路径追踪 | EVID_* 证据集 |
| P4 | 分类审计 | 按 Sink 类型深入检查 | 漏洞清单 |
| P5 | 报告组装 | 评分 + 利用链编排 | 审计报告 |

## Phase 1: 路由映射与入口点识别

解析框架路由配置，建立完整的攻击面清单:
- **Spring MVC**: `@RequestMapping`, `@GetMapping`, `@PostMapping` 等组合注解，扫描所有 `@Controller` / `@RestController` 类
- **Servlet**: `web.xml` 中的 `<servlet-mapping>` 以及 `@WebServlet` 注解注册的 Servlet
- **JAX-RS**: `@Path`, `@GET`, `@POST` 等注解，检查 `Application` 子类注册的资源
- **Struts2**: `struts.xml` 中的 `<action>` 映射和 `ActionMapping` 通配符规则
- **WebService**: CXF / Axis 的 `@WebService` 端点和 WSDL 发布路径

产出: 路由清单，每条记录包含 URL 路径、Handler 方法签名、参数绑定方式（`@RequestParam` / `@PathVariable` / `@RequestBody`）、是否需认证。

## Phase 2: 权限建模与认证审查

分析安全框架的过滤链配置，找出缺少认证保护的路由:
- **Spring Security**: `SecurityFilterChain` / `WebSecurityConfigurerAdapter` 中的 `antMatchers` / `requestMatchers` 规则
- **Apache Shiro**: `shiroFilterChainDefinition` 中的 URL-Filter 映射（anon / authc / perms）
- **自定义拦截器**: `HandlerInterceptor.preHandle()` 的注册范围和排除路径
- 检查 JWT / Session / OAuth2 Token 的签发与校验逻辑、密码存储方式（BCrypt / 明文）

## Phase 3: 数据流追踪（Source → Sink）

每条潜在漏洞路径都要产出 EVID_* 证据点（详见 evidence-contract.md）。

**三层分析法**:
1. **面** — 全局关键字扫描: 搜索 Sink 函数（参考 sink-reference.md），快速定位危险代码区域
2. **线** — 逐行追踪变量流: 从 Sink 反向追溯到 Source，记录每一步的变量传递和过滤操作
3. **点** — 验证利用条件: 确认过滤是否可绕过、参数是否可控、执行路径是否可达

**Java 特有关注点**:
- 注解驱动的参数绑定（`@RequestParam` 自动 trim、`@RequestBody` JSON 反序列化）隐式转换可能吞掉恶意输入或引入类型混淆
- AOP 切面（`@Around` / `@Before`）可能在切面层执行全局过滤或日志记录，需确认切面是否生效
- 反射调用（`Method.invoke`、`Class.forName`）会打断静态数据流追踪，需人工跟进
- 多态分派 — 接口/抽象类的实际实现类需逐一排查，不能仅看接口声明

当无法追踪到完整的 Source→Sink 路径时，只能标注为"待验证"。

## Phase 4: 分类漏洞审计

按 Sink 类型分派到对应子 skill 进行深入审计:
- 注入类（SQL / CMD / LDAP / SpEL / OGNL / EL）
- 文件类（读取 / 上传 / 写入 / 路径穿越）
- 前端类（XSS / CSRF / 重定向）
- 序列化类（Java 原生反序列化 / FastJSON / Jackson / XXE）
- 认证配置类（越权 / 弱加密 / 信息泄露 / Actuator 暴露）
- 框架特定漏洞（已知 CVE、Spring / Struts2 / Shiro 配置缺陷）

## Phase 5: 报告与利用链组装

**严重度评分**: `Score = R * 0.40 + I * 0.35 + C * 0.25`（R=可达性, I=影响范围, C=利用复杂度，各 0-3 分）

将同一目标上的多个漏洞组合为利用链（如: Actuator 信息泄露→Shiro 认证绕过→SpEL 注入→RCE）。

## 审计质量检查清单

- [ ] 所有公开路由均已纳入路由清单（含 Servlet / Filter 注册的隐式入口）
- [ ] 未认证路由已全部标记并优先审计
- [ ] 每个"已确认"漏洞都有完整的 EVID_* 证据链
- [ ] AOP 切面和全局 Filter 的实际覆盖范围已验证
- [ ] 反射调用和动态代理的数据流已人工跟进
- [ ] 框架版本及依赖组件版本已确认，已知 CVE 已交叉比对
- [ ] 漏洞评分使用了统一公式，等级划分一致
- [ ] 利用链可行性已在源码层面验证
