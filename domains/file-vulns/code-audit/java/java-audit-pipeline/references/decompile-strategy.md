# CFR 反编译策略

Java 白盒审计的目标经常是编译后的 .class 文件、JAR 包或 WAR/EAR 部署包。反编译是审计的前置步骤，本文档提供系统化的反编译策略。

---

## 何时需要反编译

| 场景 | 说明 |
|------|------|
| 仅有 .class 文件 | 目标以编译后字节码交付，无源码 |
| 无源码的第三方 JAR | 需要审计依赖库中的危险调用或已知漏洞的实际实现 |
| Spring Boot fat JAR | `BOOT-INF/classes` 为业务代码，`BOOT-INF/lib` 为依赖 JAR |
| WAR 包 | `WEB-INF/classes` 为业务代码，`WEB-INF/lib` 为依赖 JAR |
| 混淆/加壳应用 | ProGuard / DashO 混淆后的代码，反编译可能失真但仍有审计价值 |

---

## CFR 反编译器

CFR 是首选反编译器，对现代 Java（Lambda、Switch 表达式、Record 等）支持最好。

### 基本用法

**单个 .class 文件**:
```bash
java -jar cfr.jar Target.class
```

**单个 .class 文件输出到文件**:
```bash
java -jar cfr.jar Target.class > Target.java
```

**整个 JAR 包反编译到目录**:
```bash
java -jar cfr.jar app.jar --outputdir ./decompiled
```

**指定额外 classpath（解决依赖缺失警告）**:
```bash
java -jar cfr.jar app.jar --extraclasspath "lib/*" --outputdir ./decompiled
```

### 常用选项

| 选项 | 说明 |
|------|------|
| `--outputdir <dir>` | 输出目录，保持包路径结构 |
| `--extraclasspath <path>` | 补充依赖 classpath，减少反编译错误 |
| `--decodelambdas true` | 解码 Lambda 表达式（默认开启） |
| `--decodestringswitch true` | 解码 String switch 语句 |
| `--removeboilerplate true` | 移除编译器生成的样板代码 |
| `--silent true` | 静默模式，仅输出反编译结果 |
| `--comments false` | 不生成 CFR 注释 |

---

## 备选反编译器

### Procyon

对泛型信息还原较好，某些场景下比 CFR 输出更可读:
```bash
java -jar procyon-decompiler.jar -o ./decompiled app.jar
```

### FernFlower（IntelliJ 内置）

IntelliJ IDEA 自带的反编译器，直接在 IDE 中打开 .class 文件即可查看。也可命令行使用:
```bash
java -jar fernflower.jar app.jar ./decompiled
```

### 选择建议

| 反编译器 | 优势 | 劣势 |
|----------|------|------|
| CFR | Lambda/现代语法最优，主动维护 | 极端混淆场景偶尔崩溃 |
| Procyon | 泛型还原好，注释保留 | 对 Java 11+ 语法支持稍弱 |
| FernFlower | IDE 集成方便，批量处理稳定 | 输出可读性略低于 CFR |

**建议**: 优先使用 CFR，CFR 输出异常时用 Procyon 补充，IDE 内快速浏览用 FernFlower。

---

## Spring Boot fat JAR 解包策略

Spring Boot 的可执行 JAR 结构:
```
app.jar
├── META-INF/
│   └── MANIFEST.MF          # Main-Class: JarLauncher, Start-Class: 实际主类
├── BOOT-INF/
│   ├── classes/              # 业务代码 .class 文件
│   └── lib/                  # 依赖 JAR 包
└── org/springframework/boot/loader/   # Spring Boot Loader
```

### 解包步骤

```bash
# 1. 解包 JAR
mkdir app-extracted && cd app-extracted
jar -xf ../app.jar

# 2. 反编译业务代码（优先审计）
java -jar cfr.jar BOOT-INF/classes --outputdir ./src-business

# 3. 按需反编译特定依赖（仅审计可疑依赖）
java -jar cfr.jar BOOT-INF/lib/suspicious-lib.jar --outputdir ./src-lib

# 4. 获取依赖清单用于 CVE 比对
ls BOOT-INF/lib/ > dependency-list.txt
```

### WAR 包解包

```bash
mkdir app-war && cd app-war
jar -xf ../app.war

# 业务代码在 WEB-INF/classes
java -jar cfr.jar WEB-INF/classes --outputdir ./src-business

# 依赖在 WEB-INF/lib
ls WEB-INF/lib/ > dependency-list.txt
```

---

## 反编译产物的路由映射还原

反编译后需从 .java 源码中重建路由清单，重点关注:

### 注解保留

Java 编译器会将运行时可见注解（`@Retention(RUNTIME)`）保留在 .class 文件中，CFR 能正确还原:
- `@RequestMapping`, `@GetMapping`, `@PostMapping` 等 Spring MVC 注解
- `@WebServlet`, `@WebFilter` 等 Servlet 注解
- `@Path`, `@GET`, `@POST` 等 JAX-RS 注解
- `@PreAuthorize`, `@Secured` 等安全注解

### 参数名恢复

- 使用 `-parameters` 编译的 .class 文件，CFR 可还原真实参数名
- 未使用 `-parameters` 时，参数名显示为 `arg0`, `arg1` 等，但 `@RequestParam("name")` 注解中的值仍然可读
- Spring Boot 默认通过 `spring-boot-maven-plugin` 保留参数名信息

### 路由还原检查清单

- [ ] 扫描所有 `@Controller` / `@RestController` 类及其类级 `@RequestMapping`
- [ ] 拼接类级和方法级路径得到完整 URL
- [ ] 检查 `web.xml` 或 `@WebServlet` 注册的 Servlet
- [ ] 检查 `FilterRegistrationBean` 或 `@WebFilter` 注册的 Filter 链
- [ ] 确认 `application.properties/yml` 中的 `server.servlet.context-path` 前缀

---

## 注意事项

### 内部类

编译后内部类会生成独立的 .class 文件（如 `Outer$Inner.class`、`Outer$1.class`），CFR 通常能正确还原嵌套关系。匿名内部类（`Outer$1.class`）的还原可能不够直观，需对照外部类上下文理解。

### Lambda 表达式

Java 8+ 的 Lambda 编译为 `invokedynamic` 指令和私有静态方法（`lambda$methodName$0`）。CFR 默认能将其还原为 Lambda 语法，但复杂的链式 Lambda（如 Stream API 多级操作）偶尔还原不完整，此时查看原始字节码中的 bootstrap method 有助于理解。

### 泛型擦除

Java 泛型在编译后被擦除为原始类型（`List<String>` → `List`），但泛型签名信息保留在 `Signature` 属性中。CFR 通常能还原泛型参数，但以下场景可能丢失:
- 局部变量的泛型类型（编译器未保留 `LocalVariableTypeTable` 时）
- 桥接方法（Bridge Method）— 编译器为泛型协变返回类型生成的合成方法，可能造成方法签名混淆

### 混淆代码

ProGuard 等混淆工具会重命名类/方法/字段为 `a`, `b`, `c` 等短名称:
- 反编译产物可读性大幅下降，但数据流追踪仍然有效
- 字符串常量不受混淆影响，可通过搜索 SQL 语句、URL 模式、日志信息等定位关键代码
- Spring 注解中的字符串值（如 `@RequestMapping("/api/user")`）不会被混淆
- 建议配合 mapping.txt（如果可获取）进行反混淆还原
