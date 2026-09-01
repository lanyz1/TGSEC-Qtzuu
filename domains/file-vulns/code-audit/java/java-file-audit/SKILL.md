---
name: java-file-audit
description: |
  Java 源码文件操作类漏洞审计。当在 Java 白盒审计中需要检测文件相关漏洞时触发。
  覆盖 5 类文件风险: 任意文件上传(MultipartFile/Servlet Part/类型绕过)、任意文件读取(NIO/IO流/路径穿越)、
  任意文件写入(覆盖配置/WebShell落地)、归档提取漏洞(ZipInputStream/Zip Slip)、文件删除/重命名竞争。
  需要 java-audit-pipeline 提供的数据流证据。
metadata:
  tags: file upload, file read, file write, path traversal, zip slip, 文件上传, 任意读取, 任意写入, java nio, multipartfile, 路径穿越
  category: code-audit
---

# Java 文件操作类漏洞源码审计
本 skill 聚焦源码层面判断"文件操作漏洞是否成立"，核心是验证路径可控性、文件名可控性和内容可控性。构造上传绕过 payload、目录穿越利用链等运行时利用技术属于对应黑盒 exploit skill 范畴。

## 深入参考

- 5 类文件漏洞的危险模式 / 安全模式代码对比 / EVID 证据示例 → [references/file-vuln-patterns.md](references/file-vuln-patterns.md)

---

## Sink 分类决策树

根据遇到的 Sink 函数类型，进入不同审计分支:

| Sink 函数 | 分支 | 典型严重度 |
|-----------|------|-----------|
| `MultipartFile.transferTo()` / `Part.write()` | 文件上传 | Critical-High |
| `FileInputStream` / `Files.readAllBytes()` / `new File(path)` / `ClassLoader.getResourceAsStream()` | 文件读取 | High-Medium |
| `FileOutputStream` / `Files.write()` / `FileWriter` | 文件写入 | Critical-High |
| `ZipInputStream.getNextEntry()` / `ZipFile.entries()` | 归档提取 | High |
| `File.delete()` / `Files.delete()` | 文件删除 | Medium |

## 文件上传审计要点

上传漏洞本质是三要素同时满足: 可执行扩展名 + Web 可达存储路径 + 未被重命名/内容清洗。

- **MultipartFile**: `file.transferTo(new File(dir + file.getOriginalFilename()))` — `getOriginalFilename()` 返回客户端原始文件名，可含 `../` 路径穿越或恶意扩展名
- **Servlet Part**: `part.write(uploadPath + fileName)` — 检查 `fileName` 是否来自 `part.getSubmittedFileName()` 且未净化
- **ContentType 校验 vs 扩展名校验**: `file.getContentType()` 来自客户端 HTTP 头，完全可伪造；扩展名白名单更可靠但需 `toLowerCase()` 处理
- **存储路径可控性**: 文件名中的 `../` 跳出上传目录，`Paths.get(dir, fileName).normalize()` 后需验证前缀
- **Spring multipart-config**: `spring.servlet.multipart.location` / `max-file-size` / `max-request-size` 配置影响上传行为，检查是否限制合理
- **文件头 Magic bytes 校验**: 真实类型检测需读取文件头字节（如 `ImageIO.read()` 或 Apache Tika），而非信任 Content-Type

## 文件读取审计要点

路径穿越是文件读取漏洞的核心，`../` 及其变体可跳出预期目录:

- **路径穿越 `../`**: `new FileInputStream("/data/" + userPath)` — 用户输入 `../../etc/passwd` 读取任意文件
- **NIO 安全模式**: `Path resolved = baseDir.resolve(userInput).normalize(); if (!resolved.startsWith(baseDir)) throw ...` — `normalize()` 消除 `../`，`startsWith()` 校验前缀
- **URL 编码绕过**: `%2e%2e%2f`（`../`）、双重编码 `%252e%252e%252f` — 检查框架是否自动解码后再传入路径
- **ClassLoader.getResourceAsStream**: 类路径读取受 ClassLoader 沙箱限制，通常不可穿越到文件系统任意路径，但可读取 classpath 内敏感配置
- **Spring Resource 路径**: `classpath:` 协议限于类路径内，`file:` 协议可访问文件系统 — 检查协议是否用户可切换

## 文件写入审计要点

写入漏洞需要: 路径可控 + 内容可控 + 写入路径可被 Web 容器执行。

- **WebShell 写入**: `Files.write(Paths.get(dir + filename), content.getBytes())` — 路径和内容同时可控时，写入 `.jsp` 到 Web 根即获得 RCE
- **配置文件覆盖**: 覆写 `application.yml` / `application.properties` 修改数据源、重定向等配置；覆写 `web.xml` 添加恶意 Servlet 映射
- **日志注入写马**: 日志框架记录用户输入 → 日志文件路径可预测 → 配合文件包含或直接写入 JSP 内容到日志
- **模板文件覆盖**: Thymeleaf / FreeMarker 模板目录可写 → 覆盖模板注入 SSTI payload → 下次渲染时触发
- **安全模式**: 路径白名单 + 内容类型校验 + 文件存储到 Web 根外 + 写入权限最小化

## 归档提取审计要点

Zip Slip 是归档提取最经典的漏洞，恶意归档条目名含 `../` 导致任意路径写入:

- **ZipEntry.getName() 含 `../`**: `new File(destDir, entry.getName())` — 条目名如 `../../webapps/ROOT/shell.jsp` 直接写入 Web 目录
- **安全模式 (Canonical Path 校验)**: 解压前获取 `file.getCanonicalPath()` 和 `destDir.getCanonicalPath()`，验证文件路径以目标目录为前缀
- **TarInputStream / GzipInputStream**: 类似风险，tar 条目名同样可含路径穿越
- **文件覆盖**: 即使不穿越目录，恶意归档可覆盖同目录下已有文件（配置文件、库文件）

## 文件删除审计要点

- **路径穿越删除**: `new File(dir + userInput).delete()` — 用户输入 `../../important.conf` 删除关键文件
- **TOCTOU 竞争**: 检查权限 → 执行删除之间的时间窗口，攻击者可替换目标为符号链接指向敏感文件
- **符号链接跟随**: `Files.delete(path)` 删除链接目标而非链接本身（取决于实现），`File.delete()` 仅删除链接

## 检测清单

- [ ] 所有文件类 EVID_* 证据点已逐一审查
- [ ] 上传功能的文件名净化方式已确认（UUID 重命名 vs 原始文件名 vs 白名单扩展名）
- [ ] 上传存储路径是否在 Web 根内、是否可直接通过 URL 访问已验证
- [ ] ContentType 校验 vs 文件头 Magic bytes 校验方式已区分
- [ ] 文件读取路径的穿越防护已检查（normalize + startsWith 模式）
- [ ] 文件写入的路径和内容来源已追踪，是否可写入可执行位置已确认
- [ ] 归档解压函数的条目名称校验已检查（Canonical Path 验证）
- [ ] 文件删除操作的路径校验和符号链接风险已评估
- [ ] 过滤不充分的点已给出绕过思路或标"待验证"
- [ ] 严重度评分使用了统一公式，与 pipeline 一致
