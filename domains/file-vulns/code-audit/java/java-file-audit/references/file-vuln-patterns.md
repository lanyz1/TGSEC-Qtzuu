# Java 文件操作类漏洞审计模式参考

5 类文件漏洞的危险代码 / 安全代码对比 + EVID_* 证据格式示例。

---

## 1. 文件上传

### 1.1 扩展名与文件名绕过模式清单

| 绕过方式 | 原理 | 示例 |
|----------|------|------|
| 路径穿越文件名 | `getOriginalFilename()` 返回客户端原始名 | `../../../webapps/ROOT/shell.jsp` |
| 双扩展名 | Web 容器解析规则差异 | `shell.jsp.jpg` — 自定义映射或 Nginx 转发可能触发 |
| null byte (旧版 JDK) | JDK < 7u40 路径处理截断 | `shell.jsp%00.jpg` → 实际创建 `shell.jsp` |
| Windows ::$DATA | NTFS 备用数据流 | `shell.jsp::$DATA` → 忽略后缀 |
| Windows 尾部点/空格 | 文件系统自动剥离 | `shell.jsp.` / `shell.jsp ` → 保存为 `shell.jsp` |
| 大小写变体 | 大小写不敏感系统 | `.Jsp` / `.jSP` — 检查是否 `toLowerCase()` |
| Content-Type 伪造 | 客户端控制 HTTP 头 | `Content-Type: image/jpeg` 但内容为 JSP 代码 |
| 图片马 | 文件头 + JSP 代码 | JPEG 头 `FF D8 FF E0` + JSP 代码（需容器解析触发） |

### 1.2 Spring MultipartFile 危险代码 vs 安全代码

```java
// 危险: 原始文件名未净化
@PostMapping("/upload")
public String upload(@RequestParam MultipartFile file) {
    file.transferTo(new File(uploadDir + "/" + file.getOriginalFilename()));
    return "success";
}
// 问题: getOriginalFilename() 可返回 "../../../shell.jsp"; 未验证扩展名

// 危险: 仅检查 ContentType — 客户端完全可伪造
if (!file.getContentType().startsWith("image/")) { throw new RuntimeException(); }
file.transferTo(new File(uploadDir, file.getOriginalFilename()));

// 安全: UUID 重命名 + 扩展名白名单 + Web 根外存储 + Magic bytes 校验
private static final Set<String> ALLOWED_EXT = Set.of("jpg", "jpeg", "png", "gif");
@PostMapping("/upload")
public String upload(@RequestParam MultipartFile file) throws IOException {
    String ext = StringUtils.getFilenameExtension(file.getOriginalFilename());
    if (ext == null || !ALLOWED_EXT.contains(ext.toLowerCase())) { throw new RuntimeException(); }
    BufferedImage image = ImageIO.read(file.getInputStream());  // Magic bytes 校验
    if (image == null) { throw new RuntimeException("非有效图片"); }
    Path dest = Paths.get("/var/data/uploads", UUID.randomUUID() + "." + ext.toLowerCase());
    Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);
    return "success";
}
```

### 1.3 Servlet Part 危险模式

```java
// 危险: Part.write() + 客户端文件名 — getSubmittedFileName() 可含 ../
Part part = req.getPart("file");
part.write(uploadPath + "/" + part.getSubmittedFileName());
```

### 1.4 EVID_UPLOAD 证据示例

```
[EVID_UPLOAD_DESTPATH]  FileController.java:45
  file.transferTo(new File(uploadDir + "/" + file.getOriginalFilename()))
  uploadDir="/app/static/uploads/" — Web 根内可直接访问

[EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE]  :38-44
  无扩展名白名单 | 仅检查 ContentType 可伪造 | getOriginalFilename() 未净化可含 ../

[EVID_UPLOAD_ACCESSIBILITY_PROOF]
  /app/static/uploads/ 映射到 /uploads/** | Spring ResourceHandler 配置可直接访问 → Critical
```

---

## 2. 文件读取/路径穿越

### 2.1 IO 流路径拼接模式

```java
// 危险: FileInputStream + 用户输入直接拼接
@GetMapping("/download")
public void download(@RequestParam String filename, HttpServletResponse resp) throws Exception {
    FileInputStream fis = new FileInputStream("/data/files/" + filename);
    IOUtils.copy(fis, resp.getOutputStream());
}
// filename=../../etc/passwd → 读取 /etc/passwd

// 危险: NIO Files.readAllBytes + 用户输入
return Files.readAllBytes(Paths.get("/data/docs", userInput));
// userInput=../../../etc/shadow → 读取任意文件
```

### 2.2 NIO 安全模式

```java
// 安全: normalize() + startsWith() 前缀校验
Path baseDir = Paths.get("/data/files").toAbsolutePath().normalize();
Path resolved = baseDir.resolve(filename).normalize();
if (!resolved.startsWith(baseDir)) { throw new SecurityException("路径穿越"); }
return Files.readAllBytes(resolved);
```

必须对 `baseDir` 和 `resolved` 都调用 `normalize()`。`toRealPath()` 更严格（解析符号链接），但要求文件已存在。

### 2.3 路径穿越 Payload 变体

| Payload | 场景 |
|---------|------|
| `../../../etc/passwd` | 基础穿越 |
| `%2e%2e%2f` | URL 编码（取决于框架自动解码） |
| `%252e%252e%252f` | 双重 URL 编码 |
| `..%5c..%5c` | 反斜杠 URL 编码（Windows） |
| `....//....//` | 递归替换 `../` 为空后仍有效 |
| `..;/..;/` | Tomcat / Spring 分号路径参数 |
| `/WEB-INF/web.xml` | 绝对路径读取 Web 应用配置 |

### 2.4 Spring Resource 协议切换 & ClassLoader

```java
// 危险: 用户可控 resource 路径 — classpath: 被切换为 file: 协议
Resource resource = resourceLoader.getResource(userInput);
// userInput=file:///etc/passwd → 读取系统文件

// 安全: 强制 classpath: 前缀
Resource resource = resourceLoader.getResource("classpath:templates/" + name);

// ClassLoader: 通常不可穿越出 classpath，但可读取 classpath 内敏感配置
getClass().getClassLoader().getResourceAsStream(userInput);
// 可读: application.properties, db-config.xml 等
```

### 2.5 EVID_FILE 证据示例

```
[EVID_FILE_READ_CALLSITE]  DownloadController.java:28
  new FileInputStream(baseDir + "/" + request.getParameter("file"))

[EVID_FILE_PATH_TRAVERSAL_CHECK]  :25-27
  无 normalize() | 无 startsWith() | 无过滤 ../ | baseDir="/app/data/exports/"

[EVID_FILE_RESOLVED_TARGET]
  file=../../WEB-INF/web.xml → /app/WEB-INF/web.xml | file=../../../etc/passwd → /etc/passwd

[EVID_FILE_SOURCE_TRACE]
  Source: request.getParameter("file") → 无过滤直接拼接 → 任意文件读取已确认 → High
```

---

## 3. 文件写入

### 3.1 三要素分析

| 条件 | 完全可控 | 部分可控 | 不可控 |
|------|---------|---------|--------|
| 路径 | 写入任意位置 | 固定目录+文件名可控 | 硬编码路径 |
| 内容 | 写入任意 JSP/代码 | 部分注入(日志/模板) | 固定内容 |
| 可执行 | Web 根内 + JSP/JSPX 扩展 | Web 根内非脚本扩展 | Web 根外 |

三要素全部完全可控 = 直接写 WebShell (Critical)。

### 3.2 危险模式

```java
// 危险: 路径 + 内容均可控 — 直接写 WebShell
Files.write(Paths.get("/app/webapps/ROOT/" + filename), content.getBytes());

// 危险: 配置文件覆盖 — application.yml / web.xml
Files.write(Paths.get("src/main/resources/application.yml"), yaml.dump(userConfig).getBytes());
// 覆写 spring.datasource.url 指向攻击者数据库; 或注入 SpEL 表达式

// 日志注入: logger.info("Action: " + userInput) — JSP 代码写入日志
// 若日志路径可预测且存在文件包含 → RCE

// 模板覆盖: Thymeleaf templates/ 目录可写
// 覆写注入: [[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

### 3.3 安全模式

```java
// 安全: 路径白名单 + 文件名净化 + Web 根外存储
private static final Set<String> WRITABLE_DIRS = Set.of("/var/data/exports", "/var/data/temp");
public void safeWrite(String dir, String filename, byte[] content) throws Exception {
    if (!WRITABLE_DIRS.contains(dir)) { throw new SecurityException("不允许的目录"); }
    if (!filename.matches("[a-zA-Z0-9._-]+")) { throw new SecurityException("非法文件名"); }
    Path target = Paths.get(dir).resolve(filename).normalize();
    if (!target.startsWith(Paths.get(dir))) { throw new SecurityException("路径穿越"); }
    Files.write(target, content);
}
```

### 3.4 EVID_WRITE 证据示例

```
[EVID_WRITE_WRITE_CALLSITE]  ReportService.java:78
  Files.write(Paths.get(outputDir + "/" + reportName), reportContent.getBytes())

[EVID_WRITE_DESTPATH_RESOLVED_TARGET]  :72-76
  outputDir=servletContext.getRealPath("/reports") Web 根内 | reportName 用户可控无净化

[EVID_WRITE_CONTENT_SOURCE_INTO_WRITE]  :77
  reportContent = request.getParameter("content") → 用户完全可控

[EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF]
  Web 根内 .jsp 可被 Tomcat 编译执行 | 路径+内容+可执行全满足 → Critical
```

---

## 4. 归档提取 (Zip Slip)

### 4.1 ZipInputStream 路径穿越

```java
// 危险: ZipEntry.getName() 直接拼接 — 经典 Zip Slip
ZipInputStream zis = new ZipInputStream(zipStream);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File file = new File(destDir, entry.getName());
    // entry.getName() = "../../webapps/ROOT/shell.jsp" → 写入 Web 目录
    file.getParentFile().mkdirs();
    try (FileOutputStream fos = new FileOutputStream(file)) { IOUtils.copy(zis, fos); }
}

// ZipFile.entries() 同样危险 — 缺少 canonical path 校验
ZipFile zipFile = new ZipFile(uploadedFile);
Enumeration<? extends ZipEntry> entries = zipFile.entries();
while (entries.hasMoreElements()) {
    ZipEntry e = entries.nextElement();
    Files.copy(zipFile.getInputStream(e), new File(destDir, e.getName()).toPath());
}
```

### 4.2 安全模式: Canonical Path 校验

```java
// 安全: 解压前验证每个条目的规范路径
String canonicalDest = destDir.getCanonicalPath();
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File file = new File(destDir, entry.getName());
    if (!file.getCanonicalPath().startsWith(canonicalDest + File.separator)) {
        throw new SecurityException("Zip Slip: " + entry.getName());
    }
    file.getParentFile().mkdirs();
    try (FileOutputStream fos = new FileOutputStream(file)) {
        byte[] buf = new byte[4096]; int len;
        while ((len = zis.read(buf)) > 0) { fos.write(buf, 0, len); }
    }
}
```

关键: `getCanonicalPath()` 解析 `../` 和符号链接，拼接 `File.separator` 防止 `/app/upload` 匹配 `/app/upload-evil/`。

TarArchiveInputStream (Apache Commons Compress) 同理: `entry.getName()` 可含 `../../`，需要相同的 canonical path 校验逻辑。

### 4.3 EVID_ARCHIVE 证据示例

```
[EVID_ARCHIVE_EXTRACT_CALLSITE]  PluginManager.java:92
  new File(pluginDir, entry.getName()) + copy(zis, fos)

[EVID_ARCHIVE_ENTRY_NAME_VALIDATION]  :88-100
  无 ".." 检查 | 无 getCanonicalPath() 前缀验证 | 直接拼接

[EVID_ARCHIVE_DEST_ACCESSIBILITY]
  pluginDir=servletContext.getRealPath("/plugins") Web 根内 | Zip Slip 已确认 → High
```

---

## 5. 文件删除/竞争条件

### 5.1 路径穿越删除

```java
// 危险: 用户可控路径直接传入 delete
new File("/app/uploads/" + request.getParameter("file")).delete();
// file=../../conf/server.xml → 删除 Tomcat 配置

// 安全: normalize + startsWith 校验
Path baseDir = Paths.get("/app/uploads").toAbsolutePath().normalize();
Path target = baseDir.resolve(filename).normalize();
if (!target.startsWith(baseDir)) { throw new SecurityException("路径穿越"); }
Files.deleteIfExists(target);
```

### 5.2 TOCTOU 竞争

```java
// 危险: 检查→删除之间的竞争窗口
File file = new File(path);
if (file.exists() && isOwner(file, currentUser)) {
    // 窗口期: 攻击者替换 file 为指向敏感文件的符号链接
    file.delete(); // 删除符号链接指向的目标
}

// 安全: NIO + 不跟随符号链接
Path realPath = path.toRealPath(LinkOption.NOFOLLOW_LINKS);
if (!realPath.startsWith(allowedDir.toRealPath())) { throw new SecurityException(); }
Files.delete(realPath);
```

### 5.3 符号链接跟随

```java
// 危险: 默认跟随符号链接 — /app/uploads/evil.txt -> /etc/shadow
Files.readAllBytes(Paths.get("/app/uploads/evil.txt")); // 实际读取 /etc/shadow

// 安全: toRealPath 对比检测符号链接
Path realPath = path.toRealPath(LinkOption.NOFOLLOW_LINKS);
if (!realPath.equals(path.toAbsolutePath().normalize())) {
    throw new SecurityException("路径包含符号链接");
}
```

### 5.4 上传竞争条件

```java
// 危险: 先保存再校验 — transferTo 和 delete 之间的窗口期可被并发访问
File dest = new File(uploadDir, file.getOriginalFilename());
file.transferTo(dest);
if (!isValidImage(dest)) { dest.delete(); return "invalid"; }
// 攻击: 并发请求 /uploads/shell.jsp 在校验删除前执行

// 安全: 先存临时文件 → 校验 → 移动到最终位置
File temp = File.createTempFile("upload_", ".tmp");
file.transferTo(temp);
if (isValidImage(temp)) {
    Files.move(temp.toPath(), Paths.get(uploadDir, UUID.randomUUID() + ".jpg"));
} else { temp.delete(); }
```

### 5.5 EVID_RACE / EVID_DELETE 证据示例

```
[EVID_DELETE_CALLSITE]  CleanupService.java:55
  new File(uploadDir + "/" + filename).delete() | filename 无净化 → 路径穿越删除

[EVID_RACE_CHECK_OPERATION]  FileService.java:89
  if (file.exists() && checkPermission(file, user))
[EVID_RACE_USE_OPERATION]  :95
  file.delete() — 间隔 6 行含数据库 I/O，无文件锁
[EVID_RACE_WINDOW_ANALYSIS]
  uploadDir 用户可写 → 可创建符号链接 | checkPermission 含 DB 查询窗口较长 → Medium
```
