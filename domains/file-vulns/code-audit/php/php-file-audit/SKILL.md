---
name: php-file-audit
description: |
  PHP 源码文件操作类漏洞审计。当在 PHP 白盒审计中需要检测文件相关漏洞时触发。
  覆盖 5 类文件风险: 任意文件上传(类型绕过/路径穿越/二次渲染)、任意文件读取(include/fread/路径穿越)、
  任意文件写入(日志注入/配置覆盖)、文件系统竞争(TOCTOU/符号链接)、归档提取漏洞(Zip Slip)。
  需要 php-audit-pipeline 提供的数据流证据。
metadata:
  tags: file upload, file read, file write, path traversal, zip slip, lfi, rfi, include, 文件上传, 任意读取, 任意写入, toctou, symlink, 路径穿越
  category: code-audit
---

# PHP 文件操作类漏洞源码审计
本 skill 聚焦源码层面判断"文件操作漏洞是否成立"，核心是验证路径可控性、内容可控性和执行可达性。构造上传绕过 payload、LFI 日志投毒等运行时利用技术属于对应黑盒 exploit skill 范畴。

## 深入参考

- 5 类文件漏洞的危险模式 / 安全模式代码对比 / EVID 证据示例 → [references/file-vuln-patterns.md](references/file-vuln-patterns.md)

---

## Sink 分类决策树

根据遇到的 Sink 函数类型，进入不同审计分支:

| Sink 函数 | 分支 | 典型严重度 |
|-----------|------|-----------|
| `move_uploaded_file`, `copy($_FILES)` | 文件上传 | Critical-High |
| `include`/`require`/`include_once`/`require_once` | 文件读取+执行 | Critical |
| `file_get_contents`/`readfile`/`fread`/`highlight_file` | 文件读取 | High-Medium |
| `file_put_contents`/`fwrite`/`fopen('w')` | 文件写入 | Critical-High |
| `ZipArchive::extractTo`/`PharData::extractTo` | 归档提取 | High |
| `file_exists`/`is_file` + 后续操作 | 竞争条件 | Medium-High |

## 文件上传审计要点

上传漏洞本质是三要素同时满足: 可执行扩展名 + Web 可达存储路径 + 未被重命名/内容清洗。

- **扩展名验证**: 黑名单容易遗漏 `.phtml`/`.pht`/`.php5`/`.phar`/`.shtml`，白名单更安全但要检查大小写处理逻辑
- **MIME vs Magic bytes**: `$_FILES['type']` 来自客户端完全可伪造；`finfo_file()`/`getimagesize()` 验证文件头但图片马（GIF89a + PHP 代码）可绕过
- **存储路径可控性**: 用户是否能通过文件名中的 `../` 控制存储位置，跳出预定上传目录
- **Web 根可达性**: 文件存储在 Web 根外则即使上传了 PHP 也无法直接执行
- **重命名策略**: `md5(time())` 等可预测命名可被猜解，`random_bytes()` 更安全

## 文件读取/包含审计要点

`include` 系列既读取又执行，危害远大于纯读取函数:

- **路径拼接模式**: `include($dir . '/' . $page . '.php')` — 检查 `$page` 是否用户可控，`../` 穿越是否被过滤
- **%00 截断**: PHP < 5.3.4 可用 null 字节截断 `.php` 后缀；高版本已修复但审计遗留系统时仍需关注
- **Wrapper 利用**: `php://filter/convert.base64-encode/resource=` 读取源码、`php://input` 注入代码、`data://` 执行 payload
- **RFI 条件**: `allow_url_include=On` 时远程文件包含成立，检查 `php.ini` 配置
- **纯读取函数**: `file_get_contents`/`readfile` 虽不执行但可泄露敏感配置（数据库密码、API Key）

## 文件写入审计要点

写入漏洞需要三要素: 路径可控 + 内容可控 + 写入文件可被执行。

- **直接写 shell**: `file_put_contents($path, $content)` 中两个参数都用户可控时，直接写入 Webshell
- **日志注入链**: 日志记录用户输入 → 日志文件被 `include` 加载 → 间接代码执行。审查日志路径是否可预测、内容是否被过滤
- **配置文件覆盖**: 写入 `.htaccess`（使 `.jpg` 被解析为 PHP）或 PHP 配置文件（注入代码到 `<?php return [...];`）
- **Session 文件利用**: `session.save_path` 下的 session 文件内容部分用户可控，配合 LFI 实现 RCE

## 归档提取审计要点

- **Zip Slip**: `ZipArchive::extractTo()` 不验证条目名称中的 `../../`，恶意归档可向任意目录写文件
- **PharData**: 与 ZipArchive 同理，`extractTo()` 存在路径穿越风险
- **安全解压**: 解压前遍历条目名称，拒绝包含 `..` 的路径；或解压到临时目录后逐文件校验移动

## 竞争条件审计要点

- **TOCTOU**: `is_file($path)` 检查通过后、`unlink($path)` 执行前，攻击者替换文件为符号链接 → 删除任意文件
- **上传竞争**: 文件先保存再校验删除，窗口期内发起大量并发请求访问已上传的 PHP 文件
- **符号链接跟随**: `file_get_contents($userPath)` 若 `$userPath` 是符号链接则读取链接目标文件，绕过目录限制
- **原子操作**: `rename()` 是原子操作可用于安全替换；先写临时文件再 `rename` 到目标位置可避免竞争

## 检测清单

- [ ] 所有文件类 EVID_* 证据点已逐一审查
- [ ] 上传功能的扩展名验证方式已确认（白名单 vs 黑名单 vs 无验证）
- [ ] 上传存储路径是否在 Web 根内、是否可直接访问已验证
- [ ] include/require 的路径参数来源和过滤逻辑已追踪
- [ ] php://filter 等 Wrapper 在当前配置下的可利用性已评估
- [ ] file_put_contents/fwrite 的路径和内容来源已追踪
- [ ] 归档解压函数的条目名称校验已检查
- [ ] TOCTOU 模式（检查→操作间隔）已识别
- [ ] 过滤不充分的点已给出绕过思路或标"待验证"
- [ ] 严重度评分使用了统一公式，与 pipeline 一致
