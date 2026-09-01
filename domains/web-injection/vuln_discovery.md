# 漏洞发现 (Vulnerability Discovery)

## 目标
从信息收集结果中发现可利用的漏洞。

## 方法

### 1. Web 漏洞
- **SQL 注入**: 在参数后加 `'` `"` 测试报错，检查响应中的数据库错误
- **XSS**: 在输入框/参数插入 `<script>alert(1)</script>`
- **文件包含**: 测试 `?page=../../etc/passwd`
- **SSRF**: 测试 `?url=http://127.0.0.1:8080`
- **文件上传**: 尝试上传 webshell 文件

### 2. CVE 查询
- 使用 `query_cve` 查询已知漏洞
- 输入：服务名+版本号（如 "Apache 2.4.49"）
- 重点关注：RCE、SQLi、文件包含的 CVE

### 3. 逻辑漏洞
- 越权访问：修改 user/id 参数
- 验证绕过：尝试修改/删除 cookie
- 重放攻击：重复发送同一请求

### 4. 认证测试
- 弱口令测试（常见组合）
- JWT 解码检查
- Session 固定测试
