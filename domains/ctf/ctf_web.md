# CTF Web — Web 安全 CTF 题

## 目标
找到 Web 题目中的 flag。

## 方法

### 1. 目录扫描
- 使用 `dir_brute` 扫目录
- 默认字典扩展：php,html,txt,zip,tar,git.bak

### 2. 源码审计
- 查看页面源代码（Ctrl+U）
- 检查 JS 文件中的隐藏逻辑
- 注意 HTML 注释中的提示

### 3. 参数篡改
- GET/POST 参数修改
- Cookie 修改（admin=1, role=admin）
- HTTP 头伪造（X-Forwarded-For）

### 4. 常见 CTF 考点
- **文件包含**: `?page=php://filter/convert.base64-encode/resource=flag`
- **命令执行**: `?cmd=cat /flag`
- **SQL 注入**: `' or 1=1 --`
- **反序列化**: 修改序列化数据中的属性值
- ** SSTI**: `{{config}}` `{{7*7}}`

### 5. 编码/加密绕过
- Base64 双重编码
- URL 编码绕过 WAF
- Unicode 正规化绕过

### 6. Flag 格式
- `flag{...}`, `FLAG{...}`, `ctf{...}`, `CTF{...}`
