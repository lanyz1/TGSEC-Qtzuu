# HTTP 响应分析技巧

分析 HTTP 响应中隐藏线索和常见陷阱的速查表。

## 空响应 / 静默失败

- **HTTP 200 + Content-Length: 0（响应体为空）**：代码被执行了但产生了空输出
  - PHP：可能是 include() 执行了 PHP 文件但遇到语法错误（被 error_reporting(0) 静默）
  - 解决：不要用 `system('cat file.php')` 读 PHP 文件（输出会被 PHP 引擎再次解析），用 `file_get_contents() + echo`
  - Python/Node：检查是否有异常被 try/except 静默吞掉

## 注入无效果

- **所有注入变体（包括 `'` 和正常值）返回完全相同的响应**：
  - 很可能**缺少必要的 POST 参数**（如 `submit=1`），导致后端逻辑根本没执行
  - 用 `analyze_response` 重新分析表单，确保包含所有 input/button/select/textarea 的 name 参数
  - 检查响应的 Etag/Content-Length 是否与静态页面相同（完全一致 = 后端没处理你的输入）

## 文件包含 (LFI)

- **php://filter 返回 "not found"**：目标用了 `file_exists()` 检查，PHP wrapper 不通过
  - 改用日志投毒：先在 User-Agent 写入 PHP 代码，再包含 `/var/log/apache2/access.log`
  - 或尝试 `php://filter/read=convert.base64-encode/resource=index` (不带 .php 后缀)

## SQL 注入输出

- **EXTRACTVALUE/UPDATEXML 输出上限只有 32 字符！**
  - FLAG 通常 60-80 字符，一次提取必定不完整
  - **优先用 UNION SELECT**（无截断限制）！列数不对就继续尝试 1-10 列
  - 只有 UNION 确实不可用时才用 EXTRACTVALUE，但**必须用 Python 脚本自动分段提取**
  - **绝不手动拼接分段结果** — LLM 数 hex 字符极易出错

## 认证相关

- **POST 登录后 HTTP 302 + Set-Cookie** → 这是认证流程的关键响应，必须观察 Set-Cookie 内容
  - 如果 cookie 值是 Base64 编码 → 解码查看是否为序列化数据
  - 如果 cookie 值是 JWT → 用 `jwt_decode` 解析
- **HTTP 200 但无 Set-Cookie** → 确认 `http_request` 是否跟随了重定向（POST 默认不跟随，但如果手动设了 follow_redirects=true 则会丢失中间 Set-Cookie）

## 命令注入输出过滤

- **输出被过滤/解析**（如 Ping 工具只显示统计）：
  1. 先从错误消息获取输出格式（如 "expected format: X packets transmitted..."）
  2. 用 `%0a` 换行（**放在输入最前面**，让原命令参数为空→失败），注入 echo 伪造匹配格式
  3. 将 flag 嵌入到格式的某个字段中
  4. **不要在 %0a 前面加正常 IP！** 否则原命令正常执行，其输出先匹配正则

## Flag 验证

在报告任何 flag{} 之前：
```
python3 -c "flag='你提取的flag'; print(len(flag)); assert len(flag) >= 64"
```
如果从 SQL 注入 LENGTH() 获得了期望长度，必须验证 `len(flag) == expected_len`。
