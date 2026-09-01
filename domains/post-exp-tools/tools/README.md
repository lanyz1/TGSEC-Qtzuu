# SecAtlas Tools

> 实战工具集 — Python + Go + Shell，覆盖 Web/网络/密码学/漏洞利用

## 工具索引

| 工具 | 语言 | 用途 | 用法示例 |
|------|------|------|---------|
| `jwt-analyzer.py` | Python | JWT 分析/alg:none/RS→HS/弱密钥爆破 | `python3 jwt-analyzer.py <token> --test-none` |
| `cache-poison-detector.go` | Go | Web 缓存投毒探测器 | `go run cache-poison-detector.go -url https://target.com` |
| `js-extractor.py` | Python | JS 文件敏感信息提取 | `python3 js-extractor.py https://target.com/app.js -r` |
| `redis-exploit.py` | Python | Redis 未授权利用 | `python3 redis-exploit.py -H 10.0.0.5 ssh-key` |

## 维护脚本

| 脚本 | 用途 |
|------|------|
| `mule-auto-learn.sh` | 自动学习新知识 |
| `mule-auto-maintain.sh` | 仓库自动维护 |
| `mule-review-prs.sh` | PR 自动审查 |
| `mule-merge-pr.sh` | PR 自动合并 |
| `mule-comment-pr.sh` | PR 评论 |
| `mule-tempmail.sh` | 临时邮箱工具 |

## 贡献工具

1. 放到 `tools/` 目录
2. 确保文件头有 shebang 和用法说明
3. 更新此 README
4. PR
