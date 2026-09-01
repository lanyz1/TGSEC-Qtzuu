---
name: efficiency-rules
description: "渗透测试效率规则。防止盲目枚举、工具阻塞等低效行为，确保在有限时间内最大化漏洞发现数量。当开始渗透测试、发现扫描工具运行时间过长、陷入盲目爆破循环、或需要决策下一步攻击方向时使用。每轮渗透开始前建议阅读"
metadata:
  tags: "efficiency,enumeration,timeout,optimization,渗透效率,枚举,超时"
  category: "general"
---

# 渗透测试效率规则

## ⛔ 规则 1: 禁止盲目手动枚举

**触发场景**: 用 curl 逐个测试路径（如 /upload, /admin/upload, /bank/upload ...）

**规则**:
- 对同一类型路径（如文件上传端点），手动 curl 最多尝试 **3 个最可能的路径**
- 3 次 404 后 **立即停止手动枚举**，改用工具：
  ```bash
  # ✅ 用 gobuster/dirsearch 一次扫完
  gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -q -t 20 --timeout 10s 2>&1 | head -50
  ```
- ⛔ **绝不**逐个 HEAD 请求 20+ 个猜测路径 — 这是浪费时间

## ⛔ 规则 2: 长时间工具必须加 timeout

**触发场景**: 运行 sqlmap、nikto、dirsearch 等扫描工具

**规则**:
- 所有扫描工具必须用 `timeout` 包裹，最长 **8 分钟**
- 必须用 `tee` 保留输出，超时后检查已有结果
  ```bash
  # ✅ 正确
  timeout 480 sqlmap -u 'http://target/page?id=1' --batch --level 2 --risk 2 2>&1 | tee /tmp/sqlmap.log
  # 超时后
  tail -80 /tmp/sqlmap.log
  ```
- ⛔ **禁止** `sleep N && tail` 轮询等待 — 浪费轮次时间

## ⛔ 规则 3: 无果时快速切换方向

**触发场景**: 连续多次尝试同一类漏洞未果

**规则**:
- 同一端点 + 同一漏洞类型，**5 个不同 payload 无果后切换方向**
- 切换前用 `evidence_save` 记录已测试内容（避免下一轮重复）
- 优先切换到未测试的漏洞类型，而非同一类型的更多变体

## 效率优先级

| 行为 | 效率 | 说明 |
|------|------|------|
| 用工具批量扫描 | ⭐⭐⭐ | gobuster/sqlmap/nikto 一次覆盖大量路径 |
| 针对性手动测试 | ⭐⭐ | 基于分析结果精确测试 3-5 个高概率点 |
| 盲目手动枚举 | ⛔ | 逐个 curl 猜测路径，效率极低 |
