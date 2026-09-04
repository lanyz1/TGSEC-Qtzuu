# HTTP/HTTPS 请求记录代理

基于 [mitmproxy 12.2.3](https://mitmproxy.org/) 的代理服务器，同时支持 **HTTP 与 HTTPS**（HTTPS 经 MITM 解密后才能拿到路径/参数/body），把流经代理的**所有请求包**按 **完整 URL**（协议+主机+路径）分类落盘，用于接口与参数清点。

监听端口、日志目录均可参数化配置。

> 📐 内部设计与实现原理（架构、数据流、落盘格式、关键决策、续跑机制）见 [设计文档](../docs/代理服务器设计文档.md)。

---

## 1. 安装

```powershell
python -m pip install -r proxy/requirements.txt
```

## 2. 启动

```powershell
# 默认监听 127.0.0.1:24304，日志写到 <项目根>\proxy-logs
python proxy/start.py

# 自定义端口与日志目录
python proxy/start.py --port 9090 --log-dir logs\proxy

# 只记录目标主机（过滤浏览器后台噪声）
python proxy/start.py --target-hosts example.com,api.example.com
```

首次启动会在 mitmproxy 默认 CA 目录 自动生成 CA 证书 `mitmproxy-ca-cert.pem`。按 `Ctrl+C` 停止。

### 启动参数

| 参数 | 默认 | 说明 |
|------|------|------|
| `--port` | `24304` | 监听端口（用 `--config` 且未显式时取 `config.proxy_port`） |
| `--host` | `127.0.0.1` | 监听地址（仅本机） |
| `--log-dir` | `<项目根>/proxy-logs` | 日志目录 |
| `--target-hosts` | 空（全部） | 逗号分隔的目标主机过滤（子串匹配） |
| `--body-cap` | `1048576` | 原始请求 body 落盘截断字节数（0=不限） |
| `--param-value-cap` | `100` | 参数样本值最大字符数（超出截断） |
| `--resp-preview-cap` | `200` | 响应体预览落盘字节数（仅文本类响应 page/api/other；0=关闭） |
| `--scope` | 空（全部） | 范围限制，仅记录范围内请求；可多次指定（任一匹配即记录） |
| `--scope-regex` | 关 | 把 `--scope` 的值都当正则（对完整 URL 做 search） |
| `--exclude` | 空（不排除） | 排除规则，命中则不记录（优先级高于 `--scope`）；可多次指定，语法同 `--scope` |
| `--exclude-regex` | 关 | 把 `--exclude` 的值都当正则 |
| `--config` | 无 | 从 config.json 读 scope/exclude/regex（与门禁同源）；与 `--scope`/`--exclude` 互斥 |

### 范围限制 `--scope`（域名 / 路径 / 正则）

配置后**仅记录范围内的请求**，范围外的完全不落盘。可多次指定，多条之间「任一匹配即记录」。与 `--target-hosts` 同时配置时取**交集**。

**默认字面匹配**：
- **纯域名**（不含 `/`）：按主机精确或子域匹配。`--scope TGSEC.com` 记录 `TGSEC.com` 与 `*.TGSEC.com`，但**不**记录 `notTGSEC.com`。
- **带路径**（含 `/`）：按 URL 前缀匹配。`--scope http://www.TGSEC.com/pentest/`，或不带协议的 `--scope www.TGSEC.com/pentest/`（不带协议时忽略 http/https）。

**正则模式**（加 `--scope-regex`）：每条 `--scope` 当正则，对完整 URL 做 `search`。

```powershell
# 仅记录某域名（含子域）
python proxy/start.py --scope TGSEC.com
# 仅记录某路径下
python proxy/start.py --scope http://www.TGSEC.com/pentest/
# 多个范围（OR）
python proxy/start.py --scope api.TGSEC.com --scope www.TGSEC.com/admin/
# 正则：只记录 /api/users 或 /api/login
python proxy/start.py --scope-regex --scope "/api/(users|login)(\?|$)"
```

> 端口注意：带 scheme 的路径前缀在非标准端口下需自带端口（如 `http://host:8080/x/`），或改用域名 / 正则。

### 排除限制 `--exclude`（范围内再剔除）

在 `--scope` 命中的范围内**再排除**指定 URL，命中即不记录（**优先级高于 `--scope`**）。语法与 `--scope` 完全一致
（纯域名→主机/子域；带路径→URL 前缀；加 `--exclude-regex` 则按正则），可多次指定、任一命中即排除。
典型用途：排除 `logout` / 注销等会破坏测试会话的链接，或高风险操作端点。

```powershell
# 记录 pentest 目录，但排除注销链接（避免会话被踢）
python proxy/start.py --scope www.TGSEC.com:8080/pentest/ --exclude www.TGSEC.com:8080/pentest/logout.php
# 正则排除所有 logout / signout
python proxy/start.py --scope TGSEC.com --exclude-regex --exclude "/(logout|signout)(\?|$)"
```

### 配置来源 `--config`（与门禁同源，推荐流程内使用）

范围/排除同时被**代理记录**与**广度门禁**消费。为避免两处手工配置漂移，代理可用 `--config` 直接读项目
`config.json` 的 `scope`/`exclude`/`scope_regex`/`exclude_regex` 及 `proxy_port`（门禁读的是同一份，端口亦同源），天然一致。
`--config` 与 `--scope`/`--exclude` **互斥**（二选一）；不带 `--config` 时按命令行参数走（适合临时/通用抓包）。

```powershell
# 范围/排除/端口全部来自 config.json（未显式 --log-dir 时默认写到 config 同目录下的 proxy-logs）
python proxy/start.py --config pentest-data\www-TGSEC-com-8080\config.json
```

## 2.1 停止

在代理终端按 `Ctrl+C` 即可停止。也可用 `stop.py` 按端口结束（可脚本化、跨会话可靠，用于报告阶段收尾）：

```powershell
# 默认结束 127.0.0.1:24304 上的监听进程
python proxy/stop.py
# 指定端口
python proxy/stop.py --port 9090
# 从 config 读 proxy_port（与 start.py --config 同源）
python proxy/stop.py --config pentest-data\www-TGSEC-com-8080\config.json
```

端口解析优先级：`--port` > `--config` 的 `proxy_port` > 默认 `24304`。**幂等**——端口无监听进程（已停止）时正常退出、不报错。

---

## 3. 客户端路由配方（临时，不持久化）

代理跑起来后，让客户端指向它（`<PORT>` 用实际端口，`<CA>` = mitmproxy 启动日志显示的默认 CA 证书）：

```powershell
# curl —— 每条命令显式指定（最干净，零残留）
curl -x http://127.0.0.1:<PORT> --cacert "<CA>" https://target/api?x=1
#   或跳过证书校验： curl -x http://127.0.0.1:<PORT> -k https://target/...

# curl —— 仅当前 PowerShell 会话内生效（关窗即失效）
$env:HTTP_PROXY  = "http://127.0.0.1:<PORT>"
$env:HTTPS_PROXY = "http://127.0.0.1:<PORT>"
$env:CURL_CA_BUNDLE = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem"
curl https://target/api?x=1

# 浏览器（Playwright）—— 启动参数追加
--proxy-server http://127.0.0.1:<PORT> --ignore-https-errors
```

---

## 4. 日志输出

日志目录下产出三类文件：

```
<log-dir>/
├── url_index.jsonl          # 成功请求(2XX/3XX)的 URL 清单，每 URL 一行
├── failed_index.jsonl       # 失败请求(4XX/5XX/无响应)的 URL 清单（备查，字段同上 + status_codes）
├── requests/
│   ├── URL00001.log         # 该 URL 全部原始请求报文（成功+失败，含响应头 + 文本类响应体预览），追加写
│   └── URL00002.log
└── params/
    ├── URL00001.json        # 该 URL 参数详情（仅「成功且有参数」才生成）
    └── URL00002.json
```

**唯一编码**：`URL` 前缀 + 5 位递增序号（`URL00001`…），既作清单 `id`，也作日志/参数文件名。
路径标识 = **完整 URL**（协议 + 主机 + 路径，不含 query）；同一 URL 的不同请求方法合并为一条，http 与 https 的同一路径视为不同 URL、分别成条。

### 4.1 `url_index.jsonl`（路径清单）

每路径一行 JSON：

```json
{"id":"URL00001","url":"https://example.com/api/login","methods":["GET","POST"],
 "category":"api","content_types":["application/json"],
 "param_count":3,"param_names":["password","remember","username"],
 "request_count":12,"first_seen":"2026-06-26T10:00:00","last_seen":"2026-06-26T10:30:00"}
```

- `param_count` / `param_names`：该路径出现过的**全部去重参数名**（合并 query 与各类 body）。
- `request_count`：该路径总请求次数。
- `category`：依据响应 Content-Type**结合请求路径/后缀**判定的 URL 类别——`page`（页面）/ `api`（接口）/ `js`（脚本）/ `resource`（资源）/ `other`（其它）/ `unknown`（无响应）。同一路径出现多种响应类型时，按优先级 **page > api > js > resource > other** 取最高者。
- `content_types`：该路径见过的所有响应 MIME（去重），即分类依据。

**URL 分类规则**（取 MIME 主类型、忽略 charset）：

| 类别 | 响应 Content-Type |
|------|------------------|
| `page` | `text/html`、`application/xhtml+xml` |
| `js` | 含 `javascript`/`ecmascript`（独立成类，供门禁反查 js 清单完整性） |
| `resource` | `text/css`、`image/*`、`font/*`、`audio/*`、`video/*`、`application/pdf`、`application/wasm`、`application/octet-stream`、`application/zip`/`gzip`、各类字体 |
| `api` | 含 `json`、`application/xml`、`text/xml`、`*+xml`、`application/grpc*`、`protobuf`、`text/csv` |
| `other` | 有响应但不属于以上（如 `text/plain`） |
| `unknown` | 从未拿到响应（仅请求失败被记录过） |

> 注：`image/svg+xml` 归 `resource`（按 `image/` 前缀优先判定，避免被 `*+xml` 误判为 `api`）。
>
> 注：**路径/后缀纠偏**——分类以响应 Content-Type 为基础，但当请求路径特征表明是**动态端点**（脚本后缀 `.php`/`.jsp`/`.asp` 等，或路径含 `/api/`、`/ajax/`、`/rest/` 等）却返回资源型 MIME（如**图片验证码** `captcha.php` 返回 `image/png`）时，纠正为 `api`，避免此类接口被误判为 `resource` 而在后续挖掘中被漏掉。静态后缀（`.png`/`.css`/`.woff` 等）优先级高于路径信号，`/api/img/logo.png` 仍判 `resource`。

### 4.2 `failed_index.jsonl`（失败请求清单）

把**失败**请求从主清单分流到此备查，避免污染成功探测的清单与参数。
- **失败** = HTTP **4XX/5XX** 或**无响应**（连接失败/超时/TLS 失败）；**成功** = 有响应且状态码 `< 400`（2XX/3XX）。
- 字段与 `url_index.jsonl` 一致，额外多 `status_codes`（失败状态码分布，无响应记 `no-response`）：

```json
{"id":"URL00007","url":"http://x/admin","methods":["GET"],"category":"page",
 "content_types":["text/html"],"status_codes":{"404":2,"no-response":1},
 "param_count":1,"param_names":["t"],"request_count":3,"first_seen":"...","last_seen":"..."}
```

**成功 / 失败落盘规则**：
- 成功请求 → `url_index.jsonl` + `params/<id>.json`。
- 失败请求 → `failed_index.jsonl`（**不**写 `params/` 详情）。
- 原始报文 → 不论成功失败都写 `requests/<id>.log`，**编码统一**。
- 一个 URL **既有成功又有失败**：在 `url_index`（成功统计）与 `failed_index`（失败统计）各一条、**同一 `id`**；`requests/<id>.log` 含其全部报文；`params/<id>.json` 仅含成功参数。
- 一个 URL **只有失败**：仅在 `failed_index` + `requests/<id>.log`，无 `url_index` 条目、无 `params/<id>.json`。

### 4.3 `requests/<id>.log`（原始请求报文）

以**二进制追加**写入，文本请求正常可读、文件上传等二进制 body 原样保留。每条记录 = 请求原始报文 + 响应头（若有）+ 文本类响应体预览（若有）：

```
###### [URL00001 #37] 2026-06-26T10:30:00 | POST https://example.com/api/login ######
--- REQUEST ---
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"admin","password":"x"}

--- RESPONSE HEADERS ---
HTTP/1.1 200 OK
Content-Type: application/json

--- RESPONSE BODY (preview: 200Byte only) ---
{"code":0,"msg":"success","data":{"token":"eyJhbGci...
<...truncated>
============================================================
```

无响应（超时/连接失败/TLS 失败）时该块为 `--- NO RESPONSE ---`。
响应记**头部** + **文本类响应体前 200 字节预览**（仅 `page`/`api`/`other` 类响应；`js`/图片/字体/二进制等 `resource` 不预览，避免落入二进制字节；`--resp-preview-cap 0` 可完全关闭）。预览取**已解压**响应体的前 N 字节，达到上限时以 `<...truncated>` 标记，用于挖掘阶段快速判断端点行为、选取有效测试基线。

### 4.4 `params/<id>.json`（参数详情）

记录每个参数的**来源**、**数据类型**、**参数名**与一个**样本值**（截断至 `--param-value-cap`，默认 100 字符）：

```json
{
  "id": "URL00001",
  "url": "https://example.com/api/login",
  "param_count": 4,
  "params": [
    {"name": "redirect",    "source": "query",         "type": "string", "sample_value": "/home"},
    {"name": "username",    "source": "json",          "type": "string", "sample_value": "admin"},
    {"name": "profile.age", "source": "json",          "type": "number", "sample_value": "30"},
    {"name": "avatar",      "source": "multipart-file","type": "file",   "sample_value": "photo.png (image/png)"}
  ]
}
```

支持的参数来源（`source`）：

| source | 对应请求格式 |
|--------|-------------|
| `query` | URL 查询字符串 |
| `json` | `application/json`（嵌套展平为点路径，数组折叠下标） |
| `form` | `application/x-www-form-urlencoded` |
| `multipart-field` | `multipart/form-data` 普通字段 |
| `multipart-file` | `multipart/form-data` 文件字段（`type=file`，样本记文件名+类型） |

数据类型（`type`）：`string` / `number` / `boolean` / `file` / `array` / `object` / `null`。

---

## 5. 行为说明

- **不去重**：`requests/<id>.log` 记录该 URL **每一次**请求；`url_index.jsonl` / `failed_index.jsonl` / `params/<id>.json` 为聚合视图。
- **成功/失败分流**：成功(2XX/3XX)进 `url_index` + `params`；失败(4XX/5XX/无响应)进 `failed_index`、不写参数详情；原始报文统一进 `requests/<id>.log`。
- **崩溃安全**：原始请求逐条 `fsync` 追加；清单与参数详情用临时文件 + 原子替换重写。
- **重启续跑**：再次启动时从既有 `url_index.jsonl` + `failed_index.jsonl` + `params/*.json` 重建状态，编码沿用、成功/失败次数各自累加。

## 6. 故障排查

| 现象 | 处理 |
|------|------|
| `未找到 mitmproxy` | 先执行第 1 步安装 |
| curl 报 TLS/证书错误 | `--cacert` 指向 CA，或临时用 `-k`；确认代理已启动 |
| 请求没被记录 | 确认客户端已指向代理；若设了 `--target-hosts`，确认目标主机匹配 |
| 端口被占用 | 换 `--port`，并同步客户端代理地址 |
