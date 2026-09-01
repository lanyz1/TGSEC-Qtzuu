# Stopen — 自动化渗透测试 Agent

> OODA 循环 + 黑板驱动 + 多工具集成

![Web 界面](stopen/TPIAN/Web.png)

> **免责声明**：Stopen 仅面向**授权安全测试**场景（渗透测试项目、CTF 竞赛、
> 自有系统或已获明确授权的目标研究）。严禁用于任何非法用途，使用者对自身
> 行为负责，作者不承担任何滥用导致的法律责任。

---

## 一、快速启动

### 0.1 克隆项目

```powershell
git clone https://github.com/swfk2154/Stopen.git
cd Stopen
```

### 0.2 一键安装

```powershell
python install.py
```

脚本会自动完成：
- **安装 Python 依赖**：通过 `pip install -r requirements.txt` 安装 FastAPI、aiohttp、cryptography 等依赖
- **初始化存储目录**：创建 `stopen/storage/logs/` 和 `stopen/storage/uploads/`

> 也可以手动安装：`pip install -r requirements.txt`

### 0.3 构建前端（可选）

如果前端页面空白或需要更新：

```powershell
cd stopen/frontend
npm install
npx vite build
cd ../..
```

> 预构建的前端已包含在仓库中，通常不需要此步骤。

### 1.1 启动后端

```powershell
cd Stopen
python run.py
```

| 参数 | 说明 |
|------|------|
| `--port 8081` | 指定端口（默认 8080） |
| `--host 0.0.0.0` | 监听所有网卡（默认，局域网可访问） |
| `--host 127.0.0.1` | 仅本机可访问 |
| `--no-reload` | 禁用热重载 |

环境变量: `$env:STOPEN_PORT=8081`

### 1.2 访问 WebUI

打开浏览器 → `http://localhost:8080`

本机访问自动认证；局域网内其他机器访问时，界面会弹出登录面板，
粘贴服务器上 `stopen/storage/.auth_secret` 文件中的 Token 即可。

---

## 二、首次配置

### 2.1 配置 API Key

WebUI → 左侧导航 → **配置** → 选择 LLM 提供商 → 输入 API Key → 勾选启用 → 保存

目前支持 12 家 LLM 提供商：

| 提供商 | 获取 Key 地址 |
|--------|---------------|
| OpenAI | https://platform.openai.com/api-keys |
| Anthropic | https://console.anthropic.com/settings/keys |
| Google (Gemini) | https://aistudio.google.com/app/apikey |
| DeepSeek | https://platform.deepseek.com/api_keys |
| Kimi (月之暗面) | https://platform.moonshot.cn/console/api-keys |
| MiniMax | https://platform.minimaxi.com/user-center/basic-information/interface-key |
| 智谱 GLM (Z.ai) | https://open.bigmodel.cn/usercenter/apikeys |
| 字节豆包 (Doubao) | https://console.volcengine.com/ark/region:ark+cn-beijing/apiKey |
| 通义千问 (Qwen) | https://help.aliyun.com/zh/model-studio/developer-reference/get-api-key |
| SiliconFlow | https://cloud.siliconflow.cn/account/ak |
| 百川 (Baichuan) | https://platform.baichuan-ai.com/console/apikey |
| 自定义 | 任意 OpenAI 兼容接口 |

> API Key 会被 **AES 加密存储**在 `storage/config.enc`，密钥文件为 `storage/keyfile.key`，不会明文泄漏。

### 2.2 配置 MCP 服务器（可选）

MCP（Model Context Protocol）服务器可将外部安全工具集成到 Stopen 的 Agent 工具列表中。

WebUI → **MCP 配置** → 添加服务器

| 服务器 | 类型 | 地址 | 功能 |
|--------|------|------|------|
| Yakit | HTTP | `http://127.0.0.1:8082/mcp` | 端口扫描、FOFA 搜索、子域名枚举、CVE 查询 |
| Burp Suite | HTTP/SSE | `http://127.0.0.1:9876/sse` | 代理抓包、扫描器、Repeater、Intruder |
| Wireshark (tshark) | Stdio | `tshark` | 网络流量捕获与分析 |
| 科来 (CSNAS) | Stdio | `cmdl.exe` | 网络协议分析与取证 |

---

## 三、功能详解

### 3.1 对话（Chat）

导航 → **对话**

对话模块提供与 LLM 的全流式自然语言交互界面：

- **流式输出**：SSE 逐 token 实时渲染，光标跟随
- **思考过程可视化**：推理模型（DeepSeek-R1 / GLM-Thinking / Qwen-Thinking 等）的
  `reasoning_content` 实时流入可折叠的「思考过程」面板
- **工具调用可视化**：助手可在对话中调用已注册的安全工具（端口扫描、HTTP 请求、
  CVE 查询、编解码等），每次调用以卡片展示参数与输出（最多 8 轮）
- **多轮对话**：上下文持续，支持连续问答
- **模型选择**：顶部下拉菜单位选择要使用的 LLM 模型（仅显示已配置 API Key 且已启用的模型）
- **对话管理**：左侧面板列出所有对话，新建 / 切换 / 删除
- **发送方式**：Enter 发送，Shift+Enter 换行

> 对话模块使用轻量工具循环（非完整 OODA 黑板循环），适用于咨询问答与快速辅助验证。

### 3.1.1 仪表盘

导航 → **仪表盘**

聚合统计视图（`/api/stats`）：任务、漏洞（按严重度着色）、C2 活跃会话、监听器、
WebShell、对话、技能与工具数量，附快速操作与系统/MCP 状态卡片。

### 3.1.2 技能库

导航 → **技能库**

浏览内置渗透/CTF 知识库（`stopen/skills/*.md`），左侧列表 + 右侧阅读面板；
同一批技能文件会按任务类型注入 Agent 提示词。

### 3.2 Agent 渗透控制台

导航 → **Agent 控制台**

Agent 控制台是 Stopen 的核心功能入口，使用 OODA 循环驱动自动化渗透测试。

**参数说明**：

| 参数 | 说明 |
|------|------|
| 目标 | IP 地址 / 域名 / URL |
| 目标说明 | 可选的任务补充描述 |
| 任务类型 | 渗透测试 / CTF 模式 / CTF Web / CTF 密码学 |
| 角色 | 可选，选择后注入对应技能提示词 |
| 持久化模式 | 复选框勾选，多周期执行，每周期自动出报告 |

**渗透流程**：

```
目标 → 端口扫描 → 服务识别 → 漏洞扫描 → CVE 查询 → 利用 → 报告
```

**界面说明**：

- **左侧终端区域**：实时显示 Agent 的流式输出（思考过程、工具调用、结果）
- **右侧黑板面板**：
  - **Facts**（已确认发现）：端口开放、Web 路径、CVE 信息、Flag 等
  - **Intents**（待探索方向）：待扫描的端口、待爆破的目录等
  - 使用「刷新」按钮手动更新状态

**核心规则**：
- 每个发现必须有工具输出原文佐证（反幻觉门）
- 连续失败 3 次或达到 15 次迭代自动停止
- CTF 模式下找到 flag 后立即报告

### 3.3 WebShell 管理

导航 → **WebShell**

WebShell 模块支持三种主流 Webshell 协议的连接与操作。

**三种协议对比**：

| 协议 | 传输方式 | 密钥生成 | 加密 |
|------|----------|----------|------|
| 蚁剑 (AntSword) | `POST pass=system('cmd');` | 明文密码直接发送 PHP 代码 | 无 |
| 冰蝎 (Behinder) | `POST pass=AES-128-CBC(payload)` | MD5(password)[:16] | AES-128-CBC |
| 哥斯拉 (Godzilla) | `POST pass=AES-128-CBC(payload)` | MD5(password + key_suffix)[:16] | AES-128-CBC |

**功能列表**：

| 功能 | 说明 |
|------|------|
| 添加 WebShell | 填写名称 / URL / 密码 / 类型 (PHP/ASP/ASPX/JSP) / 协议 |
| 测试连接 | 点击「测试」按钮，结果显示在卡片下方（绿=成功，红=失败） |
| 删除 | 点击「删除」→ 确认 → 从列表中移除 |
| 交互式终端 | 命令历史 / ↑↓ / Ctrl+C / clear / 快捷按钮 |
| 文件管理器 | 列目录 / 读文件 / 写文件 / 删除 / 新建目录 |

**交互式终端快捷键**：

| 操作 | 效果 |
|------|------|
| ↑ 键 | 上一条命令历史（最多 50 条） |
| ↓ 键 | 下一条命令历史 |
| Enter | 执行当前命令 |
| Ctrl+C | 中断（显示 ^C 后回到提示符） |
| `clear` | 清空终端显示 |

**快捷命令按钮**：whoami / id / ls / pwd / uname -a / ipconfig

**文件管理器操作**：
1. 先选择对应的 WebShell
2. 点击「文件管理」标签
3. 输入路径（默认 /），点击「列目录」
4. 点击文件名读文件，点击目录名进入子目录

![WebShell](stopen/TPIAN/Webshell-web.png)

### 3.4 C2 框架

导航 → **C2 面板**

C2（Command & Control）框架用于管理远程主机的控制信道。

**引擎架构**：监听器运行在独立的 **c2d Go 守护进程**（仓库 `c2d/` 目录）——
goroutine/连接模型可承载数万并发会话。Python 后端保持控制面角色
（REST API / SQLite 会话任务 / Payload 生成）；c2d 通过内部 bridge 接口
注册会话、拉取任务、回写结果。若 Go 二进制缺失且本机无 Go 工具链，
自动回退 legacy 纯 Python 监听器（线上协议逐字节兼容）。

**监听器类型**：

| 类型 | 说明 | 适用场景 |
|------|------|----------|
| TCP Reverse | 反向连接监听器 | 目标可主动连接外网 |
| HTTP Beacon | HTTP 轮询通信 | 防火墙严格的环境 |
| WebSocket | WebSocket 持久连接（服务端主动推送任务） | 需要低延迟双向通信 |

**加密方式**（每个监听器独立配置）：

| 加密 | 算法 | 适用场景 |
|------|------|----------|
| AES-256-CTR | 对称加密，IV 随机（兼容 128/192/256 位密钥） | 默认推荐，安全性最高 |
| XOR | 简单异或加密 | 兼容性优先，无依赖 |

**Payload 生成**：

| Payload 类型 | 加密 | 说明 |
|-------------|------|------|
| Python (TCP) | AES-256-CTR | Python TCP 反弹 Shell，功能完整 |
| Python (HTTP) | AES-256-CTR | HTTP Beacon 轮询 |
| Python (WS) | AES-256-CTR | WebSocket 持久连接 |
| PowerShell (TCP) | AES-CBC | Windows 原生，AES 加密通信 |
| Bash (TCP) | AES-256-CTR | Linux 原生，通过 Python 进程实现加密 |

**自定义 Payload 模板**：
- 通过「Payload 模板」标签页进行 CRUD 操作
- 模板内容支持三个占位符：`{host}`、`{port}`、`{secret}`
- 生成 Payload 时可通过 `listener_id` 参数自动匹配监听器密钥

**注意**：HTTP 和 WebSocket 监听器依赖 `aiohttp` 库（仅 legacy 回退路径需要；Go 引擎零依赖）。

### 3.5 漏洞管理

导航 → **漏洞**

**漏洞来源**：
- **自动写入**：Agent 运行过程中查询 CVE 时自动创建漏洞记录
- **手动创建**：填写标题、目标、严重度、类型、描述、证据

**严重度分级**：

| 级别 | 颜色 | 说明 |
|------|------|------|
| Critical | 🔴 红色 | 可远程 RCE，影响严重 |
| High | 🟠 橙色 | 高危漏洞，需优先处理 |
| Medium | 🟡 黄色 | 中危漏洞，需关注 |
| Low | 🔵 蓝色 | 低危信息泄露 |
| Info | ⚪ 灰色 | 信息类提示 |

**状态工作流**：`open → confirmed → fixed → false_positive`

**操作**：
- 创建 / 编辑 / 删除漏洞
- 按严重度或状态筛选
- 统计面板：总数 / 严重度分布 / 状态分布
- 一键生成 Python PoC 验证脚本（基于漏洞信息填充）

### 3.6 自定义 YAML 工具

导航 → **自定义工具**

用户可以无需编写 Python 代码，通过 UI 创建 YAML 格式的工具定义，自动注册到 Agent 工具注册表。

**两种模式**：

**子进程模式** — 执行本地命令行工具：

```yaml
name: nmap_scan
description: "Nmap 端口扫描"
category: scanner
type: subprocess
command: ["nmap", "-sV", "-p", "{ports}", "{target}"]
parameters:
  target: { type: string, description: "目标 IP/域名" }
  ports: { type: string, default: "80,443,8080" }
timeout: 120
```

**API 模式** — 调用外部 HTTP 接口：

```yaml
name: shodan_search
description: "Shodan 搜索"
category: scanner
type: api
command: "https://api.shodan.io/shodan/host/search"
parameters:
  query: { type: string, description: "搜索语法" }
timeout: 30
```

**操作流程**：
1. 填写名称、描述、类型、命令、参数 JSON、超时
2. 点击「测试」验证工具是否能正常运行
3. 点击「🔄 重载到 Agent」将工具注册到 Agent 工具列表
4. 在 Agent 控制台中即可调用该工具

### 3.7 报告与 PoC 生成

导航 → **任务**

**报告格式**：

| 格式 | 特点 |
|------|------|
| Markdown | 文本格式，易于阅读和版本控制 |
| HTML | 带样式表格，适合直接浏览器查看 |

**PoC 脚本**：基于漏洞信息自动生成 Python 验证脚本，包含：
- 目标 URL
- 漏洞类型和描述
- HTTP 请求验证
- 输出格式化

**持久化模式**：Agent 每完成一个周期自动生成周期报告。

### 3.8 MCP 配置

导航 → **MCP 配置**

MCP（Model Context Protocol）服务器的两种运行模式：

| 模式 | 原理 | 适用 |
|------|------|------|
| HTTP | JSON-RPC 2.0 over HTTP | Yakit、Burp Suite 等提供 HTTP API 的工具 |
| Stdio | 子进程 stdin/stdout JSON-RPC | Wireshark、科来等命令行工具 |

Stdio 模式下，command 和 args 会直接启动子进程，请确保命令可信。

### 3.9 角色系统

导航 → **角色**

**预定义角色**（6 个）：

| 角色 | 说明 |
|------|------|
| 渗透测试 (Pentest) | 端口扫描→漏扫→利用的完整流程 |
| CTF 模式 | 自动 CTF 解题流程 |
| Web 扫描 | 侧重 Web 安全检测 |
| API 测试 | API 安全测试 |
| 信息收集 | 仅信息收集阶段 |
| 报告生成 | 结果汇总和报告 |

**自定义角色**：用户可自行创建角色，配置名称、描述、系统提示词和关联的技能。

### 3.10 主题切换

侧边栏底部切换亮色 / 暗色模式，通过 localStorage 持久化，页面刷新后保持。

---

## 四、测试

```powershell
pip install -r requirements-dev.txt
pytest
```

测试套件（56 个用例）覆盖：认证中间件（含 token 接口仅本机可读的安全回归）、
SQLite 多线程并发、WebShell 密码加密存储、配置加密、报告/PoC 生成、OODA 辅助
函数（反幻觉门 / 失败分类）、LLM 流式解析（reasoning / tool_calls 分片聚合）、
对话引擎工具循环。

---

## 五、项目结构

```
Stopen/
├── run.py                    # 后端启动入口（支持 --port / --host 参数）
├── install.py                # 一键安装脚本（pip 依赖 + c2d 构建 + 初始化 storage/）
├── pytest.ini                # 测试配置
├── requirements.txt          # 运行时依赖
├── requirements-dev.txt      # 开发/测试依赖（pytest）
├── .gitignore                # Git 排除规则
├── README.md                 # 英文说明文档
├── README_CN.md              # 中文说明文档（本文件）
├── c2d/                      # Go C2 监听器守护进程（高性能引擎）
│   ├── main.go               # 控制面 API（--addr / --ctl-token / --backend-url）
│   ├── crypto.go             # AES-CTR / XOR（与 Python 端逐字节兼容）
│   ├── bridge.go             # 内部 bridge 回调（注册会话/拉任务/回结果）
│   ├── listener_tcp.go       # TCP 反向监听器
│   ├── listener_http.go      # HTTP Beacon 监听器
│   ├── listener_ws.go        # WebSocket 监听器（服务端主动推送）
│   ├── c2d.exe / c2d         # 预编译守护进程二进制（install.py 可重建）
│   └── crypto_test.go        # 跨语言加密向量测试（Python 生成）
├── tests/                    # pytest 测试套件
├── stopen/
│   ├── main.py               # FastAPI 应用入口 + lifespan + /api/stats + 日志
│   ├── app_config/           # 系统配置模块
│   │   ├── encryption.py     # AES (Fernet) 加密存储 API Key
│   │   ├── providers.py      # 12 家 LLM 厂商定义（模型列表、API 地址）
│   │   ├── auth.py           # Bearer Token 认证（token 接口仅限本机读取）
│   │   ├── settings.py       # 全局常量（路径、迭代上限等）
│   │   └── logging_config.py # 日志配置
│   ├── models/               # Pydantic 数据模型
│   │   ├── chat.py           # WebShell、消息创建模型
│   │   ├── c2.py             # 监听器、会话、任务模型
│   │   ├── task.py           # 渗透任务模型
│   │   └── report.py         # 报告模型
│   ├── routes/ (11 模块)     # FastAPI 路由
│   │   ├── agent.py          # OODA Agent SSE 流式执行
│   │   ├── c2.py             # C2 监听器/会话/Payload 模板 CRUD
│   │   ├── chat.py           # 对话 API + SSE 流式（思考/工具调用）
│   │   ├── config.py         # LLM 提供商配置 CRUD + 测试
│   │   ├── mcp_config.py     # MCP 服务器 CRUD + stdio 支持
│   │   ├── roles.py          # 角色 CRUD（内置 + 自定义）
│   │   ├── tasks.py          # 任务管理 + 报告/PoC 生成
│   │   ├── tools.py          # 工具列表 + MCP 状态
│   │   ├── vulnerabilities.py# 漏洞 CRUD + 统计
│   │   ├── webshell.py       # WebShell + 文件操作 API（密码脱敏）
│   │   └── yaml_tools.py     # 自定义 YAML 工具 CRUD + 重载
│   ├── services/             # 业务逻辑层
│   │   ├── agent_loop_ooda.py # OODA 核心循环引擎
│   │   ├── chat_engine.py     # 流式对话引擎（思考透传 + 工具循环）
│   │   ├── blackboard.py      # 黑板（Fact/Intent/Goal 数据结构）
│   │   ├── c2_service.py      # C2 引擎（监听器管理 + 加密 + Payload 生成）
│   │   ├── webshell_service.py# WebShell 三协议实现（蚁剑/冰蝎/哥斯拉）
│   │   ├── db_service.py      # SQLite 数据库操作（13 张表，线程级连接）
│   │   ├── llm_client.py      # LLM HTTP 客户端（OpenAI/Anthropic，流式）
│   │   ├── llm_service.py     # LLM 服务封装
│   │   ├── report_service.py  # 报告 + PoC 脚本生成
│   │   ├── skills_service.py  # 技能文件加载
│   │   ├── tool_base.py       # 工具抽象基类
│   │   ├── tool_registry.py   # 工具注册表单例
│   │   └── tools/             # 内置渗透工具实现
│   │       ├── scanners.py    # 端口扫描/目录枚举/子域名/CVE
│   │       ├── web_tools.py   # HTTP 请求/浏览器/Burp
│   │       ├── crypto_tools.py# 29 种编解码加密操作
│   │       ├── space_search.py# FOFA/Hunter/Shodan 搜索引擎
│   │       ├── js_discovery.py# JS 资产发现/未授权/目录枚举
│   │       ├── mcp_bridge.py  # MCP 桥接器（HTTP + Stdio）
│   │       └── yaml_loader.py # YAML 自定义工具运行时加载
│   ├── frontend/             # React SPA 前端
│   │   ├── index.html         # 入口 + 设计令牌（Inter + JetBrains Mono 双字体）
│   │   ├── src/
│   │   │   ├── main.jsx       # React 入口
│   │   │   └── App.jsx        # 完整 SPA（12 个页面，SVG 图标，登录浮层）
│   │   └── dist/              # Vite 构建产物（已纳入版本管理）
│   ├── skills/ (8 个)        # 渗透技能知识库 (.md 文件)
│   │   ├── recon.md           # 信息收集方法论
│   │   ├── vuln_discovery.md  # 漏洞发现方法论
│   │   ├── exploitation.md    # 漏洞利用方法论
│   │   ├── post_exploit.md    # 后利用方法论
│   │   ├── report.md          # 报告生成方法论
│   │   ├── ctf_web.md         # CTF Web 解题指南
│   │   ├── ctf_crypto.md      # CTF 密码学指南
│   │   └── ctf_reverse.md     # CTF 逆向指南
│   ├── TPIAN/                # 界面截图
│   │   ├── Web.png            # WebUI 首页截图
│   │   └── Webshell-web.png   # WebShell 页面截图
│   └── storage/              # 运行时数据（.gitignore 排除）
│       ├── stopen.db          # SQLite 主数据库
│       ├── config.enc         # AES 加密的 API Key 配置
│       ├── keyfile.key        # 加密密钥文件
│       ├── .auth_secret       # 认证 token
│       └── logs/              # 运行日志
```

---

## 六、开发指南

### 构建前端

前端使用 Vite + React 构建，开发前需要安装 npm 依赖：

```powershell
cd stopen/frontend
npm install
npx vite build          # 生产构建
npx vite                # 开发模式（默认端口 3000）
```

### 后端开发

```powershell
# 热重载模式（修改代码自动重启）
python run.py

# 不带热重载
python run.py --no-reload

# 指定端口
python run.py --port 8081
```

### 代码规范

- 后端：Python 3.10+，FastAPI，SQLite，全 async/await
- 前端：React 18 + Vite，单文件 SPA，CSS 变量主题
- 日志：自动滚动日志文件，位置 `storage/logs/stopen.log`
- 所有 emoji 输出已替换为 ASCII `[标签]` 格式（Windows GBK 终端兼容）

---

## 七、安全说明

1. **API Key 加密存储**：使用 Fernet (AES) 对称加密存储在磁盘上，非明文
2. **认证机制**：所有 `/api/*` 路由（除 `/api/health` 外）需要 Bearer Token 认证（常量时间比较防时序侧信道），token 自动生成并持久化到 `storage/.auth_secret`
3. **Token 接口仅限本机**：`/api/auth/config` 拒绝远程客户端匿名读取 —— 局域网访问必须通过登录面板手动输入 token
4. **CORS**：白名单机制，仅允许 `localhost:3000/8080/8081`，无通配符
5. **默认监听**：`0.0.0.0`（局域网可访问）。如仅本机使用请 `--host 127.0.0.1`；远程访问一律需要 token
6. **C2 通信**：AES-256-CTR / XOR 加密（每个监听器独立配置密钥）
7. **C2 密钥**：API 返回时自动掩码为 `****`
8. **WebShell 密码**：SQLite 中 AES 加密存储（共用 `keyfile.key`），列表 API 返回 `****`；旧明文数据读取时自动兼容
9. **`.gitignore`**：已排除 `*.db`、`*.enc`、`*.key`、`logs/`、`reports/`、`.auth_secret`
10. **YAML 工具 / MCP Stdio**：command 直接传递给子进程，请确保添加的命令可信

> 杀软提示：C2/WebShell 模块（`c2_service.py`、`webshell_service.py`）可能被
> Windows Defender 等杀毒软件报毒隔离。若文件莫名消失，请将项目目录加入杀软
> 白名单，并用 `git checkout -- <file>` 恢复。

---

## 八、架构

### 混合引擎：Go 数据面 + Python 控制面

```
┌────────────────────────────────────────────────────────┐
│  WebUI (React SPA)                                     │
└──────────────────────────┬─────────────────────────────┘
                           │ REST + SSE
┌──────────────────────────▼─────────────────────────────┐
│  Python 控制面 (FastAPI)                                │
│  REST API / SQLite(13表) / LLM / OODA / 报告 / Payload │
└──────────▲─────────────────────────────▲───────────────┘
           │ bridge 内部接口              │ 启动/停止(ctl API)
┌──────────┴─────────────────────────────┴───────────────┐
│  c2d (Go 守护进程, 数据面)                               │
│  TCP 反向 / HTTP Beacon / WebSocket 监听器               │
│  AES-256-CTR / XOR 加解密 · goroutine/连接 · 数万并发   │
└────────────────────────────────────────────────────────┘
```

### OODA 循环 + 黑板驱动

```
┌──────────────────────────────────────────────┐
│  OODA Loop (最多 15 次迭代)                  │
│  ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐  │
│  │Observe│──→│Orient│──→│Decide│──→│ Act  │  │
│  │ 观察  │   │ 定位  │   │ 决策  │   │ 行动 │  │
│  └───┬───┘   └───┬───┘   └───┬───┘   └───┬──┘│
│      │           │           │           │   │
│      ▼           ▼           ▼           ▼   │
│  ┌──────────────────────────────────────────┐│
│  │           黑板 (Blackboard)              ││
│  │  Facts: 已确认的发现                      ││
│  │   端口/服务/漏洞/Web路径/Flag             ││
│  │  Intents: 待探索的方向                     ││
│  │   端口扫描/目录爆破/漏洞利用               ││
│  │  Goal: 渗透目标 + 达成标记                 ││
│  └──────────────────────────────────────────┘│
└──────────────────────────────────────────────┘
```

### Reflexion 递进引擎

当工具调用连续失败时，自动递进载荷等级：

```
L0: 原始 payload
L1: URL/Base64 编码
L2: 转义/双写
L3: 命令替换/Unicode
L4: 混淆/换攻击面
```

### 反幻觉门

- 所有"发现"必须有工具输出原文佐证
- Flag 必须逐字出现在工具输出中才接受
- 防止 LLM 编造渗透结果

---

## 九、已知问题

1. **HTTPS/WSS 不支持**：HTTP 和 WebSocket 监听器目前只支持明文协议。生产环境如需加密，建议使用反向代理（如 Nginx）终止 TLS。
2. **速率限制**：所有 API 端点目前无速率限制。
3. **Anthropic 工具循环**：Anthropic 原生模型暂不支持对话工具循环（仅支持 OpenAI 兼容端点）。
4. **legacy 监听器并发**：Python 回退监听器为单任务 asyncio 循环，适合少量会话；真实并发场景请使用 Go 引擎。

---

*Stopen v1.0 — 自动化渗透测试 Agent*
