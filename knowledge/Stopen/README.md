# Stopen — Automated Penetration Testing Agent

> OODA loop + Blackboard-driven + Multi-tool Integration

![Web UI](stopen/TPIAN/Web.png)

> **Disclaimer**: Stopen is intended **only for authorized security testing**
> (pentest engagements, CTF, security research on systems you own or have
> explicit permission to test). Do not use it for any illegal purpose. The
> authors are not liable for any misuse.

---

## 1. Quick Start

### 0.1 Clone

```powershell
git clone https://github.com/swfk2154/Stopen.git
cd Stopen
```

### 0.2 One-Click Install

```powershell
python install.py
```

The script automatically:
- **Installs Python dependencies**: `pip install -r requirements.txt` (FastAPI, aiohttp, cryptography, etc.)
- **Initializes storage directories**: creates `stopen/storage/logs/` and `stopen/storage/uploads/`

> Manual install: `pip install -r requirements.txt`

### 0.3 Build Frontend (Optional)

Skip if the pre-built frontend works fine. Rebuild if the UI page is blank:

```powershell
cd stopen/frontend
npm install
npx vite build
cd ../..
```

> Pre-built frontend is tracked in the repo — this step is usually not needed.

### 1.1 Start Backend

```powershell
cd Stopen
python run.py
```

| Argument | Description |
|----------|-------------|
| `--port 8081` | Custom port (default: 8080) |
| `--host 0.0.0.0` | Listen on all interfaces for LAN access (default) |
| `--host 127.0.0.1` | Localhost only |
| `--no-reload` | Disable hot reload |

Environment variable: `$env:STOPEN_PORT=8081`

### 1.2 Access WebUI

Open browser → `http://localhost:8080`

Local access is authenticated automatically. When accessing from another
machine over LAN, the UI shows a login panel — paste the token from
`stopen/storage/.auth_secret` on the server.

---

## 2. First-Time Setup

### 2.1 Configure API Key

WebUI → sidebar → **Configuration** → select LLM provider → enter API Key → enable → save

12 providers supported:

| Provider | Get API Key |
|----------|-------------|
| OpenAI | https://platform.openai.com/api-keys |
| Anthropic | https://console.anthropic.com/settings/keys |
| Google (Gemini) | https://aistudio.google.com/app/apikey |
| DeepSeek | https://platform.deepseek.com/api_keys |
| Kimi | https://platform.moonshot.cn/console/api-keys |
| MiniMax | https://platform.minimaxi.com/user-center/basic-information/interface-key |
| GLM (Zhipu) | https://open.bigmodel.cn/usercenter/apikeys |
| Doubao (ByteDance) | https://console.volcengine.com/ark/region:ark+cn-beijing/apiKey |
| Qwen | https://help.aliyun.com/zh/model-studio/developer-reference/get-api-key |
| SiliconFlow | https://cloud.siliconflow.cn/account/ak |
| Baichuan | https://platform.baichuan-ai.com/console/apikey |
| Custom | Any OpenAI-compatible endpoint |

> API Keys are **AES-encrypted** at `storage/config.enc` (key file at `storage/keyfile.key`), never stored in plaintext.

### 2.2 Configure MCP Servers (Optional)

MCP (Model Context Protocol) servers integrate external security tools into Stopen's Agent tool registry.

WebUI → **MCP Configuration** → Add server

| Server | Type | Address | Purpose |
|--------|------|---------|---------|
| Yakit | HTTP | `http://127.0.0.1:8082/mcp` | Port scan, FOFA search, subdomain enum, CVE query |
| Burp Suite | HTTP/SSE | `http://127.0.0.1:9876/sse` | Proxy capture, scanner, Repeater, Intruder |
| Wireshark (tshark) | Stdio | `tshark` | Network traffic capture and analysis |
| CSNAS (Colasoft) | Stdio | `cmdl.exe` | Network protocol analysis and forensics |

---

## 3. Features

### 3.1 Chat

Nav → **Chat**

Multi-turn LLM conversation interface with full streaming:

- **Streaming output**: tokens appear in real time via SSE
- **Reasoning visibility**: thinking-model reasoning (`reasoning_content` from
  DeepSeek-R1 / GLM-Thinking / Qwen-Thinking etc.) streams into a collapsible
  "思考过程" block
- **Tool calls in chat**: the assistant can invoke registered security tools
  (port scan, HTTP request, CVE query, codec...) mid-conversation; each call
  shows a compact card with arguments and output (max 8 tool rounds)
- **Multi-turn**: Context preserved across continuous Q&A
- **Model selector**: Dropdown showing only configured & enabled models
- **Conversation management**: sidebar list, create / switch / delete
- **Send**: Enter to send, Shift+Enter for new line

> Chat runs a lightweight tool loop (not the full OODA blackboard cycle) —
> suitable for Q&A, consulting, and quick assisted checks.

### 3.1.1 Dashboard

Nav → **Dashboard**

Aggregated stats view (`/api/stats`): tasks, vulnerabilities by severity,
active C2 sessions, listeners, webshells, conversations, skills, and tools —
with quick actions and system/MCP status cards.

### 3.1.2 Skills Library

Nav → **Skills Library**

Browse the built-in pentest/CTF knowledge base (`stopen/skills/*.md`) with a
reader pane; the same skill files are injected into Agent prompts by task type.

### 3.2 Agent Console

Nav → **Agent Console**

The Agent Console is Stopen's core feature, driving automated penetration testing via the OODA loop.

**Parameters**:

| Parameter | Description |
|-----------|-------------|
| Target | IP address / domain / URL |
| Goal | Optional task description |
| Task Type | Pentest / CTF / CTF Web / CTF Crypto |
| Role | Optional preset role for skill injection |
| Persistent Mode | Multi-cycle execution with auto-report per cycle |

**Penetration Flow**:

```
Target → Port Scan → Service Detection → Vuln Scan → CVE Query → Exploit → Report
```

**Interface**:

- **Left (Terminal)**: Real-time streaming output (thought process, tool calls, results)
- **Right (Blackboard panel)**:
  - **Facts**: Confirmed findings — open ports, web paths, CVEs, flags
  - **Intents**: Pending exploration directions — ports to scan, directories to brute
  - Use "Refresh" button to update manually

**Core Rules**:
- Every finding must be backed by tool output evidence (anti-hallucination gate)
- Auto-stop after 3 consecutive failures or 15 iterations
- CTF mode reports flag immediately upon discovery

### 3.3 WebShell Management

Nav → **WebShell**

Supports 3 mainstream Webshell protocols.

**Protocol Comparison**:

| Protocol | Transport | Key Derivation | Encryption |
|----------|-----------|----------------|------------|
| AntSword | `POST pass=system('cmd');` | Plaintext password, sends PHP code directly | None |
| Behinder | `POST pass=AES-128-CBC(payload)` | MD5(password)[:16] | AES-128-CBC |
| Godzilla | `POST pass=AES-128-CBC(payload)` | MD5(password+key_suffix)[:16] | AES-128-CBC |

**Features**:

| Feature | Description |
|---------|-------------|
| Add WebShell | Name / URL / password / type (PHP/ASP/ASPX/JSP) / protocol |
| Connection Test | Click test button, result shown inline (green=success, red=fail) |
| Delete | Confirm then permanently remove |
| Interactive Terminal | Command history, ↑↓, Ctrl+C, clear, quick buttons |
| File Manager | List directory / read / write / delete / create folder |

**Terminal Shortcuts**:

| Action | Effect |
|--------|--------|
| ↑ key | Previous command (up to 50 history entries) |
| ↓ key | Next command in history |
| Enter | Execute current command |
| Ctrl+C | Interrupt (shows ^C, returns to prompt) |
| `clear` | Clear terminal display |

**Quick Commands**: whoami / id / ls / pwd / uname -a / ipconfig

**File Manager Usage**:
1. Select a WebShell
2. Click "File Manager" tab
3. Enter path (default /), click "List Directory"
4. Click file name to read, click directory name to enter

![WebShell](stopen/TPIAN/Webshell-web.png)

### 3.4 C2 Framework

Nav → **C2 Panel**

C2 (Command & Control) framework for managing remote host control channels.

**Engine**: listeners run in **c2d**, a standalone Go daemon (`c2d/` in the
repo) — goroutine-per-connection scales to tens of thousands of concurrent
sessions. The Python backend stays the control plane (REST API, SQLite
sessions/tasks, payload generation); c2d registers sessions, pulls tasks and
reports results via internal bridge endpoints. If the Go binary is missing and
no Go toolchain is available, it automatically falls back to the legacy pure
Python listeners (identical wire protocol).

**Listener Types**:

| Type | Description | Use Case |
|------|-------------|----------|
| TCP Reverse | Reverse connection listener | Target can connect outbound |
| HTTP Beacon | HTTP polling communication | Strict firewall environments |
| WebSocket | WebSocket persistent connection (server-push task loop) | Low-latency bidirectional communication |

**Encryption** (configurable per listener):

| Type | Algorithm | Use Case |
|------|-----------|----------|
| AES-256-CTR | Symmetric encryption, random IV (128/192/256-bit keys supported) | Default, highest security |
| XOR | Simple XOR obfuscation | Maximum compatibility, no dependencies |

**Payload Generation**:

| Payload | Encryption | Description |
|---------|------------|-------------|
| Python (TCP) | AES-256-CTR | Full-featured Python TCP reverse shell |
| Python (HTTP) | AES-256-CTR | HTTP Beacon polling |
| Python (WS) | AES-256-CTR | WebSocket persistent connection |
| PowerShell (TCP) | AES-CBC | Windows-native, AES encrypted |
| Bash (TCP) | AES-256-CTR | Linux via Python process with AES |

**Custom Payload Templates**:
- CRUD operations via "Payload Templates" tab
- Supports 3 placeholders: `{host}`, `{port}`, `{secret}`
- Can auto-match listener secret key via `listener_id` parameter

> Note: HTTP and WebSocket listeners require the `aiohttp` library (legacy
> fallback only; the Go engine is dependency-free).

### 3.5 Vulnerability Management

Nav → **Vulnerabilities**

**Vulnerability Sources**:
- **Auto-imported**: Agent creates records automatically when querying CVEs
- **Manual**: Fill in title, target, severity, type, description, evidence

**Severity Levels**:

| Level | Color | Description |
|-------|-------|-------------|
| Critical | 🔴 Red | Remote RCE, severe impact |
| High | 🟠 Orange | High-risk, prioritize remediation |
| Medium | 🟡 Yellow | Medium-risk, requires attention |
| Low | 🔵 Blue | Low-risk information disclosure |
| Info | ⚪ Gray | Informational only |

**Status Workflow**: `open → confirmed → fixed → false_positive`

**Operations**:
- Create / edit / delete vulnerabilities
- Filter by severity or status
- Statistics panel: total / by severity / by status
- One-click Python PoC script generation (populated from vulnerability data)

### 3.6 Custom YAML Tools

Nav → **Custom Tools**

Create YAML-defined tools via UI without writing Python code, automatically registered into Agent tool registry.

**Two Modes**:

**Subprocess Mode** — Execute local command-line tools:

```yaml
name: nmap_scan
description: "Nmap port scan"
category: scanner
type: subprocess
command: ["nmap", "-sV", "-p", "{ports}", "{target}"]
parameters:
  target: { type: string, description: "Target IP/domain" }
  ports: { type: string, default: "80,443,8080" }
timeout: 120
```

**API Mode** — Call external HTTP interfaces:

```yaml
name: shodan_search
description: "Shodan search"
category: scanner
type: api
command: "https://api.shodan.io/shodan/host/search"
parameters:
  query: { type: string, description: "Search syntax" }
timeout: 30
```

**Workflow**:
1. Fill in name, description, type, command, parameter JSON, timeout
2. Click "Test" to verify the tool works
3. Click "Reload to Agent" to register into Agent tool list
4. The tool is now available in Agent Console

### 3.7 Reports & PoC Generation

Nav → **Tasks**

**Report Formats**:

| Format | Characteristics |
|--------|----------------|
| Markdown | Text format, easy to read and version-control |
| HTML | Styled tables, suitable for browser viewing |

**PoC Scripts**: Auto-generated Python verification scripts from vulnerability data, including:
- Target URL
- Vulnerability type and description
- HTTP request validation
- Formatted output

**Persistent Mode**: Agent auto-generates a report at the end of each cycle.

### 3.8 MCP Configuration

Nav → **MCP Configuration**

MCP (Model Context Protocol) server modes:

| Mode | Principle | Applicable |
|------|-----------|------------|
| HTTP | JSON-RPC 2.0 over HTTP | Yakit, Burp Suite and other HTTP API tools |
| Stdio | Subprocess stdin/stdout JSON-RPC | Wireshark, CSNAS and other CLI tools |

In Stdio mode, command and args are passed directly to subprocess — ensure the commands are trustworthy.

### 3.9 Role System

Nav → **Roles**

**6 Built-in Roles**:

| Role | Description |
|------|-------------|
| Pentest | Full flow — port scan → vuln scan → exploitation |
| CTF | Automated CTF challenge solving flow |
| Web Scan | Web security focused detection |
| API Test | API security testing |
| Recon | Information gathering only |
| Report | Result aggregation and reporting |

**Custom Roles**: Users can create roles with custom name, description, system prompt, and skill bindings.

### 3.10 Theme Switcher

Sidebar bottom: Light / Dark mode toggle. Persists via localStorage across page refreshes.

---

## 4. Testing

```powershell
pip install -r requirements-dev.txt
pytest
```

The suite (56 tests) covers the auth middleware (including the loopback-only
token endpoint regression), SQLite thread safety, webshell password encryption
at rest, config encryption, report/PoC generation, OODA helpers
(anti-hallucination gate, failure classification), LLM client streaming
parsing, and the chat tool-loop engine.

---

## 5. Project Structure

```
Stopen/
├── run.py                    # Backend entry (supports --port/--host)
├── install.py                # One-click install (pip deps + c2d build + storage/ init)
├── pytest.ini                # Test configuration
├── requirements.txt          # Runtime dependencies
├── requirements-dev.txt      # Dev/test dependencies (pytest)
├── .gitignore                # Git exclusion rules
├── README.md                 # English documentation
├── README_CN.md              # Chinese documentation
├── c2d/                      # Go C2 listener daemon (high-performance engine)
│   ├── main.go               # Control-plane API (--addr/--ctl-token/--backend-url)
│   ├── crypto.go             # AES-CTR / XOR (Python-compatible byte format)
│   ├── bridge.go             # Internal callbacks to Python backend
│   ├── listener_tcp.go       # TCP reverse listener
│   ├── listener_http.go      # HTTP beacon listener
│   ├── listener_ws.go        # WebSocket listener (server-push task loop)
│   ├── c2d.exe / c2d         # Prebuilt daemon binary (rebuilt by install.py)
│   └── crypto_test.go        # Cross-language crypto vectors (from Python)
├── tests/                    # pytest suite (auth/db/crypto/chat engine/C2 e2e/...)
├── stopen/
│   ├── main.py               # FastAPI app + lifespan + /api/stats + logs
│   ├── app_config/           # Configuration module
│   │   ├── encryption.py     # AES (Fernet) API key encryption
│   │   ├── providers.py      # 12 LLM provider definitions
│   │   ├── auth.py           # Bearer Token auth (token endpoint loopback-only)
│   │   ├── settings.py       # Global constants
│   │   └── logging_config.py # Logging setup
│   ├── models/               # Pydantic data models
│   │   ├── chat.py           # WebShell/message creation models
│   │   ├── c2.py             # Listener/session/task models
│   │   ├── task.py           # Pentest task model
│   │   └── report.py         # Report model
│   ├── routes/ (11 modules)  # FastAPI route modules
│   │   ├── agent.py          # OODA Agent SSE streaming
│   │   ├── c2.py             # C2 listener/session/payload CRUD
│   │   ├── chat.py           # Chat API + SSE streaming (reasoning/tools)
│   │   ├── config.py         # LLM provider config CRUD + test
│   │   ├── mcp_config.py     # MCP server CRUD + stdio support
│   │   ├── roles.py          # Role CRUD (built-in + custom)
│   │   ├── tasks.py          # Task management + report/PoC
│   │   ├── tools.py          # Tool listing + MCP status
│   │   ├── vulnerabilities.py# Vulnerability CRUD + stats
│   │   ├── webshell.py       # WebShell + file operation API (masked passwords)
│   │   └── yaml_tools.py     # Custom YAML tool CRUD + reload
│   ├── services/             # Business logic layer
│   │   ├── agent_loop_ooda.py # OODA core loop engine
│   │   ├── chat_engine.py     # Streaming chat with reasoning + tool loop
│   │   ├── blackboard.py      # Blackboard (Fact/Intent/Goal)
│   │   ├── c2_service.py      # C2 engine (listener/encryption/payload)
│   │   ├── webshell_service.py# 3-protocol WebShell
│   │   ├── db_service.py      # SQLite (13 tables, per-thread connections)
│   │   ├── llm_client.py      # LLM HTTP client (OpenAI/Anthropic, streaming)
│   │   ├── llm_service.py     # LLM service wrapper
│   │   ├── report_service.py  # Report + PoC generation
│   │   ├── skills_service.py  # Skill file loader
│   │   ├── tool_base.py       # Base tool abstract class
│   │   ├── tool_registry.py   # Tool registry singleton
│   │   └── tools/             # Built-in pentest tools
│   │       ├── scanners.py    # Port scan/dir brute/subdomain/CVE
│   │       ├── web_tools.py   # HTTP request/browser/Burp
│   │       ├── crypto_tools.py# 29 encoding/crypto operations
│   │       ├── space_search.py# FOFA/Hunter/Shodan search
│   │       ├── js_discovery.py# JS asset discovery/unauth/dir enum
│   │       ├── mcp_bridge.py  # MCP bridge (HTTP + Stdio)
│   │       └── yaml_loader.py # YAML custom tool loader
│   ├── frontend/             # React SPA frontend
│   │   ├── index.html         # Dual-theme design tokens (Inter + JetBrains Mono)
│   │   ├── src/
│   │   │   ├── main.jsx       # React entry
│   │   │   └── App.jsx        # Full SPA (12 pages, SVG icon set, login overlay)
│   │   └── dist/              # Vite build output (tracked in repo)
│   ├── skills/ (8 files)     # Pentest knowledge base (.md)
│   │   ├── recon.md           # Reconnaissance methodology
│   │   ├── vuln_discovery.md  # Vulnerability discovery methodology
│   │   ├── exploitation.md    # Exploitation methodology
│   │   ├── post_exploit.md    # Post-exploitation methodology
│   │   ├── report.md          # Report writing methodology
│   │   ├── ctf_web.md         # CTF web challenge guide
│   │   ├── ctf_crypto.md      # CTF cryptography guide
│   │   └── ctf_reverse.md     # CTF reverse engineering guide
│   ├── TPIAN/                # Screenshots
│   │   ├── Web.png            # WebUI homepage screenshot
│   │   └── Webshell-web.png   # WebShell page screenshot
│   └── storage/              # Runtime data (.gitignored)
│       ├── stopen.db          # SQLite main database
│       ├── config.enc         # AES-encrypted API key config
│       ├── keyfile.key        # Encryption key file
│       ├── .auth_secret       # Auth token
│       └── logs/              # Runtime logs
```

---

## 6. Development

### Build Frontend

```powershell
cd stopen/frontend
npm install
npx vite build          # Production build
npx vite                # Dev mode (default port 3000)
```

### Backend Development

```powershell
# Hot reload (auto-restart on code changes)
python run.py

# No hot reload
python run.py --no-reload

# Custom port
python run.py --port 8081
```

### Code Standards

- Backend: Python 3.10+, FastAPI, SQLite, full async/await
- Frontend: React 18 + Vite, single-file SPA, CSS variable theming
- Logging: Auto-rotating log files at `storage/logs/stopen.log`
- All emoji output replaced with ASCII `[tag]` format (Windows GBK terminal compatible)

---

## 7. Security

1. **API Key encrypted storage**: Fernet (AES) symmetric encryption on disk, never plaintext
2. **Auth**: All `/api/*` routes (except `/api/health`) require Bearer Token (constant-time compare), auto-generated at `storage/.auth_secret`
3. **Token endpoint is loopback-only**: `/api/auth/config` refuses remote clients — LAN visitors must paste the token into the login panel; it can no longer be fetched anonymously
4. **CORS**: Whitelist — localhost only (no wildcard)
5. **Default listen**: `0.0.0.0` (LAN accessible by default). Use `--host 127.0.0.1` to restrict to localhost; remote access always requires the token
6. **C2 communication**: AES-256-CTR / XOR encryption (per-listener key)
7. **C2 secrets**: Automatically masked as `****` in API responses
8. **WebShell passwords**: AES-encrypted at rest in SQLite (shared `keyfile.key`), masked as `****` in list APIs; legacy plaintext rows are migrated transparently on read
9. **`.gitignore`**: Excludes `*.db`, `*.enc`, `*.key`, `logs/`, `reports/`, `.auth_secret`
10. **YAML tools / MCP Stdio**: Command passed directly to subprocess — ensure commands are trustworthy

> Antivirus note: C2/WebShell modules (`c2_service.py`, `webshell_service.py`)
> may be flagged by Windows Defender or other AV and quarantined. If files
> disappear after a commit, add the project folder to your AV exclusion list
> and restore with `git checkout -- <file>`.

---

## 8. Architecture

### Hybrid engine: Go data plane + Python control plane

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

### OODA Loop + Blackboard

```
┌──────────────────────────────────────────────┐
│  OODA Loop (max 15 iterations)              │
│  ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐  │
│  │Observe│──→│Orient│──→│Decide│──→│ Act  │  │
│  └───┬───┘   └───┬───┘   └───┬───┘   └───┬──┘│
│      │           │           │           │   │
│      ▼           ▼           ▼           ▼   │
│  ┌──────────────────────────────────────────┐│
│  │          Blackboard                      ││
│  │  Facts: confirmed findings               ││
│  │    ports/services/vulns/web paths/flags  ││
│  │  Intents: pending directions             ││
│  │    port scans/dir brute/exploit          ││
│  │  Goal: target state + achieved flag      ││
│  └──────────────────────────────────────────┘│
└──────────────────────────────────────────────┘
```

### Reflexion Escalation Engine

When tool calls fail consecutively, payload level auto-escalates:

```
L0: Original payload
L1: URL/Base64 encoding
L2: Escape/double-write
L3: Command substitution/Unicode
L4: Obfuscation/change attack surface
```

### Anti-Hallucination Gate

- All findings must originate from tool output text
- Flag must match character-for-character in evidence
- Prevents LLM from fabricating results

---

## 9. Known Issues

1. **No HTTPS/WSS support**: HTTP and WebSocket listeners support plaintext only. Use a reverse proxy (e.g. Nginx) for TLS termination in production.
2. **No rate limiting**: All API endpoints currently have no rate limiting.
3. **Anthropic tool-loop**: Anthropic-native models do not support the chat tool loop yet (OpenAI-compatible endpoints only).
4. **Legacy listener scaling**: the Python fallback listeners are single-connection-per-task asyncio loops — fine for a few sessions; use the Go engine for real concurrency.

---

*Stopen v1.0 — Automated Penetration Testing Agent*
