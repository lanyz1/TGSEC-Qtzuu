---
name: stopen
description: "Use when running automated pentesting with OODA loop."
version: 1.0.0
---

# Stopen (local) — /root/Stopen

Automated Penetration Testing Agent (swfk2154/Stopen). OODA loop + Blackboard architecture, FastAPI + Web UI.

## Content

| Area | Path | Description |
|---|---|---|
| **Core App** | `stopen/` | FastAPI backend, frontend, models, routes, services |
| **Skills** (8) | `stopen/skills/` | recon, vuln_discovery, exploitation, post_exploit, ctf_web, ctf_crypto, ctf_reverse, report |
| **Tool Services** | `stopen/services/tools/` | crypto_tools, js_discovery, mcp_bridge, scanners, space_search, web_tools, yaml_loader |
| **Routes** | `stopen/routes/` | agent, c2, chat, config, mcp_config, roles, tasks, tools, vulnerabilities, webshell, yaml_tools |
| **C2** | `c2d/` | C2 daemon |
| **Install** | `install.py` | One-click install (pip + storage init) |
| **Frontend** | `stopen/frontend/` | Web UI (dist + src) |

## Architecture

OODA loop (Observe-Orient-Decide-Act) + Blackboard-driven multi-tool integration.

## Usage

```
cd /root/Stopen
python install.py
python run.py
```

## Notes

- FastAPI + Web UI for interactive pentesting
- Blackboard architecture for shared knowledge state
- 8 pentest skills covering full chain
- MCP bridge integration
- C2 daemon for command/control
