---
name: insecure-source-code-management
description: >-
  Source control and artifact exposure (.git, .svn, .hg, backups, .env). Use when recon finds VCS paths, 403 on hidden dirs, or backup/config leaks during authorized testing.
---

# SKILL: Insecure Source Code Management

> **AI LOAD INSTRUCTION**: This skill covers detection of exposed version-control metadata, common backup artifacts, and related misconfigurations. Use only in **authorized** assessments. Treat recovered credentials and URLs as sensitive; do not exfiltrate real data beyond scope. For broad discovery workflow, cross-load [recon-for-sec](../recon-for-sec/SKILL.md) and [recon-and-methodology](../recon-and-methodology/SKILL.md) when those skills exist in the workspace.

## 0. QUICK START

High-value paths to probe first (GET or HEAD, respect rate limits):

```http
/.git/HEAD
/.git/config
/.svn/entries
/.svn/wc.db
/.hg/requires
/.bzr/README
/.DS_Store
/.env
```

**Routing note**: quickly probe these paths first; for full recon workflow, load methodology from `recon-for-sec` and `recon-and-methodology` before deeper testing.

---

## 1. GIT EXPOSURE

### Detection

- **`/.git/HEAD`** — valid repo often returns plain text like:

```text
ref: refs/heads/main
```

- **`/.git/config`** — may expose `remote.origin.url`, user identity, or embedded credentials.
- **`/.git/index`**, **`/.git/objects/`** — partial object store access enables reconstruction with the right tools.

### 403 vs 404

- **`404`** — path likely absent or fully blocked at the edge.
- **`403` on `/.git/`** — directory may **exist** but listing is denied; still try direct file URLs:

```http
/.git/HEAD
/.git/config
/.git/logs/HEAD
/.git/refs/heads/main
```

A **403 on the directory** plus **200 on `HEAD`** strongly indicates exposure.


### Key files to prioritize

| Path | Why it matters |
|------|----------------|
| `.git/config` | Remotes, credentials, hooks paths |
| `.git/logs/HEAD` | Commit history, reflog-style leakage |
| `.git/refs/heads/*` | Branch tips, commit SHAs |
| `.git/packed-refs` | Packed branch/tag refs |
| `.git/objects/**` | Object blobs for reconstruction |

---

## 2. SVN EXPOSURE

### Detection

- **SVN before 1.7**: **`/.svn/entries`** — XML or text metadata listing paths and revisions.
- **SVN ≥ 1.7**: **`/.svn/wc.db`** — SQLite working copy database (`PRAGMA table_info` after download).

Example probe:

```http
GET /.svn/entries HTTP/1.1
GET /.svn/wc.db HTTP/1.1
```


---

## 3. MERCURIAL EXPOSURE

### Detection

- **`/.hg/requires`** — small text file listing repository features; confirms Mercurial metadata.

```http
GET /.hg/requires HTTP/1.1
GET /.hg/store/ HTTP/1.1
```

---

## 4. OTHER LEAKS

### Bazaar (Bzr)

- Probe **`/.bzr/README`** and **`/.bzr/branch-format`** for Bazaar metadata.

### macOS `.DS_Store`

- **`/.DS_Store`** can encode directory and filename listings.
- Tools: **`gehaxelt/ds-store`**, **`lijiejie/ds_store_exp`** — parse `.DS_Store` offline.

### Backup and config artifacts

Probe (adjust for app root and naming conventions):

```text
/.env
/backup.zip
/backup.tar.gz
/wwwroot.rar
/backup.sql
/config.php.bak
/.config.php.swp
```

### Web server misconfiguration signal (example: NGINX)

- **`location /.git { deny all; }`** — may return **403** for `/.git/` while still allowing or denying specific subpaths depending on rules.
- **403 on a protected location** can **confirm the route exists**; always distinguish from **404** on non-existent paths.

---

## 5. DECISION TREE

1. **Probe `/.git/HEAD`** → `ref: refs/heads/` pattern? → run **git-dumper / GitTools / GitHacker**; review `config` and `logs/HEAD` for secrets.
2. **Else probe `/.hg/requires`** → success? → **mercurial dumper**.
3. **Else probe `/.bzr/README`** → Bazaar tooling or manual path walk.
4. **Parallel**: fetch **`/.DS_Store`**, **`/.env`**, common **backup extensions** on app root and parent paths.
5. **Interpret status codes**: **403 on directory** + **200 on specific files** → treat as **high priority** for file-by-file extraction.

---

## 6. RELATED ROUTING

- From **[recon-for-sec](../recon-for-sec/SKILL.md)** — scope-safe discovery, crawling, and fingerprinting before deep VCS tests.
- From **[recon-and-methodology](../recon-and-methodology/SKILL.md)** — structured methodology and evidence handling.

**Note**: coordinate with recon skills—set scope and request rate first, then run targeted VCS/backup validation.

---

## 7. 2026 EMERGING TECHNIQUES

### 7.1 CI/CD Supply-Chain Attacks — TeamPCP Campaign (2025-2026)

The dominant 2025-2026 source-code threat is **CI/CD supply-chain compromise** via stolen repository and pipeline credentials, driven by the threat cluster **TeamPCP** (aka DeadCatx3, PCPcat, PersyPCP, ShellForce), active since November 2025.

#### Trivy Supply-Chain Attack — CVE-2026-33634 (CVSS 9.4)

On March 19, 2026, TeamPCP force-pushed a malicious `v0.69.4` release tag to Aqua Security's `aquasecurity/trivy` repository. **Git tag poisoning**: 76 of 77 release tags in `aquasecurity/trivy-action` were redirected to malicious commits. Root cause: incomplete credential rotation following a February 2026 GitHub Actions misconfiguration.

**Key insight**: git tags are **mutable pointers** — signed commits don't protect against malicious tag redirection. **Tag signing (GPG/Sigstore gitsign)** and immutable release artifacts (SLSA provenance) are the mitigation.

#### LiteLLM Backdoor (PyPI)

On March 24, 2026, TeamPCP compromised the AI model proxy package **LiteLLM**, publishing malicious versions `1.82.7` and `1.82.8`. Three-stage payload:
1. **Credential harvester** — SSH keys, cloud credentials, Kubernetes secrets, crypto wallets, `.env` files
2. **Kubernetes lateral-movement toolkit** — deploys privileged pods to every node
3. **Persistent systemd backdoor** (`sysmon.service`) polling `checkmarx[.]zone/raw` for additional binaries

#### Megalodon — Mass CI/CD Pipeline Poisoning

A distinct campaign using throwaway/compromised GitHub accounts to inject malicious workflow files containing **base64-encoded payloads** harvesting 30+ secret categories: AWS access keys, GCP OAuth tokens, Azure instance role credentials, SSH private keys, OIDC tokens, Kubernetes configurations.

### 7.2 Docker Layer Secret Exposure (2026)

Docker images built without proper multi-stage builds or secret management leak credentials in image layers:

```bash
# Extract secrets from Docker image layers
docker history --no-trunc target/image:latest
# Look for ENV lines with credentials

# Pull and inspect all layers
docker save target/image:latest -o image.tar
tar xf image.tar
# Each layer is a .tar.gz — grep for secrets
for layer in */layer.tar; do
    tar xf "$layer" -C /tmp/layer-extract 2>/dev/null
    grep -r "AWS_ACCESS_KEY\|SECRET\|PASSWORD\|PRIVATE_KEY" /tmp/layer-extract/
done
```

**2026-specific**: AI model Docker images (SGLang, vLLM, TGI) frequently embed API keys, HuggingFace tokens, and cloud credentials in layers.

### 7.3 Kubernetes Secret Misconfiguration

```bash
# Exposed Kubernetes secrets via etcd
curl -k https://etcd-ip:2379/v2/keys/secrets/
# Or via kubectl if kubelet API is exposed
curl -k https://node-ip:10250/pods | grep -A5 "secret"

# Common 2026 pattern: AI/ML pods with mounted cloud credentials
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].env}{"\n"}'
```

### 7.4 AI Model File Leaks

AI model files (`.gguf`, `.pt`, `.safetensors`, `.bin`) may contain embedded credentials or metadata:

```bash
# Scan GGUF model files for embedded strings
strings model.gguf | grep -iE "key|secret|token|password|api"

# PyTorch pickle files may contain malicious code
python3 -c "import pickletools; pickletools.dis(open('model.pt','rb'))"
# Look for __reduce__ entries — these execute on load
```

### 7.5 GitHub Internal Repository Breach (May 2026)

In May 2026, an employee device compromise led to exfiltration of **3,800+ internal GitHub repositories**; TeamPCP listed the source code for sale (~$50,000). This illustrates that even the platform hosting source code is a viable target.

### 7.6 2026 Source Code Management Testing Checklist

```
□ Check for git tag poisoning — compare local vs remote tag SHAs
□ Scan Docker images for secrets in layers (docker history + layer extraction)
□ Audit CI/CD workflows for base64-encoded payloads and external fetches
□ Check Kubernetes pods for mounted cloud credentials (especially AI/ML pods)
□ Scan AI model files (.gguf, .pt) for embedded credentials
□ Verify GitHub Actions use OIDC instead of long-lived secrets
□ Check for .env files in Docker build contexts (.dockerignore)
□ Audit git tags for GPG/Sigstore signatures (unsigned tags = mutable)
□ Scan PyPI/npm packages for typosquatting and dependency confusion
□ Check for exposed .git on cloud storage (S3 static websites)
```
