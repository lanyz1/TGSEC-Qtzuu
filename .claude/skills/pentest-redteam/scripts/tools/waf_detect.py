#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF 类型识别: 发探测请求→根据响应头/内容特征判断 WAF
用法:
  python waf_detect.py -u https://target.com
  python waf_detect.py -u https://target.com/path?q=1' OR '1'='1
"""
import argparse, re, ssl, sys, urllib.request, urllib.error

WAF_FINGERPRINTS = [
    ("Cloudflare", {"cf-ray", "cf-request-id", "__cfduid"}),
    ("ModSecurity", {"Mod_Security", "mod_security", "ModSecurity"}),
    ("AWS WAF", {"x-amzn-RequestId", "x-amz-cf-id"}),
    ("Akamai", {"X-Akamai-Transformed", "akamai"}),
    ("F5 BigIP", {"BIG-IP", "F5-TrafficShield", "X-WA-Info"}),
    ("Imperva", {"incap_ses_", "visid_incap_", "X-Iinfo"}),
    ("Sucuri", {"sucuri", "X-Sucuri-ID"}),
    ("FortiWeb", {"FortiWeb"}),
    ("Barracuda", {"barracuda"}),
    ("Citrix NetScaler", {"ns_af=", "citrix_ns_id"}),
    ("WordFence", {"wordfence_"}),
    ("Nginx WAF", {"nginx-waf"}),
    ("Radware", {"X-SL-CompBy"}),
    ("Kona/SiteDefender", {"akamaighost"}),
]

def detect(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    # 正常请求
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    findings = []
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            hdrs = str(r.headers).lower()
            body = r.read().decode("utf-8","ignore").lower()
            code = r.status
    except urllib.error.HTTPError as e:
        hdrs = str(e.headers).lower()
        body = e.read().decode("utf-8","ignore").lower()
        code = e.code
    except Exception:
        return ["连接失败"]

    # 攻击探测
    attack_url = url + ("&" if "?" in url else "?") + "q=1%27%20OR%20%271%27=%271"
    req2 = urllib.request.Request(attack_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req2, timeout=10, context=ctx) as r:
            atk_body = r.read().decode("utf-8","ignore").lower()
            atk_code = r.status
            atk_hdrs = str(r.headers).lower()
    except urllib.error.HTTPError as e:
        atk_body = e.read().decode("utf-8","ignore").lower()
        atk_code = e.code
        atk_hdrs = str(e.headers).lower()
    except Exception:
        atk_code = None; atk_body = ""; atk_hdrs = ""

    # 指纹匹配
    for name, keywords in WAF_FINGERPRINTS:
        combined = hdrs + atk_hdrs
        if any(k.lower() in combined for k in keywords):
            findings.append(f"匹配 WAF: {name} (响应头)")

    # 状态码分析
    if atk_code and atk_code in (403, 406):
        findings.append(f"探测被封: {atk_code}")
    if atk_code == code == 200:
        findings.append("探测请求 200 → WAF 可能未拦截")
    if (atk_code or 0) > 400 and (code or 0) < 400:
        findings.append("触发 WAF 拦截(状态码差异)")

    return findings

def main():
    ap = argparse.ArgumentParser(description="WAF 类型识别")
    ap.add_argument("-u", "--url", required=True, help="目标 URL")
    args = ap.parse_args()
    results = detect(args.url)
    print(f"[*] {args.url}")
    for r in results:
        print(f"  {r}")
    if not results:
        print("  [-] 未识别到 WAF")

if __name__ == "__main__":
    main()
