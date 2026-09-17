#!/usr/bin/env python3
"""CMS 指纹识别: 根据特征头/路径/页面内容判断 CMS 类型
用法: python cms_fingerprint.py -u https://target.com"""
import argparse, re, ssl, sys, urllib.request, urllib.error

FINGERPRINTS = [
    ("WordPress", ["/wp-login.php","/wp-admin","/wp-content","/wp-json"], ["WordPress"]),
    ("Joomla", ["/administrator","/components","/modules"], ["Joomla"]),
    ("Drupal", ["/sites/default","/modules","/misc/drupal.js"], ["Drupal"]),
    ("Laravel", ["/vendor/laravel","/_debugbar"], ["Laravel"]),
    ("Django", ["/admin/","/static/admin"], ["Django","__debug__","csrftoken"]),
    ("Spring", ["/actuator","/swagger-ui.html"], ["Spring","actuator"]),
    ("nginx", [], ["nginx"]),
    ("Apache", [], ["Apache/2","Apache/2.4"]),
    ("IIS", [], ["Microsoft-IIS","ASP.NET"]),
    ("Tomcat", ["/manager/html", "/docs"], ["Tomcat","Apache-Coyote"]),
]

def check(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            body = r.read().decode("utf-8","ignore")
            hdrs = str(r.headers)
            svr = r.headers.get("Server","")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8","ignore")
        hdrs = str(e.headers)
        svr = e.headers.get("Server","")
    except Exception:
        return ["连接失败"]
    results = [f"Server: {svr}"] if svr else []
    for name, paths, keywords in FINGERPRINTS:
        for p in paths:
            try:
                req2 = urllib.request.Request(url.rstrip("/")+p,headers={"User-Agent":"Mozilla/5.0"})
                r2 = urllib.request.urlopen(req2,timeout=5,context=ctx)
                results.append(f"{name}: {url.rstrip('/')+p} -> {r2.status}")
            except urllib.error.HTTPError as e2:
                if e2.code != 404: results.append(f"{name}: {url.rstrip('/')+p} -> {e2.code}")
            except Exception: pass
        for kw in keywords:
            if kw.lower() in body.lower() or kw.lower() in hdrs.lower():
                results.append(f"{name}: 关键词 '{kw}' 命中")
    return results

def main():
    ap = argparse.ArgumentParser(description="CMS 指纹识别")
    ap.add_argument("-u","--url",required=True,help="目标 URL")
    args = ap.parse_args()
    for r in check(args.url):
        print(f"  {r}")
if __name__ == "__main__": main()
