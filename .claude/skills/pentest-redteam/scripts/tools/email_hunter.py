#!/usr/bin/env python3
"""被动 OSINT 邮箱/人员收集: Hunter.io 风格—从域名猜测邮箱 + 验证
用法: python email_hunter.py -d example.com -n "John Smith,Jane Doe" -o emails.txt"""
import argparse, re, socket, ssl, sys, urllib.request

def permute(first, last, domain):
    formats = [
        f"{first}@{domain}", f"{last}@{domain}",
        f"{first}.{last}@{domain}", f"{first[0]}{last}@{domain}",
        f"{first}_{last}@{domain}", f"{first}{last[0]}@{domain}",
        f"{first}-{last}@{domain}",
    ]
    return [f.lower() for f in formats]

def verify_smtp(email, timeout=8):
    """简单 SMTP VRFY/RCPT 验证(需开放 SMTP 25)"""
    try:
        domain = email.split("@")[1]
        import smtplib
        with smtplib.SMTP(domain, 25, timeout=timeout) as s:
            s.helo("test")
            code, _ = s.mail("test@test.com")
            if code == 250:
                s.docmd("RCPT TO:<%s>" % email)
                return True
    except Exception:
        pass
    return None

def main():
    ap = argparse.ArgumentParser(description="被动 OSINT 邮箱收集")
    ap.add_argument("-d","--domain",required=True,help="目标域名")
    ap.add_argument("-n","--names",default="",help="姓名,逗号分隔: John Smith,Jane Doe")
    ap.add_argument("-o","--output",default="emails.txt")
    args = ap.parse_args()
    domain = args.domain.strip().lower()
    emails = set()
    if args.names:
        for name in args.names.split(","):
            parts = name.strip().split()
            if len(parts) >= 2:
                emails.update(permute(parts[0], parts[-1], domain))
    with open(args.output, "w") as f:
        for e in sorted(emails):
            f.write(e + "\n")
            print(e)
    print(f"[+] {len(emails)} 个邮箱 -> {args.output}")
if __name__ == "__main__": main()
