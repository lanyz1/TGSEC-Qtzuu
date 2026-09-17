#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linux 轻量提权枚举器: 检查 SUID/sudo/定时任务/可写文件/capabilities
用法:
  python linpeas_light.py
  python linpeas_light.py --quick
"""
import argparse, os, re, stat, subprocess, sys, platform

IS_LINUX = platform.system() == "Linux"
if IS_LINUX:
    import grp, pwd

def run(cmd):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return out.stdout.strip()
    except Exception:
        return ""

def check_suid():
    print("\n[*] SUID 文件检查...")
    out = run("find / -perm -4000 -type f 2>/dev/null | head -50")
    for line in out.split("\n")[:30]:
        print(f"    {line}")

def check_sudo():
    print("\n[*] sudo 配置检查...")
    out = run("sudo -l 2>/dev/null")
    if out:
        for line in out.split("\n"):
            print(f"    {line}")
    else:
        print("    (无 sudo 权限或未配置)")

def check_cron():
    print("\n[*] 定时任务检查...")
    paths = ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
             "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs"]
    for p in paths:
        try:
            if os.path.isdir(p):
                for f in os.listdir(p):
                    fp = os.path.join(p, f)
                    if os.path.isfile(fp) and os.access(fp, os.R_OK):
                        print(f"    [可读] {fp}")
                        with open(fp, errors="ignore") as fh:
                            lines = fh.read()[:300]
                            for ln in lines.split("\n"):
                                if ln.strip() and not ln.startswith("#"):
                                    print(f"      {ln.strip()[:100]}")
            elif os.path.isfile(p) and os.access(p, os.R_OK):
                print(f"    [可读] {p}")
        except Exception:
            pass

def check_writable():
    print("\n[*] 可写系统目录...")
    check_dirs = ["/etc", "/tmp", "/var/tmp", "/opt", "/usr/local/bin"]
    for d in check_dirs:
        if os.path.isdir(d) and os.access(d, os.W_OK):
            print(f"    [!] 可写: {d}")

def check_kernel():
    print("\n[*] 内核版本: " + (run("uname -r") or "?"))
    print("    检查: linux-exploit-suggester")

def main():
    ap = argparse.ArgumentParser(description="Linux 轻量提权枚举器")
    ap.add_argument("--quick", action="store_true", help="仅快速检查")
    args = ap.parse_args()

    if not IS_LINUX:
        print("[!] 本工具仅支持 Linux 平台")
        sys.exit(1)

    print("=== Linux 提权枚举 ===")
    print(f"用户: {pwd.getpwuid(os.getuid()).pw_name} | UID: {os.getuid()}")
    print(f"组: {[g.gr_name for g in grp.getgrall() if os.getuid() in g.gr_mem]}")
    check_suid()
    check_sudo()
    if not args.quick:
        check_cron()
        check_writable()
    check_kernel()
    print("\n[*] 完成 — 进一步排查: GTFOBins / pspy / linpeas")

if __name__ == "__main__":
    main()
