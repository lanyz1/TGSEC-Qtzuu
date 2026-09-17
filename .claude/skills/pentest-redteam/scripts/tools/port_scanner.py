#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""异步端口扫描器: 并发 connect 探测 + 常见服务 banner 抓取
用法:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t example.com -p 1-1000 --banner
"""
import argparse
import asyncio
import socket
import sys

COMMON = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3000: "WebDev", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis",
    7001: "WebLogic", 8000: "WebAlt", 8080: "HTTP-Alt", 8081: "HTTP-Alt2",
    8443: "HTTPS-Alt", 8888: "WebAlt3", 9000: "AppSvc", 9090: "WebConsole",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

def grab_banner(host, port, timeout=4):
    """尝试抓取服务 banner"""
    banners = {
        21: b"220 ", 22: b"SSH-", 25: b"220", 110: b"+OK", 143: b"* OK",
        445: b"SMB", 3306: b"5.", 5432: b"PostgreSQL", 6379: b"-ERR",
        11211: b"", 27017: b"",
    }
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(256)
            return data.decode("utf-8", "ignore").strip()[:80] if data else ""
        except Exception:
            return ""
        finally:
            s.close()
    except Exception:
        return ""

async def check(host, port, timeout):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None

async def scan(host, ports, timeout, concurrency):
    sem = asyncio.Semaphore(concurrency)
    async def worker(p):
        async with sem:
            return await check(host, p, timeout)
    tasks = [worker(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [p for p in results if p]

def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    ap = argparse.ArgumentParser(description="异步端口扫描器")
    ap.add_argument("-t", "--target", required=True, help="目标 IP/域名")
    ap.add_argument("-p", "--ports", default="21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,5601,5900,6379,7001,8000,8080,8443,8888,9000,9090,9200,11211,27017", help="端口列表,如 1-1000 或 80,443,8080")
    ap.add_argument("--timeout", type=float, default=2.0, help="连接超时(秒)")
    ap.add_argument("-c", "--concurrency", type=int, default=200, help="并发数")
    ap.add_argument("-b", "--banner", action="store_true", help="抓取服务 banner")
    args = ap.parse_args()

    host = args.target
    try:
        socket.gethostbyname(host)
    except Exception:
        print(f"[!] 无法解析目标: {host}")
        sys.exit(1)

    ports = parse_ports(args.ports)
    print(f"[*] 扫描 {host} ({len(ports)} 端口)...")
    try:
        open_ports = asyncio.run(scan(host, ports, args.timeout, args.concurrency))
    except KeyboardInterrupt:
        print("\n[!] 已中断")
        sys.exit(130)

    print(f"\n[+] 开放端口 {len(open_ports)} 个:")
    for p in open_ports:
        svc = COMMON.get(p, "?")
        line = f"    {p:<6} {svc}"
        if args.banner:
            b = grab_banner(host, p)
            if b:
                line += f"  ->  {b}"
        print(line)

if __name__ == "__main__":
    main()
