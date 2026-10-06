#!/usr/bin/env python3
"""
WAF Auto Fuzzer — 自动化WAF绕过探测工具

测试 WAF 对各类攻击 payload 的拦截策略，识别 WAF 类型，
并自动生成绕过脚本。

仅限授权的安全评估使用。
"""

import argparse
import os
import signal
import sys
import time

from colorama import Fore, Style, init as colorama_init

from waf_fuzz import __version__
from waf_fuzz.bypass import generate_bypass_script
from waf_fuzz.detector import identify_waf
from waf_fuzz.encoders import encode_payload
from waf_fuzz.fuzzer import Fuzzer
from waf_fuzz.output import (
    save_bypass_report,
    save_csv,
    save_json,
    write_html_report,
)
from waf_fuzz.payloads import get_all

colorama_init(autoreset=True)

# ──────────────────────────────────────────────
# 信号处理
# ──────────────────────────────────────────────
stop_flag = False

def signal_handler(sig, frame):
    global stop_flag
    stop_flag = True
    print(f"\n{Fore.YELLOW}[!] 收到中断，等待当前请求完成...")

signal.signal(signal.SIGINT, signal_handler)


# ──────────────────────────────────────────────
# 进度回调
# ──────────────────────────────────────────────
def make_progress(start_time):
    """Return a progress callback closure."""
    def progress(done, total, last_result):
        if stop_flag:
            return False
        elapsed = time.time() - start_time
        bypass = 0
        blocked = 0
        # cheap approximate — real counts tracked in Fuzzer
        pct = done / total * 100
        bar_len = 30
        filled = int(bar_len * done / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        arrow = ">" if last_result.is_bypass() else "x"
        color = Fore.GREEN if last_result.is_bypass() else Fore.RED
        sys.stdout.write(
            f"\r{Fore.CYAN}[{bar}] {pct:.0f}%  "
            f"{done}/{total}  "
            f"{color}{arrow} {last_result.status_code} "
            f"{last_result.encoding:18s} "
            f"{Fore.RESET}"
        )
        sys.stdout.flush()
        return True
    return progress


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description=f"WAF Auto Fuzzer v{__version__} — 自动化WAF绕过探测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # GET 参数 fuzz
  python waf_fuzz.py -t "http://target.com/search?q=" -p q

  # POST 表单 fuzz
  python waf_fuzz.py -t "http://target.com/login" -m POST -p username

  # 指定分类
  python waf_fuzz.py -t "http://target.com/search?q=" -p q -c sqli xss

  # 仅特定编码方式
  python waf_fuzz.py -t "http://target.com/search?q=" -p q -e urlencode base64

  # 代理 + 输出到文件
  python waf_fuzz.py -t "http://target.com" -p q --proxy http://127.0.0.1:8080 -o result.json

  # Cookie 注入测试
  python waf_fuzz.py -t "http://target.com" -m COOKIE -p session_id

  # Header 注入测试
  python waf_fuzz.py -t "http://target.com" -m HEADER -p X-Forwarded-For
        """,
    )

    parser.add_argument("-t", "--target", required=True,
                        help="目标 URL（如 http://target.com/search?q= ）")
    parser.add_argument("-p", "--param", default="q",
                        help="参数名（默认 q）")
    parser.add_argument("-m", "--method", default="GET",
                        choices=["GET", "POST", "PUT", "COOKIE", "HEADER"],
                        help="HTTP 方法（默认 GET）")
    parser.add_argument("-d", "--data-param",
                        help="POST 参数名（默认同 --param）")
    parser.add_argument("-c", "--categories", nargs="+",
                        choices=["sqli", "xss", "cmdi", "traversal",
                                 "ssrf", "rce", "xxe", "ssti", "ldap",
                                 "redirect"],
                        help="要测试的payload分类（默认全部）")
    parser.add_argument("-e", "--encodings", nargs="+",
                        help="仅测试指定的编码方式")
    parser.add_argument("--threads", type=int, default=10,
                        help="并发线程数（默认 10）")
    parser.add_argument("--delay", type=float, default=0,
                        help="请求间延迟秒数（默认 0）")
    parser.add_argument("--timeout", type=int, default=10,
                        help="超时秒数（默认 10）")
    parser.add_argument("--proxy",
                        help="代理地址，如 http://127.0.0.1:8080")
    parser.add_argument("--header", action="append", default=[],
                        help="自定义请求头，可多次使用，如 'X-Forwarded-For: 127.0.0.1'")
    parser.add_argument("--user-agent-rotate", action="store_true",
                        help="随机轮换 User-Agent")
    parser.add_argument("--no-verify", action="store_true",
                        help="跳过 SSL 证书验证")
    parser.add_argument("--follow-redirects", action="store_true",
                        help="跟随重定向（默认不跟随）")
    parser.add_argument("--impersonate", metavar="TARGET", nargs="?", const="chrome120",
                        help="TLS 指纹伪装（需 curl_cffi）。目标：chrome120/chrome131/safari17_0/firefox135 等")
    parser.add_argument("-o", "--output",
                        help="输出文件路径 (.json / .csv)")
    parser.add_argument("--html-report",
                        help="生成 HTML 报告文件路径")
    parser.add_argument("--bypass-report",
                        help="生成绕过摘要报告路径")
    parser.add_argument("--generate-script", action="store_true",
                        help="自动生成绕过脚本 waf_bypass.py")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅显示测试计划，不实际发送请求")

    args = parser.parse_args()

    # ── 解析自定义头 ──────────────────────────────────
    custom_headers = {}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            custom_headers[k.strip()] = v.strip()

    # ── 准备 payload ──────────────────────────────────
    all_items = get_all()
    if args.categories:
        cat_set = set(args.categories)
        filtered = [(c, p) for c, p in all_items if c in cat_set]
    else:
        filtered = all_items

    # ── 构建测试任务 ──────────────────────────────────
    tasks = []
    for cat, payload in filtered:
        encodings = encode_payload(payload)
        for enc_name, enc_val in encodings:
            if args.encodings and enc_name not in args.encodings:
                continue
            tasks.append((cat, payload, enc_name, enc_val))

    if not tasks:
        print(f"{Fore.RED}[!] 没有匹配的 payload/编码组合，退出.")
        sys.exit(1)

    # 去重 sent_value
    seen = set()
    unique_tasks = []
    for t in tasks:
        key = t[3]
        if key not in seen:
            seen.add(key)
            unique_tasks.append(t)
    tasks = unique_tasks

    print(f"\n{Fore.CYAN}{'=' * 58}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  WAF Auto Fuzzer  v{__version__}")
    print(f"{Fore.CYAN}{'=' * 58}")
    print(f"  目标:          {args.target}")
    print(f"  方法/参数:     {args.method} / {args.param}")
    print(f"  分类:          {', '.join(args.categories) if args.categories else '全部'}")
    print(f"  Payload:       {len(filtered)} 条")
    print(f"  测试任务:      {len(tasks)} 个")
    print(f"  线程:          {args.threads}")
    print(f"  代理:          {args.proxy or '(无)'}")
    print(f"{Fore.CYAN}{'=' * 58}\n")

    # ── 试运行 ────────────────────────────────────────
    if args.dry_run:
        print(f"{Fore.GREEN}[+] 试运行模式，以下为测试计划:\n")
        for cat, payload, enc_name, enc_val in tasks[:20]:
            print(f"  [{cat:10s}] {enc_name:18s} {payload[:40]}")
        if len(tasks) > 20:
            print(f"  ... 还有 {len(tasks) - 20} 个测试")
        print(f"\n{Fore.GREEN}[+] 共 {len(tasks)} 个测试，去掉 --dry-run 执行.")
        return

    # ── 执行 FUZZ ─────────────────────────────────────
    fuzzer = Fuzzer(
        target_url=args.target,
        method=args.method,
        param=args.param,
        data_param=args.data_param,
        custom_headers=custom_headers,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads,
        delay=args.delay,
        user_agent_rotate=args.user_agent_rotate,
        verify_ssl=not args.no_verify,
        follow_redirects=args.follow_redirects,
        impersonate=args.impersonate,
    )

    start = time.time()
    callback = make_progress(start)
    results = fuzzer.run(tasks, progress_cb=callback)
    elapsed = time.time() - start

    bypass_list = fuzzer.get_bypass_results()
    blocked_list = fuzzer.get_blocked_results()

    print(f"\n\n{Fore.CYAN}{'=' * 58}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  测试完成")
    print(f"{Fore.CYAN}{'=' * 58}")
    print(f"  总测试:       {len(results)}")
    print(f"  {Fore.GREEN}绕过:         {len(bypass_list)}")
    print(f"  {Fore.RED}拦截:         {len(blocked_list)}")
    print(f"  耗时:         {elapsed:.0f}s ({elapsed/len(results):.2f}s/req)")

    if bypass_list:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}  绕过结果（Top 10）:")
        print(f"  {Fore.CYAN}{'-' * 58}")
        for r in bypass_list[:10]:
            print(f"  {Fore.GREEN}[{r.category:8s}] {r.encoding:18s} "
                  f"HTTP {r.status_code}  {r.payload[:40]}")
        if len(bypass_list) > 10:
            print(f"  ... 共 {len(bypass_list)} 条绕过")
        print(f"  {Fore.CYAN}{'-' * 58}")

    # ── WAF 指纹识别 ─────────────────────────────────
    print(f"\n{Fore.YELLOW}[*] 正在识别 WAF 类型...")
    waf_matches = []
    for r in results[:50]:
        if r.status_code > 0:
            matches = identify_waf(
                {"Content-Type": "", "Set-Cookie": "", "Server": ""},
                "",
                r.status_code,
            )
            break
    if waf_matches:
        print(f"{Fore.GREEN}[+] WAF 识别结果:")
        for name, conf in waf_matches[:3]:
            print(f"     {name} (置信度: {conf*100:.0f}%)")
    else:
        print(f"{Fore.YELLOW}[*] 未识别出已知 WAF")

    # ── 输出结果 ──────────────────────────────────────
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            save_json(results, args.output)
        elif ext == ".csv":
            save_csv(results, args.output)
        else:
            save_json(results, args.output + ".json")
            save_csv(results, args.output + ".csv")
        print(f"{Fore.GREEN}[+] 结果已保存: {args.output}")

    if args.html_report:
        path = write_html_report(results, bypass_list, args.html_report,
                                 elapsed, waf_matches)
        print(f"{Fore.GREEN}[+] HTML 报告已生成: {path}")

    if args.bypass_report:
        path = save_bypass_report(bypass_list, args.bypass_report)
        print(f"{Fore.GREEN}[+] 绕过报告已生成: {path}")

    # ── 生成绕过脚本 ──────────────────────────────────
    if args.generate_script:
        script = generate_bypass_script(bypass_list, args.target, args.param)
        path = "waf_bypass.py"
        with open(path, "w", encoding="utf-8") as f:
            f.write(script)
        print(f"{Fore.GREEN}[+] 绕过脚本已生成: {path}")

    print()


if __name__ == "__main__":
    main()
