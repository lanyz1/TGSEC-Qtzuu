#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启动 HTTP/HTTPS 请求记录代理（mitmdump + recorder.py），单进程、跨平台。

    python proxy/start.py                                  # 默认 127.0.0.1:24304，记录全部
    python proxy/start.py --port 9090 --log-dir logs    # 自定义端口与日志目录
    python proxy/start.py --target-hosts example.com,api.example.com
    python proxy/start.py --scope TGSEC.com --exclude TGSEC.com/logout   # 范围内排除指定 URL
    python proxy/start.py --config pentest-data\\{id}\\config.json          # 范围/排除从 config 读

范围与排除有两种数据源，二者互斥：
  - 命令行：--scope / --exclude（及各自 --*-regex），适合临时/通用抓包。
  - --config：从 config.json 读 scope/exclude/scope_regex/exclude_regex，与门禁同一数据源、
    天然一致（推荐用于 pentest-web-assess-pipeline 流程）。

监听端口（--port）与日志目录（--log-dir）均可参数化配置。本工具只负责「代理引擎 + 记录」，
不修改也不持久化任何环境变量；curl / Playwright 如何指向代理见启动时打印的「客户端路由配方」。
"""

import argparse
import json
import os
import re
import sys

# 控制台/重定向 UTF-8（Windows 下中文输出与落盘不乱码，与 common.py / recorder.py 一致）
for _stream in ("stdout", "stderr"):
    try:
        getattr(sys, _stream).reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
RECORDER = os.path.join(HERE, "recorder.py")
DEFAULT_LOG_DIR = os.path.join(PROJECT_ROOT, "proxy-logs")
DEFAULT_PROXY_PORT = 24304


def _precompile_regex(rules, label):
    """对规则逐条 re.compile 预校验，非法则退出（避免运行时才报错）。"""
    for s in rules:
        try:
            re.compile(s)
        except re.error as e:
            sys.exit("无效的 %s 正则：%r → %s" % (label, s, e))


def main():
    p = argparse.ArgumentParser(
        description="HTTP/HTTPS 请求记录代理（mitmdump + recorder.py）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--port", type=int, default=None,
                   help="监听端口（默认 24304；用 --config 且未显式时取 config.proxy_port）")
    p.add_argument("--host", default="127.0.0.1", help="监听地址（仅本机）")
    p.add_argument("--log-dir", default=None,
                   help="日志目录（默认 <项目根>/proxy-logs；用 --config 时默认取 config 同目录下 proxy-logs）")
    p.add_argument("--target-hosts", default="", help="逗号分隔的目标主机过滤（子串匹配）；为空记录全部")
    p.add_argument("--body-cap", type=int, default=1024 * 1024,
                   help="原始请求 body 落盘截断字节数（0=不限）")
    p.add_argument("--param-value-cap", type=int, default=100, help="参数样本值最大字符数")
    p.add_argument("--resp-preview-cap", type=int, default=200,
                   help="响应体预览落盘字节数（仅文本类响应 page/api/other；0=不记录）")
    p.add_argument("--config", default=None, metavar="PATH",
                   help="从 config.json 读 scope/exclude/scope_regex/exclude_regex（与门禁同源）；"
                        "与 --scope/--exclude 互斥")
    p.add_argument("--scope", action="append", default=[], metavar="RULE",
                   help="范围限制，仅记录范围内请求；可多次指定（任一匹配即记录）。"
                        "默认字面：纯域名→主机/子域匹配，带路径→URL 前缀（如 www.TGSEC.com/pentest/）")
    p.add_argument("--scope-regex", action="store_true",
                   help="把 --scope 的值都当正则表达式（对完整 URL 做 search）")
    p.add_argument("--exclude", action="append", default=[], metavar="RULE",
                   help="排除规则，命中则不记录（优先级高于 --scope）；可多次指定。语法同 --scope")
    p.add_argument("--exclude-regex", action="store_true",
                   help="把 --exclude 的值都当正则表达式（对完整 URL 做 search）")
    args = p.parse_args()

    if not os.path.exists(RECORDER):
        sys.exit("未找到插件文件：%s" % RECORDER)

    # ---- 解析范围/排除数据源：--config（单一数据源）或命令行，二者互斥 ----
    if args.config:
        if args.scope or args.exclude or args.scope_regex or args.exclude_regex:
            sys.exit("--config 与 --scope/--exclude/--scope-regex/--exclude-regex 互斥，请二选一。")
        if not os.path.exists(args.config):
            sys.exit("未找到 config 文件：%s" % args.config)
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            sys.exit("读取 config 失败：%s → %s" % (args.config, e))
        scope = cfg.get("scope") or []
        exclude = cfg.get("exclude") or []
        scope_regex = bool(cfg.get("scope_regex"))
        exclude_regex = bool(cfg.get("exclude_regex"))
        log_dir = args.log_dir or os.path.join(os.path.dirname(os.path.abspath(args.config)), "proxy-logs")
        port = args.port or cfg.get("proxy_port") or DEFAULT_PROXY_PORT
        source_desc = "config: %s" % args.config
    else:
        scope = args.scope or []
        exclude = args.exclude or []
        scope_regex = args.scope_regex
        exclude_regex = args.exclude_regex
        log_dir = args.log_dir or DEFAULT_LOG_DIR
        port = args.port or DEFAULT_PROXY_PORT
        source_desc = "命令行"

    # 若启用正则，启动前预校验范围/排除规则
    if scope_regex:
        _precompile_regex(scope, "--scope")
    if exclude_regex:
        _precompile_regex(exclude, "--exclude")

    # 把可配置项通过环境变量传给 recorder.py（仅本进程，不持久化）
    os.environ["PROXY_LOG_DIR"] = log_dir
    os.environ["PROXY_TARGET_HOSTS"] = args.target_hosts
    os.environ["PROXY_BODY_CAP"] = str(args.body_cap)
    os.environ["PROXY_VALUE_CAP"] = str(args.param_value_cap)
    os.environ["PROXY_RESP_PREVIEW_CAP"] = str(args.resp_preview_cap)
    os.environ["PROXY_SCOPE"] = json.dumps(scope)
    os.environ["PROXY_SCOPE_REGEX"] = "1" if scope_regex else ""
    os.environ["PROXY_EXCLUDE"] = json.dumps(exclude)
    os.environ["PROXY_EXCLUDE_REGEX"] = "1" if exclude_regex else ""

    ca = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.pem")
    proxy_url = "http://%s:%d" % (args.host, port)

    print("\n==== HTTP/HTTPS 请求记录代理 ====")
    print("监听地址  : %s" % proxy_url)
    print("日志目录  : %s" % log_dir)
    print("配置来源  : %s" % source_desc)
    print("目标过滤  : %s" % (args.target_hosts or "ALL（记录全部）"))
    if scope:
        print("范围限制  : %s%s" % ("[正则] " if scope_regex else "", "  |  ".join(scope)))
    else:
        print("范围限制  : 无（记录全部）")
    if exclude:
        print("排除规则  : %s%s" % ("[正则] " if exclude_regex else "", "  |  ".join(exclude)))
    else:
        print("排除规则  : 无")
    print("body 截断 : %s 字节" % (args.body_cap or "不限"))
    print("参数值截断: %d 字符" % args.param_value_cap)
    print("响应预览  : %s" % ("%d 字节" % args.resp_preview_cap if args.resp_preview_cap else "关闭"))
    print("CA 证书   : %s" % ca)
    print("\n客户端临时指向本代理（不持久化，关窗即失效）：")
    print('  curl(每条)      : curl -x %s --cacert "%s" URL' % (proxy_url, ca))
    print('  curl(每条/跳过校验): curl -x %s -k URL' % proxy_url)
    print("  curl(PS 会话)   : $env:HTTP_PROXY=$env:HTTPS_PROXY='%s'; $env:CURL_CA_BUNDLE='%s'" % (proxy_url, ca))
    print("  浏览器          : Playwright 加 --proxy-server %s --ignore-https-errors" % proxy_url)
    print("\n按 Ctrl+C 停止。\n")

    try:
        from mitmproxy.tools.main import mitmdump
    except ImportError:
        sys.exit("未找到 mitmproxy。请先安装：python -m pip install -r proxy/requirements.txt")

    rc = mitmdump([
        "-s", RECORDER,
        "--listen-host", args.host,
        "--listen-port", str(port),
    ])
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
