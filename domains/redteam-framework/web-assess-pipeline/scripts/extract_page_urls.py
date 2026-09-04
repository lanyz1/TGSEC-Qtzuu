# -*- coding: utf-8 -*-
"""从每个页面的落盘 HTML 枚举「可能含 URL 的位置」，与页面已登记 URL 对比，列出疑似遗漏供 AI 复核。

抽取范围（尽量穷举各种 HTML 标签与 JS 语法中可能带 URL/接口的位置）：
- 标签属性：href/src/action/formaction/poster/cite/manifest/background/ping/xlink:href/data-*/hx-*/srcset …
- 样式：CSS url(...)；<meta http-equiv=refresh ... url=...>
- 网络/导航调用的字符串实参（wrapper 感知）：fetch / axios.方法 / $.get|post|ajax|getJSON|load /
  自定义封装 jsonPost|jsonGet|postJSON|getJSON|request|ajax|load / http.* / $http.* / ky.* / got /
  sendBeacon / EventSource / WebSocket / io / import / window.open / location.assign|replace ；
  以及 location.href= 赋值、XMLHttpRequest.open(method, URL) 的第 2 实参
- **wrapper 无关兜底**：扫描所有字符串字面量（含反引号模板，`${...}`→FUZZ 占位），保留「形似接口/页面」者——
  绝对/协议相对/根相对 URL、`./`|`../` 相对路径、以及裸/相对的 `*.php|jsp|aspx|do|json|action…`（可带 query）

比对对象 = 该页 `discovered_urls[].url` ∪ `discovered_js[].abs_url`（均按 norm_url 规范化）。
输出「候选但未登记」清单；跨主机候选标 [异域]，便于快速排除第三方静态资源。
**这是软核验：不做硬校验、恒 exit 0，结果交由 AI 复核。**

用法：
    python extract_page_urls.py --project <id> [--data-root pentest-data]
"""

import argparse
import os
import re
import sys
from urllib.parse import urljoin, urlsplit, urlunsplit

import common as c

# ── 各类可能承载 URL 的 HTML 属性（含 SVG xlink、htmx hx-*、data-* 常见变体、ping） ──
_URL_ATTRS = (r"href|src|srcdoc|action|formaction|poster|cite|manifest|background|longdesc|usemap|ping"
              r"|data-url|data-src|data-href|data-link|data-api|data-action|data-remote|data-target|data-ajax"
              r"|hx-get|hx-post|hx-put|hx-delete|hx-patch|xlink:href")
ATTR_RE = re.compile(r'(?:%s)\s*=\s*["\']([^"\']+)["\']' % _URL_ATTRS, re.I)
SRCSET_RE = re.compile(r'srcset\s*=\s*["\']([^"\']+)["\']', re.I)
CSS_URL_RE = re.compile(r'url\(\s*["\']?([^"\')\s]+)["\']?\s*\)', re.I)
# <meta http-equiv="refresh" content="0; url=xxx">
META_REFRESH_RE = re.compile(r'http-equiv\s*=\s*["\']?refresh["\']?[^>]*?[?&;\s]url\s*=\s*["\']?([^"\'>\s;]+)', re.I)

# 服务端脚本/接口常见扩展名——用于识别「形似接口/页面」的相对或裸路径字符串（低噪：需真带扩展名）
_DYN_EXT = (r"php\d?|phtml|phps|aspx?|jspx?|jspa|do|action|cgi|fcgi|pl|py|rb|go|ashx|asmx|axd"
            r"|jsonp?|xml|s?html?|xhtml|action|api")

# 已知网络/导航函数：捕获其首个字符串实参（wrapper 感知，连 REST 裸词资源名也纳入）
_AJAX_FNS = (r"fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax|getJSON|load)|jQuery\.\w+"
             r"|jsonPost|jsonGet|postJSON|getJSON|postForm|getForm|reqJson"
             r"|ajax|request|require|load|http\.\w+|\$http(?:\.\w+)?|ky(?:\.\w+)?|got|superagent\.\w+"
             r"|sendBeacon|navigator\.sendBeacon|EventSource|WebSocket|io"
             r"|import|window\.open|location\.assign|location\.replace|open")
AJAX_CALL_RE = re.compile(r'(?:\b|\.)(?:%s)\s*\(\s*[`\'"]([^`\'"]+)[`\'"]' % _AJAX_FNS, re.I)
# location.href = 'xxx' / window.location = 'xxx'（导航赋值）
NAV_ASSIGN_RE = re.compile(
    r'(?:window\.)?location(?:\.href)?\s*=\s*[`\'"]([^`\'"]+)[`\'"]', re.I)
# XMLHttpRequest.open(method, URL[, ...]) —— URL 是第 2 实参
XHR_OPEN_RE = re.compile(
    r'\.open\s*\(\s*[`\'"][A-Za-z]+[`\'"]\s*,\s*[`\'"]([^`\'"]+)[`\'"]', re.I)
# 所有字符串字面量（双引号/单引号/反引号），逐个交给 LOOKS_ENDPOINT_RE 甄别
STRING_LIT_RE = re.compile(r'"([^"\n]{1,400})"|\'([^\'\n]{1,400})\'|`([^`\n]{1,400})`')
TEMPLATE_EXPR_RE = re.compile(r'\$\{[^}]*\}')
# 「形似接口/页面」判定（对完整字符串字面量做整体匹配，低误报）
LOOKS_ENDPOINT_RE = re.compile(
    r'^(?:'
    r'(?:https?:)?//[^\s]+'                                  # 绝对 / 协议相对 //host/...
    r'|/[A-Za-z0-9_~][^\s]*'                                 # 根相对 /path...
    r'|\.{1,2}/[^\s]+'                                       # ./ 或 ../ 相对路径
    r'|[\w.\-/]+\.(?:%s)(?:[?#][^\s]*)?'                     # 裸/相对 xxx[.../]name.ext[?..]
    r')$' % _DYN_EXT, re.I)
# AJAX 首参若为 HTTP 方法名（method-first 风格如 request('POST', url)）则跳过，避免噪声
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace", "connect"}

# 静态资源扩展名（非 page/api/js 目标，抽取时跳过以降噪；.js 保留，与 discovered_js 比对）
STATIC_EXT = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".ogg",
    ".pdf", ".zip", ".gz", ".map",
}
_NON_HTTP_PREFIX = ("javascript:", "mailto:", "tel:", "data:", "blob:", "about:", "#",
                    "sms:", "geo:", "ftp:", "ws:", "wss:", "{{", "${")


def norm_url(u):
    """规范化：去 query / fragment、去尾斜杠，便于跨清单比对（与 check_breadth 一致）。"""
    try:
        s = urlsplit(u)
        return urlunsplit((s.scheme, s.netloc, s.path, "", "")).rstrip("/")
    except Exception:
        return (u or "").rstrip("/")


def _candidates_from_html(html):
    """枚举 HTML 里所有可能的 URL 原始字符串（未解析相对路径）。"""
    raw = set()
    # 1) HTML 标签属性 / srcset / CSS url() / meta refresh
    for m in ATTR_RE.finditer(html):
        raw.add(m.group(1).strip())
    for m in SRCSET_RE.finditer(html):
        for part in m.group(1).split(","):
            tok = part.strip().split()
            if tok:
                raw.add(tok[0])
    for rx in (CSS_URL_RE, META_REFRESH_RE):
        for m in rx.finditer(html):
            raw.add(m.group(1).strip())
    # 2) 已知网络/导航函数调用的首个字符串实参（wrapper 感知，含 REST 裸词；跳过 HTTP 方法名）
    for m in AJAX_CALL_RE.finditer(html):
        v = TEMPLATE_EXPR_RE.sub("FUZZ", m.group(1)).strip()
        if v and v.lower() not in _HTTP_METHODS:
            raw.add(v)
    for m in NAV_ASSIGN_RE.finditer(html):
        raw.add(TEMPLATE_EXPR_RE.sub("FUZZ", m.group(1)).strip())
    for m in XHR_OPEN_RE.finditer(html):
        raw.add(TEMPLATE_EXPR_RE.sub("FUZZ", m.group(1)).strip())
    # 3) wrapper 无关兜底：扫描所有字符串字面量（含反引号模板），保留「形似接口/页面」者
    for m in STRING_LIT_RE.finditer(html):
        v = m.group(1) or m.group(2) or m.group(3) or ""
        if m.group(3) is not None:      # 反引号模板：${...} 占位为 FUZZ，保留静态骨架
            v = TEMPLATE_EXPR_RE.sub("FUZZ", v)
        v = v.strip()
        if v and LOOKS_ENDPOINT_RE.match(v):
            raw.add(v)
    return raw


def _resolve(base_url, raw):
    """相对转绝对 + 规范化；返回 http(s) 且非静态资源的候选，否则 None。"""
    if not raw or raw.startswith(_NON_HTTP_PREFIX):
        return None
    try:
        absu = urljoin(base_url, raw)
    except Exception:
        return None
    s = urlsplit(absu)
    if s.scheme not in ("http", "https") or not s.netloc:
        return None
    ext = os.path.splitext(s.path)[1].lower()
    if ext in STATIC_EXT:
        return None
    return norm_url(absu)


def main():
    p = argparse.ArgumentParser(description="页面 HTML 候选 URL 抽取（软核验）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    pages = c.load_jsonl(paths["pages"])
    cfg = c.load_json(paths["config"], default={}) or {}
    scopes = cfg.get("scope", []) or []
    excludes = cfg.get("exclude", []) or []
    scope_regex = bool(cfg.get("scope_regex"))
    exclude_regex = bool(cfg.get("exclude_regex"))

    print("==== 页面候选 URL 抽取（软核验，供 AI 复核；不做硬校验）====")
    print("页面 %d | scope=%s" % (len(pages), scopes or "ALL"))
    print("")

    total_missing = no_html = 0
    for pg in pages:
        pid = pg.get("id", "(无id)")
        purl = pg.get("url", "")
        hf = pg.get("html_file", "")
        if not hf:
            no_html += 1
            print("[%s] %s —— 未登记 html_file，跳过（应先下载渲染后 HTML）" % (pid, purl))
            continue
        hp = hf if os.path.isabs(hf) else os.path.join(paths["dir"], hf)
        if not os.path.exists(hp):
            no_html += 1
            print("[%s] %s —— html_file 不存在：%s" % (pid, purl, hp))
            continue

        with open(hp, "r", encoding="utf-8", errors="replace") as f:
            html = f.read()

        registered = {norm_url(d.get("url", "")) for d in pg.get("discovered_urls", []) if d.get("url")}
        registered |= {norm_url(d.get("abs_url", "")) for d in pg.get("discovered_js", []) if d.get("abs_url")}
        registered.discard("")

        cands = set()
        for raw in _candidates_from_html(html):
            r = _resolve(purl or ("http://" + urlsplit(hp).netloc), raw)
            if r:
                cands.add(r)

        missing = sorted(cands - registered)
        phost = urlsplit(purl).netloc
        # 范围内候选优先展示（AI 复核聚焦范围内；范围外多为第三方/平台噪声）
        in_scope_missing = [u for u in missing if c.url_in_test_scope(u, scopes, excludes, scope_regex, exclude_regex)]
        print("[%s] %s —— 候选 %d / 已登记 %d / 疑似未登记 %d（范围内 %d）"
              % (pid, purl, len(cands), len(registered), len(missing), len(in_scope_missing)))
        for u in missing:
            scope_tag = "[范围内]" if c.url_in_test_scope(u, scopes, excludes, scope_regex, exclude_regex) else "[范围外]"
            host_tag = "" if urlsplit(u).netloc == phost else " [异域]"
            print("    · %s %s%s" % (scope_tag, u, host_tag))
        total_missing += len(in_scope_missing)

    print("")
    print("【小结】范围内疑似未登记候选合计 %d；缺 HTML 的页面 %d。" % (total_missing, no_html))
    print("说明：[范围内] 候选优先复核（据 config.scope 判定，与代理/门禁口径一致）；"
          "[范围外]/[异域] 多为第三方/平台资源噪声。请 AI 逐条复核，把确属本目标的页面/接口/JS 补登记。")
    sys.exit(0)


if __name__ == "__main__":
    main()
