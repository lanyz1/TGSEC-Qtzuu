# -*- coding: utf-8 -*-
"""广度建模质量门禁——机器硬检查。

检查五个清单的格式 / 必填字段 / 枚举值 / 交叉引用 / 参数覆盖，以及全部 page/api URL 的权限矩阵覆盖
（逐角色访问控制验证已完成、judgment 合法、证据字段齐全，页面型另做反向抽查兜底漏判），
并列出需 AI 语义复核的项。
退出码：0=硬检查通过（仍须完成 AI 复核项才算门禁通过），1=有硬错误需处置。

用法：
    python check_breadth.py --project <id> [--data-root pentest-data]
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit, urlunsplit

import common as c
import extract_page_urls as epu

# 动态脚本/接口扩展名（页面 HTML 正向端点覆盖硬校验用；.js/静态资源不在此列，另由 js 清单/资源治理）
_DYN_ENDPOINT_EXT = {
    "php", "php3", "php4", "php5", "php7", "phtml", "phps",
    "asp", "aspx", "jsp", "jspx", "jspa", "do", "action",
    "cgi", "fcgi", "pl", "py", "rb", "go", "ashx", "asmx", "axd",
    "json", "jsonp", "xml", "htm", "html", "shtml", "xhtml", "api",
}


def _looks_dyn_endpoint(u):
    """URL 路径是否以动态脚本/接口扩展名结尾（低误报：仅带明确扩展名者算端点）。"""
    ext = os.path.splitext(urlsplit(u).path)[1].lower().lstrip(".")
    return ext in _DYN_ENDPOINT_EXT


# 浏览器访问信号：UA 含浏览器标识，或请求头带仅浏览器发送的头
_BROWSER_UA_RE = re.compile(r"mozilla/|applewebkit|chrome/|firefox/|safari/|edg/|gecko/", re.I)
_BROWSER_HINT_RE = re.compile(r"^(sec-fetch-|sec-ch-ua|upgrade-insecure-requests)", re.I)
# 工具访问信号：常见命令行/脚本 UA
_TOOL_UA_RE = re.compile(
    r"curl/|wget|python-requests|python-urllib|python/|go-http-client|okhttp|java/|libwww"
    r"|postmanruntime|axios/|node-fetch|httpie|guzzle|scrapy|apache-httpclient|winhttp"
    r"|powershell|http\.rb|restsharp|aiohttp", re.I)


def page_access_kind(log_path):
    """解析 requests/{id}.log 全部请求的请求头段，判断是否有浏览器/工具访问。
    返回 (has_browser, has_tool)。请求头段 = 每条记录 `--- REQUEST ---` 后到首个空行之间。"""
    has_browser = has_tool = False
    if not os.path.exists(log_path):
        return has_browser, has_tool
    in_req_headers = False
    ua = ""
    hint = False
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.rstrip("\n").rstrip("\r")
            if s == "--- REQUEST ---":
                in_req_headers, ua, hint = True, "", False  # 进入新请求头段
                continue
            if in_req_headers:
                if s == "":  # 头段结束（空行分隔 body）→ 结算本条
                    in_req_headers = False
                    if _TOOL_UA_RE.search(ua):
                        has_tool = True
                    elif hint or _BROWSER_UA_RE.search(ua):
                        has_browser = True
                    continue
                low = s.lower()
                if low.startswith("user-agent:"):
                    ua = s.split(":", 1)[1].strip()
                elif _BROWSER_HINT_RE.match(s):
                    hint = True
    return has_browser, has_tool

REQUIRED = {
    "pages": ["id", "url", "accessed_as_roles", "html_file", "fully_parsed", "discovered_js",
              "discovered_urls", "interactive_elements", "business_constraints", "notes"],
    "js": ["id", "source_url", "is_opensource", "download_status", "local_path", "fully_read",
           "secrets", "discovered_urls", "business_constraints", "notes"],
    "chains": ["id", "name", "goal", "description", "related_urls",
               "business_constraints", "walkthrough_status", "walkthrough_detail", "notes"],
    "threats": ["id", "name", "priority", "related_objects", "description",
                "verification_status", "verification_detail", "notes"],
}


def norm_url(u):
    """规范化：去 query / fragment、去尾斜杠，便于跨清单比对。"""
    try:
        s = urlsplit(u)
        return urlunsplit((s.scheme, s.netloc, s.path, "", "")).rstrip("/")
    except Exception:
        return (u or "").rstrip("/")


def load_jsonl_strict(path, errors, label):
    recs = []
    if not os.path.exists(path):
        return recs
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception as e:
                errors.append("[%s] 第 %d 行 JSON 解析失败：%s" % (label, n, e))
    return recs


def check_required(recs, fields, label, errors):
    for i, r in enumerate(recs):
        rid = r.get("id", "(无id第%d条)" % (i + 1))
        for fld in fields:
            if fld not in r:
                errors.append("[%s] %s 缺字段：%s" % (label, rid, fld))


def check_param_coverage(static_doc, inv_urls, proxy_idx, inv_url_set,
                         proxy_success_urls, retest_disp, scopes, excludes,
                         scope_regex, exclude_regex, errors, reviews):
    """【参数覆盖·硬门禁】静态提取(url-static-params.json)的 high 参数是否都出现在代理实测 param_names
    中。缺失 = 该参数在页面/JS 内联请求体可见、却从未随真实请求发送 → 业务流程未真实走通、漏洞挖掘阶段不会挖掘。
    仅对「in-scope + 已被访问(inv/成功) + 能对齐 URLID」的接口检查（未访问的由 URL 级接口覆盖检查负责，
    不重复报）。retest 已研判(retest/blocked+access_note)则降为复核。文件缺失 → 复核提示，不 blocking。"""
    if static_doc is None:
        reviews.append("[复核] 未找到 url-static-params.json，参数覆盖门禁未生效——"
                       "请先运行 extract_static_params.py --project <id> 再重跑 check_breadth.py")
        return
    # 代理实测参数：norm_url -> set(param_names)（url-inventory ∪ url_index，两侧口径一致）
    actual = {}
    for u in inv_urls:
        nu = norm_url(u.get("url", ""))
        if nu:
            actual.setdefault(nu, set()).update(u.get("param_names", []) or [])
    for rec in proxy_idx:
        nu = norm_url(rec.get("url", ""))
        if nu:
            actual.setdefault(nu, set()).update(rec.get("param_names", []) or [])
    for su in static_doc.get("urls", []):
        uid = su.get("url_id")
        surl = su.get("url", "")
        nu = norm_url(surl)
        if not nu or not uid:
            continue  # 对不上代理 URLID 的静态项不检查（无实测基准可比）
        if not c.url_in_test_scope(surl, scopes, excludes, scope_regex, exclude_regex):
            continue
        if nu not in inv_url_set and nu not in proxy_success_urls:
            continue  # 未被访问的接口由 URL 级覆盖检查负责，不在此重复
        expected = {p.get("name") for p in su.get("static_params", [])
                    if p.get("confidence") == "high" and p.get("name")}
        if not expected:
            continue
        act = actual.get(nu, set())
        # 容忍代理 _flatten_json 的嵌套展平：静态顶层键(如 items)若实测以点路径 items.* 出现
        # (items.product_no/items.quantity)则视为已覆盖，避免"嵌套数组/对象"两侧口径不一致的假阳性。
        missing = {k for k in expected
                   if k not in act and not any(a.startswith(k + ".") for a in act)}
        if not missing:
            continue
        src = ""
        for p in su.get("static_params", []):
            if p.get("name") in missing and p.get("confidence") == "high":
                src = "%s:%s" % (p.get("source_file", ""), p.get("line", ""))
                break
        disp, has_note = retest_disp.get(nu, ("pending", False))
        if disp in ("retest", "blocked") and has_note:
            reviews.append("[复核] 接口 %s 静态参数 {%s} 未见于代理实测但已在 retest-list.json 研判(%s)："
                           "复核 access_note 理由是否成立（仅特定分支/特权角色发送记 blocked；可补测记 retest）"
                           % (uid, ",".join(sorted(missing)), disp))
        else:
            errors.append("[参数覆盖] 接口 %s 静态发现请求参数 {%s} 在页面/JS 内联请求体可见却未出现在代理"
                          "实测 param_names({%s})——通常是该接口业务流程未被真实走通、参数从未随真实请求发送，"
                          "漏洞挖掘阶段不会挖掘：%s（静态来源 %s）；应先用 playwright 走通完整业务流程使参数进入代理"
                          "记录并重跑 build_url_inventory.py；确属客观无法触发(仅特定分支/特权角色发送)在 "
                          "retest-list.json 记 disposition+access_note，或在 state.json.gates.breadth.acknowledged "
                          "记 match(%s)+reason_code(precondition_unmet/not_exist)+note 豁免"
                          % (uid, ",".join(sorted(missing)), ",".join(sorted(act)) or "空", surl, src, uid))


# ---- 权限矩阵覆盖（广度阶段收尾：全部 page/api 逐角色访问控制验证）----

def _owner_of(url):
    """按路径段推导页面型 URL 的归属角色（与 permission_probe.py 同口径）。"""
    p = (url or "").split("?")[0].lower()
    if "/admin/" in p:
        return "admin"
    if "/merchant/" in p:
        return "merchant"
    if "/user/" in p:
        return "user"
    return None


def _fp_len(res):
    """从权限矩阵角色记录取响应长度（优先 response_length）。"""
    try:
        return int(res.get("response_length", -1))
    except Exception:
        return -1


def check_page_underreport(uid, pm, reviews, len_tol=120):
    """页面型 URL 反向抽查：各角色全 normal 但低权角色响应与归属角色雷同 → 疑似漏判越权。

    用「与判定器不同的逻辑」（纯长度对比）兜底，防止判定假设错误静默漏报。
    """
    results = {r.get("role"): r for r in pm.get("results", [])}
    if any(r.get("judgment") == "abnormal" for r in pm.get("results", [])):
        return  # 已判出越权，无需抽查
    owner = _owner_of(pm.get("url", ""))
    if not owner or owner not in results:
        return
    own = results[owner]
    if own.get("session_valid") is False:
        return  # 成功锚点不成立，不抽查
    own_len = _fp_len(own)
    unauth_len = _fp_len(results.get("unauth", {}))
    if own_len < 0:
        return
    for role, res in results.items():
        if role in (owner, "unauth"):
            continue
        if res.get("session_valid") is False:
            continue
        rl = _fp_len(res)
        # 低权角色长度贴近归属角色、又明显不同于未登录基线 → 疑似越权被判定器漏判
        if abs(rl - own_len) <= len_tol and (unauth_len < 0 or abs(rl - unauth_len) > len_tol):
            reviews.append("[复核] 页面 %s 低权角色 %s 响应(len=%d)与归属角色 %s(len=%d)雷同、"
                           "远离未登录基线(len=%s)，疑似判定器漏判越权，须人工确认是否越权"
                           % (uid, role, rl, owner, own_len, unauth_len))


def check_permission_matrix(pageapi, paths, errors, reviews):
    """权限矩阵覆盖硬校验：URL 攻击面覆盖清零后，对全部 page/api URL 逐角色验证访问控制。
    每个 URL 须 permission_matrix_status=verified、permission-matrix/{id}.json 非空、
    results 各角色 judgment 合法且带 session_valid/final_status/body_fingerprint 证据字段；
    页面型再以纯长度对比反向抽查兜底判定器漏判。abnormal 项须另在 threats.jsonl 登记为攻击面。"""
    for u in pageapi:
        uid = u.get("id")
        if u.get("permission_matrix_status") != "verified":
            errors.append("[权限矩阵] %s permission_matrix_status 非 verified（对该 URL 跑 permission_probe.py 后回填）" % uid)
        perm_file = os.path.join(paths["perm_dir"], "%s.json" % uid)
        if not os.path.exists(perm_file):
            errors.append("[权限矩阵] %s 缺文件：%s（运行 permission_probe.py 产出）" % (uid, perm_file))
            continue
        pm = c.load_json(perm_file, default={})
        if not pm or not pm.get("results"):
            errors.append("[权限矩阵] %s 文件内容为空或无 results" % uid)
            continue
        for res in pm["results"]:
            if res.get("judgment") not in c.JUDGMENT:
                errors.append("[权限矩阵] %s results.judgment 非法：%r" % (uid, res.get("judgment")))
            for fld in ("session_valid", "final_status", "body_fingerprint"):
                if fld not in res:
                    errors.append("[权限矩阵] %s 角色 %s 缺证据字段 %s（须由 permission_probe.py 产出）"
                                  % (uid, res.get("role", "?"), fld))
        cat = pm.get("url_category") or u.get("category")
        if cat == "page":
            check_page_underreport(uid, pm, reviews)


def main():
    p = argparse.ArgumentParser(description="广度建模质量门禁")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    errors = []   # 硬错误 → exit 1
    reviews = []  # 待 AI 语义复核

    pages = load_jsonl_strict(paths["pages"], errors, "pages")
    jss = load_jsonl_strict(paths["js"], errors, "js")
    chains = load_jsonl_strict(paths["chains"], errors, "chains")
    threats = load_jsonl_strict(paths["threats"], errors, "threats")

    inv = c.load_json(paths["inventory"], default=None)
    if inv is None:
        errors.append("[inventory] 未找到 url-inventory.json，请先运行 build_url_inventory.py")
        inv = {"urls": []}
    inv_urls = inv.get("urls", [])

    # 必填字段
    check_required(pages, REQUIRED["pages"], "pages", errors)
    check_required(jss, REQUIRED["js"], "js", errors)
    check_required(chains, REQUIRED["chains"], "chains", errors)
    check_required(threats, REQUIRED["threats"], "threats", errors)

    # 枚举
    for r in chains:
        if r.get("walkthrough_status") not in c.WALKTHROUGH_STATUS:
            errors.append("[chains] %s walkthrough_status 非法：%r" % (r.get("id"), r.get("walkthrough_status")))
    for r in threats:
        if r.get("priority") not in c.PRIORITIES:
            errors.append("[threats] %s priority 非法：%r" % (r.get("id"), r.get("priority")))
    # 页面：HTML 已下载（文件存在）且已全文解析
    for r in pages:
        pid = r.get("id")
        hf = r.get("html_file") or ""
        if not hf:
            errors.append("[pages] %s 未登记 html_file（须下载渲染后 HTML 并登记路径）" % pid)
        else:
            hp = hf if os.path.isabs(hf) else os.path.join(paths["dir"], hf)
            if not os.path.exists(hp):
                errors.append("[pages] %s html_file 文件不存在：%s" % (pid, hf))
        if r.get("fully_parsed") is not True:
            errors.append("[pages] %s fully_parsed 非 true（须完整阅读并解析 HTML 源码）" % pid)

    # JS：字段/枚举 + 非开源已下载须全读
    js_id_set = set()
    for r in jss:
        jid = r.get("id")
        js_id_set.add(jid)
        if not isinstance(r.get("is_opensource"), bool):
            errors.append("[js] %s is_opensource 必须为 bool" % jid)
        if r.get("download_status") not in c.DOWNLOAD_STATUS:
            errors.append("[js] %s download_status 非法：%r" % (jid, r.get("download_status")))
        if not isinstance(r.get("fully_read"), bool):
            errors.append("[js] %s fully_read 必须为 bool" % jid)
        if r.get("is_opensource") is False and r.get("download_status") == "downloaded" \
                and r.get("fully_read") is not True:
            errors.append("[js] %s 非开源且已下载，fully_read 必须为 true（须全文阅读）" % jid)

    # 页面 discovered_js：js_id 非空且已在 js 清单登记（所有发现的 JS 都登记）
    for r in pages:
        for dj in r.get("discovered_js", []):
            jid = (dj.get("js_id") or "").strip()
            if not jid:
                errors.append("[pages] %s discovered_js 缺 js_id（每个引用 JS 都须登记 js 清单）：%s"
                              % (r.get("id"), dj.get("src")))
            elif jid not in js_id_set:
                errors.append("[pages] %s discovered_js 的 js_id 未在 js 清单：%s" % (r.get("id"), jid))

    # JS 覆盖度：代理请求日志里每个 js 类 URL 都须登记在 js 清单
    js_src_set = {norm_url(r.get("source_url", "")) for r in jss}
    js_src_set.discard("")
    proxy_idx = c.load_jsonl(paths["url_index"])
    failed_idx = c.load_jsonl(paths["failed_index"])
    for rec in proxy_idx:
        if rec.get("category") != "js":
            continue
        ju = norm_url(rec.get("url", ""))
        if ju and ju not in js_src_set:
            errors.append("[覆盖度] 代理记录的 JS 未登记 js 清单：%s（%s）" % (ju, rec.get("id")))

    # 页面浏览器访问核验：每个页面须据代理请求日志确认经浏览器(playwright)走查，而非仅工具触达
    url2id = {}  # 规范化 url -> URLID（合并成功/失败清单，覆盖登录 4xx 等页面）
    for rec in proxy_idx + failed_idx:
        nu = norm_url(rec.get("url", ""))
        if nu and rec.get("id"):
            url2id.setdefault(nu, rec.get("id"))
    for r in pages:
        pu = norm_url(r.get("url", ""))
        uid = url2id.get(pu)
        if not uid:
            reviews.append("[复核] 页面 %s 无匹配的代理访问记录，确认是否确经浏览器访问（如 SPA 哈希路由或 URL 与代理记录不一致）：%s"
                           % (r.get("id"), r.get("url")))
            continue
        has_browser, has_tool = page_access_kind(os.path.join(paths["requests_dir"], "%s.log" % uid))
        if not has_browser:
            if has_tool:
                errors.append("[浏览器访问] 页面 %s 仅有工具(curl/python 等)访问记录，无浏览器(playwright)走查：%s（%s）"
                              % (r.get("id"), r.get("url"), uid))
            else:
                reviews.append("[复核] 页面 %s 代理记录未见明确浏览器访问信号，确认是否确经浏览器走查：%s（%s）"
                               % (r.get("id"), r.get("url"), uid))

    # 交叉引用
    inv_url_set = {norm_url(u.get("url", "")) for u in inv_urls}
    inv_pageapi = {norm_url(u.get("url", "")) for u in inv_urls if u.get("category") in ("page", "api")}

    # config.scope/exclude（in_scope 缺省时现场计算，与代理记录口径一致）
    cfg = c.load_json(paths["config"], default={}) or {}
    scopes = cfg.get("scope", []) or []
    excludes = cfg.get("exclude", []) or []
    scope_regex = bool(cfg.get("scope_regex"))
    exclude_regex = bool(cfg.get("exclude_regex"))

    def d_in_scope(d):
        """discovered_url 是否在范围内：优先取记录的 in_scope，缺失则用 config.scope 现场算。"""
        v = d.get("in_scope")
        if isinstance(v, bool):
            return v
        return c.url_in_test_scope(d.get("url", ""), scopes, excludes, scope_regex, exclude_regex)

    def page_key(u):
        """页面归一键：norm_url 基础上，把「目录形式」与「/index.php 默认文件」视为同一页面。
        如 .../shop 与 .../shop/index.php 归一为同键，避免目录URL与默认首页文件误判为两个页面。"""
        n = norm_url(u)
        if n.endswith("/index.php"):
            n = n[: -len("/index.php")]
        return n

    # 已解析页面集合（type=page 的范围内 discovered 须命中其一）
    parsed_pages = set()
    for r in pages:
        if r.get("fully_parsed") is True and (r.get("html_file") or ""):
            parsed_pages.add(page_key(r.get("url", "")))

    # discovered 汇总（含来源标签与 type/in_scope），pages ∪ js 同治
    discovered = []  # (label, holder_id, type, in_scope, norm_url)
    for label, recs in (("pages", pages), ("js", jss)):
        for r in recs:
            for d in r.get("discovered_urls", []):
                if d.get("type") in ("page", "api"):
                    discovered.append((label, r.get("id"), d.get("type"),
                                       d_in_scope(d), norm_url(d.get("url", ""))))

    # 改动1【page 覆盖】范围内 type=page 的 discovered → 必须有独立 fully_parsed 页面记录
    # 比对用 page_key（目录/默认index归一；同 path 不同 query 已由 norm_url 去 query 归一）
    _page_reported = set()
    for label, hid, typ, insc, u in discovered:
        if typ != "page" or not insc or not u:
            continue
        k = page_key(u)
        if k not in parsed_pages and k not in _page_reported:
            _page_reported.add(k)
            errors.append("[页面覆盖] 范围内页面链接被发现但未作为独立页面下载解析：%s（来源 %s %s）"
                          % (u, label, hid))

    # 改动1b【api 覆盖】范围内 type=api 的 discovered → 判定"是否被真实访问"（不止 url-inventory）
    # 访问口径：url-inventory（已纳入）∪ 代理成功记录(含被判 resource/js/unknown) ∪ 失败记录。
    proxy_success_urls = {norm_url(rec.get("url", "")) for rec in proxy_idx}
    proxy_success_urls.discard("")
    failed_url_set = {norm_url(rec.get("url", "")) for rec in failed_idx}
    failed_url_set.discard("")
    # 补测清单研判台账：norm_url -> (disposition, 是否已填 access_note)
    retest_items = c.load_json(paths["retest_list"], default={"items": []}).get("items", [])
    retest_disp = {}
    for it in retest_items:
        retest_disp[norm_url(it.get("url", ""))] = (
            it.get("disposition", "pending"), bool((it.get("access_note") or "").strip()))

    _api_reported = set()
    for label, hid, typ, insc, u in discovered:
        if typ != "api" or not insc or not u or u in _api_reported:
            continue
        if u in inv_url_set:
            continue  # 已访问且已纳入 URL 清单
        _api_reported.add(u)
        if u in proxy_success_urls:
            # 真访问成功、仅被代理误判为非接口(resource/js/unknown) → 复核改判纳入挖掘（需求2 核心，消除误报）
            reviews.append("[复核] 范围内接口 %s 已被代理**成功**记录但归类为非接口(资源/脚本/未知)未纳入 URL 清单；"
                           "确为接口则修正代理归类后重跑 build_url_inventory.py 纳入挖掘（来源 %s %s）"
                           % (u, label, hid))
        elif u in failed_url_set:
            # 曾访问失败：默认按"未走通正规业务流程"处置，保留强告警；仅显式研判(retest/blocked)+access_note 后消除
            disp, has_note = retest_disp.get(u, ("pending", False))
            if disp in ("retest", "blocked") and has_note:
                reviews.append("[复核] 范围内接口 %s 访问失败且已研判(%s)：复核 access_note 理由是否成立"
                               "（安全边界所限记 blocked 可不补测；客观阻塞记 retest 交漏洞挖掘阶段补测）（来源 %s %s）"
                               % (u, disp, label, hid))
            else:
                errors.append("[接口覆盖·强告警] 范围内接口被发现但访问失败：通常是未走通正规业务流程——"
                              "应先用 playwright 走通正规业务流程后再访问；确属系统bug/人机校验无法绕过等客观阻塞记 retest、"
                              "安全边界所限记 blocked，在 retest-list.json 填 disposition+access_note 后消除：%s（来源 %s %s）"
                              % (u, label, hid))
        else:
            errors.append("[接口覆盖] 范围内接口被发现但从未被访问(不在 url-inventory/代理记录)：%s（来源 %s %s）"
                          % (u, label, hid))

    # 补测清单 pending 项统一提醒研判（未被上面按接口强告警覆盖的失败URL也须研判）
    for it in retest_items:
        if it.get("disposition") == "pending" and norm_url(it.get("url", "")) not in _api_reported:
            reviews.append("[复核] 补测清单 %s 访问失败未研判：走通则重访问入清单、客观阻塞→retest、"
                           "安全边界/无需测→blocked，并填 access_note：%s" % (it.get("id"), it.get("url")))

    # 改动6【参数覆盖·硬门禁】静态可见的请求参数(url-static-params.json)是否都被代理实测记录；
    # 缺失 = 参数从未随真实请求发送、业务流程未真实走通、漏洞挖掘阶段不会挖掘（治 order_time 类漏报）。
    static_doc = c.load_json(paths["static_params"], default=None)
    check_param_coverage(static_doc, inv_urls, proxy_idx, inv_url_set,
                         proxy_success_urls, retest_disp, scopes, excludes,
                         scope_regex, exclude_regex, errors, reviews)

    # 改动2【page 对称覆盖度】代理 url_index 里 category=page 的范围内 URL → 必须登记 pages 清单
    pages_url_set = {norm_url(r.get("url", "")) for r in pages}
    pages_key_set = {page_key(r.get("url", "")) for r in pages}
    for rec in proxy_idx:
        if rec.get("category") != "page":
            continue
        pu = norm_url(rec.get("url", ""))
        if pu and c.url_in_test_scope(rec.get("url", ""), scopes, excludes, scope_regex, exclude_regex) and page_key(rec.get("url", "")) not in pages_key_set:
            errors.append("[覆盖度] 代理记录的页面未登记 pages 清单：%s（%s）" % (pu, rec.get("id")))

    # 改动4【HTML 正向端点覆盖·硬门禁】页面 HTML 里"形似动态端点"的范围内候选，
    # 若既不在 URL清单 / discovered_urls / 代理记录(成功∪失败) / JS 源(含其 page_key 归一集)，
    # 则判为"页面里有、模型里没有"的漏抓端点 → 硬错误（噪声/不存在项可 acknowledged 豁免）。
    # 根因：清单主要源自代理运行时流量 + 手工 discovered_urls；未被触发且手工漏登的孪生/二级端点
    # （如商品详情页"立即购买"onclick→confirmBuyNow()→ create-order.php）会静默丢失。
    # 本检查用 HTML 静态候选(_candidates_from_html)做正向兜底，补齐既有正向检查"只认 discovered_urls"的盲区。
    modeled = set(inv_url_set)
    modeled |= {u for (_l, _h, _t, _s, u) in discovered}
    modeled |= pages_url_set | proxy_success_urls | failed_url_set | js_src_set
    for r in pages:
        for dj in r.get("discovered_js", []):
            au = norm_url(dj.get("abs_url", ""))
            if au:
                modeled.add(au)
    modeled.discard("")
    modeled_keys = {page_key(u) for u in modeled}

    _html_ep_reported = set()
    for r in pages:
        hf = r.get("html_file") or ""
        if not hf:
            continue
        hp = hf if os.path.isabs(hf) else os.path.join(paths["dir"], hf)
        if not os.path.exists(hp):
            continue
        try:
            with open(hp, "r", encoding="utf-8", errors="replace") as f:
                html = f.read()
        except Exception:
            continue
        base = r.get("url") or ""
        for raw in epu._candidates_from_html(html):
            u = epu._resolve(base, raw)
            if not u or not _looks_dyn_endpoint(u):
                continue
            if not c.url_in_test_scope(u, scopes, excludes, scope_regex, exclude_regex):
                continue
            if u in modeled or page_key(u) in modeled_keys or u in _html_ep_reported:
                continue
            _html_ep_reported.add(u)
            errors.append("[HTML端点覆盖] 页面HTML出现的范围内端点未纳入任何模型"
                          "(URL清单/discovered_urls/代理记录)：%s（页面 %s；应补登记 discovered_urls、"
                          "playwright 走通业务后并入 URL 清单挖掘；确不存在/噪声则在 "
                          "state.json.gates.breadth.acknowledged 记 match+reason_code+note 豁免）"
                          % (u, r.get("id")))

    # 改动5【业务链 related_urls 反向对账·硬门禁】业务链声明的范围内 related_url，
    # 若既不在 URL清单、也不在代理成功/失败记录（即从未被真正访问、进不了漏洞挖掘阶段），则硬报错。
    # 根因：related_urls 是"跑业务得到的知识"，可含服务端返回、运行时 window.open 的动态 URL——
    # 如天积宝支付 pay/index.php：pay_url 由接口响应返回、JS 里只有 window.open(payUrl) 无静态串，
    # 静态提取与改动4(HTML正向)均抓不到；且既有 (b) 交叉引用把 related_urls 当"承载方"，
    # 从不反向要求其进 inventory → URL 只活在业务链里，穿过所有覆盖检查，漏洞挖掘阶段(从 inventory 取)永远看不到。
    # 客观走不通者(第三方支付弹窗等)在 retest-list.json 记 disposition+access_note，
    # 或 state.json.gates.breadth.acknowledged 记 match+reason_code+note 豁免。
    _chain_reported = set()
    for r in chains:
        cid = r.get("id")
        for raw in r.get("related_urls", []):
            u = norm_url(raw)
            if not u or u in _chain_reported or u in _api_reported:
                continue
            if not c.url_in_test_scope(raw, scopes, excludes, scope_regex, exclude_regex):
                continue
            if u in inv_url_set or u in proxy_success_urls or u in failed_url_set or u in js_src_set:
                continue
            _chain_reported.add(u)
            disp, has_note = retest_disp.get(u, ("pending", False))
            if disp in ("retest", "blocked") and has_note:
                reviews.append("[复核] 业务链 related_url %s 未被访问但已研判(%s)：复核 access_note 理由是否成立"
                               "（第三方支付弹窗等客观走不通记 blocked；可补测记 retest 交漏洞挖掘阶段）（业务链 %s）"
                               % (u, disp, cid))
            else:
                errors.append("[业务链覆盖] 业务链 related_url 为范围内端点却从未被真正访问"
                              "(不在 URL清单/代理成功/代理失败记录)，无法进入漏洞挖掘阶段：%s（业务链 %s；"
                              "应先用 playwright 走通该业务流程使其入代理与 URL 清单；确属客观走不通(如第三方支付弹窗)"
                              "在 retest-list.json 记 disposition+access_note，或 state.json.gates.breadth.acknowledged "
                              "记 match+reason_code+note 豁免）" % (u, cid))

    # (b) URL 清单的 page/api → 应在 页面.url ∪ 所有 discovered_urls ∪ 业务链.related_urls 承载
    coverage = set(pages_url_set)
    coverage |= {u for (_l, _h, _t, _s, u) in discovered}
    for r in chains:
        for u in r.get("related_urls", []):
            coverage.add(norm_url(u))
    for u in inv_pageapi:
        if u and u not in coverage:
            errors.append("[交叉引用] URL 清单的 page/api 未在 页面/JS/业务链 中承载：%s" % u)

    # 改动3【in_scope 校验】discovered_urls 的 in_scope 类型合法 + 与现场计算一致性（pages ∪ js）
    for label, recs in (("pages", pages), ("js", jss)):
        for r in recs:
            for d in r.get("discovered_urls", []):
                if d.get("type") not in ("page", "api"):
                    continue
                v = d.get("in_scope")
                if v is not None and not isinstance(v, bool):
                    errors.append("[in_scope] %s %s 的 discovered_url in_scope 非 bool：%r（%s）"
                                  % (label, r.get("id"), v, d.get("url")))
                elif isinstance(v, bool):
                    calc = c.url_in_test_scope(d.get("url", ""), scopes, excludes, scope_regex, exclude_regex)
                    if v != calc:
                        reviews.append("[复核] %s %s 的 discovered_url in_scope=%s 与按 config.scope 现场计算(%s)不一致，确认是否 scope 变更或误标：%s"
                                       % (label, r.get("id"), v, calc, d.get("url")))

    # not_found / 空 一致性（JS：已读却空 → 应判定；未读却 not_found → 存疑）
    for r in jss:
        read = r.get("fully_read") is True
        for fld in ("secrets", "business_constraints"):
            v = r.get(fld)
            is_nf = v == c.NOT_FOUND or v == [c.NOT_FOUND]
            is_empty = v in ("", [], None)
            if read and is_empty:
                reviews.append("[一致性] js %s 已读但 %s 为空，应判定为 not_found 或填具体值" % (r.get("id"), fld))
            if (not read) and is_nf:
                reviews.append("[一致性] js %s 未读完却填 %s=not_found，请确认" % (r.get("id"), fld))

    # 待 AI 语义复核
    for u in inv_urls:
        if u.get("needs_review"):
            reviews.append("[复核] URL %s category=other，判断是否实为页面/接口：%s" % (u.get("id"), u.get("url")))
    for r in jss:
        if r.get("is_opensource") is True:
            reviews.append("[复核] JS %s 标 is_opensource(不下载不通读)，确认确为开源第三方库：%s"
                           % (r.get("id"), r.get("source_url")))
        if r.get("download_status") == "failed":
            reviews.append("[复核] JS %s 下载失败，确认是资源不存在而非路径拼接错误：%s"
                           % (r.get("id"), r.get("source_url")))
    reviews.append("[复核] extract_page_urls.py 列出的「疑似未登记」候选 URL，逐条判断是否遗漏页面/接口/JS")
    reviews.append("[复核] 先跑 build_retest_list.py 刷新补测清单(retest-list.json)，再逐条研判失败URL："
                   "失败默认是没走通业务→优先 playwright 走通；确属客观阻塞→disposition=retest 交漏洞挖掘阶段补测；"
                   "安全边界所限→disposition=blocked 留痕不补测；均须填 access_note")
    for r in chains:
        if r.get("walkthrough_status") in ("partial", "blocked"):
            reviews.append("[复核] 业务链 %s 未完全走通(%s)，确认是客观/边界限制而非操作错误：%s"
                           % (r.get("id"), r.get("walkthrough_status"), r.get("name")))
    reviews.append("[复核] 业务链是否覆盖所有业务目标 / 生命周期 / 可交互元素 / 接口，有无遗漏")
    reviews.append("[复核] 威胁建模是否充分考虑业务约束条件")
    reviews.append("[复核] 抽查 not_found 记录确属未发现；检查所有 notes 是否符合实际、合理")

    # 权限矩阵覆盖（攻击面/URL 覆盖清零后，对全部 page/api URL 逐角色验证访问控制）
    check_permission_matrix([u for u in inv_urls if u.get("category") in ("page", "api")], paths, errors, reviews)
    reviews.append("[复核] 权限矩阵 judgment=abnormal（越权/未授权）的项是否均已补入 threats.jsonl 作为攻击面威胁（related_objects 指向该 URL、verification_status=pending）")
    reviews.append("[复核] 各角色 session_valid=true；存在 false（会话失效）者其判定不作数，须重登刷新 sessions.json 后重跑 permission_probe.py 再复核")

    # 报告 + 门禁退出态落盘（由脚本写 state.json.gates.breadth，供下一阶段强制校验）
    print("==== 广度建模质量门禁——脚本硬检查 ====")
    print("页面 %d | JS %d | 业务链 %d | 威胁 %d | URL清单 %d"
          % (len(pages), len(jss), len(chains), len(threats), len(inv_urls)))
    print("")
    sys.exit(1 if c.emit_gate_result(paths, "breadth", errors, reviews) else 0)


if __name__ == "__main__":
    main()
