"""提交方式 → 请求中间态 → 输出渲染器（§6.3 两级）+ 成品约束校验（§8.2）。"""

import json
from urllib.parse import quote, urlsplit

from .bypass import shell_quote

# ---------------------------------------------------------------- 提交方式处理器
# 组装结果 + 提交方式 → 请求中间态 {method, url, headers, body}


# 固定 boundary：§4.3 要求输出确定性，随机 boundary 会让黄金样本失效
BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW"


def _base_url(state):
    scheme = state.get("scheme", "http")
    return "%s://%s%s" % (scheme, state.get("host", "example.com"), state.get("path", "/"))


def _multipart_body(payload, state):
    """文件上传的 multipart 体。

    `part` 决定载荷落在哪：`filename`（文件名，路径穿越常用）或 `content`（文件内容）。
    这是 §B.6 里唯一需要新提交方式的场景——原来的 place.* 只有 urlencoded 表单，
    出不了 multipart。
    """
    field = state.get("field", "file")
    part = state.get("part", "filename")
    if part == "content":
        filename, content = state.get("filename", "a.txt"), payload
    elif part == "filename":
        filename, content = payload, state.get("content", "x")
    else:
        raise ValueError("未知 part: %s（只能是 filename / content）" % part)

    return (
        "--{b}\r\n"
        'Content-Disposition: form-data; name="{field}"; filename="{fn}"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
        "{content}\r\n"
        "--{b}--\r\n"
    ).format(b=BOUNDARY, field=field, fn=filename, content=content)


def place(payload, state):
    submit = state.get("submit", "query")
    method = state.get("method", "GET")
    param = state.get("param", "id")
    url, headers, body = _base_url(state), {}, None

    if submit == "query":
        sep = "&" if "?" in url else "?"
        url = "%s%s%s=%s" % (url, sep, param, quote(payload, safe=""))
    elif submit == "path":
        url = url.rstrip("/") + "/" + quote(payload, safe="")
    elif submit == "header":
        headers[state.get("header", "X-Test")] = payload
    elif submit == "cookie":
        headers["Cookie"] = "%s=%s" % (state.get("cookie", "sid"), payload)
    elif submit == "json":
        # 载荷作为**一个字段的字符串值**塞进去
        headers["Content-Type"] = "application/json"
        body = json.dumps({param: payload})
    elif submit == "json-body":
        # 载荷**就是整个 JSON 体**（不加引号）。NoSQL 注入的对象型载荷走这条——
        # `{"$ne": null}` 当字符串值塞进去会变成 "{\"$ne\": null}"，完全不是一个东西。
        headers["Content-Type"] = "application/json"
        body = payload
    elif submit == "form":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = "%s=%s" % (param, quote(payload, safe=""))
    elif submit == "raw":
        body = payload
    elif submit == "multipart":
        headers["Content-Type"] = "multipart/form-data; boundary=" + BOUNDARY
        body = _multipart_body(payload, state)
    else:
        raise ValueError("未知提交方式: %s" % submit)

    if body is not None and method == "GET":
        method = "POST"
    return {"method": method, "url": url, "headers": headers, "body": body}


# ---------------------------------------------------------------- 输出渲染器
# 请求中间态 + 输出形态 → 最终文本

PLACERS = ["query", "path", "header", "cookie", "json", "json-body", "form", "raw", "multipart"]

RENDERERS = ["raw", "encoded", "request", "curl", "httpie", "powershell", "python", "node", "java", "php", "burp"]


def _render_raw(req, payload, state):
    return payload


def _render_encoded(req, payload, state):
    return quote(payload, safe="")


def _render_request(req, payload, state):
    u = urlsplit(req["url"])
    target = u.path + (("?" + u.query) if u.query else "")
    lines = ["%s %s HTTP/1.1" % (req["method"], target), "Host: " + u.netloc]
    lines += ["%s: %s" % (k, v) for k, v in req["headers"].items()]
    body = req["body"] or ""
    if body:
        lines.append("Content-Length: %d" % len(body.encode("utf-8")))
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _curl_args(req, state):
    args = []
    if req["method"] != "GET":
        args += ["-X", req["method"]]
    for k, v in req["headers"].items():
        args += ["-H", "%s: %s" % (k, v)]
    if req["body"] is not None:
        args += ["--data", req["body"]]
    args.append(req["url"])
    return args


def _render_curl(req, payload, state):
    shell = state.get("shell", "bash")
    return "curl " + " ".join(shell_quote(a, shell) for a in _curl_args(req, state))


def _render_httpie(req, payload, state):
    shell = state.get("shell", "bash")
    args = [req["method"], req["url"]] + ["%s:%s" % (k, v) for k, v in req["headers"].items()]
    if req["body"] is not None:
        args.append("<<< " + req["body"])
    return "http " + " ".join(shell_quote(a, shell) for a in args)


def _render_powershell(req, payload, state):
    u = urlsplit(req["url"])
    lines = ["$r = Invoke-WebRequest -Uri '%s' -Method %s" % (req["url"], req["method"])]
    if req["headers"]:
        h = "; ".join("'%s'='%s'" % (k, v.replace("'", "''")) for k, v in req["headers"].items())
        lines.append("$r.Headers = @{%s}" % h)
    if req["body"] is not None:
        lines.append("$r.Body = '%s'" % req["body"].replace("'", "''"))
    return "\n".join(lines)


def _render_python(req, payload, state):
    lines = ["import requests", "", "r = requests.%s(" % req["method"].lower()]
    lines.append("    %r," % req["url"])
    if req["headers"]:
        lines.append("    headers=%r," % (req["headers"],))
    if req["body"] is not None:
        lines.append("    data=%r," % req["body"])
    lines.append(")")
    return "\n".join(lines)


def _render_node(req, payload, state):
    lines = ["await fetch(%r, {" % req["url"], "  method: %r," % req["method"]]
    if req["headers"]:
        lines.append("  headers: %s," % json.dumps(req["headers"]))
    if req["body"] is not None:
        lines.append("  body: %s," % json.dumps(req["body"]))
    lines.append("});")
    return "\n".join(lines)


def _render_java(req, payload, state):
    return (
        "var client = java.net.http.HttpClient.newHttpClient();\n"
        "var req = java.net.http.HttpRequest.newBuilder()\n"
        "    .uri(java.net.URI.create(%s))\n"
        "    .method(%s, java.net.http.HttpRequest.BodyPublishers.ofString(%s))\n"
        "    .build();\n"
        "client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());"
        % (json.dumps(req["url"]), json.dumps(req["method"]), json.dumps(req["body"] or ""))
    )


def _render_php(req, payload, state):
    lines = ["$ch = curl_init();", "curl_setopt($ch, CURLOPT_URL, %s);" % json.dumps(req["url"])]
    if req["method"] != "GET":
        lines.append("curl_setopt($ch, CURLOPT_CUSTOMREQUEST, %s);" % json.dumps(req["method"]))
    if req["headers"]:
        h = ", ".join("%s: %s" % (k, v) for k, v in req["headers"].items())
        lines.append("curl_setopt($ch, CURLOPT_HTTPHEADER, [%s]);" % json.dumps(h))
    if req["body"] is not None:
        lines.append("curl_setopt($ch, CURLOPT_POSTFIELDS, %s);" % json.dumps(req["body"]))
    lines.append("curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);")
    lines.append("$r = curl_exec($ch);")
    return "\n".join(lines)


def _render_burp(req, payload, state):
    return _render_request(req, payload, state)


_RENDER = {
    "raw": _render_raw,
    "encoded": _render_encoded,
    "request": _render_request,
    "curl": _render_curl,
    "httpie": _render_httpie,
    "powershell": _render_powershell,
    "python": _render_python,
    "node": _render_node,
    "java": _render_java,
    "php": _render_php,
    "burp": _render_burp,
}


def render(name, req, payload, state):
    fn = _RENDER.get(name)
    if fn is None:
        raise ValueError("未知输出形态: %s" % name)
    return fn(req, payload, state)


# ---------------------------------------------------------------- 成品约束校验（§8.2）
# 提示，不拦截。未设约束时不产生任何条目。

# 提交方式会不会在放入请求时再做一次 URL 编码
TRANSPORT_CODEC = {"query": "url", "path": "url", "form": "url"}

# 每种 codec 相当于几轮 URL 编码，用于数重复次数
_URL_ROUNDS = {"url": 1, "url2": 2}


def _double_encoding_note(state, applied):
    """绕过链里已经有 URL 编码、提交方式又会再编一次 —— 提示可能重复编码。

    方案 §7 规定"用户的选择，工具不拦不提示"，但双重编码多数时候是误操作
    而非有意为之，所以这里只加一条提示（仍然不拦截）。
    """
    transport = TRANSPORT_CODEC.get(state.get("submit", "query"))
    if not transport:
        return None
    rounds = 0
    for b in applied or []:
        if b.get("type") == "encode":
            rounds += _URL_ROUNDS.get((b.get("params") or {}).get("codec"), 0)
    if not rounds:
        return None
    return ("绕过链已做 %d 次 URL 编码，提交方式 %s 放入请求时会再编码一次（请求内共 %d 次）；"
            "若本意只是 WAF 绕过可忽略" % (rounds, state.get("submit", "query"), rounds + 1))


def _applies_to_note(state, applied):
    """绕过上与当前漏洞类型不匹配的提示。

    §4.1 决定绕过不做过滤（全量可选），但 `applies_to` 字段若就此闲置就是死数据。
    改成提示：跨类型套用绕过（比如把 SQL 的空格绕过套到 shell 命令上）照样生成，
    但明确告诉用户这可能不适用 —— 仍然不拦截。
    """
    vuln = state.get("vuln")
    if not vuln:
        return None
    bad = []
    for b in applied or []:
        at = b.get("applies_to") or []
        if at and vuln not in at:
            bad.append("%s（标注适用于 %s）" % (b.get("name", b["id"]), "/".join(at)))
    if not bad:
        return None
    return ("绕过与当前漏洞类型不匹配：%s，当前是 %s；仍按你的选择应用了"
            % ("；".join(bad), vuln))


def check_constraints(payload, state, applied=None):
    c = state.get("constraints") or {}
    issues = []
    if c.get("max_len") is not None and len(payload) > c["max_len"]:
        issues.append("长度 %d 超过上限 %d" % (len(payload), c["max_len"]))
    for ch in c.get("forbidden_chars") or []:
        if ch in payload:
            issues.append("含被禁字符 %r" % ch)
    for kw in c.get("blocked_keywords") or []:
        if kw.lower() in payload.lower():
            issues.append("含黑名单关键字 %r" % kw)
    for note in (_double_encoding_note(state, applied), _applies_to_note(state, applied)):
        if note:
            issues.append(note)
    return issues
