# -*- coding: utf-8 -*-
"""
mitmproxy 插件：记录流经代理的所有 HTTP/HTTPS 请求包，按「主机 + 路径」分类落盘。

由 start.py 调用（也可手动）：
    mitmdump -s proxy/recorder.py --listen-host 127.0.0.1 --listen-port 24304

可配置环境变量（由 start.py 注入，仅本进程）：
    PROXY_LOG_DIR       日志目录（默认 proxy-logs，相对 mitmdump 工作目录）
    PROXY_TARGET_HOSTS  逗号分隔的目标主机过滤（子串匹配）；为空则记录全部
    PROXY_SCOPE         JSON 数组，范围白名单（域名/路径/正则）；为空记录全部
    PROXY_SCOPE_REGEX   "1" 时把 PROXY_SCOPE 每条当正则
    PROXY_EXCLUDE       JSON 数组，排除黑名单（语法同 scope，优先级高于 scope）；命中则不记录
    PROXY_EXCLUDE_REGEX "1" 时把 PROXY_EXCLUDE 每条当正则
    PROXY_BODY_CAP      原始请求 body 落盘截断字节数（默认 1MB，0=不限）
    PROXY_VALUE_CAP     参数样本值最大字符数（默认 100，超出截断）
    PROXY_RESP_PREVIEW_CAP  响应体预览落盘字节数（默认 200，0=不记录）；仅文本类响应（page/api/other）

产物（日志目录下）：
    url_index.jsonl     URL 路径清单，每路径一行（id/参数名/参数数/请求次数…）
    requests/<id>.log   该路径的全部原始请求报文（含响应头 + 文本类响应体预览），追加写、崩溃安全
    params/<id>.json    该路径的参数详情（来源/数据类型/参数名/样本值），仅有参数时生成

设计要点：
    - 路径标识 = 完整 URL（协议+主机+路径，不含 query），编码 = URL + 5 位序号。
    - 原始请求以二进制 append 写入，文件上传等二进制 body 原样保留、不被破坏。
    - 钩子用 response + error：有响应附响应头（文本类另附响应体前若干字节预览），无响应也记录请求本身。
    - 启动时从既有 url_index.jsonl + params/*.json 重建状态 → 重启续跑、编码稳定、计数累加。
"""

import email
import json
import logging
import os
import re
import threading
import time
from urllib.parse import parse_qsl, urlsplit, urlunsplit

log = logging.getLogger("recorder")

LOG_DIR = os.environ.get("PROXY_LOG_DIR", "proxy-logs")
TARGET_HOSTS = [h.strip() for h in os.environ.get("PROXY_TARGET_HOSTS", "").split(",") if h.strip()]
SCOPES = json.loads(os.environ.get("PROXY_SCOPE", "") or "[]")
SCOPE_REGEX = os.environ.get("PROXY_SCOPE_REGEX", "") == "1"
EXCLUDES = json.loads(os.environ.get("PROXY_EXCLUDE", "") or "[]")
EXCLUDE_REGEX = os.environ.get("PROXY_EXCLUDE_REGEX", "") == "1"
BODY_CAP = int(os.environ.get("PROXY_BODY_CAP", str(1024 * 1024)))
VALUE_CAP = int(os.environ.get("PROXY_VALUE_CAP", "100"))
RESP_PREVIEW_CAP = int(os.environ.get("PROXY_RESP_PREVIEW_CAP", "200"))

SEPARATOR = b"=" * 60


# --------------------------- 通用辅助 ---------------------------

def _safe_text(message):
    """取 HTTP 消息体文本，自动解 gzip/deflate 等内容编码；失败返回空串。"""
    try:
        txt = message.get_text(strict=False)
        return txt if txt is not None else ""
    except Exception:
        return ""


def _truncate(value, cap):
    """转字符串并按 cap 截断（cap<=0 表示不截断）。"""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    if cap and len(s) > cap:
        return s[:cap]
    return s


def _infer_scalar_type(text):
    """对字符串值做轻量数据类型推断：boolean / number / string。"""
    t = (text or "").strip()
    if t.lower() in ("true", "false"):
        return "boolean"
    if t and re.fullmatch(r"[+-]?\d+(\.\d+)?([eE][+-]?\d+)?", t):
        return "number"
    return "string"


def _json_type(v):
    """Python 值 -> JSON 数据类型名（bool 必须先于 int 判断）。"""
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "string"


def _json_value_str(v):
    """把 JSON 叶子值转为样本字符串。"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _flatten_json(obj, prefix=""):
    """把 JSON 结构展平为 [(name, value, json_type)]：嵌套用点路径、数组折叠下标。
    空对象/空数组作为叶子保留其参数名（标 object/array），避免漏掉参数。"""
    out = []
    if isinstance(obj, dict):
        if not obj and prefix:
            out.append((prefix.rstrip("."), obj, "object"))
        for k, v in obj.items():
            out += _flatten_json(v, "{}{}.".format(prefix, k))
    elif isinstance(obj, list):
        if not obj and prefix:
            out.append((prefix.rstrip("."), obj, "array"))
        for v in obj:
            out += _flatten_json(v, prefix)
    else:
        name = prefix.rstrip(".")
        if name:
            out.append((name, obj, _json_type(obj)))
    return out


def _parse_multipart(content_type, body):
    """解析 multipart/form-data，返回 [(name, source, type, value)]。
    用标准库 email 解析每个 part 的 Content-Disposition（name/filename）与 Content-Type：
        有 filename → multipart-file / file，样本记 "filename (content-type)"，不落文件内容；
        无 filename → multipart-field，值做类型推断。
    解析失败返回 []（由调用方回退到 req.multipart_form）。"""
    out = []
    try:
        raw = b"Content-Type: " + content_type.encode("utf-8", "replace") + b"\r\n\r\n" + (body or b"")
        msg = email.message_from_bytes(raw)
        if not msg.is_multipart():
            return out
        for part in msg.get_payload():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_param("filename", header="content-disposition")
            if name is None:
                continue
            if filename is not None:
                pct = part.get_content_type() or "application/octet-stream"
                out.append((name, "multipart-file", "file", "{} ({})".format(filename, pct)))
            else:
                payload = part.get_payload(decode=True)
                val = payload.decode("utf-8", "replace") if payload is not None else ""
                out.append((name, "multipart-field", _infer_scalar_type(val), val))
    except Exception:
        return []
    return out


def _extract_params(req):
    """从请求中提取全部参数：返回 [(name, source, type, value)]。
    覆盖 query / json / x-www-form-urlencoded / multipart（文件+字段）。"""
    params = []

    # 1) URL 查询参数
    try:
        for k, v in parse_qsl(urlsplit(req.url).query, keep_blank_values=True):
            params.append((k, "query", _infer_scalar_type(v), v))
    except Exception:
        pass

    # 2) body：按 content-type 分发
    ct = req.headers.get("content-type", "").lower()
    try:
        if "application/json" in ct:
            txt = _safe_text(req)
            if txt.strip():
                data = json.loads(txt)
                for name, val, jtype in _flatten_json(data):
                    params.append((name, "json", jtype, _json_value_str(val)))
        elif "x-www-form-urlencoded" in ct:
            for k, v in req.urlencoded_form.items(multi=True):
                params.append((k, "form", _infer_scalar_type(v), v))
        elif "multipart/form-data" in ct:
            mp = _parse_multipart(req.headers.get("content-type", ""), req.content)
            if mp:
                params.extend(mp)
            else:  # 解析失败回退：只取字段名，无法区分文件
                for k, v in req.multipart_form.items(multi=True):
                    val = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)
                    params.append((k, "multipart-field", _infer_scalar_type(val), val))
    except Exception:
        pass

    return params


def _headers_bytes(headers):
    """把 mitmproxy Headers 序列化为原始字节（保留顺序/大小写/重复头）。"""
    out = bytearray()
    try:
        for k, v in headers.fields:  # tuple[bytes, bytes]
            if isinstance(k, str):
                k = k.encode("utf-8", "replace")
            if isinstance(v, str):
                v = v.encode("utf-8", "replace")
            out += k + b": " + v + b"\r\n"
    except Exception:
        for k, v in headers.items():
            out += "{}: {}\r\n".format(k, v).encode("utf-8", "replace")
    return bytes(out)


# --------------------------- URL 分类（按响应 Content-Type） ---------------------------

# 类别优先级（数字越小越优先）：同一路径出现多种响应类型时，取优先级最高者。
# js 从资源大类独立成一类，便于门禁用「请求日志里的 js」反查「js 清单」的完整性。
_CATEGORY_RANK = {"page": 0, "api": 1, "js": 2, "resource": 3, "other": 4, "unknown": 5}

_BINARY_RESOURCE_TYPES = {
    "application/pdf", "application/wasm", "application/octet-stream",
    "application/zip", "application/gzip", "application/x-gzip",
    "application/x-tar", "application/x-7z-compressed", "application/x-rar-compressed",
    "application/vnd.ms-fontobject", "application/x-font-ttf", "application/x-font-woff",
}


def classify_content_type(ct):
    """根据响应 Content-Type 把 URL 归类：page / api / js / resource / other。
    判定顺序保证 image/svg+xml 等先按资源归类，避免被 *+xml 规则误判为 api。"""
    ct = (ct or "").split(";")[0].strip().lower()
    if not ct:
        return "other"
    # 页面
    if ct in ("text/html", "application/xhtml+xml"):
        return "page"
    # 脚本：JavaScript / ECMAScript 独立成 js 类
    if "javascript" in ct or "ecmascript" in ct:
        return "js"
    # 资源：样式
    if ct == "text/css":
        return "resource"
    # 资源：媒体 / 字体（含 image/svg+xml）
    if ct.startswith(("image/", "font/", "audio/", "video/")):
        return "resource"
    # 资源：二进制 / 文档 / 字体
    if ct in _BINARY_RESOURCE_TYPES or "font" in ct:
        return "resource"
    # 接口：结构化数据
    if "json" in ct:
        return "api"
    if ct in ("application/xml", "text/xml") or ct.endswith("+xml"):
        return "api"
    if ct.startswith("application/grpc") or "protobuf" in ct:
        return "api"
    if ct == "text/csv":
        return "api"
    return "other"


# 动态脚本后缀（服务端脚本；即便返回图片/二进制也应视为接口，而非静态资源）
_DYNAMIC_EXT_RE = re.compile(
    r"\.(?:php[0-9s]?|phtml|asp|aspx|ashx|asmx|axd|jsp|jspx|jspa|do|action"
    r"|cgi|fcgi|pl|py|rb|cfm)$", re.I)
# 静态资源后缀（优先级高于接口路径信号：即便在 /api/ 下也仍判资源，避免 /api/img/logo.png 误判）
_STATIC_EXT_RE = re.compile(
    r"\.(?:css|less|scss|png|jpe?g|gif|svg|webp|bmp|ico|cur|apng|tiff?"
    r"|woff2?|ttf|otf|eot|mp[34]|m4[av]|aac|oga|ogg|opus|wav|weba|webm|mkv|avi|mov|flv|wmv"
    r"|pdf|zip|gz|bz2|xz|7z|rar|tar|tgz|wasm|swf|map)$", re.I)
# 接口路径信号（RESTful/AJAX/RPC 风格入口）——无明确后缀时据此判端点
_API_PATH_RE = re.compile(
    r"/(?:api|apis|rest|restful|ajax|graphql|gql|rpc|jsonrpc|service|services"
    r"|webservice|gateway|interface)(?:/|$)", re.I)


def _looks_like_endpoint(url):
    """据请求路径/后缀判断 URL 是否为动态接口端点（与响应类型无关）。
    优先级：动态脚本后缀 → 静态资源后缀 → 接口路径信号 → 否。
    静态后缀优先于路径信号，避免 /api/img/logo.png 之类静态资源被误判为接口。"""
    try:
        path = urlsplit(url).path or ""
    except Exception:
        return False
    last = path.rsplit("/", 1)[-1]
    if _DYNAMIC_EXT_RE.search(last):
        return True
    if _STATIC_EXT_RE.search(last):
        return False
    return bool(_API_PATH_RE.search(path))


def classify_url(url, content_type):
    """结合请求路径/后缀与响应 Content-Type 归类 URL。
    先按响应 Content-Type 得基础类别；当基础类别为 resource 但路径特征表明是动态接口端点
    （脚本后缀如 .php 或 /api/ 路径）时纠正为 api——避免图片验证码等接口被误判为资源而漏挖。
    只纠 resource→api，其余分类不动（page/api/js/other 已由内容判定，无需纠偏）。"""
    base = classify_content_type(content_type)
    if base == "resource" and _looks_like_endpoint(url):
        return "api"
    return base


def _response_preview(resp, cap):
    """文本类响应（page/api/other）返回响应体前 cap 字节（已解压）；否则/无体返回 None。
    按纯 MIME 分类门控：js/资源/二进制（含 captcha.php 返回的 image/png 等）一律跳过，
    既避免把二进制字节写进日志，也免去为取 cap 字节而整体解压大响应的开销。"""
    if cap <= 0:
        return None
    if classify_content_type(resp.headers.get("content-type", "")) not in ("page", "api", "other"):
        return None
    try:
        body = resp.content or b""   # 访问即触发内容解码（解压）；js/resource 已被上面挡掉
    except Exception:
        return None
    return body[:cap] if body else None


# --------------------------- 路径记录 ---------------------------

class UrlRecord:
    """一个 URL（协议+主机+路径，不含 query）的聚合状态。"""

    def __init__(self, code, url):
        self.code = code
        self.url = url
        self.methods = set()
        self.request_count = 0
        self.first_seen = ""
        self.last_seen = ""
        self.category = "unknown"      # page / api / js / resource / other / unknown
        self.content_types = set()     # 见过的所有响应 MIME（去重）
        self.status_codes = {}         # 仅失败桶用：{"404": n, "no-response": n}
        self.params = {}  # (source, name) -> {name, source, type, sample_value}

    def param_names(self):
        return sorted({name for (_src, name) in self.params.keys()})

    def update_category(self, content_type):
        """有响应时调用：并入响应 MIME，结合 URL 路径/后缀与响应类型按优先级更新分类
        （page > api > js > resource > other）。经 classify_url 纠偏：动态端点即便返回资源型 MIME 也归 api。"""
        mime = (content_type or "").split(";")[0].strip().lower()
        if mime:
            self.content_types.add(mime)
        cat = classify_url(self.url, content_type)
        if _CATEGORY_RANK.get(cat, 4) < _CATEGORY_RANK.get(self.category, 4):
            self.category = cat

    def add_status(self, status):
        """失败桶用：累计失败状态码分布；status 为 None 记 no-response。"""
        key = str(status) if status is not None else "no-response"
        self.status_codes[key] = self.status_codes.get(key, 0) + 1

    def index_line(self):
        names = self.param_names()
        d = {
            "id": self.code,
            "url": self.url,
            "methods": sorted(self.methods),
            "category": self.category,
            "content_types": sorted(self.content_types),
        }
        if self.status_codes:
            d["status_codes"] = dict(sorted(self.status_codes.items()))
        d.update({
            "param_count": len(names),
            "param_names": names,
            "request_count": self.request_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        })
        return d

    def params_doc(self):
        return {
            "id": self.code,
            "url": self.url,
            "param_count": len(self.param_names()),
            "params": [self.params[k] for k in sorted(self.params.keys())],
        }


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.codes = {}        # path_key -> code（成功/失败统一编码）
        self.totals = {}       # path_key -> 总请求数（成功+失败，用作 <id>.log 的 #seq）
        self.success = {}      # path_key -> UrlRecord（成功请求 → url_index.jsonl + params）
        self.failed = {}       # path_key -> UrlRecord（失败请求 → failed_index.jsonl）
        self.next_seq = 1
        self.log_dir = LOG_DIR
        self.req_dir = os.path.join(self.log_dir, "requests")
        self.param_dir = os.path.join(self.log_dir, "params")
        self.success_index = os.path.join(self.log_dir, "url_index.jsonl")
        self.failed_index = os.path.join(self.log_dir, "failed_index.jsonl")
        self.targets = TARGET_HOSTS
        self.body_cap = BODY_CAP
        self.value_cap = VALUE_CAP
        self.resp_preview_cap = RESP_PREVIEW_CAP
        self.scope_regex = SCOPE_REGEX
        self.scope_rules = [re.compile(s) for s in SCOPES] if SCOPE_REGEX else list(SCOPES)
        self.exclude_regex = EXCLUDE_REGEX
        self.exclude_rules = [re.compile(s) for s in EXCLUDES] if EXCLUDE_REGEX else list(EXCLUDES)
        os.makedirs(self.req_dir, exist_ok=True)
        os.makedirs(self.param_dir, exist_ok=True)
        self._rehydrate()

    # ---- 启动时从既有日志重建状态（成功 + 失败两个清单）----
    def _rehydrate(self):
        max_seq = [0]
        self._rehydrate_bucket(self.success_index, self.success, True, max_seq)
        self._rehydrate_bucket(self.failed_index, self.failed, False, max_seq)
        for pk, rec in self.success.items():
            self.totals[pk] = self.totals.get(pk, 0) + rec.request_count
        for pk, rec in self.failed.items():
            self.totals[pk] = self.totals.get(pk, 0) + rec.request_count
        self.next_seq = max_seq[0] + 1

    def _rehydrate_bucket(self, index_file, bucket, restore_params, max_seq):
        if not os.path.exists(index_file):
            return
        restored = 0
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except Exception:
                        continue
                    code = d.get("id")
                    url = d.get("url", "")
                    if not code or not url:
                        continue
                    rec = UrlRecord(code, url)
                    rec.methods = set(d.get("methods", []))
                    rec.request_count = int(d.get("request_count", 0) or 0)
                    rec.first_seen = d.get("first_seen", "")
                    rec.last_seen = d.get("last_seen", "")
                    rec.category = d.get("category", "unknown")
                    # 后缀/路径纠偏：旧日志里被判 resource 的动态端点，重建时纠正为 api（与新记录口径一致，无需全量重爬）
                    if rec.category == "resource" and _looks_like_endpoint(url):
                        rec.category = "api"
                    rec.content_types = set(d.get("content_types", []))
                    rec.status_codes = dict(d.get("status_codes", {}) or {})
                    if restore_params:
                        self._restore_params(rec)
                    bucket[url] = rec
                    self.codes[url] = code
                    m = re.match(r"URL0*(\d+)$", code)
                    if m:
                        max_seq[0] = max(max_seq[0], int(m.group(1)))
                    restored += 1
        except Exception as e:
            log.warning("rehydrate(%s) failed: %s", os.path.basename(index_file), e)
        if restored:
            log.info("rehydrated %d entries from %s", restored, os.path.basename(index_file))

    def _restore_params(self, rec):
        pfile = os.path.join(self.param_dir, rec.code + ".json")
        if not os.path.exists(pfile):
            return
        try:
            with open(pfile, "r", encoding="utf-8") as f:
                doc = json.load(f)
            for p in doc.get("params", []):
                key = (p.get("source"), p.get("name"))
                rec.params[key] = {
                    "name": p.get("name"),
                    "source": p.get("source"),
                    "type": p.get("type"),
                    "sample_value": p.get("sample_value", ""),
                }
        except Exception:
            pass

    # ---- 作用域过滤 ----
    def _in_scope(self, url, host):
        # 排除优先：命中 --exclude 直接不记录（即使在 scope 内），语法同 scope
        if self.exclude_rules:
            if self.exclude_regex:
                if any(p.search(url) for p in self.exclude_rules):
                    return False
            elif any(self._scope_match_literal(e, url, host) for e in self.exclude_rules):
                return False
        # --target-hosts（主机子串）与 --scope（域名/路径/正则）取交集；未配置的过滤器放行
        if self.targets and not any(t in host for t in self.targets):
            return False
        if self.scope_rules:
            if self.scope_regex:
                if not any(p.search(url) for p in self.scope_rules):
                    return False
            elif not any(self._scope_match_literal(s, url, host) for s in self.scope_rules):
                return False
        return True

    @staticmethod
    def _scope_match_literal(scope, url, host):
        """字面范围匹配：纯域名 → 主机精确/子域；带路径 → URL 前缀。

        SCOPE-MATCH-SYNC: 本函数逻辑与 scripts/common.py.url_in_scope 必须一致，
        修改需同步 common.py（门禁/子代理判定范围须与代理记录口径统一）。
        """
        has_scheme = "://" in scope
        bare = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", scope) if has_scheme else scope
        if "/" in bare:  # 路径前缀模式
            if has_scheme:
                return url.startswith(scope)
            url_bare = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url)
            return url_bare.startswith(bare)
        d = bare.rstrip("/").lower()  # 域名精确/子域模式
        h = (host or "").lower()
        return h == d or h.endswith("." + d)

    def _next_code(self):
        code = "URL{:05d}".format(self.next_seq)
        self.next_seq += 1
        return code

    # ---- 记录一条流 ----
    def _record(self, flow, errored=False):
        req = flow.request
        if req is None:
            return
        u = urlsplit(req.url)
        url = urlunsplit((u.scheme, u.netloc, u.path, "", ""))  # 完整 URL，去 query/fragment
        if not self._in_scope(url, req.pretty_host):
            return
        path_key = url
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        resp = None if errored else flow.response
        is_success = resp is not None and resp.status_code < 400  # 2XX/3XX 成功；4XX/5XX 或无响应失败

        with self.lock:
            # 统一编码 + 总请求计数（成功+失败共享，用作 <id>.log 的 #seq）
            code = self.codes.get(path_key)
            if code is None:
                code = self._next_code()
                self.codes[path_key] = code
            self.totals[path_key] = self.totals.get(path_key, 0) + 1
            seq = self.totals[path_key]

            # 原始报文：所有请求（成功+失败）都写入统一编码的 <id>.log
            self._append_raw(code, seq, ts, req, resp, errored)

            # 按成功/失败分流到对应聚合桶
            bucket = self.success if is_success else self.failed
            rec = bucket.get(path_key)
            if rec is None:
                rec = UrlRecord(code, url)
                rec.first_seen = ts
                bucket[path_key] = rec
            rec.methods.add(req.method)
            rec.request_count += 1
            rec.last_seen = ts
            if resp is not None:
                rec.update_category(resp.headers.get("content-type", ""))
            if not is_success:
                rec.add_status(resp.status_code if resp is not None else None)

            for name, source, ptype, value in _extract_params(req):
                key = (source, name)
                if key not in rec.params:
                    rec.params[key] = {
                        "name": name,
                        "source": source,
                        "type": ptype,
                        "sample_value": _truncate(value, self.value_cap),
                    }

            if is_success:
                self._write_index(self.success, self.success_index)
                if rec.params:
                    self._write_params(rec)       # 仅成功请求写参数详情
            else:
                self._write_index(self.failed, self.failed_index)  # 失败不写 params 详情

    # ---- 写原始请求报文（二进制 append） ----
    def _append_raw(self, code, seq, ts, req, resp, errored):
        buf = bytearray()
        head = "###### [{} #{}] {} | {} {} ######\n".format(code, seq, ts, req.method, req.url)
        buf += head.encode("utf-8", "replace")

        buf += b"--- REQUEST ---\n"
        request_line = "{} {} {}\r\n".format(req.method, req.path, req.http_version)
        buf += request_line.encode("utf-8", "replace")
        buf += _headers_bytes(req.headers)
        buf += b"\r\n"
        body = req.content or b""
        if self.body_cap and len(body) > self.body_cap:
            buf += body[:self.body_cap]
            buf += "\n<...truncated {} bytes>".format(len(body) - self.body_cap).encode("utf-8")
        else:
            buf += body
        buf += b"\n\n"

        if errored or resp is None:
            buf += b"--- NO RESPONSE ---\n"
        else:
            buf += b"--- RESPONSE HEADERS ---\n"
            status_line = "{} {} {}\r\n".format(resp.http_version, resp.status_code, resp.reason or "")
            buf += status_line.encode("utf-8", "replace")
            buf += _headers_bytes(resp.headers)
            # 文本类响应体预览（前 resp_preview_cap 字节，已解压）——供挖掘阶段快速判断端点行为/选测试基线
            preview = _response_preview(resp, self.resp_preview_cap)
            if preview is not None:
                buf += "\n--- RESPONSE BODY (preview: {}Byte only) ---\n".format(self.resp_preview_cap).encode("utf-8")
                buf += preview
                if len(preview) == self.resp_preview_cap:
                    buf += b"\n<...truncated>"

        buf += b"\n" + SEPARATOR + b"\n\n"

        path_file = os.path.join(self.req_dir, code + ".log")
        with open(path_file, "ab") as f:
            f.write(buf)
            f.flush()
            os.fsync(f.fileno())

    # ---- 重写清单（原子替换，bucket+文件参数化：url_index / failed_index）----
    def _write_index(self, bucket, index_file):
        tmp = index_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in sorted(bucket.values(), key=lambda r: r.code):
                f.write(json.dumps(rec.index_line(), ensure_ascii=False) + "\n")
        os.replace(tmp, index_file)

    # ---- 重写某路径参数详情（原子替换） ----
    def _write_params(self, rec):
        pfile = os.path.join(self.param_dir, rec.code + ".json")
        tmp = pfile + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec.params_doc(), f, ensure_ascii=False, indent=2)
        os.replace(tmp, pfile)

    # ---- mitmproxy 钩子 ----
    def response(self, flow):
        try:
            self._record(flow, errored=False)
        except Exception as e:
            log.warning("record(response) failed: %s", e)

    def error(self, flow):
        try:
            self._record(flow, errored=True)
        except Exception as e:
            log.warning("record(error) failed: %s", e)

    def done(self):
        try:
            with self.lock:
                if self.success:
                    self._write_index(self.success, self.success_index)
                if self.failed:
                    self._write_index(self.failed, self.failed_index)
                for rec in self.success.values():
                    if rec.params:
                        self._write_params(rec)
        except Exception as e:
            log.warning("flush on done failed: %s", e)

    def running(self):
        scope_desc = (("regex:" if self.scope_regex else "") + ", ".join(SCOPES)) if SCOPES else "ALL"
        exclude_desc = (("regex:" if self.exclude_regex else "") + ", ".join(EXCLUDES)) if EXCLUDES else "NONE"
        log.info(
            "recorder ready | dir=%s | targets=%s | scope=%s | exclude=%s | body_cap=%d | value_cap=%d | resp_preview=%d",
            self.log_dir, self.targets or "ALL", scope_desc, exclude_desc,
            self.body_cap, self.value_cap, self.resp_preview_cap,
        )


addons = [Recorder()]
