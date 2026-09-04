# -*- coding: utf-8 -*-
"""从页面 HTML 内联脚本与外链 JS 静态提取每个接口的请求体参数（内联对象字面量顶层键名），
产出 url-static-params.json 作为「应有参数」基准，供 check_breadth.py 的参数覆盖门禁与代理实测
param_names 比对，发现「静态可见却从未随真实流量记录」的参数缺口（=业务流程未真实走通）。

动机（真实漏报）：create-order.php 的客户端可控参数 order_time（决定限时优惠）明明写在商品详情页
内联下单 JS `jsonPost('../api/user/create-order.php',{product_no,quantity,order_time,use_points})`
里，却因真实「立即购买」流程未走通、代理没观测到，导致漏洞挖掘阶段从未挖掘。本脚本机械抓出这类缺口。

保守·零误报策略（宁漏个别、绝不误报阻塞流程）：
  仅提取「请求体在第2实参」的封装/库方法（jsonPost/postJSON/jsonGet/getJSON/postForm 及
  axios.post/$http.put 等 post/put/patch 写方法；GET-config 类与 jQuery $.xxx[注] 不列入）
  紧跟 URL 之后的**内联对象字面量 {key:val} 顶层键**，标 high：
  [注] jQuery $.post 受上游 extract_page_urls.AJAX_CALL_RE 的 (?:\\b|\\.) 前缀限制可能匹配不到，
       属既有局限（宁漏不误）；自定义封装与 axios.* 不受影响。
      jsonPost('/api/x', { a, b:1, c:foo() })  → high: a,b,c
  以下一律不产出 high（跳过或标 low，门禁不消费）：
    - 第2实参非内联 {（变量/JSON.stringify/FormData）：jsonPost('/api/x', payload) → 跳过
    - fetch/axios/$.ajax（第2实参是 init/config 对象，顶层键是 method/headers/body 而非业务参数）→ 不识别为 body-fn
    - 含展开 {...base,a} 或计算属性 { [k]:v } → 该对象标 low
    - 动态 URL fn(`/api/${id}`,{...}) → 跳过（无法对齐 URLID）

这不是 JS 解析器：字符串内括号做引号感知配对；跨函数拼接/Object.assign/局部变量对象均不作 high 提取。
URL 对齐复用 extract_page_urls._resolve/norm_url。恒 exit 0（生成器，非门禁）。

用法：
    python extract_static_params.py --project <id> [--data-root pentest-data]
"""

import argparse
import os
import re
import sys

import common as c
import extract_page_urls as epu

# 「请求体在第2实参」的封装函数（约定：fn(url, bodyObj)）——只对这些提取 high。
# 明确排除 fetch/axios(config)/$.ajax（第2实参是 init/config，顶层键非业务参数）。
_BODY_FNS = {"jsonpost", "postjson", "jsonget", "getjson", "postform", "getform", "reqjson"}
# 库写方法：$.post/axios.post/http.put 等第2实参约定为请求体。GET 不列入——axios.get(url,config)
# 第2实参是 config 而非 body，避免把 params/headers 等 config 键误当业务参数。
_BODY_METHODS = {"post", "put", "patch"}


def _fn_head(call_raw):
    """从 AJAX_CALL_RE 的 group(0)（形如 "jsonPost('..." / "$.post('..." / ".post('..."）取 `(` 前的函数头。"""
    return call_raw.split("(", 1)[0].strip()


def _fn_name(call_raw):
    """展示用函数名：取函数头最后一个标识符段（$.post→post、jsonPost→jsonPost）。"""
    head = _fn_head(call_raw)
    seg = re.split(r"[.$\s]+", head)
    return (seg[-1] if seg and seg[-1] else head) or head


def _is_body_fn(call_raw):
    """该调用的第2实参是否约定为请求体对象（只对这些函数提取 high，杜绝 fetch/axios-config 误报）。
    按末段方法名判定：命中自定义封装(_BODY_FNS)或 axios.post/http.put 等写方法(_BODY_METHODS)。
    jQuery $.post 受上游 URL 正则前缀限制可能不进入此判定，属既有局限（宁漏不误）。"""
    last = re.split(r"[.$\s]+", _fn_head(call_raw))[-1].lower()
    return last in _BODY_FNS or last in _BODY_METHODS


def _skip_ws(text, i):
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    return i


def _read_string(text, i):
    """text[i] 是引号(' " `)。返回 (内容, 闭合引号后位置)；处理 \\ 转义；反引号整体当字符串
    读到配对反引号（不解析 ${} 嵌套，保守）。未闭合返回 (内容, len)。"""
    q = text[i]
    n = len(text)
    j = i + 1
    buf = []
    while j < n:
        ch = text[j]
        if ch == "\\":
            if j + 1 < n:
                buf.append(text[j + 1])
                j += 2
                continue
            j += 1
            continue
        if ch == q:
            return "".join(buf), j + 1
        buf.append(ch)
        j += 1
    return "".join(buf), n  # 未闭合


def _extract_object_keys(text, start):
    """text[start] == '{'。返回 (keys:list[str], has_low:bool, end_index_or_None)。
    引号/括号感知，只收深度=1 顶层键（`k:` 正常键、`k,`/`k}` ES6 简写）；含展开 ... 或计算属性
    [..] 标 has_low。配对到最外层 } 返回其下标；未闭合返回 end=None（调用方按解析失败跳过）。"""
    keys = []
    has_low = False
    n = len(text)
    i = start
    depth = 0
    expect_key = False  # { 或顶层 , 之后，期待一个键
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            if depth == 1 and expect_key:
                s, j = _read_string(text, i)
                k = _skip_ws(text, j)
                if k < n and text[k] == ":":
                    keys.append(s)
                expect_key = False
                i = j
                continue
            _, j = _read_string(text, i)
            i = j
            continue
        if ch == "{":
            depth += 1
            expect_key = (depth == 1)
            i += 1
            continue
        if ch == "}":
            depth -= 1
            if depth == 0:
                return keys, has_low, i
            i += 1
            continue
        if ch in "[(":
            if depth == 1 and expect_key and ch == "[":
                has_low = True      # 计算属性名 [k]:v
                expect_key = False
            depth += 1
            i += 1
            continue
        if ch in "])":
            depth -= 1
            i += 1
            continue
        if depth == 1 and ch == ",":
            expect_key = True
            i += 1
            continue
        if depth == 1 and ch == "." and text[i:i + 3] == "...":
            has_low = True          # 展开 ...base
            expect_key = False
            i += 3
            continue
        if depth == 1 and expect_key and (ch.isalpha() or ch in "_$"):
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            ident = text[i:j]
            k = _skip_ws(text, j)
            if k < n and text[k] in ":,}":   # 正常键 ident: 或简写 ident,/ident}
                keys.append(ident)
            expect_key = False
            i = j
            continue
        if depth == 1 and not ch.isspace():
            expect_key = False
        i += 1
    return keys, has_low, None  # 未闭合 {


def _body_calls(text):
    """yield (url_raw, keys, has_low, fn_name, line, parsed_ok)。仅 body-fn 且第2实参是内联 {。"""
    for m in epu.AJAX_CALL_RE.finditer(text):
        if not _is_body_fn(m.group(0)):
            continue
        pos = _skip_ws(text, m.end())
        if pos >= len(text) or text[pos] != ",":
            continue  # 无第2实参
        pos = _skip_ws(text, pos + 1)
        if pos >= len(text) or text[pos] != "{":
            continue  # 第2实参非内联对象（变量/JSON.stringify/FormData…）→ 跳过
        keys, has_low, end = _extract_object_keys(text, pos)
        line = text.count("\n", 0, m.start()) + 1
        yield m.group(1), keys, has_low, _fn_name(m.group(0)), line, (end is not None)


def _infer_method(fn):
    f = (fn or "").lower()
    if "post" in f:
        return "POST"
    if "put" in f:
        return "PUT"
    if "patch" in f:
        return "PATCH"
    if "del" in f:
        return "DELETE"
    if "get" in f:
        return "GET"
    return ""


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def main():
    p = argparse.ArgumentParser(description="静态请求参数提取（供 check_breadth 参数覆盖门禁比对）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()
    paths = c.project_paths(args.data_root, args.project)

    # URL → URLID 对齐表 {norm_url: URLID}：以 url-inventory（权威 URL 清单，含未被真实流量命中的接口）
    # 为主源，代理 url_index 兜底补充 inventory 未收录的；两侧皆经 norm_url 归一，仍对不上则 url_id=null。
    norm2id = {}
    for u in (c.load_json(paths["inventory"], default={}) or {}).get("urls", []):
        nu = epu.norm_url(u.get("url", ""))
        if nu and u.get("id"):
            norm2id.setdefault(nu, u.get("id"))
    for rec in c.load_jsonl(paths["url_index"]):
        nu = epu.norm_url(rec.get("url", ""))
        if nu and rec.get("id"):
            norm2id.setdefault(nu, rec.get("id"))

    # 待解析源：页面内联 JS（base=页面 url）+ 已下载外链 JS（base=source_url）
    sources = []  # (source_file_rel, base_url, text)
    for pg in c.load_jsonl(paths["pages"]):
        hf = pg.get("html_file") or ""
        base = pg.get("url") or ""
        if not hf or not base:
            continue
        hp = hf if os.path.isabs(hf) else os.path.join(paths["dir"], hf)
        if os.path.exists(hp):
            sources.append((hf, base, _read_text(hp)))
    for js in c.load_jsonl(paths["js"]):
        if js.get("download_status") != "downloaded":
            continue
        lp = js.get("local_path") or ""
        base = js.get("source_url") or ""
        if not lp or not base:
            continue
        jp = lp if os.path.isabs(lp) else os.path.join(paths["dir"], lp)
        if os.path.exists(jp):
            sources.append((lp, base, _read_text(jp)))

    # 解析并按 norm_url 聚合
    agg = {}          # norm_url -> {url_id, methods:set, params:{name:{confidence,source_file,line,call}}}
    parse_skipped = 0
    for source_file, base, text in sources:
        for url_raw, keys, has_low, fn, line, ok in _body_calls(text):
            if not ok:
                parse_skipped += 1
                continue
            if not keys:
                continue
            if "${" in url_raw or "FUZZ" in url_raw:
                continue  # 动态 URL，无法稳定对齐
            absu = epu._resolve(base, url_raw)
            if not absu:
                continue
            uid = norm2id.get(absu)  # 对不上为 None
            conf = "low" if has_low else "high"
            node = agg.setdefault(absu, {"url_id": uid, "methods": set(), "params": {}})
            if uid and not node["url_id"]:
                node["url_id"] = uid
            mth = _infer_method(fn)
            if mth:
                node["methods"].add(mth)
            for k in keys:
                if not k:
                    continue
                cur = node["params"].get(k)
                if cur is None or (cur.get("confidence") == "low" and conf == "high"):
                    node["params"][k] = {"confidence": conf, "source_file": source_file,
                                         "line": line, "call": fn}

    urls_out = []
    for absu in sorted(agg):
        node = agg[absu]
        sp = [{"name": k, "confidence": v["confidence"], "source_file": v["source_file"],
               "line": v["line"], "call": v["call"]}
              for k, v in sorted(node["params"].items())]
        urls_out.append({
            "url": absu,
            "url_id": node["url_id"],
            "methods": sorted(node["methods"]),
            "static_params": sp,
        })

    doc = {
        "_note": "静态提取的每接口请求参数基准（内联对象字面量顶层键名）；供 check_breadth 参数覆盖门禁比对。非实测。",
        "generated_at": c.now_iso(),
        "parse_skipped": parse_skipped,
        "urls": urls_out,
    }
    c.atomic_write_json(paths["static_params"], doc)

    n_high = sum(1 for u in urls_out for pp in u["static_params"] if pp["confidence"] == "high")
    print("==== 静态请求参数提取（供 check_breadth 参数覆盖门禁比对）====")
    print("源文件 %d（页面内联+外链JS）| 覆盖接口 %d | high 参数合计 %d | 解析跳过 %d"
          % (len(sources), len(urls_out), n_high, parse_skipped))
    for u in urls_out:
        highs = [pp["name"] for pp in u["static_params"] if pp["confidence"] == "high"]
        if highs:
            print("  %-10s %s  high=%s" % (u["url_id"] or "(未对齐)", u["url"], ",".join(highs)))
    print("[已落盘] %s" % paths["static_params"])
    sys.exit(0)


if __name__ == "__main__":
    main()
