# -*- coding: utf-8 -*-
"""权限矩阵——多角色越权探测与判定引擎（广度建模阶段收尾产出）。

以未登录基线与各已登录角色身份逐个访问每个 page/api URL，产出标准
`permission-matrix/{URLID}.json`，并汇总疑似越权（judgment=abnormal）清单供主代理
逐条补入 `threats.jsonl` 作为攻击面威胁（related_objects 指向该 URL、verification_status=pending），
交后续漏洞挖掘逐参数验证、威胁收敛阶段消账。

判定分三管齐下，专治「页面型越权被判定器漏判」：
  1. 会话有效性预检：某角色的 cookie 若在整批 URL 上与未登录基线表现完全一致（状态码+长度），
     判为会话失效（session_valid=false），其结果不参与越权判定，避免「会话失效冒充正确拦截」。
  2. 禁止自动跟随重定向：3xx→登录页 是拦截信号，200→后台 是放行信号，二者绝不可被跟随抹平；
     分别记录原始 status_code 与 final_status。
  3. 分流判定：
     - api（JSON）：按 success 语义 + 401/403 判定；非归属角色拿到 success 即越权。
     - page（HTML）：内容指纹 + 长度三锚点对比——以 unauth 为拦截锚点、URL 归属角色为成功锚点，
       非归属角色响应贴近成功锚点（同标题且长度相近）即判越权。

登录由主代理按项目认证方式完成并写入 `sessions.json`（本脚本不登录）；本脚本消费其 cookie。
全程走代理（默认 127.0.0.1:{config.proxy_port}）。

用法：
    python permission_probe.py --project <id> [--data-root pentest-data]
        [--proxy 127.0.0.1:24304] [--timeout 15] [--len-tol 120]
"""

import argparse
import json
import os
import re
import sys
import http.cookiejar
import urllib.request
import urllib.error

import common as c

# 常见「公开」端点名（无角色归属，各角色访问均属正常）——用于把登录/注册/搜索等排除出越权判定。
PUBLIC_HINTS = (
    "login.php", "logout.php", "register.php", "captcha.php", "send-sms.php",
    "forgot-password.php", "reset-password.php", "reset_password.php", "search.php",
    "forgot_password.php",
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随 3xx，保留原始状态码与 Location。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def owner_of(url):
    """按路径段推导 URL 的归属角色；公开端点与无法判定者返回 None（视为公开，不判越权）。"""
    p = url.split("/shop/")[-1] if "/shop/" in url else url
    p = p.split("?")[0]
    tail = p.rsplit("/", 1)[-1]
    if tail in PUBLIC_HINTS:
        return None
    if "/admin/" in p or p.startswith("admin/"):
        return "admin"
    if "/merchant/" in p or p.startswith("merchant/"):
        return "merchant"
    if "/user/" in p or p.startswith("user/"):
        return "user"
    return None


def fingerprint(status, body):
    """响应指纹：标题 + 长度。页面型越权判定与门禁抽查的依据。"""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = (m.group(1).strip() if m else "")[:60]
    return {"title": title, "len": len(body)}


def same_page(a, b, len_tol):
    """两个页面指纹是否雷同：标题相同且长度相近。"""
    if a["title"] and b["title"]:
        return a["title"] == b["title"] and abs(a["len"] - b["len"]) <= len_tol
    return abs(a["len"] - b["len"]) <= len_tol


def is_json_success(body):
    return '"success":true' in body.replace(" ", "").replace("\n", "")


def role_key(sess):
    """把 sessions.json 的角色名归一为矩阵用角色标识；未登录基线统一为 unauth。"""
    r = sess.get("role", "")
    return "unauth" if r in ("unauthenticated", "unauth", "") else r


def build_openers(sessions, proxy):
    """为每个角色建带 cookie 的 opener（禁跟随重定向）。"""
    proxies = {"http": proxy, "https": proxy}
    ph = urllib.request.ProxyHandler(proxies)
    openers = {}
    for s in sessions:
        rk = role_key(s)
        cj = http.cookiejar.CookieJar()
        openers[rk] = {
            "opener": urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cj), ph, _NoRedirect()),
            "cookie": (s.get("auth", {}) or {}).get("cookie", "") or "",
        }
    if "unauth" not in openers:
        openers["unauth"] = {"opener": urllib.request.build_opener(ph, _NoRedirect()), "cookie": ""}
    return openers


def fetch(entry, url, timeout):
    """发一次请求（禁跟随重定向），返回 (status, final_status, body)。"""
    headers = {"Referer": url}
    if entry["cookie"]:
        headers["Cookie"] = entry["cookie"]
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        r = entry["opener"].open(req, timeout=timeout)
        return r.status, "", r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "") if e.headers else ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, (loc or str(e.code)), body
    except Exception as e:
        return 0, "error", str(e)[:120]


def main():
    p = argparse.ArgumentParser(description="权限矩阵多角色越权探测与判定")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--proxy", default="")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--len-tol", type=int, default=120, help="页面长度雷同容差（字节）")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    cfg = c.load_json(paths["config"], default={}) or {}
    proxy = args.proxy or ("127.0.0.1:%s" % cfg.get("proxy_port", 24304))
    if not proxy.startswith("http"):
        proxy = "http://" + proxy

    inv = c.load_json(paths["inventory"], default=None)
    if inv is None:
        print("[错误] 未找到 url-inventory.json，请先运行 build_url_inventory.py")
        sys.exit(1)
    sess_doc = c.load_json(paths["sessions"], default={"sessions": []}) or {"sessions": []}
    sessions = sess_doc.get("sessions", [])
    if not any(role_key(s) == "unauth" for s in sessions):
        sessions = sessions + [{"role": "unauthenticated", "auth": {}}]

    openers = build_openers(sessions, proxy)
    roles = list(openers.keys())
    auth_roles = [r for r in roles if r != "unauth"]
    pageapi = [u for u in inv.get("urls", []) if u.get("category") in ("page", "api")]

    # 第一遍：收集全部响应（禁跟随重定向）
    raw = {}  # uid -> role -> (status, final_status, fp)
    meta = {}  # uid -> (url, category)
    for u in pageapi:
        uid, url, cat = u.get("id"), u.get("url"), u.get("category")
        meta[uid] = (url, cat)
        raw[uid] = {}
        for r in roles:
            st, fst, body = fetch(openers[r], url, args.timeout)
            raw[uid][r] = (st, fst, fingerprint(st, body), is_json_success(body))

    # 会话有效性：某角色若在所有 URL 上与 unauth 表现完全一致（状态码+长度），判会话失效
    session_valid = {}
    for r in auth_roles:
        differs = False
        for uid in raw:
            st_r, _, fp_r, _ = raw[uid][r]
            st_u, _, fp_u, _ = raw[uid]["unauth"]
            if st_r != st_u or fp_r["len"] != fp_u["len"]:
                differs = True
                break
        session_valid[r] = differs
    session_valid["unauth"] = True

    # 第二遍：分流判定，写矩阵
    now = c.now_iso()
    abn_summary = []
    invalid_roles = [r for r in auth_roles if not session_valid[r]]
    for uid in raw:
        url, cat = meta[uid]
        owner = owner_of(url)
        results = []
        for r in roles:
            st, fst, fp, jsucc = raw[uid][r]
            note = "无"
            if r == "unauth":
                judgment = "normal"
            elif not session_valid[r]:
                judgment = "normal"
                note = "会话失效(整批与未登录基线一致)，本条判定不作数，须重登后复测"
            elif owner is None:
                judgment = "normal"
                note = "公开端点，各角色访问均属正常"
            elif r == owner:
                judgment = "normal"
            else:  # 非归属角色
                if cat == "api":
                    judgment = "abnormal" if (st == 200 and jsucc) else "normal"
                else:  # page：内容指纹三锚点对比
                    owner_fp = raw[uid].get(owner, (None, None, None, None))[2]
                    unauth_fp = raw[uid]["unauth"][2]
                    owner_ok = session_valid.get(owner, False) and owner_fp is not None
                    if owner_ok and same_page(fp, owner_fp, args.len_tol) \
                            and not same_page(fp, unauth_fp, args.len_tol):
                        judgment = "abnormal"
                    else:
                        judgment = "normal"
                        if not owner_ok:
                            note = "归属角色会话失效，无法建立成功锚点，判定存疑须人工复核"
                if judgment == "abnormal":
                    note = "越权：%s 访问 %s 归属资源，响应贴近归属角色成功页/接口" % (r, owner)
                    abn_summary.append((uid, url.split("/shop/")[-1], r, owner, cat))
            results.append({
                "role": r,
                "status_code": st,
                "final_status": fst if fst else st,
                "response_length": fp["len"],
                "body_fingerprint": "%s | len=%d" % (fp["title"], fp["len"]),
                "session_valid": bool(session_valid.get(r, True)),
                "judgment": judgment,
                "notes": note,
            })
        pm = {
            "url_id": uid,
            "url": url,
            "url_category": cat,
            "test_request": "GET %s" % url,
            "results": results,
            "created": now,
            "updated": now,
        }
        c.atomic_write_json(os.path.join(paths["perm_dir"], "%s.json" % uid), pm)

    # 更新 url-inventory 的 permission_matrix_status=verified
    for u in inv.get("urls", []):
        if u.get("category") in ("page", "api"):
            u["permission_matrix_status"] = "verified"
    c.atomic_write_json(paths["inventory"], inv)

    print("==== 权限矩阵探测完成 ====")
    print("page/api URL %d | 角色 %s | 代理 %s" % (len(pageapi), ",".join(roles), proxy))
    if invalid_roles:
        print("[会话失效] 以下角色整批与未登录一致，需主代理重登后复测：%s" % ",".join(invalid_roles))
    print("")
    if abn_summary:
        print("【疑似越权（abnormal）—— 主代理须逐条验证危害并出报告 %d】" % len(abn_summary))
        for uid, path, role, owner, cat in abn_summary:
            print("  - %s [%s] %s 越权访问 %s 归属(%s)资源：%s" % (uid, cat, role, owner, cat, path))
    else:
        print("【未发现疑似越权】各非归属角色访问均正常（或会话失效待复测）。")

    sys.exit(0)


if __name__ == "__main__":
    main()
