# -*- coding: utf-8 -*-
"""生成/更新补测清单 retest-list.json（研判台账）。

**前向驱动，不反向扫描 failed_index**：候选只来自 `pages.jsonl` / `js.jsonl` 中**已登记**的
in-scope 接口/链接（`discovered_urls` 的 type=api/page，及页面自身 url）——这些是测评者主动登记的
真实攻击面。若某个已登记 URL 落入 `failed_index`（失败访问）且未成功纳入 `url-inventory`，即成为补测候选。
`failed_index` 只作**查表**（取该 URL 的 URLID / 参数名 / 状态码），**不作枚举源**——避免把 payload 探测、
备份文件猜测、上传残留（PWNED_*.png 等）这类从未登记的探测噪声反向卷入清单。

理念：失败访问**默认视为"没走通正规业务流程"**，本清单只 seed 候选（disposition=pending）、不代表已处置。
须逐条研判：能经正常业务流程(playwright)走通的走通后进 url-inventory；确属客观阻塞（系统 bug / 人机校验
无法绕过 / 前置条件无法满足）→ disposition=retest 交漏洞挖掘阶段补测；安全边界所限或无需/无法测 → disposition=blocked
留痕不补测。

幂等：以 url id 为键 upsert——保留已填的 disposition/access_note/mining_status/mining_result/notes，
刷新代理带入字段；清单每次按当前"已登记∩失败∩未覆盖"候选集重算，非候选项（已解决 / 已改常规访问 /
不再登记 / 历史噪声）自动剔除。

用法：
    python build_retest_list.py --project <id> [--data-root pentest-data]
"""

import argparse
from urllib.parse import urlsplit, urlunsplit

import common as c


def norm_url(u):
    """规范化：去 query / fragment、去尾斜杠（与 check_breadth / build_url_inventory 口径一致）。"""
    try:
        s = urlsplit(u)
        return urlunsplit((s.scheme, s.netloc, s.path, "", "")).rstrip("/")
    except Exception:
        return (u or "").rstrip("/")


def default_item(rec):
    return {
        "id": rec.get("id"),
        "url": rec.get("url", ""),
        "category": rec.get("category", "unknown"),
        "methods": rec.get("methods", []),
        "param_names": rec.get("param_names", []),
        "status_codes": rec.get("status_codes", {}),
        "disposition": "pending",
        "access_note": "",
        "mining_status": "pending",
        "mining_result": "pending",
        "notes": c.DEFAULT_NOTES,
    }


def refresh_carried(cur, rec):
    """刷新由代理带入的客观字段，保留人工/AI 研判字段。"""
    cur["url"] = rec.get("url", cur.get("url", ""))
    cur["category"] = rec.get("category", cur.get("category", "unknown"))
    cur["methods"] = sorted(set(cur.get("methods", [])) | set(rec.get("methods", [])))
    cur["param_names"] = sorted(set(cur.get("param_names", [])) | set(rec.get("param_names", [])))
    cur["status_codes"] = rec.get("status_codes", cur.get("status_codes", {}))


def main():
    p = argparse.ArgumentParser(description="生成/更新补测清单（前向驱动的研判台账）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    failed = c.load_jsonl(paths["failed_index"])
    success = c.load_jsonl(paths["url_index"])
    inv_urls = c.load_json(paths["inventory"], default={"urls": []}).get("urls", [])
    pages = c.load_jsonl(paths["pages"])
    jss = c.load_jsonl(paths["js"])

    cfg = c.load_json(paths["config"], default={}) or {}
    scopes = cfg.get("scope", []) or []
    excludes = cfg.get("exclude", []) or []
    scope_regex = bool(cfg.get("scope_regex"))
    exclude_regex = bool(cfg.get("exclude_regex"))

    def in_scope(url):
        return c.url_in_test_scope(url, scopes, excludes, scope_regex, exclude_regex)

    def d_in_scope(d):
        v = d.get("in_scope")
        if isinstance(v, bool):
            return v
        return in_scope(d.get("url", ""))

    # 前向来源：pages / js 中已登记的 in-scope 接口/链接（discovered_urls type=api/page + 页面自身 url）
    registered = set()  # norm_url
    for pg in pages:
        pu = pg.get("url", "")
        if pu and in_scope(pu):
            registered.add(norm_url(pu))
        for d in pg.get("discovered_urls", []):
            if d.get("type") in ("page", "api") and d_in_scope(d):
                registered.add(norm_url(d.get("url", "")))
    for j in jss:
        for d in j.get("discovered_urls", []):
            if d.get("type") in ("page", "api") and d_in_scope(d):
                registered.add(norm_url(d.get("url", "")))
    registered.discard("")

    # 已被成功记录覆盖的 URL（有成功记录就走常规挖掘，不入补测）
    covered = {norm_url(r.get("url", "")) for r in success}
    covered |= {norm_url(u.get("url", "")) for u in inv_urls}
    covered.discard("")

    # failed_index 作查表（非枚举源）：norm_url -> 失败记录
    failed_by_url = {}
    for r in failed:
        nu = norm_url(r.get("url", ""))
        if nu and r.get("id"):
            failed_by_url.setdefault(nu, r)

    # 候选 = 已登记 ∩ 失败 ∩ 未被成功覆盖
    candidates = [failed_by_url[nu] for nu in registered
                  if nu not in covered and nu in failed_by_url]

    old = {it.get("id"): it for it in c.load_json(paths["retest_list"], default={"items": []}).get("items", [])}
    new_by_id, added, updated = {}, 0, 0
    for rec in candidates:
        uid = rec.get("id")
        if uid in old:
            refresh_carried(old[uid], rec)
            new_by_id[uid] = old[uid]
            updated += 1
        else:
            new_by_id[uid] = default_item(rec)
            added += 1
    removed = len(old) - updated  # 非候选项（已解决 / 改常规访问 / 不再登记 / 历史反向扫描噪声）剔除

    out = {"_note": "补测清单（研判台账·前向驱动）：pages/js 已登记接口∩failed_index∩未纳入 url-inventory；"
                    "默认 pending 需研判，disposition∈{pending,retest,blocked}",
           "items": sorted(new_by_id.values(), key=lambda x: x.get("id", ""))}
    c.atomic_write_json(paths["retest_list"], out)

    print("[完成] 补测清单：%s" % paths["retest_list"])
    print("       本次新增 %d，刷新 %d，剔除 %d，现存 %d 条（前向：已登记接口∩失败）。"
          % (added, updated, removed, len(out["items"])))
    pend = [it["id"] for it in out["items"] if it.get("disposition") == "pending"]
    if pend:
        print("       [待研判 disposition=pending] 逐条研判为 retest(补测)/blocked(不补测)并填 access_note：%s"
              % ", ".join(pend))
    else:
        print("       无待研判项。")


if __name__ == "__main__":
    main()
