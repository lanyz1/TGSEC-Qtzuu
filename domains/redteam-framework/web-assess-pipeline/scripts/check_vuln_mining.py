# -*- coding: utf-8 -*-
"""漏洞挖掘质量门禁——机器硬检查。

检查：
- url-inventory 与代理 url_index.jsonl 一致；
- 必挖清单基线（mining-scope.json，进入阶段前 build_mining_scope.py 固化）内每个 URL 两类
  *_mining_done ∈ {completed, not_applicable}（无 pending）；payload 副产物等基线外新 URL/参数转软复核；
- 必挖基线内每个【有参数】URL 有 vuln-matrix/{URLID}.json，且基线 param_names 每个参数都有矩阵条目，
  条目 status 合法（found→有 report_id 且在报告清单；tested_not_found/doubtful/filtered→有 tests+basis）；
  无参数 URL 若已产出矩阵则同样校验其 _url_level 条目（与 check_matrix.py 自检口径一致）；
- 通用漏洞（category=generic）tested_not_found/doubtful/filtered 条目的 filter_probe 为结构化对象
  {符号/关键字: [防护情况∈{过滤,拦截,替换,转义,放行}, 说明]}；key 疑似完整 payload 仅软告警；
- 有编号测试要点的漏洞类型（见 references/test-checkpoints.md）tested_not_found/doubtful/filtered 条目
  须填 checkpoint_response（要点编号→应答），KEY 命中该类型编号集、值非空；
- *_mining_result 形态合法（每参数 {漏洞类型: 报告号|tested_not_found|doubtful}）；
- 矩阵中 found 条目的 report_id 已登记在漏洞报告清单；
- 已生成的报告文件（reports/VULN-VD-*.md）都已登记 vuln-reports.json（主代理已逐份阅读验收，门禁只校验登记完整）。

退出码：0=硬检查通过（仍须 AI 复核），1=有硬错误。

用法：
    python check_vuln_mining.py --project <id> [--data-root pentest-data]
"""

import argparse
import glob
import os
import sys

import common as c

MATRIX_ENTRY_REQUIRED = ["vuln_type", "category", "status"]
MATRIX_CATEGORY = {"generic", "business_logic"}


def _check_filter_probe(uid, pname, vt, fp, errors, reviews):
    """通用漏洞 filter_probe 结构硬校验：非空对象，每值为 [防护情况, 说明] 二元数组、
    防护情况∈枚举、说明非空；key 疑似完整 payload（含空格或过长）仅软告警交 AI 复核，不硬 block。"""
    if not isinstance(fp, dict) or not fp:
        errors.append("[矩阵] %s %s 漏洞[%s] 通用漏洞缺 filter_probe（须为非空对象 {符号/关键字:[防护情况,说明]}）" % (uid, pname, vt))
        return
    for key, val in fp.items():
        if not (isinstance(val, list) and len(val) == 2):
            errors.append("[矩阵] %s %s 漏洞[%s] filter_probe['%s'] 应为二元数组 [防护情况,说明]" % (uid, pname, vt, key))
            continue
        guard, desc = val[0], val[1]
        if guard not in c.FILTER_PROBE_GUARD:
            errors.append("[矩阵] %s %s 漏洞[%s] filter_probe['%s'] 防护情况非法（须∈%s）：%r"
                          % (uid, pname, vt, key, "/".join(sorted(c.FILTER_PROBE_GUARD)), guard))
        if not (isinstance(desc, str) and desc.strip()):
            errors.append("[矩阵] %s %s 漏洞[%s] filter_probe['%s'] 说明为空" % (uid, pname, vt, key))
        if (" " in str(key)) or (len(str(key)) > 16):
            reviews.append("[复核] %s %s 漏洞[%s] filter_probe 的 key '%s' 疑似完整 payload 而非单个符号/关键字（含空格或过长），请人工确认"
                           % (uid, pname, vt, key))


def _check_checkpoint_response(uid, pname, vt, st, cr, errors):
    """有编号测试要点的漏洞类型，tested_not_found/doubtful/filtered 须填 checkpoint_response；
    KEY 须命中该类型要点编号集、VALUE 非空。不强制要点全覆盖（漏答交 AI 复核）。"""
    ck_ids = c.checkpoint_ids_for(vt)
    if ck_ids and st in c.FILTER_PROBE_REQUIRED_STATUS:
        if not isinstance(cr, dict) or not cr:
            errors.append("[矩阵] %s %s 漏洞[%s] 该类型有测试要点，%s 须填 checkpoint_response（要点编号→应答，编号∈%s）"
                          % (uid, pname, vt, st, "/".join(sorted(ck_ids))))
            return
        for k, v in cr.items():
            if k not in ck_ids:
                errors.append("[矩阵] %s %s 漏洞[%s] checkpoint_response 的 KEY '%s' 不在该类型要点编号集 %s"
                              % (uid, pname, vt, k, "/".join(sorted(ck_ids))))
            if not (isinstance(v, str) and v.strip()):
                errors.append("[矩阵] %s %s 漏洞[%s] checkpoint_response['%s'] 应答为空" % (uid, pname, vt, k))
    elif cr is not None and not isinstance(cr, dict):
        errors.append("[矩阵] %s %s 漏洞[%s] checkpoint_response 应为对象" % (uid, pname, vt))


def _filter_probe_summary(fp):
    """filtered 跟踪清单的 filter_probe 摘要：object 取 key:防护情况 拼接，兼容旧 string。"""
    if isinstance(fp, dict):
        return " ".join("%s:%s" % (k, (v[0] if isinstance(v, list) and v else "")) for k, v in fp.items())
    if isinstance(fp, str):
        return fp.strip()
    return ""


def _protection_guards_in(fp):
    """返回 filter_probe 中出现的"防护"guard 集合（每个值数组首元素 ∈ FILTER_PROBE_PROTECTION，即非放行）。
    空集 = 未探到任何防护。供"探到防护禁判 tested_not_found"硬门禁使用。"""
    if not isinstance(fp, dict):
        return set()
    return {v[0] for v in fp.values()
            if isinstance(v, list) and v and v[0] in c.FILTER_PROBE_PROTECTION}


def check_entry(uid, pname, e, report_ids, errors, reviews, filtered_items):
    if not isinstance(e, dict):
        errors.append("[矩阵] %s %s 条目非对象：%r" % (uid, pname, e))
        return
    for fld in MATRIX_ENTRY_REQUIRED:
        if fld not in e:
            errors.append("[矩阵] %s %s 条目缺字段 %s" % (uid, pname, fld))
    vt = e.get("vuln_type")
    st = e.get("status")
    cat = e.get("category")
    if st not in c.MATRIX_STATUS:
        errors.append("[矩阵] %s %s 漏洞[%s] status 非法：%r" % (uid, pname, vt, st))
    if cat not in MATRIX_CATEGORY:
        errors.append("[矩阵] %s %s 漏洞[%s] category 非法（generic/business_logic）：%r" % (uid, pname, vt, cat))
    if st == "found":
        rid = (e.get("report_id") or "").strip()
        if not rid:
            errors.append("[矩阵] %s %s 漏洞[%s] 已发现但无 report_id" % (uid, pname, vt))
        elif rid not in report_ids:
            errors.append("[矩阵] %s %s 漏洞[%s] report_id 未登记报告清单：%s" % (uid, pname, vt, rid))
    # tested_not_found（已测未发现）/ doubtful（客观或边界不可测）/ filtered（有防护绕不过）均须留痕
    if st in ("tested_not_found", "doubtful", "filtered"):
        if not (e.get("tests") or "").strip():
            errors.append("[矩阵] %s %s 漏洞[%s] %s 缺 tests（测试payload/现象）" % (uid, pname, vt, st))
        if not (e.get("basis") or "").strip():
            errors.append("[矩阵] %s %s 漏洞[%s] %s 缺 basis（判定依据）" % (uid, pname, vt, st))
    # 通用漏洞过滤机制探测：filter_probe 须为结构化对象（found/not_applicable 可空）
    if cat == "generic" and st in c.FILTER_PROBE_REQUIRED_STATUS:
        _check_filter_probe(uid, pname, vt, e.get("filter_probe"), errors, reviews)
    elif isinstance(e.get("filter_probe"), str) and e.get("filter_probe").strip():
        reviews.append("[复核] %s %s 漏洞[%s] filter_probe 为字符串（旧格式），应改为对象 {符号/关键字:[防护情况,说明]}" % (uid, pname, vt))
    # 【软复核】通用漏洞探到防护(过滤/拦截/替换/转义)却判 tested_not_found：探到防护是潜在可绕信号的线索，
    # 由测试者判断该参数是否存在漏洞信号与绕过必要——确无信号且无绕过价值记 tested_not_found（basis 说明依据），
    # 有信号且值得绕过则记 filtered 交威胁收敛阶段专项绕过。此处仅列软复核抽查项，交 AI 判断分流是否合理，不作硬拦截。
    if cat == "generic" and st == "tested_not_found":
        guards = _protection_guards_in(e.get("filter_probe"))
        if guards:
            reviews.append("[复核] %s %s 漏洞[%s] filter_probe 探到防护(%s)且判 tested_not_found——"
                           "确认确无潜在漏洞信号且无绕过必要；若存在可绕信号则记 filtered 交威胁收敛阶段专项绕过"
                           % (uid, pname, vt, "/".join(sorted(guards))))
    # 有编号测试要点的漏洞类型：checkpoint_response 逐要点应答
    _check_checkpoint_response(uid, pname, vt, st, e.get("checkpoint_response"), errors)
    # filtered（被防护）汇入跟踪清单，供后续重点复查（换绕过手法 / 防护变更后重测）
    if st == "filtered":
        filtered_items.append((uid, pname, vt, _filter_probe_summary(e.get("filter_probe"))))


def check_matrix(uid, param_names, matrix, report_ids, errors, reviews, filtered_items):
    params = matrix.get("params")
    if not isinstance(params, dict):
        errors.append("[矩阵] %s 缺 params 对象" % uid)
        params = {}
    for pname in param_names:
        entries = params.get(pname)
        if not entries:
            errors.append("[矩阵] %s 参数 %s 无矩阵条目（每个参数都须先比对再记录结果）" % (uid, pname))
            continue
        if not isinstance(entries, list):
            errors.append("[矩阵] %s 参数 %s 条目应为数组" % (uid, pname))
            continue
        for e in entries:
            check_entry(uid, pname, e, report_ids, errors, reviews, filtered_items)
    for e in matrix.get("_url_level", []) or []:
        check_entry(uid, "_url_level", e, report_ids, errors, reviews, filtered_items)


def check_result_values(uid, res_key, res, errors):
    for pname, val in res.items():
        if not isinstance(val, dict):
            errors.append("[inventory] %s %s 参数 %s 结果应为 {漏洞类型:结果} 对象" % (uid, res_key, pname))
            continue
        for vt, outcome in val.items():
            ok = isinstance(outcome, str) and (
                outcome in ("tested_not_found", "doubtful", "filtered") or outcome.startswith("VULN-VD-"))
            if not ok:
                errors.append("[inventory] %s %s 参数 %s 漏洞[%s] 结果非法（应为报告号或 tested_not_found/doubtful/filtered）：%r"
                              % (uid, res_key, pname, vt, outcome))


def check_inventory_url(u, errors):
    uid = u.get("id")
    for done_key, res_key in [
        ("generic_vuln_mining_done", "generic_vuln_mining_result"),
        ("business_logic_mining_done", "business_logic_mining_result"),
    ]:
        done = u.get(done_key)
        if done not in c.MINING_STATUS:
            errors.append("[inventory] %s %s 非法：%r" % (uid, done_key, done))
        elif done == "pending":
            errors.append("[inventory] %s %s 仍为 pending（未完成挖掘）" % (uid, done_key))
        res = u.get(res_key)
        if done == "completed":
            if not isinstance(res, dict):
                errors.append("[inventory] %s %s 应为对象（completed 时）" % (uid, res_key))
            else:
                check_result_values(uid, res_key, res, errors)


def check_retest_list(paths, report_ids, errors, reviews, filtered_items):
    """补测清单硬校验：每条须已研判(非 pending)且填 access_note；
    disposition=retest 须已挖掘（mining_status 非 pending），有参数则有合规矩阵；
    disposition=blocked（安全边界/无需测）留痕不补测。返回 (retest 数, blocked 数)。"""
    items = c.load_json(paths["retest_list"], default={"items": []}).get("items", [])
    n_retest = n_blocked = 0
    for it in items:
        rid = it.get("id")
        disp = it.get("disposition")
        if disp not in c.RETEST_DISPOSITION:
            errors.append("[补测清单] %s disposition 非法：%r" % (rid, disp))
            continue
        if disp == "pending":
            errors.append("[补测清单] %s 未研判(pending)：须在广度/验证阶段研判为 retest(补测)或 blocked(不补测)" % rid)
            continue
        if not (it.get("access_note") or "").strip():
            errors.append("[补测清单] %s 为 %s 但缺 access_note（须记录走不通的客观现象/原因）" % (rid, disp))
        if disp == "blocked":
            n_blocked += 1
            continue  # 安全边界所限/无需测：留痕不补测
        # disposition == retest：确属客观阻塞，须已挖掘（漏洞挖掘阶段不得忽略）
        n_retest += 1
        ms = it.get("mining_status")
        if ms not in c.MINING_STATUS or ms == "pending":
            errors.append("[补测清单] %s 为 retest 但 mining_status=%r（补测URL须挖掘，漏洞挖掘阶段不得忽略）" % (rid, ms))
        pn = it.get("param_names", [])
        if pn and ms == "completed":
            mf = os.path.join(paths["vuln_matrix_dir"], "%s.json" % rid)
            if not os.path.exists(mf):
                errors.append("[补测清单] %s 有参数且已挖掘但缺矩阵文件：%s" % (rid, mf))
            else:
                check_matrix(rid, pn, c.load_json(mf, default={}), report_ids, errors, reviews, filtered_items)
    if items:
        reviews.append("[复核] 逐条复核补测清单：disposition 理由(access_note)是否成立、retest 项挖掘结论是否合理")
    return n_retest, n_blocked


def check_reports_registered(paths, report_ids, errors):
    """已生成的报告文件须都已登记 vuln-reports.json。

    主代理在阶段「结果验收」已逐份阅读并验收报告，门禁不重复阅读，只校验登记完整性：
    扫描 reports/VULN-VD-*.md，文件名（去 .md）即报告号，未登记者硬错误。返回已扫描报告文件数。"""
    rdir = paths["reports_dir"]
    n = 0
    if not os.path.isdir(rdir):
        return n
    for fp in sorted(glob.glob(os.path.join(rdir, "VULN-VD-*.md"))):
        n += 1
        vid = os.path.splitext(os.path.basename(fp))[0]
        if vid not in report_ids:
            errors.append("[报告登记] 报告文件已生成但未登记 vuln-reports.json：%s（请用 register_report.py 登记）" % vid)
    return n


def main():
    p = argparse.ArgumentParser(description="漏洞挖掘质量门禁")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    errors, reviews, filtered_items = [], [], []

    # 前置门禁：广度门禁须已清零（读 state.json 落盘退出态）。
    # 广度门禁尤为关键——本阶段常晚触达新页面/接口（二级页 create-order、账号接管链 reset-password），
    # 须按本门禁「第 0 步」重跑 build_url_inventory / build_retest_list / check_breadth 后，此处才会清零。
    errors += c.check_prior_gate(paths, "breadth")

    inv = c.load_json(paths["inventory"], default=None)
    if inv is None:
        print("[错误] 未找到 url-inventory.json")
        sys.exit(1)
    urls = inv.get("urls", [])
    inv_by_id = {u.get("id"): u for u in urls}

    # 必挖清单基线（进入阶段前 build_mining_scope.py 固化）——覆盖度硬门禁只认基线：
    # 挖掘阶段 payload 产生的新 URL/参数（如自上传 shell）不入必挖清单，转软复核由 AI 判断是否 --add 纳入。
    scope = c.load_json(paths["mining_scope"], default=None)
    if scope is None:
        errors.append("[必挖清单] 未找到 mining-scope.json——进入漏洞挖掘阶段前须先运行 "
                      "build_mining_scope.py 固化必挖清单基线（作覆盖度硬门禁依据）")
        scope = {"urls": []}
    scope_urls = scope.get("urls", [])
    scope_ids = {s.get("id") for s in scope_urls}

    # 与代理 url_index 一致性（保留硬校验：第 0 步重跑 build_url_inventory 后 inventory ⊇ 代理记录）
    idx = c.load_jsonl(paths["url_index"])
    idx_ids = {r.get("id") for r in idx if r.get("category") in ("page", "api", "other")}
    inv_ids = {u.get("id") for u in urls}
    for i in sorted(idx_ids - inv_ids):
        errors.append("[一致性] 代理记录的 URL %s 不在 URL 清单（请重跑 build_url_inventory.py）" % i)
    for i in sorted(inv_ids - idx_ids):
        errors.append("[一致性] URL 清单的 %s 在代理记录中不存在（凭空记录）" % i)

    report_ids = {r.get("vuln_id") for r in c.load_json(paths["vuln_reports"], default={"reports": []}).get("reports", [])}

    # 【必挖清单覆盖度·硬门禁】遍历固化基线：每个 URL 须已挖掘（两类 *_mining_done 非 pending），
    # 有参数则有合规矩阵（按基线 param_names 校验覆盖）。基线外的挖掘阶段新 URL/参数不在此强制。
    n_with_params = n_matrix = 0
    for s in scope_urls:
        uid = s.get("id")
        u = inv_by_id.get(uid)
        if u is None:
            errors.append("[必挖清单] 基线 URL %s 不在当前 URL 清单（勿删已固化的必挖 URL；确不再测须重固化基线）" % uid)
            continue
        if u.get("needs_review"):
            reviews.append("[复核] %s 仍标 needs_review（other 未判定），请先归类" % uid)
        param_names = s.get("param_names", []) or []
        matrix_file = os.path.join(paths["vuln_matrix_dir"], "%s.json" % uid)
        has_matrix = os.path.exists(matrix_file)
        if param_names:
            n_with_params += 1
            if not has_matrix:
                errors.append("[矩阵] %s 有参数但缺矩阵文件：%s" % (uid, matrix_file))
            else:
                n_matrix += 1
                check_matrix(uid, param_names, c.load_json(matrix_file, default={}), report_ids, errors, reviews, filtered_items)
        elif has_matrix:
            # 无参数 URL 若产出矩阵（记 _url_level 级测试）则校验其条目，与 check_matrix.py 自检口径一致
            check_matrix(uid, [], c.load_json(matrix_file, default={}), report_ids, errors, reviews, filtered_items)
        check_inventory_url(u, errors)
        # 基线固化后该 URL 新出现的参数（payload 注入等）→ 软复核，不强制入矩阵
        new_params = sorted(set(u.get("param_names", []) or []) - set(param_names))
        if new_params:
            reviews.append("[复核] %s 挖掘阶段新出现参数 {%s} 不在必挖基线，默认不强制挖掘；"
                           "确为正规业务参数则补测并重固化基线，payload 注入参数忽略" % (uid, ",".join(new_params)))

    # 挖掘阶段新出现的 page/api URL（不在必挖基线）→ 软复核（payload 副产物忽略 / 正规接口 --add 纳入）
    for u in urls:
        uid = u.get("id")
        if u.get("category") in ("page", "api") and uid not in scope_ids:
            reviews.append("[复核] %s 挖掘阶段新出现 URL 不在必挖基线，默认不入必挖清单；确为正规业务接口用 "
                           "build_mining_scope.py --add 纳入挖掘，payload 副产物（如自上传文件）忽略：%s"
                           % (uid, u.get("url", "")))

    # 补测清单（failed_index 来源）覆盖硬校验——避免漏洞挖掘阶段忽略失败URL
    n_retest, n_blocked = check_retest_list(paths, report_ids, errors, reviews, filtered_items)

    # 【报告登记·硬门禁】已生成报告文件须都已登记 vuln-reports.json（主代理已逐份阅读验收，门禁不重复阅读）
    n_reports = check_reports_registered(paths, report_ids, errors)

    reviews.append("[复核] 威胁消账前置回填：验收完成的 URL 是否已顺带对账 threats.jsonl 中 related_objects 指向该 URL "
                   "的威胁（命中报告→confirmed+report_id；矩阵证据充分不可利用→excluded+detail），减轻阶段四队列 A（非强制，最终以威胁收敛门禁为准）")
    reviews.append("[复核] filter_probe 结构专项：key 是否为单个符号/关键字（非整条 payload，重点看脚本软告警项）、防护情况(过滤/拦截/替换/转义/放行)与说明是否真实、是否覆盖该类型常用字符/关键字")
    reviews.append("[复核] checkpoint_response 专项：有编号要点的类型是否逐要点应答（对照 references/test-checkpoints.md）、有无漏答关键要点、应答是否属实且与 tests/报告证据一致（杜绝套话）")
    reviews.append("[复核] 对 tested_not_found / doubtful / filtered 各自抽样复核判定依据；核对状态分流正确：有漏洞信号但防护经真实尝试绕不过记 filtered（被防护），客观条件或安全边界导致无法测试或无法验证危害记 doubtful（存疑），确无信号记 tested_not_found")
    reviews.append("[复核] 挖掘阶段新出现 URL/参数（基线外软复核项）逐条判断：正规业务接口/参数则 build_mining_scope.py --add 或补测重固化，payload 副产物忽略")
    reviews.append("[复核] 所有 notes 特殊情况说明是否符合实际、合理")

    print("==== 漏洞挖掘质量门禁——脚本硬检查 ====")
    print("必挖基线 URL %d（有参数 %d，已出矩阵 %d） | URL清单 %d | 补测清单 retest %d / blocked %d | 报告 %d | 被防护(filtered) %d"
          % (len(scope_urls), n_with_params, n_matrix, len(urls), n_retest, n_blocked, n_reports, len(filtered_items)))
    print("")
    # 落盘退出态到 state.json.gates.vuln_mining（收尾门禁，供最终报告与断点续跑核对）
    nb = c.emit_gate_result(paths, "vuln_mining", errors, reviews)

    # 被防护清单：防护绕不过的接口/参数，交威胁收敛阶段专项绕过（build_bypass_list.py 汇集、pentest-bypass-miner 突破）
    print("")
    print("【被防护清单（filtered %d）——交威胁收敛阶段 build_bypass_list.py 汇集、pentest-bypass-miner 专项绕过】" % len(filtered_items))
    for uid, pname, vt, fp in filtered_items:
        print("  - %s · %s · %s%s" % (uid, pname, vt, ("（%s）" % fp if fp else "")))

    sys.exit(1 if nb else 0)


if __name__ == "__main__":
    main()
