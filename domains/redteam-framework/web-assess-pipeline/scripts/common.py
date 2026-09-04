# -*- coding: utf-8 -*-
"""WEB 应用安全评估 skill 共享工具：路径推导、原子读写、时间戳、ID 分配、枚举常量。

被 init_project / build_url_inventory / build_bypass_list / check_breadth /
check_vuln_mining / check_threat_convergence / extract_url_context / register_report 共用。
枚举常量须与 references/data-schemas.md 保持一致。
"""

import json
import os
import re
import sys
from datetime import datetime

# 控制台 UTF-8（Windows 下中文输出不乱码）
for _stream in ("stdout", "stderr"):
    try:
        getattr(sys, _stream).reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---- 枚举常量（与 references/data-schemas.md 一致）----
PRIORITIES = {"critical", "high", "medium", "low"}
WALKTHROUGH_STATUS = {"pending", "partial", "completed", "blocked"}
PERMISSION_STATUS = {"pending", "verified"}
JUDGMENT = {"normal", "abnormal"}
DOWNLOAD_STATUS = {"downloaded", "opensource", "failed"}
LOGIN_STATUS = {"success", "failed"}
PROJECT_STATUS = {"in_progress", "completed"}
SECURITY_LEVELS = {"high", "medium", "low"}
URL_CATEGORY = {"page", "api", "js", "resource", "other", "unknown"}
# 威胁收敛状态（威胁收敛阶段对账挖掘产出后更新）：待收敛 / 已确认 / 已排除 / 存疑(客观或边界不可测) / 被防护(有防护绕不过)
VERIFICATION_STATUS = {"pending", "confirmed", "excluded", "doubtful", "filtered"}
# 漏洞挖掘完成状态（URL 清单）：待开展 / 已完成 / 不适用
MINING_STATUS = {"pending", "completed", "not_applicable"}
# 补测清单研判处置（retest-list.json）：待研判 / 确属客观阻塞需补测 / 安全边界所限或无需测（留痕不补测）
RETEST_DISPOSITION = {"pending", "retest", "blocked"}
# 绕过台账处置（bypass-list.json）：待绕过 / 已专项绕过（转 found 或仍 filtered 且证据已扩充）
BYPASS_STATUS = {"pending", "retested"}
# 漏洞报告审核状态：待审核 / 已通过 / 已拒绝
REVIEW_STATUS = {"pending_review", "approved", "rejected"}
# 参数漏洞矩阵单元状态：不适用 / 已测试未发现 / 已发现漏洞 / 存疑(客观或边界不可测) / 被防护(有防护绕不过)
MATRIX_STATUS = {"not_applicable", "tested_not_found", "found", "doubtful", "filtered"}
# filter_probe 每个符号/关键字的防护情况取值（object 值数组首元素）：过滤/拦截/替换/转义/放行
FILTER_PROBE_GUARD = {"过滤", "拦截", "替换", "转义", "放行"}
# filter_probe 中代表"存在防护"的 guard（= 非放行）：任一命中即表示服务端对该字符/关键字有过滤/拦截/替换/转义。
# 通用漏洞(generic)探到防护是潜在可绕信号的线索，由测试者判断是否存在漏洞信号与绕过必要——有信号且值得绕过记
# filtered（交威胁收敛阶段专项绕过），确无信号或无绕过价值记 tested_not_found；门禁据此列软复核抽查项、不硬拦截。
FILTER_PROBE_PROTECTION = FILTER_PROBE_GUARD - {"放行"}
# filter_probe / checkpoint_response 必填的矩阵状态（已测未发现/存疑/被防护——假阴性高发区须留证）
FILTER_PROBE_REQUIRED_STATUS = {"tested_not_found", "doubtful", "filtered"}
# 报告阶段代码：漏洞挖掘（含威胁收敛阶段的补测/绕过产出，均逐 URL 归属）
REPORT_PHASE = {"VD"}
# 报告来源：逐 URL 挖掘产出，恒为 URL
REPORT_SOURCE = {"URL"}
NOT_FOUND = "not_found"
DEFAULT_NOTES = "无"

# ---- 测试要点编号映射（机读单一事实源，与 references/test-checkpoints.md 保持一致）----
# 前缀 → 该漏洞类型的测试要点编号集；门禁据此校验矩阵 checkpoint_response 的 KEY 是否命中。
# 新增/调整要点须同步更新此表与 test-checkpoints.md（两处由 code review 对齐）。
VULN_CHECKPOINTS = {
    "SQL": {"SQL001", "SQL002", "SQL003"},
    "XSS": {"XSS001", "XSS002"},
    "CMDI": {"CMDI001", "CMDI002", "CMDI003"},
    "SSRF": {"SSRF001", "SSRF002", "SSRF003"},
    "PATH": {"PATH001", "PATH002", "PATH003"},
    "UPLOAD": {"UPLOAD001", "UPLOAD002"},
    "ENUM": {"ENUM001", "ENUM002"},
    "AUTHZ": {"AUTHZ001", "AUTHZ002", "AUTHZ003"},
    "PRIZE": {"PRIZE001"},
    "RACE": {"RACE001", "RACE002", "RACE003"},
    "REPLAY": {"REPLAY001"},
    "SMS": {"SMS001", "SMS002"},
}
# vuln_type → 前缀 的归一线索（有序：更具体的关键字排前，子串匹配，兼容中英文/历史多写法）
_VT_PREFIX_HINTS = [
    ("CMDI", ["命令注入", "command inj", "os command", "os 命令"]),
    ("SQL", ["sql注入", "sql 注入", "sqli", "sql injection"]),
    ("XSS", ["xss", "跨站脚本"]),
    ("SSRF", ["ssrf", "服务端请求伪造"]),
    ("PATH", ["路径穿越", "目录穿越", "任意文件读", "任意文件下载", "path travers", "directory travers"]),
    ("UPLOAD", ["文件上传", "任意文件上传", "file upload"]),
    ("ENUM", ["用户枚举", "账号枚举", "用户名枚举", "user enum", "account enum"]),
    ("AUTHZ", ["越权", "未授权", "idor", "水平权限", "垂直权限", "水平越权", "垂直越权",
               "access control", "broken access", "authz", "unauthoriz"]),
    ("PRIZE", ["优惠", "积分", "抽奖", "签到", "优惠券", "领券"]),
    ("RACE", ["竞态", "并发", "toctou", "race condition", "双花", "超卖"]),
    ("REPLAY", ["重放", "replay"]),
    ("SMS", ["验证码", "短信", "captcha", "otp", "sms"]),
]


def vt_prefix(vuln_type):
    """把矩阵 vuln_type（多历史写法）归一到测试要点前缀；无匹配返回 None（该类型无强制要点）。"""
    s = (vuln_type or "").lower()
    for prefix, hints in _VT_PREFIX_HINTS:
        for h in hints:
            if h.lower() in s:
                return prefix
    return None


def checkpoint_ids_for(vuln_type):
    """该 vuln_type 对应的测试要点编号集合（无则空集，表示该类型无强制要点、不要求 checkpoint_response）。"""
    return VULN_CHECKPOINTS.get(vt_prefix(vuln_type) or "", set())


def now_iso():
    """本地时区 ISO8601 时间戳（秒级），如 2026-06-28T17:49:13+08:00。"""
    return datetime.now().astimezone().replace(microsecond=0).isoformat()


# ---- 范围（scope）/ 排除（exclude）判定 ----
# SCOPE-MATCH-SYNC: 本节匹配逻辑（_match_scope_rule）与 proxy/recorder.py._scope_match_literal /
# _in_scope 必须一致，修改需同步 recorder.py：代理只记录「在 scope 内且未被 exclude 排除」的流量，
# 门禁/子代理判定口径须与之统一（scope 与 exclude 两侧规则语法皆同源）。
def _match_scope_rule(rule, url, host, is_regex=False):
    """单条 scope/exclude 规则是否命中 url。语法（scope 与 exclude 共用）：
      - 正则（is_regex=True）→ 对完整 url 做 re.search（非法正则视为不命中）。
      - 字面·带路径（去 scheme 后含 "/"）→ URL 前缀匹配（去 scheme 后 startswith）。
      - 字面·纯域名（无 "/"）→ 主机精确或子域匹配（host == d 或 host.endswith("."+d)）。
    """
    if is_regex:
        try:
            return bool(re.search(rule, url))
        except re.error:
            return False
    has_scheme = "://" in rule
    bare = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", rule) if has_scheme else rule
    if "/" in bare:  # 路径前缀模式
        if has_scheme:
            return url.startswith(rule)
        url_bare = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url)
        return url_bare.startswith(bare)
    d = bare.rstrip("/").lower()  # 域名精确/子域模式
    return host == d or host.endswith("." + d)


def url_in_scope(url, scopes, scope_regex=False):
    """判断 url 是否在测试范围（config.json.scope）白名单内。

    scopes: config.scope 列表（如 ["localhost/TGSECdev/range/pentest/shop/"]）。
            空列表 → 返回 True（全部在范围，与代理"无 --scope 则记录全部"一致）。
    scope_regex: True 时把每条 scope 当正则对完整 url 做 search。
    任一命中即在范围内。注意：本函数只判白名单，排除见 url_excluded / url_in_test_scope。
    """
    from urllib.parse import urlsplit
    if not scopes:
        return True
    host = (urlsplit(url).netloc or "").lower()
    return any(_match_scope_rule(s, url, host, scope_regex) for s in scopes)


def url_excluded(url, excludes, exclude_regex=False):
    """判断 url 是否命中排除（config.json.exclude）黑名单，语法与 url_in_scope 对称。

    excludes: config.exclude 列表。空列表 → 返回 False（不排除任何）。
    exclude_regex: True 时把每条 exclude 当正则对完整 url 做 search。
    任一命中即被排除。
    """
    from urllib.parse import urlsplit
    if not excludes:
        return False
    host = (urlsplit(url).netloc or "").lower()
    return any(_match_scope_rule(e, url, host, exclude_regex) for e in excludes)


def url_in_test_scope(url, scopes, excludes=None, scope_regex=False, exclude_regex=False):
    """最终测试范围判定：在 scope 白名单内且未被 exclude 排除（排除优先）。

    门禁/子代理统一入口，与代理记录口径一致（代理 = in scope 且 not excluded 才落盘）。
    """
    return url_in_scope(url, scopes, scope_regex) and not url_excluded(url, excludes or [], exclude_regex)


# ---- JSON 读写（原子替换，与 recorder.py 一致）----

def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def atomic_write_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def load_jsonl(path):
    """宽松读取 jsonl，跳过坏行（严格校验见 check_*.py 内的 strict 加载）。"""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def dump_jsonl(path, records):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def next_id(prefix, existing_ids, width=4):
    """根据已有 id（如 PAGE0007）算下一个递增 id。"""
    mx = 0
    pat = re.compile(re.escape(prefix) + r"0*(\d+)$")
    for i in existing_ids:
        m = pat.match(str(i))
        if m:
            mx = max(mx, int(m.group(1)))
    return "{}{:0{}d}".format(prefix, mx + 1, width)


# ---- 路径推导 ----

# ---- 门禁退出态落盘 / 前置门禁校验（state.json.gates）----
# 设计意图：门禁脚本结束时由【脚本本身】把真实退出码与硬错误清单写进 state.json.gates[<gate>]，
# AI 无法伪造"通过"；下一阶段门禁开头读取上一门禁退出态并强制校验，杜绝"数据改了/门禁没重跑/
# 却空口记通过"。为避免客观走不通导致死锁，保留 acknowledged 出口：AI 逐条研判后在对应 gate 节点
# 补 {match, reason_code, note}，未被有效 acknowledged 覆盖的硬错误即 blocking；exit(blocking) 决定放行。
# 要点1(错误可豁免性由 reason_code 体现)/要点4(acknowledged 须复核+进残余清单) 由 AI 按原则执行。

# 可豁免原因码（固定小集合，作 AI 研判标尺；非机器校验表）
GATE_REASON_CODES = {
    "out_of_scope",          # 经确认不在测试范围
    "system_bug",            # 靶标系统缺陷导致走不通（非本方操作问题）
    "captcha_unbypassable",  # 人机校验确实无法绕过
    "precondition_unmet",    # 前置条件客观无法满足（如账号未锁定无法测解锁）
    "not_exist",             # 探测项确不存在（404 等）
    "accepted_residual",     # 承认残余风险、显式接受（须进最终报告残余清单）
}


def _ack_valid(a):
    """acknowledged 条目是否合法：reason_code 在固定集合、有 note、有 match 键。"""
    return (isinstance(a, dict)
            and a.get("reason_code") in GATE_REASON_CODES
            and bool((a.get("note") or "").strip())
            and bool((a.get("match") or a.get("error") or "").strip()))


def _ack_matches(a, err):
    """acknowledged 条目是否命中某条硬错误：以 match（通常为 URL 等唯一子串）子串包含判定。"""
    key = (a.get("match") or a.get("error") or "").strip()
    return bool(key) and key in err


def gate_blocking_errors(hard_errors, acknowledged):
    """返回未被【有效】acknowledged 覆盖的硬错误（=blocking，须修复才能放行）。

    [前置门禁] 类错误（及其 `    · ` 缩进明细）**不可 acknowledged**——只能通过修复/研判【上一门禁本身】
    来消除，防止在下游门禁越级豁免、架空前置门禁强制校验。"""
    acks = [a for a in (acknowledged or []) if _ack_valid(a)]
    blocking = []
    for e in hard_errors:
        if e.startswith("[前置门禁]") or e.startswith("    · "):
            blocking.append(e)          # 前置门禁错误不可下游豁免
        elif not any(_ack_matches(a, e) for a in acks):
            blocking.append(e)
    return blocking


def record_gate_state(paths, gate_name, hard_errors):
    """门禁脚本结束时把真实退出态写入 state.json.gates[gate_name]（脚本作者，非人工）。
    幂等保留仍命中现存错误的 acknowledged；已修复错误对应的陈旧 acknowledged 自动失效剔除。
    返回 (blocking:list, invalid_acks:list)。"""
    state = load_json(paths["state"], default={}) or {}
    gates = state.get("gates", {}) or {}
    node = gates.get(gate_name, {}) or {}
    ack_all = node.get("acknowledged", []) or []
    # 仅保留仍命中某条现存硬错误的 acknowledged（错误已修复→其豁免自动失效）
    ack = [a for a in ack_all if any(_ack_matches(a, e) for e in hard_errors)]
    invalid_acks = [a for a in ack if not _ack_valid(a)]
    blocking = gate_blocking_errors(hard_errors, ack)
    gates[gate_name] = {
        "exit": 1 if hard_errors else 0,        # 原始硬检查退出码（脚本写，真值）
        "blocking_count": len(blocking),         # 未 acknowledged 的硬错误数（=放行判据）
        "hard_errors": hard_errors,
        "acknowledged": ack,
        "checked_at": now_iso(),
    }
    state["gates"] = gates
    state["updated"] = now_iso()
    atomic_write_json(paths["state"], state)
    return blocking, invalid_acks


def read_gate_state(paths, gate_name):
    state = load_json(paths["state"], default={}) or {}
    return (state.get("gates", {}) or {}).get(gate_name)


def check_prior_gate(paths, prior_gate_name):
    """下一阶段门禁开头调用：校验上一门禁已"清零"（exit=0 或硬错误全部有效 acknowledged）。
    返回错误字符串列表（并入调用方 errors，前缀 [前置门禁]），空列表=上一门禁已清零。"""
    errs = []
    node = read_gate_state(paths, prior_gate_name)
    if not node:
        errs.append("[前置门禁] 未找到上一门禁(%s)的落盘退出态：须先运行其 check_*.py 生成 "
                    "state.json.gates.%s（禁止跳过门禁直接流转）" % (prior_gate_name, prior_gate_name))
        return errs
    hard = node.get("hard_errors", []) or []
    ack = node.get("acknowledged", []) or []
    blocking = gate_blocking_errors(hard, ack)
    if blocking:
        errs.append("[前置门禁] 上一门禁(%s)仍有 %d 条未处置/未有效 acknowledged 的硬错误，禁止流转"
                    "（先修复并重跑该门禁，或在 state.json.gates.%s.acknowledged 逐条研判 "
                    "reason_code+note）：" % (prior_gate_name, len(blocking), prior_gate_name))
        for b in blocking[:10]:
            errs.append("    · " + b)
    for a in ack:
        if not _ack_valid(a):
            errs.append("[前置门禁] %s 的 acknowledged 非法（reason_code 须∈%s 且 note 非空）：%r"
                        % (prior_gate_name, sorted(GATE_REASON_CODES), a))
    return errs


def emit_gate_result(paths, gate_name, errors, reviews):
    """统一收尾：落盘退出态 + 打印硬错误/acknowledged/待复核；返回 blocking 数（调用方据此 sys.exit）。
    exit 语义 = blocking（0 表示无硬错误或硬错误全部有效 acknowledged，可流转）。"""
    blocking, invalid_acks = record_gate_state(paths, gate_name, errors)
    node = read_gate_state(paths, gate_name) or {}
    blocking_set = set(blocking)
    acked = [e for e in errors if e not in blocking_set]

    if not errors:
        print("【硬检查通过】无硬错误。")
    else:
        if blocking:
            print("【必须修复（%d，未 acknowledged）】" % len(blocking))
            for e in blocking:
                print("  - " + e)
        if acked:
            print("【已 acknowledged 放行（%d，理由见 state.json.gates.%s.acknowledged 与质量报告）】"
                  % (len(acked), gate_name))
            for e in acked:
                print("  - " + e)
        if invalid_acks:
            print("【无效 acknowledged（%d，reason_code 非法或缺 note，未生效仍 blocking）】" % len(invalid_acks))
            for a in invalid_acks:
                print("  - " + repr(a))
        if not blocking:
            print("【硬错误已全部有效 acknowledged → 门禁放行】（须在质量报告逐条列明 reason_code+note）")
    print("")
    print("【待 AI 语义复核（%d）——脚本 exit 0 ≠ 门禁通过，须逐项复核】" % len(reviews))
    for r in reviews:
        print("  - " + r)
    print("")
    print("[门禁退出态已落盘 state.json.gates.%s] exit=%d hard_errors=%d blocking=%d "
          "→ 下一阶段门禁将强制校验（未清零禁止流转）"
          % (gate_name, node.get("exit", 0), len(errors), len(blocking)))
    return len(blocking)


def index_path(data_root):
    return os.path.join(data_root, "index.json")


def project_paths(data_root, project_id):
    """返回项目相关全部路径。"""
    d = os.path.join(data_root, project_id)
    return {
        "dir": d,
        "config": os.path.join(d, "config.json"),
        "state": os.path.join(d, "state.json"),
        "sessions": os.path.join(d, "sessions.json"),
        "pages": os.path.join(d, "pages.jsonl"),
        "pages_html": os.path.join(d, "pages-html"),
        "js": os.path.join(d, "js.jsonl"),
        "chains": os.path.join(d, "business-chains.jsonl"),
        "threats": os.path.join(d, "threats.jsonl"),
        "inventory": os.path.join(d, "url-inventory.json"),
        "mining_scope": os.path.join(d, "mining-scope.json"),
        "static_params": os.path.join(d, "url-static-params.json"),
        "retest_list": os.path.join(d, "retest-list.json"),
        "bypass_list": os.path.join(d, "bypass-list.json"),
        "vuln_reports": os.path.join(d, "vuln-reports.json"),
        "js_files": os.path.join(d, "js-files"),
        "perm_dir": os.path.join(d, "permission-matrix"),
        "reports_dir": os.path.join(d, "reports"),
        "report_out_dir": os.path.join(d, "report"),
        "vuln_matrix_dir": os.path.join(d, "vuln-matrix"),
        "url_context_dir": os.path.join(d, "url-context"),
        "proxy_logs": os.path.join(d, "proxy-logs"),
        "sessions_dir": os.path.join(d, "sessions"),
        "tmp_dir": os.path.join(d, "tmp"),
        "url_index": os.path.join(d, "proxy-logs", "url_index.jsonl"),
        "failed_index": os.path.join(d, "proxy-logs", "failed_index.jsonl"),
        "params_dir": os.path.join(d, "proxy-logs", "params"),
        "requests_dir": os.path.join(d, "proxy-logs", "requests"),
    }
