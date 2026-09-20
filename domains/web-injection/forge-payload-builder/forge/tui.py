"""Forge · 载荷拼接器 · 终端交互界面。

    python -m forge [--data 规则库目录]

零依赖（只用 stdlib）。**面向 SSH / 跳板机场景**——GUI 要显示器，这里不要。

设计取舍：原来的 flag 式 CLI 有 27 个参数，要用户记住模板 id、绕过 id、22 个前提键。
而 GUI 和 flag CLI 做的是同一件事——把选择喂给引擎——只是交互方式不同，
所以 flag CLI 作为冗余砍掉，换成这里的菜单式界面。

生成逻辑一行都不在本文件里，全部走 forge.engine。
"""

import os
import sys
import unicodedata

from . import engine, output


def _w(s):
    """字符串的**显示宽度**：CJK 全角字符占 2 列。"""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in str(s))


def pad(s, n):
    """按显示宽度右侧补空格。

    不能用 `%-14s`——它按**字符数**补，而中文占 2 个显示列，
    结果是列会随内容飘（「（不限）」和「mysql」对不齐）。
    """
    s = str(s)
    return s + " " * max(0, n - _w(s))


def ask(prompt):
    """读一行。返回 None=回车跳过，'q'=退出，其余是输入串。"""
    try:
        raw = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "q"
    if not raw:
        return None
    return "q" if raw in ("q", "quit", "exit") else raw


# 选项多过这个数才提示「可以过滤」。9 个提交方式那种短菜单不需要——
# 多印一行提示反而是噪音。
_FILTER_HINT_FROM = 12


def menu(title, options, current=None, allow_cancel=True):
    """编号菜单，**选项多时可以直接输入文字过滤**。

    options 是 [(值, 说明)]，也可以给三元组 [(值, 说明, 显示文本)]——
    显示和取值分开，是为了能显示「SQL 注入 sqli」而返回 `sqli`。
    返回选中的值 / None=取消 / 'q'=退出。

    过滤是为了「全部可用模板」那个菜单：默认 sqli 视图就有 134 项、
    不限漏洞类型 584 项，一次打印出来是几屏，而用户往往是**从文档里
    已经知道 id**（`sqli.mysql.union.basic`）才来的——输几个字符直接命中，
    比在 134 行里找快得多。GUI 那边有搜索框，这里对齐。

    编号按**过滤后的列表**算：过滤完输 `3` 选的是过滤结果的第 3 条。
    """
    def render(opts):
        print("\n%s" % title)
        for i, opt in enumerate(opts, 1):
            val, note = opt[0], opt[1]
            show = opt[2] if len(opt) > 2 else val
            print("  %2d) %s %s%s" % (i, pad(show, 30), note, "  *" if val == current else ""))
        if allow_cancel:
            print("   0) 取消")
        if len(options) >= _FILTER_HINT_FROM:
            print("   输文字=过滤 · * =显示全部 · q=退出")

    shown = options
    render(shown)
    while True:
        raw = ask("选择 > ")
        if raw in (None, "q"):
            return raw
        if raw == "0" and allow_cancel:
            return None
        if raw.isdigit():
            k = int(raw)
            if 1 <= k <= len(shown):
                return shown[k - 1][0]
            print("  请输入 0-%d" % len(shown))
            continue
        # 非数字 → 当关键字过滤。三处都匹配：取值 id、显示文本、说明，
        # 因为用户可能在找「union.basic」（id）、「JSP」（显示名）或
        # 「反弹」（说明里才有）。
        if raw == "*":
            shown = options
        else:
            q = raw.lower()
            def text(o):
                return " ".join(str(x) for x in (o[0], o[1], o[2] if len(o) > 2 else ""))
            hit = [o for o in options if q in text(o).lower()]
            if not hit:
                # 过滤不到就复原，别把用户晾在一个空菜单里
                shown = options
                print("  没有匹配「%s」的，已显示全部 %d 项" % (raw, len(options)))
                render(shown)
                continue
            shown = hit
        print("  匹配 %d / %d 条" % (len(shown), len(options)))
        render(shown)


def draw(rules, st):
    """重绘主界面，返回 (可用模板行, 全量行)。"""
    rows = engine.filter_templates(rules, engine.make_state(**st))
    usable = [r for r in rows if r["usable"]]

    # 展示走 engine.label（「SQL 注入 sqli」），取值仍是 id——两者不能混，见 labels.yaml
    def L(kind, v):
        return engine.label(rules, kind, v) if v else "（不限）"

    print("\n" + "=" * 74)
    print(" 1 漏洞类型 %s 2 组件 %s 3 内容类型 %s"
          % (pad(L("vuln", st.get("vuln")), 20), pad(st.get("component") or "（不限）", 14),
             L("content_type", st.get("content_type"))))
    print(" 4 版本     %s 5 输出层 %s"
          % (pad(st.get("version") or "（不限）", 20),
             ", ".join(engine.label(rules, "render", o) for o in (st.get("outputs") or ["raw"]))))
    print(" 6 提交方式 %s 7 绕过 %s"
          % (pad(engine.label(rules, "submit", st.get("submit", "query")), 20),
             ", ".join(st.get("bypasses") or []) or "无"))
    on = [rules["requires_name"].get(k, k) for k in st.get("without") or []]
    print(" 8 目标前提 %s" % ("、".join(on) if on else "无"))
    print("-" * 74)

    if not usable:
        print(" 当前条件下没有可用模板。放宽下列任一条：")
        for s in engine.relax_suggestions(rules, st)["suggestions"]:
            print("   %-40s 多出 %d 条" % (s["desc"], s["gain"]))
        return usable, rows

    cur = st.get("template")
    print(" 可用 %d 条 / 共 %d 条" % (len(usable), len(rows)))
    for i, r in enumerate(usable[:12], 1):
        print("  %2d) %-34s %s%s"
              % (i, r["id"], r["name"], "  ←已选" if r["id"] == cur else ""))
    if len(usable) > 12:
        print("   … 还有 %d 条，按 t 打开完整列表" % (len(usable) - 12))

    # 有结果时也给一条放宽提示——否则用户不知道再放宽能拿到什么（GUI 一直显示）。
    # 不要写成「放宽「{desc}」」——desc 自己带「」，会套两层引号。
    sug = engine.relax_suggestions(rules, st)["suggestions"]
    if sug:
        print("   （多出 %d 条：%s）" % (sug[0]["gain"], sug[0]["desc"]))

    if cur:
        tpl = next((t for t in rules["templates"] if t["id"] == cur), None)
        for name in sorted(set(tpl.get("slots") or {}) | set(tpl.get("vars") or [])):
            # 显示**生效值**：槽位没设过要显示它的 default，不是空串。
            # 显示原始值会让界面和实际产出对不上——这个坑犯过两次。
            if name in (tpl.get("slots") or {}):
                val = (st.get("slots") or {}).get(name, tpl["slots"][name].get("default"))
                shown = engine.label(rules, "slot", name)
            else:
                val = (st.get("vars") or {}).get(name, "")
                shown = engine.label(rules, "var", name)
            print("      参数 %s = %r" % (pad(shown, 20), val))
    return usable, rows


def edit_params(rules, st, tid):
    tpl = next((t for t in rules["templates"] if t["id"] == tid), None)
    if tpl is None:
        return
    slots = dict(st.get("slots") or {})
    vs = dict(st.get("vars") or {})
    for name, spec in (tpl.get("slots") or {}).items():
        opts = [(engine.option_id(o), "", engine.option_text(o)) for o in spec["options"]]
        v = menu("槽位 %s（当前 %r）"
                 % (engine.label(rules, "slot", name), slots.get(name, spec.get("default"))),
                 opts, current=slots.get(name, spec.get("default")))
        if v == "q":
            return
        if v is not None:
            slots[name] = v
    for name in tpl.get("vars") or []:
        v = ask("\n变量 %s（当前 %r，回车跳过）> "
                % (engine.label(rules, "var", name), vs.get(name, "")))
        if v == "q":
            return
        if v is not None:
            vs[name] = v
    st["slots"], st["vars"] = slots, vs


def do_generate(rules, st):
    try:
        res = engine.generate(rules, engine.make_state(**st))
    except engine.RuleError as e:
        print("\n错误：%s" % e)
        return
    if not res["ok"]:
        print("\n没有可用模板。")
        return
    print("\n" + "=" * 74)
    print("组装链：")
    for s in res["steps"]:
        print("  %s %s" % (pad(s["step"], 12), s["text"]))
    for name, text in res["outputs"]:
        print("\n--- %s ---\n%s" % (name, text))
    print("\n语法：%s" % res["syntax"]["message"])
    for c in res["checks"]:
        print("提示：%s" % c)


# ---- 各字段的编辑器 ----

def _ed_vuln(rules, st):
    counts = {}
    for t in rules["templates"]:
        for v in t.get("vuln") or []:
            counts[v] = counts.get(v, 0) + 1
    opts = [(v, "(%d 条)" % counts[v], engine.label(rules, "vuln", v))
            for v in sorted(counts, key=lambda x: -counts[x])]
    v = menu("漏洞类型", opts, current=st.get("vuln"))
    if v not in (None, "q"):
        st["vuln"], st["template"] = v, None


def _ed_component(rules, st):
    comps = sorted({c for t in rules["templates"] for c in (t.get("component") or [])})
    v = menu("组件", [(None, "（不限）")] + [(c, "") for c in comps], current=st.get("component"))
    if v not in (None, "q"):
        st["component"], st["template"] = v, None


def _ed_ctype(rules, st):
    cts = sorted({c for t in rules["templates"] for c in (t.get("content_type") or [])})
    v = menu("内容类型", [(None, "（不限）")]
             + [(c, "", engine.label(rules, "content_type", c)) for c in cts],
             current=st.get("content_type"))
    if v not in (None, "q"):
        st["content_type"], st["template"] = v, None


def _ed_version(rules, st):
    v = ask("\n版本（如 8.0.32，回车跳过）当前 %r > " % st.get("version"))
    if v not in (None, "q"):
        st["version"] = v


def _ed_outputs(rules, st):
    print("\n可选：\n%s"
          % "\n".join("  %s" % pad(engine.label(rules, "render", r), 26) for r in output.RENDERERS))
    print("当前：%s" % ", ".join(engine.label(rules, "render", o)
                                for o in (st.get("outputs") or ["raw"])))
    v = ask("输出层（填 id 或中文名，逗号分隔，回车跳过）> ")
    if v not in (None, "q"):
        # 中文名和 id 都收——界面上显示的是中文，用户照着敲回来的也是中文
        picks = [engine.unlabel(rules, "render", x.strip()) for x in v.split(",") if x.strip()]
        picks = [p for p in picks if p in output.RENDERERS]
        if picks:
            st["outputs"] = picks


def _ed_submit(rules, st):
    v = menu("提交方式",
             [(p, "", engine.label(rules, "submit", p)) for p in output.PLACERS],
             current=st.get("submit"))
    if v not in (None, "q"):
        st["submit"] = v


def _ed_bypass(rules, st):
    cur = list(st.get("bypasses") or [])
    while True:
        # 互斥提示走引擎的 visible_bypasses——§4.1 定的是"绕过不过滤、只标互斥"，
        # 同一份逻辑 TUI 和 GUI 共用，不在界面层各算一遍。
        st["bypasses"] = cur
        rows = engine.visible_bypasses(rules, st)
        names = {b["id"]: b["name"] for b in rows}
        print("\n绕过（按列表顺序依次应用；选中已有的即移除）")
        for i, b in enumerate(cur, 1):
            print("  %2d) %s" % (i, b))
        if not cur:
            print("  （还没加）")
        for a, b in engine.bypass_pairs(rules, st):
            # 显示中文名，不带 id——带上会到 88 列，终端 80 列下会折行
            print("  ⚠ 互斥：%s 与 %s —— 同选会互相抵消"
                  % (engine.bypass_name(rules, a), engine.bypass_name(rules, b)))
        v = menu("添加 / 移除", [(b["id"], names[b["id"]]) for b in rows])
        if v in (None, "q"):
            break
        if v in cur:
            cur.remove(v)
        else:
            cur.append(v)
    st["bypasses"] = cur


def _ed_requires(rules, st):
    on = set(st.get("without") or [])
    while True:
        v = menu("目标没有哪些前提（选一次切换，带 * 的是已勾上）",
                 [(r["id"], r["name"]) for r in rules["requires"]])
        if v in (None, "q"):
            break
        on ^= {v}
    st["without"] = sorted(on)


EDITORS = {1: _ed_vuln, 2: _ed_component, 3: _ed_ctype, 4: _ed_version,
           5: _ed_outputs, 6: _ed_submit, 7: _ed_bypass, 8: _ed_requires}


def run(rules, st=None):
    # 在这里**原地**补全默认值，不依赖调用方，也不重建 dict——
    # 曾经 main 传了个没有 vuln 的 dict，界面读 st.get("vuln") 显示"不限"，
    # 而过滤已按默认值生效，两边对不上。原地补全同时让调用方能拿到最终状态（测试要用）。
    st = st if st is not None else {}
    for k, v in engine.make_state().items():
        st.setdefault(k, v)
    while True:
        usable, _ = draw(rules, st)
        print("\n 编号=改字段   t=选模板   s=填参数   g=生成   q=退出")
        cmd = ask("> ")

        if cmd is None:
            continue
        if cmd == "q":
            return 0
        if cmd == "g":
            do_generate(rules, st)
        elif cmd == "t":
            if usable:
                r = menu("全部可用模板", [(x["id"], x["name"]) for x in usable],
                         current=st.get("template"))
                if r not in (None, "q"):
                    st["template"], st["slots"], st["vars"] = r, {}, {}
        elif cmd == "s":
            if st.get("template"):
                edit_params(rules, st, st["template"])
            else:
                print("  先选一条模板")
        elif cmd and cmd.isdigit() and int(cmd) in EDITORS:
            EDITORS[int(cmd)](rules, st)
        else:
            print("  认不出的命令")


def main(argv=None):
    # Windows 控制台默认 cp936，中文会崩。这一行比到处 try/except 便宜。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args = list(argv if argv is not None else sys.argv[1:])
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    if len(args) >= 2 and args[0] == "--data":
        data_dir = args[1]

    try:
        rules = engine.load_rules(data_dir)
    except Exception as e:  # noqa: BLE001 - 启动失败要给一句人话，不是 traceback
        print("规则库加载失败：%s" % e, file=sys.stderr)
        return 1

    print("Forge 载荷拼接器 · %d 条模板 / %d 条绕过 / %d 个前提"
          % (len(rules["templates"]), len(rules["bypasses"]), len(rules["requires_name"])))
    print("全部本地生成，不联网、不执行。q 退出。")
    # 用 make_state 起手，让 st 一开始就带全默认值——
    # 否则界面读 st.get("vuln") 显示"不限"，而过滤已按默认的 sqli 生效，两边对不上。
    return run(rules, engine.make_state(outputs=["raw", "curl"]))
