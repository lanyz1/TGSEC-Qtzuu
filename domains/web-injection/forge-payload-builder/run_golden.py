"""黄金样本比对（§13.2）。逐字节比对，不引入测试框架。



    python run_golden.py [golden_dir]

"""



import glob

import os

import re

import sys



import yaml



from forge import engine



GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")



ALL_SAMPLES = []  # main() 里填充，供覆盖率检查用





def compare(name, got, want, fails):

    if got != want:

        fails.append("%s\n    期望: %r\n    实际: %r" % (name, want, got))





def run_sample(rules, rules_version, sample, fails):

    """两种失败要分开表达：



    - `ok: false`  —— 生成正常跑完，但没有可用模板（空结果）

    - `raises: s`  —— 用户输入本身非法，抛 RuleError（空结果之外的用法错误）

    """

    name = sample["name"]

    state = engine.make_state(**sample["state"])

    exp = sample["expect"]



    if "raises" in exp:

        try:

            engine.generate(rules, state)

        except engine.RuleError as e:

            if exp["raises"] not in str(e):

                fails.append("%s: 报错信息不含 %r，实际：%s" % (name, exp["raises"], e))

        except Exception as e:  # noqa: BLE001

            fails.append("%s: 期望 RuleError，实际 %s: %s" % (name, type(e).__name__, e))

        else:

            fails.append("%s: 期望报错，实际成功" % name)

        return



    # 样本自己写坏了（槽位取值不在 options 里、模板 id 不存在……）不能让整个套件崩掉。

    # 抛出去的话后面几百条样本一条都跑不到，而**「哪条样本坏了」这个信息本身就没了**——

    # 记成一条失败，既跑得完又说清了是谁的问题。 实际踩到过：

    # 有人给样本填了个 options 里没有的槽位取值，run_golden 直接抛栈退出。

    try:

        res = engine.generate(rules, state)

    except engine.RuleError as e:

        fails.append("%s: 样本本身有问题，引擎抛了 RuleError：%s" % (name, e))

        return



    if exp.get("ok") is False:

        if res["ok"]:

            fails.append("%s: 期望生成失败，实际成功" % name)

        return



    if not res["ok"]:

        fails.append("%s: 期望成功，实际失败（%s）" % (name, res["reason"]))

        return



    if "payload" in exp:

        compare(name + " / payload", res["payload"], exp["payload"], fails)



    for out_name, want in (exp.get("outputs") or {}).items():

        got = dict(res["outputs"]).get(out_name)

        compare("%s / %s" % (name, out_name), got, want, fails)



    if "checks_count" in exp and len(res["checks"]) != exp["checks_count"]:

        fails.append("%s: 期望 %d 条提示，实际 %d 条（%s）"

                     % (name, exp["checks_count"], len(res["checks"]), res["checks"]))



    if "note" in exp:

        compare(name + " / note", res["note"], exp["note"], fails)



    if "syntax" in exp:

        compare(name + " / syntax", res["syntax"]["status"], exp["syntax"], fails)





def coverage_report(rules, docs_failed):

    """列出没有任何黄金样本引用的模板。



    便宜（O(n)），但只能发现「新模板没配样本」。要验样本是否**真的在断言**

    这个模板，用 `--mutate`：逐条篡改 body，看有没有样本会挂。

    """

    named = set()

    for s in ALL_SAMPLES:

        t = (s.get("state") or {}).get("template")

        if t:

            named.add(t)

    missing = [t["id"] for t in rules["templates"] if t["id"] not in named]

    if not missing:

        return []

    return ["模板 %s 没有黄金样本" % m for m in missing]





def mutation_coverage(rules):
    """逐条篡改模板 body，检查是否至少有一条样本会失败。

    比"样本里提到了这个 id"强得多——它验证的是样本**真的在断言**这个模板。
    篡改后没有任何样本失败的模板 = 假覆盖。
    """
    import copy
    from collections import defaultdict

    # **只重跑会受这条模板影响的样本。**
    # 改一条模板的 body，只会影响两类样本：
    #   1. 显式指定了这条模板的
    #   2. 没指定模板（按「第一条可用」选）而它恰好被选中的
    # 其余样本跟这条模板毫无关系，把它们的产物也算进指纹纯属浪费。
    #
    # 优化前是「每篡改一条就把**全部**样本重跑一遍」：584 模板 × 1053 样本
    # ≈ 60 万次 generate()，实测要跑十几分钟。现在每个模板平均只剩个位数样本。
    by_tpl = defaultdict(list)
    for s in ALL_SAMPLES:
        tid = (s.get("state") or {}).get("template")
        if tid:
            by_tpl[tid].append(s)

    # 没显式指定模板的样本，先算一次它实际选中了哪条
    implicit, unresolved = defaultdict(list), []
    for s in ALL_SAMPLES:
        if (s.get("state") or {}).get("template"):
            continue
        try:
            r = engine.generate(rules, engine.make_state(**s["state"]))
        except Exception:  # noqa: BLE001
            unresolved.append(s)
            continue
        if r.get("ok"):
            implicit[r["template"]].append(s)
        else:
            unresolved.append(s)   # 选不出模板的，任何一条被改都可能影响它

    def fingerprint(rs, samples):
        out = []
        for s in samples:
            try:
                r = engine.generate(rs, engine.make_state(**s["state"]))
                out.append((r.get("ok"), r.get("payload"), tuple(r.get("outputs") or []),
                            tuple(r.get("checks") or []), r.get("note"),
                            (r.get("syntax") or {}).get("status")))
            except Exception as e:  # noqa: BLE001
                out.append(("ERR", type(e).__name__, str(e)))
        return out

    blind = []
    for i, t in enumerate(rules["templates"]):
        cands = by_tpl.get(t["id"], []) + implicit.get(t["id"], []) + unresolved
        if not cands:
            # 一条样本都落不到它身上 —— 它从没被验证过，正是这个检查要找的东西
            blind.append("%s（没有任何样本会用到它）" % t["id"])
            continue
        mut = copy.deepcopy(rules)
        mut["templates"][i]["body"] += "Z"
        try:
            if fingerprint(rules, cands) == fingerprint(mut, cands):
                blind.append(t["id"])
        except Exception as e:  # noqa: BLE001
            blind.append("%s（变异后抛异常：%s）" % (t["id"], e))
    return blind


def smoke_requires(rules, fails):

    """requires 受控词表与筛选的冒烟测试。



    没有它的话，词表退化成自由文本、或者筛选静默失效，都不会有人发现——

    而这两件事正是这次改动要解决的问题。

    """

    vocab = set(rules.get("requires_name") or {})

    if not vocab:

        fails.append("smoke_requires: 没加载到 requires 词表")

        return



    # 每条模板的 requires 都必须来自词表

    bad = [(t["id"], r) for t in rules["templates"] for r in (t.get("requires") or [])

           if r not in vocab]

    if bad:

        fails.append("smoke_requires: 有 requires 不在词表里：%s" % bad[:3])



    def avail(**st):

        return {r["id"]: r for r in engine.filter_templates(rules, engine.make_state(**st)) if r["usable"]}



    base = avail(vuln="sqli")

    no_echo = avail(vuln="sqli", without=["echo"])

    if len(no_echo) >= len(base):

        fails.append("smoke_requires: 声明 without=echo 后可用模板没变少（%d → %d）"

                     % (len(base), len(no_echo)))



    # 需要 echo 的必须被筛掉，不需要的必须留下

    for tid, r in base.items():

        need = "echo" in (r["template"].get("requires") or [])

        if need and tid in no_echo:

            fails.append("smoke_requires: %s 需要 echo 却没被筛掉" % tid)

        if not need and tid not in no_echo:

            fails.append("smoke_requires: %s 不需要 echo 却被筛掉了" % tid)



    # 原因文案要能让人看懂

    rows = engine.filter_templates(rules, engine.make_state(vuln="sqli", without=["echo"]))

    reasons = {r["id"]: r["reason"] for r in rows if not r["usable"]}

    sample = next((v for v in reasons.values() if v and v.startswith("缺少前提")), None)

    if not sample:

        fails.append("smoke_requires: 被筛掉的模板没有「缺少前提」原因")

    elif "页面有回显位" not in sample:

        fails.append("smoke_requires: 原因里应带词表的展示名，实际 %r" % sample)



    # 组合筛选必须单调（每加一个 without，可用数只减不增）

    prev = len(base)

    for keys in (["echo"], ["echo", "error"], ["echo", "error", "stacked"],

                 ["echo", "error", "stacked", "outbound"]):

        n = len(avail(vuln="sqli", without=keys))

        if n > prev:

            fails.append("smoke_requires: 加 without=%s 后可用数反而变多（%d → %d）" % (keys, prev, n))

        prev = n





def smoke_relax(rules, fails):

    """§4.1 后半句：放宽建议的冒烟测试。



    重点是**建议里报的增量必须与实际相符**——报错了比不给建议更糟，

    用户会照着做然后发现还是空的。

    """

    cases = [

        dict(vuln="rce", content_type="sql-expression"),          # 类型错配，真·空

        dict(vuln="sqli", without=["echo", "error", "boolean"]),  # 筛得太紧

        dict(vuln="sqli"),                                        # 正常有结果

    ]

    for st in cases:

        state = engine.make_state(**st)

        sug = engine.relax_suggestions(rules, state)

        tag = "relax(%s)" % st



        for s in sug["suggestions"]:

            if s["gain"] <= 0:

                fails.append("%s: 给了一条增量为 %d 的建议：%s" % (tag, s["gain"], s["desc"]))

            if s["total"] != sug["base"] + s["gain"]:

                fails.append("%s: total 与 base+gain 对不上：%s" % (tag, s))



        # 真的把建议应用上去，数量必须和它报的一致

        for s in sug["suggestions"]:

            patched = dict(state)

            d = s["desc"]

            if d.startswith("去掉漏洞类型"):

                patched["vuln"] = None

            elif d.startswith("去掉组件限定"):

                patched["component"] = None

            elif d.startswith("去掉内容类型"):

                patched["content_type"] = None

            elif d.startswith("放宽前提"):

                name = d[len("放宽前提「"):-1]

                key = next(k for k, v in (rules["requires_name"] or {}).items() if v == name)

                patched["without"] = [x for x in patched["without"] if x != key]

            else:

                fails.append("%s: 认不出的建议描述 %r" % (tag, d))

                continue

            got = sum(1 for r in engine.filter_templates(rules, patched) if r["usable"])

            if got != s["total"]:

                fails.append("%s: 建议「%s」报共 %d 条，实际 %d 条" % (tag, d, s["total"], got))



    # 一个筛子都没开还是空的 —— 不该编出建议

    empty = engine.relax_suggestions({"templates": [], "requires_name": {}},

                                     engine.make_state())

    if empty["suggestions"]:

        fails.append("relax: 规则库为空时不该给出放宽建议")



    # 拼错的前提键必须报错，不能静默忽略

    try:

        engine.filter_templates(rules, engine.make_state(vuln="sqli", without=["typo"]))

        fails.append("relax: 未知前提键应抛 RuleError，实际静默通过")

    except engine.RuleError:

        pass





def smoke_render(rules, fails):

    """渲染器的结构化断言。



    为什么不放进黄金样本：multipart 请求体是几百字符、还带精确 Content-Length，

    逐字节手算的出错概率远高于它验证的价值——而一旦算错，人会倾向于

    "把期望值改成工具的输出"，那正好破坏了 §13.2 的纪律。

    改成断言**结构性质**（首尾边界、载荷落点、头部声明），既稳定又能抓真错。

    """

    from forge import output



    def gen(**st):

        return engine.generate(rules, engine.make_state(**st))



    fn = "upload.generic.filename.traversal"

    base = dict(vuln="upload", content_type="file-path", template=fn,

                vars={"name": "shell"}, submit="multipart", outputs=["request"])



    r = gen(**base)

    if not r["ok"]:

        fails.append("smoke_render: 生成失败（%s）" % r["reason"])

        return

    b = output.BOUNDARY

    body = r["request"]["body"]

    checks = [

        (body.startswith("--%s\r\n" % b), "multipart 体应以边界行开头"),

        ('filename="/../../../../var/www/html/shell.php"' in body, "载荷应落在 filename 属性里"),

        (body.endswith("\r\n--%s--\r\n" % b), "multipart 体应以结束边界结尾"),

        (r["request"]["headers"].get("Content-Type") == "multipart/form-data; boundary=" + b,

         "Content-Type 应声明 boundary"),

        (r["request"]["method"] == "POST", "multipart 应为 POST"),

    ]



    # part=content 时载荷应落到部件正文里

    r2 = gen(**dict(base, part="content", filename="a.php", outputs=["request"]))

    checks.append(('filename="a.php"' in r2["request"]["body"], "part=content 时文件名应取 --filename"))

    checks.append((r2["payload"] in r2["request"]["body"], "part=content 时载荷应在正文里"))



    # Content-Length 必须是**字节数**，不能是字符数——多字节文件名会暴露这个错

    r3 = gen(**dict(base, vars={"name": "中文"}, outputs=["request"]))

    want = len(r3["request"]["body"].encode("utf-8"))

    checks.append(("Content-Length: %d" % want in dict(r3["outputs"])["request"],

                   "Content-Length 应为字节数（期望 %d）" % want))



    for ok, desc in checks:

        if not ok:

            fails.append("smoke_render / %s" % desc)





def smoke_scaffold(rules, fails):

    """脚手架冒烟测试（在临时目录里跑，不碰真实规则库）。



    重点是别把「生成出来通不过校验」当成 bug——**骨架就该通不过**，

    那是让作者知道还没填完的信号。真正要验的是：

    生成的内容是合法 YAML、id 前缀对得上、追加不破坏已有内容、唯一性拦得住。

    """

    import shutil

    import subprocess

    import tempfile



    root = os.path.dirname(os.path.abspath(__file__))

    tmp = tempfile.mkdtemp(prefix="scaffold_")

    try:

        shutil.copytree(DATA_DIR, os.path.join(tmp, "data"))

        shutil.copytree(GOLDEN_DIR, os.path.join(tmp, "golden"))

        d, g = os.path.join(tmp, "data"), os.path.join(tmp, "golden")



        # 基线要**从刚复制出来的那份副本**上取，不能用外面那个 `rules`。

        # 用外面的会在两种情况下误报：复制之后、读基线之前，真实目录被别人改了

        # （多个人/多个 agent 同时在加数据时实测到过 553 → 557 的假失败）。

        # 这个测试只关心「副本上加一条会不会正好 +1」，基线就该来自副本自己。

        before = len(engine.load_rules(d)["templates"])

        tid = "rce.linux.reverse.perl"



        # 子进程也要设 UTF-8：Windows 控制台默认 cp936，输出里的中文和箭头会直接崩

        env = dict(os.environ, PYTHONIOENCODING="utf-8")



        def run(*extra):

            return subprocess.run(

                [sys.executable, os.path.join(root, "new_template.py"),

                 *extra, "--data", d, "--golden", g],

                capture_output=True, text=True, encoding="utf-8", cwd=root, env=env)



        r = run(tid, "--name", "Perl 反弹 Shell", "--ctype", "shell-command")

        if r.returncode != 0:

            fails.append("smoke_scaffold: 脚手架退出码 %d：%s" % (r.returncode, r.stderr[:200]))

            return



        # 生成的内容必须是合法 YAML，且模板数 +1

        try:

            after = engine.load_rules(d)

        except Exception as e:  # noqa: BLE001

            fails.append("smoke_scaffold: 生成后规则库解析失败（多半是 YAML 坏了）：%s" % e)

            return

        if len(after["templates"]) != before + 1:

            fails.append("smoke_scaffold: 模板数没 +1（%d → %d）"

                         % (before, len(after["templates"])))

        new = next((t for t in after["templates"] if t["id"] == tid), None)

        if new is None:

            fails.append("smoke_scaffold: 没找到新模板 %s" % tid)

            return

        if new.get("content_type") != ["shell-command"]:

            fails.append("smoke_scaffold: --ctype 没填进去，实际 %r" % new.get("content_type"))



        # 已有的模板不能被追加破坏

        if len({t["id"] for t in after["templates"]}) != len(after["templates"]):

            fails.append("smoke_scaffold: 追加后出现重复 id——旧内容被破坏了")



        # 骨架里仍有 TODO，必须能被校验器抓出来（用 content_type 留空那条）

        r2 = run("rce.linux.reverse.ruby", "--name", "Ruby 反弹 Shell")

        v = subprocess.run([sys.executable, os.path.join(root, "validate_rules.py"), d],

                           capture_output=True, text=True, encoding="utf-8", cwd=root, env=env)

        if "reverse.ruby" not in v.stdout or "content_type" not in v.stdout:

            fails.append("smoke_scaffold: 没填 content_type 的骨架应当被校验器报出来")



        # 重复 id 必须拦住

        r3 = run(tid, "--name", "重复")

        if r3.returncode == 0:

            fails.append("smoke_scaffold: 重复 id 没有被拦住")

        elif "已存在" not in r3.stderr:

            fails.append("smoke_scaffold: 重复 id 的报错信息不明确：%r" % r3.stderr[:120])

    finally:

        shutil.rmtree(tmp, ignore_errors=True)





def smoke_gui(rules, fails):

    """GUI 冒烟测试。无显示环境（CI/无头）自动跳过。



    这些断言都对应实现期真实踩到的 bug——GUI 的问题靠肉眼看代码是发现不了的，

    必须驱动它跑。第一个 bug（参数区空掉）就是驱动时炸出来的 KeyError。

    """

    try:

        import tkinter as tk



        from gui import build

        root = tk.Tk()

    except Exception:  # noqa: BLE001 - 无显示环境或 tkinter 缺失都不该让测试失败

        return

    root.withdraw()

    try:

        # 走**和 main() 同一套**组装（含最外层滚动容器），

        # 不一祥的话测的就不是用户看到的那个界面

        app = build(root, rules)

        root.update()



        def pick(tid):

            # 从 app.lst_rows 取 id，**不要解析列表的显示文本**。
            # 谁在前、怎么垫是界面细节，改一次就打断一次测试；GUI 自己
            # 定位选中项用的也是 lst_rows，测试跟它走同一条路。
            ids = [r["id"] for r in app.lst_rows]

            if tid not in ids:

                return False

            app.lst_templates.selection_clear(0, "end")

            app.lst_templates.selection_set(ids.index(tid))

            app.on_pick_template()

            root.update()

            return True



        # 1. 换模板后参数区必须跟着重建（曾经：控件字典被清空但缓存键还在，参数区空掉）。

        #    必须**真的切一次**——选已选中的模板会走提前返回，测不到这条路径。

        app.v_vuln.set("upload")

        app.v_ctype.set("file-path")

        app.v_component.set("（不限）")

        app.refresh()

        root.update()

        first = app.selected_template

        target = "upload.generic.filename.traversal"

        if first == target:

            target = "upload.generic.filename.double_ext"

        if not pick(target):

            fails.append("smoke_gui: 选不到 %s" % target)

            return

        if app.selected_template == first:

            fails.append("smoke_gui: 切换模板没生效，仍停在 %s" % first)

        tpl = next(t for t in rules["templates"] if t["id"] == app.selected_template)

        if set(app.slot_widgets) != set(tpl.get("slots") or {}):

            fails.append("smoke_gui: %s 的槽位控件与声明不符：%s vs %s"

                         % (tpl["id"], sorted(app.slot_widgets), sorted(tpl.get("slots") or {})))

        if set(app.var_entries) != set(tpl.get("vars") or []):

            fails.append("smoke_gui: %s 的变量控件与声明不符：%s vs %s"

                         % (tpl["id"], sorted(app.var_entries), sorted(tpl.get("vars") or [])))

        if not app.var_entries and not app.slot_widgets:

            fails.append("smoke_gui: 切换后参数区是空的（%s 声明了 slots/vars）" % tpl["id"])



        # 1b. **重新选中同一条模板必须是空操作**。

        #     曾经的 bug 就走这条路：清空控件字典 → 因缓存键未变而跳过重建 → 参数区空掉。

        saved_slots = {k: v.get() for k, v in app.slot_widgets.items()}

        saved_vars = {k: v.get() for k, v in app.var_entries.items()}

        pick(app.selected_template)

        if set(app.slot_widgets) != set(tpl.get("slots") or {}):

            fails.append("smoke_gui: 重新选中同一条模板后槽位控件丢了：%s"

                         % sorted(app.slot_widgets))

        if set(app.var_entries) != set(tpl.get("vars") or []):

            fails.append("smoke_gui: 重新选中同一条模板后变量控件丢了：%s"

                         % sorted(app.var_entries))

        for k, v in saved_slots.items():

            if k in app.slot_widgets and app.slot_widgets[k].get() != v:

                fails.append("smoke_gui: 重新选中同一条模板后槽位 %s 的值被重置" % k)

        for k, v in saved_vars.items():

            if k in app.var_entries and app.var_entries[k].get() != v:

                fails.append("smoke_gui: 重新选中同一条模板后变量 %s 的值被重置" % k)



        # 2. 绕过链与模板无关，换模板时必须保留

        app.v_addbypass.set("bypass.url")

        app.add_bypass()

        if "bypass.url" not in app.bypass_order:

            fails.append("smoke_gui: 添加绕过没生效")

        pick("upload.generic.filename.double_ext")

        if app.bypass_order != ["bypass.url"]:

            fails.append("smoke_gui: 换模板后绕过链丢了：%s" % app.bypass_order)



        # 3. 槽位跨模板沿用前必须校验合法性（同名槽位候选集可能不同）

        app.v_vuln.set("traversal")

        app.refresh()

        root.update()

        if pick("traversal.generic.linux"):

            app.slot_widgets["depth"].set("/../../../")

            app.refresh()

            pick("traversal.generic.windows")

            win = next(t for t in rules["templates"] if t["id"] == "traversal.generic.windows")

            opts = win["slots"]["depth"]["options"]

            if app.slot_widgets["depth"].get() not in opts:

                fails.append("smoke_gui: 槽位沿用了新模板不支持的取值 %r"

                             % app.slot_widgets["depth"].get())



        # 4. 空结果时标签页要给出可动作的下一步

        app.v_vuln.set("rce")

        app.v_ctype.set("sql-expression")

        app.refresh()

        root.update()

        names = [app.nb.tab(i, "text") for i in range(app.nb.index("end"))]

        if "无可用模板" not in names:

            fails.append("smoke_gui: 空结果时应有「无可用模板」标签页，实际 %s" % names)

        elif "放宽" not in app._tab_texts["无可用模板"].get("1.0", "end-1c"):

            fails.append("smoke_gui: 空结果页里没有放宽建议")



        # 5. 复制按钮必须真能取到文本（曾经：nametowidget 拿到 Frame，没有 .get()）

        app.copy_current()

        if "已复制" not in app.lbl_status.cget("text"):

            fails.append("smoke_gui: 复制后状态栏没反馈：%r" % app.lbl_status.cget("text"))



        # ---- requires ↔ GUI 联动（§4.1 后半句的可点击版本）----



        # 6. 勾选框要标出影响面，用户才知道勾上会少掉几条

        app.v_vuln.set("sqli")

        app.refresh()

        root.update()

        labeled = [cb.cget("text") for cb, _ in app.require_checks.values()]

        if not any("(" in t for t in labeled):

            fails.append("smoke_gui: 前提勾选框上没有影响面计数：%s" % labeled[:3])



        # 7. 「显示缺前提的」只能带出**因为缺前提**被筛掉的，不能把

        #    「漏洞类型不符」的也塞进来——选了 sqli 却看到别的类型是噪音

        app.v_show_excluded.set(True)

        app.without_vars["echo"].set(True)

        app.refresh()

        root.update()

        if not app.lst_rows:

            fails.append("smoke_gui: 列表为空")

        else:

            bad = [r["id"] for r in app.lst_rows

                   if not r["usable"] and not (r["reason"] or "").startswith("缺少前提")]

            if bad:

                fails.append("smoke_gui: 被筛掉的列表混进了非前提原因：%s" % bad[:3])

            if not any(not r["usable"] for r in app.lst_rows):

                fails.append("smoke_gui: 开了「显示缺前提的」却一条都没带出来")



        # 8. 选中缺前提的模板 → 面板给出可点的放宽按钮，点了要真放宽并选中

        idx = next((i for i, r in enumerate(app.lst_rows) if not r["usable"]), None)

        if idx is None:

            fails.append("smoke_gui: 找不到缺前提的模板用于测试放宽")

        else:

            app.lst_templates.selection_clear(0, "end")

            app.lst_templates.selection_set(idx)

            app.on_pick_template()

            root.update()

            tid = app.selected_template

            btns = [w for w in app.params.winfo_children() if w.winfo_class() == "TButton"]

            if not btns:

                fails.append("smoke_gui: 缺前提的模板没有给出放宽按钮（%s）" % tid)

            else:

                missing = [k for k in (next(r for r in app.lst_rows if r["id"] == tid)

                                       ["template"].get("requires") or [])

                           if app.without_vars.get(k) and app.without_vars[k].get()]

                if not missing:

                    fails.append("smoke_gui: 该模板没有可放宽的前提，按钮不该出现")

                else:

                    app.relax_and_pick(missing)

                    root.update()

                    row = next((r for r in app.lst_rows if r["id"] == tid), None)

                    if row is None or not row["usable"]:

                        fails.append("smoke_gui: 点了放宽后 %s 仍不可用" % tid)

                    if app.selected_template != tid:

                        fails.append("smoke_gui: 放宽后没选中原模板，停在 %s" % app.selected_template)

                    if any(app.without_vars[k].get() for k in missing):

                        fails.append("smoke_gui: 放宽后勾选状态没清掉：%s" % missing)



        # 9. 小窗口下不该有控件被挤出可视区。

        #    前提词表从 22 个键涨到 40 多个之后，固定 6 列在窄窗口下会把右边几列

        #    推到看不见的地方——用户看到的是「部分选项」，而且不知道右边还有。

        #

        #    **必须 deiconify 之后量**：withdraw 状态下控件不参与几何计算，

        #    winfo_width() 拿到的是请求尺寸而不是可视尺寸，断言会退化成空操作。

        #    第一版就是这么写的，量出来画布「宽 1464」而窗口只有 900 —— 完全对不上。

        root.deiconify()

        root.geometry("900x640")

        root.update()

        app._relayout_requires()

        root.update()



        win_w = root.winfo_width()

        if win_w > 1:

            # 可见宽度是**顶层窗口**的宽度：窗口比内容窄时画布仍按请求宽度布局再被裁掉，

            # 拿画布宽度去比，多宽的内容都能"放下"

            inner = app.require_scroll.inner

            over = [t for cb, t in app.require_checks.values()

                    if inner.winfo_x() + cb.winfo_x() + cb.winfo_width() > win_w]

            if over:

                fails.append("smoke_gui: 窗口 %dpx 时前提勾选框超出可视宽度"

                             "（%d/%d 个，例如 %r）"

                             % (win_w, len(over), len(app.require_checks),

                                [t[:14] for t in over[:2]]))

        # 内容超高可以滚，但不该被**挤没**——高度为 1 意味着用户完全够不着

        for name, w in (("模板列表", app.lst_templates), ("结果区", app.nb),

                        ("参数区", app.params_scroll.canvas)):

            if w.winfo_height() <= 1:

                fails.append("smoke_gui: 小窗口下%s被挤没了（高度 %d）"

                             % (name, w.winfo_height()))

    finally:

        root.destroy()





def smoke_select(rules, fails):

    """`<<select(cols,pos[,expr])>>` —— 回显位数与回显位的防线。



    这类模板以前把回显位写死在 1（`@@version,2,3`），目标回显在第 2 位就只能手改。

    现在能按 cols/pos 生成，但生成规则有几个边界，逐个钉住。

    """

    lu = {"cols": "3", "pos": "2", "expr": "@@version", "fp": "/etc/passwd"}

    cases = [

        ("<<select(cols,pos)>>", "1,2,3", "两参数：纯数字列表"),

        ("<<select(cols,pos,expr)>>", "1,@@version,3", "三参数：按名字取值"),

        ("<<select(cols,pos,pg_read_file('<<fp>>'))>>", "1,pg_read_file('<<fp>>'),3",

         "三参数写内联字面量，带括号和引号"),

        ("<<select(cols,pos,concat(0x7e,version()))>>", "1,concat(0x7e,version()),3",

         "字面量里的逗号不能被当成参数分隔"),

    ]

    for body, want, desc in cases:

        got, iss = engine.expand_select(body, lu)

        if got != want:

            fails.append("smoke_select: %s —— 期望 %r，实际 %r" % (desc, want, got))

        if iss:

            fails.append("smoke_select: %s 不该报问题：%s" % (desc, iss))



    # 越界要报出来，不能静默留个占位符在载荷里

    got, iss = engine.expand_select("<<select(cols,pos,expr)>>", {"cols": "3", "pos": "5"})

    if got != "<<select(cols,pos,expr)>>" or not iss:

        fails.append("smoke_select: 回显位超过列数应当报出来，实际 got=%r iss=%s" % (got, iss))



    # 参数没填 → 原样透传（契约 3）

    got, iss = engine.expand_select("<<select(cols,pos,expr)>>", {"cols": "3"})

    if got != "<<select(cols,pos,expr)>>":

        fails.append("smoke_select: 参数没填时应当原样透传，实际 %r" % got)



    # 一条 body 里有多个 select 也要都对

    got, _ = engine.expand_select("A <<select(cols,pos,expr)>> B <<select(cols,pos)>> C", lu)

    if got != "A 1,@@version,3 B 1,2,3 C":

        fails.append("smoke_select: 同一 body 多个 select 展开不对：%r" % got)



    # 走完整管线：默认值也必须能被 <<select>> 看到（踩过：fill_slots 的解析值没传下去）

    tid = "sqli.mysql.union.marker"

    res = engine.generate(rules, engine.make_state(

        vuln="sqli", component="mysql", template=tid, slots={"cols": "3", "pos": "2"},

        outputs=["raw"]))

    if res["ok"] and "0x41" not in res["payload"]:

        fails.append("smoke_select: 槽位默认值没传进 <<select>>，载荷=%r" % res["payload"])





def smoke_rep(rules, fails):

    """`<<rep(n,item)>>` —— 重复次数本身是选项的那类载荷。



    穿越序列（`....//` 重复几次）以前只能把三份硬写在 body 里，用户改不了层数。

    这里钉住「次数可调」和几个边界。

    """

    lu = {"n": "3", "item": "../../", "d": "x", "d.seq": "..;/"}



    cases = [

        ("<<rep(n,item)>>", "../../../../../../", "两个参数都按名字查"),

        ("<<rep(2,'a')>>", "'a''a'", "字面量参数（查不到就当字面量，引号也照带）"),

        ("<<rep(n,d.seq)>>", "..;/..;/..;/", "item 取字典槽位的字段"),

        ("A<<rep(1,item)>>B", "A../../B", "夹在正文中间"),

        ("<<rep(0,item)>>", "", "重复 0 次是合法输入，产出空串"),

    ]

    for body, want, desc in cases:

        got, iss = engine.expand_rep(body, lu)

        if got != want:

            fails.append("smoke_rep: %s —— 期望 %r，实际 %r" % (desc, want, got))

        if iss:

            fails.append("smoke_rep: %s 不该报问题：%s" % (desc, iss))



    # 次数不是数字 → 原样透传（契约 3），且**不报问题**（那是没填，不是错误）

    got, iss = engine.expand_rep("<<rep(missing,item)>>", lu)

    if got != "<<rep(missing,item)>>" or iss:

        fails.append("smoke_rep: 次数没填时应原样透传且不报问题，实际 %r %s" % (got, iss))



    # 超过上限要**报出来**，不能静默吃内存

    got, iss = engine.expand_rep("<<rep(999999,item)>>", lu)

    if got != "<<rep(999999,item)>>" or not iss:

        fails.append("smoke_rep: 超过次数上限应当报出来，实际 got=%r iss=%s" % (got, iss))



    # 参数个数不对要报出来

    got, iss = engine.expand_rep("<<rep(n)>>", lu)

    if not iss:

        fails.append("smoke_rep: 参数个数不对应当报出来")



    # 一条 body 里有多个 rep 也要都对（从后往前替换是为了这个）

    got, _ = engine.expand_rep("<<rep(2,item)>>|<rep>|<<rep(3,'b')>>", lu)

    if got != "../../../../|<rep>|'b''b''b'":

        fails.append("smoke_rep: 同一 body 多个 rep 展开不对：%r" % got)



    # 展开结果里的变量占位符要走后面的变量替换 —— 这是 expand_rep 在

    # expand_select 之后、变量替换之前跑的根据

    tid = "traversal.generic.dotdot.bypass"

    res = engine.generate(rules, engine.make_state(

        vuln="traversal", template=tid, slots={"depth": "5"},

        vars={"filepath": "/etc/passwd"}, outputs=["raw"]))

    if not res["ok"]:

        fails.append("smoke_rep: %s 生成失败：%s" % (tid, res["reason"]))

    else:

        want = "....//" * 5 + "/etc/passwd"

        if res["payload"] != want:

            fails.append("smoke_rep: 穿越层级没跟着 depth 走 —— 期望 %r，实际 %r"

                         % (want, res["payload"]))





def smoke_bypass_order(rules, fails):

    """绕过顺序与「无效绕过」提示。



    这是"绕过是盲盒"那条的防线：用户排了顺序，但某一步可能被前一步抵消而**静默失效**。

    工具要主动说出来，而不是让人去比对组装链。

    """

    def gen(bs, **kw):

        st = dict(vuln="sqli", template="sqli.mysql.union.basic", bypasses=bs, outputs=["raw"])

        st.update(kw)

        return engine.generate(rules, engine.make_state(**st))



    # 空格替换排在 URL 编码之后 → 什么都不做（空格已变成 %20）

    r = gen(["bypass.url", "bypass.space.comment"])

    if not any("没有改变载荷" in c for c in r["checks"]):

        fails.append("smoke_bypass_order: 被抵消的绕过没有提示（%s）" % r["checks"])



    # 反过来就该生效，不该有提示

    r2 = gen(["bypass.space.comment", "bypass.url"])

    if any("没有改变载荷" in c for c in r2["checks"]):

        fails.append("smoke_bypass_order: 正常生效的绕过多报了「没有改变载荷」")

    if r2["payload"] == r["payload"]:

        fails.append("smoke_bypass_order: 两种顺序产出居然一样，用例选错了")



    # 顺序无关的一对不该报（免得提示变成噪音）

    r3 = gen(["bypass.url", "bypass.case.alternate"])

    if any("没有改变载荷" in c for c in r3["checks"]):

        fails.append("smoke_bypass_order: 顺序无关的组合误报了")





def smoke_var_notes(rules, fails):

    """变量替换阶段的**提示**是否该报的报、不该报的不报。



    这条提示管的是「载荷会被提前截断」——最该说出来的一类问题。

    它出过两次错，方向正好相反：



    1. **假阳性**：`'...'` 里塞进 `"` 也报（`"` 根本闭合不了单引号字面量）。

       两个独立写模板的人都撞上了，去把引擎改对。

    2. **静默漏报**：引号区间是替换**前**算的，而循环会改 body 长度——

       模板里有两个以上变量、靠前那个替换后变长时，靠后的就查错区间、

       提示直接消失。多变量模板实测踩到（filepath 12→24 字节）。

    """

    # 用例都带上一个前导字符：**片段以引号开头时那个引号是「闭合上层上下文的

    # 逃逸符」，不是开启引号**，整条会按代码处理（见 bypass.quoted_spans 的说明）。

    # 第一版忘了这点，写成 "'<<a>>'"，结果一个提示都测不出来。

    LIT = "x'<<a>>'"



    # 同种引号 → 报

    _, notes = engine.substitute_vars(LIT, {"vars": {"a": "y'z"}})

    if not any("落在模板的" in n for n in notes):

        fails.append("smoke_var_notes: 值里含同种引号时应当提示截断风险")



    # 异种引号 → 不报（`'...'` 里放 `"` 是安全的）

    _, notes = engine.substitute_vars(LIT, {"vars": {"a": 'y"z'}})

    if notes:

        fails.append("smoke_var_notes: 值里只有异种引号时不该提示：%s" % notes)



    # 变量不在引号里 → 不报

    _, notes = engine.substitute_vars("<<a>>", {"vars": {"a": "y'z"}})

    if notes:

        fails.append("smoke_var_notes: 变量不在字面量里时不该提示：%s" % notes)



    # ⭐ 两个变量，前一个替换后**变长** —— 后一个的区间不能因此查错

    _, notes = engine.substitute_vars(

        "<<pad>>" + LIT, {"vars": {"pad": "x" * 40, "a": "y'z"}})

    if not any("变量 a " in n for n in notes):

        fails.append("smoke_var_notes: 靠前的变量变长后，靠后的变量仍应被检查"

                     "（引号区间是替换前算的这个坑）")



    # 反过来的顺序也要对：含引号的那个先替换

    _, notes = engine.substitute_vars(

        LIT + "<<pad>>", {"vars": {"a": "y'z", "pad": "x" * 40}})

    if not any("变量 a " in n for n in notes):

        fails.append("smoke_var_notes: 变量顺序反过来时也该提示")



    # <<len()>> 算的是**字节**数，不是字符数

    txt, _ = engine.substitute_vars("s:<<len(v)>>:\"\"", {"vars": {"v": "管理员"}})

    if txt != 's:9:""':

        fails.append("smoke_var_notes: <<len()>> 应按字节算（管理员 = 9），实际 %r" % txt)





def smoke_phpser(rules, fails):

    """PHP 序列化：结构 DSL（生成）+ 良构性校验（解析）。



    这两件事是**分开实现**的（`forge/phpser.py` 与 `forge/syntax.py`），

    这里也要分开验：生成对了不代表校验器认得出错，校验器严了也不代表生成没跑偏。

    最要紧的一条是最后那个回归——它钉的是一个真实存在过的 bug：

    模板声明了 N 个属性却只写得下一个属性对，而默认取值恰好是对的，

    所以黄金样本一直没碰到。

    """

    from forge import phpser, syntax



    # ---- 生成：每种值类型 + 可见性 + 嵌套 ----

    cases = [

        ('N', 'N;'),

        ('b:1', 'b:1;'),

        ('i:-42', 'i:-42;'),

        ('d:1.5', 'd:1.5;'),

        ('s:"hello"', 's:5:"hello";'),

        ('s:""', 's:0:"";'),

        ('s:"管理员"', 's:9:"管理员";'),          # 3 个字符 9 个字节

        ('a{}', 'a:0:{}'),

        ('a{ i:0 s:"a" i:1 s:"b" }', 'a:2:{i:0;s:1:"a";i:1;s:1:"b";}'),

        ('O:Foo{}', 'O:3:"Foo":0:{}'),

        ('O:Foo{ bar=s:"x" }', 'O:3:"Foo":1:{s:3:"bar";s:1:"x";}'),

        # protected：长度要把 `\0*\0` 一起算进去（6 = 1+1+1+3）

        ('O:Foo{ -bar=s:"x" }', 'O:3:"Foo":1:{s:6:"\0*\0bar";s:1:"x";}'),

        # private：长度含 `\0类名\0`（8 = 1+3+1+3）

        ('O:Foo{ #bar=s:"x" }', 'O:3:"Foo":1:{s:8:"\0Foo\0bar";s:1:"x";}'),

        # 嵌套 + 命名空间反斜杠

        (r'O:App\Cache{socket=O:SoapClient{uri=s:"http://x"}}',

         'O:9:"App\\Cache":1:{s:6:"socket";O:10:"SoapClient":1:{s:3:"uri";s:8:"http://x";}}'),

        # 内容里有分隔符也要原样收下——长度前缀就是为了这个

        ('s:"a;b}"', 's:4:"a;b}";'),

        # 私有属性的 mangling 类名可以显式指定（父类的私有属性就是这种形状）

        # 期望值里的 NUL 是**载荷内容**（private 属性的 mangled 名里嵌着它）。
        # 这里用 chr(0) 拼而不是写转义：源码里出现真实 NUL 会让整个文件解析不了，
        # 期望值里的 NUL 是**载荷内容**（private 属性的 mangled 名里嵌着它）。
        # 这里用 chr(0) 拼而不是写字面转义：源码里出现真实 NUL 会让整个文件解析不了，
        # 而用转义写法又要数一层（工具链上已经栽过两次）。
        ('O:Sub{ #Base/p=i:1 }',
         'O:3:"Sub":1:{s:7:"' + chr(0) + 'Base' + chr(0) + 'p";i:1;}'),
        ('O:Sub{ #Base/p=i:1 }',
         'O:3:"Sub":1:{s:7:"' + chr(0) + 'Base' + chr(0) + 'p";i:1;}'),
    ]

    for spec, want in cases:

        try:

            got = phpser.build(spec)

        except phpser.SpecError as e:

            fails.append("smoke_phpser: %r 应当能展开，却报错 %s" % (spec, e))

            continue

        if got != want:

            fails.append("smoke_phpser: %r\n    期望: %r\n    实际: %r" % (spec, want, got))



    # ---- 生成：坏结构必须报错，不能吐半截串 ----

    for bad in ('O:Foo{ bar=', 'a{ x=i:1 }', 'q:1', 'i:', 's:"未闭合', 'O:Foo{ bar=s:"x"',

                'O:Foo{ #/x=i:1 }', 'O:Foo{ #A/=i:1 }'):

        try:

            phpser.build(bad)

            fails.append("smoke_phpser: %r 是坏结构，应当抛 SpecError" % bad)

        except phpser.SpecError:

            pass



    # ---- 生成：深度上限（挡住手滑写出的深层嵌套）----

    deep = "O:A{" * (phpser.MAX_DEPTH + 5)

    try:

        phpser.build(deep)

        fails.append("smoke_phpser: 超过深度上限的结构应当抛 SpecError")

    except phpser.SpecError:

        pass



    # ---- 校验：生成出来的串必须全部判 ok ----

    for spec, _ in cases:

        st, msg = syntax.check(phpser.build(spec), "serialized")

        if st != "ok":

            fails.append("smoke_phpser: 自己生成的串没通过自己的校验（%r）：%s"

                         % (spec, msg))



    # ---- 校验：手写的坏串必须判 fail ----

    bad_payloads = [

        ('O:3:"Foo":2:{s:3:"bar";s:1:"x";}', "属性个数声明与实际不符"),

        ('s:4:"abc";', "字符串长度多算一个字节"),

        ('s:3:"管理员";', "长度按字符数算而不是字节数"),

        ('a:2:{i:0;s:1:"a";}', "数组元素个数声明与实际不符"),

        ('O:3:"Foo":1:{s:3:"bar";s:1:"x";}Z', "结尾多出字节"),

    ]

    for payload, why in bad_payloads:

        st, msg = syntax.check(payload, "serialized")

        if st != "fail":

            fails.append("smoke_phpser: %s 的串应当判 fail，实际 %s（%s）"

                         % (why, st, msg[:60]))



    # ---- 校验：没建模的语法要判 unchecked，不能判 fail ----

    # 判 fail 会让用户去改一条本来正确的载荷，比漏报更糟

    # 引用（R:/r:）以前也在这张单子上，现在**建模了**，见下面一组。

    for payload in ('C:3:"Foo":5:{a:1:{}}',):

        st, _ = syntax.check(payload, "serialized")

        if st != "unchecked":

            fails.append("smoke_phpser: 未建模的 %r 应当判 unchecked，实际 %s"

                         % (payload, st))



    # ---- 引用：期望值**全部来自真实 PHP 的 unserialize 判定** ----

    # 不是照着 syntax.py 的实现反推的——那样实现错了测试也跟着错，

    # 就成了自我确认。这批值是在 PHP 7.0.12 上逐条跑出来的。

    for payload, want in (

            ('O:1:"A":1:{s:1:"p";r:1;}', "ok"),      # 自引用，PHP 成功

            ('a:2:{i:0;s:1:"v";i:1;r:2;}', "ok"),    # 指向前一个值，PHP 成功

            ('a:2:{i:0;s:1:"v";i:1;R:2;}', "ok"),    # 真引用，PHP 成功

            ('a:2:{i:0;s:1:"v";i:1;r:3;}', "fail"),  # 指向「引用自己那个号」，PHP false

            ('a:2:{i:0;s:1:"v";i:1;r:9;}', "fail"),  # 越界，PHP false

            ('a:2:{i:0;s:1:"v";i:1;r:0;}', "fail"),  # 号从 1 起，PHP false

            ('a:2:{i:0;i:5;i:1;r:2;}', "ok"),        # r: 指向非对象——PHP 照样成功，

                                                     # 所以**不能**检查目标类型，查了就是误报

    ):

        st, _ = syntax.check(payload, "serialized")

        if st != want:

            fails.append("smoke_phpser: %r 应当判 %s，实际 %s（期望值来自真实 PHP）"

                         % (payload, want, st))



    # ---- 引擎接线 ----

    got, iss = engine.expand_phpser("<<phpser(spec)>>", {"spec": 'O:Foo{ a=i:1 }'})

    if got != 'O:3:"Foo":1:{s:1:"a";i:1;}' or iss:

        fails.append("smoke_phpser: 引擎展开不对：%r %s" % (got, iss))

    # 名字查不到 = 没填 → 原样透传且**不报问题**（契约 3）

    got, iss = engine.expand_phpser("<<phpser(spec)>>", {})

    if got != "<<phpser(spec)>>" or iss:

        fails.append("smoke_phpser: 没填结构描述时应原样透传且不报问题：%r %s" % (got, iss))

    # 结构坏了要**报出来**，而且不能吐出半截串

    got, iss = engine.expand_phpser("<<phpser(spec)>>", {"spec": "O:Foo{ a="})

    if got != "<<phpser(spec)>>" or not iss:

        fails.append("smoke_phpser: 结构坏时应报出来并保留占位符：%r %s" % (got, iss))

    # 结构描述里可以嵌变量（POP 链里塞 http://<<lhost>>/ 很常见）

    got, _ = engine.expand_phpser("<<phpser(spec)>>",

                                 {"spec": 's:"http://<<lhost>>/"', "lhost": "10.0.0.1"})

    if got != 's:16:"http://10.0.0.1/";':      # http:// 7 + 8 位 IP + / 1

        fails.append("smoke_phpser: 结构描述里的变量没被替换：%r" % got)



    # ---- ⭐ 回归：结构类模板不许出现「声明 N 个属性却只写一个」----

    # 这是真实存在过的 bug：deser.php.syntax.object 的 n 槽位能选 2/3，

    # 但 body 里只有一个属性对，产出 `O:3:"Foo":2:{s:3:"bar";s:1:"x";}`。

    # 默认值恰好是 1，所以黄金样本从没碰到——只有拿校验器过一遍才现形。

    for t in rules["templates"]:

        if "serialized" not in (t.get("content_type") or []):

            continue

        st = dict(vuln=(t.get("vuln") or [None])[0], template=t["id"],

                  vars={k: "x" for k in (t.get("vars") or [])}, outputs=["raw"])

        for name, spec in (t.get("slots") or {}).items():

            for opt in spec["options"]:

                val = opt["id"] if isinstance(opt, dict) else opt

                st["slots"] = {name: val}

                r = engine.generate(rules, engine.make_state(**st))

                if not r["ok"] or r["syntax"]["status"] != "fail":

                    continue

                fails.append("smoke_phpser: %s 取 %s=%s 时产出的序列化串过不了校验：%s"

                             % (t["id"], name, val, r["syntax"]["message"][:70]))





def smoke_bypass_coverage(rules, fails):

    """每条绕过都必须至少被一份样本引用过。



    这是 `coverage_report`（管模板）的绕过版，补的是同一个洞：

    **`--mutate` 只篡改模板 body，绕过的代码路径它碰不到**。

    在加这个检查之前，41 条绕过里有 31 条一次都没被执行过——包括全部 8 个 codec，

    也就是说 gzip 的「压缩后必须再 base64」这类约定写错了不会有任何测试变红。



    它只保证「跑过」，不保证「跑对」——那是 `golden/bypasses.yaml` 里逐字节期望值的事。

    """

    named = set()

    for s in ALL_SAMPLES:

        named |= set((s.get("state") or {}).get("bypasses") or [])

    missing = [b["id"] for b in rules["bypasses"] if b["id"] not in named]

    if missing:

        fails.append("smoke_bypass_coverage: 这些绕过没有任何样本引用过（从没被执行）：%s"

                     % missing)



    # 样本里引用的绕过 id 必须真的存在（改名/删条目时留下的死引用）

    known = {b["id"] for b in rules["bypasses"]}

    for s in ALL_SAMPLES:

        for bid in (s.get("state") or {}).get("bypasses") or []:

            if bid not in known:

                fails.append("smoke_bypass_coverage: 样本「%s」引用了不存在的绕过 %s"

                             % (s.get("name"), bid))



    # 非 encode 的绕过：**至少有一条**用到它的样本真的改变了载荷。

    #

    # 为什么是「至少一条」而不是「每一条」：有一种正当的**负向样本**——

    # 「这个绕过**不该**动引号里的内容」，它的期望值本来就该和没加绕过时一样。

    # 但如果**所有**样本里它都没生效，那这条绕过的代码路径就仍然没被验证过，

    # 只是恰好被一个空操作蒙混过去了。`bypass.case.upper` 就这样躲过一次。

    for b in rules["bypasses"]:

        if b.get("type") == "encode":

            continue

        users = [s for s in ALL_SAMPLES

                 if b["id"] in ((s.get("state") or {}).get("bypasses") or [])]

        if not users:

            continue

        changed = False

        for s in users:

            st = dict(s["state"])

            st["bypasses"] = []

            try:

                base = engine.generate(rules, engine.make_state(**st))

                cur = engine.generate(rules, engine.make_state(**s["state"]))

            except engine.RuleError:

                continue

            if base.get("ok") and cur.get("ok") and base["payload"] != cur["payload"]:

                changed = True

                break

        if not changed:

            fails.append("smoke_bypass_coverage: 绕过 %s 在所有用到它的样本里都没改变载荷"

                         "（等于从没被验证过）：%s"

                         % (b["id"], [s.get("name") for s in users]))





def smoke_labels(rules, fails):

    """展示标签层的冒烟测试。



    标签是**纯显示层**——它一旦漏进取值路径，生成结果就会变成「SQL 注入 sqli」

    这种废串，而且黄金样本会一起红。所以这里钉的是「显示改了、取值没变」。

    """

    labels = rules.get("labels") or {}

    if not labels:

        fails.append("smoke_labels: 没加载到 data/labels.yaml")

        return



    # 每个维度都至少要有中文，否则界面还是一屏标识符

    for kind in ("vuln", "content_type", "submit", "render", "slot", "var"):

        if not labels.get(kind):

            fails.append("smoke_labels: 维度 %s 没有标签" % kind)



    # 只要是规则库里出现过的取值，就该有中文——漏一个就是界面上留一句黑话

    def used(kind, values):

        miss = sorted(v for v in values if v not in labels.get(kind, {}))

        if miss:

            fails.append("smoke_labels: %s 里这些取值没有中文标签：%s" % (kind, miss[:8]))



    used("vuln", {v for t in rules["templates"] for v in (t.get("vuln") or [])})

    used("content_type", {c for t in rules["templates"] for c in (t.get("content_type") or [])})

    used("slot", {s for t in rules["templates"] for s in (t.get("slots") or {})})

    used("var", {v for t in rules["templates"] for v in (t.get("vars") or [])})

    from forge import output

    used("submit", set(output.PLACERS))

    used("render", set(output.RENDERERS))



    # 往返：label 出来的一定能 unlabel 回原值

    for kind in ("vuln", "content_type", "submit", "render", "slot", "var"):

        for key in labels.get(kind, {}):

            if engine.unlabel(rules, kind, engine.label(rules, kind, key)) != key:

                fails.append("smoke_labels: %s/%s 的显示文本还原不回原值" % (kind, key))

    # 没登记的取值原样透传（新槽位不必先登记才能用）

    if engine.label(rules, "slot", "还没登记的新槽位") != "还没登记的新槽位":

        fails.append("smoke_labels: 未登记的取值应原样显示")

    if engine.unlabel(rules, "slot", "close") != "close":

        fails.append("smoke_labels: 直接传 id 应原样返回")



    # 最要紧的一条：标签不能漏进载荷

    res = engine.generate(rules, engine.make_state(

        vuln="sqli", component="mysql", template="sqli.mysql.union.basic", outputs=["raw"]))

    if res["ok"] and res["payload"] != "' UNION SELECT 1,2,3 -- -":

        fails.append("smoke_labels: 标签漏进了生成结果：%r" % res["payload"])





def smoke_doc(rules, fails):

    """使用说明.md 里引用的数字必须仍然成立。



    文档里的数字最容易在加数据后悄悄过期——而"文档说错数字比没文档更糟"。

    这里不做 markdown 解析（太脆），只把文档引用的值断言一遍；

    数据一变这里就红，提醒去改文档。

    """

    def n(**kw):

        return sum(1 for r in engine.filter_templates(rules, engine.make_state(**kw))

                   if r["usable"])



    # 期望值写在**这里**，文档里的那句话只是标签——数据变了这里会红，

    # 提醒去把 使用说明.md / README.md 里对应的数字一起改掉。

    claims = [

        ("默认(sqli) 可用 134 条", n(vuln="sqli"), 134),

        ("模板总数 584 条", len(rules["templates"]), 584),

        ("sqli + mysql 36 条", n(vuln="sqli", component="mysql"), 36),

        ("sqli + mysql + 勾回显/出网 剩 24 条",

         n(vuln="sqli", component="mysql", without=["echo", "outbound"]), 24),

        ("rce + sql-expression 是空结果", n(vuln="rce", content_type="sql-expression"), 0),

        ("放宽漏洞类型多出 134 条", n(content_type="sql-expression"), 134),

        ("放宽内容类型多出 51 条", n(vuln="rce"), 51),

        # 绕过条数与前提键数在 README 里写着，一起钉住

        ("绕过 41 条", len(rules["bypasses"]), 41),

        ("前提词表 42 个键", len(rules["requires_name"]), 42),

    ]

    for name, got, want in claims:

        if got != want:

            fails.append("smoke_doc: 使用说明.md 说「%s」，实际 %d——改了数据就要改文档"

                         % (name, got))



    # 文档里不该出现**已删除**的命令。漏过整整 6 处——批量改文档时用 str.replace，

    # 不匹配就静默跳过，改完看着像成功了。文档教用户敲不存在的命令，比没文档更糟。

    # 豁免：邻近几行出现「已删除 / 原来 / 曾经」的，是在记录历史，属有意保留。

    root = os.path.dirname(os.path.abspath(__file__))

    for path in sorted(glob.glob(os.path.join(root, "*.md"))):

        lines = open(path, encoding="utf-8").read().splitlines()

        for i, line in enumerate(lines, 1):

            m = re.search(r"python -m forge\s+(\S+)", line)

            if not m or m.group(1).startswith("-"):

                continue

            near = " ".join(lines[max(0, i - 4):i])

            if any(w in near for w in ("已删除", "原来", "曾经")):

                continue

            fails.append("smoke_doc: %s:%d 引用了已删除的子命令 %r"

                         % (os.path.basename(path), i, m.group(1)))





def smoke_tui(rules, fails):

    """TUI 冒烟测试：喂脚本化输入驱动它跑完整流程。



    重点不是"能跑"，而是**界面显示的状态和实际生成用的状态一致**——

    踩过两次：draw() 读原始 dict 而过滤用 make_state 补全后的，

    导致界面显示"漏洞类型 不限"、实际按 sqli 过滤；槽位显示空串、实际用默认值。

    这类偏差靠读代码看不出来，只能驱动它跑。

    """

    import builtins

    import contextlib

    import io



    from forge import tui



    def drive(script, st=None):

        it = iter(script)

        out = io.StringIO()

        real = builtins.input

        builtins.input = lambda prompt="": (print(prompt, end=""), next(it, "q"))[1]

        try:

            with contextlib.redirect_stdout(out):

                # 故意传不完整的 dict——run() 必须自己归一化

                tui.run(rules, st if st is not None else {"outputs": ["raw"]})

        finally:

            builtins.input = real

        return out.getvalue()



    # 1. 起手必须带全默认值：否则界面读 st.get("vuln") 显示"不限"，

    #    而过滤已按默认的 sqli 生效，两边对不上。

    #    断言用 engine.label 算出的展示串，而不是写死文案——加中文标签时

    #    写死的断言会红，但那不是 bug，是断言该跟着数据走。

    text = drive(["q"], {"outputs": ["raw"]})

    want_vuln = engine.label(rules, "vuln", "sqli")

    if "漏洞类型 %s" % want_vuln not in text:

        fails.append("smoke_tui: 起手显示的漏洞类型与生效值不符（应显示 %r）" % want_vuln)



    # 2. 选模板后，参数区要显示**生效值**（槽位默认值），不是空串

    text = drive(["t", "2", "q"], {"outputs": ["raw"]})

    if "参数" in text and "= ''" in text.split("参数", 1)[1]:

        fails.append("smoke_tui: 槽位显示成空串——应显示它的 default")



    # 3. 选模板 → 生成。槽位有默认值，不填也能出结果。

    #    驱动脚本不数提示符个数——那样加一个槽位就会让测试失效。

    st = {"outputs": ["raw"]}

    text = drive(["t", "2", "g", "q"], st)

    want = engine.generate(rules, engine.make_state(**st))

    if "组装链" not in text:

        fails.append("smoke_tui: 没走到生成（选了模板 %r）" % st.get("template"))

    elif want["ok"] and want["payload"] not in text:

        fails.append("smoke_tui: 生成结果里没有预期载荷 %r" % want["payload"])

    elif not want["ok"]:

        fails.append("smoke_tui: 引擎对该状态也生成失败：%s" % want.get("reason"))



    # 4. 空结果时给出可动作的下一步，而不是干瞪眼

    text = drive(["q"], {"outputs": ["raw"], "vuln": "rce", "content_type": "sql-expression"})

    if "没有可用模板" not in text or "放宽" not in text:

        fails.append("smoke_tui: 空结果时没给出放宽建议")



    # 5. 认不出的命令不该崩

    text = drive(["zzz", "q"], {"outputs": ["raw"]})

    if "认不出" not in text:

        fails.append("smoke_tui: 未知命令没有反馈")



    # 6. 模板菜单的过滤。默认视图 134 项、不限漏洞类型 584 项，一次打印是几屏——
    #    能输几个字符直接命中是主要用法。这里钉两件事：过滤真的缩小了列表、
    #    **编号按过滤后的列表算**（这条最容易写错：沿用过滤前的序号就会选错模板）。

    # run() 是**原地**补全并修改传入的 dict，所以状态从它身上拿

    st = {"outputs": ["raw"]}

    text = drive(["t", "union.basic", "2", "q"], st)

    if st.get("template") != "sqli.mysql.union.basic":

        fails.append("smoke_tui: 过滤后按编号选中错了——期望 sqli.mysql.union.basic，"

                     "实际 %r" % st.get("template"))

    if "匹配 5 / 134" not in text:

        fails.append("smoke_tui: 菜单过滤没有收窄列表（应提示「匹配 5 / 134」）")



    # 7. 过滤不到要复原，不能把用户晾在一个空菜单里

    st = {"outputs": ["raw"]}

    text = drive(["t", "zzzz不存在", "1", "q"], st)

    if "没有匹配" not in text or st.get("template") != "sqli.mssql.detect.version":

        fails.append("smoke_tui: 过滤不到时应复原成全量列表，实际选中 %r"

                     % st.get("template"))





def main():

    argv = [a for a in sys.argv[1:] if not a.startswith("--")]

    mutate = "--mutate" in sys.argv

    golden_dir = argv[0] if argv else GOLDEN_DIR

    rules = engine.load_rules(DATA_DIR)



    total, fails = 0, []

    for path in sorted(glob.glob(os.path.join(golden_dir, "*.yaml"))):

        with open(path, encoding="utf-8") as f:

            doc = yaml.safe_load(f) or {}

        ver = doc.get("ruleDB")

        if ver and ver != "v0.1.0":

            print("跳过 %s：样本针对 ruleDB %s" % (os.path.basename(path), ver))

            continue

        for s in doc.get("samples") or []:

            total += 1

            ALL_SAMPLES.append(s)

            run_sample(rules, ver, s, fails)



    smoke_labels(rules, fails)

    smoke_var_notes(rules, fails)

    smoke_phpser(rules, fails)

    smoke_bypass_coverage(rules, fails)

    smoke_tui(rules, fails)

    smoke_select(rules, fails)

    smoke_rep(rules, fails)

    smoke_bypass_order(rules, fails)

    smoke_doc(rules, fails)

    smoke_render(rules, fails)

    smoke_requires(rules, fails)

    smoke_relax(rules, fails)

    smoke_gui(rules, fails)

    smoke_scaffold(rules, fails)

    warnings = coverage_report(rules, fails)

    if mutate:

        blind = mutation_coverage(rules)

        warnings += ["篡改 body 后无样本失败的模板（假覆盖）：%s" % b for b in blind]



    for f in fails:

        print("失败: %s" % f)

    for w in warnings:

        print("警告: %s" % w)

    print()

    print("黄金样本 %d 条，失败 %d 条，覆盖警告 %d 条" % (total, len(fails), len(warnings)))

    return 1 if fails else 0





if __name__ == "__main__":

    sys.exit(main())

